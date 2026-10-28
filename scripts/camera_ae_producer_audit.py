"""Recheck retained AE camera reads without opening USB or changing the capture."""
import argparse
import ast
from datetime import datetime
import hashlib
import json
from pathlib import Path
import struct
import uuid

from z62_common import ROOT, identity, now, read, save


def digest(data):
    return hashlib.sha256(data).hexdigest()


def literal(node, known):
    if isinstance(node, ast.Name):
        return known[node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        return tuple(literal(item, known) for item in node.elts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return literal(node.left, known) + literal(node.right, known)
    return ast.literal_eval(node)


def frozen_windows(source, declared):
    known = {}
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                known[node.targets[0].id] = literal(node.value, known)
            except (KeyError, ValueError, TypeError, SyntaxError):
                pass
    wanted = tuple((int(row['address'], 16), row['bytes'], row['label']) for row in declared)
    matches = [name for name, value in known.items() if name.endswith('RAM_WINDOWS') and value == wanted]
    if not matches:
        raise ValueError('Declared windows differ from frozen capture source literals')
    return wanted, matches


def containers(data):
    result = []
    while data:
        if len(data) < 12:
            raise ValueError('Truncated PTP header')
        length, kind, code, tid = struct.unpack_from('<IHHI', data)
        if not 12 <= length <= min(1048576, len(data)):
            raise ValueError('Invalid PTP container length')
        result.append((kind, code, tid, data[12:length]))
        data = data[length:]
    return result


def audit(directory):
    directory = directory.resolve()
    directory.relative_to((ROOT / 'results').resolve())
    manifest = read(directory / 'manifest.json')
    files = {}
    if not isinstance(manifest['files'], list) or not isinstance(manifest['execution_files'], list):
        raise ValueError('Capture manifest file groups must be lists')
    for row in manifest['files'] + manifest['execution_files']:
        path = (directory / row['path']).resolve()
        path.relative_to(directory)
        data = path.read_bytes()
        if row['path'] in files or len(data) != row['bytes'] or digest(data) != row['sha256']:
            raise ValueError('Capture file identity differs: ' + row['path'])
        files[row['path']] = data
    summary, transactions = json.loads(files['summary.json']), json.loads(files['transactions.json'])
    source = files['execution-sources/scripts/camera_ae_producer_read.py'].decode()
    windows, window_literals = frozen_windows(source, summary['fixed_RAM_windows'])
    for row in summary['execution_sources']:
        data = files[row['path']]
        if len(data) != row['bytes'] or digest(data) != row['sha256']:
            raise ValueError('Frozen execution source identity differs')
    reference = summary['reference_ROM']
    rom = (ROOT / reference['path']).read_bytes()
    if len(rom) != reference['bytes'] or digest(rom) != reference['sha256']:
        raise ValueError('Package reference ROM identity differs')
    session, diagnostic, terminal = False, False, []
    checked, ram_reads = [], []
    for ordinal, tx in enumerate(transactions, 1):
        op, params = int(tx['operation'], 16), tuple(int(p, 16) for p in tx['parameters'])
        command = containers(files[tx['command_file']])
        if len(command) != 1 or command[0][:3] != (1, op, tx['tid']):
            raise ValueError('Command envelope differs')
        expected = struct.pack('<' + 'I' * len(params), *params)
        if command[0][3] != expected or tx['ordinal'] != ordinal or tx['tid'] != ordinal - 1:
            raise ValueError('Command parameters or transaction ordering differs')
        allowed = (op, params) in {
            (0x1001, ()), (0x1002, (1,)), (0x1003, ()),
            (0x94FD, (0xF001, 0, 0, 0, 0)), (0x94FD, (0xF002, 0, 0, 0, 0)),
        }
        allowed |= op == 0x1015 and len(params) == 1 and params[0] in (0x5001, 0x5007, 0x500D, 0x500F, 0x500E)
        memory_read = op == 0x94FF and len(params) == 5 and params[0] == 0xF036
        if memory_read:
            address, size = params[1:3]
            allowed |= (session and diagnostic and params[3:] == (0, 0) and 0 < size <= 128 and
                        any(base <= address and address + size <= base + length for base, length, _ in windows))
        if not allowed:
            raise ValueError('Command outside the fixed read allowlist')
        incoming = containers(b''.join(files[p] for p in tx['bulk_reads']))
        if any(tid != tx['tid'] for _, _, tid, _ in incoming):
            raise ValueError('Incoming transaction ID differs')
        if len(incoming) not in (1, 2) or incoming[-1][0] != 3 or incoming[-1][1] != 0x2001:
            raise ValueError('Missing successful terminal response')
        response_body = incoming[-1][3]
        if len(response_body) % 4:
            raise ValueError('Invalid response parameter length')
        response = list(struct.unpack('<' + 'I' * (len(response_body) // 4), response_body))
        if response != tx['response_parameters'] or int(tx['response_code'], 16) != 0x2001:
            raise ValueError('Declared response differs from recorded bytes')
        if op in (0x94FD, 0x94FF) and response[:1] != [0x2001]:
            raise ValueError('Vendor response status differs')
        payload = b''
        if len(incoming) == 2:
            if incoming[0][:3] != (2, op, tx['tid']):
                raise ValueError('Unexpected incoming DATA container')
            payload = incoming[0][3]
            if payload != files[tx['payload_file']] or digest(payload) != tx['payload_sha256']:
                raise ValueError('Retained payload differs from USB DATA bytes')
        if len(payload) != tx['payload_bytes'] or memory_read and len(payload) != params[2]:
            raise ValueError('Payload length differs')
        if op == 0x1002:
            if session or diagnostic:
                raise ValueError('Duplicate OpenSession')
            session = True
        elif op == 0x94FD:
            if not session or (params[0] == 0xF001) == diagnostic:
                raise ValueError('Diagnostic lifecycle differs')
            diagnostic = params[0] == 0xF001
            terminal.append(hex(params[0]))
        elif op == 0x1003:
            if not session or diagnostic:
                raise ValueError('CloseSession before diagnostic exit')
            session = False
            terminal.append('CloseSession')
        if memory_read:
            ram_reads.append(dict(ordinal=ordinal, role=tx['role'], address=params[1],
                                  bytes=params[2], payload=payload))
        checked.append(dict(ordinal=ordinal, tid=tx['tid'], operation=hex(op), parameters=tx['parameters'],
                            command_sha256=digest(files[tx['command_file']]), payload_bytes=len(payload)))
    if session or diagnostic or terminal != ['0xf001', '0xf002', 'CloseSession']:
        raise ValueError('Incomplete owned session lifecycle')
    if not summary['complete'] or summary['transaction_count'] != len(transactions):
        raise ValueError('Capture incomplete')
    samples, consumed = [], set()
    for sample in summary['samples']:
        observed = {}
        for (base, size, label), row in zip(windows, sample['windows'], strict=True):
            data = files[row['path']]
            if int(row['address'], 16) != base or len(data) != size or row['bytes'] != size or digest(data) != row['sha256']:
                raise ValueError('Fixed window identity differs')
            parts = []
            for offset in range(0, size, 128):
                role = 'pass%d-%s-%04x' % (sample['index'], label, offset)
                matches = [tx for tx in ram_reads if tx['role'] == role]
                if len(matches) != 1 or matches[0]['address'] != base + offset or matches[0]['bytes'] != min(128, size - offset):
                    raise ValueError('Fixed window chunk request differs')
                parts.append(matches[0]['payload'])
                consumed.add(matches[0]['ordinal'])
            if b''.join(parts) != data:
                raise ValueError('Assembled fixed window differs from USB payload')
            observed[label] = data
        def words(label, offset, count):
            return list(struct.unpack_from('<' + 'I' * count, observed[label], offset))
        item = dict(index=sample['index'], windows_verified=len(observed),
                    default_input_nonzero=any(observed['AE_default_input']),
                    rational_1603=words('AE_rational_1603_through_1609', 0, 2),
                    rational_1608=words('AE_rational_1603_through_1609', 0x1C, 2),
                    rational_1609=words('AE_rational_1603_through_1609', 0x24, 2),
                    exposure_180x=words('exposure_1800_through_1810', 0, 3),
                    user_ISO_1810=words('exposure_1800_through_1810', 0x40, 1)[0])
        if summary['fixed_profile'] == 'mask4-source':
            source = observed['mask4_default_input92']
            item.update(mask4_source92_words=words('mask4_default_input92', 0, 23),
                        mask4_source92_nonzero=any(source),
                        main_AE_mode_byte_7=observed['main_AE_mask4_owner'][7],
                        mask4_adapter_flag_byte_18=observed['mask4_adapter_flags_and_control'][0x18],
                        mask4_adapter_flag_mask6=observed['mask4_adapter_flags_and_control'][0x18] & 6,
                        lens_mounted=words('lens_mounted_property', 0, 1)[0],
                        group20_ready=words('exposure_group20_ready_property', 0, 1)[0])
        if summary['fixed_profile'] == 'request-gates':
            item.update(main_AE_gate_58=words('main_AE_routing_and_request_gate', 0x58, 1)[0],
                        main_AE_route_40=words('main_AE_routing_and_request_gate', 0x40, 1)[0],
                        main_AE_route_50=words('main_AE_routing_and_request_gate', 0x50, 1)[0],
                        queue_counts={name: words('pending_ready_membership_queues', offset + 8, 1)[0]
                                      for name, offset in [('pending', 0), ('ready', 0x20), ('membership', 0x40)]},
                        lens_mounted=words('lens_mounted_property', 0, 1)[0],
                        group20_ready=words('exposure_group20_ready_property', 0, 1)[0])
        if summary['fixed_profile'] == 'captg-state':
            owner = observed['CAPTG_upstream_owner']
            item.update(
                CAPTG_state_byte_00=owner[0],
                CAPTG_substate_byte_0c=owner[0x0C],
                CAPTG_owner_callback_28=hex(words('CAPTG_upstream_owner', 0x28, 1)[0]),
                CAPTG_owner_count_64=words('CAPTG_upstream_owner', 0x64, 1)[0],
                CAPTG_owner_flag_wrapper_b0_words=words('CAPTG_upstream_owner', 0xB0, 4),
                CAPTG_message_owner_words=words('CAPTG_message_owner', 0, 16),
                SDES_callback_10=hex(words('SDES_source_callback_object', 0x10, 1)[0]),
                TG_callback_34=hex(words('TG_source_callback_object', 0x34, 1)[0]),
                CAPTG_upstream_callback_04=hex(words('CAPTG_event_control', 4, 1)[0]),
                lens_mounted=words('lens_mounted_property', 0, 1)[0],
                group20_ready=words('exposure_group20_ready_property', 0, 1)[0])
        samples.append(item)
    if len(consumed) != len(ram_reads):
        raise ValueError('Unassigned RAM read transaction')
    return dict(schema='z62.camera-ae-producer-audit/1', generated=now(), verified=True,
                capture=identity(directory / 'manifest.json'), reference_ROM=reference,
                files_verified=len(files), frozen_window_literals=window_literals,
                transactions_verified=len(checked), bounded_RAM_read_transactions=len(ram_reads),
                recorded_memory_or_property_write_commands=0, session_closed=True, diagnostic_exited=True,
                USB_release_reported=summary['USB_release_ok'], camera_model=summary['identity']['model'],
                camera_version=summary['identity']['version'], samples=samples, transactions=checked,
                physical_ROM_read_verified=False, atomic_snapshot=False, physical_cold_boot_observed=False,
                callback_execution_observed=False, original_capture_modified=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('run')
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    output = args.out or ROOT / 'results/camera-audits' / (
        datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:6])
    output = (output if output.is_absolute() else ROOT / output).resolve()
    output.relative_to((ROOT / 'results').resolve())
    report = audit(ROOT / 'results' / args.run)
    output.mkdir(parents=True, exist_ok=False)
    report['execution_source'] = identity(Path(__file__))
    save(output / 'report.json', report)
    lines = ['# 真机 AE 读取原始证据复查', '',
             '固定采样：`%s`；%s / %s。' % (args.run, report['camera_model'], report['camera_version']), '',
             '%s 个文件、%s 个 PTP 事务及 %s 个有界 RAM 读取事务的身份、请求参数、原始 DATA/RESPONSE 字节与拼接窗口均通过。' % (
                 report['files_verified'], report['transactions_verified'], report['bounded_RAM_read_transactions']), '',
             '记录内 RAM／属性写命令为零。F001→固定读取→F002→CloseSession 生命周期已从命令与返回字节复核；USB release 依据采样脚本的收尾记录。', '',
             '这些是 F001 后顺序读取的运行态样本。它们不认证物理冷启动、原厂 callback 执行或原厂 ROM 字节读回。', '',
             '| 遍次 | 1603 | 1608 | 1609 | 1800/1801/1802 | 1810 | default_input非零 |',
             '|---|---|---|---|---|---|---|']
    for sample in report['samples']:
        lines.append('| %s | %s | %s | %s | %s | %s | %s |' % tuple(sample[k] for k in (
            'index', 'rational_1603', 'rational_1608', 'rational_1609', 'exposure_180x', 'user_ISO_1810', 'default_input_nonzero')))
    lines += ['', '[逐事务与逐窗口复查](report.json)。', '']
    (output / 'report.md').write_text('\n'.join(lines))
    save(output / 'manifest.json', dict(files=[identity(p, output) for p in sorted(output.iterdir()) if p.is_file()]))
    print(json.dumps(dict(report=str(output / 'report.md'), verified=True,
                          transactions=report['transactions_verified']), ensure_ascii=False))


if __name__ == '__main__':
    main()
