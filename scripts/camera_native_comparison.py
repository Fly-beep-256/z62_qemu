"""Compare retained physical PTP bytes with one verified native QEMU run.

This offline entry never opens USB, starts QEMU or alters either input run.
Camera summaries are recomputed from their command-bound raw payloads. Native
bytes must have a passing regression bound to the exact selected result.
Each invocation writes a new report and real-pixel review in results/.
"""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import struct
import sys
import uuid

from z62_common import ROOT, HARNESS, read, save, identity, now, evidence_path

sys.dont_write_bytecode = True
sys.path.insert(0, str(HARNESS))
from camera_battery_read import (allowed, parse_identity, RAM_WINDOWS,
    ROM_WINDOWS, CONFIG_ROM_WINDOWS, CLASSIFICATION_ROM_WINDOWS,
    CLASSIFICATION_RAM_WINDOWS)
from ex1850_battery_config import ConfigObserver, GROUP4_BYTES, convert_group4
from ex1850_battery_task import (BODY_BASE, CONTROL_BASE, CLASSIFICATION_INPUT,
    CLASSIFICATION_ENTRY, classification_from_globals)
from ex1850_cmd89 import INFO_BASE, INFO_BYTES, AUX_BASE, BUILDERS, reconstruct_cmd89, xor_bytes


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def inside(base, name):
    path = (base / name).resolve(strict=True)
    require(path.is_relative_to(base.resolve()), 'Evidence path escapes its input directory: ' + str(name))
    return path


def checked(base, item):
    path = inside(base, item['path'])
    data = path.read_bytes()
    require(len(data) == item['bytes'] and sha(data) == item['sha256'],
            'SHA/size changed: ' + item['path'])
    return path


def select(name):
    path = Path(name)
    if not path.is_absolute():
        path = ROOT / path
    path = path.resolve(strict=True)
    require(path.is_relative_to(ROOT), 'Select an input inside this package')
    return path


def verify_camera(directory):
    summary = read(directory / 'summary.json')
    manifest = read(directory / 'manifest.json')
    require(summary['schema'] == 'z62.camera-battery-read/1', 'Unsupported camera schema')
    names = [item['path'] for item in manifest['files']]
    require(len(names) == len(set(names)), 'Duplicate camera manifest file')
    for item in manifest['files']:
        checked(directory, item)
    for item in manifest['scripts']:
        checked(ROOT, item)
    rom = (ROOT / 'inputs/firmware/ex1850_012000.bi.bin').read_bytes()
    require(sha(rom) == summary['reference_ROM_sha256'], 'Wrong original MCU ROM')
    windows = [*ROM_WINDOWS, *RAM_WINDOWS]
    if summary['config_trace_enabled']:
        windows.extend((*CONFIG_ROM_WINDOWS, (0x2000E7E8, 32, 'pointer_slot')))
    if summary.get('classification_trace_enabled'):
        windows.extend((*CLASSIFICATION_ROM_WINDOWS, *CLASSIFICATION_RAM_WINDOWS))
    transactions = read(directory / 'transactions.json')
    require(len(transactions) == summary['transaction_count'], 'PTP transaction count differs')
    roles, containers, diagnostic = {}, 0, False
    for index, transaction in enumerate(transactions):
        op = int(transaction['operation'], 16)
        params = tuple(int(value, 16) for value in transaction['parameters'])
        require(allowed(op, params, windows), 'Command outside recorded read allowlist')
        require(transaction['ordinal'] == index + 1 and transaction['tid'] == index,
                'PTP command ordinal or transaction ID differs')
        command = struct.pack('<IHHI', 12 + 4 * len(params), 1, op, index)
        command += struct.pack('<' + 'I' * len(params), *params)
        require(inside(directory, transaction['command_file']).read_bytes() == command,
                'Actual PTP command bytes differ')
        require(op != 0x94FF or diagnostic, 'Diagnostic read outside F001/F002')
        raw = b''.join(inside(directory, name).read_bytes() for name in transaction['bulk_reads'])
        pos, payload, terminal = 0, None, None
        while pos < len(raw):
            require(len(raw) - pos >= 12, 'Truncated PTP container')
            size, kind, code, tid = struct.unpack_from('<IHHI', raw, pos)
            require(12 <= size <= 1048576 and pos + size <= len(raw)
                    and tid == index and terminal is None, 'Invalid PTP container boundary')
            body = raw[pos + 12:pos + size]
            pos += size
            containers += 1
            if kind == 2:
                require(code == op and payload is None, 'Wrong/duplicate PTP data container')
                payload = body
            else:
                require(kind == 3 and len(body) % 4 == 0, 'Unexpected PTP container type')
                terminal = (code, list(struct.unpack('<' + 'I' * (len(body) // 4), body)))
        require(terminal == (int(transaction['response_code'], 16), transaction['response_parameters'])
                and terminal[0] == 0x2001, 'PTP terminal response differs or failed')
        if op in (0x94FD, 0x94FF):
            require(terminal[1][:1] == [0x2001], 'Nikon diagnostic status failed')
        if payload is not None:
            require(payload == inside(directory, transaction['payload_file']).read_bytes()
                    and sha(payload) == transaction['payload_sha256']
                    and len(payload) == transaction['payload_bytes'], 'Raw PTP payload differs')
        else:
            require(transaction['payload_bytes'] == 0, 'Missing raw PTP payload')
        if op == 0x94FF:
            require(payload is not None and len(payload) == params[2], 'F044 length differs')
        role = transaction['role']
        require(role not in roles, 'Duplicate recorded PTP role')
        roles[role] = dict(op=op, params=params, payload=payload)
        if role.endswith('-group4-pointer-before-0000'):
            require(op == 0x94FF and params == (0xF044, 0x2000E7F0, 4, 0, 0),
                    'Group4 pointer did not come from the original slot')
            pointer = int.from_bytes(payload, 'little')
            require(ConfigObserver.region(pointer, GROUP4_BYTES) != 'outside_observed_ROM_and_SRAM',
                    'Group4 source outside bounded ROM/SRAM')
            windows.append((pointer, GROUP4_BYTES, 'actual_pointer_source'))
        if op == 0x94FD:
            require(diagnostic == (params[0] == 0xF002), 'Duplicate diagnostic entry/exit')
            diagnostic = params[0] == 0xF001
    require(not diagnostic and summary['complete'] and summary['F002_exit_ok']
            and summary['CloseSession_ok'] and summary['USB_release_ok'], 'Incomplete camera cleanup')
    require(transactions[0]['role'] == 'OpenSession' and transactions[-1]['role'] == 'CloseSession',
            'Missing owned PTP session lifecycle')
    actual_identity = parse_identity(roles['GetDeviceInfo']['payload'])
    require(actual_identity == summary['identity'] and actual_identity['model'] == 'Z 6_2'
            and actual_identity['version'] == 'V1.70', 'Camera identity differs')
    for role, value in summary['normal_mode'].items():
        require(roles[role]['payload'].hex() == value, 'Normal-mode payload differs: ' + role)

    def joined(role, address, size):
        data = bytearray()
        for offset in range(0, size, 128):
            part = roles[role + f'-{offset:04X}']
            require(part['op'] == 0x94FF and part['params'] == (
                0xF044, address + offset, min(128, size - offset), 0, 0),
                'Read address/size binding differs: ' + role)
            data.extend(part['payload'])
        require(inside(directory, role + '.bin').read_bytes() == data,
                'Joined read bytes differ: ' + role)
        return bytes(data)

    for window in summary['ROM_windows']:
        actual = joined(Path(window['path']).stem, int(window['address'], 16), window['bytes'])
        offset = int(window['address'], 16) - 0x08000000
        require(actual == rom[offset:offset + window['bytes']] and sha(actual) == window['sha256'],
                'Physical MCU ROM window differs')

    def verify_cache(sample, prefix):
        before = joined(prefix + '-context-before', 0x2001F4E8, 16)
        buffers = joined(prefix + '-buffers', 0x2001F538, 96)
        after = joined(prefix + '-context-after', 0x2001F4E8, 16)
        tx_length, rx_length = before[1], before[3]
        tx = buffers[0x20:0x20 + min(tx_length, 24)]
        rx = buffers[0x38:0x38 + min(rx_length, 40)]
        complete = (before[:6] == after[:6] and before[5] == 0
            and before[1] == before[2] and before[3] == before[4]
            and 4 <= tx_length <= 24 and 4 <= rx_length <= 40
            and tx[:1] == b'\x02' and len(tx) == tx[2] + 4
            and rx[1:2] == b'\x06' and xor_bytes(tx) == xor_bytes(rx) == 0)
        values = dict(context_before=before[:6].hex(), context_after=after[:6].hex(),
            context_unchanged=before[:6] == after[:6], TX=tx.hex(), RX=rx.hex(),
            consistent_completed_cache_pair=complete,
            physical_cmd89_cache_pair=complete and tx[1] == 0x89,
            raw_UART_capture=False, atomic_snapshot=False)
        require(all(sample[key] == value for key, value in values.items()),
                'UART cache summary differs from raw payloads: ' + prefix)

    for sample in summary['snapshots']:
        prefix = 'pass' + str(sample['pass_index'])
        verify_cache(sample, prefix)
        info = joined(prefix + '-config', INFO_BASE, INFO_BYTES)
        copied = joined(prefix + '-config-copy-and-body', 0x2001FAF8, 136)
        auxiliary = joined(prefix + '-auxiliary', 0x2000ED90, 32)[AUX_BASE - 0x2000ED90:AUX_BASE - 0x2000ED90 + 2]
        mode = copied[BODY_BASE - 0x2001FAF8 + 0x2E]
        require(info.hex() == sample['info72_hex'] and auxiliary.hex() == sample['auxiliary2_hex']
                and mode == sample['body_mode']
                and (info == copied[:INFO_BYTES]) == sample['info72_copies_equal'],
                'Physical config/body/auxiliary summary differs')
        candidates = [reconstruct_cmd89(info, auxiliary, mode, builder, pin)
                      for builder in BUILDERS for pin in (0, 1)]
        require(candidates == sample['reconstructed_cmd89_candidates'], 'Conditional cmd89 reconstruction differs')
        if summary['config_trace_enabled']:
            group = sample['group4_configuration']
            before = joined(prefix + '-group4-pointer-before', 0x2000E7F0, 4)
            after = joined(prefix + '-group4-pointer-after', 0x2000E7F0, 4)
            pointer = int.from_bytes(before, 'little')
            source = joined(prefix + '-group4-source', pointer, GROUP4_BYTES)
            info_after = joined(prefix + '-config-after', INFO_BASE, INFO_BYTES)
            require(int(group['pointer'], 16) == pointer and before.hex() == group['pointer_before_hex']
                    and after.hex() == group['pointer_after_hex']
                    and (before == after) == group['pointer_unchanged']
                    and source.hex() == group['source_hex'] and sha(source) == group['source_sha256']
                    and copied[:INFO_BYTES].hex() == group['cache72_hex']
                    and info_after.hex() == group['info72_after_hex']
                    and (info == info_after) == group['info72_unchanged']
                    and [c for c in (0, 1) if convert_group4(source, copied[:INFO_BYTES], c)
                         == copied[:INFO_BYTES]] == group['conversion_matches_cache_for_correction'],
                    'Group4 source/cache summary differs from raw payloads')
        if summary.get('classification_trace_enabled'):
            value = sample['global_classification']
            before = joined(prefix + '-class-input-before', CLASSIFICATION_INPUT, 8)
            after = joined(prefix + '-class-input-after', CLASSIFICATION_INPUT, 8)
            body_before = joined(prefix + '-class-body-before', BODY_BASE + 0x29, 1)[0]
            body_after = joined(prefix + '-class-body-after', BODY_BASE + 0x29, 1)[0]
            cache_before = joined(prefix + '-class-cache-before', CONTROL_BASE + 0x14, 1)[0]
            cache_after = joined(prefix + '-class-cache-after', CONTROL_BASE + 0x14, 1)[0]
            stable = before == after and body_before == body_after and cache_before == cache_after
            predicted_before = classification_from_globals(before, body_before)
            predicted_after = classification_from_globals(after, body_after)
            values = dict(input8_before_hex=before.hex(), input8_after_hex=after.hex(),
                body_state_before=body_before, body_state_after=body_after,
                cached_classification_before=cache_before, cached_classification_after=cache_after,
                repeated_samples_equal=stable, statically_recomputed_classification_before=predicted_before,
                statically_recomputed_classification_after=predicted_after,
                cached_value_equals_recomputation=(cache_before == predicted_before) if stable else None)
            require(all(value[key] == expected for key, expected in values.items()),
                    'Classification summary differs from raw payloads')
    for sample in summary.get('cache_samples', []):
        verify_cache(sample, 'cache' + str(sample['sample_index']))
    all_samples = [*summary['snapshots'], *summary.get('cache_samples', [])]
    verification = dict(manifest_files_verified=len(manifest['files']),
        reader_sources_verified=len(manifest['scripts']), PTP_commands_verified=len(transactions),
        PTP_containers_verified=containers, all_commands_in_bounded_read_allowlist=True,
        MCU_ROM_windows_equal=len(summary['ROM_windows']),
        normal_battery_percent=int(summary['normal_mode']['BatteryLevel'], 16),
        normal_exposure_program=int.from_bytes(bytes.fromhex(summary['normal_mode']['ExposureProgram']), 'little'),
        cache_samples=len(all_samples), consistent_cache_pairs=sum(s['consistent_completed_cache_pair'] for s in all_samples),
        changed_or_incomplete_cache_pairs=sum(not s['consistent_completed_cache_pair'] for s in all_samples),
        physical_cmd89_cache_pairs=sum(s['physical_cmd89_cache_pair'] for s in all_samples),
        F002_exit_ok=True, CloseSession_ok=True, USB_release_ok=True)
    return summary, verification


def verify_native(directory, regression_path):
    raw_path = directory / 'run/native-unified-result.json'
    raw = read(raw_path)
    regression = read(regression_path)
    require(regression['schema'] == 'z62.native-evidence-regression/1' and regression['passed']
            and all(check['passed'] for check in regression['checks']), 'Native regression did not pass')
    require(checked(ROOT, regression['input']) == raw_path.resolve(),
            'Native regression belongs to another run')
    for item in regression['sources']:
        checked(ROOT, item)
    require(raw['machine'] == 'nikon-z6ii-native' and raw['architecture_passed']
            and raw['debugger_zero_guest_writes'], 'Native architecture/write gate failed')
    locked = read(directory / 'prepare/锁定命令与输入.json')
    audit = read(directory / 'acceptance.json')
    sram_item = raw['MCU_final_SRAM']
    sram_path = evidence_path(sram_item['path'], directory, locked).resolve(strict=True)
    sram = sram_path.read_bytes()
    require(len(sram) == sram_item['bytes'] == 262144 and sha(sram) == sram_item['sha256'],
            'Final MCU SRAM identity differs')
    classification = []
    for event in raw['original_battery_task_events']:
        if 'classification_input8_hex' not in event:
            continue
        item = {key: event[key] for key in ('phase', 'entry', 'observation_sequence',
            'stop_epoch', 'virtual_time_ns', 'main_body_state', 'classification_input8_hex', 'classification_byte')}
        item['statically_recomputed'] = classification_from_globals(
            bytes.fromhex(event['classification_input8_hex']), event['main_body_state'])
        if event['phase'] == 'return':
            item.update(function_entry=event['function_entry'], entry_sequence=event['entry_sequence'],
                stack_and_return_pair_match=event['stack_and_return_pair_match'])
        classification.append(item)
    final = dict(stop_epoch=sram_item['stop_epoch'], virtual_time_ns=raw['common_stop']['virtual_time_ns'],
        input8_hex=sram[CLASSIFICATION_INPUT - 0x20000000:CLASSIFICATION_INPUT - 0x20000000 + 8].hex(),
        body_state=sram[BODY_BASE + 0x29 - 0x20000000], cached_classification=sram[CONTROL_BASE + 0x14 - 0x20000000])
    final['statically_recomputed'] = classification_from_globals(bytes.fromhex(final['input8_hex']), final['body_state'])
    frames = []
    from PIL import Image
    for item in audit['LCD']['frames']:
        source = evidence_path(item['evidence']['path'], directory, locked).resolve(strict=True)
        require(source.is_relative_to(directory) and len(source.read_bytes()) == item['evidence']['bytes']
                and sha(source.read_bytes()) == item['evidence']['sha256'], 'Saved native frame identity differs')
        with Image.open(source) as image:
            pixels = image.convert('RGB')
            require(list(pixels.size) == item['size'] and sha(pixels.tobytes()) == item['pixel_sha256'],
                    'Native pixel identity differs')
            nonblack = pixels.getbbox() is not None
            uniform = all(low == high for low, high in pixels.getextrema())
            require(nonblack == item['nonblack'] and uniform == item['uniform'], 'Native frame classification differs')
        frames.append(dict(**identity(source), pixel_sha256=item['pixel_sha256'], size=item['size'],
                           nonblack=nonblack, uniform=uniform))
    require(frames, 'No actual native console frame')
    return raw, audit, classification, final, frames


def make_visual(output, native_directory, audit, frames, assisted_directory):
    from PIL import Image, ImageDraw, ImageFont, ImageOps
    selected = next((item for item in frames if item['nonblack'] and not item['uniform']), frames[-1])
    native_source = ROOT / selected['path']
    with Image.open(native_source) as image:
        image.convert('RGB').save(output / 'native-console.png')
    canvas = Image.new('RGB', (1520, 830), '#10161f')
    draw = ImageDraw.Draw(canvas)
    title_font = ImageFont.load_default(size=30)
    font = ImageFont.load_default(size=22)
    small = ImageFont.load_default(size=18)
    draw.text((28, 22), 'Z6II: current unified native and retained assisted DISP', font=title_font, fill='white')
    sources = []

    def panel(x, source, title, subtitle, notes):
        draw.rounded_rectangle((x, 86, x + 720, 754), radius=12, fill='#1c2532', outline='#354457', width=2)
        draw.text((x + 16, 102), title, font=font, fill='white')
        draw.text((x + 16, 136), subtitle, font=small, fill='#bdc7d5')
        with Image.open(source) as original:
            fitted = ImageOps.contain(original.convert('RGB'), (720, 480), Image.Resampling.LANCZOS)
            canvas.paste(fitted, (x + (720 - fitted.width) // 2, 176 + (480 - fitted.height) // 2))
        for index, note in enumerate(notes):
            draw.text((x + 16, 673 + index * 28), note, font=small, fill='#d4dce8')
        sources.append(identity(source))

    writes = audit['debugger_assistance']['actual_guest_write_packets']
    panel(28, native_source, 'CURRENT: one QEMU / five CPUs', native_directory.name,
          [f'{len(frames)} saved frames; {len({f["pixel_sha256"] for f in frames})} pixel hash(es)',
           f'Host RAM/register write packets: {writes}; MENU not verified'])
    if assisted_directory:
        old = read(assisted_directory / 'acceptance.json')
        require(old['profile'] == 'still-disp', 'Selected auxiliary run is not still-disp')
        frame = next(row for row in old['LCD']['frames'] if
                     row['evidence']['path'].endswith('disp_mode0_detailed_indicators.png'))
        source = checked(assisted_directory, frame['evidence'])
        with Image.open(source) as image:
            require(sha(image.convert('RGB').tobytes()) == frame['pixel_sha256'], 'Assisted pixel identity differs')
        old_writes = old['debugger_assistance']['actual_guest_write_packets']
        panel(772, source, 'RETAINED: assisted still-disp', assisted_directory.name,
              [f'Host RAM/register write packets: {old_writes}', 'Firmware rendering with assistance; separate acceptance'])
        sources.append(identity(assisted_directory / 'acceptance.json'))
    else:
        draw.text((796, 300), 'No assisted reference selected', font=font, fill='#bdc7d5')
    draw.text((28, 785), 'Actual saved pixels. Borders, captions and scaling are review annotations only.',
              font=small, fill='#bdc7d5')
    canvas.save(output / 'comparison.png')
    return dict(sources=sources, outputs=[identity(output / name) for name in ('native-console.png', 'comparison.png')],
                annotations_are_review_only=True, input_pixels_modified=False,
                QMP_console_engine_assignment_verified=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--camera', required=True, help='Retained camera-battery directory')
    parser.add_argument('--native', required=True, help='Retained single-instance native run')
    parser.add_argument('--regression', required=True, help='Passing evidence regression for that exact native run')
    parser.add_argument('--assisted', help='Optional retained still-disp run for pixel comparison')
    args = parser.parse_args()
    camera, native, regression = select(args.camera), select(args.native), select(args.regression)
    assisted = select(args.assisted) if args.assisted else None
    output = ROOT / 'results/camera-comparisons' / (datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:6])
    output.mkdir(parents=True, exist_ok=False)
    report = dict(schema='z62.camera-native-comparison/1', created=now(), method=identity(Path(__file__)),
        scope=dict(camera_access=False, QEMU_launched=False, input_runs_modified=False,
            raw_physical_UART_capture=False, atomic_physical_snapshot=False, physical_natural_cold_boot=False,
            firmware_memory_writes=0, physical_cmd89_sent_by_this_tool=False, full_camera_acceptance=False),
        inputs=[identity(camera / name) for name in ('summary.json', 'manifest.json', 'transactions.json')]
            + [identity(native / 'run/native-unified-result.json'), identity(native / 'acceptance.json'), identity(regression)],
        passed=False)
    try:
        physical, verification = verify_camera(camera)
        raw, audit, classification, final, frames = verify_native(native, regression)
        samples = physical['snapshots']
        source_hashes = {s['group4_configuration']['source_sha256'] for s in samples if 'group4_configuration' in s}
        cache_values = {s['info72_hex'] for s in samples}
        conversions = [dict(sequence=e['observation_sequence'], virtual_time_ns=e['virtual_time_ns'],
            source_address=e['group4_address'], source_sha256=e['group4_source_sha256'],
            equals_physical_source=e['group4_source_sha256'] in source_hashes)
            for e in raw['original_battery_config_events'] if e['phase'] == 'conversion_entry']
        copies = [dict(sequence=e['observation_sequence'], virtual_time_ns=e['virtual_time_ns'],
            equals_physical_info72=e['info72_hex'] in cache_values)
            for e in raw['original_battery_config_events'] if e['phase'] == 'copy_completed']
        report.update(physical_identity={key: physical['identity'][key] for key in ('manufacturer', 'model', 'version')},
            physical_verification=verification,
            physical_classification=[s['global_classification'] for s in samples if 'global_classification' in s],
            physical_reconstructed_cmd89_candidates=sorted({c['frame_hex'] for s in samples for c in s['reconstructed_cmd89_candidates']}),
            native=dict(run=native.name, architecture_passed=audit['architecture']['passed'],
                QEMU_PID=raw['QEMU_lifecycle']['pid'], original_battery_task_events=len(raw['original_battery_task_events']),
                classification_events=classification, final_MCU_classification=final,
                cmd89_returns=raw['original_cmd89_transaction_returns'],
                battery_status=audit['battery']['status'], wire=audit['battery']['wire'],
                battery_functional_gaps=audit['battery']['errors'],
                unframed_UART=audit['battery']['unframed_UART'], required_cmd89=audit['battery']['required_cmd89_requests'],
                conversion_entries=conversions, copy_completions=copies,
                LCD={k: v for k, v in audit['LCD'].items() if k != 'frames'},
                guest_write_packets=audit['debugger_assistance']['actual_guest_write_packets'],
                package_runtime_status=audit['package_runtime_status'], acceptance_errors=audit['errors'],
                common_stop=raw['common_stop'], functional_gates=audit['functional_gates']),
            visuals=make_visual(output, native, audit, frames, assisted), passed=True,
            unknowns=['Physical UART meaning, timing and the missing second cmd89 request',
                'Physical classification call time and meaning of body-state byte',
                'Cause of native refresh scheduling differences',
                'Physical Flash boot, full cross-engine causality, stable menu, photo/movie/HDMI'])
        entries = [e for e in classification if e['phase'] == 'entry' and int(e['entry'], 16) == CLASSIFICATION_ENTRY]
        physical_classes = sorted({(s['global_classification']['body_state_before'],
            s['global_classification']['cached_classification_before']) for s in samples if 'global_classification' in s})
        call_details = [dict(input8=e['classification_input8_hex'], body_state=e['main_body_state'],
            returned_classification=next((r['classification_byte'] for r in classification
                if r['phase'] == 'return' and r['entry_sequence'] == e['observation_sequence']), None))
            for e in entries]
        wire = audit['battery']['wire']
        text = f'''# 真机与单实例 native QEMU 对照

输入真机为 Z6II V1.70，正常电量返回 `{physical['normal_mode']['BatteryLevel']}`，即 {verification['normal_battery_percent']}%。本报告从原始 USB bytes 重算并绑定 {verification['PTP_commands_verified']} 个命令、{verification['PTP_containers_verified']} 个 PTP 容器、{verification['manifest_files_verified']} 个文件与 {verification['MCU_ROM_windows_equal']} 个原厂 ROM 窗口；F002、CloseSession 与 USB 释放成功。全部读取处于固定或实际指针授权的窗口。

共 {verification['cache_samples']} 次 UART 缓存采样：{verification['consistent_cache_pairs']} 次完整一致，{verification['changed_or_incomplete_cache_pairs']} 次变化或不完整；实际真机 `0x89` 缓存对为 {verification['physical_cmd89_cache_pairs']}。配置、分类与候选报文均从对应 F044 payload 重算。这是 F001 后的顺序读取，无法证明物理 UART 时间、原子状态或真机分类函数刚刚执行。

真机前后读取的 `(body_state, cached_classification)` 为 `{physical_classes}`。native 在本轮观察到分类入口 {len(entries)} 次，调用时的全局输入、store、返回和最终 SRAM 见 [result.json](result.json)。`body_state` 位于 `0x2001FB69`，与 `body_mode` 的 `0x2001FB6E` 分开记录。最终 SRAM 的分类字节不能反推前面调用时点。

native 分类调用的原始输入和返回为 `{call_details}`；最终 `(body_state, cached_classification)` 为 `({final['body_state']}, {final['cached_classification']})`。这些是本轮实际观察，分支差异的充分原因仍未知。

原厂配置转换共观察到 {len(conversions)} 次，其中 {sum(e['equals_physical_source'] for e in conversions)} 次的 360 字节源与真机相同；原厂复制共 {len(copies)} 次，其中 {sum(e['equals_physical_info72'] for e in copies)} 次的 72 字节缓存与真机相同。初始原厂默认配置与后续加载配置分别记录，不把最终一致倒推为整条初始化过程一致。

native 实际运行 `{native.name}`：一个 QEMU PID={raw['QEMU_lifecycle']['pid']}，五核、三个私有芯片域、共同虚拟时间；Host RAM/寄存器写包 {audit['debugger_assistance']['actual_guest_write_packets']}。结束时共同虚拟时间 {raw['common_stop']['virtual_time_ns'] / 1e9:.9f} 秒。原厂 `0x89` 返回、帧外 UART 字节、所需完整请求与功能缺口均保留；本报告的 `passed` 只表示对照方法核实成功，不是完整相机通过。

本轮保留的 UART TX / RX 为 {wire['public_TX_bytes']} / {wire['synthetic_RX_bytes']} 字节，完整原厂 `0x89` 返回为 {len(raw['original_cmd89_transaction_returns'])} 次；电池功能状态为 `{audit['battery']['status']}`。帧外字节状态为 `{audit['battery']['unframed_UART']['status']}`；本轮没有观察到的字节不沿用其他运行的偏移或来源结论。

本轮保存 {len(frames)} 个实际 QMP 帧，像素状态为 `{audit['LCD']['status']}`。左侧为当前 native；右侧若有图则来自明确标记的历史辅助 still-disp，辅助写入数另列。QMP console 的引擎归属尚未验收。光圈依赖镜头；未连镜头时 `F---` 是合理状态，辅助图中的光圈值不证明 native 镜头冷启动。`movie-disp` 仍未完成。

![当前 native 与历史辅助 DISP](comparison.png)

原始 native 的目录与证据验收错误为 `{audit['errors']}`；电池功能缺口为 `{audit['battery']['errors']}`。历史失败报告不在这里改写。机器可读明细见 [result.json](result.json)，入口与范围见 [CAMERA-BATTERY.md](../../../docs/CAMERA-BATTERY.md)。
'''
        (output / 'comparison.md').write_text(text)
    except (OSError, KeyError, TypeError, ValueError, AssertionError, StopIteration) as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
    report['finished'] = now()
    save(output / 'result.json', report)
    print(('PASS ' if report['passed'] else 'FAIL ') + str(output.relative_to(ROOT)), flush=True)
    if 'error' in report:
        print(report['error'], flush=True)
    return int(not report['passed'])


if __name__ == '__main__':
    raise SystemExit(main())
