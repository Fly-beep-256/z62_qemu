"""Audit saved exposure display reads from original USB bytes; no USB access."""
import argparse
from fractions import Fraction
import json
import math
from pathlib import Path
import struct

from camera_ae_producer_audit import containers, frozen_windows
from camera_exposure_display_read import (DESCRIPTORS, FLAG_BYTES, decode_mirror,
                                         rom_contract, u32)
from z62_common import ROOT, identity, now, read, save
from camera_native_ui_read import sha


def audit(directory):
    directory = directory.resolve()
    directory.relative_to((ROOT/'results').resolve())
    manifest = read(directory/'manifest.json')
    files = {}
    for item in manifest['files']+manifest['execution_files']:
        path = (directory/item['path']).resolve()
        path.relative_to(directory)
        data = path.read_bytes()
        if item['path'] in files or len(data) != item['bytes'] or sha(data) != item['sha256']:
            raise ValueError('Capture identity differs: '+item['path'])
        files[item['path']] = data
    summary = json.loads(files['summary.json'])
    transactions = json.loads(files['transactions.json'])
    if summary['schema'] != 'z62.camera-exposure-display-read/1':
        raise ValueError('Unexpected capture schema')
    source = files['execution-sources/scripts/camera_exposure_display_read.py'].decode()
    windows, names = frozen_windows(source, summary['fixed_RAM_windows'])
    reference = summary['reference_ROM']
    rom = (ROOT/reference['path']).read_bytes()
    if len(rom) != reference['bytes'] or sha(rom) != reference['sha256']:
        raise ValueError('Reference ROM identity differs')
    contract = rom_contract(rom)
    if contract != summary['original_ROM_contract']:
        raise ValueError('Saved ROM display contract differs')
    expected, samples = [], []

    def retain_window(row, address, size, label):
        if int(row['address'], 16) != address or row['path'] != label+'.bin':
            raise ValueError('Sample window label/address differs')
        data = files[row['path']]
        if len(data) != size or row['bytes'] != size or row['sha256'] != sha(data):
            raise ValueError('Sample window identity differs')
        for offset in range(0, size, 128):
            payload = data[offset:offset+min(128, size-offset)]
            expected.append((label+f'-{offset:04x}', address+offset, payload))
        return data

    for index, sample in enumerate(summary['samples'], 1):
        if sample['index'] != index or len(sample['windows']) != len(windows):
            raise ValueError('Sample order/windows differs')
        values = {}
        for row, (address, size, label) in zip(sample['windows'], windows, strict=True):
            values[label] = retain_window(row, address, size, f'pass{index}-'+label)
        if len(sample['descriptors']) != len(DESCRIPTORS):
            raise ValueError('Descriptor count differs')
        for row, (label, address, key) in zip(sample['descriptors'], DESCRIPTORS, strict=True):
            pointer = u32(values[key], 0x2C)
            if (row['label'], int(row['descriptor_address'], 16), int(row['pointer_slot'], 16),
                    int(row['flags_pointer'], 16), row['bytes']) != (label, address, address+0x2C, pointer, FLAG_BYTES):
                raise ValueError('Dynamic authorization differs from recorded descriptor')
            if 0xC0000000 <= pointer <= 0xD0000000-FLAG_BYTES:
                data = retain_window(row['window'], pointer, FLAG_BYTES, f'pass{index}-'+label+'-flags')
                items = [dict(index=i, first_three_bytes=list(data[i*48:i*48+3])) for i in range(4)]
                if items != row['items']:
                    raise ValueError('Flag decoding differs')
            elif 'window' in row:
                raise ValueError('Read outside authorized Master RAM')
        for field, label in (('current_mirror', 'current_OSD_mirror'), ('previous_mirror', 'previous_OSD_mirror')):
            if sample[field] != decode_mirror(values[label], contract):
                raise ValueError('Mirror decoding differs')
        if sample['lens_mounted'] != u32(values['lens_mounted_property']):
            raise ValueError('Mounted property decoding differs')
        rational = values['AE_rational_1603_through_1609']
        rational_words = {hex(prop): list(struct.unpack_from('<II', rational, offset))
                          for prop, offset in ((0x1603, 0), (0x1608, 28), (0x1609, 36))}
        if sample['AE_rational_words'] != rational_words:
            raise ValueError('AE rational decoding differs from original RAM bytes')
        exposure = values['exposure_1800_through_1810']
        scalars = [u32(exposure, offset) for offset in (0, 4, 8)]
        user_iso = u32(exposure, 0x40)
        ready = u32(values['exposure_group20_ready_property'])
        if (sample['exposure_words_1800_1801_1802'] != scalars or
                sample['exposure_word_1810'] != user_iso or
                sample['exposure_group20_ready'] != ready):
            raise ValueError('Exposure scalar/ready decoding differs from original RAM bytes')
        pairs = {}
        for prop, offset in ((0x1603, 0), (0x1608, 28), (0x1609, 36)):
            denominator = struct.unpack_from('<h', rational, offset)[0]
            numerator = struct.unpack_from('<i', rational, offset+4)[0]
            pairs[hex(prop)] = dict(
                address=hex(0xC253D85C+offset), raw_hex=rational[offset:offset+8].hex(),
                words=[f'{word:08X}' for word in rational_words[hex(prop)]],
                signed_denominator_low16=denominator, signed_numerator=numerator,
                positive_scale=denominator > 0,
                numerator_over_denominator=str(Fraction(numerator, denominator))
                if denominator > 0 else None)
        samples.append(dict(index=index, current_mirror=sample['current_mirror'],
                            user_ISO_code=user_iso,
                            user_ISO_text_candidate=contract['ISO_entries'][user_iso]['text']
                            if user_iso < len(contract['ISO_entries']) else None,
                            AE_rational_pairs=pairs,
                            exposure_words_1800_1801_1802=scalars,
                            exposure_group20_ready=ready,
                            OSD_render_state=list(values['OSD_render_state']),
                            lens_mounted=sample['lens_mounted'], descriptors=sample['descriptors']))
    checked, used = [], 0
    session = diagnostic = False
    terminal = []
    for ordinal, tx in enumerate(transactions, 1):
        op, params = int(tx['operation'], 16), tuple(int(p, 16) for p in tx['parameters'])
        envelope = containers(files[tx['command_file']])
        command_body = struct.pack('<'+'I'*len(params), *params)
        if envelope != [(1, op, tx['tid'], command_body)] or (tx['ordinal'], tx['tid']) != (ordinal, ordinal-1):
            raise ValueError('Outgoing command identity/order differs')
        memory = op == 0x94FF and len(params) == 5 and params[0] == 0xF036
        permitted = (op, params) in {(0x1001, ()), (0x1002, (1,)), (0x1003, ()),
                                    (0x94FD, (0xF001, 0, 0, 0, 0)),
                                    (0x94FD, (0xF002, 0, 0, 0, 0))}
        permitted |= op == 0x1015 and params in [(c,) for c in (0x5001, 0x5007, 0x500D, 0x500F, 0x500E)]
        if memory:
            if used >= len(expected):
                raise ValueError('Unexpected RAM read')
            role, address, payload = expected[used]
            permitted |= session and diagnostic and params == (0xF036, address, len(payload), 0, 0) and tx['role'] == role
        if not permitted:
            raise ValueError('Command outside retained read contract')
        incoming = containers(b''.join(files[p] for p in tx['bulk_reads']))
        if any(row[2] != tx['tid'] for row in incoming) or len(incoming) not in (1, 2):
            raise ValueError('Incoming order/container count differs')
        if incoming[-1][:3] != (3, 0x2001, tx['tid']):
            raise ValueError('Terminal response unsuccessful')
        body = incoming[-1][3]
        if len(body) % 4:
            raise ValueError('Response parameter length differs')
        parameters = list(struct.unpack('<'+'I'*(len(body)//4), body))
        if parameters != tx['response_parameters'] or int(tx['response_code'], 16) != 0x2001:
            raise ValueError('Saved response differs from original bytes')
        if op in (0x94FD, 0x94FF) and parameters[:1] != [0x2001]:
            raise ValueError('Vendor status unsuccessful')
        data = b''
        if len(incoming) == 2:
            if incoming[0][:3] != (2, op, tx['tid']):
                raise ValueError('Unexpected DATA container')
            data = incoming[0][3]
            if data != files[tx['payload_file']] or sha(data) != tx['payload_sha256']:
                raise ValueError('Payload identity differs')
        if len(data) != tx['payload_bytes']:
            raise ValueError('Declared DATA size differs')
        if memory:
            if data != expected[used][2]:
                raise ValueError('Sample bytes differ from USB RAM payload')
            used += 1
        if op == 0x1015:
            value = summary['normal_properties'][hex(params[0])]
            if value != dict(raw_hex=data.hex(), unsigned_value=int.from_bytes(data, 'little')):
                raise ValueError('Standard property differs from original bytes')
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
                raise ValueError('CloseSession before F002')
            session = False
            terminal.append('CloseSession')
        checked.append(dict(ordinal=ordinal, tid=tx['tid'], operation=hex(op), parameters=tx['parameters']))
    if used != len(expected) or session or diagnostic or terminal != ['0xf001', '0xf002', 'CloseSession']:
        raise ValueError('Incomplete read/session sequence')
    if not summary['complete'] or summary['transaction_count'] != len(transactions) or not summary['execution_sources_unchanged']:
        raise ValueError('Capture incomplete or source changed')
    return dict(schema='z62.camera-exposure-display-audit/1', generated=now(), verified=True,
                capture=identity(directory/'manifest.json'), reference_ROM=reference,
                files_verified=len(files), frozen_window_literals=names,
                transactions_verified=len(checked), bounded_RAM_read_transactions=used,
                recorded_memory_or_property_write_commands=0,
                diagnostic_exited=True, session_closed=True, USB_release_reported=summary['USB_release_ok'],
                physical_cold_boot_observed=False, screen_text_observed=False,
                original_callback_execution_observed=False,
                normal_properties=summary['normal_properties'],
                operator_state=summary['operator_state'],
                started=summary['started'], finished=summary['finished'],
                rational_representation='Signed low halfword of word0 is scale D; signed word1 is N. '
                                        'N/D is an internal exposure encoding, not a direct time or ISO number. '
                                        'Positive scale is an arithmetic usability check, not physical validation.',
                samples=samples, transactions=checked)


def operator_comparison(result, path):
    observation = read(path)
    if observation['schema'] != 'z62.camera-exposure-operator-observation/1':
        raise ValueError('Unexpected operator observation schema')
    if observation['capture_manifest'] != result['capture']:
        raise ValueError('Operator observation belongs to a different capture')
    shutter = Fraction(observation['reported_shutter_seconds'])
    if shutter <= 0:
        raise ValueError('Operator shutter time must be positive')
    current_iso = int(observation['reported_current_ISO'])
    user_iso = int(observation['reported_user_ISO'])
    if current_iso <= 0 or user_iso <= 0:
        raise ValueError('Operator ISO values must be positive')
    samples = []
    for sample in result['samples']:
        tv = sample['AE_rational_pairs']['0x1608']
        sv = sample['AE_rational_pairs']['0x1609']
        row = dict(index=sample['index'],
                   current_ISO_ROM_text_matches_operator=
                   sample['current_mirror']['ISO_text_candidate'] == str(current_iso),
                   user_ISO_ROM_text_matches_operator=
                   sample['user_ISO_text_candidate'] == str(user_iso))
        if tv['positive_scale']:
            value = tv['signed_numerator'] / tv['signed_denominator_low16']
            row.update(shutter_APEX_candidate_seconds=2.0 ** -value,
                       shutter_APEX_candidate_error_EV=value + math.log2(float(shutter)))
        if sv['positive_scale']:
            value = sv['signed_numerator'] / sv['signed_denominator_low16']
            row.update(ISO_APEX_candidate=3.125 * 2.0 ** value,
                       ISO_APEX_candidate_matches_operator=
                       math.isclose(3.125 * 2.0 ** value, current_iso, rel_tol=1e-9))
        samples.append(row)
    return dict(observation_source=identity(path), observation=observation,
                source_kind='direct user report, separate from USB capture',
                captured_screen_pixels=False,
                PTP_shutter_matches_operator=
                Fraction(result['normal_properties']['0x500d']['unsigned_value'], 10000) == shutter,
                PTP_user_ISO_matches_operator=
                result['normal_properties']['0x500f']['unsigned_value'] == user_iso,
                conversion_status='APEX candidates compared with standard PTP and operator display; '
                                  'actual conversion RAM tables and hardware feedback not validated',
                samples=samples)


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('run')
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--operator-observation', type=Path,
                        help='Optional capture-bound direct user display confirmation; no USB access')
    args = parser.parse_args()
    result = audit(ROOT/'results'/args.run)
    if args.operator_observation is not None:
        observation_path = (args.operator_observation if args.operator_observation.is_absolute()
                            else ROOT/args.operator_observation).resolve()
        observation_path.relative_to((ROOT/'results').resolve())
        result['operator_comparison'] = operator_comparison(result, observation_path)
    output = (args.out if args.out.is_absolute() else ROOT/args.out).resolve()
    output.relative_to((ROOT/'results').resolve())
    output.mkdir(parents=True, exist_ok=False)
    result['execution_source'] = identity(Path(__file__))
    save(output/'report.json', result)
    lines = ['# Original-camera exposure display read audit', '',
             f"Verified {result['files_verified']} retained files, {result['transactions_verified']} transactions, "
             f"and {result['bounded_RAM_read_transactions']} bounded RAM reads against original USB bytes.", '',
             'The F001 -> F036 -> F002 -> CloseSession sequence is verified. '
             'Recorded RAM and property write commands: zero.', '',
             'These are sequential observations of a running camera. ROM text candidates do not establish '
             'screen pixels, rendering-time state, physical cold boot, or hardware feedback.', '',
             '| Pass | mirror[0] | Current ISO code | User ISO code | Selected consumer field | ROM text candidate |',
             '|---|---|---|---|---|---|']
    for sample in result['samples']:
        mirror = sample['current_mirror']
        lines.append(f"| {sample['index']} | {mirror['state_byte_0']} | {mirror['raw_ISO']} | "
                     f"{mirror['raw_user_ISO']} | {mirror['selected_ISO_field']} | {mirror['ISO_text_candidate']} |")
    lines += ['', result['rational_representation'], '',
              '| Pass | Property | RAM address | Word0 | Word1 | Signed D | Signed N | N/D with positive scale |',
              '|---|---|---|---|---|---|---|---|']
    for sample in result['samples']:
        for prop, pair in sample['AE_rational_pairs'].items():
            lines.append(f"| {sample['index']} | {prop} | {pair['address']} | {pair['words'][0]} | "
                         f"{pair['words'][1]} | {pair['signed_denominator_low16']} | "
                         f"{pair['signed_numerator']} | {pair['numerator_over_denominator']} |")
    if 'operator_comparison' in result:
        comparison = result['operator_comparison']
        observation = comparison['observation']
        lines += ['', '## Operator display corroboration', '',
                  'This direct user report was supplied after the USB capture and refers to that capture. '
                  'It is retained separately from machine-observed screen pixels.', '',
                  f"User report: {observation['quote_zh']}", '',
                  f"Reported shutter: {observation['reported_shutter_seconds']} seconds; "
                  f"current automatic ISO: {observation['reported_current_ISO']}; "
                  f"manual ISO setting: {observation['reported_user_ISO']}.", '',
                  f"Standard PTP shutter matches: {comparison['PTP_shutter_matches_operator']}; "
                  f"standard PTP user ISO matches: {comparison['PTP_user_ISO_matches_operator']}.", '',
                  comparison['conversion_status']+'.', '',
                  '| Pass | Shutter APEX candidate, seconds | Shutter error, EV | ISO APEX candidate | Current/user ISO ROM text matches |',
                  '|---|---|---|---|---|']
        for sample in comparison['samples']:
            lines.append(f"| {sample['index']} | {sample.get('shutter_APEX_candidate_seconds')} | "
                         f"{sample.get('shutter_APEX_candidate_error_EV')} | {sample.get('ISO_APEX_candidate')} | "
                         f"{sample['current_ISO_ROM_text_matches_operator']}/"
                         f"{sample['user_ISO_ROM_text_matches_operator']} |")
    (output/'report.md').write_text('\n'.join(lines)+'\n')
    save(output/'manifest.json', dict(files=[identity(p, output) for p in sorted(output.iterdir()) if p.is_file()]))
    print(json.dumps(dict(report=str(output/'report.md'), verified=True,
                          transactions=result['transactions_verified']), ensure_ascii=False))


if __name__ == '__main__':
    main()
