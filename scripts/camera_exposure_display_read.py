"""Read the original exposure display contract of the connected Z6II.

Uses the established F001/F036/F002 lifecycle and bounded Master RAM reads.
The mode/lens condition is supplied by the operator; this script changes no
camera property. ROM text candidates are separate from observed screen text.
"""
import argparse
from datetime import datetime
from pathlib import Path
import struct
import uuid

from z62_common import ROOT, identity, now, save
from camera_native_ui_read import (Connection, PROPERTY_CODES, ROM_FILE,
                                   ROM_SHA256, allowed, parse_identity, sha)


DISPLAY_RAM_WINDOWS = (
    (0xC202BF40, 0x384, 'current_OSD_mirror'),
    (0xC202C2C4, 0x384, 'previous_OSD_mirror'),
    (0xC202CA48, 4, 'secondary_mirror_400'),
    (0xC202E344, 16, 'widget_suppression'),
    (0xC181DABD, 4, 'OSD_render_state'),
    (0xC1821554, 8, 'ISO_visibility_cache'),
    (0xC1821558, 8, 'ISO_visibility_source'),
    (0xC181DC0C, 12, 'shutter_aperture_display_states'),
    (0xC181E988, 48, 'ISO_descriptor'),
    (0xC181FA58, 48, 'shutter_aperture_descriptor'),
    (0xC253DC28, 68, 'exposure_1800_through_1810'),
    (0xC253D85C, 44, 'AE_rational_1603_through_1609'),
    (0xC253E618, 4, 'lens_mounted_property'),
    (0xC253D72C, 4, 'exposure_group20_ready_property'),
)
DESCRIPTORS = (('ISO', 0xC181E988, 'ISO_descriptor'),
               ('shutter_aperture', 0xC181FA58, 'shutter_aperture_descriptor'))
FLAG_BYTES = 4 * 48
BASE = 0x10020000


def u32(data, offset=0):
    return struct.unpack_from('<I', data, offset)[0]


def rom_contract(rom):
    if sha(rom) != ROM_SHA256:
        raise ValueError('Master ROM identity differs')
    literals = {
        0x104B00DC: 0x10956808, 0x104B00E0: 0x109566C4,
        0x1052759C: 0xC202BF40, 0x105275A0: 0xC181DABD,
        0x105587B4: 0xC202BF40, 0x105587B8: 0xC202C2C4,
        0x105587C8: 0xC202E344, 0x105587CC: 0xC202C648,
        0x105587D0: 0xC181DABD, 0x10558C24: 0xC1821554,
        0x1055CF24: 0xC181DC0C, 0x1055CF28: 0xC181DC13,
        0x1094F808: 0xC181E988, 0x1094F854: 0xC181FA58,
    }
    for address, expected in literals.items():
        if u32(rom, address-BASE) != expected:
            raise ValueError('Original display literal differs: '+hex(address))
    entries = []
    for index in range(81):
        key, value = struct.unpack_from('<II', rom, 0x10956808-BASE+index*8)
        if (key, value) != (index, index):
            raise ValueError('ISO lookup entry differs')
        pointer = u32(rom, 0x109566C4-BASE+index*4)
        offset = pointer-BASE
        if not 0 <= offset < len(rom):
            raise ValueError('ISO string pointer outside ROM')
        raw = rom[offset:offset+32].split(b'\0', 1)[0]
        entries.append(dict(code=index, pointer=hex(pointer), text=raw.decode('ascii'),
                            raw_hex=raw.hex()))
    if entries[80]['text'] != 'AUTO':
        raise ValueError('Original ISO AUTO text differs')
    return dict(ISO_entries=entries, literal_words=[dict(address=hex(a), value=hex(v))
                                                  for a, v in literals.items()])


def decode_mirror(data, contract):
    alternate = data[0] == 5
    code = data[0x1F1 if alternate else 0x8D]
    raw = data[0x172 if alternate else 0x171]
    return dict(
        state_byte_0=data[0], state_byte_8=data[8],
        raw_shutter=u32(data, 0x16C), raw_aperture=data[0x170],
        raw_ISO=data[0x171], raw_user_ISO=data[0x172],
        clamped_shutter=u32(data, 0x1C), clamped_aperture=u32(data, 0x20),
        clamped_ISO=data[0x8D], clamped_user_ISO=data[0x1F1],
        selected_ISO_raw=raw, selected_ISO_code=code,
        selected_ISO_field='0x1f1' if alternate else '0x8d',
        ISO_renderer_range_allows_raw=raw < 81,
        ISO_text_candidate=contract['ISO_entries'][code]['text'] if code < 81 else None,
        ISO_number_widget_slot=9 if code > 64 else 8,
        shutter_display_word_24=u32(data, 0x24), aperture_display_word_28=u32(data, 0x28),
        screen_text_observed=False,
        state_byte_0_business_name='not established; 5 is a renderer branch condition',
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--passes', type=int, choices=range(1, 5), default=2)
    parser.add_argument('--operator-state', default='not supplied')
    args = parser.parse_args(argv)
    contract = rom_contract(ROM_FILE.read_bytes())
    directory = args.out or ROOT/'results'/(
        datetime.now().strftime('%Y%m%d-%H%M%S')+'-camera-exposure-display-'+uuid.uuid4().hex[:6])
    directory = (directory if directory.is_absolute() else ROOT/directory).resolve()
    directory.relative_to((ROOT/'results').resolve())
    directory.mkdir(parents=True, exist_ok=False)
    sources = []
    for path in (Path(__file__).resolve(), ROOT/'scripts/camera_native_ui_read.py',
                 ROOT/'scripts/camera_battery_read.py', ROOT/'scripts/z62_common.py'):
        target = directory/'execution-sources'/path.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(path.read_bytes())
        sources.append(dict(**identity(target, directory),
                            original_relative_path=str(path.relative_to(ROOT))))
    report = dict(
        schema='z62.camera-exposure-display-read/1', started=now(), complete=False,
        reference_ROM=identity(ROM_FILE), operator_state=args.operator_state,
        physical_ROM_bytes_verified=False, physical_cold_boot_observed=False,
        atomic_snapshot=False, original_callback_execution_observed=False,
        screen_text_observed=False, memory_or_property_writes=0, camera_reset=False,
        command_allowlist='standard reads; F001/F002; bounded RAM F036 <=128 bytes',
        fixed_RAM_windows=[dict(address=hex(a), bytes=n, label=l) for a, n, l in DISPLAY_RAM_WINDOWS],
        dynamic_RAM_rule='actual descriptor +0x2c pointer; four 48-byte items; Master RAM only',
        execution_sources=sources, original_ROM_contract=contract,
        normal_properties={}, samples=[])
    connection = None
    print('Camera exposure display read: '+str(directory), flush=True)
    save(directory/'summary.json', report)
    try:
        connection = Connection(directory)
        connection.windows = list(DISPLAY_RAM_WINDOWS)
        report['USB'] = connection.details
        connection.util.claim_interface(connection.dev, connection.interface)
        connection.claimed = True
        connection.require(0x1002, (1,), 'OpenSession')
        connection.session_owned = True
        info = parse_identity(connection.require(0x1001, (), 'GetDeviceInfo'))
        report['identity'] = info
        if (info['model'], info['version']) != ('Z 6_2', 'V1.70'):
            raise ValueError('Connected model/version differs from locked ROM')
        for code in PROPERTY_CODES:
            payload = connection.require(0x1015, (code,), 'normal-property-'+hex(code))
            if payload is None:
                raise ValueError('Missing standard property payload')
            report['normal_properties'][hex(code)] = dict(
                raw_hex=payload.hex(), unsigned_value=int.from_bytes(payload, 'little'))
        connection.diagnostic_attempted = True
        connection.require(0x94FD, (0xF001, 0, 0, 0, 0), 'EnterF001')
        connection.diagnostic_active = True
        for index in range(args.passes):
            started, values, windows = now(), {}, []
            for address, size, label in DISPLAY_RAM_WINDOWS:
                data, retained = connection.read(address, size, f'pass{index+1}-'+label)
                values[label] = data
                windows.append(retained)
            descriptors = []
            for label, address, key in DESCRIPTORS:
                pointer = u32(values[key], 0x2C)
                row = dict(label=label, descriptor_address=hex(address),
                           pointer_slot=hex(address+0x2C), flags_pointer=hex(pointer),
                           bytes=FLAG_BYTES)
                if 0xC0000000 <= pointer <= 0xD0000000-FLAG_BYTES:
                    connection.windows.append((pointer, FLAG_BYTES, label+'_flags'))
                    data, retained = connection.read(pointer, FLAG_BYTES, f'pass{index+1}-'+label+'-flags')
                    row.update(window=retained,
                               items=[dict(index=i, first_three_bytes=list(data[i*48:i*48+3]))
                                      for i in range(4)])
                else:
                    row['status'] = 'pointer outside Master RAM; no read attempted'
                descriptors.append(row)
            rational = values['AE_rational_1603_through_1609']
            sample = dict(
                index=index+1, started=started, finished=now(), windows=windows,
                current_mirror=decode_mirror(values['current_OSD_mirror'], contract),
                previous_mirror=decode_mirror(values['previous_OSD_mirror'], contract),
                mirror_bytes_equal=values['current_OSD_mirror'] == values['previous_OSD_mirror'],
                descriptors=descriptors,
                OSD_render_state=list(values['OSD_render_state']),
                widget_suppression=list(values['widget_suppression']),
                shutter_aperture_states=list(values['shutter_aperture_display_states']),
                exposure_words_1800_1801_1802=list(struct.unpack_from('<III', values['exposure_1800_through_1810'])),
                exposure_word_1810=u32(values['exposure_1800_through_1810'], 0x40),
                AE_rational_words={hex(prop): list(struct.unpack_from('<II', rational, offset))
                                   for prop, offset in ((0x1603, 0), (0x1608, 28), (0x1609, 36))},
                lens_mounted=u32(values['lens_mounted_property']),
                exposure_group20_ready=u32(values['exposure_group20_ready_property']))
            report['samples'].append(sample)
            save(directory/'summary.json', report)
            print('Sample '+str(index+1)+': '+str(sample['current_mirror'])+
                  ' descriptor flags='+str([d.get('items') for d in descriptors]), flush=True)
        report['complete'] = True
    except BaseException as exc:
        report['error'] = type(exc).__name__+': '+str(exc)
        print(report['error'], flush=True)
    finally:
        if connection is not None:
            connection.cleanup(report)
            report['transaction_count'] = len(connection.transactions)
        report['finished'] = now()
        report['execution_sources_unchanged'] = all(
            identity(ROOT/s['original_relative_path'])['sha256'] == s['sha256'] for s in sources)
        save(directory/'summary.json', report)
        save(directory/'manifest.json', dict(
            schema='z62.camera-exposure-display-read-manifest/1',
            files=[identity(p, directory) for p in sorted(directory.iterdir()) if p.is_file()],
            execution_files=sources))
        print('Saved: '+str(directory), flush=True)
    return int(not (report['complete'] and report.get('F002_exit_ok') and
                    report.get('CloseSession_ok') and report.get('USB_release_ok') and
                    report['execution_sources_unchanged']))


if __name__ == '__main__':
    raise SystemExit(main())
