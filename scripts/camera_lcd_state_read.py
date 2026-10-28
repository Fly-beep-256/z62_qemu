"""Read the native LCD source/region state from a connected Z6II C1.70.

Reuse the retained F001/F036/F002/CloseSession lifecycle. Fixed original-ROM
pointer slots authorize only the small Master RAM windows listed below.
No peripheral MMIO, firmware ROM, property write or key command is sent.
The samples are sequential running-state references, not physical cold boot.
"""
import argparse
from datetime import datetime
import struct
import uuid

from camera_native_ui_read import Connection, PROPERTY_CODES, ROM_FILE, ROM_SHA256, allowed, sha
from camera_battery_read import parse_identity
from z62_common import ROOT, identity, now, save


FIXED_WINDOWS = (
    (0xC1808554, 56, 'display_global'),
    (0xC180806C, 4, 'alternate_display_object_slot'),
    (0xC1D178DC, 8, 'source_state'),
    (0xC1D17DEC, 8, 'cache_mode'),
    (0xC181C9D0, 64, 'MENU_state_array'),
    (0xC253D85C, 44, 'AE_rational_1603_through_1609'),
    (0xC253DC28, 68, 'exposure_1800_through_1810'),
    (0xC253E618, 4, 'lens_mounted_property'),
    (0xC253D72C, 4, 'exposure_group20_ready_property'),
)
CHILD_WINDOWS = ((0x1E0, 16, 'control_parameters'),
                 (0x240, 4, 'source_gate'),
                 (0x254, 16, 'geometry'),
                 (0x510, 32, 'cache_flags'),
                 (0x1CD4, 8, 'region0_enable'))


def u32(data, offset=0):
    return struct.unpack_from('<I', data, offset)[0]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--passes', type=int, choices=(1, 2, 3), default=2)
    args = parser.parse_args(argv)
    if sha(ROM_FILE.read_bytes()) != ROM_SHA256:
        parser.error('Master ROM identity differs')
    directory = ROOT/'results'/(
        datetime.now().strftime('%Y%m%d-%H%M%S')+'-camera-lcd-state-'+uuid.uuid4().hex[:6])
    directory.mkdir(parents=True, exist_ok=False)
    sources = []
    for path in (ROOT/'scripts/camera_lcd_state_read.py', ROOT/'scripts/camera_native_ui_read.py',
                 ROOT/'scripts/camera_battery_read.py', ROOT/'scripts/z62_common.py'):
        target = directory/'execution-sources'/path.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(path.read_bytes())
        sources.append(dict(**identity(target, directory), original_relative_path=str(path.relative_to(ROOT))))
    report = dict(schema='z62.camera-lcd-state-read/1', started=now(), complete=False,
                  reference_ROM=identity(ROM_FILE), execution_sources=sources,
                  command_allowlist='standard reads; F001/F002; declared RAM F036 <=128 bytes',
                  fixed_RAM_windows=[dict(address=hex(a), bytes=n, label=l) for a, n, l in FIXED_WINDOWS],
                  pointer_authorization='only object/child at original C1808574/C1808588; bounded RAM windows',
                  memory_or_property_writes=0, peripheral_MMIO_read=False, camera_reset=False,
                  atomic_snapshot=False, physical_cold_boot_observed=False,
                  physical_ROM_bytes_verified=False, normal_properties={}, samples=[])
    connection = None
    print('Camera LCD read: '+str(directory), flush=True)
    try:
        connection = Connection(directory)
        connection.windows = list(FIXED_WINDOWS)
        for a, n, _ in FIXED_WINDOWS:
            if not allowed(0x94FF, (0xF036, a, n, 0, 0), connection.windows):
                raise ValueError('Declared fixed request rejected')
        report['USB'] = connection.details
        connection.util.claim_interface(connection.dev, connection.interface)
        connection.claimed = True
        connection.require(0x1002, (1,), 'OpenSession')
        connection.session_owned = True
        info = parse_identity(connection.require(0x1001, (), 'GetDeviceInfo'))
        report['identity'] = info
        if (info['model'], info['version']) != ('Z 6_2', 'V1.70'):
            raise ValueError('Connected model/version differs from locked ROM')
        print('Identity: '+info['model']+' '+info['version'], flush=True)
        for code in PROPERTY_CODES:
            raw = connection.require(0x1015, (code,), 'normal-property-'+hex(code))
            if raw is None:
                raise ValueError('Missing standard property payload')
            report['normal_properties'][hex(code)] = dict(raw_hex=raw.hex(), unsigned_value=int.from_bytes(raw, 'little'))
        connection.diagnostic_attempted = True
        connection.require(0x94FD, (0xF001, 0, 0, 0, 0), 'EnterF001')
        connection.diagnostic_active = True
        for index in range(args.passes):
            connection.windows = list(FIXED_WINDOWS)
            sample = dict(index=index+1, started=now(), windows=[], pointer_windows=[])
            values = {}
            for a, n, label in FIXED_WINDOWS:
                raw, retained = connection.read(a, n, f'pass{index+1}-'+label)
                values[label] = raw
                sample['windows'].append(retained)
            obj = u32(values['display_global'], 0x20)
            child = u32(values['display_global'], 0x34)
            targets = [(obj, 16, 'display_object')]
            targets += [(child+off, size, 'child_'+label) for off, size, label in CHILD_WINDOWS]
            for a, n, label in targets:
                row = dict(address=hex(a), bytes=n, label=label)
                if 0xC0000000 <= a <= 0xD0000000-n:
                    connection.windows.append((a, n, label))
                    raw, retained = connection.read(a, n, f'pass{index+1}-'+label)
                    values[label] = raw
                    row.update(**retained, raw_hex=raw.hex())
                else:
                    row['status'] = 'outside_Master_RAM; no read attempted'
                sample['pointer_windows'].append(row)
            rational = values['AE_rational_1603_through_1609']
            sample.update(object_pointer=hex(obj), child_pointer=hex(child),
                          source_state_byte=values['source_state'][0], cache_mode_byte=values['cache_mode'][1],
                          MENU_state_indices_0_1=list(struct.unpack_from('<II', values['MENU_state_array'], 8)),
                          AE_rational_words={hex(p): list(struct.unpack_from('<II', rational, off))
                                             for p, off in ((0x1603, 0), (0x1608, 28), (0x1609, 36))},
                          exposure_words_1800_1801_1802=list(struct.unpack_from('<III', values['exposure_1800_through_1810'])),
                          lens_mounted_property=u32(values['lens_mounted_property']),
                          exposure_group20_ready_property=u32(values['exposure_group20_ready_property']))
            for label, offset in (('display_object', 4), ('child_source_gate', 0), ('child_region0_enable', 4)):
                if label in values:
                    sample[label+'_value'] = u32(values[label], offset)
            sample['finished'] = now()
            report['samples'].append(sample)
            save(directory/'summary.json', report)
            print('Sample '+str(index+1)+': source_state='+str(sample['source_state_byte'])+
                  ' source_gate='+str(sample.get('child_source_gate_value'))+
                  ' region0='+str(sample.get('child_region0_enable_value'))+
                  ' AE='+str(sample['AE_rational_words']), flush=True)
        report['complete'] = True
    except BaseException as exc:
        report['error'] = type(exc).__name__+': '+str(exc)
        print(report['error'], flush=True)
    finally:
        if connection is not None:
            connection.cleanup(report)
            report['transaction_count'] = len(connection.transactions)
        report['finished'] = now()
        save(directory/'summary.json', report)
        files = [identity(p, directory) for p in sorted(directory.iterdir()) if p.is_file()]
        save(directory/'manifest.json', dict(schema='z62.camera-lcd-state-manifest/1', files=files, execution_sources=sources))
        print('Saved: '+str(directory), flush=True)
    return int(not (report['complete'] and report.get('F002_exit_ok') and
                    report.get('CloseSession_ok') and report.get('USB_release_ok')))


if __name__ == '__main__':
    raise SystemExit(main())
