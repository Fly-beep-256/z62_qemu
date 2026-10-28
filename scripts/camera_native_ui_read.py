"""Read fixed original MENU/exposure state from an explicitly connected Z6II.

Uses the previously retained F036 Master read and F001/F002 diagnostic
lifecycle. The closed command set contains no memory/property writes, reset,
capture or battery commands. These sequential reads are a running-camera
reference, not an atomic snapshot or an observation of physical cold boot.
"""
import argparse
from datetime import datetime
import hashlib
from pathlib import Path
import struct
import sys
import time
import uuid

from z62_common import ROOT, identity, now, save
from camera_battery_read import parse_identity


ROM_FILE = ROOT / 'inputs/firmware/master-original-with-crc.bin'
ROM_SHA256 = 'bb83613121f843d65101da936d942acdc513d86dbd3abc26259d0d870d03f5d4'
RAM_WINDOWS = ((0xC181C9D0, 64, 'MENU_state_array'),
               (0xC1811E50, 144, 'application_manager_and_reports'),
               (0xC2098600, 176, 'observed_MENU_notification_contexts'),
               (0xC181B5E0, 96, 'MENU_request_context'),
               (0xC181C580, 64, 'MENU_control_flag_wrapper'),
               (0xC253D85C, 44, 'AE_rational_1603_through_1609'),
               (0xC253DC28, 68, 'exposure_1800_through_1810'),
               (0xC253E22C, 144, 'SAISO_gate_properties'),
               (0xC253E314, 96, 'lens_property_block'),
               (0xC25616F0, 64, 'ISO_user_properties'),
               (0xC1866CD4, 144, 'AE_descriptor_manager'),
               (0xC23C44B0, 96, 'AE_callback_blob_input_slots'),
               (0xC23C8B00, 640, 'AE_internal_storage'),
               (0xC186E528, 96, 'AE_range_wrappers'),
               (0xC2539C18, 80, 'AE_range_data'),
               (0xC1875350, 104, 'SAISO_workspace'),
               (0xC25C4A88, 84, 'SAISO_publication_storage'),
               (0xC202C0A0, 64, 'OSD_exposure_mirror'))
PROPERTY_CODES = (0x5001, 0x5007, 0x500D, 0x500F, 0x500E)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def allowed(op, params, windows):
    if (op, params) in {(0x1001, ()), (0x1002, (1,)), (0x1003, ()),
                       (0x94FD, (0xF001, 0, 0, 0, 0)),
                       (0x94FD, (0xF002, 0, 0, 0, 0))}:
        return True
    if op == 0x1015:
        return len(params) == 1 and params[0] in PROPERTY_CODES
    if op == 0x94FF and len(params) == 5:
        command, address, size, zero1, zero2 = params
        return (command == 0xF036 and zero1 == zero2 == 0 and 0 < size <= 128
                and any(base <= address and address+size <= base+length
                        for base, length, _ in windows))
    return False


class Connection:
    def __init__(self, directory):
        import usb.backend.libusb1
        import usb.core
        import usb.util
        self.util, self.directory = usb.util, directory
        self.transactions, self.windows = [], list(RAM_WINDOWS)
        self.tid, self.claimed = 0, False
        self.session_owned = self.diagnostic_attempted = self.diagnostic_active = False
        backend = usb.backend.libusb1.get_backend(
            find_library=lambda _: str(ROOT / 'runtime/lib/libusb-1.0.0.dylib'))
        if backend is None:
            raise RuntimeError('Package-contained libusb could not be loaded')
        devices = list(usb.core.find(find_all=True, idVendor=0x04B0, idProduct=0x044C, backend=backend))
        if len(devices) != 1:
            raise RuntimeError(f'Expected one connected 04B0:044C camera, found {len(devices)}')
        self.dev = devices[0]
        interfaces = [i for i in self.dev.get_active_configuration()
                      if (i.bInterfaceClass, i.bInterfaceSubClass, i.bInterfaceProtocol,
                          i.bAlternateSetting) == (6, 1, 1, 0)]
        if len(interfaces) != 1:
            self.util.dispose_resources(self.dev)
            raise RuntimeError('Expected one active PTP interface')
        interface = interfaces[0]
        self.interface = interface.bInterfaceNumber
        inputs = [e for e in interface if e.bmAttributes & 3 == 2 and e.bEndpointAddress & 0x80]
        outputs = [e for e in interface if e.bmAttributes & 3 == 2 and not e.bEndpointAddress & 0x80]
        if len(inputs) != 1 or len(outputs) != 1:
            self.util.dispose_resources(self.dev)
            raise RuntimeError('Expected one bulk IN and one bulk OUT endpoint')
        self.ep_in, self.ep_out = inputs[0].bEndpointAddress, outputs[0].bEndpointAddress
        self.details = dict(vendor='0x04B0', product='0x044C', bus=self.dev.bus,
                            address=self.dev.address, interface=self.interface,
                            bulk_in=hex(self.ep_in), bulk_out=hex(self.ep_out))

    def require(self, op, params, role):
        params = tuple(params)
        if not allowed(op, params, self.windows):
            raise ValueError('Operation outside the closed read allowlist')
        if op == 0x94FF and not self.diagnostic_active:
            raise ValueError('F036 read outside owned F001/F002 lifecycle')
        tid = self.tid
        self.tid += 1
        prefix = f'{len(self.transactions)+1:03d}-{role}'
        row = dict(ordinal=len(self.transactions)+1, tid=tid, operation=hex(op),
                   parameters=[hex(x) for x in params], role=role, started=now(),
                   command_file=prefix+'-cmd.bin', bulk_reads=[])
        self.transactions.append(row)
        packet = struct.pack('<IHHI', 12+len(params)*4, 1, op, tid)
        packet += struct.pack('<'+'I'*len(params), *params)
        (self.directory/row['command_file']).write_bytes(packet)
        try:
            if self.dev.write(self.ep_out, packet, timeout=5000) != len(packet):
                raise RuntimeError('Short USB command write')
            pending, payload = bytearray(), None
            deadline = time.monotonic()+20
            for index in range(1, 129):
                remaining = deadline-time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('PTP response deadline')
                raw = bytes(self.dev.read(self.ep_in, 65536,
                            timeout=max(1, min(5000, int(remaining*1000)))))
                filename = prefix+f'-in-{index:02d}.bin'
                (self.directory/filename).write_bytes(raw)
                row['bulk_reads'].append(filename)
                pending.extend(raw)
                while len(pending) >= 12:
                    length, kind, code, received_tid = struct.unpack_from('<IHHI', pending)
                    if not 12 <= length <= 1048576 or received_tid != tid:
                        raise ValueError('Invalid PTP container header')
                    if len(pending) < length:
                        break
                    body = bytes(pending[12:length])
                    del pending[:length]
                    if kind == 2 and code == op and payload is None:
                        payload = body
                    elif kind == 3 and len(body) % 4 == 0 and not pending:
                        response = list(struct.unpack('<'+'I'*(len(body)//4), body))
                        row.update(response_code=hex(code), response_parameters=response,
                                   payload_bytes=len(payload) if payload is not None else 0)
                        if payload is not None:
                            row.update(payload_file=prefix+'-payload.bin', payload_sha256=sha(payload))
                            (self.directory/row['payload_file']).write_bytes(payload)
                        if code != 0x2001 or op in (0x94FD, 0x94FF) and response[:1] != [0x2001]:
                            raise RuntimeError(f'{role}: response={hex(code)}, parameters={response}')
                        return payload
                    else:
                        raise ValueError('Unexpected PTP container')
            raise TimeoutError('No terminal PTP response')
        except BaseException as exc:
            row['error'] = type(exc).__name__+': '+str(exc)
            raise
        finally:
            row['finished'] = now()
            save(self.directory/'transactions.json', self.transactions)

    def read(self, address, size, label):
        data = bytearray()
        for offset in range(0, size, 128):
            length = min(128, size-offset)
            part = self.require(0x94FF, (0xF036, address+offset, length, 0, 0), label+f'-{offset:04x}')
            if part is None or len(part) != length:
                raise ValueError('F036 payload length differs')
            data.extend(part)
        target = self.directory/(label+'.bin')
        target.write_bytes(data)
        return bytes(data), dict(address=hex(address), **identity(target, self.directory))

    def cleanup(self, report):
        if self.session_owned and self.diagnostic_attempted:
            try:
                self.require(0x94FD, (0xF002, 0, 0, 0, 0), 'ExitF002')
                self.diagnostic_active = False
                report['F002_exit_ok'] = True
            except BaseException as exc:
                report['F002_error'] = str(exc)
        if self.session_owned:
            try:
                self.require(0x1003, (), 'CloseSession')
                report['CloseSession_ok'] = True
            except BaseException as exc:
                report['CloseSession_error'] = str(exc)
        try:
            if self.claimed:
                self.util.release_interface(self.dev, self.interface)
            self.util.dispose_resources(self.dev)
            report['USB_release_ok'] = True
        except BaseException as exc:
            report['USB_release_error'] = str(exc)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    ap.add_argument('--out', type=Path)
    ap.add_argument('--passes', type=int, choices=range(1, 5), default=2)
    args = ap.parse_args(argv)
    rom = ROM_FILE.read_bytes()
    if sha(rom) != ROM_SHA256:
        ap.error('Master ROM identity differs')
    directory = args.out or ROOT/'results'/(
        datetime.now().strftime('%Y%m%d-%H%M%S')+'-camera-native-ui-'+uuid.uuid4().hex[:6])
    if not directory.is_absolute():
        directory = ROOT/directory
    directory = directory.resolve()
    directory.relative_to(ROOT/'results')
    directory.mkdir(parents=True, exist_ok=False)
    report = dict(schema='z62.camera-native-ui-read/1', started=now(), complete=False,
                  reference_ROM=identity(ROM_FILE), command_allowlist='standard reads; F001/F002; bounded F036',
                  memory_or_property_writes=0, camera_reset=False, atomic_snapshot=False,
                  physical_cold_boot_observed=False, original_callback_execution_observed=False,
                  normal_properties={}, ROM_windows=[], samples=[],
                  physical_ROM_bytes_verified=False,
                  reference_identity_scope='package ROM SHA256 plus camera GetDeviceInfo model/version; no physical ROM read',
                  prior_ROM_read_rejection='F036 ROM read returned Nikon status 0x201D in 20261026-003332-camera-native-ui-4127df; RAM-only follow-up')
    connection = None
    print('Camera read: '+str(directory), flush=True)
    try:
        connection = Connection(directory)
        report['USB'] = connection.details
        connection.util.claim_interface(connection.dev, connection.interface)
        connection.claimed = True
        connection.require(0x1002, (1,), 'OpenSession')
        connection.session_owned = True
        info = parse_identity(connection.require(0x1001, (), 'GetDeviceInfo'))
        report['identity'] = info
        if info['model'] != 'Z 6_2' or info['version'] != 'V1.70':
            raise ValueError('Connected model/version differs from locked ROM')
        print('Identity: '+info['model']+' '+info['version'], flush=True)
        for code in PROPERTY_CODES:
            value = connection.require(0x1015, (code,), 'normal-property-'+hex(code))
            report['normal_properties'][hex(code)] = dict(raw_hex=value.hex(), unsigned_value=int.from_bytes(value, 'little'))
        connection.diagnostic_attempted = True
        connection.require(0x94FD, (0xF001, 0, 0, 0, 0), 'EnterF001')
        connection.diagnostic_active = True
        for index in range(args.passes):
            values, windows = {}, []
            started = now()
            for address, size, label in RAM_WINDOWS:
                data, retained = connection.read(address, size, f'pass{index+1}-'+label)
                windows.append(retained)
                values[label] = data
            # Only the two pointers actually read from their fixed original
            # callback-input slots can authorize these small additional reads.
            sources = []
            slots = values['AE_callback_blob_input_slots']
            for offset, label in ((0x18, '2015'), (0x1C, '2002')):
                pointer = int.from_bytes(slots[offset:offset+4], 'little')
                row = dict(slot_address=hex(0xC23C44B0+offset), pointer=hex(pointer), input_ID=label)
                if 0xC0000000 <= pointer <= 0xD0000000-8:
                    connection.windows.append((pointer, 8, 'observed_callback_source'))
                    data, retained = connection.read(pointer, 8, f'pass{index+1}-callback-source-'+label)
                    row.update(**retained, raw_hex=data.hex())
                else:
                    row['status'] = 'outside_Master_RAM; no read attempted'
                sources.append(row)
            states = struct.unpack_from('<II', values['MENU_state_array'], 8)
            rational = values['AE_rational_1603_through_1609']
            sample = dict(index=index+1, started=started, finished=now(), windows=windows,
                          MENU_state_indices_0_1=list(states), callback_input_sources=sources,
                          AE_rational_words={hex(prop): list(struct.unpack_from('<II', rational, offset))
                                             for prop, offset in ((0x1603, 0), (0x1608, 28), (0x1609, 36))},
                          exposure_words_1800_1801_1802=list(struct.unpack_from('<III', values['exposure_1800_through_1810'])),
                          callback_slots_are_call_time_evidence=False)
            report['samples'].append(sample)
            save(directory/'summary.json', report)
            print('Sample: '+str(index+1)+' MENU='+str(states)+' AE='+str(sample['AE_rational_words'])+
                  ' exposure='+str(sample['exposure_words_1800_1801_1802']), flush=True)
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
        sources = []
        for path in (Path(__file__), ROOT/'scripts/z62_common.py', ROOT/'scripts/camera_battery_read.py'):
            target = directory/'execution-sources'/path.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(path.read_bytes())
            sources.append(dict(**identity(target, directory), original_relative_path=str(path.relative_to(ROOT))))
        save(directory/'manifest.json', dict(schema='z62.camera-native-ui-read-manifest/1',
                                            files=files, execution_files=sources))
        print('Saved: '+str(directory), flush=True)
    return int(not (report['complete'] and report.get('F002_exit_ok') and
                    report.get('CloseSession_ok') and report.get('USB_release_ok')))


if __name__ == '__main__':
    raise SystemExit(main())
