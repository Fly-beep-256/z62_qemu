"""Explicit, bounded PTP reads of a connected Z6II C1.70 battery configuration.

Every USB command and bulk response is retained. Known F001/F002 diagnostics
are entered and exited; only F044 reads are allowed inside fixed ROM/SRAM
windows. This does not reset the body, write memory, or send a battery command.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'src/harness'))
from ex1850_cmd89 import (ROM_WINDOWS, INFO_BASE, INFO_BYTES, AUX_BASE,
                          BODY_BASE, BUILDERS, reconstruct_cmd89, xor_bytes)
from ex1850_battery_config import (ConfigObserver, GROUP4_BYTES, ROM_SHA256,
                                  ROM_WINDOWS as CONFIG_ROM_WINDOWS, convert_group4)
from ex1850_battery_task import (CLASSIFICATION_INPUT, CLASSIFICATION_ENTRY,
                                 CONTROL_BASE, classification_from_globals)

VID, PID = 0x04B0, 0x044C
RAM_WINDOWS = ((0x2001F4E8, 16, 'context'),
               (0x2001F538, 96, 'buffers'),
               (INFO_BASE, INFO_BYTES, 'config'),
               (0x2001FAF8, 136, 'config_copy_and_body'),
               (0x2000ED90, 32, 'auxiliary'))
CLASSIFICATION_ROM_WINDOWS = ((CLASSIFICATION_ENTRY, 64, 'battery_global_classification'),)
CLASSIFICATION_RAM_WINDOWS = ((CLASSIFICATION_INPUT, 8, 'battery_classification_inputs'),
                              (CONTROL_BASE + 0x14, 1, 'battery_cached_classification'))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def parse_identity(data):
    pos = 0

    def take(length):
        nonlocal pos
        if pos + length > len(data):
            raise ValueError('truncated DeviceInfo')
        value = data[pos:pos + length]
        pos += length
        return value

    def string():
        count = take(1)[0]
        return take(count * 2).decode('utf-16-le').rstrip('\0')

    take(8)  # StandardVersion, VendorExtensionID, VendorExtensionVersion.
    vendor_description = string()
    take(2)  # FunctionalMode.
    arrays = []
    for _ in range(5):
        count = struct.unpack('<I', take(4))[0]
        if count > 65536:
            raise ValueError('unbounded DeviceInfo array')
        arrays.append(list(struct.unpack('<' + 'H' * count, take(count * 2))))
    result = dict(zip(('manufacturer', 'model', 'version', 'serial'),
                      (string() for _ in range(4))))
    result.update(vendor_description=vendor_description,
                  operations=[f'0x{x:04X}' for x in arrays[0]],
                  parsed_bytes=pos, payload_bytes=len(data))
    if pos != len(data):
        raise ValueError('unexpected trailing DeviceInfo bytes')
    return result


def allowed(op, params, read_windows=None):
    ordinary = {(0x1002, (1,)), (0x1003, ()), (0x1001, ()),
                (0x1015, (0x5001,)), (0x1015, (0x500E,)),
                (0x1014, (0x5001,)), (0x942B, ())}
    if (op, params) in ordinary:
        return True
    if op == 0x94FD:
        return params in ((0xF001, 0, 0, 0, 0), (0xF002, 0, 0, 0, 0))
    if op == 0x94FF and len(params) == 5:
        command, address, length, zero1, zero2 = params
        return (command == 0xF044 and zero1 == zero2 == 0 and 0 < length <= 128
                and any(start <= address and address + length <= start + size
                        for start, size, _ in (read_windows or (*ROM_WINDOWS, *RAM_WINDOWS))))
    return False


class Connection:
    def __init__(self, directory, config_trace=False, classification_trace=False):
        import usb.backend.libusb1
        import usb.core
        import usb.util
        self.util = usb.util
        self.directory = directory
        self.tid = 0
        self.transactions = []
        self.claimed = False
        self.read_windows = [*ROM_WINDOWS, *RAM_WINDOWS]
        if config_trace:
            self.read_windows.extend(CONFIG_ROM_WINDOWS)
            self.read_windows.append((0x2000E7E8, 32, 'group4_pointer_slot'))
        if classification_trace:
            self.read_windows.extend((*CLASSIFICATION_ROM_WINDOWS, *CLASSIFICATION_RAM_WINDOWS))
        backend = usb.backend.libusb1.get_backend(
            find_library=lambda _: str(ROOT / 'runtime/lib/libusb-1.0.0.dylib'))
        if backend is None:
            raise RuntimeError('package-contained libusb could not be loaded')
        devices = list(usb.core.find(find_all=True, idVendor=VID, idProduct=PID, backend=backend))
        if len(devices) != 1:
            raise RuntimeError(f'expected one connected 04B0:044C camera, found {len(devices)}')
        self.dev = devices[0]
        interfaces = [i for i in self.dev.get_active_configuration()
                      if (i.bInterfaceClass, i.bInterfaceSubClass, i.bInterfaceProtocol,
                          i.bAlternateSetting) == (6, 1, 1, 0)]
        if len(interfaces) != 1:
            self.util.dispose_resources(self.dev)
            raise RuntimeError('expected one active PTP interface')
        self.interface = interfaces[0].bInterfaceNumber
        ep_in = [e for e in interfaces[0] if e.bmAttributes & 3 == 2 and e.bEndpointAddress & 0x80]
        ep_out = [e for e in interfaces[0] if e.bmAttributes & 3 == 2 and not e.bEndpointAddress & 0x80]
        if len(ep_in) != 1 or len(ep_out) != 1:
            self.util.dispose_resources(self.dev)
            raise RuntimeError('expected one bulk IN and one bulk OUT endpoint')
        self.ep_in, self.ep_out = ep_in[0].bEndpointAddress, ep_out[0].bEndpointAddress
        self.details = dict(vendor='0x04B0', product='0x044C', bus=self.dev.bus,
                            address=self.dev.address, interface=self.interface,
                            bulk_in=f'0x{self.ep_in:02X}', bulk_out=f'0x{self.ep_out:02X}')

    def claim(self):
        self.util.claim_interface(self.dev, self.interface)
        self.claimed = True

    def close(self):
        try:
            if self.claimed:
                self.util.release_interface(self.dev, self.interface)
        finally:
            self.util.dispose_resources(self.dev)

    def send(self, op, params, role):
        params = tuple(params)
        if not allowed(op, params, self.read_windows):
            raise ValueError('operation outside the fixed read-only allowlist')
        tid = self.tid
        self.tid += 1
        ordinal = len(self.transactions) + 1
        prefix = f'{ordinal:03d}-{role}'
        row = dict(ordinal=ordinal, tid=tid, operation=f'0x{op:04X}',
                   parameters=[f'0x{x:X}' for x in params], role=role,
                   started=datetime.now(timezone.utc).isoformat(),
                   command_file=prefix + '-cmd.bin', bulk_reads=[])
        self.transactions.append(row)
        cmd = struct.pack('<IHHI', 12 + 4 * len(params), 1, op, tid)
        cmd += struct.pack('<' + 'I' * len(params), *params)
        (self.directory / row['command_file']).write_bytes(cmd)
        try:
            if self.dev.write(self.ep_out, cmd, timeout=5000) != len(cmd):
                raise RuntimeError('short USB command write')
            pending = bytearray()
            payload = None
            deadline = time.monotonic() + 20
            for index in range(1, 513):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('PTP response deadline')
                raw = bytes(self.dev.read(self.ep_in, 65536,
                            timeout=max(1, min(5000, int(remaining * 1000)))))
                name = prefix + f'-in-{index:02d}.bin'
                (self.directory / name).write_bytes(raw)
                row['bulk_reads'].append(name)
                pending.extend(raw)
                while len(pending) >= 12:
                    size, kind, code, received_tid = struct.unpack_from('<IHHI', pending)
                    if not 12 <= size <= 1024 * 1024:
                        raise ValueError('invalid PTP container size')
                    if len(pending) < size:
                        break
                    container = bytes(pending[:size])
                    del pending[:size]
                    if received_tid != tid:
                        raise ValueError('unexpected PTP transaction ID')
                    if kind == 2:
                        if code != op or payload is not None:
                            raise ValueError('unexpected PTP data container')
                        payload = container[12:]
                    elif kind == 3:
                        if (size - 12) % 4 or pending:
                            raise ValueError('invalid terminal response or trailing bytes')
                        response_params = list(struct.unpack('<' + 'I' * ((size - 12) // 4), container[12:]))
                        row.update(response_code=f'0x{code:04X}', response_parameters=response_params,
                                   payload_bytes=len(payload) if payload is not None else 0)
                        if payload is not None:
                            row['payload_file'] = prefix + '-payload.bin'
                            row['payload_sha256'] = sha(payload)
                            (self.directory / row['payload_file']).write_bytes(payload)
                        return payload, code, response_params
                    else:
                        raise ValueError('unexpected PTP container kind')
            raise TimeoutError('no terminal PTP response')
        except BaseException as error:
            row['error'] = type(error).__name__ + ': ' + str(error)
            raise
        finally:
            row['finished'] = datetime.now(timezone.utc).isoformat()
            save(self.directory / 'transactions.json', self.transactions)

    def require(self, op, params, role):
        payload, code, response_params = self.send(op, params, role)
        if code != 0x2001 or (op in (0x94FD, 0x94FF) and response_params[:1] != [0x2001]):
            raise RuntimeError(f'{role}: response=0x{code:04X}, parameters={response_params}')
        return payload

    def read_range(self, address, size, role):
        data = bytearray()
        for offset in range(0, size, 128):
            length = min(128, size - offset)
            part = self.require(0x94FF, (0xF044, address + offset, length, 0, 0),
                                role + f'-{offset:04X}')
            if part is None or len(part) != length:
                raise ValueError('F044 payload length mismatch')
            data.extend(part)
        (self.directory / (role + '.bin')).write_bytes(data)
        return bytes(data)

    def allow_observed_group4_source(self, pointer):
        """Permit only the source reached through the recorded group4 slot."""
        if ConfigObserver.region(pointer, GROUP4_BYTES) == 'outside_observed_ROM_and_SRAM':
            return False
        window = (pointer, GROUP4_BYTES, 'observed_group4_source')
        if window not in self.read_windows:
            self.read_windows.append(window)
        return True


def cache_snapshot(connection, index):
    """Read the current UART cache, bounded by two public context reads.

    Matching counters delimit a consistent retained cache sample, not an
    atomic CPU stop or a recording of the physical UART wire.
    """
    prefix = f'cache{index}'
    started = datetime.now(timezone.utc).isoformat()
    before = connection.read_range(0x2001F4E8, 16, prefix + '-context-before')
    buffers = connection.read_range(0x2001F538, 96, prefix + '-buffers')
    after = connection.read_range(0x2001F4E8, 16, prefix + '-context-after')
    tx_length, rx_length = before[1], before[3]
    tx = buffers[0x20:0x20 + min(tx_length, 24)]
    rx = buffers[0x38:0x38 + min(rx_length, 40)]
    completed = (before[:6] == after[:6] and before[5] == 0
                 and before[1] == before[2] and before[3] == before[4]
                 and 4 <= tx_length <= 24 and 4 <= rx_length <= 40
                 and tx[:1] == b'\x02' and len(tx) == tx[2] + 4
                 and rx[1:2] == b'\x06' and xor_bytes(tx) == xor_bytes(rx) == 0)
    return dict(sample_index=index, started=started,
                context_before=before[:6].hex(), context_after=after[:6].hex(),
                context_unchanged=before[:6] == after[:6], TX=tx.hex(), RX=rx.hex(),
                consistent_completed_cache_pair=completed,
                physical_cmd89_cache_pair=completed and tx[1] == 0x89,
                raw_UART_capture=False, atomic_snapshot=False,
                finished=datetime.now(timezone.utc).isoformat())


def classification_snapshot(connection, prefix):
    """Bracket fixed global inputs, body state and cached classification.

    Repeated equal values are sequential cache evidence. They do not identify
    the inputs at a physical call or establish that the function ran now.
    """
    started = datetime.now(timezone.utc).isoformat()
    before = connection.read_range(CLASSIFICATION_INPUT, 8, prefix + '-class-input-before')
    body_before = connection.read_range(BODY_BASE + 0x29, 1, prefix + '-class-body-before')[0]
    cached_before = connection.read_range(CONTROL_BASE + 0x14, 1, prefix + '-class-cache-before')[0]
    cached_after = connection.read_range(CONTROL_BASE + 0x14, 1, prefix + '-class-cache-after')[0]
    body_after = connection.read_range(BODY_BASE + 0x29, 1, prefix + '-class-body-after')[0]
    after = connection.read_range(CLASSIFICATION_INPUT, 8, prefix + '-class-input-after')
    predicted_before = classification_from_globals(before, body_before)
    predicted_after = classification_from_globals(after, body_after)
    stable = before == after and body_before == body_after and cached_before == cached_after
    return dict(started=started, finished=datetime.now(timezone.utc).isoformat(),
        input_address=f'0x{CLASSIFICATION_INPUT:08X}',
        cached_classification_address=f'0x{CONTROL_BASE + 0x14:08X}',
        body_state_address=f'0x{BODY_BASE + 0x29:08X}',
        input8_before_hex=before.hex(), input8_after_hex=after.hex(),
        body_state_before=body_before, body_state_after=body_after,
        cached_classification_before=cached_before, cached_classification_after=cached_after,
        repeated_samples_equal=stable,
        statically_recomputed_classification_before=predicted_before,
        statically_recomputed_classification_after=predicted_after,
        cached_value_equals_recomputation=(cached_before == predicted_before) if stable else None,
        atomic_snapshot=False, original_classification_execution_observed=False,
        physical_battery_state_meaning_verified=False,
        scope='Sequential diagnostic reads and offline ROM comparisons; physical call time and meaning unknown')


def snapshot(connection, index, config_trace=False, classification_trace=False):
    started = datetime.now(timezone.utc).isoformat()
    monotonic_start = time.monotonic()
    prefix = f'pass{index}'
    context1 = connection.read_range(0x2001F4E8, 16, prefix + '-context-before')
    buffers = connection.read_range(0x2001F538, 96, prefix + '-buffers')
    context2 = connection.read_range(0x2001F4E8, 16, prefix + '-context-after')
    config = connection.read_range(INFO_BASE, INFO_BYTES, prefix + '-config')
    copied = connection.read_range(0x2001FAF8, 136, prefix + '-config-copy-and-body')
    auxiliary = connection.read_range(0x2000ED90, 32, prefix + '-auxiliary')
    tx_length, rx_length = context1[1], context1[3]
    tx = buffers[0x20:0x20 + min(tx_length, 24)]
    rx = buffers[0x38:0x38 + min(rx_length, 40)]
    completed = (context1[:6] == context2[:6] and context1[5] == 0
                 and context1[1] == context1[2] and context1[3] == context1[4]
                 and 4 <= tx_length <= 24 and 4 <= rx_length <= 40
                 and tx[:1] == b'\x02' and len(tx) == tx[2] + 4
                 and rx[1:2] == b'\x06' and xor_bytes(tx) == xor_bytes(rx) == 0)
    mode = copied[BODY_BASE - 0x2001FAF8 + 0x2E]
    auxiliary2 = auxiliary[AUX_BASE - 0x2000ED90:AUX_BASE - 0x2000ED90 + 2]
    candidates = [reconstruct_cmd89(config, auxiliary2, mode, builder, pin)
                  for builder in BUILDERS for pin in (0, 1)]
    result = dict(pass_index=index, started=started, context_before=context1[:6].hex(),
                context_after=context2[:6].hex(), context_unchanged=context1[:6] == context2[:6],
                TX=tx.hex(), RX=rx.hex(), consistent_completed_cache_pair=completed,
                physical_cmd89_cache_pair=completed and tx[1] == 0x89,
                raw_UART_capture=False, atomic_snapshot=False,
                info72_hex=config.hex(), info72_copies_equal=config == copied[:INFO_BYTES],
                auxiliary2_hex=auxiliary2.hex(), body_mode=mode,
                reconstructed_cmd89_candidates=candidates)
    if config_trace:
        slot_before = connection.read_range(0x2000E7F0, 4, prefix + '-group4-pointer-before')
        pointer = int.from_bytes(slot_before, 'little')
        group4 = None
        if connection.allow_observed_group4_source(pointer):
            group4 = connection.read_range(pointer, GROUP4_BYTES, prefix + '-group4-source')
        slot_after = connection.read_range(0x2000E7F0, 4, prefix + '-group4-pointer-after')
        config_after = connection.read_range(INFO_BASE, INFO_BYTES, prefix + '-config-after')
        result['group4_configuration'] = dict(
            pointer_slot='0x2000E7F0', pointer=f'0x{pointer:08X}',
            pointer_before_hex=slot_before.hex(), pointer_after_hex=slot_after.hex(),
            pointer_unchanged=slot_before == slot_after,
            source_region=ConfigObserver.region(pointer, GROUP4_BYTES),
            source_bytes=len(group4) if group4 is not None else 0,
            source_hex=group4.hex() if group4 is not None else None,
            source_sha256=sha(group4) if group4 is not None else None,
            cache72_hex=copied[:INFO_BYTES].hex(), info72_after_hex=config_after.hex(),
            info72_unchanged=config == config_after,
            conversion_matches_cache_for_correction=[correction for correction in (0, 1)
                if group4 is not None and convert_group4(group4, copied[:INFO_BYTES], correction) == copied[:INFO_BYTES]],
            original_conversion_execution_observed=False,
            scope='Sequential diagnostic source/cache comparison; conversion R1 and call time are unknown')
    if classification_trace:
        result['global_classification'] = classification_snapshot(connection, prefix)
    result.update(finished=datetime.now(timezone.utc).isoformat(),
                  elapsed_seconds=round(time.monotonic() - monotonic_start, 6))
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', type=Path)
    ap.add_argument('--passes', type=int, choices=range(1, 13), default=2)
    ap.add_argument('--interval', type=float, default=0,
                    help='Seconds between retained sequential samples, bounded to 0..5')
    ap.add_argument('--config-trace', action='store_true',
                    help='Also read original config code, group4 pointer and its bounded ROM/SRAM source')
    ap.add_argument('--classification-trace', action='store_true',
                    help='Also read the original classification code and fixed global/body/cache bytes')
    ap.add_argument('--cache-samples', type=int, choices=range(257), default=0,
                    help='Also retain 0..256 faster UART-cache samples in the same read-only session')
    ap.add_argument('--cache-interval', type=float, default=0,
                    help='Seconds between cache samples, bounded to 0..0.25')
    args = ap.parse_args()
    if not 0 <= args.interval <= 5 or (args.passes - 1) * args.interval > 60:
        ap.error('sample interval must be 0..5 and total delay at most 60 seconds')
    if (not 0 <= args.cache_interval <= 0.25 or
            (args.passes - 1) * args.interval +
            max(0, args.cache_samples - 1) * args.cache_interval > 60):
        ap.error('cache interval must be 0..0.25 and combined sample delay at most 60 seconds')
    directory = args.out or Path('results') / ('camera-battery-' + datetime.now().strftime('%Y%m%d-%H%M%S'))
    directory = (ROOT / directory).resolve()
    if not directory.is_relative_to(ROOT):
        ap.error('output must be inside this independent package')
    directory.mkdir(mode=0o700)
    report = dict(schema='z62.camera-battery-read/1', started=datetime.now(timezone.utc).isoformat(),
                  input_scope='sequential post-F001 diagnostic reads of physical MCU; not raw UART',
                  firmware_memory_writes=0, battery_wire_commands_sent=0,
                  camera_reset_requested=False, physical_battery_private_key_recovered=False,
                  raw_USB_retained=True, config_trace_enabled=args.config_trace,
                  classification_trace_enabled=args.classification_trace,
                  sampling_interval_seconds=args.interval, snapshots=[], ROM_windows=[], complete=False)
    connection = None
    session_owned = diagnostic_attempted = False
    try:
        connection = Connection(directory, args.config_trace, args.classification_trace)
        report['USB'] = connection.details
        connection.claim()
        connection.require(0x1002, (1,), 'OpenSession')
        session_owned = True
        payload = connection.require(0x1001, (), 'GetDeviceInfo')
        report['identity'] = parse_identity(payload)
        if report['identity']['model'] != 'Z 6_2' or report['identity']['version'] != 'V1.70':
            raise ValueError('requires the expected Z 6_2 V1.70 before diagnostic access')
        print('Identity: ' + json.dumps({k: report['identity'][k] for k in ('model', 'version', 'serial')}), flush=True)
        report['normal_mode'] = {}
        for op, params, role in ((0x1015, (0x5001,), 'BatteryLevel'),
                                 (0x1015, (0x500E,), 'ExposureProgram'),
                                 (0x942B, (), 'NormalCache942B')):
            data = connection.require(op, params, role)
            report['normal_mode'][role] = data.hex() if data is not None else None
        diagnostic_attempted = True
        connection.require(0x94FD, (0xF001, 0, 0, 0, 0), 'EnterF001')
        rom = (ROOT / 'inputs/firmware/ex1850_012000.bi.bin').read_bytes()
        report['reference_ROM_sha256'] = sha(rom)
        if report['reference_ROM_sha256'] != ROM_SHA256:
            raise ValueError('package MCU ROM identity changed')
        windows = [*ROM_WINDOWS]
        if args.config_trace:
            windows.extend(CONFIG_ROM_WINDOWS)
        if args.classification_trace:
            windows.extend(CLASSIFICATION_ROM_WINDOWS)
        for address, size, role in windows:
            observed = connection.read_range(address, size, role)
            expected = rom[address - 0x08000000:address - 0x08000000 + size]
            report['ROM_windows'].append(dict(address=f'0x{address:08X}', bytes=size,
                    path=role + '.bin', sha256=sha(observed), package_ROM_equal=observed == expected))
            if observed != expected:
                raise ValueError('live MCU source window differs from package ROM: ' + role)
        for index in range(1, args.passes + 1):
            if index > 1 and args.interval:
                time.sleep(args.interval)
            sample = snapshot(connection, index, args.config_trace, args.classification_trace)
            report['snapshots'].append(sample)
            public = {k: sample[k] for k in ('pass_index', 'body_mode', 'physical_cmd89_cache_pair', 'elapsed_seconds')}
            public['cached_command'] = sample['TX'][2:4]
            if args.config_trace:
                public['group4_pointer'] = sample['group4_configuration']['pointer']
                public['config_unchanged'] = sample['group4_configuration']['info72_unchanged']
            if args.classification_trace:
                public['classification'] = {k: sample['global_classification'][k] for k in (
                    'input8_before_hex', 'body_state_before', 'cached_classification_before',
                    'repeated_samples_equal', 'statically_recomputed_classification_before')}
            print('Cache: ' + json.dumps(public), flush=True)
            save(directory / 'summary.json', report)
        report['cache_samples'] = []
        report['cache_sampling_interval_seconds'] = args.cache_interval
        for index in range(1, args.cache_samples + 1):
            if index > 1 and args.cache_interval:
                time.sleep(args.cache_interval)
            sample = cache_snapshot(connection, index)
            report['cache_samples'].append(sample)
            if index % 32 == 0 or sample['physical_cmd89_cache_pair']:
                print('Cache watch: ' + json.dumps({k: sample[k] for k in (
                    'sample_index', 'consistent_completed_cache_pair', 'physical_cmd89_cache_pair')}) +
                    ' TX=' + sample['TX'], flush=True)
                save(directory / 'summary.json', report)
        report['captured_physical_cmd89_cache_pair'] = any(
            s['physical_cmd89_cache_pair'] for s in (*report['snapshots'], *report['cache_samples']))
        report['complete'] = True
    except BaseException as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
        print(report['error'], flush=True)
    finally:
        if connection is not None:
            if session_owned and diagnostic_attempted:
                try:
                    connection.require(0x94FD, (0xF002, 0, 0, 0, 0), 'ExitF002')
                    report['F002_exit_ok'] = True
                except BaseException as error:
                    report['F002_exit_ok'] = False
                    report['F002_error'] = type(error).__name__ + ': ' + str(error)
            if session_owned:
                try:
                    connection.require(0x1003, (), 'CloseSession')
                    report['CloseSession_ok'] = True
                except BaseException as error:
                    report['CloseSession_ok'] = False
                    report['CloseSession_error'] = type(error).__name__ + ': ' + str(error)
            try:
                connection.close()
                report['USB_release_ok'] = True
            except BaseException as error:
                report['USB_release_ok'] = False
                report['USB_release_error'] = type(error).__name__ + ': ' + str(error)
            report['transaction_count'] = len(connection.transactions)
        report['finished'] = datetime.now(timezone.utc).isoformat()
        save(directory / 'summary.json', report)
        files = [dict(path=str(p.relative_to(directory)), bytes=p.stat().st_size, sha256=sha(p.read_bytes()))
                 for p in sorted(directory.rglob('*')) if p.is_file()]
        scripts = [dict(path=str(p.relative_to(ROOT)), bytes=p.stat().st_size, sha256=sha(p.read_bytes()))
                   for p in (Path(__file__), ROOT / 'src/harness/ex1850_cmd89.py',
                             ROOT / 'src/harness/ex1850_battery_config.py',
                             ROOT / 'src/harness/ex1850_battery_task.py')]
        save(directory / 'manifest.json', dict(schema='z62.camera-read-manifest/1', files=files, scripts=scripts))
        print('Saved: ' + str(directory), flush=True)
    return int(not (report['complete'] and report.get('F002_exit_ok')
                    and report.get('CloseSession_ok') and report.get('USB_release_ok')))


if __name__ == '__main__':
    raise SystemExit(main())
