"""Reject damaged configuration evidence without executing any guest code."""
import argparse
from copy import deepcopy
from datetime import datetime
from pathlib import Path
import sys
import uuid

from z62_common import ROOT, HARNESS, identity, now, read, save


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run', help='A completed package-relative native run directory')
    args = parser.parse_args()
    envelope = (ROOT / args.run).resolve()
    if not envelope.is_relative_to(ROOT / 'results'):
        raise ValueError('Select completed evidence inside this package results directory')
    endpoint = envelope / 'run/native-unified-result.json'
    if not endpoint.is_file():
        endpoint = envelope / 'run/MCU/结果.json'
    acceptance = read(envelope / 'acceptance.json')
    original = read(endpoint)
    if not original or not acceptance:
        raise ValueError('Run completion and acceptance evidence are required')
    sys.path[:0] = [str(HARNESS)]
    from audit_battery_config import audit_battery_config
    rom_path = ROOT / 'inputs/firmware/ex1850_012000.bi.bin'
    rom = rom_path.read_bytes()
    assistance = acceptance['debugger_assistance']

    def rom_observation(row):
        address = int(row.get('address', '0'), 16)
        raw = bytes.fromhex(row.get('original_ROM_bytes', ''))
        offset = address - 0x08000000
        return bool(raw and offset >= 0 and rom[offset:offset + len(raw)] == raw and
                    int(row.get('registers', {}).get('r15', '0'), 16) == address)

    baseline, errors = audit_battery_config(rom, original, assistance, rom_observation)
    if errors or baseline['status'] != 'verified_original_configuration_chain':
        raise ValueError('Select a run with a verified original configuration chain: ' + str(errors))
    before = identity(endpoint)
    output = ROOT / 'results/component-tests' / (
        datetime.now().strftime('%Y%m%d-%H%M%S') + '-battery-config-' + uuid.uuid4().hex[:6])
    checks = []
    cases = (
        ('wrong-restored-SP', 'stack_address', 'r13',
         'Original group4 conversion completion lacks matching SP/LR entry'),
        ('wrong-original-LR', 'caller_return_register', 'r14',
         'Original group4 conversion completion lacks matching SP/LR entry'),
        ('wrong-conversion-output', 'cache72_hex', None,
         'Original group4 conversion output differs from source-bound reconstruction'),
    )
    for name, field, register, expected in cases:
        damaged = deepcopy(original)
        observation = next(o for o in damaged['observations'] if any(
            e['phase'] == 'conversion_completed'
            for e in o.get('original_battery_config_events', [])))
        event = next(e for e in observation['original_battery_config_events']
                     if e['phase'] == 'conversion_completed')
        if register:
            value = hex(int(event[field], 16) + (4 if register == 'r13' else 2))
            event[field] = value
            observation['registers'][register] = value
        else:
            payload = bytes.fromhex(event[field])
            event[field] = (bytes([payload[0] ^ 1]) + payload[1:]).hex()
        damaged['original_battery_config_events'] = [
            e for o in damaged['observations']
            for e in o.get('original_battery_config_events', [])]
        result, added_errors = audit_battery_config(rom, damaged, assistance, rom_observation)
        checks.append(dict(name=name, expected_error=expected, actual_errors=added_errors,
            passed=expected in added_errors and result['status'] == 'failed_or_incomplete',
            deliberate_damage_scope='offline in-memory copy of retained observations',
            supplied_to_any_guest=False))
    restored, errors = audit_battery_config(rom, read(endpoint), assistance, rom_observation)
    checks.append(dict(name='original-evidence-remains-verified',
        passed=identity(endpoint) == before and not errors and
               restored['status'] == 'verified_original_configuration_chain'))
    report = dict(schema='z62.battery-evidence-negative-test/1', checked=now(),
        source_run=str(envelope.relative_to(ROOT)), endpoint=before,
        original_ROM=identity(rom_path), auditor=identity(Path(__file__)),
        baseline_configuration_status=baseline['status'],
        baseline_native_errors=acceptance['errors'], checks=checks,
        passed=all(c['passed'] for c in checks),
        camera_access=False, guest_execution=False, guest_state_supplied=False,
        scope='Configuration evidence rejection only; native cmd89 requirements remain unchanged')
    save(output / 'test.json', report)
    for check in checks:
        print(('PASS ' if check['passed'] else 'FAIL ') + check['name'])
    print('Report: ' + str((output / 'test.json').relative_to(ROOT)))
    return int(not report['passed'])


if __name__ == '__main__':
    raise SystemExit(main())
