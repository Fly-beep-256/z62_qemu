"""Replay real native samples and reject damaged metadata without guest writes.

This is an offline regression of the evidence auditor. The input run is never
changed, no QEMU or camera is contacted, and synthetic negative cases exist
only in Python memory. It does not grant original-boot or camera acceptance.
"""
import argparse
import copy
from datetime import datetime
import json
from pathlib import Path
import sys
import uuid

from z62_common import ROOT, HARNESS, read, save, identity, digest, evidence_path, now

sys.path[:0] = [str(HARNESS), str(HARNESS / 'tools')]
from acceptance import (native_protocol_audit, native_read_bindings,
                        native_architecture_binding, native_final_inputs,
                        native_saiso_sample_binding, native_task_sample_binding,
                        native_loader_sample_binding, native_passive_battery_binding)
from acceptance import native_scenario_binding
from audit_battery import audit_battery
from audit_battery_uart import TOKENS, load_uart_source_log, verify_original_zero


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', default='latest-native')
    args = parser.parse_args()
    if args.run == 'latest-native':
        envelope = ROOT / 'results' / read(ROOT / 'results/latest-native.json')['run']
    else:
        envelope = Path(args.run)
        if not envelope.is_absolute():
            envelope = ROOT / envelope
    envelope = envelope.resolve(strict=True)
    name = datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:6]
    output = ROOT / 'results/evidence-regressions' / name
    output.mkdir(parents=True, exist_ok=False)
    locked = read(envelope / 'prepare/锁定命令与输入.json')
    raw_file = envelope / 'run/native-unified-result.json'
    raw = read(raw_file)
    report = dict(schema='z62.native-evidence-regression/1', started=now(),
                  scope='offline real-byte replay and in-memory negative metadata',
                  camera_access=False, QEMU_launched=False, guest_state_written=False,
                  full_camera_acceptance=False, original_run_modified=False,
                  input=identity(raw_file), sources=[identity(Path(__file__)),
                      identity(ROOT / 'scripts/acceptance.py'),
                      identity(ROOT / 'scripts/audit_battery.py'),
                      identity(ROOT / 'scripts/audit_battery_uart.py'),
                      identity(ROOT / 'scripts/audit_battery_task.py'),
                      identity(HARNESS / 'ex1850_battery_task.py'),
                      identity(HARNESS / 'expeed_task_observer.py')], checks=[],
                  coverage={}, skipped_cases=[])

    def checked(item):
        path = evidence_path(item['path'], envelope, locked).resolve(strict=True)
        if (('bytes' in item and path.stat().st_size != item['bytes']) or
                digest(path) != item['sha256']):
            raise ValueError('SHA/size changed: ' + item['path'])
        return path

    def check(name, action, reject=False, rejection_text=None):
        detail = None
        try:
            action()
            passed = not reject
        except (OSError, KeyError, TypeError, ValueError, AssertionError) as error:
            detail = type(error).__name__ + ': ' + str(error)
            passed = bool(reject and (rejection_text is None or rejection_text in str(error)))
        report['checks'].append(dict(name=name, passed=passed,
                                     expected='reject' if reject else 'accept', detail=detail))
        print(('PASS ' if passed else 'FAIL ') + name, flush=True)
        save(output / 'result.json', report)
        if not passed and not reject:
            raise RuntimeError(name + ': ' + str(detail))

    def require(condition, message):
        if not condition:
            raise AssertionError(message)

    try:
        protocol = native_protocol_audit(envelope / 'run', raw, checked, identity)
        check('complete_actual_connections_zero_guest_writes', lambda: require(
            not protocol['errors'] and not protocol['writes'] and not protocol['unknown'],
            str(protocol['errors'])))
        bound = native_read_bindings(protocol, raw)
        check('actual_CPU_selected_memory_register_binding', lambda: require(
            not bound['errors'], str(bound['errors'])))
        blobs = {r: checked(raw['identities'][r + '_ROM']).read_bytes()
                 for r in ('master', 'slave', 'MCU')}
        check('passive_battery_recomputed_from_actual_CPU4_bytes', lambda:
              native_passive_battery_binding(raw, blobs, bound))

        def load(path, required=False):
            if required and not Path(path).is_file():
                raise FileNotFoundError(path)
            return read(path)

        def battery(value):
            result, errors = audit_battery(envelope, value, protocol['assistance'],
                                          load, checked, identity)
            functional = result.get('original_cmd89_functional_errors', [])
            hard = [e for e in errors if not e.startswith((
                'Required original cmd89 return not observed:',
                'Original MCU authentication comparator/ready-store acceptance not observed'))
                and e not in functional]
            require(not hard, str(hard))
            return result

        check('battery_wire_and_original_return_evidence_verified', lambda: battery(raw))
        original_battery = battery(raw)
        calls = raw['original_cmd89_transaction_returns']
        rows = original_battery['original_cmd89_returns']
        report['coverage']['cmd89_returns'] = dict(
            status='observed' if calls else 'not_observed', count=len(calls),
            original_failure_count=sum(row['returned_R0'] != 0 for row in calls))
        check('original_call_counts_and_failures_remain_faithful', lambda: require(
            len(rows) == len(calls)
            and all(row['evidence_verified'] and row['status'] == (
                'verified' if row['returned_R0'] == 0 else 'original_failure_verified') for row in rows)
            and sum(original_battery['original_cmd89_accepted_counts'].values()) ==
                sum(row['returned_R0'] == 0 for row in rows)
            and bool(original_battery['original_cmd89_functional_errors']) ==
                any(row['returned_R0'] != 0 for row in rows),
            'A failed call lost its evidence or was counted as successful'))
        index = next((i for i, row in enumerate(calls) if row['returned_R0'] != 0), 0)

        def damaged_call():
            value = copy.deepcopy(raw)
            row = value['original_cmd89_transaction_returns'][index]
            event = next(o for o in value['observations']
                         if o.get('original_cmd89_transaction_return') == row)
            event['original_cmd89_transaction_return'] = row
            return value, row, event

        if calls:
            bad, row, event = damaged_call()
            row['returned_R0'] = 0 if row['returned_R0'] else 4
            event['registers']['r0'] = hex(row['returned_R0'])
            check('reject_forged_battery_R0_against_actual_register_reply', lambda: bound['registers'](
                4, event['stop_epoch'], event['registers']), True)
            bad, row, event = damaged_call()
            original = bytes.fromhex(event['original_ROM_bytes'])
            event['original_ROM_bytes'] = (bytes([original[0] ^ 1]) + original[1:]).hex()
            check('reject_battery_return_wrong_original_ROM', lambda: battery(bad), True)
            bad, row, event = damaged_call()
            body = bytearray.fromhex(row['body_hex'])
            body[0x2e] ^= 1
            row['body_hex'] = body.hex()
            check('reject_battery_return_wrong_body_mode', lambda: battery(bad), True)
            bad, row, event = damaged_call()
            control = bytearray.fromhex(row['control_hex'])
            control[2] -= 1
            row['control_hex'] = control.hex()
            check('reject_battery_incomplete_original_request', lambda: battery(bad), True)
            bad, row, event = damaged_call()
            row['returned_R0'], event['registers']['r0'] = 0, '0x0'
            control = bytearray.fromhex(row['control_hex'])
            control[4:6] = b'\x04\x00'
            row['control_hex'], row['RX_hex'] = control.hex(), '00000000'
            check('reject_battery_success_without_received_reply', lambda: battery(bad), True)
        else:
            report['skipped_cases'].append(dict(group='cmd89_return_negative_cases',
                reason='No actual original cmd89 return in this retained run; no positive was fabricated'))

        uart_events, uart_log = load_uart_source_log(raw, checked, identity)
        check('UART_source_log_SHA_verified', lambda: require(uart_log['identity_verified'], 'Missing log identity'))
        bad = copy.deepcopy(raw)
        bad['QEMU_log']['sha256'] = '0' * 64
        check('reject_UART_wrong_log_SHA', lambda: load_uart_source_log(bad, checked, identity),
              True, 'SHA/size changed:')
        zero_proofs = original_battery.get('unframed_UART', {}).get('bytes', [])
        report['coverage']['frame_external_UART_zeros'] = dict(
            status='verified' if zero_proofs else 'not_observed',
            offsets=[p['wire_offset'] for p in zero_proofs],
            physical_protocol_meaning_verified=False)
        if zero_proofs:
            peer = read(envelope / 'run/MCU/USART1-peer/closed.json')
            tx = checked(peer['streams']['public_TX']).read_bytes()
            proof = zero_proofs[-1]
            offset = proof['wire_offset']
            check('original_UART_setup_DR_completion_source_verified', lambda:
                  verify_original_zero(blobs['MCU'], tx, offset, uart_events))

            def event_case(label, token, field, value, expected):
                changed = copy.deepcopy(uart_events)
                names = {TOKENS[0]: 'reset', TOKENS[1]: 'setup', TOKENS[2]: 'DR', TOKENS[3]: 'completion'}
                row = next(r for r in changed[token] if r['log_line'] == proof['log_lines'][names[token]])
                row[field] = value
                check('reject_UART_' + label, lambda:
                      verify_original_zero(blobs['MCU'], tx, offset, changed), True, expected)

            for label, token, field, value, expected in (
                ('wrong_offset', TOKENS[3], 'wire_offset', str(len(tx)), 'completion observation'),
                ('wrong_DR_PC', TOKENS[2], 'pc', '0804a0d8', 'DR instruction/registers/counters'),
                ('wrong_DR_address', TOKENS[2], 'addr', '40011008', 'DR instruction/registers/counters'),
                ('wrong_DR_handle_register', TOKENS[2], 'r0', '2001f51c', 'DR instruction/registers/counters'),
                ('wrong_DR_value_register', TOKENS[2], 'r1', '00000001', 'DR instruction/registers/counters'),
                ('wrong_DR_USART_register', TOKENS[2], 'r2', '40011400', 'DR instruction/registers/counters'),
                ('wrong_accepted_count', TOKENS[2], 'accepted_before', '-1', 'DR instruction/registers/counters'),
                ('wrong_completed_count', TOKENS[3], 'completed', '0', 'completion does not match'),
                ('wrong_reset_generation', TOKENS[3], 'reset_generation', '0', 'reset generation'),
                ('wrong_reset_source', TOKENS[0], 'source', 'host_synthetic', 'invalid reset origin'),
                ('wrong_completion_source', TOKENS[3], 'source', 'host_synthetic', 'completion does not match'),
                ('wrong_virtual_order', TOKENS[2], 'virtual_ns', str(proof['completion_virtual_ns']), 'virtual order'),
                ('wrong_HAL_TX_pointer', TOKENS[1], 'tx_pointer', '2001f55c', 'HAL send setup'),
                ('wrong_HAL_LR', TOKENS[1], 'lr', '080236f5', 'transaction first-send path'),
                ('wrong_HAL_root', TOKENS[1], 'r4', '2001f4ec', 'transaction first-send path'),
                ('wrong_HAL_stack', TOKENS[1], 'sp', '20000001', 'HAL setup SRAM/stack'),
            ):
                event_case(label, token, field, value, expected)
            setup = next(r for r in uart_events[TOKENS[1]] if r['log_line'] == proof['log_lines']['setup'])
            for label, field, byte_offset, expected in (
                ('wrong_HAL_size', 'handle_hex', 0x24, 'HAL setup SRAM/stack'),
                ('wrong_saved_upstream_caller', 'stack64_hex', 0x1c, 'saved caller lacks Thumb'),
                ('wrong_cleared_TX', 'tx24_hex', 20, 'single-zero transaction'),
                ('wrong_declared_TX_length', 'control6_hex', 1, 'single-zero transaction'),
                ('wrong_control_sent_count', 'control6_hex', 2, 'single-zero transaction'),
                ('wrong_expected_RX_length', 'control6_hex', 3, 'single-zero transaction'),
                ('wrong_original_stack_payload', 'stack64_hex', 0x24, 'single-zero transaction'),
            ):
                value = bytearray.fromhex(setup[field]); value[byte_offset] ^= 1
                event_case(label, TOKENS[1], field, value.hex(), expected)
            for label, token, name in (('missing_setup', TOKENS[1], 'setup'),
                                       ('missing_completion', TOKENS[3], 'completion')):
                changed = copy.deepcopy(uart_events)
                changed[token] = [r for r in changed[token] if r['log_line'] != proof['log_lines'][name]]
                check('reject_UART_' + label, lambda:
                      verify_original_zero(blobs['MCU'], tx, offset, changed), True, 'missing or ambiguous')
            for label, address in (('wrong_ROM_DR', 0x4a0d6), ('wrong_ROM_HAL', 0x4677c),
                                   ('wrong_ROM_upstream_TX_length', 0x24972),
                                   ('wrong_ROM_transaction_length_store', 0x2385c)):
                changed_rom = bytearray(blobs['MCU']); changed_rom[address] ^= 1
                check('reject_UART_' + label, lambda:
                      verify_original_zero(changed_rom, tx, offset, uart_events), True, 'differ')
            check('reject_UART_inserted_extra_zero', lambda:
                  verify_original_zero(blobs['MCU'], tx + b'\0', len(tx), uart_events),
                  True, 'completion observation')
        else:
            report['skipped_cases'].append(dict(group='UART_setup_DR_completion_negative_cases',
                reason='No actual frame-external NUL in this run; original source positive not observed'))

        classified = original_battery.get('passive_task_timing', {}).get('classification_calls', [])
        report['coverage']['original_classification'] = dict(
            status='observed' if classified else 'not_observed', calls=len(classified))
        if classified:
            from ex1850_battery_task import CLASSIFICATION_ENTRY
            for label, field in (('wrong_classification_global_input', 'classification_input8_hex'),
                                 ('wrong_classification_control', 'control96_hex')):
                bad = copy.deepcopy(raw)
                row = next(e for o in bad['observations'] for e in o.get('original_battery_task_events', [])
                           if int(e['entry'], 16) == CLASSIFICATION_ENTRY)
                value = bytearray.fromhex(row[field]); value[0 if field.endswith('8_hex') else 0x14] ^= 1
                row[field] = value.hex()
                if field == 'control96_hex':
                    row['classification_byte'] = value[0x14]
                bad['original_battery_task_events'] = [e for o in bad['observations']
                    for e in o.get('original_battery_task_events', [])]
                check('reject_' + label + '_against_actual_CPU4_bytes', lambda:
                      native_passive_battery_binding(bad, blobs, bound), True, 'Passive task output differs')
        else:
            report['skipped_cases'].append(dict(group='classification_input_negative_cases',
                reason='No actual classification entry/store/return pair in this run'))

        clocks = [json.loads(s) for s in checked(raw['virtual_clock_observation_ledger']).read_text().splitlines()]

        actual_scenario = read(envelope / 'run/native-gpio-scenario-result.json')

        def scenario_check(value, contract):
            result, issues = native_scenario_binding(value, raw, contract, protocol, clocks, checked)
            require(not issues and result['binding_verified'], str(issues))

        check('selected_pad_table_actual_clock_get_set_get_clock', lambda:
              scenario_check(actual_scenario, locked))
        bad = copy.deepcopy(actual_scenario)
        bad['schedule'][0]['mask'] ^= 1
        check('reject_changed_declared_pad_mask', lambda: scenario_check(bad, locked), True)
        if locked.get('scenario_schedule_input'):
            bad = copy.deepcopy(actual_scenario)
            bad['schedule_input']['sha256'] = '0' * 64
            check('reject_changed_external_pad_file_identity', lambda: scenario_check(bad, locked), True)
            bad_lock = copy.deepcopy(locked)
            bad_lock['scenario_argv'] = ['--schedule']
            check('reject_missing_external_pad_file_argument', lambda:
                  scenario_check(actual_scenario, bad_lock), True)
            bad_lock = copy.deepcopy(locked)
            bad_lock['scenario_argv'] += ['--schedule', 'other.json']
            check('reject_duplicate_external_pad_file_argument', lambda:
                  scenario_check(actual_scenario, bad_lock), True)
        if actual_scenario.get('events') and actual_scenario['events'][0].get('acknowledgement'):
            bad = copy.deepcopy(actual_scenario)
            bad['events'][0]['acknowledgement']['applied_virtual_ns'] += 1
            check('reject_pad_ACK_changed_virtual_time', lambda: scenario_check(bad, locked), True)

        def architecture(value, reject=False):
            errors = []
            result = native_architecture_binding(value, protocol, clocks, errors)
            if reject:
                require(bool(errors) and result['QMP_reply_binding_verified'] is False
                        and result['passed'] is False, 'Changed initial snapshot retained a passing flag')
            else:
                require(not errors and result['passed'], str(errors))
        check('actual_initial_final_QMP_architecture_binding', lambda: architecture(raw))
        bad = copy.deepcopy(raw)
        bad['initial_architecture']['snapshot_epoch'] += 1
        check('changed_initial_epoch_clears_all_architecture_flags', lambda: architecture(bad, True))

        plan, reference = native_final_inputs(envelope, locked, raw, blobs, checked)
        check('launch_time_locked_task_Loader_plans', lambda: require(
            set(plan['roles']) == {'master', 'slave'}, 'Missing E6 role'))
        bad_lock = copy.deepcopy(locked)
        bad_lock['input_files'] = [r for r in bad_lock['input_files'] if
            evidence_path(r['path'], envelope, locked).resolve() !=
            checked(raw['task_observation_plan'])]
        check('reject_unlocked_task_plan', lambda: native_final_inputs(
            envelope, bad_lock, raw, blobs, checked), reject=True)

        epoch, gate = raw['common_stop']['stop_epoch'], raw['common_stop']
        saiso = raw['SAISO_UI_RAM']
        check('all_seven_SAISO_samples_bind_to_actual_bytes', lambda: native_saiso_sample_binding(saiso, epoch, bound))
        check('reject_missing_SAISO_sample', lambda: native_saiso_sample_binding(saiso[:-1], epoch, bound), True)
        check('reject_duplicate_SAISO_sample', lambda: native_saiso_sample_binding(saiso + saiso[:1], epoch, bound), True)
        bad = copy.deepcopy(saiso)
        bad[0]['global_cpu'] = 2
        check('reject_SAISO_wrong_CPU', lambda: native_saiso_sample_binding(bad, epoch, bound), True)

        for role in ('master', 'slave'):
            path = evidence_path(raw['task_RAM'][role]['report'], envelope, locked)
            doc = read(path)
            def task(value):
                return native_task_sample_binding(value, role, plan['roles'][role], epoch,
                                                  gate, path.parent, bound, checked)
            check(role + '_task_roots_registry_recomputed_from_actual_bytes', lambda: task(doc))
            for label, mutate in (
                ('missing_root', lambda value: value['roots'].pop()),
                ('missing_read', lambda value: value['reads'].pop()),
                ('missing_saved_bytes', lambda value: value['reads'][0].pop('saved')),
                ('forged_allocated_count', lambda value: value['task_registry'].__setitem__(
                    'allocated_count', value['task_registry']['allocated_count'] + 1)),
                ('wrong_stop_epoch', lambda value: value['stop_gate'].__setitem__('stop_epoch', epoch + 1)),
            ):
                bad = copy.deepcopy(doc)
                mutate(bad)
                check(role + '_reject_' + label, lambda: task(bad), True)

        loader = raw['Loader_payloads']['regions']
        def loader_check(value):
            native_loader_sample_binding(value, reference, epoch, protocol, bound,
                                         checked, envelope, locked)
        check('complete_Loader_0B_0C_actual_CPU0_memsave', lambda: loader_check(loader))
        check('reject_missing_Loader_region', lambda: loader_check(loader[:-1]), True)
        bad = copy.deepcopy(loader)
        bad[0]['QMP_arguments']['size'] -= 1
        check('reject_changed_Loader_extent', lambda: loader_check(bad), True)
        bad = copy.deepcopy(loader)
        bad[0]['QMP_arguments']['cpu-index'] = 2
        check('reject_Loader_wrong_CPU', lambda: loader_check(bad), True)
        require(digest(raw_file) == report['input']['sha256'], 'Original run changed')
        report['passed'] = all(row['passed'] for row in report['checks'])
    except Exception as error:
        report.update(passed=False, error=type(error).__name__ + ': ' + str(error))
        print(report['error'], flush=True)
    report['finished'] = now()
    save(output / 'result.json', report)
    print('Evidence regression: ' + str((output / 'result.json').relative_to(ROOT)), flush=True)
    return int(not report['passed'])


if __name__ == '__main__':
    raise SystemExit(main())
