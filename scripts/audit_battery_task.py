"""Validate passive post-configuration task stops and actual paired returns."""
from collections import Counter
import hashlib
from ex1850_battery_task import classification_from_globals


def audit_battery_task(rom, mcu, assistance, configuration, rom_observation):
    from ex1850_battery_task import (TaskObserver, POINTS, PAIRED_RETURNS,
                                    R0_BODY, R1_BODY, R2_BODY, MAX_HITS, BODY_BASE,
                                    CONTROL_BASE, CLASSIFICATION_INPUT,
                                    CLASSIFICATION_ENTRY, CLASSIFICATION_STORES)
    from ex1850_battery_config import ROM_BASE, RAM_BASE, RAM_BYTES
    issues = []
    result = dict(schema='z62.battery-task-timing/1',
        enabled=mcu.get('battery_task_trace_enabled') is True,
        status='not_observed', activation=None, timeline=[], return_pairs=[],
        classification_calls=[],
        guest_state_supplied=False, physical_cold_boot_verified=False,
        scope='Actual ROM stops after the original nonzero config copy; '
              'raw conditions do not establish branch execution')
    if not result['enabled']:
        return result, issues

    def need(condition, message):
        if not condition:
            issues.append('Battery task timing: ' + message)
        return bool(condition)

    def raw(row, key, length):
        value = bytes.fromhex(row[key])
        if len(value) != length:
            raise ValueError('incomplete ' + key)
        return value

    try:
        TaskObserver(rom)
        observations = mcu.get('observations', [])
        by_sequence = {o['observation_sequence']: o for o in observations if 'observation_sequence' in o}
        events = mcu.get('original_battery_task_events', [])
        need(events == [e for o in observations for e in o.get('original_battery_task_events', [])],
             'events differ from actual stopped observations')
        need(assistance.get('complete_expected_connection_capture',
                            assistance.get('complete_six_connection_capture')) is True and
             assistance.get('actual_guest_write_packets') == 0,
             'complete debugger capture with zero guest writes is required')
        config_events = mcu.get('original_battery_config_events', [])
        trigger = next((e for e in config_events if e['phase'] == 'copy_completed' and
            e.get('stack_and_return_pair_match') is True and any(bytes.fromhex(e['info72_hex']))), None)
        activation = mcu.get('battery_task_trace_activation')
        result['activation'] = activation
        if trigger is None:
            need(activation is None and not events, 'task tracing preceded the original nonzero copy')
            result['status'] = 'configuration_trigger_not_observed'
            return result, issues
        need(bool(activation) and activation['config_copy_sequence'] == trigger['observation_sequence'] and
             activation['HAL_tick'] == trigger['HAL_tick'] and
             activation['host_elapsed_seconds'] == trigger['host_elapsed_seconds'] and
             activation['info72_sha256'] == hashlib.sha256(bytes.fromhex(trigger['info72_hex'])).hexdigest() and
             activation.get('guest_state_written') is False,
             'activation does not match the actual first nonzero copy')
        need(any(p['completion_sequence'] == trigger['observation_sequence'] and p['status'] == 'verified'
                 for p in configuration.get('copy_pairs', [])), 'activation copy was not independently verified')
        pending, consumed, last_sequence = {}, set(), trigger['observation_sequence']
        classification_stores = {}
        for row in events:
            sequence, phase, address = row['observation_sequence'], row['phase'], int(row['entry'], 16)
            observation = by_sequence[sequence]
            registers = observation['registers']
            need(sequence >= last_sequence and sequence >= trigger['observation_sequence'],
                 'events are not ordered after the original copy')
            last_sequence = sequence
            need(rom_observation(observation) and row['entry'] == observation['address'] and
                 row['original_ROM_bytes'] == observation['original_ROM_bytes'], 'original ROM stop is invalid')
            need(row['stack_address'] == hex(int(registers['r13'], 16)) and
                 row['caller_return_register'] == hex(int(registers['r14'], 16)) and
                 row['HAL_tick'] == observation['HAL_tick'] and
                 row['host_elapsed_seconds'] == observation['host_elapsed_seconds'] and
                 row['activation_config_copy_sequence'] == trigger['observation_sequence'],
                 'register, time or activation metadata differs from the actual stop')
            need(row.get('guest_state_written') is False and
                 row.get('peripheral_MMIO_read_by_debugger') is False, 'observer supplied guest state or read MMIO')
            control, body = raw(row, 'control96_hex', 96), raw(row, 'main_body64_hex', 64)
            raw(row, 'info72_hex', 72)
            raw(row, 'auxiliary2_hex', 2)
            raw(row, 'power_guard_byte', 1)
            voltage, tag = int.from_bytes(control[0x34:0x36], 'little'), int.from_bytes(body[0x26:0x28], 'little')
            state, comparison = body[0x29], row['comparison_global_u16']
            need(type(comparison) is int and 0 <= comparison <= 0xffff and
                 row['main_control_ushort_34'] == voltage and row['main_body_state'] == state and
                 row['main_body_tag_26'] == tag and
                 row['raw_tag_difference_before_read_refresh'] == (tag != comparison) and
                 row['raw_voltage_gate'] == (voltage > 0x2133 and state in (2, 9) or
                                             voltage < 0x2134 and state == 5),
                 'raw condition fields do not match the retained SRAM bytes')
            item = dict(observation_sequence=sequence, phase=phase, entry=row['entry'],
                HAL_tick=row['HAL_tick'], host_elapsed_seconds=row['host_elapsed_seconds'],
                main_body_state=state, main_control_ushort_34=voltage, main_body_tag_26=tag,
                comparison_global_u16=comparison, power_guard_byte=row['power_guard_byte'],
                raw_voltage_gate=row['raw_voltage_gate'],
                raw_tag_difference_before_read_refresh=tag != comparison)
            is_classification = (address == CLASSIFICATION_ENTRY or address in CLASSIFICATION_STORES or
                phase == 'return' and int(row.get('function_entry', '0'), 16) == CLASSIFICATION_ENTRY)
            if is_classification:
                status = raw(row, 'classification_input8_hex', 8)
                need(row['classification_input_address'] == hex(CLASSIFICATION_INPUT) and
                     row['classification_byte'] == control[0x14],
                     'classification globals do not match the original literal/control bytes')
                item.update(classification_input8_hex=status.hex(),
                    classification_byte=control[0x14],
                    statically_recomputed_classification=classification_from_globals(status, state))
            if phase == 'return':
                previous = pending.get(row.get('entry_sequence'))
                valid = bool(previous and row['entry_sequence'] not in consumed and
                    previous['observation_sequence'] < sequence and
                    previous['stack_address'] == row['stack_address'] and
                    previous['expected_return_address'] == row['entry'] == row['expected_return_address'] and
                    previous['entry'] == row['function_entry'] and
                    row['original_return_R0'] == registers['r0'] and
                    row.get('stack_and_return_pair_match') is True)
                need(valid, 'return lacks its actual SP/LR entry pair')
                if valid:
                    consumed.add(row['entry_sequence'])
                pair = dict(entry_sequence=row.get('entry_sequence'), completion_sequence=sequence,
                    function_entry=row['function_entry'], return_address=row['entry'],
                    original_return_R0=row['original_return_R0'],
                    status='verified' if valid else 'failed_or_incomplete')
                result['return_pairs'].append(pair)
                item.update(function_entry=row['function_entry'], R0=row['original_return_R0'])
                if is_classification:
                    stores = classification_stores.get(row.get('entry_sequence'), [])
                    complete = bool(valid and len(stores) == 1)
                    need(complete, 'classification return lacks one actual original store in its SP/LR pair')
                    classified = dict(entry_sequence=row.get('entry_sequence'), return_sequence=sequence,
                        return_classification=control[0x14],
                        status='failed_or_incomplete', input_pointer_argument=False,
                        physical_battery_state_meaning_verified=False)
                    if complete:
                        store = stores[0]
                        register, value = CLASSIFICATION_STORES[int(store['entry'], 16)]
                        stored_value = int(store[register], 16) & 0xff
                        need(control[0x14] == stored_value == value,
                             'classification return differs from the actual original store value')
                        stable = (previous['classification_input8_hex'] ==
                            store['classification_input8_hex'] == row['classification_input8_hex'] and
                            previous['main_body_state'] == store['main_body_state'] == state)
                        predicted = classification_from_globals(
                            bytes.fromhex(previous['classification_input8_hex']), previous['main_body_state'])
                        if stable:
                            need(predicted == stored_value,
                                 'classification branch differs from stable original global inputs')
                        classified.update(store_sequence=store['observation_sequence'],
                            original_store_PC=store['entry'], original_store_register=register,
                            original_stored_value=stored_value,
                            input8_hex_at_entry=previous['classification_input8_hex'],
                            body_state_at_entry=previous['main_body_state'],
                            statically_recomputed_classification=predicted,
                            input_snapshots_stable=stable,
                            status='verified_original_classification_store_and_return' if stable else
                                   'original_store_and_return_observed_inputs_changed',
                            scope='Actual original store and paired return; entry/store/return SRAM '
                                  'are stopped samples, not continuous physical observation')
                    result['classification_calls'].append(classified)
            elif phase in ('entry', 'instruction'):
                need(address in POINTS and phase == ('entry' if address in R0_BODY | R1_BODY | R2_BODY | PAIRED_RETURNS
                    else 'instruction'), 'unknown entry or instruction phase')
                need(all(row[key] == registers[key.lower()] for key in ('R0', 'R1', 'R2', 'R3')),
                     'entry arguments differ from actual registers')
                pointer = (int(registers['r1'], 16) if address in R1_BODY else
                           int(registers['r2'], 16) if address in R2_BODY else
                           int(registers['r0'], 16) if address in R0_BODY else None)
                need(row['argument_body_pointer'] == (hex(pointer) if pointer is not None else None),
                     'body argument pointer differs from the original ABI')
                if pointer is not None and RAM_BASE <= pointer <= RAM_BASE + RAM_BYTES - 64:
                    argument = raw(row, 'argument_body64_hex', 64)
                    if pointer == BODY_BASE:
                        need(argument == body, 'main body argument differs from the same stopped SRAM')
                else:
                    need(row['argument_body64_hex'] is None, 'out-of-SRAM body argument was misclassified')
                if address in PAIRED_RETURNS:
                    caller = int(registers['r14'], 16)
                    need(caller & 1 and ROM_BASE <= (caller & ~1) < ROM_BASE + len(rom) and
                         row['expected_return_address'] == hex(caller & ~1) and
                         row.get('return_point_is_original_Thumb_ROM') is True, 'paired return address is invalid')
                    pending[sequence] = row
                if address in CLASSIFICATION_STORES:
                    register, expected = CLASSIFICATION_STORES[address]
                    candidates = [e for s, e in pending.items() if s not in consumed and
                        int(e['entry'], 16) == CLASSIFICATION_ENTRY and
                        e['stack_address'] == row['stack_address'] and
                        e['caller_return_register'] == row['caller_return_register']]
                    need(len(candidates) == 1 and int(row['R0'], 16) == CONTROL_BASE and
                         int(row[register], 16) & 0xff == expected,
                         'classification store lacks its original global destination/value and entry')
                    if len(candidates) == 1:
                        classification_stores.setdefault(candidates[0]['observation_sequence'], []).append(row)
                    item.update(original_store_value=int(row[register], 16) & 0xff,
                                original_store_register=register)
                item['R0'] = row['R0']
            else:
                need(False, 'unknown task phase')
            result['timeline'].append(item)
        counts = Counter(hex(address) for address, sequence in {
            (int(e['entry'], 16), e['observation_sequence']) for e in events})
        need(all(n <= MAX_HITS for n in counts.values()), 'observer stop limit exceeded')
        remaining = [e for sequence, e in pending.items() if sequence not in consumed]
        completion = mcu.get('battery_task_trace_completion', {})
        need(completion.get('observed_events') == len(events) and
             completion.get('unmatched_return_entries') == len(remaining) and
             completion.get('pending_return_points') == sorted({e['expected_return_address'] for e in remaining},
                                                              key=lambda p: int(p, 16)),
             'completion summary differs from actual paired events')
        result.update(observed_events=len(events), stops_by_address=dict(counts),
            unmatched_return_entries=len(remaining), limit_reached=mcu.get('battery_task_trace_limit_reached', []))
        result['status'] = ('bounded_partial_observation' if remaining or result['limit_reached'] else
                            'verified_passive_task_observation' if events else 'post_configuration_tasks_not_observed')
    except (KeyError, TypeError, ValueError) as error:
        issues.append('Battery task timing: ' + str(error))
    if issues:
        result['status'] = 'failed_or_incomplete'
    result['errors'] = list(dict.fromkeys(issues))
    return result, result['errors']
