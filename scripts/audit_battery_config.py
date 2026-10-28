"""Check retained original conversion/copy events; never execute or supply state."""
import hashlib


def audit_battery_config(rom, mcu, assistance, rom_observation):
    from ex1850_battery_config import (ConfigObserver, convert_group4, ROM_BASE,
                                      ROM_WINDOWS, GROUP4_BYTES, CACHE_BASE, INFO_BASE)
    issues = []
    enabled = mcu.get('battery_config_trace_enabled') is True
    result = dict(schema='z62.battery-config-timing/1', status='not_observed',
                  enabled=enabled, conversion_pairs=[], copy_pairs=[], timeline=[],
                  guest_state_supplied=False, physical_cold_boot_verified=False,
                  scope='Original stopped conversion/copy events and caller timing; '
                        'final RAM and physical diagnostic caches have separate scopes')
    if not enabled:
        return result, issues

    def need(condition, text):
        if not condition:
            issues.append(text)
        return bool(condition)

    def raw(row, key, length):
        value = bytes.fromhex(row[key])
        if len(value) != length:
            raise ValueError('incomplete ' + key)
        return value

    try:
        ConfigObserver(rom)  # Full original ROM identity and dispatch literals.
        result['original_code_windows'] = [dict(address=hex(p), bytes=n, name=name,
            sha256=hashlib.sha256(rom[p - ROM_BASE:p - ROM_BASE + n]).hexdigest())
            for p, n, name in ROM_WINDOWS]
        observations = mcu.get('observations', [])
        by_sequence = {o['observation_sequence']: o for o in observations if 'observation_sequence' in o}
        events = mcu.get('original_battery_config_events', [])
        flattened = [e for o in observations for e in o.get('original_battery_config_events', [])]
        need(events == flattened, 'Battery config event list differs from actual stopped observations')
        need(bool(events), 'Enabled original battery config trace has no events')
        need(assistance.get('complete_expected_connection_capture',
                            assistance.get('complete_six_connection_capture')) is True and
             assistance.get('actual_guest_write_packets') == 0,
             'Battery config timing requires complete debugger capture with zero guest writes')
        entries, converted, copies, completed_copies = {}, {}, {}, []
        last_sequence = 0
        for row in events:
            sequence, phase = row['observation_sequence'], row['phase']
            observation = by_sequence.get(sequence, {})
            registers = observation.get('registers', {})
            need(type(sequence) is int and sequence >= last_sequence,
                 'Battery config events are not ordered by actual observation sequence')
            last_sequence = sequence
            need(rom_observation(observation) and row['entry'] == observation.get('address') and
                 row['original_ROM_bytes'] == observation.get('original_ROM_bytes'),
                 'Battery config event lacks unchanged original instruction evidence')
            need(row['stack_address'] == hex(int(registers['r13'], 16)) and
                 row['caller_return_register'] == hex(int(registers['r14'], 16)) and
                 row['HAL_tick'] == observation.get('HAL_tick') and
                 row['host_elapsed_seconds'] == observation.get('host_elapsed_seconds'),
                 'Battery config event register/time metadata differs from its stopped state')
            need(row.get('guest_state_written') is False and
                 row.get('peripheral_MMIO_read_by_debugger') is False,
                 'Battery config observer supplied state or read peripheral MMIO')
            info, cache = raw(row, 'info72_hex', 72), raw(row, 'cache72_hex', 72)
            item = dict(observation_sequence=sequence, phase=phase, entry=row['entry'],
                        HAL_tick=row['HAL_tick'], host_elapsed_seconds=row['host_elapsed_seconds'],
                        info72_sha256=hashlib.sha256(info).hexdigest(),
                        cache72_sha256=hashlib.sha256(cache).hexdigest(),
                        auxiliary2_hex=row['auxiliary2_hex'], body_mode=row['body_mode'])
            if phase == 'conversion_entry':
                need(int(row['entry'], 16) == 0x080294F4 and
                     int(row['group4_address'], 16) == int(registers['r0'], 16) and
                     row['correction_R1'] == int(registers['r1'], 16),
                     'Original group4 conversion input differs from its actual ABI')
                source = raw(row, 'group4_hex', GROUP4_BYTES)
                pointer = int(row['group4_address'], 16)
                need(row['group4_region'] == ConfigObserver.region(pointer, GROUP4_BYTES),
                     'Original group4 source region was misclassified')
                need(hashlib.sha256(source).hexdigest() == row['group4_source_sha256'],
                     'Original group4 source digest mismatch')
                expected_initial = (source == rom[pointer - ROM_BASE:pointer - ROM_BASE + GROUP4_BYTES]
                    if ConfigObserver.region(pointer, GROUP4_BYTES) == 'MCU_Flash_mapping' else None)
                need(row['group4_matches_initial_firmware_data'] == expected_initial,
                     'Original group4 initial-versus-current Flash comparison is invalid')
                entries[sequence] = row
                item.update(group4_address=row['group4_address'], correction_R1=row['correction_R1'],
                            group4_matches_initial_firmware_data=expected_initial,
                            group4_source_sha256=row['group4_source_sha256'])
            elif phase == 'conversion_completed':
                previous = entries.get(row.get('conversion_entry_sequence'))
                valid = bool(previous and int(row['entry'], 16) == 0x080298CC and
                    previous['observation_sequence'] < sequence and
                    previous['stack_address'] == row['stack_address'] and
                    previous['caller_return_register'] == row['caller_return_register'] and
                    int(row['output_R0'], 16) == int(registers['r0'], 16) == CACHE_BASE and
                    row.get('stack_and_return_pair_match') is True)
                need(valid, 'Original group4 conversion completion lacks matching SP/LR entry')
                match = bool(valid and convert_group4(raw(previous, 'group4_hex', GROUP4_BYTES),
                    raw(previous, 'cache72_hex', 72), previous['correction_R1']) == cache)
                need(match, 'Original group4 conversion output differs from source-bound reconstruction')
                converted[sequence] = row
                result['conversion_pairs'].append(dict(entry_sequence=row.get('conversion_entry_sequence'),
                    completion_sequence=sequence, stack_and_return_pair_match=valid,
                    source_to_cache_match=match, status='verified' if valid and match else 'failed'))
            elif phase == 'copy_entry':
                source = raw(row, 'copy_source72_hex', 72)
                pointer, caller = int(row['copy_source_address'], 16), int(registers['r14'], 16)
                need(int(row['entry'], 16) == 0x08024998 and pointer == int(registers['r0'], 16) and
                     row['destination_address'] == hex(INFO_BASE) and row['copy_bytes'] == 72 and
                     row['copy_source_region'] == ConfigObserver.region(pointer, 72) and
                     row['expected_return_address'] == hex(caller & ~1) and caller & 1 and
                     ROM_BASE <= (caller & ~1) < ROM_BASE + len(rom) and
                     row.get('return_point_is_original_Thumb_ROM') is True,
                     'Original battery config copy ABI/return address is invalid')
                previous = converted.get(row.get('conversion_completed_sequence'))
                if row.get('conversion_completed_sequence') is not None:
                    need(previous is not None and previous['observation_sequence'] < sequence and
                         previous['stack_address'] == row['stack_address'] and
                         previous['caller_return_register'] == row['caller_return_register'] and
                         pointer == CACHE_BASE and source == raw(previous, 'cache72_hex', 72),
                         'Original conversion-to-copy link has mismatched SP/LR or source bytes')
                copies[sequence] = row
            elif phase == 'copy_completed':
                previous = copies.get(row.get('copy_entry_sequence'))
                valid = bool(previous and previous['observation_sequence'] < sequence and
                    previous['stack_address'] == row['stack_address'] and
                    previous['expected_return_address'] == row['entry'] == row['expected_return_address'] and
                    row.get('stack_and_return_pair_match') is True)
                need(valid, 'Original battery config copy completion lacks its actual SP/LR return pair')
                match = bool(valid and info == raw(previous, 'copy_source72_hex', 72))
                need(match, 'Original 72-byte copy destination differs from the observed source')
                result['copy_pairs'].append(dict(entry_sequence=row.get('copy_entry_sequence'),
                    completion_sequence=sequence, stack_and_return_pair_match=valid,
                    source_to_info_match=match, status='verified' if valid and match else 'failed'))
                if valid and match:
                    completed_copies.append(row)
            else:
                issues.append('Unknown original battery config phase: ' + str(phase))
            result['timeline'].append(item)
        for row in mcu.get('original_cmd89_transaction_returns', []):
            sequence = row.get('observation_sequence')
            observation = by_sequence.get(sequence, {})
            need(observation.get('original_cmd89_transaction_return') == row and
                 row.get('HAL_tick') == observation.get('HAL_tick') and
                 row.get('host_elapsed_seconds') == observation.get('host_elapsed_seconds'),
                 'Original cmd89 return is missing from the shared config observation timeline')
            earlier = [c for c in completed_copies if c['observation_sequence'] < sequence]
            previous = max(earlier, key=lambda c: c['observation_sequence']) if earlier else None
            result['timeline'].append(dict(observation_sequence=sequence, phase='cmd89_return',
                entry=row['entry'], HAL_tick=row['HAL_tick'], host_elapsed_seconds=row['host_elapsed_seconds'],
                TX_hex=row['TX_hex'], returned_R0=row['returned_R0'], body_mode=row['body_mode'],
                auxiliary2_hex=row['auxiliary2_hex'],
                info72_sha256=hashlib.sha256(raw(row, 'info72_hex', 72)).hexdigest(),
                preceding_copy_completion_sequence=previous['observation_sequence'] if previous else None,
                preceding_copy_info_matches_call=(previous['info72_hex'] == row['info72_hex'] if previous else None)))
        result['timeline'].sort(key=lambda r: r['observation_sequence'])
        completion = mcu.get('battery_config_trace_completion', {})
        result['unmatched_conversion_entries'] = completion.get('unmatched_conversion_entries')
        result['unmatched_copy_entries'] = completion.get('unmatched_copy_entries')
        result['limit_reached'] = mcu.get('battery_config_trace_limit_reached', [])
        need(bool(result['conversion_pairs']) and bool(result['copy_pairs']),
             'Original battery configuration conversion/copy chain is incomplete')
        result['status'] = ('failed_or_incomplete' if issues else 'bounded_partial_observation'
            if result['limit_reached'] or result['unmatched_conversion_entries'] or result['unmatched_copy_entries']
            else 'verified_original_configuration_chain')
    except (KeyError, TypeError, ValueError) as error:
        issues.append('Battery config timing: ' + str(error))
        result['status'] = 'failed_or_incomplete'
    result['errors'] = list(dict.fromkeys(issues))
    return result, result['errors']
