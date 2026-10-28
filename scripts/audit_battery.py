"""Audit retained public UART exchanges and unchanged MCU caller returns.

No camera access, guest execution or state writes. Successful synthetic wire
input and original firmware acceptance are measured separately from physical
battery authentication and full camera boot.
"""
from collections import Counter
from pathlib import Path
import sys

from z62_common import HARNESS


def audit_battery(envelope, mcu, assistance, load, checked, ref):
    sys.path[:0] = [str(HARNESS), str(HARNESS / 'tools')]
    from ex1850_battery_peer import load_spec
    from ex1850_cmd89 import BUILDERS, parse_cmd89, reconstruct_cmd89, xor_bytes
    from ex1850_original_prng import auth_tag8_from_public_entropy

    issues = []
    report = dict(schema='z62.original-battery-acceptance/1', status='not_observed',
                  original_authentication_acceptance_observed=False,
                  physical_authentication_verified=False,
                  physical_battery_effects_verified=False,
                  reply_classification='declared public synthetic RNG battery peer',
                  original_cmd89_returns=[], wire_cmd89_exchanges=[],
                  original_cmd89_functional_errors=[],
                  scope='Complete retained public wire bytes and passive original caller returns; '
                        'physical battery ACK, full power-up and camera functions remain separate')
    peer_path = envelope / 'run/MCU/USART1-peer/closed.json'
    if not peer_path.exists():
        if mcu.get('USART1_battery_specification'):
            issues.append('Missing declared battery peer closure')
        return report, issues

    def need(condition, message):
        if not condition:
            issues.append(message)
        return bool(condition)

    try:
        peer = load(peer_path, required=True)
        report['peer_evidence'] = ref(peer_path)
        spec_path = checked(peer['specification'])
        spec, constants = load_spec(spec_path)
        for source in [spec['ROM'], *spec['source_evidence']]:
            checked(source)
        report['specification'] = ref(spec_path)
        contract = spec.get('native_cmd89_acceptance', {})
        required = contract.get('required_TX', [])
        report['required_cmd89_requests'] = required
        if contract.get('proof'):
            proof_path = checked(contract['proof'])
            proof = load(proof_path, required=True)
            report['request_proof'] = ref(proof_path)
            report['physical_camera_comparison'] = proof.get('physical_observations', {})
        rom = checked(spec['ROM']).read_bytes()
        tx_path = checked(peer['streams']['public_TX'])
        rx_path = checked(peer['streams']['synthetic_RX'])
        tx, rx = tx_path.read_bytes(), rx_path.read_bytes()
        report['wire_evidence'] = [ref(tx_path), ref(rx_path)]
        closed = (peer.get('endpoint_closed') is True if peer.get('clock') == 'QEMU_CLOCK_VIRTUAL'
                  else peer.get('worker_stopped') is True)
        need(peer.get('connected') is True and closed,
             'Battery peer lacks a connected, stopped wire closure')
        need(not peer.get('error'), 'Battery peer error: ' + str(peer.get('error')))
        need(not peer.get('unmodeled_public_TX'), 'Battery peer contains unmodeled requests')
        from audit_virtual_battery import audit_virtual_battery
        timing, timing_errors = audit_virtual_battery(peer, checked, ref)
        report['virtual_wire_timing'] = timing
        issues.extend(timing_errors)
        ref(Path(__file__).with_name('audit_virtual_battery.py'))

        # Native frame-external zeros require an original setup/store/completion
        # chain. Keep parsing complete frames for diagnostics after a bad zero,
        # while retaining its hard evidence error. Never scan past other bytes.
        from audit_battery_uart import load_uart_source_log, verify_original_zero
        ref(Path(__file__).with_name('audit_battery_uart.py'))
        native = mcu.get('schema') == 'z62.native-unified-result/1'
        uart_events = {}
        uart = dict(status='not_observed', bytes=[], errors=[],
                    physical_protocol_meaning_verified=False)
        report['unframed_UART'] = uart
        if native:
            try:
                uart_events, source = load_uart_source_log(mcu, checked, ref)
                uart.update(source)
            except (KeyError, TypeError, ValueError, OSError) as error:
                message = 'Battery UART source log: ' + str(error)
                issues.append(message)
                uart['errors'].append(message)
        tx_offset = 0
        rx_offset = 0
        frames, wire_pairs, authentication = [], [], []
        exact = {bytes.fromhex(t['TX']): t for t in spec['exact_transactions']}
        need(len(exact) == len(spec['exact_transactions']), 'Duplicate exact battery request')
        words = spec['public_entropy']['words']
        response = bytes.fromhex(spec['authentication']['response17'])
        auth_seen = False
        while tx_offset < len(tx):
            if tx[tx_offset] == 0:
                try:
                    if native:
                        item = verify_original_zero(rom, tx, tx_offset, uart_events)
                    elif tx_offset == 0:
                        item = dict(wire_offset=0, value=0, source_verified=False,
                            status='legacy_initial_preamble_assumption',
                            physical_protocol_meaning_verified=False)
                    else:
                        raise ValueError('No native source proof for a noninitial zero')
                    uart['bytes'].append(item)
                except (KeyError, TypeError, ValueError) as error:
                    message = 'Battery unframed UART evidence: ' + str(error)
                    issues.append(message)
                    uart['errors'].append(message)
                    uart['bytes'].append(dict(wire_offset=tx_offset, value=0,
                        source_verified=False, status='failed_or_incomplete'))
                tx_offset += 1
                continue
            if len(tx) - tx_offset < 3:
                raise ValueError('Incomplete battery TX header at byte %d' % tx_offset)
            length = tx[tx_offset + 2] + 4
            frame = tx[tx_offset:tx_offset + length]
            if (frame[:1] != b'\x02' or length > 68 or len(frame) != length or xor_bytes(frame)):
                raise ValueError('Invalid complete battery TX at byte %d' % tx_offset)
            sequence = len(frames) + 1
            frames.append(frame)
            if frame[:3] == b'\x02\x01\x11':
                event = next((e for e in peer.get('events', []) if e.get('public_TX') == frame.hex()), {})
                indices = event.get('public_entropy_matching_word_indices') or range(1, len(words) + 1)
                selected = None
                for index in indices:
                    if type(index) is not int or not 1 <= index <= len(words):
                        continue
                    try:
                        tag = auth_tag8_from_public_entropy(constants, words[index - 1], frame, response)
                        selected = index
                        break
                    except ValueError:
                        continue
                if selected is None:
                    raise ValueError('Battery authentication TX C has no declared public RNG match')
                prefix = b'\x02\x06\x00' + tag + response
                expected = prefix + bytes([xor_bytes(prefix)])
                auth_seen = True
                authentication.append(dict(sequence=sequence, public_entropy_word_index=selected,
                                           recomputed_from_public_TX_and_immutable_inputs=True))
            else:
                transaction = exact.get(frame)
                if transaction is None:
                    raise ValueError('Unknown complete battery TX: ' + frame.hex())
                need(auth_seen or transaction.get('allowed_before_authentication') is True,
                     'Post-authentication battery request preceded authentication')
                expected = bytes.fromhex(transaction['RX'])
            actual = rx[rx_offset:rx_offset + len(expected)]
            matched = need(actual == expected,
                           'Battery RX mismatch/truncation for TX sequence %d' % sequence)
            pair = dict(sequence=sequence, TX_hex=frame.hex(), RX_hex=actual.hex(),
                        TX_byte_offset=tx_offset, RX_byte_offset=rx_offset,
                        RX_bytes=len(actual), immutable_contract_match=matched)
            wire_pairs.append(pair)
            if frame[1] == 0x89:
                report['wire_cmd89_exchanges'].append(dict(**pair, fields=parse_cmd89(frame)))
            tx_offset += length
            rx_offset += len(expected)
        need(rx_offset == len(rx), 'Unassociated trailing battery RX bytes')
        need(peer.get('replies') == len(frames), 'Battery reply counter differs from raw exchange count')
        need(peer.get('parser_counts', {}).get('unframed_bytes', 0) == len(uart['bytes']),
             'Battery raw unframed-byte counter mismatch')
        uart['status'] = ('failed_or_incomplete' if uart['errors'] else
            'verified_original_guest_transmissions' if native and uart['bytes'] else
            'legacy_preamble_assumption' if uart['bytes'] else 'not_observed')
        raw_counts = Counter('command_%02x' % f[1] for f in frames)
        for key, count in raw_counts.items():
            need(peer.get('parser_counts', {}).get(key) == count, 'Battery raw TX counter mismatch: ' + key)
        report['wire'] = dict(status='matched' if not issues else 'failed_or_incomplete',
                             complete_TX_frames=len(frames), replies=peer.get('replies'),
                             commands=dict(raw_counts), public_TX_bytes=len(tx), synthetic_RX_bytes=len(rx),
                             initial_zero_preamble_bytes=1 if tx[:1] == b'\0' else 0,
                             frame_external_zero_bytes=len(uart['bytes']),
                             authentication=authentication)

        observations = mcu.get('observations', [])
        auth = mcu.get('original_battery_authentication_comparator', {})
        completion = mcu.get('original_battery_authentication_completion', {})
        auth_obs = next((o for o in observations if o.get('original_battery_authentication_comparator') == auth), {})
        completion_obs = next((o for o in observations if o.get('original_battery_authentication_completion') == completion), {})

        def rom_observation(o):
            address = int(o.get('address', '0'), 16)
            saved = bytes.fromhex(o.get('original_ROM_bytes', ''))
            return bool(saved and rom[address - 0x08000000:address - 0x08000000 + len(saved)] == saved
                        and int(o.get('registers', {}).get('r15', '0'), 16) == address)

        from audit_battery_config import audit_battery_config
        configuration, configuration_errors = audit_battery_config(rom, mcu, assistance, rom_observation)
        report['configuration_timing'] = configuration
        issues.extend(configuration_errors)
        ref(Path(__file__).with_name('audit_battery_config.py'))
        ref(HARNESS / 'ex1850_battery_config.py')
        from audit_battery_task import audit_battery_task
        task, task_errors = audit_battery_task(rom, mcu, assistance, configuration, rom_observation)
        report['passive_task_timing'] = task
        issues.extend(task_errors)
        ref(Path(__file__).with_name('audit_battery_task.py'))
        ref(HARNESS / 'ex1850_battery_task.py')

        body = bytes.fromhex(completion.get('body_hex', ''))
        auth_ok = (bool(authentication) and rom_observation(auth_obs) and rom_observation(completion_obs)
                   and int(auth_obs.get('registers', {}).get('r0', '0'), 16) == 1
                   and len(body) == 64 and body[0] == 1
                   and int.from_bytes(body[4:8], 'little') == 1
                   and int.from_bytes(body[0x14:0x18], 'little') == 0
                   and auth.get('guest_state_written') is False and completion.get('guest_state_written') is False)
        report['original_authentication_acceptance_observed'] = auth_ok
        report['authentication_observation'] = dict(comparator_return=auth.get('comparator_return'),
            completion_ready=completion.get('ready'), completion_error=completion.get('error'),
            source='passive original comparator and ready-store observations')
        if required:
            need(auth_ok, 'Original MCU authentication comparator/ready-store acceptance not observed')

        accepted = Counter()
        for row in mcu.get('original_cmd89_transaction_returns', []):
            try:
                point = int(row['entry'], 16)
                builder = int(row['builder_entry'], 16)
                need((point, builder) in ((0x080244E0, BUILDERS[0]), (0x080247CC, BUILDERS[1])),
                     'Unrecognized original cmd89 return point')
                o = next((o for o in observations if o.get('original_cmd89_transaction_return') == row), {})
                control = bytes.fromhex(row['control_hex'])
                original_tx = bytes.fromhex(row['TX_hex'])
                original_rx = bytes.fromhex(row['RX_hex'])
                parse_cmd89(original_tx)
                saved_body = bytes.fromhex(row['body_hex'])
                matches = [c for c in (reconstruct_cmd89(bytes.fromhex(row['info72_hex']),
                    bytes.fromhex(row['auxiliary2_hex']), row['body_mode'], builder, pin) for pin in (0, 1))
                           if c['frame_hex'] == row['TX_hex']]
                need(bool(matches), 'Original cmd89 TX does not reconstruct from its stopped config')
                request_exists = any(p['TX_hex'] == row['TX_hex'] and p['immutable_contract_match']
                                     for p in wire_pairs)
                pair_exists = any(p['TX_hex'] == row['TX_hex'] and p['RX_hex'] == row['RX_hex']
                                  and p['immutable_contract_match'] for p in wire_pairs)
                # A real failed call is a functional finding only after its
                # ROM, registers, completed request and stopped configuration
                # have passed the same evidence checks as a successful call.
                # Actual CPU4 reply binding is also required by native audit.
                evidence_valid = (rom_observation(o) and row.get('original_instruction_bytes') == '0446'
                         and rom[point - 0x08000000:point - 0x08000000 + 2] == b'\x04\x46'
                         and type(row['returned_R0']) is int
                         and int(o.get('registers', {}).get('r0', '-1'), 16) == row['returned_R0']
                         and len(control) == 6 and control[1:4] == bytes([18, 18, 4])
                         and len(original_rx) == 4
                         and len(saved_body) == 64 and saved_body[0x2E] == row['body_mode']
                         and row.get('guest_state_written') is False and bool(matches) and request_exists)
                valid = (evidence_valid and row['returned_R0'] == 0
                         and control[1:6] == bytes([18, 18, 4, 4, 0])
                         and original_rx[:2] == b'\x02\x06' and xor_bytes(original_rx) == 0
                         and pair_exists)
                failed_call_verified = evidence_valid and row['returned_R0'] != 0
                if failed_call_verified:
                    failure = ('Original cmd89 call returned failure under declared inputs: '
                               + row['entry'] + ' R0=' + str(row['returned_R0']))
                    issues.append(failure)
                    report['original_cmd89_functional_errors'].append(failure)
                elif not evidence_valid:
                    need(False, 'Original cmd89 return evidence failed/incomplete at ' + row['entry'])
                else:
                    need(valid, 'Original cmd89 success return failed/incomplete at ' + row['entry'])
                item = dict(entry=row['entry'], builder=row['builder_entry'], occurrence=row['occurrence'],
                            observation_sequence=row.get('observation_sequence'),
                            HAL_tick=row.get('HAL_tick'), host_elapsed_seconds=row.get('host_elapsed_seconds'),
                            TX_hex=row['TX_hex'], RX_hex=row['RX_hex'], returned_R0=row['returned_R0'],
                            control_hex=row['control_hex'], original_ROM_instruction_verified=rom_observation(o),
                            config_reconstruction_match=bool(matches),
                            matching_READPIN_branches=[c['readpin_result'] for c in matches],
                            READPIN_directly_observed=False, body_mode=row['body_mode'],
                            auxiliary2_hex=row['auxiliary2_hex'], evidence_verified=evidence_valid,
                            status=('verified' if valid else 'original_failure_verified'
                                    if failed_call_verified else 'failed_or_incomplete'))
                report['original_cmd89_returns'].append(item)
                if valid:
                    accepted[row['TX_hex']] += 1
            except (KeyError, TypeError, ValueError) as error:
                issues.append('Invalid original cmd89 return observation: ' + str(error))
        for request in required:
            need(accepted[request] > 0, 'Required original cmd89 return not observed: ' + request)
        if required:
            need(assistance.get('complete_expected_connection_capture',
                                assistance.get('complete_six_connection_capture')) is True
                 and assistance.get('actual_guest_write_packets') == 0,
                 'Native battery acceptance needs complete debugger capture with zero guest writes')
        if mcu.get('budget_SRAM_snapshot'):
            ram = checked(mcu['budget_SRAM_snapshot']).read_bytes()
            report['final_stopped_MCU'] = dict(auxiliary2_hex=ram[0xED99:0xED9B].hex(),
                info72_hex=ram[0x1F4A0:0x1F4E8].hex(), cache72_hex=ram[0x1FAF8:0x1FB40].hex(),
                info72_copies_equal=ram[0x1F4A0:0x1F4E8] == ram[0x1FAF8:0x1FB40],
                body_ready=ram[0x1FB40], body_state=int.from_bytes(ram[0x1FB44:0x1FB48], 'little'),
                body_error=int.from_bytes(ram[0x1FB54:0x1FB58], 'little', signed=True),
                body_mode=ram[0x1FB6E],
                scope='Budget snapshot only; not substituted for caller-time observations')
        report['original_cmd89_accepted_counts'] = dict(accepted)
        report['status'] = ('verified_under_declared_inputs' if required and not issues else
                            'wire_verified_original_returns_partial' if not issues else 'failed_or_incomplete')
    except (KeyError, TypeError, ValueError, OSError) as error:
        issues.append('Battery audit: ' + str(error))
        report['status'] = 'failed_or_incomplete'
    report['errors'] = list(dict.fromkeys(issues))
    return report, report['errors']
