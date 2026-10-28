"""Read complete original resource extents after both EXPEED CPUs stop.

The reference is previously recorded camera runtime RAM. This module does not
replay it, change the task observer whitelist, or establish a physical Flash
container's provenance. QMP pmemsave copies guest physical memory to new files.
"""
from pathlib import Path
import hashlib
import json
import time
from recorded_ram_input import inspect_spec, identity, REGIONS, ROM_BASE

EXPECTED = {
    '0B': 'dc9cad799ef683b56851abbc907e41f0d80fd3db20280ae384cdb9b3e46b6494',
    '0C': '52602fde0e855277970b1a1ca61af666694f132dd3fc8c0f2fa7825eaf181f07',
}


def load_reference(path, original_master):
    checked, _ = inspect_spec(path, original_master)
    if {item['region'] for item in checked['regions']} != set(REGIONS):
        raise ValueError('Complete Loader audit requires both original extents')
    entries = []
    for item in checked['regions']:
        if item['pass1']['sha256'] != EXPECTED[item['region']]:
            raise ValueError('Recorded resource reference identity changed')
        address, size = REGIONS[item['region']]
        sections = []
        for va in range(address & ~0xfffff, address + size, 0x100000):
            slot = 0x10030000 + (va >> 20) * 4
            raw = original_master[slot-ROM_BASE:slot-ROM_BASE+4]
            descriptor = int.from_bytes(raw, 'little')
            if len(raw) != 4 or descriptor & 3 != 2 or descriptor & 0xfff00000 != va:
                raise ValueError('Original resource L1 section is not identity')
            sections.append(dict(VA=hex(va), original_L1_slot=hex(slot),
                                 original_descriptor=hex(descriptor)))
        entries.append(dict(region=item['region'], address=hex(address), bytes=size,
                            reference=item['pass1'], original_L1_sections=sections))
    return dict(schema='z6ii.loader-runtime-read-reference/1',
                spec=checked['spec'], regions=entries,
                reference_kind='recorded-camera-runtime-RAM',
                original_physical_Flash_container_proven=False,
                original_L1_identity_verified=True, runtime_L1_sampled=False,
                guest_RAM_replay=False, guest_state_writes=0)


def observe(probe, reference, output, stop_gate):
    if probe.role != 'master' or not stop_gate.get('complete'):
        raise ValueError('Complete Loader read requires the two-EXPEED stop gate')
    if not all(stop_gate['roles'][role].get('pause_confirmed')
               for role in ('master', 'slave')):
        raise ValueError('Both EXPEED CPUs must remain paused before Loader reads')
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    report = dict(schema='z6ii.loader-runtime-full-payload-audit/1',
                  host_start_monotonic_ns=time.monotonic_ns(),
                  reference=reference, regions=[],
                  diagnostic_RAM_replay_disabled=True,
                  guest_state_writes=0, task_observer_whitelist_expanded=False,
                  source_provenance='descriptor-derived synthetic Flash container with recorded runtime RAM payloads',
                  original_physical_Flash_container_loaded=False,
                  both_EXPEED_stopped=True, simultaneous_three_process_snapshot=False)
    save_path = output / '完整Loader载荷核验.json'
    try:
        registers = probe.remote.registers()
        report['QMP_status_before'] = status = probe.monitor.command('query-status')
        if status.get('running') is not False or status.get('status') not in ('paused', 'debug'):
            raise ValueError('Master resumed before physical resource memory read')
        for entry in reference['regions']:
            target = output / ('region' + entry['region'] + '-Loader-runtime.bin')
            command = dict(val=int(entry['address'], 0), size=entry['bytes'], filename=str(target))
            reply = probe.monitor.command('pmemsave', command)
            observed = identity(target)
            body = target.read_bytes()
            report['regions'].append(dict(region=entry['region'],
                physical_address=entry['address'], requested_bytes=entry['bytes'],
                QMP_command=dict(execute='pmemsave', arguments=command), QMP_return=reply,
                runtime=observed, reference=entry['reference'],
                all_zero=not any(body),
                complete=observed['bytes'] == entry['bytes'],
                full_SHA_matches_recorded_RAM=observed['bytes'] == entry['bytes'] and
                    observed['sha256'] == entry['reference']['sha256']))
        report['QMP_status_after'] = probe.monitor.command('query-status')
        report['selected_CPU_registers_unchanged'] = probe.remote.registers() == registers
        report['all_payloads_complete'] = all(item['complete'] for item in report['regions'])
        report['all_payloads_match_recorded_RAM'] = all(
            item['full_SHA_matches_recorded_RAM'] for item in report['regions'])
        if not report['selected_CPU_registers_unchanged'] or report['QMP_status_after'].get('running') is not False:
            raise ValueError('Stopped CPU state changed during Loader audit')
    except Exception as exc:
        report['error'] = type(exc).__name__ + ': ' + str(exc)
        raise
    finally:
        report['host_end_monotonic_ns'] = time.monotonic_ns()
        save_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    return dict(path=str(save_path), **report)
