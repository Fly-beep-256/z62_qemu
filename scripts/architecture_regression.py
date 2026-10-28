"""Active structural regression of the production single-instance topology.

This is an explicitly synthetic RAM-only fixture. Register and RAM writes are
audited, bounded and counted. Its result is never camera or original-boot
acceptance. The normal native runner keeps its zero-write debugger facade.
"""
import argparse
import copy
from datetime import datetime
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid
from types import SimpleNamespace

from z62_common import ROOT, HARNESS, clean_environment, runtime_environment, read, save, identity, digest, now

sys.dont_write_bytecode = True
sys.path.insert(0, str(HARNESS))
from native_unified_probe import UnifiedSession, recipes, prepare_native, initial_observation
from run_evidence import ProcessLedger


class FixtureSession(UnifiedSession):
    """Separate opt-in mutation interface; production command() is untouched."""
    def __init__(self, *args, **kwargs):
        self.fixture_writes = []
        self.fixture_controls = []
        super().__init__(*args, **kwargs)

    def reg_descriptor(self, cpu, name):
        mapping = self.register_map(cpu)
        aliases = {'r13': 'sp', 'r14': 'lr', 'r15': 'pc', 'cpsr': 'xpsr'}
        actual = name if name in mapping else aliases.get(name, name)
        if actual not in mapping:
            raise ValueError('Missing actual register XML descriptor: ' + name)
        return actual, mapping[actual]

    def reg(self, cpu, name):
        self.select_cpu(cpu)
        _, (number, bits) = self.reg_descriptor(cpu, name)
        raw = self.command('p%x' % number)
        value = bytes.fromhex(raw)
        if len(value) * 8 != bits:
            raise ValueError('Short fixture register read')
        return int.from_bytes(value, 'little')

    def _write(self, cpu, packet, record):
        self.select_cpu(cpu)
        start = self.rsp_ledger.offsets['tx']
        reply = self.remote.command(packet)
        end = self.rsp_ledger.offsets['tx']
        self.fixture_writes.append(dict(global_cpu=cpu, thread=self.threads[cpu],
            packet=packet, RSP_tx_start=start, RSP_tx_end=end, reply=reply,
            stop_epoch=self.stop_epoch, classification='synthetic structural fixture', **record))
        if reply != 'OK':
            raise RuntimeError('Fixture write rejected: ' + reply)

    def set_reg(self, cpu, name, value, purpose):
        # No CPSR/system register override is needed to perform these tests.
        if name not in ('r0', 'r1', 'r2', 'r15'):
            raise ValueError('Register outside the RAM fixture input/entry contract')
        actual, (number, bits) = self.reg_descriptor(cpu, name)
        packet = 'P%x=%s' % (number, int(value).to_bytes(bits // 8, 'little').hex())
        self._write(cpu, packet, dict(operation='register', register=actual, value=value, purpose=purpose))

    def load_ram(self, cpu, address, payload):
        lower, upper = (0x2003e000, 0x2003f000) if cpu == 4 else (0x80000000, 0x80001000)
        if not payload or not lower <= address < address + len(payload) <= upper:
            raise ValueError('Code load outside bounded private fixture RAM')
        self._write(cpu, 'M%x,%x:%s' % (address, len(payload), payload.hex()),
                    dict(operation='RAM', address=address, bytes=len(payload),
                         sha256=hashlib.sha256(payload).hexdigest(), purpose='install RAM-only structural test code'))
        if self.read_va(cpu, address, len(payload)) != payload:
            raise ValueError('Fixture code readback mismatch')

    def step_fixture(self, cpu):
        self.select_cpu(cpu)
        self.remote.send('vCont;s:' + self.threads[cpu])
        self.running = True
        packet = self.receive_stop(5)
        if packet is None or self.stopped_cpu(packet) != cpu:
            raise RuntimeError('Fixture step lacks an attributed stop')
        self.control.append(dict(action='step_synthetic_fixture_instruction', global_cpu=cpu,
                                 stop_epoch=self.stop_epoch, packet=packet))
        return packet

    def resume_cpu(self, cpu):
        self.select_cpu(cpu)
        self.remote.send('vCont;c:' + self.threads[cpu])
        self.running = True
        self.control.append(dict(action='continue_only_fixture_CPU', global_cpu=cpu,
                                 stop_epoch=self.stop_epoch, thread=self.threads[cpu]))

    def advance(self, cpu, virtual_ns=10000, host_timeout=5):
        before = self.clock()
        self.resume_cpu(cpu)
        deadline = time.monotonic() + host_timeout
        while self.clock() < before + virtual_ns:
            if self.receive_stop(0) is not None:
                raise RuntimeError('Unexpected breakpoint during fixture time advance')
            if time.monotonic() > deadline:
                self.interrupt()
                raise TimeoutError('Fixture virtual time did not advance')
            time.sleep(.005)
        self.interrupt()
        after = self.clock()
        return dict(global_cpu=cpu, before_virtual_ns=before, after_virtual_ns=after,
                    minimum_requested_ns=virtual_ns, host_sleep_is_guest_time=False)

    def architecture_sample(self, label):
        self.read_architecture_qom(label)
        return copy.deepcopy(self.architecture['QOM'])


def ledger_audit(session):
    """Check actual transmitted packets against every declared fixture write."""
    raw = (session.run / 'RSP-tx.bin').read_bytes()
    packets = []
    for match in re.finditer(rb'\$([^#]*)#([0-9a-fA-F]{2})', raw):
        payload, checksum = match.groups()
        if sum(payload) % 256 != int(checksum, 16):
            raise ValueError('Actual fixture RSP TX checksum mismatch')
        packets.append(payload.decode('ascii'))
    actual = [p for p in packets if p.startswith(('P', 'G', 'M', 'X'))]
    expected = [w['packet'] for w in session.fixture_writes]
    return dict(actual_guest_write_packets=len(actual), declared_fixture_write_packets=len(expected),
                all_actual_writes_accounted=actual == expected,
                RAM_write_packets=sum(p.startswith('M') for p in actual),
                register_write_packets=sum(p.startswith('P') for p in actual),
                Flash_write_packets=0, production_zero_write_facade_modified=False,
                packet_count=len(packets), ledgers={name: ledger.summary() for name, ledger in
                    (('RSP', session.rsp_ledger), ('QMP', session.qmp_ledger))})


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir', type=Path)
    args = parser.parse_args()
    os.chdir(ROOT)
    profile = read(ROOT / 'profiles/native/profile.json')
    selection = read(ROOT / 'artifacts/rebuilt/latest.json')
    if not selection:
        parser.error('Build the contained production QEMU first')
    fixture = read(ROOT / 'tests/architecture/fixture.json')
    if not fixture:
        parser.error('Assemble tests with scripts/build_architecture_fixture.py first')
    name = datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:6]
    run = (args.output_dir or ROOT / 'results/architecture-regressions' / name).resolve()
    run.mkdir(parents=True, exist_ok=False)
    target = run / 'result.json'
    report = dict(schema='z62.architecture-regression/1', started=now(),
        classification='synthetic structural fixture', camera_access=False,
        original_boot_or_camera_acceptance=False, physical_architecture_certified=False,
        firmware_files_modified=False, production_debugger_zero_write_policy_modified=False,
        selected_build=selection, fixture_code=fixture, runner=identity(__file__),
        checks=[], limitations=[], passed=False)
    save(target, report)
    session = prepared = process = stream = None
    lifecycle = ProcessLedger(run, 'unified-architecture-fixture')

    def check(label, passed, **evidence):
        report['checks'].append(dict(name=label, passed=bool(passed), **evidence))
        save(target, report)
        print(('PASS ' if passed else 'FAIL ') + label, flush=True)
        if not passed:
            raise AssertionError(label)

    try:
        for item in (selection['binary'], selection['EXPEED_manifest'], selection['MCU_manifest']):
            assert digest(ROOT / item['path']) == item['sha256'], 'Selected build identity changed'
        for program in fixture['programs'].values():
            for key in ('source', 'binary'):
                assert identity(ROOT / program[key]['path']) == program[key], 'Fixture identity changed'
        baseline_file, mcu_file = ROOT / profile['baseline'], ROOT / profile['mcu']
        baseline, mcu = recipes(baseline_file, mcu_file)
        env = clean_environment()
        env.update(runtime_environment(read(ROOT / profile['environment']), run, run / 'prepare'))
        os.environ.clear()
        os.environ.update(env)
        status = read(ROOT / selection['build_status']['path'])
        bus_id = selection.get('bus_binary') or status.get('bus_binary')
        bus_tool = ROOT / bus_id['path'] if bus_id else ROOT / 'bin/mcu-wire-host'
        if bus_id:
            assert digest(bus_tool) == bus_id['sha256'], 'Selected wire tool identity changed'
        prepare_args = SimpleNamespace(qemu_manifest=ROOT / selection['EXPEED_manifest']['path'],
            mcu_manifest=ROOT / selection['MCU_manifest']['path'],
            baseline_command_json=baseline_file, mcu_profile_json=mcu_file,
            bus_tool=bus_tool, poll_ns=profile['poll_ns'], known_wait_ms=profile['known_wait_ms'])
        prepared = prepare_native(prepare_args, run, baseline, mcu, report)
        stream = (run / 'qemu.log').open('w')
        lifecycle.attempting(prepared['command'])
        process = subprocess.Popen(prepared['command'], env=prepared['env'], cwd=run,
                                   stdout=stream, stderr=subprocess.STDOUT)
        lifecycle.started(process)
        session = FixtureSession(run, process, prepared['qmp_port'], prepared['gdb_port'], prepared['instance_uuid'])
        session.pa_manifest_verified = report['selected_unified_build_contract']['CPU_selected_PA_GDB_source_verified'] is True
        initial_observation(session, prepared, report)
        original = session.architecture_sample('before_fixture_install')
        report['initial_production_topology'] = original
        systick_reset_state = {name: int.from_bytes(session.read_va(4, addr, 4), 'little')
                               for name, addr in (('CTRL', 0xe000e010),
                                                  ('LOAD', 0xe000e014),
                                                  ('VAL', 0xe000e018))}
        report['initial_MCU_SysTick_reset_state'] = systick_reset_state
        cpus = original['cpus']
        check('one_QEMU_five_CPUs_three_domains_two_GICs',
              original['pid'] == process.pid and len(cpus) == 5 and len(original['domains']) == 3
              and len(original['gics']) == 2 and len(session.threads) == 5
              and len({c['thread-id'] for c in session.architecture['query_cpus_fast']}) == 1,
              PID=process.pid, UUID=prepared['instance_uuid'], discovered_threads=session.threads)
        if prepared['peer']:
            prepared['peer'].wait_connected()
        programs = fixture['programs']
        for cpu in (0, 2, 4):
            role = 'mcu' if cpu == 4 else 'e6'
            p = programs[role]
            session.load_ram(cpu, p['load_address'], (ROOT / p['binary']['path']).read_bytes())

        def execute(cpu, name, inputs=None):
            role = 'mcu' if cpu == 4 else 'e6'
            p = programs[role]
            begin, end = (p['load_address'] + p['symbols'][role + '_' + name + suffix]
                          for suffix in ('', '_done'))
            for reg, value in (inputs or {}).items():
                session.set_reg(cpu, reg, value, name + ' input')
            session.set_reg(cpu, 'r15', begin, 'enter synthetic ' + name)
            before, steps = session.clock(), 0
            while session.reg(cpu, 'r15') != end:
                if steps >= 64:
                    raise RuntimeError('Fixture failed to reach its named end: ' + name)
                session.step_fixture(cpu)
                steps += 1
            return dict(global_cpu=cpu, program=name, entry=begin, done=end,
                        steps=steps, before_virtual_ns=before, after_virtual_ns=session.clock())

        def word(cpu, address):
            return int.from_bytes(session.read_va(cpu, address, 4), 'little')

        def store(cpu, address, value):
            return execute(cpu, 'store', {'r0': value, 'r1': address})

        for cpu in range(4):
            execution = execute(cpu, 'mpidr')
            value = word(cpu, 0x8000f000)
            check('actual_MRC_MPIDR_CPU%d' % cpu, value & 0xffffff == cpu % 2,
                  actual_MPIDR=value, local_core=cpu % 2, execution=execution)

        address = 0x8000f100
        for cpu, value in ((0, 0x11223344), (3, 0x55667788)):
            store(cpu, address, value)
        values = [word(cpu, address) for cpu in range(4)]
        check('private_RAM_isolated_between_E6_shared_within_each_E6',
              values == [0x11223344, 0x11223344, 0x55667788, 0x55667788], address=address, actual_values=values)
        for label, a, b in (('master_buffer', 0xc2900000, 0x42900000),
                            ('slave_DMA', 0x46b00000, 0xc6b00000)):
            offset = 0x100
            store(0, a + offset, 0xa1b2c3d4)
            first = word(2, b + offset)
            store(3, b + offset, 0x5e6f7788)
            second = word(1, a + offset)
            check('bidirectional_guest_STR_shared_' + label,
                  first == 0xa1b2c3d4 and second == 0x5e6f7788,
                  master_address=a + offset, slave_address=b + offset,
                  master_to_slave=first, slave_to_master=second)

        for cpu in range(4):
            execute(cpu, 'gic_enable')

        def ack(cpu):
            execute(cpu, 'gic_ack')
            return word(cpu, 0x8000f008)

        def eoi(cpu, iar):
            execute(cpu, 'gic_eoi', {'r1': iar})

        for sender, recipient in ((0, 1), (1, 0), (2, 3), (3, 2)):
            before = session.architecture_sample('before_SGI_%d_to_%d' % (sender, recipient))
            execute(sender, 'sgi_send', {'r1': (1 << (16 + recipient % 2)) | 5})
            iar = ack(recipient)
            outsiders = {cpu: ack(cpu) for cpu in range(4) if cpu != recipient}
            eoi(recipient, iar)
            after = session.architecture_sample('after_SGI_%d_to_%d' % (sender, recipient))
            other = 1 - sender // 2
            check('SGI_CPU%d_to_CPU%d_stays_in_local_GIC' % (sender, recipient),
                  iar & 0x3ff == 5 and ((iar >> 10) & 7) == sender % 2
                  and all(v & 0x3ff == 1023 for v in outsiders.values())
                  and before['gics'][other]['observed_local_cpu_activity'][0]['SGI_sent'] ==
                      after['gics'][other]['observed_local_cpu_activity'][0]['SGI_sent']
                  and before['gics'][other]['observed_local_cpu_activity'][1]['SGI_sent'] ==
                      after['gics'][other]['observed_local_cpu_activity'][1]['SGI_sent'],
                  actual_IAR=iar, other_CPUs_IAR=outsiders,
                  before_GICs=before['gics'], after_GICs=after['gics'])

        for cpu in range(4):
            for timer, ppi in (('virtual_timer', 27), ('secure_timer', 29)):
                execution = execute(cpu, timer)
                advance = session.advance(cpu)
                iar = ack(cpu)
                outsiders = {n: ack(n) for n in range(4) if n != cpu}
                execute(cpu, timer + '_off')
                eoi(cpu, iar)
                check('%s_CPU%d_PPI%d_local_routing' % (timer, cpu, ppi),
                      iar & 0x3ff == ppi and all(v & 0x3ff == 1023 for v in outsiders.values()),
                      actual_IAR=iar, other_CPUs_IAR=outsiders, execution=execution, advance=advance)

        for cpu in range(4):
            execution = execute(cpu, 'counter')
            counter = int.from_bytes(session.read_va(cpu, 0x8000f010, 8), 'little')
            frequency = word(cpu, 0x8000f018)
            low = execution['before_virtual_ns'] * 48000000 // 1000000000
            high = execution['after_virtual_ns'] * 48000000 // 1000000000
            check('CPU%d_CNTVCT_uses_common_virtual_clock' % cpu,
                  frequency == 48000000 and low <= counter <= high,
                  actual_CNTVCT=counter, actual_CNTFRQ=frequency,
                  virtual_counter_interval=[low, high], execution=execution)

        for cpu in range(4):
            # GIC group 1 is configured by guest STR while still secure.
            # Enter nonsecure SVC and return via an actual SMC/Monitor handler.
            store(cpu, 0x2c001080, 1 << 30)
            store(cpu, 0x2c00141c, 0x00800000)
            store(cpu, 0x2c001000, 3)
            store(cpu, 0x2c002000, 3)
            enter = execute(cpu, 'nonsecure_enter')
            scr_ns = word(cpu, 0x8000f024)
            timer = execute(cpu, 'physical_timer')
            advance = session.advance(cpu)
            iar = ack(cpu)
            outsiders = {n: ack(n) for n in range(4) if n != cpu}
            execute(cpu, 'physical_timer_off')
            eoi(cpu, iar)
            leave = execute(cpu, 'secure_return')
            scr_s = word(cpu, 0x8000f028)
            check('nonsecure_physical_timer_CPU%d_PPI30_local_routing' % cpu,
                  scr_ns & 1 == 1 and scr_s & 1 == 0 and iar & 0x3ff == 30
                  and all(v & 0x3ff == 1023 for v in outsiders.values()),
                  actual_IAR=iar, other_CPUs_IAR=outsiders, actual_SCR_NS=scr_ns,
                  actual_SCR_after_SMC=scr_s, enter_nonsecure=enter, timer=timer,
                  advance=advance, return_secure=leave)

        execute(4, 'mask')
        marker_address, marker = 0x2003ff00, 0xbad06200
        store(4, marker_address, marker)
        store(4, 0xe000e014, 15)  # SysTick reload, 16 cycles at reset HSI.
        store(4, 0xe000e018, 0)
        store(4, 0xe000e010, 7)
        systick_advance = session.advance(4)
        ctrl, icsr = word(4, 0xe000e010), word(4, 0xe000ed04)
        check('MCU_SysTick_runs_on_common_virtual_clock',
              ctrl & 0x10000 != 0 and icsr & (1 << 26) != 0,
              CTRL=ctrl, ICSR=icsr, advance=systick_advance,
              MCU_frequency_hz=session.architecture_sample('armed_MCU_SysTick')['domains'][2]['cpu_hz'])

        before = session.architecture_sample('before_actual_MCU_SYSRESETREQ')
        e6_regs = {cpu: session.registers(cpu) for cpu in range(4)}
        e6_markers = [word(cpu, address) for cpu in range(4)]
        frozen = session.freeze('before_actual_MCU_SYSRESETREQ')
        p = programs['mcu']
        session.set_reg(4, 'r15', p['load_address'] + p['symbols']['mcu_reset'], 'enter actual AIRCR-store fixture')
        reset_vector = 0x080002b4
        if session.command('Z1,%x,2' % reset_vector) != 'OK':
            raise RuntimeError('Cannot set actual original MCU reset-vector breakpoint')
        session.resume_cpu(4)
        packet = session.receive_stop(5)
        if packet is None:
            session.interrupt()
            raise TimeoutError('MCU AIRCR reset did not return to original vector')
        if session.stopped_cpu(packet) != 4:
            raise RuntimeError('Reset vector stop attributed to another CPU')
        session.command('z1,%x,2' % reset_vector)
        after = session.architecture_sample('after_actual_MCU_SYSRESETREQ')
        regs = session.registers(4)
        m_before, m_after = before['domains'][2], after['domains'][2]
        check('MCU_AIRCR_SYSRESETREQ_is_local_preserves_SRAM_and_common_time',
              int(regs['r15'], 16) == reset_vector and int(regs['r13'], 16) == 0x20000c08
              and word(4, marker_address) == marker
              and m_after['SYSRESETREQ_count'] == m_before['SYSRESETREQ_count'] + 1
              and m_after['local_reset_count'] == m_before['local_reset_count'] + 1
              and m_after['system_reset_count'] == m_before['system_reset_count']
              and m_after['cpu_hz'] == m_after['reset_HSI_hz'] == 16000000
              and after['virtual_ns'] >= frozen['first_ns']
              and {cpu: session.registers(cpu) for cpu in range(4)} == e6_regs
              and [word(cpu, address) for cpu in range(4)] == e6_markers
              and all(a['system_reset_count'] == b['system_reset_count']
                      for a, b in zip(before['cpus'][:4], after['cpus'][:4])),
              stop_packet=packet, actual_MCU_registers=regs,
              before_MCU=m_before, after_MCU=m_after,
              before_virtual_ns=before['virtual_ns'], after_virtual_ns=after['virtual_ns'])
        ctrl_after, load_after, val_after, icsr_after = (word(4, addr) for addr in
            (0xe000e010, 0xe000e014, 0xe000e018, 0xe000ed04))
        check('MCU_local_reset_clears_NVIC_SysTick_without_resetting_E6_GICs',
              # With no refclk wired, QEMU keeps CLKSOURCE set at reset.
              # Compare the actual cold reset state and require ENABLE,
              # TICKINT and COUNTFLAG to clear; CLKSOURCE is not an enable.
              ctrl_after == systick_reset_state['CTRL'] and ctrl_after & 0x10003 == 0
              and load_after == systick_reset_state['LOAD'] == 0
              and val_after == systick_reset_state['VAL'] == 0 and icsr_after & (1 << 26) == 0
              and m_after['active_exception'] == 0 and m_after['nvic_pending_exception'] == 0
              and before['gics'] == after['gics'],
              SysTick_CTRL=ctrl_after, SysTick_LOAD=load_after, SysTick_VAL=val_after,
              initial_MCU_SysTick_reset_state=systick_reset_state, ICSR=icsr_after,
              before_GICs=before['gics'], after_GICs=after['gics'])
        final_rom = session.read_va(4, 0x08000000, len(prepared['blobs']['MCU']))
        check('MCU_original_Flash_bytes_preserved_after_fixture', final_rom == prepared['blobs']['MCU'],
              bytes=len(final_rom), actual_sha256=hashlib.sha256(final_rom).hexdigest())
        final_frozen = session.freeze('after_all_structural_checks')
        check('paused_virtual_clock_frozen_no_observed_regression',
              final_frozen['frozen'] and not session.architecture.get('virtual_clock_regressions'),
              frozen_sample=final_frozen, clock_observation_count=session.architecture['clock_observation_count'])
        report['final_production_topology_with_fixture_state'] = session.architecture_sample('final_fixture_state')
        report['structural_checks_passed'] = True
    except BaseException as error:
        report.update(error=type(error).__name__ + ': ' + str(error), structural_checks_passed=False)
        print(report['error'], flush=True)
    finally:
        cleanup_errors = []
        if session:
            try:
                session.interrupt()
                session.qmp('quit')
            except Exception as error:
                cleanup_errors.append('QEMU cleanup: ' + repr(error))
            try:
                session.close()
                report['debugger_fixture_audit'] = ledger_audit(session)
            except Exception as error:
                cleanup_errors.append('Debugger audit: ' + repr(error))
            report['fixture_writes'] = session.fixture_writes
            report['fixture_controls'] = session.fixture_controls
            report['instruction_control'] = session.control
            report['common_clock_observations'] = session.architecture
        if process:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        if prepared and prepared['peer']:
            try:
                report['unused_fixture_battery_peer'] = prepared['peer'].finish()
            except Exception as error:
                cleanup_errors.append('Peer cleanup: ' + repr(error))
        if stream:
            stream.close()
        report['process_lifecycle'] = lifecycle.closed(process)
        report['cleanup_errors'] = cleanup_errors
        report['finished'] = now()
        report['passed'] = bool(report.get('structural_checks_passed') and not cleanup_errors
            and report.get('debugger_fixture_audit', {}).get('all_actual_writes_accounted')
            and report['process_lifecycle'].get('exit') == 'observed'
            and report['process_lifecycle'].get('exit_code') == 0)
        save(target, report)
        save(ROOT / 'results/architecture-regressions/latest.json', dict(result=str(target.relative_to(ROOT)), passed=report['passed']))
        print('Structural regression report: ' + str(target.relative_to(ROOT)), flush=True)
    return int(not report['passed'])


if __name__ == '__main__':
    raise SystemExit(main())
