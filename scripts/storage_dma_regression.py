"""Read real run-local SD sectors through guest-programmed SDMA and ADMA.

This opt-in synthetic fixture exercises the production single-QEMU board.
Only its private RAM code and input registers are installed by the debugger;
guest STR instructions program the controllers and descriptors. It never
counts as original firmware, physical storage, MENU or camera acceptance.
"""
import argparse
from datetime import datetime
import hashlib
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import uuid

from z62_common import ROOT, clean_environment, runtime_environment, read, save, identity, digest, now
from architecture_regression import FixtureSession, ledger_audit
from native_unified_probe import recipes, prepare_native, initial_observation
from run_evidence import ProcessLedger


# Both generated E6 profiles back this 64 KiB software RAM window. Keep
# fixture data beyond the bounded code-load page and inside that window;
# addresses just above 0x8000ffff are deliberately strict/unmodeled.
FIXTURE_RAM_BASE, FIXTURE_RAM_BYTES = 0x80000000, 0x10000
DESCRIPTOR_ADDRESS, BUFFER_ADDRESS = 0x80002000, 0x80003000


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--build-dir', type=Path, help='Contained immutable rebuilt directory; default latest')
    parser.add_argument('--output-dir', type=Path)
    args = parser.parse_args()
    os.chdir(ROOT)
    if args.build_dir:
        folder = args.build_dir.resolve(strict=True)
        folder.relative_to(ROOT / 'artifacts/rebuilt')
        selection = {key: identity(folder / name) for key, name in (
            ('binary', 'qemu-system-arm'), ('EXPEED_manifest', 'EXPEED-build-manifest.json'),
            ('MCU_manifest', 'MCU-build-manifest.json'), ('build_status', 'build-status.json'))}
        selection['directory'] = str(folder.relative_to(ROOT))
    else:
        selection = read(ROOT / 'artifacts/rebuilt/latest.json')
    if not selection:
        parser.error('Build the contained production QEMU first')
    fixture = read(ROOT / 'tests/architecture/fixture.json')
    profile = read(ROOT / 'profiles/native/profile.json')
    name = datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:6]
    run = (args.output_dir or ROOT / 'results/storage-dma-regressions' / name).resolve()
    run.mkdir(parents=True, exist_ok=False)
    target = run / 'result.json'
    report = dict(schema='z62.storage-dma-regression/1', started=now(),
        classification='synthetic structural fixture', camera_access=False,
        original_boot_or_camera_acceptance=False, physical_slot_mapping_verified=False,
        firmware_files_modified=False, production_debugger_zero_write_policy_modified=False,
        selected_build=selection, fixture_code=fixture, runner=identity(__file__), checks=[], passed=False)
    report['fixture_RAM_layout'] = dict(
        mapped_software_window=dict(base=FIXTURE_RAM_BASE, bytes=FIXTURE_RAM_BYTES),
        descriptor=dict(address=DESCRIPTOR_ADDRESS, bytes=8),
        buffer=dict(address=BUFFER_ADDRESS, bytes=512),
        physical_RAM_capacity_verified=False)
    save(target, report)
    session = prepared = process = stream = None
    lifecycle = ProcessLedger(run, 'unified-storage-DMA-fixture')

    def check(label, passed, **evidence):
        report['checks'].append(dict(name=label, passed=bool(passed), **evidence))
        save(target, report)
        print(('PASS ' if passed else 'FAIL ') + label, flush=True)
        if not passed:
            raise AssertionError(label)

    try:
        for item in (selection['binary'], selection['EXPEED_manifest'], selection['MCU_manifest']):
            assert digest(ROOT / item['path']) == item['sha256'], 'Selected build identity changed'
        program = fixture['programs']['e6']
        code_start = program['load_address']
        code_end = code_start + program['binary']['bytes']
        for address, length in ((DESCRIPTOR_ADDRESS, 8), (BUFFER_ADDRESS, 512)):
            assert FIXTURE_RAM_BASE <= address < address + length <= FIXTURE_RAM_BASE + FIXTURE_RAM_BYTES
            assert address >= code_end or address + length <= code_start, 'Fixture data overlaps code'
        for key in ('source', 'binary'):
            assert identity(ROOT / program[key]['path']) == program[key], 'Fixture code identity changed'
        baseline_file, mcu_file = ROOT / profile['baseline'], ROOT / profile['mcu']
        baseline, mcu = recipes(baseline_file, mcu_file)
        assert baseline.get('slave-sdhci-mode') == 'fat-card', 'Fixture needs run-local virtual SD media'
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
            mcu_manifest=ROOT / selection['MCU_manifest']['path'], baseline_command_json=baseline_file,
            mcu_profile_json=mcu_file, bus_tool=bus_tool, poll_ns=profile['poll_ns'],
            known_wait_ms=profile['known_wait_ms'])
        prepared = prepare_native(prepare_args, run, baseline, mcu, report)
        payloads = []
        for channel, medium in enumerate(report['virtual_SD_cards']):
            payload = bytes(1 + (i * 73 + channel * 41) % 255 for i in range(512))
            filename = Path(medium['path'])
            # Sector128 is outside all declared FAT partitions. This changes
            # only freshly created fixture files, before QEMU opens them.
            filename.relative_to(run / 'slave')
            with filename.open('r+b') as disk:
                disk.seek(128 * 512)
                disk.write(payload)
            medium['storage_fixture'] = dict(LBA=128, bytes=512, sha256=hashlib.sha256(payload).hexdigest())
            payloads.append(payload)
        save(run / 'inputs.json', report['virtual_SD_cards'])
        stream = (run / 'qemu.log').open('w')
        lifecycle.attempting(prepared['command'])
        process = subprocess.Popen(prepared['command'], env=prepared['env'], cwd=run,
                                   stdout=stream, stderr=subprocess.STDOUT)
        lifecycle.started(process)
        session = FixtureSession(run, process, prepared['qmp_port'], prepared['gdb_port'], prepared['instance_uuid'])
        session.pa_manifest_verified = report['selected_unified_build_contract']['CPU_selected_PA_GDB_source_verified'] is True
        initial_observation(session, prepared, report)
        topology = session.architecture_sample('before_storage_fixture')
        check('production_one_QEMU_five_CPUs_three_private_domains',
              topology['pid'] == process.pid and len(topology['cpus']) == 5 and len(topology['domains']) == 3,
              topology=topology, UUID=prepared['instance_uuid'])
        if prepared['peer']:
            prepared['peer'].wait_connected()
        code = (ROOT / program['binary']['path']).read_bytes()
        for cpu in (0, 2):
            session.load_ram(cpu, program['load_address'], code)
        begin = program['load_address'] + program['symbols']['e6_store']
        end = program['load_address'] + program['symbols']['e6_store_done']

        def store(cpu, address, value):
            session.set_reg(cpu, 'r0', value, 'storage fixture guest STR value')
            session.set_reg(cpu, 'r1', address, 'storage fixture guest STR address')
            session.set_reg(cpu, 'r15', begin, 'enter storage fixture guest STR')
            session.step_fixture(cpu)
            if session.reg(cpu, 'r15') != end:
                raise RuntimeError('Guest STR did not reach fixture end')

        def word(address):
            return int.from_bytes(session.read_va(2, address, 4), 'little')

        def command(base, index, argument=0, response=0x1a, transfer=0):
            store(2, base + 0x30, 0xffffffff)
            store(2, base + 8, argument)
            store(2, base + 0xc, ((index << 8 | response) << 16) | transfer)
            status = word(base + 0x30)
            if status & 0xffff0000 or not status & 1:
                raise RuntimeError('SD command%d failed: status=%08x' % (index, status))
            return word(base + 0x10)

        # Same virtual addresses deliberately carry conflicting contents in
        # the two E6 domains. ADMA must read the slave descriptor and must
        # write only the slave buffer, for each independent SD controller.
        descriptor, buffer = DESCRIPTOR_ADDRESS, BUFFER_ADDRESS
        for offset in range(0, 512, 64):
            store(0, buffer + offset, 0xa15a0000 | offset)
        store(0, descriptor, 0xdeadbeef)
        store(0, descriptor + 4, 0xdeadbeef)
        master_buffer = session.read_va(0, buffer, 512)
        master_descriptor = session.read_va(0, descriptor, 8)
        for channel in range(2):
            base = 0x2a810000 + channel * 0x1000
            store(2, base + 0x28, 0x00000f10)  #3.3V/power, ADMA2-32
            store(2, base + 0x2c, 0x00000007)  #internal/SD clock
            store(2, base + 0x34, 0xffffffff)  #native status enable
            check('host%d_card_present' % channel, bool(word(base + 0x24) & (1 << 16)))
            command(base, 0, response=0)
            command(base, 8, 0x1aa)
            for attempt in range(8):
                command(base, 55)
                ocr = command(base, 41, 0x40ff8000, response=2)
                if ocr & 0x80000000:
                    break
                session.advance(2, virtual_ns=1000000)
            check('host%d_standard_SD_protocol_initializes' % channel, bool(ocr & 0x80000000), OCR=ocr)
            command(base, 2, response=9)
            rca = command(base, 3) & 0xffff0000
            command(base, 7, rca, response=0x1b)
            if not ocr & 0x40000000:
                command(base, 16, 512)
            argument = 128 if ocr & 0x40000000 else 128 * 512
            for mode in ('ADMA2-32', 'SDMA'):
                store(2, base + 0x28, 0x00000f10 if mode == 'ADMA2-32' else 0x00000f00)
                # Clear through actual guest stores before each independent read.
                for offset in range(0, 512, 4):
                    store(2, buffer + offset, 0)
                store(2, base + 4, (1 << 16) | 512)
                if mode == 'ADMA2-32':
                    store(2, descriptor, (512 << 16) | 0x23)  #valid/end/transfer
                    store(2, descriptor + 4, buffer)
                    store(2, base + 0x58, descriptor)
                    store(2, base + 0x5c, 0)
                else:
                    store(2, base, buffer)
                command(base, 17, argument, response=0x3a, transfer=0x13)
                status = word(base + 0x30)
                for attempt in range(8):
                    if status & 2 or status & 0xffff0000:
                        break
                    session.advance(2, virtual_ns=1000000)
                    status = word(base + 0x30)
                actual = session.read_va(2, buffer, 512)
                untouched = session.read_va(0, buffer, 512) == master_buffer
                desc_untouched = session.read_va(0, descriptor, 8) == master_descriptor
                check('host%d_%s_read_exact_sector_into_slave_private_RAM' % (channel, mode),
                      actual == payloads[channel] and bool(status & 2) and not status & 0xffff8000
                      and untouched and desc_untouched,
                      status=status, ADMA_error=word(base + 0x54), descriptor_address=descriptor,
                      buffer_address=buffer, LBA=128, expected_sha256=hashlib.sha256(payloads[channel]).hexdigest(),
                      actual_sha256=hashlib.sha256(actual).hexdigest(), master_buffer_unchanged=untouched,
                      master_descriptor_unchanged=desc_untouched)
        report['storage_checks_passed'] = True
    except BaseException as error:
        report.update(error=type(error).__name__ + ': ' + str(error), storage_checks_passed=False)
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
            report['instruction_control'] = session.control
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
        report['passed'] = bool(report.get('storage_checks_passed') and not cleanup_errors
            and report.get('debugger_fixture_audit', {}).get('all_actual_writes_accounted')
            and report['process_lifecycle'].get('exit_code') == 0)
        save(target, report)
        save(ROOT / 'results/storage-dma-regressions/latest.json',
             dict(result=str(target.relative_to(ROOT)), passed=report['passed']))
        print('Storage DMA regression report: ' + str(target.relative_to(ROOT)), flush=True)
    return int(not report['passed'])


if __name__ == '__main__':
    raise SystemExit(main())
