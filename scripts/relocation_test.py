"""Verify a real package copy, offline rebuild, native run and evidence failures.

The default fresh native check is an explicitly bounded architecture observation.
--complete-scenario also requires every declared virtual-time pad deadline.

All deliberate damage is confined to a disposable copy and restored before
execution. The original package, original evidence and physical camera are not
modified by those tests.
"""
import argparse
from datetime import datetime
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import time
import uuid

from z62_common import ROOT, now, read, save, identity, digest, clean_environment


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', action='store_true', help='Recompile offline inside the moved copy')
    parser.add_argument('--keep', action='store_true', help='Keep the disposable package after the test')
    parser.add_argument('--native-seconds', type=int, default=120,
                        help='Fresh native host budget (1..1200 seconds; default 120)')
    parser.add_argument('--complete-scenario', action='store_true',
                        help='Require the complete virtual pad schedule instead of bounded architecture')
    args = parser.parse_args()
    if not 1 <= args.native_seconds <= 1200:
        parser.error('--native-seconds must be 1..1200')
    name = datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:6]
    output = ROOT/'results/relocation-tests'/name
    logs = output/'logs'
    logs.mkdir(parents=True, exist_ok=False)
    scratch = Path(tempfile.mkdtemp(prefix='z62 relocation ', dir='/private/tmp'))
    copy = scratch/'Z6II QEMU'
    build_scratch = None
    report = dict(schema='z62.relocation-test/2', started=now(),
                  original_package=str(ROOT), temporary_copy=str(copy),
                  copy_path_contains_spaces=' ' in str(copy), other_cwd='/private/tmp',
                  offline_rebuild_requested=args.build, checks=[], camera_access=False,
                  fresh_native_acceptance_scope=('complete_declared_scenario' if args.complete_scenario
                                                 else 'architecture_observation'),
                  fresh_native_host_seconds=args.native_seconds,
                  negative_tests_scope='disposable retained evidence and README only',
                  original_baseline=identity(ROOT/'provenance/package-manifest.json'))
    env = clean_environment()
    env.pop('PYTHONPATH', None)

    def step(label, argv, expected=0, timeout=900):
        log = logs/(label+'.log')
        started = time.monotonic()
        print('Relocation check: ' + label, flush=True)
        with log.open('w') as stream:
            process = subprocess.Popen([str(a) for a in argv], cwd='/private/tmp', env=env,
                                       stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
            heartbeat = started + 25
            while process.poll() is None:
                if time.monotonic() - started > timeout:
                    os.killpg(process.pid, 15)
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, 9)
                        process.wait()
                    raise TimeoutError(label)
                if time.monotonic() > heartbeat:
                    print('%s: %.0fs' % (label, time.monotonic()-started), flush=True)
                    heartbeat = time.monotonic() + 25
                time.sleep(.2)
        item = dict(name=label, argv=[str(a) for a in argv], cwd='/private/tmp',
                    expected_exit=expected, actual_exit=process.returncode,
                    elapsed_seconds=round(time.monotonic()-started, 3),
                    passed=process.returncode == expected, log=identity(log))
        report['checks'].append(item)
        save(output/'test.json', report)
        if not item['passed']:
            raise RuntimeError('%s: expected %d, got %d; see %s' %
                               (label, expected, process.returncode, log.relative_to(ROOT)))

    def clone(source, target, label):
        if target.exists():
            raise FileExistsError(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        step(label, ['/bin/cp', '-cRp', source, target])

    def copied_reference(value, envelope):
        path = Path(value)
        if path.is_absolute():
            return copy/path.relative_to(ROOT)
        local = envelope/path
        return local if local.exists() else copy/path

    try:
        clone(ROOT, copy, 'clone-package-preserving-sparse-files')
        report['copy_method'] = 'macOS cp -cRp; APFS clone, permissions and relative symlinks'
        step('copied-doctor-full', [copy/'z62', 'doctor', '--full'])
        step('copied-retained-native', [copy/'verify.sh', 'latest-native'])
        step('copied-retained-still-disp', [copy/'verify.sh', 'latest-still-disp'])
        step('strict-rejects-unverified-camera', [copy/'verify.sh', 'latest-native', '--strict'], expected=2)

        envelope = copy/'results'/read(copy/'results/latest-native.json')['run']
        retained_lock = read(envelope/'prepare/锁定命令与输入.json')
        unified = retained_lock.get('execution_model') == 'single-qemu-five-cpu'
        if unified:
            endpoint = read(envelope/'run/native-unified-result.json')
            ledgers = endpoint['debugger_zero_guest_writes']
            capture_key = 'complete_expected_connection_capture'
            task_directory = envelope/'run/master/final-task-RAM'
        else:
            endpoint = read(envelope/'run/MCU/结果.json')
            ledgers = endpoint.get('debugger_API_byte_ledgers', endpoint.get('debugger_byte_ledgers', {}))
            capture_key = 'complete_six_connection_capture'
            task_directory = envelope/'run/EXPEED/engines/master/task-RAM'
        report['retained_native_execution_model'] = retained_lock.get('execution_model', 'legacy-three-process')
        ledger = copied_reference(ledgers['RSP']['streams']['tx']['path'], envelope)
        held = ledger.with_name(ledger.name+'.negative-test-hold')
        ledger.rename(held)
        try:
            step('missing-ledger-is-rejected', [copy/'verify.sh', 'latest-native'], expected=1)
            bad = read(envelope/'acceptance.json')
            assert not bad['debugger_assistance'][capture_key]
        finally:
            held.rename(ledger)

        candidates = sorted(task_directory.glob('*.bin'))
        assert candidates, 'No retained raw task RAM'
        task_bytes = candidates[0]
        before = task_bytes.read_bytes()
        original = ROOT/task_bytes.relative_to(copy)
        original_sha = digest(original)
        try:
            task_bytes.write_bytes(bytes([before[0] ^ 1]) + before[1:])
            step('changed-task-RAM-is-rejected', [copy/'verify.sh', 'latest-native'], expected=1)
            bad = read(envelope/'acceptance.json')
            causes = list(bad.get('errors', []))
            causes.extend(bad.get('final_evidence', {}).get('sampling_errors', []))
            identity_errors = [error for error in causes
                               if 'SHA/size changed' in error and str(task_bytes) in error]
            assert identity_errors, 'Changed task RAM was not rejected for its byte identity: ' + repr(causes)
            report['changed_task_RAM_identity_rejection'] = identity_errors
        finally:
            task_bytes.write_bytes(before)
        assert digest(original) == original_sha, 'Original evidence changed'
        report['original_negative_test_reference_unchanged'] = identity(original)

        document = copy/'README.md'
        before = document.read_bytes()
        try:
            document.write_bytes(before + b'\nTemporary integrity-test marker\n')
            step('changed-static-file-is-rejected', [copy/'z62', 'doctor', '--full'], expected=1)
            assert 'Static file, size, executable bit or symlink changed' in (
                logs/'changed-static-file-is-rejected.log').read_text()
        finally:
            document.write_bytes(before)
        step('restored-evidence-passes', [copy/'verify.sh', 'latest-native'])
        step('restored-copied-doctor-full', [copy/'z62', 'doctor', '--full'])

        if args.build:
            # QEMU's upstream configure explicitly rejects spaces and colons in
            # source/build paths. Test compilation in a second genuine copy,
            # then test that newly compiled binary in the copy with spaces.
            build_scratch = Path(tempfile.mkdtemp(prefix='z62-build-', dir='/private/tmp'))
            build_copy = build_scratch/'Z6II-QEMU'
            clone(ROOT, build_copy, 'clone-package-for-upstream-QEMU-build')
            report['offline_build_copy'] = str(build_copy)
            report['upstream_build_path_constraint'] = 'QEMU configure rejects spaces and colons'
            step('copied-offline-build', [build_copy/'z62', 'build', '--jobs', '2'], timeout=1800)
            selected = read(build_copy/'artifacts/rebuilt/latest.json')
            directory = Path(selected['directory'])
            clone(build_copy/directory, ROOT/directory, 'retain-relocated-rebuild')
            clone(build_copy/directory, copy/directory, 'use-relocated-rebuild-in-spaced-copy')
            save(copy/'artifacts/rebuilt/latest.json', selected)
            report['retained_rebuild'] = selected
            report['original_rebuild_selection_changed'] = False

        fresh_command = [copy/'launch.sh', '--profile', 'native', '--binary', 'rebuilt',
                         '--seconds', str(args.native_seconds)]
        if not args.complete_scenario:
            fresh_command.append('--architecture-only')
        step('copied-fresh-native-default-binary', fresh_command,
             timeout=args.native_seconds + 300)
        run_name = read(copy/'results/latest-native.json')['run']
        retained = output/'native-run'
        clone(copy/'results'/run_name, retained, 'retain-relocated-native-evidence')
        step('relocated-evidence-rechecks-at-delivery-root', [ROOT/'verify.sh', retained])
        fresh = read(retained/'acceptance.json')
        assert fresh['package_runtime_status'] == 'verified' and not fresh['errors']
        assert fresh['debugger_assistance']['actual_guest_write_packets'] == 0
        assert fresh['execution_model'] == 'single-qemu-five-cpu'
        assert fresh['lifecycle']['actual_instance_count'] == 1
        assert fresh['debugger_assistance']['expected_connection_count'] == 2
        assert fresh['debugger_assistance']['complete_expected_connection_capture']
        assert fresh['architecture']['passed'] and fresh['final_evidence']['complete']
        report['fresh_run'] = dict(directory=str(retained.relative_to(ROOT)),
                                  acceptance=identity(retained/'acceptance.json'),
                                  binary_selection=read(retained/'prepare/锁定命令与输入.json')['profile']['binary_selection'],
                                  actual_guest_write_packets=0,
                                  acceptance_scope=fresh['acceptance_scope'],
                                  QEMU_instances=1, debugger_connections=2,
                                  architecture_passed=True, final_evidence_complete=True,
                                  pending_virtual_input_indices=fresh.get('external_input_scenario', {}).get(
                                      'pending_schedule_indices', []),
                                  full_camera_status=fresh['full_camera_status'])
        step('copied-final-doctor-full', [copy/'z62', 'doctor', '--full'])
        assert digest(ROOT/'provenance/package-manifest.json') == report['original_baseline']['sha256']
        report['passed'] = True
    except BaseException as error:
        report.update(passed=False, error=type(error).__name__ + ': ' + str(error))
        print(report['error'], flush=True)
    finally:
        report['finished'] = now()
        report['temporary_copy_retained'] = args.keep or not report.get('passed')
        if not report['temporary_copy_retained']:
            shutil.rmtree(scratch)
            if build_scratch is not None:
                shutil.rmtree(build_scratch)
        save(output/'test.json', report)
        save(ROOT/'provenance/relocation-test.json', report)
        print('Relocation report: ' + str((output/'test.json').relative_to(ROOT)), flush=True)
    return int(not report.get('passed'))


if __name__ == '__main__':
    raise SystemExit(main())
