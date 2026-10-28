"""Select retained native UI acceptance by verified bytes and build identity.

The index contains file identities, not success flags. Historical acceptance
remains visible when the selected binary or native environment has changed.
This module never runs QEMU or edits the source run's acceptance.
"""
from pathlib import Path

from z62_common import ROOT, identity, now, read, runtime_environment, save


INDEX = 'results/latest-native-ui-acceptance.json'


def checked(row, base=ROOT):
    if not isinstance(row, dict) or not {'path', 'bytes', 'sha256'} <= row.keys():
        raise ValueError('Missing evidence file identity')
    relative = Path(row['path'])
    if relative.is_absolute():
        raise ValueError('Evidence identity must use a package-relative path')
    path = (base / relative).resolve(strict=True)
    if not path.is_relative_to(base.resolve()) or not path.is_file():
        raise ValueError('Evidence identity escapes its retained directory')
    actual = identity(path, base)
    if any(actual[key] != row[key] for key in ('bytes', 'sha256')):
        raise ValueError('Evidence identity mismatch: ' + row['path'])
    return path


def record(output):
    output = output.resolve(strict=True)
    if not output.is_relative_to((ROOT / 'results').resolve()):
        raise ValueError('UI acceptance must remain in results/')
    pointer = dict(schema='z62.native-ui-acceptance-index/1', updated=now(),
                   report=identity(output / 'report.json'),
                   manifest=identity(output / 'manifest.json'))
    save(ROOT / INDEX, pointer)
    return pointer


def relocate(value, old_root):
    if isinstance(value, str) and old_root and value.startswith(old_root + '/'):
        return str(ROOT / value[len(old_root) + 1:])
    if isinstance(value, list):
        return [relocate(item, old_root) for item in value]
    if isinstance(value, dict):
        return {key: relocate(item, old_root) for key, item in value.items()}
    return value


def verify(pointer, current_binary=None, current_environment=None):
    """Verify a saved index; optional current identities support drift checks."""
    if pointer.get('schema') != 'z62.native-ui-acceptance-index/1':
        raise ValueError('Unknown native UI index schema')
    report_path = checked(pointer['report'])
    manifest_path = checked(pointer['manifest'])
    if report_path.parent != manifest_path.parent or report_path.name != 'report.json':
        raise ValueError('UI report and manifest must be retained together')
    output = report_path.parent
    if not output.is_relative_to(ROOT / 'results'):
        raise ValueError('UI index must refer to results/')
    report, manifest = read(report_path), read(manifest_path)
    if report.get('schema') != 'z62.native-ui-acceptance/2' or \
            manifest.get('schema') != 'z62.native-ui-acceptance-manifest/2':
        raise ValueError('Unknown native UI acceptance schema')
    files = manifest.get('files', [])
    if len({row['path'] for row in files}) != len(files):
        raise ValueError('Duplicate UI manifest file')
    if not any(row['path'] == 'report.json' and
               all(row[key] == pointer['report'][key] for key in ('bytes', 'sha256'))
               for row in files):
        raise ValueError('UI report is missing from its manifest')
    for row in files:
        checked(row, output)
    display = report['display']
    if manifest['source_run'] != display['retained_result'] or \
            manifest['locked_execution'] != display['locked']:
        raise ValueError('UI report and manifest disagree on the source run')
    raw_path = checked(display['retained_result'])
    locked_path = checked(display['locked'])
    envelope = ROOT / 'results' / display['run']
    if raw_path != envelope / 'run/native-unified-result.json' or \
            locked_path != envelope / 'prepare/锁定命令与输入.json':
        raise ValueError('UI source run does not match its envelope')
    raw, locked = read(raw_path), read(locked_path)
    if display['execution'] != 'single-QEMU' or \
            locked.get('execution_model') != 'single-qemu-five-cpu' or \
            locked.get('guest_state_injection') is not False:
        raise ValueError('UI acceptance is not a native single-QEMU execution')
    binary = display['binary']
    checked(binary)
    if locked.get('selected_binary') != binary:
        raise ValueError('UI binary differs from the locked native binary')
    for row in locked.get('build_manifests', []) + locked.get('input_files', []):
        checked(row)
    for row in locked.get('execution_files', []):
        checked(row, envelope)
    for row in report.get('original_event_audit', {}).get('original_ROMs', {}).values():
        checked(row)
    for frame in display['pixels']['frames']:
        checked(frame['image'])
    checks = report['checks']
    required = report['required_check']
    if set(checks) != {'evidence', 'menu-reentry', 'stable-menu', 'exposure'} or \
            any(type(value) is not bool for value in checks.values()) or \
            report['required_check_passed'] is not checks[required]:
        raise ValueError('Inconsistent UI check result')
    debugger = raw.get('debugger_zero_guest_writes', {})
    final = raw.get('final_evidence', {})
    evidence = bool(raw.get('architecture_passed') and final.get('complete') and
                    final.get('common_stop_complete') and final.get('sampling_complete') and
                    debugger.get('verified') and
                    debugger.get('actual_guest_RAM_register_write_count') == 0 and
                    display.get('input_delivery_complete') and
                    report.get('original_event_audit', {}).get('verified') and
                    not report.get('evidence_failures'))
    if checks['evidence'] != evidence or \
            checks['stable-menu'] != bool(evidence and report['menu']['stable_MENU_verified']):
        raise ValueError('UI checks disagree with retained execution evidence')
    if current_binary is None:
        selected = read(ROOT / 'artifacts/rebuilt/latest.json', {})
        current_binary = selected.get('binary')
        if current_binary:
            checked(current_binary)
            for key in ('EXPEED_manifest', 'MCU_manifest'):
                checked(selected[key])
    profile = read(ROOT / 'profiles/native/profile.json')
    if current_environment is None:
        current_environment = runtime_environment(read(ROOT / profile['environment']),
                                                  envelope / 'run', envelope / 'prepare')
    binary_matches = bool(current_binary and binary['sha256'] == current_binary['sha256'] and
                          binary['bytes'] == current_binary['bytes'])
    environment_matches = relocate(locked['environment'], locked.get('package_root_at_run')) == \
        current_environment
    current = binary_matches and environment_matches
    return dict(status='verified_current_binary_and_environment' if current else 'verified_historical',
                run=display['run'], report=identity(report_path), manifest=identity(manifest_path),
                checks=checks, current_checks=checks if current else {key: None for key in checks},
                required_check=required, required_check_passed=report['required_check_passed'],
                binary=binary, current_binary=current_binary,
                binary_matches_current=binary_matches, environment_matches_current=environment_matches,
                final_virtual_ns=final.get('virtual_ns'),
                menu_hold_ns=report['menu'].get('final_reentered_menu_hold_ns'),
                Host_guest_write_packets=debugger.get('actual_guest_RAM_register_write_count'),
                full_camera_status=report['full_camera_status'],
                evidence_basis='verified UI manifest, original run, locked inputs and sources, ROM, binary and pixels')


def snapshot():
    pointer = read(ROOT / INDEX, {})
    if not pointer:
        return dict(status='not_run', current_checks={})
    try:
        return verify(pointer)
    except Exception as error:
        return dict(status='invalid_evidence', error=str(error), current_checks={})
