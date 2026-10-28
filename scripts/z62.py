"""Offline, directory-contained Z6II QEMU entry and progress audit."""
import argparse
import math
from pathlib import Path
import os
import platform
import shutil
import signal
import subprocess
import sys
import time
import uuid
from datetime import datetime
from z62_common import ROOT, PYTHON, HARNESS, now, read, save, digest, identity, profiles, clean_environment, expand, runtime_environment, freeze_native_plans

def doctor(full=False, quiet=False, baseline='provenance/package-manifest.json'):
    os.chdir(ROOT)
    checks = []
    def check(name, fn):
        try:
            detail = fn()
            checks.append(dict(name=name, passed=True, detail=detail))
        except Exception as error:
            checks.append(dict(name=name, passed=False, error=type(error).__name__ + ': ' + str(error)))
    def assert_file(path, expected=None):
        path = ROOT / path
        assert path.is_file(), 'Missing: ' + str(path.relative_to(ROOT))
        if expected:
            assert digest(path) == expected, 'SHA256 mismatch: ' + str(path.relative_to(ROOT))
        return identity(path)
    def version(path):
        result = subprocess.run([str(ROOT / path), '--version'], capture_output=True,
                                text=True, timeout=20, env=clean_environment())
        assert result.returncode == 0, result.stderr
        return result.stdout.splitlines()[0]
    def host_platform():
        value = platform.system() + '/' + platform.machine()
        assert value == 'Darwin/arm64', 'The shipped runtime targets macOS Apple Silicon: ' + value
        return value
    check('platform', host_platform)
    check('bundled Python', lambda: version('runtime/python/bin/python3.12'))
    sys.path[:0] = [str(HARNESS), str(HARNESS / 'tools')]
    def dependencies():
        import PIL, numpy, socket, ssl, mmap
        import natural_boot, run_exmcu_qemu_reset
        return dict(Pillow=PIL.__version__, NumPy=numpy.__version__, harness_imports=True)
    check('Python dependencies and harness imports', dependencies)
    def python_bootstrap():
        result = subprocess.run([str(PYTHON), '-E', '-s', '-m', 'ensurepip', '--version'],
                                capture_output=True, text=True, timeout=20, env=clean_environment())
        assert result.returncode == 0, result.stderr
        return result.stdout.strip()
    check('offline Python build bootstrap', python_bootstrap)
    check('bundled OCR', lambda: version('runtime/ocr/bin/tesseract'))
    check('OCR English data', lambda: assert_file('runtime/ocr/share/tessdata/eng.traineddata'))
    for tool in ('ninja', 'pkgconf', 'meson'):
        check('offline build ' + tool, lambda tool=tool: version('runtime/build/bin/' + tool))
    check('bus tool', lambda: assert_file('bin/mcu-wire-host'))
    fw = read(ROOT / 'inputs/firmware/manifest.json', {})
    for item in fw.get('images', []):
        check('original ROM ' + item['role'], lambda item=item: assert_file(item['path'], item['sha256']))
    for name, profile in profiles().items():
        def profile_paths(profile=profile):
            for key in ('baseline','mcu','environment','coordinator','scenario','qemu_manifest','mcu_manifest'):
                value = profile[key]
                assert not Path(value).is_absolute(), key + ' must be package-relative'
                assert_file(value)
            for key in ('baseline','mcu','environment'):
                text = (ROOT / profile[key]).read_text()
                assert '/Users/' not in text, 'Historical absolute path in active ' + key
                assert 'historical:' not in text, 'Unresolved runtime reference in ' + key
            return dict(relative_recipes=True, guest_state_injection=profile['guest_state_injection'])
        check('profile ' + name, profile_paths)
    manifests = set(p[k] for p in profiles().values() for k in ('qemu_manifest','mcu_manifest'))
    def check_build(name):
            m = read(ROOT / name)
            assert m, 'Missing build manifest: ' + name
            assert_file(m['binary'], m['binary_sha256'])
            version(m['binary'])
            count = 0
            for fn, path in m.get('immutable_model_sources', {}).items():
                assert_file(path, m.get('z6ii_sources',{}).get(fn))
                count += 1
            for entry in m.get('model_generator_sources',{}).values():
                assert_file(entry['snapshot'], entry['sha256'])
            if m.get('board_source'):
                assert_file(m['board_source'], m['board_source_sha256'])
            for entry in m.get('native_mcu_model_headers', {}).values():
                assert_file(entry['snapshot'], entry['sha256'])
            hook = m.get('native_FLASH_TCG_wait_hook')
            if hook:
                assert_file(hook['patch_script'], hook['patch_script_sha256'])
                for entry in hook['sources'].values():
                    assert_file(entry['original_source'], entry['original_sha256'])
                    assert_file(entry['patched_source'], entry['patched_sha256'])
            for key, group in (('source50_TCG_observer', 'sources'), ('boot_TCG_observer', 'common_sources')):
                for entry in m.get(key, {}).get(group, {}).values():
                    assert_file(entry['snapshot'], entry['sha256'])
            if m.get('Kconfig_overlay_snapshot'):
                assert_file(m['Kconfig_overlay_snapshot'], m['Kconfig_overlay_sha256'])
            for key in ('host_debug_clock_guard', 'native_deep_sleep_boundary_guard'):
                guard = m.get(key, {})
                for path_key, hash_key in (('patched_source', 'patched_sha256'), ('header_source', 'header_sha256')):
                    if guard.get(path_key):
                        assert_file(guard[path_key], guard[hash_key])
            return dict(binary=m['binary'], sha256=m['binary_sha256'], pinned_model_files=count)
    for name in sorted(manifests):
        check(name, lambda name=name: check_build(name))
    if (ROOT/'artifacts/rebuilt/latest.json').is_file():
        def latest_rebuild():
            selection = read(ROOT/'artifacts/rebuilt/latest.json')
            assert selection, 'Invalid rebuilt selection'
            for key in ('binary', 'build_status', 'EXPEED_manifest', 'MCU_manifest'):
                item = selection[key]
                assert_file(item['path'], item['sha256'])
            status = read(ROOT/selection['build_status']['path'])
            assert status.get('status') == 'verified', 'Selected rebuild has not passed build checks'
            assert status.get('network_downloads_enabled') is False, 'Selected build is not marked offline'
            item = status['bus_binary']
            assert_file(item['path'], item['sha256'])
            for key in ('EXPEED_manifest', 'MCU_manifest'):
                check_build(selection[key]['path'])
            inventory_path = read(ROOT/selection['EXPEED_manifest']['path'])['build_source_inventory']
            inventory = read(ROOT/inventory_path)
            import hashlib, json
            tree_hash = hashlib.sha256(json.dumps(inventory['files'], sort_keys=True,
                                     separators=(',', ':')).encode()).hexdigest()
            assert tree_hash == inventory['tree_sha256'], 'Build source inventory changed'
            assert tree_hash == read(ROOT/selection['EXPEED_manifest']['path'])['build_source_tree_sha256']
            return dict(binary=selection['binary'], wire_tool=item, source_tree_sha256=tree_hash,
                        source_files=len(inventory['files']))
        check('latest contained offline rebuild', latest_rebuild)
    def portable_dependencies():
        from dependency_closure import inspect
        result = inspect(ROOT)
        assert result['passed'], '; '.join(result['errors'][:12])
        return dict(Mach_O_files=result['Mach_O_file_count'], owned_dependency_edges=result['owned_dependency_edges'],
                    external_or_broken_symlinks=result['external_or_broken_symlinks'],
                    dependency_scope='runtime, imported boards, selected rebuild and wire tool')
    check('package-owned dynamic dependency closure', portable_dependencies)
    def inputs():
        from persistent_input import inspect_spec
        from loader_runtime_audit import load_reference
        from parameter_source_reference import inspect_spec as parameters
        from expeed_task_observer import load_plan
        master = (ROOT / 'inputs/firmware/master-original-with-crc.bin').read_bytes()
        blobs = {role:(ROOT / ('inputs/firmware/' + role + '-original-with-crc.bin')).read_bytes()
                 for role in ('master','slave')}
        inspect_spec(ROOT / 'inputs/specs/descriptor-flash.json')
        load_reference(ROOT / 'inputs/specs/loader-reference.json', master)
        parameters(ROOT / 'inputs/specs/parameter-reference.json',
                   read(ROOT / 'artifacts/formal-expeed/build-manifest.json'))
        load_plan(ROOT / 'inputs/specs/tasks.json', blobs)
        return dict(Flash='descriptor reconstruction with recorded payloads',
                    Loader='read-only reference', parameters='identity checked', task_plan='bounded')
    check('active input contracts', inputs)
    if full:
        def integrity():
            selected = (ROOT / baseline).resolve()
            assert not Path(baseline).is_absolute() and selected.is_relative_to(ROOT), \
                'Static baseline must be a package-relative path inside this package'
            manifest = read(selected)
            assert manifest, 'Package manifest has not been sealed'
            from seal_package import inventory
            import hashlib, json
            baseline_tree = {key: manifest[key] for key in ('files', 'symlinks')}
            encoded = json.dumps(baseline_tree, sort_keys=True, separators=(',', ':')).encode()
            assert hashlib.sha256(encoded).hexdigest() == manifest['tree_sha256'], 'Invalid baseline tree SHA256'
            actual = inventory()
            if actual['tree_sha256'] != manifest['tree_sha256']:
                expected_items = {item['path']: item for group in baseline_tree.values() for item in group}
                actual_items = {item['path']: item for key in ('files', 'symlinks') for item in actual[key]}
                changed = sorted(path for path in expected_items.keys() | actual_items.keys()
                                 if expected_items.get(path) != actual_items.get(path))
                raise ValueError('Static file, size, executable bit or symlink changed: ' + ', '.join(changed[:12]))
            return dict(files=len(manifest['files']), symlinks=len(manifest['symlinks']),
                        tree_sha256=manifest['tree_sha256'],
                        manifest=identity(selected))
        check('complete package files and relative symlinks', integrity)
    result = dict(schema='z62.package-doctor/1', checked=now(), root=str(ROOT),
                  passed=bool(checks) and all(c['passed'] for c in checks), checks=checks,
                  camera_access=False, whole_camera_verified=False)
    if not quiet:
        for c in checks:
            print(('PASS ' if c['passed'] else 'FAIL ') + c['name'] +
                  (': ' + c['error'] if not c['passed'] else ''), flush=True)
        print('Package preflight: ' + ('PASS' if result['passed'] else 'FAIL'), flush=True)
    return result

def stop(process, seconds=35):
    if process is None or process.poll() is not None:
        return
    process.send_signal(signal.SIGINT)
    try:
        process.wait(timeout=seconds)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)

def run(args):
    os.chdir(ROOT)
    profile = dict(profiles()[args.profile])
    unified = profile.get('execution_model') == 'single-qemu-five-cpu'
    architecture_only = bool(getattr(args, 'architecture_only', False))
    display_observation = bool(getattr(args, 'display_observation', False))
    virtual_seconds = getattr(args, 'virtual_seconds', None)
    pad_input = getattr(args, 'pad_schedule', None)
    ui_plan = getattr(args, 'ui_plan', None)
    tg_model = getattr(args, 'tg_clock_model', None)
    if tg_model is not None and not unified:
        raise ValueError('--tg-clock-model requires the native single-instance profile')
    isp_commit_model = getattr(args, 'isp_commit_model', None)
    if isp_commit_model is not None and not unified:
        raise ValueError('--isp-commit-model requires the native single-instance profile')
    image_status_model = getattr(args, 'image_status_model', None)
    if image_status_model is not None and not unified:
        raise ValueError('--image-status-model requires the native single-instance profile')
    persistent_output = bool(getattr(args, 'persistent_output', False))
    persistent_input = getattr(args, 'persistent_input', None)
    if (persistent_output or persistent_input is not None) and not unified:
        raise ValueError('--persistent-output/--persistent-input require the native single-instance profile')
    if persistent_input is not None:
        persistent_input = (persistent_input if persistent_input.is_absolute() else ROOT / persistent_input).resolve(strict=True)
        persistent_input.relative_to(ROOT)
    mcu_rtc_retained = getattr(args, 'mcu_rtc_retained', None)
    if mcu_rtc_retained is not None and not unified:
        raise ValueError('--mcu-rtc-retained requires the native single-instance profile')
    mcu_rtc_backup_input = getattr(args, 'mcu_rtc_backup_input', None)
    mcu_rtc_backup_output = bool(getattr(args, 'mcu_rtc_backup_output', False))
    if (mcu_rtc_backup_input is not None or mcu_rtc_backup_output) and not unified:
        raise ValueError('--mcu-rtc-backup-input/--mcu-rtc-backup-output require the native single-instance profile')
    if mcu_rtc_backup_input is not None:
        mcu_rtc_backup_input = (mcu_rtc_backup_input if mcu_rtc_backup_input.is_absolute()
                                else ROOT / mcu_rtc_backup_input).resolve(strict=True)
        mcu_rtc_backup_input.relative_to(ROOT)
        sys.path.insert(0, str(HARNESS))
        from rtc_backup_input import inspect_spec as inspect_rtc_backup
        backup, _ = inspect_rtc_backup(mcu_rtc_backup_input)
        if mcu_rtc_retained is not None and int(mcu_rtc_retained.split(',')[1], 16) != backup['words'][19]:
            raise ValueError('--mcu-rtc-retained BKP19 must match the imported complete RTC bank')
    if (display_observation or pad_input is not None or ui_plan is not None) and not unified:
        raise ValueError('Custom external pads and UI plans require the native single-instance profile')
    if architecture_only and display_observation:
        raise ValueError('Choose either architecture or display observation scope')
    if virtual_seconds is not None:
        if not unified:
            raise ValueError('--virtual-seconds requires the native single-instance profile')
        if not math.isfinite(virtual_seconds) or not 1e-9 <= virtual_seconds <= 1200:
            raise ValueError('Virtual observation limit must be finite and within 1ns..1200s')
    if pad_input is not None:
        from native_unified_pads import load_schedule
        pad_input = (pad_input if pad_input.is_absolute() else ROOT / pad_input).resolve(strict=True)
        pad_input.relative_to(ROOT)
        load_schedule(pad_input)
    if ui_plan is not None:
        ui_plan = (ui_plan if ui_plan.is_absolute() else ROOT / ui_plan).resolve(strict=True)
        ui_plan.relative_to(ROOT)
        sys.path.insert(0, str(HARNESS))
        from native_ui_observer import load_plan
        blobs = {role: (ROOT / ('inputs/firmware/' + filename)).read_bytes()
                 for role, filename in [('master', 'master-original-with-crc.bin'),
                                        ('slave', 'slave-original-with-crc.bin'), ('MCU', 'ex1850_012000.bi.bin')]}
        load_plan(ui_plan, blobs)
    if architecture_only and not unified:
        raise ValueError('--architecture-only requires the native single-instance profile')
    if unified and args.binary != 'rebuilt':
        raise ValueError('Native single-instance execution requires a verified rebuilt binary')
    bus_tool = ROOT/'bin/mcu-wire-host'
    if args.binary == 'rebuilt':
        selection = read(ROOT/'artifacts/rebuilt/latest.json')
        if not selection:
            raise ValueError('No verified contained rebuild; run ./z62 build first')
        for key, role in (('qemu_manifest', 'EXPEED'), ('mcu_manifest', 'MCU')):
            item = selection[role+'_manifest']
            assert digest(ROOT/item['path']) == item['sha256'], 'Rebuilt manifest identity changed'
            profile[key] = item['path']
        bus = selection.get('bus_binary') or read(ROOT/selection['build_status']['path']).get('bus_binary')
        if bus:
            assert digest(ROOT/bus['path']) == bus['sha256'], 'Rebuilt wire tool identity changed'
            bus_tool = ROOT/bus['path']
    profile['binary_selection'] = args.binary
    if unified:
        sys.path.insert(0, str(HARNESS))
        from native_unified_probe import verify_unified_manifest
        selected = [read(ROOT/profile[k]) for k in ('qemu_manifest', 'mcu_manifest')]
        for manifest in selected:
            verify_unified_manifest(manifest)
        if len({(m['binary'], m['binary_sha256']) for m in selected}) != 1:
            raise ValueError('Unified master/slave/MCU must use the same frozen binary')
    seconds = args.seconds if args.seconds is not None else profile.get(
        'full_seconds' if args.full else 'default_seconds', 360)
    max_host_seconds = 1800 if unified and display_observation else 1200
    if not 1 <= seconds <= max_host_seconds:
        raise ValueError(f'Runtime budget must be 1..{max_host_seconds} seconds')
    preflight = doctor(quiet=True)
    if not preflight['passed']:
        for item in preflight['checks']:
            if not item['passed']:
                print('FAIL ' + item['name'] + ': ' + item['error'])
        return 1
    label = args.profile + ('-display-observation' if display_observation else '')
    name = datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + label + '-' + uuid.uuid4().hex[:6]
    envelope = ROOT / 'results' / name
    envelope.mkdir(parents=True, exist_ok=False)
    prepare, logs, guest_run = envelope / 'prepare', envelope / 'logs', envelope / 'run'
    prepare.mkdir(); logs.mkdir(); guest_run.mkdir()
    save(envelope / 'package-preflight.json', preflight)
    baseline = expand(read(ROOT / profile['baseline']), guest_run, prepare)
    milestone = getattr(args, 'native_milestone', None)
    milestone_inputs = []
    if milestone is not None:
        milestone_source = ROOT / milestone['manifest']['path']
        milestone_snapshot = prepare / 'native-milestone.json'
        shutil.copy2(milestone_source, milestone_snapshot)
        milestone_inputs = [identity(milestone_snapshot)]
        baseline['native_milestone'] = milestone
    mcu = expand(read(ROOT / profile['mcu']), guest_run, prepare)
    env_profile = runtime_environment(read(ROOT / profile['environment']), guest_run, prepare)
    if tg_model is not None:
        env_profile['Z6II_TG_CLOCK_MODEL'] = tg_model
    if isp_commit_model is not None:
        env_profile['Z6II_ISP_COMMIT_COMPLETION'] = isp_commit_model
    if image_status_model is not None:
        env_profile['Z6II_IMAGE_STATUS_MODEL'] = image_status_model
    if mcu_rtc_retained is not None:
        mcu.setdefault('arguments', []).extend(['--rtc-retained', mcu_rtc_retained])
    rtc_input_files = []
    if mcu_rtc_backup_input is not None:
        from rtc_backup_input import prepare as prepare_rtc_backup
        backup = prepare_rtc_backup(mcu_rtc_backup_input, prepare / 'rtc-backup-input')
        mcu.setdefault('arguments', []).extend(['--rtc-backup-input', backup['frozen_manifest']['path']])
        rtc_input_files = [backup['frozen_manifest'], identity(backup['snapshot']),
                           identity(backup['source_manifest_snapshot'])] + list(backup['evidence_snapshots'].values())
    if persistent_output:
        baseline['argv'].append('--master-persistent-output')
    if persistent_input is not None:
        argv = baseline['argv']
        argv[argv.index('--master-persistent-input') + 1] = str(persistent_input)
    observation_inputs = freeze_native_plans(baseline, prepare, ui_plan) if unified else []
    schedule_input = None
    if pad_input is not None:
        schedule_path = prepare / 'external-pad-schedule.json'
        shutil.copy2(pad_input, schedule_path)
        schedule_input = identity(schedule_path)
    save(prepare / 'baseline.json', baseline); save(prepare / 'mcu.json', mcu)
    save(prepare / 'environment.json', env_profile)
    save(prepare / 'initial-host-input.json', dict(sequence=0))
    save(prepare / 'initial-gpio-host-input.json', dict(sequence=0))
    execution_sources = sorted(set(HARNESS.rglob('*.py')) |
        set((ROOT/'profiles'/args.profile).glob('*.py')) |
        {ROOT/profile['coordinator'], ROOT/profile['scenario'], Path(__file__).resolve(),
         ROOT/'scripts/z62_common.py', ROOT/'scripts/acceptance.py', ROOT/'scripts/progress.py',
         ROOT/'scripts/audit_battery.py', ROOT/'scripts/audit_battery_config.py',
         ROOT/'scripts/audit_battery_task.py', ROOT/'scripts/audit_battery_uart.py'})
    if milestone is not None:
        execution_sources = sorted(set(execution_sources) |
            {ROOT/'scripts/native_milestone.py', ROOT/'VERSION', ROOT/'z62', milestone_source})
    execution_files = []
    for source in execution_sources:
        relative = source.relative_to(ROOT)
        snapshot = prepare/'execution-sources'/relative
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, snapshot)
        execution_files.append(dict(**identity(snapshot, envelope), original_relative_path=str(relative)))
    cmd = [str(PYTHON), str(ROOT / profile['coordinator']),
           '--output-dir', str(guest_run), '--baseline-command-json', str(prepare/'baseline.json'),
           '--mcu-profile-json', str(prepare/'mcu.json'),
           '--qemu-manifest', str(ROOT/profile['qemu_manifest']),
           '--mcu-manifest', str(ROOT/profile['mcu_manifest']),
           '--bus-tool', str(bus_tool), '--seconds', str(seconds),
           '--poll-ns', str(profile['poll_ns']), '--known-wait-ms', str(profile['known_wait_ms']),
           '--run-number', '0']
    if virtual_seconds is not None:
        cmd += ['--virtual-seconds', str(virtual_seconds)]
    scenario_cmd = [str(PYTHON), str(ROOT/profile['scenario']), '--prepare-dir', str(prepare),
                    '--run-dir', str(guest_run), '--safety-timeout', str(seconds)]
    if unified:
        scenario_cmd += ['--startup-timeout', '200']
        if schedule_input is not None:
            scenario_cmd += ['--schedule', str(schedule_path)]
    env = clean_environment()
    env.update(env_profile, Z62_RUN_DIR=str(guest_run),
               Z62_EXPEED_MANIFEST=str(ROOT/profile['qemu_manifest']))
    locked = dict(schema='z62.locked-run/1', created=now(), profile=profile,
                  package_root_at_run=str(ROOT), envelope_at_run=str(envelope),
                  runtime_budget_seconds=seconds, argv=cmd, scenario_argv=scenario_cmd,
                  runtime_budget_timebase='host_monotonic_seconds',
                  requested_virtual_seconds=virtual_seconds,
                  virtual_limit_timebase='QEMU_CLOCK_VIRTUAL_since_owner_origin' if virtual_seconds is not None else None,
                  requested_MCU_RTC_backup_output=mcu_rtc_backup_output,
                  requested_MCU_RTC_backup_input=str(mcu_rtc_backup_input) if mcu_rtc_backup_input is not None else None,
                  execution_model=profile.get('execution_model', 'legacy-three-process'),
                  acceptance_scope=('architecture_observation' if architecture_only else
                                    'display_observation' if display_observation else 'complete_declared_scenario'),
                  environment=env_profile,
                  explicit_MCU_host_input_file=str(prepare/'host-input.json'),
                  explicit_MCU_gpio_host_input_file=str(prepare/'gpio-host-input.json'),
                  input_files=[identity(prepare/f) for f in ('baseline.json','mcu.json','environment.json',
                                                            'initial-host-input.json','initial-gpio-host-input.json')] + observation_inputs + rtc_input_files + milestone_inputs,
                  execution_files=execution_files, bus_tool=identity(bus_tool),
                  build_manifests=[identity(ROOT/profile[k]) for k in ('qemu_manifest','mcu_manifest')],
                  firmware_manifest=read(ROOT/'inputs/firmware/manifest.json'),
                  stripped_inherited_experiment_environment=True,
                  camera_access=False, guest_state_injection=profile['guest_state_injection'],
                  application_entry_direct_load=profile['application_entry_direct_load'],
                  physical_flash_dump=profile['physical_flash_dump'])
    if unified:
        from native_unified_pads import SCHEDULE, load_schedule, schedule_rows
        from native_unified_probe import recipes
        baseline_recipe, _ = recipes(prepare/'baseline.json', prepare/'mcu.json')
        for option in ('task-observation-plan', 'loader-runtime-reference-spec', 'ui-observation-plan'):
            value = baseline_recipe.get(option)
            if not value:
                raise ValueError('Native requires a complete launch-time final sampling plan: ' + option)
            plan_path = Path(value)
            plan_path = plan_path if plan_path.is_absolute() else ROOT/plan_path
            if not any(item['path'] == identity(plan_path)['path'] for item in locked['input_files']):
                raise ValueError('Native final sampling plan was not frozen before launch: ' + option)
        schedule = load_schedule(schedule_path) if schedule_input is not None else SCHEDULE
        locked.update(machine=profile['machine'], QEMU_instances=1, CPU_count=5,
                      CPU_roles=profile['CPU_roles'], clock=profile['clock'],
                      debugger_connection_count=2, selected_binary=identity(ROOT/selected[0]['binary']),
                      scenario_schedule=schedule_rows(schedule),
                      scenario_timebase='virtual_seconds_since_owner_origin',
                      scenario_host_startup_allowance_seconds=200,
                      host_seconds_do_not_complete_virtual_schedule=True)
        if schedule_input is not None:
            locked['scenario_schedule_input'] = schedule_input
            locked['input_files'].append(schedule_input)
    save(prepare/'锁定命令与输入.json', locked)
    save(envelope/'run.json', dict(schema='z62.run-envelope/1', created=now(),
                                 profile=args.profile, run='run', locked='prepare/锁定命令与输入.json'))
    print('Profile: ' + profile['label'], flush=True)
    print('Run: ' + str(envelope), flush=True)
    print('Host budget: ' + str(seconds) + 's; scope: ' + locked['acceptance_scope'] +
          '; guest-state injection: ' + str(profile['guest_state_injection']), flush=True)
    if unified:
        if virtual_seconds is not None:
            print('Virtual observation limit: ' + str(virtual_seconds) +
                  's; host budget remains the safety limit', flush=True)
        deadlines = ', '.join(str(event['at_virtual_seconds']) for event in locked['scenario_schedule'])
        print('Virtual input deadlines: ' + deadlines +
              's after the actual common clock origin', flush=True)
    coordinator = scenario = None
    started = time.monotonic()
    status = dict(schema='z62.launch-status/1', started=now(), run=name)
    with (logs/'coordinator.log').open('w') as cf, (logs/'scenario.log').open('w') as sf:
        try:
            coordinator = subprocess.Popen(cmd, cwd=ROOT, env=env, stdout=cf,
                                           stderr=subprocess.STDOUT, start_new_session=True)
            scenario = subprocess.Popen(scenario_cmd, cwd=ROOT, env=env, stdout=sf,
                                        stderr=subprocess.STDOUT, start_new_session=True)
            status.update(coordinator_pid=coordinator.pid, scenario_pid=scenario.pid)
            save(envelope/'launcher-status.json', status)
            next_update = time.monotonic() + 30
            deadline = time.monotonic() + seconds + 230
            while coordinator.poll() is None:
                if time.monotonic() > deadline:
                    raise TimeoutError('Coordinator exceeded the bounded startup/execution/close envelope')
                if time.monotonic() > next_update:
                    if unified:
                        lifecycle = read(guest_run/'QEMU-process-lifecycle.json', {})
                        clock_state = read(guest_run/'native-unified-state.json', {})
                        print('Running %.0f host s; one QEMU PID=%s; actual virtual_ns=%s' % (
                            time.monotonic()-started, lifecycle.get('pid'), clock_state.get('virtual_time_ns')), flush=True)
                    else:
                        roles = [role for role, path in [('MCU',guest_run/'MCU/QEMU-process-lifecycle.json'),
                             ('master',guest_run/'EXPEED/engines/master/QEMU-process-lifecycle.json'),
                             ('slave',guest_run/'EXPEED/engines/slave/QEMU-process-lifecycle.json')]
                             if read(path,{}).get('launch') == 'started']
                        print('Running %.0fs; QEMU roles observed: %s' % (time.monotonic()-started, ', '.join(roles)), flush=True)
                    next_update = time.monotonic() + 30
                time.sleep(.2)
            if scenario.poll() is None:
                try:
                    scenario.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    stop(scenario, seconds=5)
        except BaseException as error:
            status['error'] = type(error).__name__ + ': ' + str(error)
            stop(coordinator); stop(scenario, seconds=5)
        finally:
            changed_sources = [item['original_relative_path'] for item in execution_files
                               if digest(ROOT/item['original_relative_path']) != item['sha256']]
            if changed_sources:
                status['error'] = 'Execution sources changed during run: ' + ', '.join(changed_sources)
            status.update(finished=now(), elapsed_seconds=round(time.monotonic()-started,3),
                          coordinator_exit=coordinator.poll() if coordinator else None,
                          scenario_exit=scenario.poll() if scenario else None)
            save(envelope/'launcher-status.json', status)
    if mcu_rtc_backup_output:
        try:
            from rtc_backup_input import export_bank
            status['MCU_RTC_backup_output'] = export_bank(envelope, guest_run / 'MCU' / 'rtc-backup-output')
            print('MCU RTC backup bank: ' + status['MCU_RTC_backup_output']['manifest'], flush=True)
        except Exception as error:
            status['error'] = 'Requested RTC bank export failed: ' + type(error).__name__ + ': ' + str(error)
        save(envelope/'launcher-status.json', status)
    if display_observation:
        save(ROOT/'results/latest-native-display-observation.json', dict(run=name, profile=args.profile, updated=now()))
    else:
        save(ROOT/'results/latest.json', dict(run=name, profile=args.profile, updated=now()))
        save(ROOT/('results/latest-'+args.profile+'.json'), dict(run=name, profile=args.profile, updated=now()))
    from acceptance import audit
    report = audit(envelope)
    print('Audit: ' + str(envelope/'acceptance.md'), flush=True)
    print('QEMU lifecycle: ' + report['lifecycle']['status'] + '; full-camera: ' + report['full_camera_status'], flush=True)
    return int(status.get('error') is not None or status.get('coordinator_exit') != 0 or
               (not architecture_only and status.get('scenario_exit') != 0) or not report['audit_completed'] or
               report['package_runtime_status'] != 'verified')

def main():
    # Input specs use package-relative paths for every CLI subcommand.
    os.chdir(ROOT)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', action='version', version='Z62 QEMU ' + (ROOT/'VERSION').read_text().strip())
    sub = parser.add_subparsers(dest='command')
    from native_milestone import add_arguments, run_milestone
    n = sub.add_parser('native', help='Source-bound v0.0.2 native exposure milestone with explicit experimental models')
    add_arguments(n)
    sub.add_parser('profiles', help='List native and explicit assisted demonstrations')
    d = sub.add_parser('doctor', help='Check package, hashes, contracts and dependencies')
    d.add_argument('--full', action='store_true')
    d.add_argument('--baseline', help='Check a new package-relative static baseline while preserving the delivery baseline')
    r = sub.add_parser('run', help='Run native in one five-CPU QEMU, or an explicit legacy assisted profile')
    r.add_argument('--profile', choices=sorted(profiles()), default='native')
    r.add_argument('--seconds', type=float, help='Host observation budget; does not specify guest virtual seconds')
    r.add_argument('--virtual-seconds', type=float,
                   help='Native observation limit on QEMU_CLOCK_VIRTUAL; --seconds remains the host safety budget')
    r.add_argument('--full', action='store_true', help='Use the profile full host budget; virtual input completion is audited')
    r.add_argument('--architecture-only', action='store_true',
                   help='Native bounded architecture/evidence audit; pending virtual inputs remain incomplete')
    r.add_argument('--display-observation', action='store_true',
                   help='Audit native display evidence and all selected pad deliveries; battery and whole-camera functions remain separate gates')
    r.add_argument('--pad-schedule', type=Path, help='Package-local external pads on the common virtual clock, frozen before launch')
    r.add_argument('--ui-plan', type=Path, help='Package-local bounded original-code UI observation plan, frozen before launch')
    r.add_argument('--tg-clock-model', choices=('sdes-input-v2', 'sdes-input-v3'),
                   help='Native TG model comparison on QEMU_CLOCK_VIRTUAL; the selection is frozen in the run environment')
    r.add_argument('--isp-commit-model', choices=('next-frame-v1', 'next-frame-ae-v2', 'next-frame-ae-v3', 'next-frame-ae-v4'),
                   help='Opt-in ISP parameter/input notification hypotheses; native exposure and physical completion semantics require separate validation')
    r.add_argument('--image-status-model', choices=('pending-v1',),
                   help='Research: keep unresolved image requests busy for continued observation; no DMA or completion is supplied')
    r.add_argument('--persistent-output', action='store_true',
                   help='Research: export the master per-run flash to run/master/final-persistent-flash.bin at exit')
    r.add_argument('--persistent-input', type=Path,
                   help='Research: replace the master persistent-input spec (package-local, analysis-only provenance)')
    r.add_argument('--mcu-rtc-retained', metavar='YYYYMMDDhhmmss,BKP19',
                   help='Research hypothesis: start the MCU with a battery-retained RTC domain (supplied calendar and BKP19)')
    r.add_argument('--mcu-rtc-backup-input', type=Path,
                   help='Research: import a complete, source-verified MCU RTC bank from a prior stopped native run')
    r.add_argument('--mcu-rtc-backup-output', action='store_true',
                   help='Research: export all 20 RTC backup words from final common-stop QOM after normal QEMU exit')
    r.add_argument('--binary', choices=('imported', 'rebuilt'), default='rebuilt',
                   help='Use the verified contained rebuild by default; imported selects historical binaries')
    v = sub.add_parser('verify', help='Audit retained evidence; strict requires whole-camera gates')
    v.add_argument('run', nargs='?', default='latest')
    v.add_argument('--strict', action='store_true')
    ui = sub.add_parser('ui-verify', help='Recompute retained native menu/input/pixel evidence')
    ui.add_argument('run')
    ui.add_argument('--out', type=Path, help='New package-local results directory')
    ui.add_argument('--require', choices=('evidence', 'menu-reentry', 'stable-menu', 'exposure'),
                    default='evidence', help='Return 2 when the selected functional check remains pending')
    ev = sub.add_parser('exposure-verify', help='Audit original numerical exposure and exact reviewed LCD pixels in a closed run')
    ev.add_argument('run')
    ev.add_argument('--visual-reviews', type=Path, required=True,
                    help='Source-bound exact-RGB visual review file')
    ev.add_argument('--out', type=Path, help='New package-local report directory; original runs and global UI index stay unchanged')
    s = sub.add_parser('status', help='Summarize actual retained development evidence')
    s.add_argument('--cached', action='store_true', help='Use saved audits without refreshing them')
    a = sub.add_parser('accept', help='Run acceptance profiles sequentially, or audit retained results')
    a.add_argument('--profiles', nargs='+', choices=sorted(profiles())+['all'],
                   default=['all'])
    a.add_argument('--binary', choices=('imported', 'rebuilt'), default='rebuilt')
    a.add_argument('--seconds', type=float, help='Override the budget for each selected profile')
    a.add_argument('--architecture-only', action='store_true', help='Only native; audit architecture while retaining pending virtual inputs')
    a.add_argument('--quick', action='store_true', help='Use default budgets; native is 120s instead of 360s')
    a.add_argument('--strict', action='store_true', help='Exit 2 if whole-camera functions remain unverified')
    a.add_argument('--audit-only', action='store_true', help='Check retained runs without starting QEMU')
    b = sub.add_parser('build', help='Rebuild the shipped source offline using the local toolchain')
    b.add_argument('--jobs', type=int, default=2)
    b.add_argument('--clean', action='store_true')
    args = parser.parse_args()
    if args.command is None:
        parser.print_help(); return 0
    if args.command == 'native':
        return run_milestone(args, run, doctor)
    if args.command == 'profiles':
        for name, p in profiles().items():
            print('%-16s %s | %s' % (name,p['label'],p['kind']))
        return 0
    if args.command == 'doctor':
        return int(not doctor(args.full or args.baseline is not None,
                              baseline=args.baseline or 'provenance/package-manifest.json')['passed'])
    if args.command == 'run':
        return run(args)
    if args.command == 'ui-verify':
        from native_ui_acceptance import main as ui_acceptance
        argv = [args.run, '--require', args.require]
        if args.out is not None:
            argv.extend(('--out', str(args.out)))
        return ui_acceptance(argv)
    if args.command == 'exposure-verify':
        from native_exposure_verification import main as exposure_verification
        argv = [args.run, '--visual-reviews', str(args.visual_reviews)]
        if args.out is not None:
            argv.extend(('--out', str(args.out)))
        return exposure_verification(argv)
    if args.command == 'verify':
        from acceptance import audit
        if args.run == 'latest' or args.run.startswith('latest-'):
            ref = read(ROOT/('results/'+args.run+'.json'))
            if not ref:
                raise ValueError('No retained run named ' + args.run)
            path = ROOT/'results'/ref['run']
        else:
            path = Path(args.run)
            if not path.is_absolute():
                path = ROOT/path if (ROOT/path).exists() else ROOT/'results'/path
        report = audit(path.resolve(strict=True))
        print((path/'acceptance.md').read_text())
        if not report['audit_completed'] or report['package_runtime_status'] != 'verified':
            return 1
        if args.strict and report['full_camera_status'] != 'verified':
            return 2
        return 0
    if args.command == 'status':
        from progress import status
        return status(refresh=not args.cached)
    if args.command == 'accept':
        from progress import accept_suite
        if 'all' in args.profiles:
            args.profiles = sorted(profiles())
        else:
            args.profiles = list(dict.fromkeys(args.profiles))
        return accept_suite(args, run)
    if args.command == 'build':
        from build import build
        return build(args)

if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(type(error).__name__ + ': ' + str(error), file=sys.stderr)
        raise SystemExit(1)
