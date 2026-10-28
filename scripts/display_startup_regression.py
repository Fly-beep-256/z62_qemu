"""Isolate native display startup with frozen inputs and external pad events.

Experimental runs do not replace the default build or latest-native result.
All CPU/memory access remains in the existing read-only evidence owners.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime
from z62_common import ROOT, PYTHON, HARNESS, clean_environment, expand, identity, read, runtime_environment, save, now, freeze_native_plans


OLD = ROOT / 'results/20261025-102519-native-ac56ad'


def rebind(value, envelope):
    if isinstance(value, str):
        return value.replace(str(OLD), str(envelope))
    if isinstance(value, list):
        return [rebind(v, envelope) for v in value]
    if isinstance(value, dict):
        return {k: rebind(v, envelope) for k, v in value.items()}
    return value


def main():
    ap = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    ap.add_argument('--execution', choices=('legacy', 'unified'), required=True)
    ap.add_argument('--recipe', choices=('old', 'current'), required=True)
    ap.add_argument('--pc5-at', type=float, help='Single external PC5 transition at this common virtual second')
    ap.add_argument('--menu-at', type=float, help='External PCAL MENU press at this common virtual second')
    ap.add_argument('--menu-hold', type=float, default=0.2, help='Virtual seconds between MENU press and release')
    ap.add_argument('--ui-plan', type=Path, help='Package-local bounded observation plan to freeze for this run')
    ap.add_argument('--seconds', type=float, default=120)
    ap.add_argument('--label', required=True)
    args = ap.parse_args()
    if not 1 <= args.seconds <= 1200 or args.pc5_at is not None and (args.execution != 'unified' or args.pc5_at < 0):
        ap.error('Use a bounded host budget and a nonnegative unified PC5 deadline')
    if args.menu_at is not None and (args.execution != 'unified' or args.menu_at < 0 or not 0 < args.menu_hold <= 5):
        ap.error('MENU requires unified execution, a nonnegative deadline and a bounded positive hold')
    if any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in args.label):
        ap.error('Label must contain lowercase letters, digits and hyphens')
    if args.execution == 'unified' and args.recipe == 'current':
        # Current experiments use the complete native launcher, including its
        # pre-launch preflight, frozen plans and declared input contract.
        from z62 import run as run_native
        schedule_path = None
        if args.pc5_at is not None or args.menu_at is not None:
            schedule = []
            if args.pc5_at is not None:
                schedule.append((args.pc5_at, 'GPIO', 0x20, 0, 'PC5:close-low', 'C'))
            if args.menu_at is not None:
                schedule += [(args.menu_at, 'PCAL', 0x200, 0, 'MENU-pad:low', None),
                             (args.menu_at + args.menu_hold, 'PCAL', 0x200, 0x200, 'MENU-pad:release', None)]
            schedule.sort(key=lambda event: event[0])
            schedule_path = ROOT / 'inputs/specs/pad-scenarios' / (
                datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + args.label + '-' + uuid.uuid4().hex[:6] + '.json')
            save(schedule_path, dict(timebase='QEMU_CLOCK_VIRTUAL', schedule=schedule,
                                     physical_identity_verified=False))
        return run_native(argparse.Namespace(profile='native', binary='rebuilt',
            seconds=args.seconds, full=False, architecture_only=False, display_observation=True,
            pad_schedule=schedule_path, ui_plan=args.ui_plan))
    name = datetime.now().strftime('%Y%m%d-%H%M%S') + '-display-' + args.label + '-' + uuid.uuid4().hex[:6]
    envelope = ROOT / 'results' / name
    prepare, logs, run = envelope / 'prepare', envelope / 'logs', envelope / 'run'
    prepare.mkdir(parents=True)
    logs.mkdir()
    if args.execution == 'unified':
        run.mkdir()
    if args.recipe == 'old':
        baseline = rebind(read(OLD / 'prepare/baseline.json'), envelope)
        mcu = rebind(read(OLD / 'prepare/mcu.json'), envelope)
        env_recipe = rebind(read(OLD / 'prepare/environment.json'), envelope)
    else:
        baseline = expand(read(ROOT / 'profiles/native/baseline.json'), run, prepare)
        mcu = expand(read(ROOT / 'profiles/native/mcu.json'), run, prepare)
        env_recipe = runtime_environment(read(ROOT / 'profiles/native/environment.json'), run, prepare)
    observation_inputs = []
    if args.ui_plan is not None:
        if args.execution != 'unified':
            ap.error('A custom UI observation plan requires unified execution')
        source = args.ui_plan if args.ui_plan.is_absolute() else ROOT / args.ui_plan
        source = source.resolve(strict=True)
        source.relative_to(ROOT)
        from importlib.util import spec_from_file_location, module_from_spec
        spec = spec_from_file_location('native_ui_observer', HARNESS / 'native_ui_observer.py')
        observer = module_from_spec(spec)
        spec.loader.exec_module(observer)
        blobs = {role: (ROOT / ('inputs/firmware/' + filename)).read_bytes()
                 for role, filename in [('master', 'master-original-with-crc.bin'),
                                        ('slave', 'slave-original-with-crc.bin'),
                                        ('MCU', 'ex1850_012000.bi.bin')]}
        observer.load_plan(source, blobs)
        argv = baseline.get('argv', [])
        option = '--ui-observation-plan'
        if option in argv:
            argv[argv.index(option) + 1] = str(source)
        else:
            argv.extend((option, str(source)))
    # Retain the actual plan bytes beside the frozen recipe. Later source or
    # profile updates must not change what this experiment observed.
    if args.execution == 'unified':
        observation_inputs = freeze_native_plans(baseline, prepare)
    for option in (() if args.execution == 'unified' else ('--ui-observation-plan',)):
        argv = baseline.get('argv', [])
        if option in argv:
            index = argv.index(option) + 1
            source = Path(argv[index])
            if not source.is_absolute():
                source = ROOT / source
            source = source.resolve(strict=True)
            source.relative_to(ROOT)
            target = prepare / (option[2:] + '.json')
            shutil.copy2(source, target)
            observation_inputs.append(identity(target, envelope))
            argv[index] = str(target)
    for fn, data in [('baseline', baseline), ('mcu', mcu), ('environment', env_recipe)]:
        save(prepare / (fn + '.json'), data)
    for fn in ('host-input', 'gpio-host-input'):
        save(prepare / ('initial-' + fn + '.json'), {'sequence': 0})
    selected = read(ROOT / 'artifacts/rebuilt/latest.json')
    qmanifest = ROOT / selected['EXPEED_manifest']['path']
    mmanifest = ROOT / selected['MCU_manifest']['path']
    bus = ROOT / read(ROOT / selected['build_status']['path'])['bus_binary']['path']
    coordinator = HARNESS / ('native_unified_probe.py' if args.execution == 'unified' else 'native_mcu_three_probe.py')
    command = [str(PYTHON), str(coordinator), '--output-dir', str(run),
               '--baseline-command-json', str(prepare / 'baseline.json'),
               '--mcu-profile-json', str(prepare / 'mcu.json'),
               '--qemu-manifest', str(qmanifest), '--mcu-manifest', str(mmanifest),
               '--bus-tool', str(bus), '--seconds', str(args.seconds),
               '--poll-ns', '100000', '--known-wait-ms', '5000', '--run-number', '0']
    scenario = ROOT / 'scripts' / ('native_unified_pads.py' if args.execution == 'unified' else 'native_pads.py')
    scenario_command = [str(PYTHON), str(scenario)]
    schedule_input = None
    if args.execution == 'unified':
        from native_unified_pads import SCHEDULE, schedule_rows
        schedule = SCHEDULE
    if args.pc5_at is not None or args.menu_at is not None:
        schedule = []
        if args.pc5_at is not None:
            schedule.append((args.pc5_at, 'GPIO', 0x20, 0, 'PC5:close-low', 'C'))
        if args.menu_at is not None:
            schedule += [(args.menu_at, 'PCAL', 0x200, 0, 'MENU-pad:low', None),
                         (args.menu_at + args.menu_hold, 'PCAL', 0x200, 0x200, 'MENU-pad:release', None)]
        schedule.sort(key=lambda event: event[0])
        save(prepare / 'external-pad-schedule.json', dict(timebase='QEMU_CLOCK_VIRTUAL',
                                                       schedule=schedule, physical_identity_verified=False))
        schedule_input = identity(prepare / 'external-pad-schedule.json')
        scenario_command += ['--schedule', str(prepare / 'external-pad-schedule.json')]
    scenario_command += ['--prepare-dir', str(prepare), '--run-dir', str(run), '--safety-timeout', str(args.seconds)]
    if args.execution == 'unified':
        scenario_command += ['--startup-timeout', '200']
    sources = []
    for source in sorted(set(HARNESS.rglob('*.py')) | set((ROOT / 'scripts').glob('*.py'))):
        relative = source.relative_to(ROOT)
        target = prepare / 'execution-sources' / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        sources.append(dict(**identity(target, envelope), original_relative_path=str(relative)))
    lock = dict(schema='z62.display-startup-experiment/1', created=now(),
                profile={'name': 'native', 'execution_model': 'single-qemu-five-cpu' if args.execution == 'unified' else 'legacy-three-process'},
                experiment={key: str(value) if isinstance(value, Path) else value
                            for key, value in vars(args).items()}, package_root_at_run=str(ROOT), envelope_at_run=str(envelope),
                argv=command, scenario_argv=scenario_command, environment=env_recipe,
                explicit_MCU_host_input_file=str(prepare / 'host-input.json'),
                explicit_MCU_gpio_host_input_file=str(prepare / 'gpio-host-input.json'),
                build_manifests=[identity(qmanifest), identity(mmanifest)], selected_binary=identity(ROOT / selected['binary']['path']),
                bus_tool=identity(bus), input_files=[identity(prepare / (fn + '.json')) for fn in ('baseline', 'mcu', 'environment')],
                observation_input_files=observation_inputs,
                execution_files=sources, guest_state_injection=False, camera_access=False,
                application_entry_direct_load=True, physical_flash_dump=False,
                experiment_result_is_not_complete_camera_acceptance=True)
    if args.execution == 'unified':
        lock.update(scenario_schedule=schedule_rows(schedule))
        lock['input_files'] += observation_inputs
        if schedule_input is not None:
            lock['scenario_schedule_input'] = schedule_input
            lock['input_files'].append(schedule_input)
    save(prepare / '锁定命令与输入.json', lock)
    env = clean_environment()
    env.update(env_recipe, Z62_RUN_DIR=str(run), Z62_EXPEED_MANIFEST=str(qmanifest))
    print('Run: ' + str(envelope), flush=True)
    start = time.monotonic()
    status = dict(started=now())
    with (logs / 'coordinator.log').open('w') as cf, (logs / 'scenario.log').open('w') as sf:
        cp = subprocess.Popen(command, cwd=ROOT, env=env, stdout=cf, stderr=subprocess.STDOUT, start_new_session=True)
        sp = subprocess.Popen(scenario_command, cwd=ROOT, env=env, stdout=sf, stderr=subprocess.STDOUT, start_new_session=True)
        status.update(coordinator_pid=cp.pid, scenario_pid=sp.pid)
        save(envelope / 'launcher-status.json', status)
        try:
            cp.wait(timeout=args.seconds + 230)
        except subprocess.TimeoutExpired:
            from z62 import stop
            stop(cp)
            status['error'] = 'Bounded coordinator envelope expired'
        try:
            sp.wait(timeout=5)
        except subprocess.TimeoutExpired:
            from z62 import stop
            stop(sp, seconds=5)
        status.update(finished=now(), elapsed_seconds=round(time.monotonic() - start, 3),
                      coordinator_exit=cp.returncode, scenario_exit=sp.returncode)
        save(envelope / 'launcher-status.json', status)
    print(json.dumps(status, ensure_ascii=False), flush=True)
    return int(cp.returncode != 0)


if __name__ == '__main__':
    raise SystemExit(main())
