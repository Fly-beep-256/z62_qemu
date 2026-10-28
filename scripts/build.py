"""Build the contained QEMU sources offline; retain imported binaries separately."""
from datetime import datetime
from pathlib import Path
import copy
import fcntl
import hashlib
import json
import os
import platform
import shutil
import subprocess
import time
import uuid

from z62_common import ROOT, PYTHON, now, read, save, digest, identity, clean_environment
from macho import relocate

SOURCE = ROOT / 'src/qemu'
CACHE = ROOT / 'build/qemu-arm'
SDK = Path('/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk')


def source_inventory():
    files = []
    for path in sorted(SOURCE.rglob('*')):
        if not path.is_file() or path.is_symlink():
            continue
        if any(p in ('.git', '__pycache__') for p in path.parts) or path.name in ('.DS_Store', '.wraplock'):
            continue
        files.append(identity(path))
    raw = json.dumps(files, sort_keys=True, separators=(',', ':')).encode()
    return dict(schema='z62.build-source-inventory/1', files=files,
                tree_sha256=hashlib.sha256(raw).hexdigest())


def build_environment():
    env = clean_environment()
    env.update(PATH=str(ROOT/'runtime/build/bin') + ':/usr/bin:/bin:/usr/sbin:/sbin',
               PKG_CONFIG=str(ROOT/'runtime/build/bin/pkgconf'),
               PKG_CONFIG_PATH=str(ROOT/'runtime/build/prefix/lib/pkgconfig'),
               PKG_CONFIG_LIBDIR=str(ROOT/'runtime/build/prefix/lib/pkgconfig'),
               SDKROOT=str(SDK), PYTHONNOUSERSITE='1',
               PIP_NO_INDEX='1', PIP_DISABLE_PIP_VERSION_CHECK='1',
               LC_ALL='C', LANG='C')
    return env


def execute(argv, log, cwd, env, status, key):
    started = time.monotonic()
    print('Build stage: ' + key, flush=True)
    with log.open('w') as stream:
        child = subprocess.Popen([str(x) for x in argv], cwd=cwd, env=env,
                                 stdout=stream, stderr=subprocess.STDOUT)
        try:
            while True:
                try:
                    code = child.wait(timeout=30)
                    break
                except subprocess.TimeoutExpired:
                    print('Build %s running %.0fs' % (key, time.monotonic()-started), flush=True)
        except BaseException:
            child.terminate()
            child.wait(timeout=10)
            raise
    status['commands'].append(dict(stage=key, argv=[str(x) for x in argv],
                                   cwd=str(cwd), exit_code=code,
                                   elapsed_seconds=round(time.monotonic()-started, 3),
                                   log=identity(log)))
    if code:
        print(log.read_text(errors='replace')[-6000:], flush=True)
        raise RuntimeError(key + ' failed with exit ' + str(code))


def manifests(version, binary, inventory, machine_list):
    """Freeze the model sources actually supplied to the compiler.

    Historical generator and patch references remain references; this builder
    compiles the contained generated sources and never executes those scripts.
    """
    originals = {role: read(ROOT/('artifacts/qemu/'+role+'-build-manifest.json'))
                 for role in ('EXPEED', 'MCU')}
    replacement, frozen = {}, {}

    def freeze(old, source):
        source = Path(source).resolve(strict=True)
        if source not in frozen:
            relative = source.relative_to(ROOT)
            target = version/'model-sources'/relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            frozen[source] = dict(path=str(target.relative_to(ROOT)), sha256=digest(target))
        replacement[old] = frozen[source]
        return frozen[source]

    ex = originals['EXPEED']
    for name, old in ex['immutable_model_sources'].items():
        freeze(old, SOURCE/'hw/arm'/name)
    freeze(ex['Kconfig_overlay_snapshot'], SOURCE/'hw/arm/Kconfig')
    mcu = originals['MCU']
    freeze(mcu['board_source'], SOURCE/'hw/arm/saiso-ex1850/nikon-ex1850-reset.c')
    for name, value in mcu['native_mcu_model_headers'].items():
        candidates = [SOURCE/'hw/arm/saiso-ex1850'/name,
                      SOURCE/'include/hw/intc'/name, SOURCE/'hw/intc'/name]
        actual = next((p for p in candidates if p.is_file()), None)
        if actual is None:
            raise FileNotFoundError('No compile source for MCU header ' + name)
        freeze(value['snapshot'], actual)
    for manifest in originals.values():
        for key, group in (('source50_TCG_observer', 'sources'), ('boot_TCG_observer', 'common_sources')):
            for relative, item in manifest.get(key, {}).get(group, {}).items():
                actual = SOURCE/relative
                if actual.is_file():
                    freeze(item['snapshot'], actual)
        for relative, item in manifest.get('native_FLASH_TCG_wait_hook', {}).get('sources', {}).items():
            freeze(item['patched_source'], SOURCE/relative)
    freeze(mcu['host_debug_clock_guard']['patched_source'], SOURCE/'accel/tcg/icount-common.c')
    guard = mcu['native_deep_sleep_boundary_guard']
    freeze(guard['patched_source'], SOURCE/'hw/intc/armv7m_nvic.c')
    freeze(guard['header_source'], SOURCE/'include/hw/intc/armv7m_nvic.h')

    # These sources belong to the contained single-instance architecture.
    # Imported manifests predate them and cannot enumerate the new engine,
    # cluster wiring or CPU-local virtual waits.
    native_sources = set()
    for directory, pattern in ((SOURCE/'hw/arm', 'nikon-z6ii*'),
                               (SOURCE/'hw/arm/saiso-ex1850', '*'),
                               (SOURCE/'target/arm/tcg', 'z6ii*')):
        native_sources.update(p for p in directory.glob(pattern)
                              if p.is_file() and p.suffix in ('.c', '.h'))
    native_sources.update(SOURCE/relative for relative in (
        'hw/arm/nikon-gpu.h', 'hw/arm/nikon-z6.c',
        'hw/arm/meson.build', 'hw/arm/Kconfig',
        'hw/cpu/a15mpcore.c', 'include/hw/cpu/a15mpcore.h',
        'hw/cpu/cluster.c', 'hw/cpu/Kconfig', 'hw/cpu/meson.build',
        'include/hw/cpu/cluster.h', 'hw/arm/armv7m.c', 'include/hw/arm/armv7m.h',
        'hw/intc/arm_gic.c', 'hw/intc/arm_gic_common.c',
        'include/hw/intc/arm_gic.h', 'include/hw/intc/arm_gic_common.h',
        'gdbstub/system.c',
        'hw/intc/armv7m_nvic.c', 'include/hw/intc/armv7m_nvic.h',
        'include/accel/tcg/cpu-ops.h',
        'accel/tcg/cputlb.c', 'accel/tcg/cpu-exec.c',
        'accel/tcg/icount-common.c',
        'target/arm/cpu.c', 'target/arm/cpu.h', 'target/arm/helper.c',
        'target/arm/tcg/translate.c', 'target/arm/tcg/op_helper.c',
    ))
    native_snapshots = {str(source.relative_to(SOURCE)):
                        freeze(str(source.relative_to(ROOT)), source)
                        for source in sorted(native_sources)}
    architecture = dict(
        machine='nikon-z6ii-native', qemu_instances=1, CPUs=5,
        virtual_clock='QEMU_CLOCK_VIRTUAL',
        domains={'master': dict(global_CPUs=[0, 1], local_MPIDR=[0, 1]),
                 'slave': dict(global_CPUs=[2, 3], local_MPIDR=[0, 1]),
                 'MCU': dict(global_CPUs=[4], reset='original vector')},
        private_address_spaces=3, QEMU_CPU_clusters=3,
        EXPEED_counter_frequency_hz=48000000,
        EXPEED_generic_timer_exact_frequency=True,
        MCU_reset_HSI_hz=16000000,
        runtime_acceptance='required separately',
        physical_clock_and_reset_relationship_verified=False,
        full_physical_Flash_boot_verified=False)

    hash_fields = {'snapshot': 'sha256', 'source': 'sha256',
                   'patched_source': 'patched_sha256', 'header_source': 'header_sha256',
                   'board_source': 'board_source_sha256',
                   'Kconfig_overlay_snapshot': 'Kconfig_overlay_sha256'}

    def rewrite(value):
        if isinstance(value, str):
            return replacement[value]['path'] if value in replacement else value
        if isinstance(value, list):
            return [rewrite(item) for item in value]
        if isinstance(value, dict):
            out = {k: rewrite(v) for k, v in value.items()}
            for key, hash_key in hash_fields.items():
                old = value.get(key)
                if isinstance(old, str) and old in replacement and hash_key in value:
                    out[hash_key] = replacement[old]['sha256']
            return out
        return value

    result = {}
    for role, original in originals.items():
        manifest = rewrite(copy.deepcopy(original))
        manifest.update(binary=str(binary.relative_to(ROOT)), binary_sha256=digest(binary),
                        build_kind='contained-offline-rebuild', built=now(),
                        build_source_inventory=str((version/'source-inventory.json').relative_to(ROOT)),
                        build_source_tree_sha256=inventory['tree_sha256'],
                        build_status=str((version/'build-status.json').relative_to(ROOT)),
                        machine_list=machine_list, camera_access=False,
                        unified_native_architecture=architecture,
                        unified_native_model_sources=native_snapshots,
                        firmware_modified=False, original_firmware_instructions_modified=False)
        manifest.pop('packaging_relocation', None)
        manifest.pop('host_header_reference_correction', None)
        manifest['inherited_contract_reference'] = identity(ROOT/('artifacts/qemu/'+role+'-build-manifest.json'))
        manifest['generator_execution'] = 'none; compiled the contained generated model sources'
        manifest['Kconfig_snapshot_scope'] = 'full hw/arm/Kconfig used by the contained build'
        if role == 'EXPEED':
            manifest['z6ii_sources'] = {name: digest(SOURCE/'hw/arm'/name)
                                       for name in original['z6ii_sources']}
            startup = read(ROOT/'artifacts/formal-expeed/build-manifest.json').get('boot_TCG_observer', {}).get('startup_focus')
            if startup:
                manifest['boot_TCG_observer']['startup_focus'] = startup
        else:
            manifest['preserved_EXPEED_sha256'] = digest(binary)
        path = version/(role+'-build-manifest.json')
        save(path, manifest)
        result[role] = identity(path)
    save(version/'compiled-model-map.json', dict(schema='z62.compiled-model-map/1',
        mappings=[dict(inherited_path=old, compiled_snapshot=value) for old, value in sorted(replacement.items())]))
    return result


def build(args):
    os.chdir(ROOT)
    if platform.system() != 'Darwin' or platform.machine() != 'arm64':
        raise RuntimeError('This bundled toolchain targets macOS arm64')
    if not SDK.is_dir():
        raise FileNotFoundError('Apple Command Line Tools SDK: ' + str(SDK))
    if not 1 <= args.jobs <= 8:
        raise ValueError('--jobs must be 1..8')
    (ROOT/'build').mkdir(exist_ok=True)
    with (ROOT/'build/build.lock').open('w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Another package build owns build/build.lock')
        name = datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:6]
        version = ROOT/'artifacts/rebuilt'/name
        version.mkdir(parents=True, exist_ok=False)
        status = dict(schema='z62.offline-build/1', started=now(), status='running',
                      package_root_at_build=str(ROOT), source='src/qemu',
                      network_downloads_enabled=False, camera_access=False, commands=[],
                      host_compiler='/Library/Developer/CommandLineTools/usr/bin/clang',
                      SDK=str(SDK.resolve()), jobs=args.jobs)
        save(version/'build-status.json', status)
        try:
            inventory = source_inventory()
            save(version/'source-inventory.json', inventory)
            env = build_environment()
            cache_contract = dict(root=str(ROOT), source=str(SOURCE),
                                  toolchain='runtime/build', SDK=str(SDK.resolve()))
            previous = read(CACHE/'z62-cache.json')
            if CACHE.exists() and (args.clean or previous != cache_contract):
                shutil.rmtree(CACHE)  # Generated cache only; no source or imported artifact.
            CACHE.mkdir(parents=True, exist_ok=True)
            configure = [SOURCE/'configure', '--target-list=arm-softmmu',
                '--without-default-devices', '--without-default-features',
                '--disable-docs', '--disable-tools', '--disable-user', '--disable-werror',
                '--disable-gtk', '--disable-sdl', '--disable-vnc', '--disable-opengl',
                '--disable-guest-agent', '--disable-slirp', '--disable-rust',
                '--disable-debug-info', '--disable-cocoa', '--disable-hvf', '--disable-gio',
                '--disable-libusb', '--disable-usb-redir', '--enable-fdt=internal',
                '--disable-plugins', '--disable-install-blobs', '--disable-download', '--enable-pixman',
                '--python='+str(PYTHON), '--cc='+str(ROOT/'runtime/build/bin/cc'),
                '--host-cc='+str(ROOT/'runtime/build/bin/cc'), '--cxx='+str(ROOT/'runtime/build/bin/c++'),
                '--objcc='+str(ROOT/'runtime/build/bin/clang'), '--ninja='+str(ROOT/'runtime/build/bin/ninja')]
            if not (CACHE/'build.ninja').is_file():
                execute(configure, version/'configure.log', CACHE, env, status, 'configure')
                save(CACHE/'z62-cache.json', cache_contract)
            else:
                status['configure_cache_reused'] = True
                shutil.copy2(CACHE/'config.status', version/'config.status.reference')
            execute([ROOT/'runtime/build/bin/ninja', '-j', str(args.jobs), 'qemu-system-arm-unsigned'],
                    version/'ninja.log', CACHE, env, status, 'compile-link')
            built = CACHE/'qemu-system-arm-unsigned'
            binary = version/'qemu-system-arm'
            shutil.copy2(built, binary)
            status['unsigned_compiler_output_sha256'] = digest(binary)
            status['Mach_O_relocation'] = relocate(binary, ROOT/'runtime/lib')
            for argv, key in (([binary, '--version'], 'binary-version'),
                              ([binary, '-machine', 'help'], 'machine-list')):
                execute(argv, version/(key+'.log'), ROOT, env, status, key)
            machine_list = (version/'machine-list.log').read_text()
            for machine in ('nikon-ex1850-reset', 'nikon-z6ii-master-boot',
                            'nikon-z6ii-slave-boot', 'nikon-z6ii-native'):
                if machine not in machine_list:
                    raise RuntimeError('Rebuilt binary missing board ' + machine)
            bus = version/'mcu-wire-host'
            execute([ROOT/'runtime/build/bin/cc', '-O2', '-Wall', '-Wextra',
                     ROOT/'src/wire/mcu_wire_host.c', '-o', bus],
                    version/'bus-compile.log', ROOT, env, status, 'bus-tool')
            status['bus_binary'] = identity(bus)
            if source_inventory()['tree_sha256'] != inventory['tree_sha256']:
                raise RuntimeError('Build source changed during compilation')
            status['manifests'] = manifests(version, binary, inventory, machine_list)
            status.update(status='verified', binary=identity(binary), finished=now(),
                          verification_scope='offline compilation, link, relocation and machine inventory; runtime tested separately')
            save(version/'build-status.json', status)
            save(ROOT/'artifacts/rebuilt/latest.json', dict(schema='z62.rebuilt-selection/1',
                directory=str(version.relative_to(ROOT)), binary=identity(binary),
                EXPEED_manifest=status['manifests']['EXPEED'], MCU_manifest=status['manifests']['MCU'],
                build_status=identity(version/'build-status.json'), updated=now()))
            print('Offline build verified: ' + str(version.relative_to(ROOT)), flush=True)
            return 0
        except Exception as error:
            status.update(status='failed', error=type(error).__name__+': '+str(error), finished=now())
            save(version/'build-status.json', status)
            raise
