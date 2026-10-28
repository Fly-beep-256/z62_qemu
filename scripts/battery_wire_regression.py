"""Build and exercise external-wire timing and UART discard boundaries."""
from datetime import datetime
from pathlib import Path
import subprocess
import uuid

from z62_common import ROOT, identity, now, save


def main():
    output = ROOT / 'results/component-tests' / (
        datetime.now().strftime('%Y%m%d-%H%M%S') + '-battery-wire-' + uuid.uuid4().hex[:6])
    output.mkdir(parents=True, exist_ok=False)
    source = ROOT / 'tests/battery_wire_core.c'
    headers = ROOT / 'src/qemu/hw/arm/saiso-ex1850'
    compiler = '/Library/Developer/CommandLineTools/usr/bin/clang'
    executable = output / 'battery-wire-core'
    argv = [compiler, '-isysroot', '/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk',
            '-std=c11', '-Wall', '-Wextra', '-Werror', '-I' + str(headers),
            str(source), '-o', str(executable)]
    build = subprocess.run(argv, capture_output=True, text=True)
    (output / 'build.log').write_text(build.stdout + build.stderr)
    if build.returncode:
        print(build.stdout + build.stderr, end='')
        print('Build log: ' + str((output / 'build.log').relative_to(ROOT)))
        return 1
    result = subprocess.run([str(executable)], capture_output=True, text=True)
    (output / 'run.log').write_text(result.stdout + result.stderr)
    checks = [dict(name=line[5:], passed=True) for line in result.stdout.splitlines() if line.startswith('PASS ')]
    report = dict(schema='z62.battery-wire-core-regression/1', checked=now(),
        compiler=compiler, command=argv, source=identity(source),
        headers=[identity(headers / name) for name in
            ('ex1850-battery-wire-core.h', 'ex1850-usart1-rx-core.h', 'ex1850-usart2-core.h')],
        binary=identity(executable), log=identity(output / 'run.log'), checks=checks,
        exit_code=result.returncode, passed=result.returncode == 0 and len(checks) == 8,
        camera_access=False, guest_execution=False, guest_state_supplied=False,
        scope='External battery timing and UART receive boundaries; native firmware UI acceptance is separate')
    save(output / 'test.json', report)
    print(result.stdout, end='')
    print('Report: ' + str((output / 'test.json').relative_to(ROOT)))
    return int(not report['passed'])


if __name__ == '__main__':
    raise SystemExit(main())
