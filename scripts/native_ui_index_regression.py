"""Check that UI progress rejects changed bytes and stale build claims.

Only index and configuration dictionaries are changed in memory. No retained
report, native input, guest state or source-run acceptance is modified.
"""
import argparse
from copy import deepcopy
from datetime import datetime
from pathlib import Path
import uuid

from native_ui_index import checked, relocate, verify
from z62_common import ROOT, identity, now, read, save


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('report', type=Path)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args(argv)
    path = args.report if args.report.is_absolute() else ROOT / args.report
    path = path.resolve(strict=True)
    report = read(path)
    if report.get('schema') != 'z62.native-ui-acceptance/2' or \
            not report['checks']['stable-menu']:
        raise ValueError('A passing retained stable-menu report is required')
    pointer = dict(schema='z62.native-ui-acceptance-index/1',
                   report=identity(path), manifest=identity(path.parent / 'manifest.json'))
    locked = read(checked(report['display']['locked']))
    binary = report['display']['binary']
    environment = relocate(locked['environment'], locked['package_root_at_run'])
    rows = []
    positive = verify(pointer, binary, environment)
    if positive['status'] != 'verified_current_binary_and_environment' or \
            positive['current_checks']['stable-menu'] is not True:
        raise AssertionError('Unmodified UI acceptance failed')
    rows.append(dict(name='unmodified-positive-control', passed=True))
    for field in ('report', 'manifest'):
        changed = deepcopy(pointer)
        changed[field]['sha256'] = '0' * 64
        try:
            verify(changed, binary, environment)
        except ValueError as error:
            rows.append(dict(name='reject-' + field + '-digest-change', passed=True, error=str(error)))
        else:
            raise AssertionError('Changed evidence digest was accepted')
    changed = deepcopy(binary)
    changed['sha256'] = '0' * 64
    historic = verify(pointer, changed, environment)
    if historic['status'] != 'verified_historical' or historic['current_checks']['stable-menu'] is not None:
        raise AssertionError('Historical menu acceptance was reused for a different binary')
    rows.append(dict(name='changed-binary-has-no-current-menu-pass', passed=True,
                     historical_menu=historic['checks']['stable-menu']))
    changed = deepcopy(environment)
    changed['Z6II_TG_CLOCK_MODEL'] = 'regression-different-model'
    historic = verify(pointer, binary, changed)
    if historic['status'] != 'verified_historical' or historic['current_checks']['stable-menu'] is not None:
        raise AssertionError('Historical menu acceptance was reused for a different environment')
    rows.append(dict(name='changed-native-environment-has-no-current-menu-pass', passed=True,
                     historical_menu=historic['checks']['stable-menu']))
    output = args.out or Path('results/ui-acceptance') / (
        datetime.now().strftime('%Y%m%d-%H%M%S') + '-index-regression-' + uuid.uuid4().hex[:6])
    output = (output if output.is_absolute() else ROOT / output).resolve()
    output.relative_to(ROOT / 'results')
    output.mkdir(parents=True, exist_ok=False)
    save(output / 'report.json', dict(schema='z62.native-ui-index-regression/1', generated=now(),
         input_report=identity(path), auditor=identity(Path(__file__)), checks=rows, passed=True,
         modified_copies_only=True, QEMU_started=False, camera_access=False,
         original_run_modified=False))
    (output / 'report.md').write_text('# Native UI 进展身份回归\n\n' +
        '\n'.join('- `%s`：通过。' % row['name'] for row in rows) + '\n\n' +
        '仅修改内存中的身份与配置副本；原始运行、图像、报告和输入均未修改。\n')
    print('Native UI index regression: %d checks passed; %s' % (len(rows), output.relative_to(ROOT)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
