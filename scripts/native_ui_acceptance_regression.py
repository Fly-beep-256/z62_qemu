"""Verify that native menu acceptance rejects missing causal evidence.

Only copies of a completed run's JSON are changed in memory. The retained
run, ROMs, debugger bytes and UI report are never edited or replaced.
"""
import argparse
from copy import deepcopy
from datetime import datetime
import hashlib
import json
from pathlib import Path
import struct
import uuid

from native_display_regression_report import byte_identity, inside
from native_ui_acceptance import MENU_METHOD, MENU_REQUEST, menu_observation, original_event_audit
from z62_common import ROOT, identity, now, read, save


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('report', type=Path, help='Completed native UI report.json')
    parser.add_argument('--out', type=Path)
    args = parser.parse_args(argv)
    report_path = inside(args.report)
    report = read(report_path)
    if report.get('schema') != 'z62.native-ui-acceptance/2' or not report['checks']['stable-menu']:
        raise ValueError('A completed passing stable-menu report is required')
    manifest = read(report_path.parent / 'manifest.json')
    expected = next(row for row in manifest['files'] if row['path'] == report_path.name)
    byte_identity(report_path, expected)
    display = report['display']
    raw_path = inside(display['retained_result']['path'])
    byte_identity(raw_path, display['retained_result'])
    raw = read(raw_path)
    groups, pads = report['pixel_groups'], report['pad_timeline']
    rows = []

    def check(name, candidate, predicate, changed):
        original = original_event_audit(candidate)
        menu = menu_observation(candidate, groups, pads)
        passed = bool(original['verified'] and predicate(menu))
        rows.append(dict(name=name, passed=passed, modified_copy_only=True,
                         original_event_identity_audit=original['verified'],
                         changed_records=changed,
                         stable_menu=menu['stable_MENU_verified'],
                         directional_navigation=menu['directional_navigation_verified'],
                         related_entries=menu['input_and_original_path_matched_entries']))
        if not passed:
            raise AssertionError('Menu acceptance regression failed: ' + name)

    check('unmodified-positive-control', raw, lambda menu: menu['stable_MENU_verified'], 0)
    for name, pc, predicate in (
        ('remove-original-menu-method-entry', MENU_METHOD,
         lambda menu: not menu['stable_MENU_verified'] and not menu['directional_navigation_verified']),
        ('remove-original-menu-request', MENU_REQUEST,
         lambda menu: not menu['stable_MENU_verified'] and menu['input_and_original_path_matched_entries'] == 0),
    ):
        candidate = deepcopy(raw)
        events = candidate['original_ui_events']
        removed = sum(int(event['PC'], 16) == pc for event in events)
        candidate['original_ui_events'] = [event for event in events if int(event['PC'], 16) != pc]
        if not removed:
            raise AssertionError('Negative control removed no events')
        check(name, candidate, predicate, removed)

    candidate, changed = deepcopy(raw), 0
    for event in candidate['original_ui_events']:
        for sample in event.get('samples', []):
            if sample.get('label') != 'normalized_key_state' or 'raw_hex' not in sample:
                continue
            data = bytearray.fromhex(sample['raw_hex'])
            value = struct.unpack_from('<I', data, 16)[0]
            if value & 0x10:
                struct.pack_into('<I', data, 16, value & ~0x10)
                sample.update(raw_hex=data.hex(), sha256=hashlib.sha256(data).hexdigest())
                changed += 1
    if not changed:
        raise AssertionError('Negative control changed no down-rise input')
    check('clear-down-rise-bit-and-recompute-RAM-SHA256', candidate,
          lambda menu: not menu['stable_MENU_verified'] and not menu['directional_navigation_verified'], changed)

    altered_pads = deepcopy(pads)
    for pad in altered_pads:
        pad['label'] = 'untrusted-label-only'
    menu = menu_observation(raw, groups, altered_pads)
    if not menu['stable_MENU_verified']:
        raise AssertionError('Human-readable input labels affected acceptance')
    rows.append(dict(name='renamed-labels-positive-control', passed=True,
                     modified_copy_only=True, stable_menu=True))

    # The originals must still have exactly the same retained bytes.
    byte_identity(raw_path, display['retained_result'])
    byte_identity(report_path, expected)
    output = args.out or ROOT / 'results/ui-acceptance' / (
        datetime.now().strftime('%Y%m%d-%H%M%S') + '-negative-' + uuid.uuid4().hex[:6])
    output = (output if output.is_absolute() else ROOT / output).resolve()
    output.relative_to((ROOT / 'results').resolve())
    output.mkdir(parents=True, exist_ok=False)
    result = dict(schema='z62.native-menu-negative-regression/1', generated=now(), passed=True,
                  sources=[identity(Path(__file__)), identity(ROOT / 'scripts/native_ui_acceptance.py'),
                           identity(report_path), identity(raw_path)],
                  checks=rows, original_run_modified=False, camera_access=False,
                  QEMU_launched=False, guest_state_written=False)
    save(output / 'report.json', result)
    (output / 'report.md').write_text('原厂菜单方法入口、MENU request 或正确的 normalized down-rise 位缺失时，'
        '验收均拒绝稳定菜单；重算 RAM SHA256 不能绕过功能检查。原始证据与画面均保持原字节。\n\n'
        '[完整负向检查](report.json)。\n')
    print(json.dumps(dict(report=str(output / 'report.json'), passed=True, checks=len(rows))))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
