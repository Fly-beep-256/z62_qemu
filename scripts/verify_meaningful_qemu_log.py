#!/usr/bin/env python3
"""Exercise the real pipe sink after ordinary retention has been exhausted.

The late backup writes reproduce the missing-evidence pattern from V42.
An optional previous module demonstrates the regression without running QEMU.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def identity(path):
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def backup(operation, index, value=0):
    return (f'EX1850_RTC_BACKUP {operation} index={index} value={value:08x} state={value:08x} '
            f'write_ignored_DBP=0 pc=08044d20 virtual_ns={20_443_000_000 + index * 8} '
            'retained_factory_backup_supplied=0\n').encode()


def drain(loaded, lines, regular, reserve):
    with tempfile.TemporaryDirectory(prefix='z62-retention-regression-') as directory:
        path = Path(directory)/'qemu.log'
        sink = loaded.MeaningfulQemuLog(path, regular_bytes=regular, fault_bytes=reserve)
        raw = b''.join(lines)
        view = memoryview(raw)
        while view:
            view = view[os.write(sink.fileno(), view):]
        sink.close()
        summary = json.loads(sink.summary_path.read_text())
        retained = path.read_bytes()
        assert summary['error'] is None and summary['truncated_input_lines'] == 0
        assert summary['input_lines'] == len(lines) and summary['input_bytes'] == len(raw)
        assert summary['retained_bytes'] == len(retained) <= regular + reserve
        assert hashlib.sha256(retained).hexdigest() == summary['sha256']
        return retained, summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--previous-module', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    current_path = ROOT/'src/harness/meaningful_qemu_log.py'
    current = module(current_path, 'current_meaningful_qemu_log')
    reads = [backup('R', i) for i in range(20)]
    filler = [(f'Z6II_RETENTION_SAMPLE index={i} ' + 'x'*160 + '\n').encode() for i in range(100)]
    writes = [backup('W', i, 0x10000000 if i == 3 else 0) for i in range(13)]
    reset = b'EX1850_RTC_BACKUP_RESET BDRST=1 original_control_required=1\n'
    bdcr = b'EX1850_RCC_BDCR W value=00010000 state=00010000\n'
    retained, summary = drain(current, reads + filler + writes + [reset, bdcr], 8192, 65536)
    assert summary['budget_exhausted']
    assert summary['input_event_counts']['EX1850_RTC_BACKUP'] == 33
    assert summary['retained_event_sample_counts']['EX1850_RTC_BACKUP'] == 33
    assert all(retained.splitlines().count(line.rstrip(b'\n')) == 1 for line in reads + writes + [reset, bdcr])
    results = dict(late_writes_after_regular_budget=dict(passed=True, emitted=33, retained=33,
                                                       missing=0, ordinary_budget_exhausted=True),
                   current_module=identity(current_path))
    if args.previous_module:
        previous = module(args.previous_module, 'previous_meaningful_qemu_log')
        old_data, old = drain(previous, reads + filler + writes + [reset, bdcr], 8192, 65536)
        assert old['input_event_counts']['EX1850_RTC_BACKUP'] == 33
        assert old['retained_event_sample_counts']['EX1850_RTC_BACKUP'] == 20
        assert not any(line.rstrip(b'\n') in old_data.splitlines() for line in writes)
        results['previous_module'] = identity(args.previous_module)
        results['regression_reproduced'] = dict(passed=True, emitted=33, retained=20, missing=13)
    cap_lines = [backup('W', i % 20, i) for i in range(700)]
    retained, capped = drain(current, cap_lines, 0, 128 * 1024)
    assert capped['input_event_counts']['EX1850_RTC_BACKUP'] == 700
    assert capped['retained_event_sample_counts']['EX1850_RTC_BACKUP'] == 512
    assert capped['discarded_reasons']['diagnostic_event_kind_limit'] == 188
    results['bounded_kind_and_full_pipe_drain'] = dict(passed=True, emitted=700, retained=512,
                                                     discarded=188, bytes=len(retained))
    retained, limited = drain(current, cap_lines[:100], 0, 256)
    assert limited['budget_exhausted'] and limited['discarded_reasons']['fault_budget'] > 0
    assert limited['input_event_counts']['EX1850_RTC_BACKUP'] == 100
    results['reserve_exhaustion'] = dict(passed=True, emitted=100, retained_bytes=len(retained), hard_limit=256)
    uart = [(f'EX1850_USART1_RX_TIMING sample={i} virtual_ns={i}\n').encode() for i in range(10)]
    retained, unchanged = drain(current, uart, 0, 4096)
    assert retained == b''.join(uart) and unchanged['retained_event_sample_counts']['EX1850_USART1_RX_TIMING'] == 10
    results['existing_UART_diagnostic_retention'] = dict(passed=True, retained=10)
    results.update(schema='z62.v43-RTC-log-retention-regression/1', passed=True,
                   test_script=identity(Path(__file__)), actual_QEMU_or_camera_contact=False)
    if args.output:
        args.output.write_text(json.dumps(results, indent=2) + '\n')
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
