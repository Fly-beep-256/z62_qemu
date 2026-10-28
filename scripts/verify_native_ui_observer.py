"""Exercise bounded indirect observation with a host-only adversarial fixture.

This does not open QEMU or a camera. A reader records every requested address,
so null, MMIO, empty and missing-element cases check the absence of a read.
"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile

from z62_common import ROOT, identity, now, save


def main(output_path=None):
    module_path = ROOT / 'src/harness/native_ui_observer.py'
    spec = importlib.util.spec_from_file_location('native_ui_observer', module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    blobs = {'master': b'\x00\xbf\x00\xbf', 'slave': b'\x00\xbf\x00\xbf',
             'MCU': b'\x00\xbf\x00\xbf'}
    work, array = 0xC0001000, 0xC0001200
    base = dict(schema='z62.native-ui-observation-plan/2',
                ROM_sha256={k: hashlib.sha256(v).hexdigest() for k, v in blobs.items()},
                windows=[dict(label='host fixture', start_virtual_ns=0)],
                sites=[dict(role='master', address='0x10020000', label='host fixture',
                            original_ROM_bytes='00bf00bf', max_hits_per_window=1, samples=[])])
    sample = dict(label='array', register='r0', bytes=16,
                  path=[dict(offset=8, dereference=True)],
                  bytes_from=dict(register='r0', path=[dict(offset=4, dereference=True)], scale=4))

    class Reader:
        def __init__(self, count, pointer=array):
            self.blocks = [(work, struct.pack('<III', 0, count, pointer)),
                           (array, bytes(range(32)))]
            self.calls = []

        def memory(self, address, size):
            self.calls.append((address, size))
            for start, data in self.blocks:
                if start <= address and address+size <= start+len(data):
                    return data[address-start:address-start+size]
            raise AssertionError('unexpected reader request: '+hex(address))

    results = []
    with tempfile.TemporaryDirectory(prefix='z62-ui-observer-') as directory:
        filename = Path(directory)/'plan.json'

        def observe(current, count=2, pointer=array):
            plan = copy.deepcopy(base)
            plan['sites'][0]['samples'] = [current]
            filename.write_text(json.dumps(plan))
            observer = module.UIObserver(filename, blobs)
            reader = Reader(count, pointer)
            event = observer.on_stop(reader, 'master', 0x10020000, {'r0': hex(work)}, {})
            return event['samples'][0], reader.calls

        item, calls = observe(copy.deepcopy(sample))
        assert item['raw_hex'] == bytes(range(8)).hex() and calls == [(work+4, 4), (work+8, 4), (array, 8)]
        assert len(item['pointer_reads']) == 2
        results.append('actual count determines array length and retains both source words')

        item, calls = observe(copy.deepcopy(sample), count=0, pointer=0)
        assert item['status'].startswith('empty_array') and calls == [(work+4, 4)]
        results.append('zero count avoids dereferencing null payload pointer')

        current = copy.deepcopy(sample)
        current['when_count_exceeds'] = dict(register='r0', path=[dict(offset=4, dereference=True)], threshold=2)
        item, calls = observe(current, count=2, pointer=0x2C012010)
        assert item['status'].startswith('element_not_present') and calls == [(work+4, 4)]
        results.append('absent blob index avoids length and payload reads')

        item, calls = observe(copy.deepcopy(sample), count=1024)
        assert item['truncated'] and item['requested_bytes'] == 4096 and item['bytes'] == 16
        assert calls[-1] == (array, 16)
        results.append('oversized count is truncated to the declared sample bound')

        for pointer in (0, 0x2C012010, 0xCFFFFFFC):
            item, calls = observe(copy.deepcopy(sample), pointer=pointer)
            assert item['status'].startswith('pointer_outside_declared_RAM')
            assert calls == [(work+4, 4), (work+8, 4)]
        results.append('null, MMIO and RAM-end overrun payloads are never read')

        current = copy.deepcopy(sample)
        current['path'].append(dict(offset=0, dereference=True))
        item, calls = observe(current, pointer=0x2C012010)
        assert 'pointer_outside_declared_RAM' in item['error'] and calls == [(work+4, 4), (work+8, 4)]
        results.append('intermediate MMIO dereference is rejected before reader access')

        plan = copy.deepcopy(base)
        plan['windows'].extend([dict(label='delivery', start_virtual_ns=5_300_000_000),
                                dict(label='after delivery', start_virtual_ns=6_000_000_000)])
        plan['sites'][0]['active_windows'] = ['delivery']
        plan['sites'][0]['samples'] = [copy.deepcopy(sample)]
        filename.write_text(json.dumps(plan))
        observer = module.UIObserver(filename, blobs)
        reader = Reader(2)
        assert observer.sites() == {} and not observer.advance(5_299_999_999)
        try:
            observer.on_stop(reader, 'master', 0x10020000, {'r0': hex(work)}, {})
        except ValueError:
            pass
        else:
            raise AssertionError('inactive site collected a sample')
        assert reader.calls == [] and not observer.counts
        assert observer.advance(5_300_000_000) and ('master', 0x10020000) in observer.sites()
        observer.on_stop(reader, 'master', 0x10020000, {'r0': hex(work)}, {})
        assert observer.sites() == {} and reader.calls[-1] == (array, 8)
        assert observer.advance(6_000_000_000) and observer.sites() == {}
        results.append('site windows arm only at the declared boundary, retain hit limits and disarm without inactive RAM reads')

        def rejected(plan):
            filename.write_text(json.dumps(plan))
            try:
                module.load_plan(filename, blobs)
            except (ValueError, KeyError, TypeError):
                return
            raise AssertionError('invalid plan accepted')

        for kind in ('v1-indirect', 'MMIO-fixed', 'bad-ROM', 'excess-path', 'bad-scale', 'excess-budget',
                     'v1-site-window', 'unknown-site-window', 'duplicate-site-window', 'empty-site-windows'):
            plan = copy.deepcopy(base)
            current = copy.deepcopy(sample)
            plan['sites'][0]['samples'] = [current]
            if kind == 'v1-indirect':
                plan['schema'] = 'z62.native-ui-observation-plan/1'
            elif kind == 'MMIO-fixed':
                current.pop('register')
                current['address'] = '0x2c012010'
            elif kind == 'bad-ROM':
                plan['sites'][0]['original_ROM_bytes'] = '00000000'
            elif kind == 'excess-path':
                current['path'] *= 4
            elif kind == 'bad-scale':
                current['bytes_from']['scale'] = 17
            elif kind == 'excess-budget':
                plan['sites'][0]['samples'] = [dict(label=str(i), address=hex(work), bytes=1024) for i in range(17)]
            elif kind == 'v1-site-window':
                plan['schema'] = 'z62.native-ui-observation-plan/1'
                plan['sites'][0]['samples'] = []
                plan['sites'][0]['active_windows'] = ['host fixture']
            elif kind == 'unknown-site-window':
                plan['sites'][0]['active_windows'] = ['missing']
            elif kind == 'duplicate-site-window':
                plan['sites'][0]['active_windows'] = ['host fixture', 'host fixture']
            elif kind == 'empty-site-windows':
                plan['sites'][0]['active_windows'] = []
            rejected(plan)
        results.append('schema, address, ROM, path, element size, event budget and site window validation reject invalid plans')

        plan = copy.deepcopy(base)
        plan['schema'] = 'z62.native-ui-observation-plan/3'
        plan['sites'] = [dict(role='master', address=hex(work), access='write', bytes=4,
                              label='original RAM write', max_hits_per_window=1,
                              samples=[dict(label='before', address=hex(work), bytes=4)])]
        filename.write_text(json.dumps(plan))
        observer = module.UIObserver(filename, blobs)
        assert observer.sites() == {} and observer.write_sites() == {
            ('master', work): dict(label='original RAM write', bytes=4)}
        reader = Reader(2)
        observer.on_stop(reader, 'master', work, {}, {})
        assert reader.calls == [(work, 4)] and not observer.write_sites()
        assert observer.completion()['write_watchpoints'] == [dict(role='master', address=hex(work), bytes=4)]
        for change in ('schema', 'MMIO', 'end', 'size', 'access'):
            invalid = copy.deepcopy(plan)
            if change == 'schema':
                invalid['schema'] = 'z62.native-ui-observation-plan/2'
            elif change == 'MMIO':
                invalid['sites'][0]['address'] = '0x20060044'
            elif change == 'end':
                invalid['sites'][0]['address'] = '0xcffffffe'
            elif change == 'size':
                invalid['sites'][0]['bytes'] = 3
            else:
                invalid['sites'][0]['access'] = 'read'
            rejected(invalid)
        results.append('passive write plans retain role and hit limits and reject older schema, MMIO, overruns and unsupported widths/access')

        selected = copy.deepcopy(base)
        selected['schema'] = 'z62.native-ui-observation-plan/4'
        selected['sites'][0].update(registers_equal={'r8': '0x3c'}, max_attempts_per_window=64,
                                    samples=[dict(label='selected group', address=hex(array), bytes=8)])
        filename.write_text(json.dumps(selected))
        observer = module.UIObserver(filename, blobs)
        reader = Reader(2)
        for group in range(37):
            event = observer.on_stop(reader, 'master', 0x10020000, {'r8': hex(group)}, {})
            assert not event['register_selection_matched'] and not event['samples']
        assert reader.calls == [] and ('master', 0x10020000) in observer.sites()
        event = observer.on_stop(reader, 'master', 0x10020000, {'r8': '0x3c'}, {})
        assert event['register_selection_matched'] and event['attempt_in_window'] == 38
        assert event['occurrence_in_window'] == 1 and reader.calls == [(array, 8)]
        assert event['samples'][0]['raw_hex'] == bytes(range(8)).hex() and not observer.sites()
        results.append('the 38th matching call is retained after 37 unrelated stops without any unrelated sample RAM reads')

        selected['sites'][0]['max_attempts_per_window'] = 2
        filename.write_text(json.dumps(selected))
        observer = module.UIObserver(filename, blobs)
        reader = Reader(2)
        for group in (1, 2):
            observer.on_stop(reader, 'master', 0x10020000, {'r8': hex(group)}, {})
        assert not observer.sites() and reader.calls == []
        assert observer.completion()['register_selection_attempts'][0]['attempt_limit_reached']
        results.append('a missing match removes the breakpoint at the explicit stop budget and reports incomplete selection')

        for change in ('old-schema', 'empty', 'register', 'value', 'missing-budget', 'excess-budget', 'write'):
            invalid = copy.deepcopy(selected)
            if change == 'old-schema':
                invalid['schema'] = 'z62.native-ui-observation-plan/2'
            elif change == 'empty':
                invalid['sites'][0]['registers_equal'] = {}
            elif change == 'register':
                invalid['sites'][0]['registers_equal'] = {'PC': 60}
            elif change == 'value':
                invalid['sites'][0]['registers_equal'] = {'r8': 0x100000000}
            elif change == 'missing-budget':
                invalid['sites'][0].pop('max_attempts_per_window')
            elif change == 'excess-budget':
                invalid['sites'][0]['max_attempts_per_window'] = 257
            else:
                invalid['sites'][0].update(address=hex(work), access='write', bytes=4)
            rejected(invalid)
        results.append('register selection rejects older schemas, malformed conditions, unbounded attempts and RAM write-site filtering')

    real = {role: (ROOT/'inputs/firmware'/name).read_bytes()
            for role, name in [('master', 'master-original-with-crc.bin'),
                               ('slave', 'slave-original-with-crc.bin'), ('MCU', 'ex1850_012000.bi.bin')]}
    module.load_plan(ROOT/'inputs/specs/native-ui-causality-20261026.json', real)
    results.append('retained schema /1 plan validates against the three locked original ROMs')
    report = dict(schema='z62.native-ui-observer-validation/1', finished=now(), passed=True,
                  checks=results, QEMU_or_camera_access=False, guest_state_written=False,
                  implementation=identity(module_path), verifier=identity(Path(__file__)))
    target = output_path or ROOT/'results/native-ui-investigation-20261025/observer-plan-validation-20261026.json'
    save(target, report)
    print(json.dumps(report, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='Retain a separate validation report without replacing the earlier report')
    args = parser.parse_args()
    raise SystemExit(main(args.output))
