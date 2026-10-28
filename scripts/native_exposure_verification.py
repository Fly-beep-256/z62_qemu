"""Audit original numerical exposure and reviewed LCD pixels in a closed run.

This command writes a new report only. It never runs QEMU, changes the original
run or global UI index, or certifies metering, a sensor frame, ISP or HDMI.
Supported numerical calibration: C1.70 ordinary Tv/Sv and no-lens Av.
"""
import argparse
from collections import Counter
from datetime import datetime
import hashlib
import json
from pathlib import Path
import shutil
import struct
import uuid

from PIL import Image
from z62_common import ROOT, identity, now, read, save
from native_display_regression_report import inspect_run
from native_ui_acceptance import original_event_audit
from acceptance import native_protocol_audit, native_read_bindings

ROM_BASE = 0x10020000
ROM_SHA256 = 'bb83613121f843d65101da936d942acdc513d86dbd3abc26259d0d870d03f5d4'
IDS = (0x1800, 0x1801, 0x1802)
KINDS = ('shutter', 'aperture', 'ISO')
STRING_TABLES = ((0x10956A90, 77), (0x10956564, 88), (0x109566C4, 81))


def reg(event, name):
    return int(event['registers'][name], 16)


def reference(event):
    return {key: event[key] for key in ('PC', 'observation_sequence', 'virtual_time_ns',
                                      'stop_epoch', 'role', 'global_cpu')}


def samples(event):
    output = {}
    for row in event.get('samples', []):
        if 'raw_hex' not in row:
            continue
        raw = bytes.fromhex(row['raw_hex'])
        if len(raw) != row['bytes'] or hashlib.sha256(raw).hexdigest() != row['sha256']:
            raise ValueError('Invalid observation sample: '+row['label'])
        output[row['label']] = raw
    return output


def cstring(raw):
    if b'\0' not in raw:
        return None
    literal = raw.split(b'\0', 1)[0]
    return literal.decode('ascii') if literal and all(32 <= v < 127 for v in literal) else None


def rom_string(rom, address):
    offset = address - ROM_BASE
    return cstring(rom[offset:offset+64]) if 0 <= offset <= len(rom)-64 else None


def strings_for_codes(rom, codes):
    output = {}
    for kind, code, (address, count) in zip(KINDS, codes, STRING_TABLES):
        if not 0 <= code < count:
            return None
        pointer = struct.unpack_from('<I', rom, address-ROM_BASE+4*code)[0]
        text = rom_string(rom, pointer)
        if text is None:
            return None
        output[kind] = text
    return output


def decode_rational(raw):
    if len(raw) != 8:
        raise ValueError('Incomplete rational sample')
    denominator = int.from_bytes(raw[:2], 'little', signed=True)
    numerator = int.from_bytes(raw[4:], 'little', signed=True)
    return dict(D=denominator, N=numerator, raw_hex=raw.hex(),
                value=numerator/denominator if denominator > 0 else None)


def calibrated_codes(rom, rationals):
    """Strict exact-grid subset of the byte-verified original conversions.

    Nonintegral scaling and other mode/lens branches remain unaccepted here.
    Original firmware handles them; this observer does not approximate them.
    """
    if set(rationals) != {'1608', '1609', '1603'}:
        return None
    av = rationals['1603']
    if (av['D'], av['N']) != (-1, -1):
        return None
    values = []
    for name in ('1608', '1609'):
        r = rationals[name]
        if not 1 <= r['D'] <= 0x400 or (r['N']*6) % r['D']:
            return None
        values.append(r['N']*6//r['D'])
    tv, sv = values
    if not -30 <= tv <= 78 or not 30 <= sv <= 84:
        return None
    return [rom[0x11990592-ROM_BASE+tv+30], 0,
            rom[0x1199065A-ROM_BASE+sv-18]]


def wire_context(envelope, raw):
    """Reuse the formal byte-capture parser without rewriting acceptance."""
    run = envelope/'run'
    cache = {}

    def ref(path):
        path = Path(path).resolve(strict=True)
        if path not in cache:
            cache[path] = identity(path)
        return cache[path]

    def checked(row):
        path = Path(row['path'])
        if not path.is_absolute():
            path = ROOT/path
        found = ref(path)
        if found['sha256'] != row['sha256'] or found['bytes'] != row['bytes']:
            raise ValueError('Captured debugger file SHA/size changed')
        return path.resolve(strict=True)

    protocol = native_protocol_audit(run,raw,checked,ref)
    if protocol['errors'] or protocol['assistance']['status'] != 'zero_guest_writes_verified':
        raise ValueError('Actual debugger capture failed: '+str(protocol['errors']))
    bound = native_read_bindings(protocol,raw)
    if bound['errors']:
        raise ValueError('Actual debugger read binding failed: '+str(bound['errors']))
    return protocol,bound,dict(capture_files=list(cache.values()),
        actual_memory_read_count=bound['actual_memory_read_count'],
        actual_register_read_count=bound['actual_register_read_count'],
        debugger_assistance=protocol['assistance'])


def bind_wire_observations(raw, protocol, bound):
    """Bind each retained UI register and RAM byte to its actual CPU/epoch."""
    clocks = {(row['stop_epoch'],row['response'].get('return'))
        for row in protocol['QMP'] if row['command'] == {'execute':'qom-get',
            'arguments':{'path':'/machine','property':'virtual-time-ns'}} and
            isinstance(row['response'].get('return'),int)}
    count = 0
    for event in raw.get('original_ui_events',[]):
        cpu,epoch = event['global_cpu'],event['stop_epoch']
        bound['registers'](cpu,epoch,event['registers'])
        if reg(event,'r15') != int(event['PC'],16) or (epoch,event['virtual_time_ns']) not in clocks:
            raise ValueError('Original UI event PC/clock lacks its actual wire observation')
        for sample in event.get('samples',[]):
            rows = list(sample.get('pointer_reads',[]))
            if 'raw_hex' in sample:
                rows.append(sample)
            for row in rows:
                body = bound['memory'](cpu,epoch,int(row['address'],16),row['bytes'])
                if body.hex() != row['raw_hex'] or hashlib.sha256(body).hexdigest() != row['sha256']:
                    raise ValueError('Original UI RAM differs from the actual CPU-selected RSP reply')
                count += 1
    dumps = [row for row in protocol['QMP'] if row['command'].get('execute')=='screendump' and
             'return' in row['response']]
    for sample in raw.get('UI',{}).get('samples',[]):
        if sample.get('image') and not any(Path(row['command']['arguments']['filename']).resolve()==
                Path(sample['image']['path']).resolve() for row in dumps):
            raise ValueError('LCD sample lacks its actual successful QMP screendump')
    return dict(verified=True,original_UI_events=len(raw.get('original_ui_events',[])),
        actual_UI_RAM_and_pointer_samples=count,actual_successful_screendumps=len(dumps),
        source='Closed RSP/QMP bytes and IO ledgers; explicit CPU, register XML, read length and stop epoch',
        debugger_or_QEMU_operations=0)


def publication_observation(raw, rom):
    if hashlib.sha256(rom).hexdigest() != ROM_SHA256:
        raise ValueError('Unsupported Master ROM identity')
    callbacks, batches, scalars, collectors, draws = [], [], [], [], []
    original = original_event_audit(raw)
    if not original['verified']:
        raise ValueError('Original event or sample identity failed: '+str(original['failures']))
    for event in raw.get('original_ui_events', []):
        if event['role'] != 'master' or not event.get('register_selection_matched', True):
            continue
        pc, s, r = int(event['PC'], 16), samples(event), reference(event)
        if pc == 0x1021010A and reg(event, 'r0') == 0x04240001 and reg(event, 'r2') == 0x1022E15D:
            packet = s.get('actual_rational_callback_packet', b'')
            if len(packet) == 0x1E8:
                callbacks.append(dict(event=r, pointer=hex(reg(event, 'r1')),
                    rational_hex={name: packet[offset:offset+8].hex()
                                  for name, offset in (('1608',0x30),('1609',0x20),('1603',0x28))}))
        if pc == 0x10357F8A and reg(event, 'r3') == 7:
            ids, lengths = s.get('actual_rational_ID_array', b''), s.get('actual_rational_length_array', b'')
            if len(ids) == len(lengths) == 28:
                ids, lengths = list(struct.unpack('<7I',ids)), list(struct.unpack('<7I',lengths))
                if ids == [0x1608,0x1609,0x1603,0x1B21,0x1B0F,0x1B1E,0x1B14] and lengths == [8,8,8,8,8,8,16]:
                    rationals = {name: decode_rational(s['rational_'+name]) for name in ('1608','1609','1603') if 'rational_'+name in s}
                    batches.append(dict(event=r, IDs=ids, lengths=lengths, rationals=rationals,
                        calibrated_codes=calibrated_codes(rom,rationals)))
        if pc == 0x106AED58:
            count = reg(event,'r2')
            ids, values = s.get('actual_scalar_ID_array',b''), s.get('actual_scalar_value_array',b'')
            if count <= min(len(ids),len(values))//4:
                pairs = {struct.unpack_from('<I',ids,4*i)[0]:struct.unpack_from('<I',values,4*i)[0] for i in range(count)}
                if all(code in pairs for code in IDS):
                    scalars.append(dict(event=r,codes=[pairs[code] for code in IDS]))
        if pc == 0x105552A6:
            prefix = s.get('UI_collector_prefix',b'')
            properties = s.get('exposure_properties',b'')
            if len(prefix) == 16 and len(properties) == 12:
                codes = list(struct.unpack('<3I',properties))
                if list(struct.unpack('<4I',prefix))[:3] == codes and strings_for_codes(rom,codes):
                    collectors.append(dict(event=r,codes=codes,user_ISO_code=struct.unpack_from('<I',prefix,12)[0],
                                           expected_strings=strings_for_codes(rom,codes)))
        if pc in (0x1052BD50,0x10526EBC,0x1052BF40):
            pointer = reg(event,'r3')
            text = cstring(s['actual_supplied_ASCII_string']) if 'actual_supplied_ASCII_string' in s else rom_string(rom,pointer)
            if text is not None:
                draws.append(dict(event=r,kind={0x1052BD50:'shutter',0x10526EBC:'aperture',0x1052BF40:'ISO'}[pc],
                                  pointer=hex(pointer),text=text))
    chains = []
    for collector in collectors:
        seq, codes = collector['event']['observation_sequence'], collector['codes']
        for scalar in scalars:
            if scalar['codes'] != codes or scalar['event']['observation_sequence'] >= seq:
                continue
            for batch in batches:
                if batch['calibrated_codes'] != codes or batch['event']['observation_sequence'] >= scalar['event']['observation_sequence']:
                    continue
                matching = [callback for callback in callbacks
                    if callback['event']['observation_sequence'] < batch['event']['observation_sequence'] and
                    callback['rational_hex'] == {name:v['raw_hex'] for name,v in batch['rationals'].items()}]
                if matching:
                    selected = {kind:next((draw for draw in draws if draw['kind']==kind and draw['text']==collector['expected_strings'][kind] and
                                seq < draw['event']['observation_sequence']),None) for kind in KINDS}
                    if all(selected.values()):
                        chains.append(dict(calculation_callback=matching[-1],rational_batch=batch,
                            scalar_batch=scalar,collector=collector,draws=selected,
                            association='Original source route plus ordered matching values; per-frame causal identity is not established'))
                        break
            if chains and chains[-1]['collector'] == collector:
                break
    return dict(original_event_audit=original, calculation_callback_count=len(callbacks),
        rational_batch_count=len(batches), scalar_triple_batch_count=len(scalars),
        initialized_collector_count=len(collectors), supplied_string_counts=dict(Counter(d['kind']+':'+d['text'] for d in draws)),
        numerical_publication_and_string_observed=bool(chains), matching_chains=chains,
        original_scalar_store_PC_instrumented=any(int(e['PC'],16)==0x10101A90 for e in raw.get('original_ui_events',[])))


def reviewed_pixels(display, review, publication):
    observations = []
    for annotation in review.get('visual_reviews', []):
        fields = annotation['content'].get('exposure_display')
        if not fields or not all(fields.get(kind) for kind in KINDS):
            continue
        path = Path(annotation['image']['path'])
        if not path.is_absolute():
            path = ROOT/path
        if identity(path)['sha256'] != annotation['image']['sha256']:
            raise ValueError('Visual review image identity changed')
        with Image.open(path) as image:
            rgb = image.convert('RGB')
            digest = hashlib.sha256(rgb.tobytes()).hexdigest()
        if digest != annotation['RGB_sha256']:
            raise ValueError('Visual review does not match its exact RGB bytes')
        frames = [frame for frame in display['pixels']['frames'] if frame['pixel_sha256']==digest]
        for chain in publication['matching_chains']:
            if fields != chain['collector']['expected_strings']:
                continue
            earliest_draw = max(draw['event']['virtual_time_ns'] for draw in chain['draws'].values())
            matching = [frame for frame in frames if frame['virtual_ns_before'] >= earliest_draw]
            if matching:
                observations.append(dict(reviewed_image=identity(path),RGB_sha256=digest,
                    first_matching_frame=matching[0],fields=fields,
                    review_method=annotation['content']['method'],chain=chain,
                    central_image_frame_accepted=False))
                break
    return observations


def complete_run_evidence(raw, display):
    final, budget = raw.get('final_evidence',{}), raw.get('observation_budget',{})
    zero = raw.get('debugger_zero_guest_writes',{})
    return bool(display['architecture_passed'] and final.get('complete') and final.get('common_stop_complete') and
        final.get('sampling_complete') and display['zero_host_guest_writes_verified'] and display['Host_guest_write_packets']==0 and
        zero.get('verified') and zero.get('actual_guest_RAM_register_write_count')==0 and
        raw.get('harness_source_unchanged') and raw.get('host_operation_completed') and budget.get('virtual_limit_reached') and
        budget.get('observed_stop_virtual_ns',-1) >= budget.get('virtual_deadline_ns',0) and
        raw.get('QEMU_lifecycle',{}).get('exit_code')==0 and not raw.get('functional_gates_relaxed') and
        not raw.get('guest_RAM_or_register_fixtures') and not raw.get('MCU_packet_replay') and not raw.get('nonce_bridge'))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,allow_abbrev=False)
    parser.add_argument('run')
    parser.add_argument('--visual-reviews',type=Path,required=True)
    parser.add_argument('--out',type=Path)
    args = parser.parse_args(argv)
    envelope = (ROOT/'results'/args.run).resolve()
    envelope.relative_to((ROOT/'results').resolve())
    output = args.out or ROOT/'results/exposure-verification'/(datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+uuid.uuid4().hex[:6])
    output = (output if output.is_absolute() else ROOT/output).resolve()
    output.relative_to((ROOT/'results').resolve())
    output.mkdir(parents=True,exist_ok=False)
    raw = read(envelope/'run/native-unified-result.json')
    display = inspect_run(envelope,output)
    if display['execution'] != 'single-QEMU':
        raise ValueError('A closed native single-QEMU run is required')
    rom = ROOT/'inputs/firmware/master-original-with-crc.bin'
    protocol,bound,capture = wire_context(envelope,raw)
    capture['original_UI_wire_bindings']=bind_wire_observations(raw,protocol,bound)
    publication = publication_observation(raw,rom.read_bytes())
    review = read(args.visual_reviews)
    if review['source_result']['sha256'] != identity(envelope/'run/native-unified-result.json')['sha256']:
        raise ValueError('Visual reviews belong to another result')
    pixels = reviewed_pixels(display,review,publication)
    evidence = complete_run_evidence(raw,display)
    checks = dict(complete_source_bound_evidence=evidence,
        original_numerical_publication_and_string_observed=evidence and publication['numerical_publication_and_string_observed'],
        original_exposure_LCD_pixels_observed=evidence and bool(pixels),
        changing_light_metering_feedback_verified=False, RAW_ISP_frame_completion_verified=False,full_camera_verified=False)
    report = dict(schema='z62.native-exposure-verification/1',generated=now(),checks=checks,
        source_result=identity(envelope/'run/native-unified-result.json'),source_ROM=identity(rom),
        source_visual_reviews=identity(args.visual_reviews),QEMU=raw['identities']['QEMU'],
        source_bound_display=display,publication=publication,reviewed_exposure_pixels=pixels,
        actual_debugger_capture_and_UI_bindings=capture,
        model_environment={k:v for k,v in raw.get('effective_environment',{}).items() if k.startswith(('Z6II_ISP_','Z6II_IMAGE_'))},
        scope='Observed original numerical publication and exact reviewed LCD pixels under the locked device models; no metering or image-processing certification',
        original_run_or_acceptance_modified=False,global_UI_index_modified=False,camera_operations=0)
    sources=[]
    for source in (Path(__file__),ROOT/'scripts/z62.py',ROOT/'scripts/z62_common.py',
                   ROOT/'scripts/native_ui_acceptance.py',ROOT/'scripts/native_display_regression_report.py',
                   ROOT/'scripts/native_ui_index.py',ROOT/'scripts/acceptance.py'):
        target=output/'execution-sources'/source.name;target.parent.mkdir(exist_ok=True)
        shutil.copyfile(source,target);sources.append(identity(target))
    report['execution_sources']=sources
    retained_review=output/'execution-sources/exact-RGB-visual-reviews.json'
    shutil.copyfile(args.visual_reviews,retained_review)
    report['retained_visual_reviews']=identity(retained_review)
    save(output/'report.json',report)
    (output/'report.md').write_text('# Original exposure numerical and LCD verification\n\n'+
        'Original numerical publication and supplied strings observed: **'+str(checks['original_numerical_publication_and_string_observed'])+'**.\n\n'+
        'Exact reviewed exposure LCD pixels observed: **'+str(checks['original_exposure_LCD_pixels_observed'])+'**.\n\n'+
        'Changing-light metering feedback, RAW/ISP completion and full-camera acceptance remain unverified.\n\n'+
        '[Machine-readable source and observation references](report.json). Original run and global UI index are unchanged.\n')
    save(output/'manifest.json',dict(schema='z62.native-exposure-verification-manifest/1',
        files=[identity(p,output) for p in sorted(output.rglob('*')) if p.is_file()]))
    print(json.dumps(dict(report=str(output/'report.json'),checks=checks)))
    return 0 if checks['original_exposure_LCD_pixels_observed'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
