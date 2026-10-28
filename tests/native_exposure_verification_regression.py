"""Damage closed exposure evidence in memory; never alter retained sources."""
import argparse
import copy
import hashlib
import json
import shutil
from pathlib import Path
import struct
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from native_exposure_verification import (publication_observation,reviewed_pixels,complete_run_evidence,
                                          wire_context,bind_wire_observations)
from z62_common import identity


def change_sample(row, raw):
    row['raw_hex']=raw.hex()
    row['sha256']=hashlib.sha256(raw).hexdigest()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--run',required=True)
    parser.add_argument('--verification',type=Path,required=True)
    parser.add_argument('--reviews',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--wire-bindings',action='store_true',
                        help='Replay actual RSP/QMP once, then reject altered RAM, registers and clock in memory')
    args=parser.parse_args()
    source=ROOT/'results'/args.run/'run/native-unified-result.json'
    sources=[source,args.verification,args.reviews,ROOT/'inputs/firmware/master-original-with-crc.bin']
    before=[identity(p) for p in sources]
    raw=json.loads(source.read_text());rom=sources[-1].read_bytes()
    saved=json.loads(args.verification.read_text());display=saved['source_bound_display']
    review=json.loads(args.reviews.read_text())
    checks={}
    publication=publication_observation(raw,rom)
    assert complete_run_evidence(raw,display) and publication['numerical_publication_and_string_observed']
    assert reviewed_pixels(display,review,publication)
    checks['complete_retained_original_publication_and_pixels']=True
    for name,pc in [('missing_calculation_callback',0x1021010A),('missing_scalar_submission',0x106AED58),
                    ('missing_UI_collector',0x105552A6),('missing_ISO_draw',0x1052BF40)]:
        bad=copy.deepcopy(raw)
        bad['original_ui_events']=[e for e in bad['original_ui_events'] if int(e['PC'],16)!=pc]
        assert not publication_observation(bad,rom)['numerical_publication_and_string_observed']
        checks[name]=True
    bad=copy.deepcopy(raw)
    for event in bad['original_ui_events']:
        if int(event['PC'],16)==0x10357F8A:
            for row in event.get('samples',[]):
                if row['label']=='rational_1608':
                    data=bytearray.fromhex(row['raw_hex']);data[:2]=b'\0\0';change_sample(row,bytes(data))
    assert not publication_observation(bad,rom)['numerical_publication_and_string_observed']
    checks['invalid_zero_denominator_even_with_recomputed_sample_hash']=True
    bad=copy.deepcopy(raw)
    for event in bad['original_ui_events']:
        if int(event['PC'],16)!=0x106AED58:continue
        rows={r['label']:r for r in event.get('samples',[]) if 'raw_hex' in r}
        if not {'actual_scalar_ID_array','actual_scalar_value_array'} <= rows.keys():continue
        ids=bytes.fromhex(rows['actual_scalar_ID_array']['raw_hex'])
        values=bytearray.fromhex(rows['actual_scalar_value_array']['raw_hex'])
        for at in range(min(int(event['registers']['r2'],16),len(ids)//4,len(values)//4)):
            if struct.unpack_from('<I',ids,4*at)[0]==0x1802:struct.pack_into('<I',values,4*at,41)
        change_sample(rows['actual_scalar_value_array'],bytes(values))
    assert not publication_observation(bad,rom)['numerical_publication_and_string_observed']
    checks['scalar_to_collector_mismatch_even_with_recomputed_sample_hash']=True
    bad=copy.deepcopy(raw)
    e=next(e for e in bad['original_ui_events'] if int(e['PC'],16)==0x105552A6)
    s=next(r for r in e['samples'] if r['label']=='UI_collector_prefix')
    s['sha256']='0'*64
    try:publication_observation(bad,rom)
    except ValueError:checks['corrupt_original_sample_hash_rejected']=True
    else:raise AssertionError('Corrupt sample accepted')
    bad=copy.deepcopy(review)
    for row in bad['visual_reviews']:
        if row['content'].get('exposure_display'):row['content']['exposure_display']['ISO']='100'
    assert not reviewed_pixels(display,bad,publication)
    checks['reviewed_text_does_not_match_original_code_table']=True
    bad=copy.deepcopy(review)
    bad['visual_reviews']=[r for r in bad['visual_reviews']
        if r['content'].get('exposure_display') and
        not all(r['content']['exposure_display'].get(kind) for kind in ('shutter','aperture','ISO'))]
    assert bad['visual_reviews'], 'This run must retain a partially visible exposure sample for the negative check'
    assert not reviewed_pixels(display,bad,publication)
    checks['partial_LCD_fields_do_not_accept_complete_exposure_row']=True
    for name,field,value in [('host_guest_write','debugger_zero_guest_writes',1),('incomplete_virtual_window','observation_budget',False)]:
        bad=copy.deepcopy(raw)
        if field=='debugger_zero_guest_writes':bad[field]['actual_guest_RAM_register_write_count']=value
        else:bad[field]['virtual_limit_reached']=value
        assert not complete_run_evidence(bad,display)
        checks[name]=True
    if args.wire_bindings:
        protocol,bound,_=wire_context(source.parent.parent,raw)
        assert bind_wire_observations(raw,protocol,bound)['verified']
        checks['actual_two_connection_UI_wire_replay']=True
        for kind in ('RAM_with_recomputed_hash','register','virtual_clock'):
            bad=copy.deepcopy(raw)
            event=next(e for e in bad['original_ui_events'] if int(e['PC'],16)==0x105552A6)
            if kind=='RAM_with_recomputed_hash':
                row=next(r for r in event['samples'] if r['label']=='UI_collector_prefix')
                body=bytearray.fromhex(row['raw_hex']);body[0]^=1;change_sample(row,bytes(body))
            elif kind=='register':
                event['registers']['r0']=hex(int(event['registers']['r0'],16)^1)
            else:
                event['virtual_time_ns']+=314159
            try:bind_wire_observations(bad,protocol,bound)
            except ValueError:checks['actual_wire_rejects_changed_'+kind]=True
            else:raise AssertionError('Altered observation accepted: '+kind)
    assert [identity(p) for p in sources]==before
    args.out.mkdir(parents=True,exist_ok=False)
    snapshots=[]
    for source_file in (Path(__file__),ROOT/'scripts/native_exposure_verification.py',ROOT/'scripts/acceptance.py'):
        target=args.out/'execution-sources'/source_file.name;target.parent.mkdir(exist_ok=True)
        shutil.copyfile(source_file,target);snapshots.append(identity(target))
    report=dict(schema='z62.native-exposure-damaged-evidence-regression/1',status='PASS',checks=checks,
        source_files=before,source_files_unchanged=True,damaged_copies_in_memory_only=True,
        camera_or_QEMU_operations=0,original_run_or_UI_index_modified=False,
        source_test=identity(Path(__file__)),source_verifier=identity(ROOT/'scripts/native_exposure_verification.py'))
    report['retained_execution_sources']=snapshots
    target=args.out/'report.json';target.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(report=identity(target),status='PASS',checks=len(checks))))


if __name__=='__main__':main()
