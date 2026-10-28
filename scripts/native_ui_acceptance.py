"""Audit retained native UI pixels, pad delivery and original execution together.

Does not run QEMU or change the run's original acceptance. Menu checks bind
delivered pads, original normalized input, actual menu-method execution and
reviewed pixels within one bounded virtual-time scenario.
"""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import shutil
import struct
import uuid

from PIL import Image, ImageDraw

from native_display_regression_report import (
    byte_identity, inside, inspect_run, retained_path, reviewed_content,
)
from z62_common import ROOT, identity, now, read, save
from native_ui_index import record as record_acceptance


def scalar_words(row):
    data = bytes.fromhex(row['raw_hex'])
    if len(data) != row['bytes'] or hashlib.sha256(data).hexdigest() != row['sha256']:
        raise ValueError('RAM sample identity mismatch: ' + row['label'])
    return list(struct.unpack('<' + 'I' * (len(data) // 4), data))


def exposure_observation(raw):
    rows = raw.get('SAISO_UI_RAM') or []
    final = {row['label']: row for row in rows if 'error' not in row}
    properties = scalar_words(final['properties_180x']) if 'properties_180x' in final else None
    iso = scalar_words(final['property_1810'])[0] if 'property_1810' in final else None
    default_inputs = []
    for event in raw.get('original_ui_events', []):
        for row in event.get('samples', []):
            if int(row.get('address', '0'), 16) == 0xC20F2A00 and row['bytes'] == 488:
                values = scalar_words(row)
                default_inputs.append(dict(virtual_ns=event['virtual_time_ns'],
                                           PC=event['PC'], label=event['label'],
                                           sha256=row['sha256'], all_zero=not any(values)))
    return dict(properties_1800_1801_1802=properties, user_ISO_1810=iso,
                final_RAM_available=bool(rows),
                final_RAM_errors=[row for row in rows if 'error' in row],
                default_input_samples=default_inputs,
                default_input_nonzero_observed=any(not row['all_zero'] for row in default_inputs),
                dynamic_exposure_values_present=(properties is not None and
                    all(value != 0xFFFFFFFF for value in properties)),
                exposure_display_verified=False,
                aperture_depends_on_lens=True, no_lens_F_dashes_are_valid=True)


def group_pixels(display, output):
    groups = []
    for index, frame in enumerate(display['pixels']['frames']):
        before, after = frame['virtual_ns_before'], frame['virtual_ns_after']
        if not isinstance(before, int) or not isinstance(after, int) or after < before:
            raise ValueError('Native frame lacks a valid common virtual sampling interval')
        if groups and before < groups[-1]['last_before_ns']:
            raise ValueError('Native frame sampling intervals are not ordered')
        if groups and groups[-1]['pixel_sha256'] == frame['pixel_sha256']:
            group = groups[-1]
            group.update(last_sample=index, last_before_ns=before, last_after_ns=after)
            group['samples'] += 1
            continue
        content = (reviewed_content(frame['pixel_sha256']) if frame['nonblack'] else
                   dict(kind='black', description='黑帧', method='RGB byte extrema'))
        source = inside(frame['image']['path'])
        preview = output / ('group-%03d.png' % len(groups))
        with Image.open(source) as image:
            image.convert('RGB').save(preview)
        with Image.open(preview) as image:
            if hashlib.sha256(image.convert('RGB').tobytes()).hexdigest() != frame['pixel_sha256']:
                raise ValueError('Generated preview changed the original pixels')
        groups.append(dict(index=len(groups), first_sample=index, last_sample=index, samples=1,
                           first_before_ns=before, first_after_ns=after,
                           last_before_ns=before, last_after_ns=after,
                           pixel_sha256=frame['pixel_sha256'], size=frame['size'],
                           content=content, source=frame['image'], preview=identity(preview)))
    return groups


def pad_timeline(events, groups):
    timeline = []
    for event in events:
        ack, request = event.get('acknowledgement', {}), event.get('request', {})
        applied = ack.get('applied_virtual_ns')
        following = next((g for g in groups if applied is not None and
                          g['first_before_ns'] >= applied), None)
        timeline.append(dict(schedule_index=event['schedule_index'], label=request.get('label'),
                             kind=request.get('pad_kind'), mask=request.get('mask'),
                             levels=request.get('levels'), requested_ns=request.get('at_virtual_ns'),
                             applied_ns=applied, delivered=event.get('delivered'),
                             readback_verified=ack.get('readback_verified'),
                             next_pixel_change_group=following['index'] if following else None,
                             next_pixel_change_delay_ns=(following['first_before_ns'] - applied
                                                         if following else None),
                             relation='temporal association; pin identity is unverified'))
    return timeline


MENU_METHOD = 0x10450BFA
METHOD_BRANCH = 0x103FD308
MENU_REQUEST = 0x106319C6
OSD_METHOD = 0x10540246
DIALOG_METHOD = 0x107438F4
RESPONSE_LIMIT_NS = 3_000_000_000
FINAL_MENU_HOLD_NS = 1_000_000_000

# These are simulator pad -> original logical rise-bit observations, not PCB
# wiring names. Record +10 is word0 rise; +24 is word1 rise, not xor.
PAD_LOGICAL_INPUTS = {
    0x10: ('down', 4, 0x10),
    0x20: ('up', 4, 0x20),
    0x40: ('right', 4, 0x80),
    0x80: ('left', 4, 0x40),
    0x100: ('confirm', 9, 0x2),
    0x200: ('menu', 9, 0x8000),
}


def original_event_audit(raw):
    """Recheck event instructions against this run's identified original ROMs."""
    blobs, identities, failures = {}, {}, []
    bases = {'master': 0x10020000, 'slave': 0x10020000, 'MCU': 0x08000000}
    for role in {e['role'] for e in raw.get('original_ui_events', [])}:
        declared = raw['identities'][role + '_ROM']
        # Resolve package inputs after relocation as well as in the original cwd.
        path = inside(ROOT / 'inputs/firmware' / Path(declared['path']).name)
        identities[role] = byte_identity(path, declared)
        blobs[role] = path.read_bytes()
    previous_ns, previous_sequence = -1, -1
    for event in raw.get('original_ui_events', []):
        pc, role = int(event['PC'], 16), event['role']
        offset = pc - bases[role]
        expected = blobs[role][offset:offset + 4] if offset >= 0 else b''
        if (len(expected) != 4 or expected.hex() != event.get('original_ROM_bytes') or
                event.get('original_ROM_verified') is not True or
                event.get('guest_state_written') is not False):
            failures.append('original event instruction or passive-observation mismatch at ' + event['PC'])
        if (event['virtual_time_ns'] < previous_ns or
                event['observation_sequence'] <= previous_sequence):
            failures.append('original event ordering is invalid')
        for sample in event.get('samples', []):
            rows = list(sample.get('pointer_reads', []))
            if 'raw_hex' in sample:
                rows.append(sample)
            for row in rows:
                data = bytes.fromhex(row['raw_hex'])
                if (len(data) != row['bytes'] or
                        hashlib.sha256(data).hexdigest() != row['sha256']):
                    failures.append('original event RAM sample identity mismatch at ' + event['PC'])
        previous_ns, previous_sequence = event['virtual_time_ns'], event['observation_sequence']
    return dict(verified=not failures and bool(blobs), failures=failures,
                original_ROMs=identities, checked_events=len(raw.get('original_ui_events', [])))


def event_reference(event):
    return {key: event[key] for key in
            ('observation_sequence', 'role', 'PC', 'virtual_time_ns', 'stop_epoch',
             'original_ROM_bytes', 'original_ROM_verified')}


def screen_family(group):
    if group is None:
        return None
    kind = group['content']['kind']
    if kind in ('playback_menu', 'photo_shooting_menu'):
        return 'menu'
    if kind == 'empty_folder_dialog':
        return 'dialog'
    return kind if kind == 'shooting_osd' else None


def state(group):
    return (group['content'].get('menu_state') or {}) if group else {}


def response_kind(action, before, after):
    """A reviewed state transition required for this particular input."""
    a, b = state(before), state(after)
    same_tab = bool(a.get('tab') and a.get('tab') == b.get('tab'))
    if action == 'left' and same_tab and a.get('focus') == 'list' and b.get('focus') == 'tabs':
        return 'left-to-tabs'
    if action == 'right' and same_tab and a.get('focus') == 'tabs' and b.get('focus') == 'list':
        return 'right-to-list'
    if action in ('down', 'up'):
        if a.get('focus') == b.get('focus') == 'tabs':
            pair = (a.get('tab'), b.get('tab'))
            if pair == (('playback', 'photo') if action == 'down' else ('photo', 'playback')):
                return action + '-tab'
        if same_tab and a.get('focus') == b.get('focus') == 'list':
            pair = (a.get('selected_item'), b.get('selected_item'))
            if pair == (('delete', 'playback_folder') if action == 'down' else ('playback_folder', 'delete')):
                return action + '-row'
    if action == 'confirm' and a.get('focus') == 'list' and screen_family(after) == 'dialog':
        return 'confirm-empty-folder'
    if action == 'menu':
        if screen_family(before) in (None, 'shooting_osd') and screen_family(after) == 'menu':
            return 'menu-entry'
        if screen_family(before) == 'dialog' and screen_family(after) == 'menu':
            return 'menu-dismiss-dialog'
        if same_tab and a.get('focus') == 'list' and b.get('focus') == 'tabs':
            return 'menu-focus-tabs'
        if screen_family(before) == 'menu' and a.get('focus') == 'tabs' and screen_family(after) == 'shooting_osd':
            return 'menu-exit'
    return None


def normalized_sample(event, word_index, bit):
    for sample in event.get('samples', []):
        if sample.get('label') != 'normalized_key_state' or 'error' in sample:
            continue
        words = scalar_words(sample)
        if len(words) > word_index and words[word_index] & bit:
            return sample
    return None


def input_responses(raw, groups, pads):
    """Match presses without trusting the human-written schedule action labels."""
    active = [p for p in pads if p['kind'] == 'PCAL' and p['levels'] == 0 and
              p['delivered'] and p['readback_verified'] and p['applied_ns'] is not None]
    events = raw.get('original_ui_events', [])
    responses = []
    for i, pad in enumerate(active):
        mapping = PAD_LOGICAL_INPUTS.get(pad['mask'])
        if mapping is None:
            continue
        action, word, bit = mapping
        start = pad['applied_ns']
        bound = min(start + RESPONSE_LIMIT_NS,
                    active[i + 1]['applied_ns'] if i + 1 < len(active) else start + RESPONSE_LIMIT_NS)
        before = next((g for g in reversed(groups) if g['first_before_ns'] < start and
                       screen_family(g) is not None), None)
        after = next((g for g in groups if start <= g['first_before_ns'] and
                      g['first_after_ns'] < bound and response_kind(action, before, g)), None)
        interval = [e for e in events if e['role'] == 'master' and
                    start <= e['virtual_time_ns'] < bound and
                    (after is None or e['virtual_time_ns'] <= after['first_after_ns'])]
        expected_method = {'menu': MENU_METHOD, 'dialog': DIALOG_METHOD,
                           'shooting_osd': OSD_METHOD}.get(screen_family(before), OSD_METHOD)
        branch = next((e for e in interval if int(e['PC'], 16) == METHOD_BRANCH and
                       int(e['registers']['r2'], 16) & ~1 == expected_method and
                       normalized_sample(e, word, bit)), None)
        entry = None
        if branch and expected_method == MENU_METHOD:
            sample = normalized_sample(branch, word, bit)
            for event in interval:
                if (int(event['PC'], 16) != MENU_METHOD or
                        event['observation_sequence'] <= branch['observation_sequence']):
                    continue
                entry_sample = normalized_sample(event, word, bit)
                if entry_sample and entry_sample['sha256'] == sample['sha256']:
                    entry = event
                    break
        request = next((e for e in interval if int(e['PC'], 16) == MENU_REQUEST), None)
        verified = bool(after and branch and (expected_method != MENU_METHOD or entry) and
                        (response_kind(action, before, after) != 'menu-entry' or request))
        responses.append(dict(schedule_index=pad['schedule_index'], label=pad['label'], action=action,
            applied_ns=start, response_bound_ns=bound, before_group=before['index'] if before else None,
            response_group=after['index'] if after else None,
            response=response_kind(action, before, after) if after else None,
            response_delay_ns=after['first_before_ns'] - start if after else None,
            normalized_rise_word_index=word, normalized_rise_mask=hex(bit),
            normalized_input_sha256=normalized_sample(branch, word, bit)['sha256'] if branch else None,
            expected_original_method=hex(expected_method),
            original_method_branch=event_reference(branch) if branch else None,
            original_menu_method_execution=event_reference(entry) if entry else None,
            original_menu_request=event_reference(request) if request else None, verified=verified))
    return responses


def menu_observation(raw, groups, pads):
    events = [dict(PC=e['PC'], virtual_ns=e['virtual_time_ns'], role=e['role'],
                   stop_epoch=e['stop_epoch'], original_ROM_verified=e['original_ROM_verified'])
              for e in raw.get('original_ui_events', [])
              if int(e['PC'], 16) == MENU_REQUEST]
    responses = input_responses(raw, groups, pads)
    sequence, entries, previous_kind = [], [], None
    for group in groups:
        kind = screen_family(group)
        if kind == 'dialog':
            kind = 'menu'
        if kind not in ('shooting_osd', 'menu'):
            continue
        if kind == previous_kind:
            continue
        sequence.append(dict(kind=kind, group=group['index'], virtual_ns=group['first_before_ns']))
        if kind == 'menu':
            original = next((e for e in reversed(events)
                             if e['virtual_ns'] <= group['first_after_ns']), None)
            pad = next((p for p in reversed(pads) if p['kind'] == 'PCAL' and p['mask'] == 0x200 and
                        p['levels'] == 0 and p['delivered'] and p['readback_verified'] and
                        p['applied_ns'] is not None and original and
                        p['applied_ns'] <= original['virtual_ns']), None)
            bound = next((p['applied_ns'] for p in pads if pad and
                          p['kind'] == 'PCAL' and p['mask'] == 0x200 and p['levels'] == 0 and
                          p['applied_ns'] is not None and p['applied_ns'] > pad['applied_ns']), None)
            input_response = next((r for r in responses if r['response_group'] == group['index'] and
                                   r['response'] == 'menu-entry' and r['verified']), None)
            related = bool(input_response and pad and original and original['original_ROM_verified'] and
                           original['virtual_ns'] - pad['applied_ns'] <= RESPONSE_LIMIT_NS and
                           group['first_after_ns'] - pad['applied_ns'] <= RESPONSE_LIMIT_NS and
                           (bound is None or group['first_after_ns'] < bound))
            entries.append(dict(group=group['index'], original_menu_event=original,
                                preceding_active_pad=pad, next_active_pad_ns=bound,
                                verified_input_response_schedule_index=(
                                    input_response['schedule_index'] if input_response else None),
                                related_input_original_path_and_pixels=related))
        previous_kind = kind
    kinds = [s['kind'] for s in sequence]
    pattern = ['shooting_osd', 'menu', 'shooting_osd', 'menu']
    reentry = any(kinds[i:i + 4] == pattern for i in range(max(0, len(kinds) - 3)))
    verified_responses = {r['response'] for r in responses if r['verified']}
    directional = all(r in verified_responses for r in
                      ('left-to-tabs', 'right-to-list', 'down-tab', 'up-tab', 'down-row', 'up-row'))
    confirmed = 'confirm-empty-folder' in verified_responses
    dismissed = 'menu-dismiss-dialog' in verified_responses
    final_entry = entries[-1] if reentry and entries else None
    tail = [g for g in groups if final_entry and g['index'] >= final_entry['group']]
    hold = tail[-1]['last_after_ns'] - tail[0]['first_after_ns'] if tail else 0
    final_hold = bool(tail and hold >= FINAL_MENU_HOLD_NS and
                      sum(g['samples'] for g in tail) >= 3 and
                      all(screen_family(g) == 'menu' for g in tail))
    stable = bool(reentry and sum(e['related_input_original_path_and_pixels'] for e in entries) >= 2 and
                  directional and confirmed and dismissed and 'menu-exit' in verified_responses and final_hold)
    return dict(visible_sequence=sequence, original_menu_events=events, entries=entries,
                entry_exit_reentry_observed=reentry,
                input_and_original_path_matched_entries=sum(
                    e['related_input_original_path_and_pixels'] for e in entries),
                input_responses=responses, directional_navigation_verified=directional,
                confirmation_dialog_verified=confirmed, dialog_dismiss_verified=dismissed,
                final_reentered_menu_hold_ns=hold, final_reentered_menu_hold_verified=final_hold,
                stable_MENU_verified=stable,
                criteria=dict(response_limit_ns=RESPONSE_LIMIT_NS, final_menu_hold_ns=FINAL_MENU_HOLD_NS,
                              original_menu_method_entry_required=True, minimum_final_menu_samples=3),
                physical_button_names_verified=False,
                limits='Sampled pixels bound display response time; intermediate black frames are retained')


def contact_sheet(groups, output):
    width, height, columns = 400, 300, 3
    rows = max(1, (len(groups) + columns - 1) // columns)
    sheet = Image.new('RGB', (columns * width, rows * height), '#202020')
    draw = ImageDraw.Draw(sheet)
    for group in groups:
        x, y = (group['index'] % columns) * width, (group['index'] // columns) * height
        with Image.open(inside(group['preview']['path'])) as image:
            image.thumbnail((width, height - 34))
            sheet.paste(image, (x, y + 34))
        draw.text((x + 5, y + 4), '%03d  %.3f s  %s' % (
            group['index'], group['first_before_ns'] / 1e9, group['content']['kind']), fill='white')
        draw.text((x + 5, y + 18), group['pixel_sha256'][:16], fill='#bbbbbb')
    path = output / 'contact.png'
    sheet.save(path)
    return identity(path)


def markdown(report):
    display, menu, exposure = report['display'], report['menu'], report['exposure']
    final = display['final_evidence'] or {}
    ns = final.get('virtual_ns')
    final_time = '%.9f 秒' % (ns / 1e9) if isinstance(ns, int) else '不可用'
    lines = ['# Native 菜单与曝光输入验收', '',
             '固定运行：`%s`。原始文件、构建身份、逐帧 RGB 与 RAM 读回身份均重新核验。' % display['run'], '',
             '一个 QEMU、共同虚拟时间；最终采样：%s。Host guest RAM／寄存器写包为 %s。' % (
                 final_time, display['Host_guest_write_packets']), '',
             '菜单进入、退出到 OSD 和重入：**%s**；此有界场景的稳定菜单：**%s**。' % (
                 '通过' if report['checks']['menu-reentry'] else '未通过',
                 '通过' if report['checks']['stable-menu'] else '未通过'), '',
             '原厂事件读回核验：%s 条；左右焦点、上下标签和上下列表导航：%s；确认弹窗：%s；关闭弹窗：%s；重入后持续菜单：%.6f 虚拟秒（%s）。' % (
                 report['original_event_audit']['checked_events'],
                 '通过' if menu['directional_navigation_verified'] else '未通过',
                 '通过' if menu['confirmation_dialog_verified'] else '未通过',
                 '通过' if menu['dialog_dismiss_verified'] else '未通过',
                 menu['final_reentered_menu_hold_ns'] / 1e9,
                 '通过' if menu['final_reentered_menu_hold_verified'] else '未通过'), '',
             '1800／1801／1802：`%s`；1810：`%s`。曝光输入非零观察：`%s`。曝光显示仍待验收；无镜头时 F--- 是正确状态。' % (
                 exposure['properties_1800_1801_1802'], exposure['user_ISO_1810'],
                 exposure['default_input_nonzero_observed']), '',
             '![按共同虚拟时间排列的像素变化](contact.png)', '',
             '| 像素组 | 首次保存虚拟秒 | 最后保存虚拟秒 | 样本数 | 人工核验内容 |',
             '|---|---:|---:|---:|---|']
    for group in report['pixel_groups']:
        lines.append('| [%03d](%s) | %.6f | %.6f | %s | %s |' % (
            group['index'], Path(group['preview']['path']).name,
            group['first_before_ns'] / 1e9, group['last_after_ns'] / 1e9,
            group['samples'], group['content']['description']))
    lines += ['', '| 外部输入 | 实际交付虚拟秒 | 下一像素变化组 | 时间差秒 |',
              '|---|---:|---:|---:|']
    for pad in report['pad_timeline']:
        applied, delay = pad['applied_ns'], pad['next_pixel_change_delay_ns']
        lines.append('| %s | %s | %s | %s |' % (pad['label'],
            '%.6f' % (applied / 1e9) if applied is not None else '未交付',
            pad['next_pixel_change_group'], '%.6f' % (delay / 1e9) if delay is not None else '未保存'))
    lines += ['', '| 按下输入 | 原厂逻辑动作 | 像素响应 | 原厂方法 | 响应时间差秒 | 联合验收 |',
              '|---|---|---|---|---:|---|']
    for response in menu['input_responses']:
        delay = response['response_delay_ns']
        lines.append('| %s | %s | %s | %s | %s | %s |' % (
            response['label'], response['action'], response['response'] or '缺少符合条件的画面',
            response['expected_original_method'],
            '%.6f' % (delay / 1e9) if delay is not None else '不可用',
            '通过' if response['verified'] else '未通过'))
    if report['evidence_failures']:
        lines += ['', '完整运行证据未通过：', '']
        lines += ['- ' + reason for reason in report['evidence_failures']]
    termination = report['termination']
    if termination.get('error'):
        lines += ['', '原轮错误：`%s`。' % termination['error']]
    if termination.get('first_unmodeled'):
        lines += ['', '原轮 first_unmodeled：`%s`。' % json.dumps(
            termination['first_unmodeled'], ensure_ascii=False, sort_keys=True)]
    lines += ['', '联合验收按实际 PCAL mask 选择原厂 normalized rise 位，核对 BX 的实际目标；菜单动作还要求原厂菜单方法入口执行且输入样本 SHA 相同，并在下一次按下前、最多3虚拟秒内出现人工核验像素。MENU进入另外要求原厂 MENU request。重入后至少1虚拟秒、3份样本持续显示菜单。详细引用见机器可读文件。', '',
              '本验收覆盖此轮保存的原厂应用入口启动与外部 pad 场景。物理 Flash／Boot ROM 完整冷启动、实际按键接线、曝光整栏、实时图像、movie-disp 与整机功能均不由此检查认证。', '',
              '[完整时间线与逐项检查](report.json)。原轮 acceptance 保持原始记录。', '']
    return '\n'.join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('run')
    parser.add_argument('--out', type=Path)
    parser.add_argument('--require', choices=('evidence', 'menu-reentry', 'stable-menu', 'exposure'),
                        default='evidence')
    args = parser.parse_args(argv)
    envelope = inside(ROOT / 'results' / args.run)
    output = args.out or ROOT / 'results/ui-acceptance' / (
        datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:6])
    output = (output if output.is_absolute() else ROOT / output).resolve()
    output.relative_to((ROOT / 'results').resolve())
    output.mkdir(parents=True, exist_ok=False)
    display = inspect_run(envelope, output)
    if display['execution'] != 'single-QEMU':
        raise ValueError('This functional check requires a retained native single-QEMU run')
    raw = read(envelope / 'run/native-unified-result.json')
    original_audit = original_event_audit(raw)
    groups = group_pixels(display, output)
    pads = pad_timeline(display['input_events'], groups)
    menu = menu_observation(raw, groups, pads)
    exposure = exposure_observation(raw)
    final = display['final_evidence'] or {}
    evidence_requirements = (
        ('架构终值未通过', display['architecture_passed']),
        ('最终证据不完整', final.get('complete')),
        ('缺少完整共同停止', final.get('common_stop_complete')),
        ('缺少完整最终采样', final.get('sampling_complete')),
        ('零 Host guest 写入审计未通过', display['zero_host_guest_writes_verified']),
        ('Host guest 写包计数不是已核验的零', display['Host_guest_write_packets'] == 0),
        ('外部输入场景未完成', display['input_delivery_complete']),
        ('没有保留画面', bool(groups)),
        ('存在未交付或未核验的输入', all(p['delivered'] and p['readback_verified'] for p in pads)),
        ('原厂事件指令或被动观测审计未通过', original_audit['verified']),
    )
    failures = [reason for reason, passed in evidence_requirements if not passed]
    evidence = not failures
    checks = {'evidence': evidence,
              'menu-reentry': evidence and menu['entry_exit_reentry_observed'] and
                              menu['input_and_original_path_matched_entries'] >= 2,
              'stable-menu': evidence and menu['stable_MENU_verified'], 'exposure': False}
    execution_sources = []
    for source in (Path(__file__), ROOT / 'scripts/native_display_regression_report.py',
                   ROOT / 'scripts/native_ui_index.py', ROOT / 'scripts/z62_common.py'):
        retained_source = output / 'execution-sources' / source.name
        retained_source.parent.mkdir(exist_ok=True)
        shutil.copy2(source, retained_source)
        execution_sources.append(dict(**identity(retained_source),
                                      original_relative_path=str(source.relative_to(ROOT))))
    report = dict(schema='z62.native-ui-acceptance/2', generated=now(),
                  execution_sources=execution_sources,
                  display=display, pixel_groups=groups, pad_timeline=pads, menu=menu,
                  evidence_failures=failures, original_event_audit=original_audit,
                  termination={key: raw.get(key) for key in
                      ('status', 'host_operation_completed', 'error', 'first_unmodeled', 'QEMU_lifecycle')},
                  exposure=exposure, checks=checks, required_check=args.require,
                  required_check_passed=checks[args.require],
                  original_run_acceptance_modified=False, full_camera_status='not_verified')
    report['contact_sheet'] = contact_sheet(groups, output)
    save(output / 'report.json', report)
    (output / 'report.md').write_text(markdown(report))
    save(output / 'manifest.json', dict(schema='z62.native-ui-acceptance-manifest/2',
        files=[identity(p, output) for p in sorted(output.rglob('*')) if p.is_file()],
        source_run=display['retained_result'], locked_execution=display['locked']))
    record_acceptance(output)
    print(json.dumps(dict(report=str(output / 'report.md'), checks=checks,
                          required=args.require, passed=checks[args.require]), ensure_ascii=False))
    return 0 if checks[args.require] else 2


if __name__ == '__main__':
    raise SystemExit(main())
