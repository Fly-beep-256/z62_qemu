"""Recompute native display regression observations from retained run bytes.

This report never launches QEMU, supplies camera inputs, or rewrites acceptance.
Pixel observations do not certify MENU handling or an original image pipeline.
"""
import argparse
from collections import Counter
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import uuid

from PIL import Image
from z62_common import ROOT, identity, now, read, save


DEFAULT_RUNS = [
    '20261025-102519-native-ac56ad',
    '20261025-204048-native-66e010',
    '20261025-212757-display-new-binary-old-three-bdcec9',
    '20261025-213019-display-same-single-pc5-at2-d32d4b',
    '20261025-213438-display-same-single-pc5-menu-216c05',
    '20261025-214323-native-7e01f2',
    '20261025-225252-native-f20ee5',
]

# Labels apply only to these exact RGB byte identities, visually inspected
# from retained QEMU screenshots. Unknown pixels stay unreviewed. A content
# label never changes the original run's acceptance or MENU/capture gates.
REVIEWED_PIXELS = {
    '16bb3f7aea6b20da47ddb1bfe8858a6324c90581c02e6ab48586f80a29969796':
        ('playback_menu', '中文播放菜单，选中删除'),
    'c7605fd5d0392877d2a0262c20896e8bc5f9a242efa6c1680bd8cf76d1b643c0':
        ('playback_menu', '中文播放菜单，焦点位于左侧播放图标'),
    '6e909bdd786c194da773035965f4dc4c06e570ba9a5675cf9cbaff3af1afd3d0':
        ('playback_menu', '中文播放菜单，焦点位于左侧播放图标'),
    'd961bbe1a5247be2344e37ef39fd236768fac16724e63261fc99489d0e448b96':
        ('photo_shooting_menu', '中文照片拍摄菜单，焦点位于左侧相机图标'),
    'b487427240ee5e8853c7df4fab6e86dd10aea7e2d0795c8288e3a68e418a29cb':
        ('playback_menu', '中文播放菜单，列表中删除行黄色选中'),
    'fa24ef16b983b0cde2fbe7444841ac9bc16c0d6446fdf0e2ff4359e53ec81574':
        ('playback_menu', '中文播放菜单，列表中播放文件夹行黄色选中'),
    '3fe861f7f6ff2f8466f11f068b851dcf2338214f31edfce7767cb4e63ca947ec':
        ('empty_folder_dialog', '原厂确认后显示文件夹不包含影像弹窗'),
    'c8a12afa4e1ae1a8bf56f7b49a0ddf24ec947e776720c90a489de8c8edef11ef':
        ('shooting_osd', '拍摄 OSD，485 与红色时钟图标'),
    '580d5644546faf7d469b2393e0ccf78617be8da7f1315288e825d5fd20ffde0b':
        ('shooting_osd', '拍摄 OSD，485'),
    '04b5d3c0cbec936bab49955bf1e8318c3671d05ed85395d44e7fc33005c4b2ad':
        ('shooting_osd', '拍摄 OSD，中心图像区域为黑色'),
    'a463d2811c742d039845612234a882470c8de05068147fa75052497aace3eebc':
        ('shooting_osd', '拍摄 OSD、电池图标与红色时钟，中心图像区域为黑色'),
    'fed5491ff826823f05f312cbd0e6b4d2eaff0f34cb2322db34f7277e6d9750ea':
        ('waiting_hourglass', '黄色等待沙漏'),
    'df509c3bbdf4168d55ed0700b6344be7d56410d02ca05bf305198ab737a0994d':
        ('battery_communication_error', '此电池无法使用／无法与照相机正确通信弹窗'),
}

# State labels are restricted to the same manually reviewed original RGB bytes.
# They describe simulator pixels; they do not identify physical PCB wiring.
REVIEWED_MENU_STATES = {
    '16bb3f7aea6b20da47ddb1bfe8858a6324c90581c02e6ab48586f80a29969796':
        dict(tab='playback', focus='list', selected_item='delete'),
    'c7605fd5d0392877d2a0262c20896e8bc5f9a242efa6c1680bd8cf76d1b643c0':
        dict(tab='playback', focus='tabs'),
    '6e909bdd786c194da773035965f4dc4c06e570ba9a5675cf9cbaff3af1afd3d0':
        dict(tab='playback', focus='tabs'),
    'd961bbe1a5247be2344e37ef39fd236768fac16724e63261fc99489d0e448b96':
        dict(tab='photo', focus='tabs'),
    'b487427240ee5e8853c7df4fab6e86dd10aea7e2d0795c8288e3a68e418a29cb':
        dict(tab='playback', focus='list', selected_item='delete'),
    'fa24ef16b983b0cde2fbe7444841ac9bc16c0d6446fdf0e2ff4359e53ec81574':
        dict(tab='playback', focus='list', selected_item='playback_folder'),
}


def reviewed_content(pixel_hash):
    label = REVIEWED_PIXELS.get(pixel_hash)
    return dict(kind=label[0] if label else 'unreviewed_nonblack',
                description=label[1] if label else '未检查内容的非黑像素',
                menu_state=REVIEWED_MENU_STATES.get(pixel_hash),
                method='manual visual inspection matched by exact RGB SHA256' if label else None,
                functional_acceptance_implied=False)


def battery_observations(raw):
    events = raw.get('original_battery_task_events', [])
    fields = ('observation_sequence', 'entry', 'function_entry', 'phase',
              'virtual_time_ns', 'HAL_tick', 'main_body_state', 'main_control_ushort_34',
              'power_guard_byte', 'original_return_R0', 'classification_byte',
              'classification_input8_hex')
    auth_fields = ('observation_sequence', 'virtual_time_ns', 'HAL_tick', 'host_elapsed_seconds')
    auth = []
    for event in raw.get('observations', []):
        for key in ('original_battery_authentication_comparator',
                    'original_battery_authentication_completion', 'original_cmd89_transaction_return'):
            if key in event:
                auth.append(dict(kind=key, **{k: event.get(k) for k in auth_fields}))
    return dict(retained_task_events=len(events),
                retained_entry_counts=dict(Counter(e['entry'] for e in events if e['phase'] == 'entry')),
                task_events=[{k: e.get(k) for k in fields} for e in events],
                authentication_and_cmd89_times=auth,
                comparator_return=raw.get('original_battery_authentication_comparator', {}).get('comparator_return'),
                activation=raw.get('battery_task_trace_activation'),
                scope='retained passive observations; entry counts are not total task execution counts')


def inside(value):
    path = Path(value)
    path = path if path.is_absolute() else ROOT / path
    path = path.resolve(strict=True)
    if not path.is_relative_to(ROOT):
        raise ValueError('Evidence must remain inside this package: ' + str(path))
    return path


def byte_identity(path, expected=None):
    result = identity(path)
    if expected is not None:
        for key in ('bytes', 'sha256'):
            if key in expected and result[key] != expected[key]:
                raise ValueError('Retained identity mismatch: ' + str(path) + ' ' + key)
    return result


def retained_path(value, envelope):
    path = Path(value)
    if path.is_absolute():
        marker = '/results/' + envelope.name + '/'
        if marker in str(path):
            return inside(envelope / str(path).split(marker, 1)[1])
    return inside(path if path.is_absolute() else envelope / path)


def lcd_log(path):
    lines = path.read_text(errors='replace').splitlines()
    submissions = [line for line in lines if 'Z6II_LCD_SUBMISSION ns=' in line]
    enabled = [line for line in submissions if re.search(r' enable=11/1 ', line)]
    scanouts = [line for line in lines if 'Z6II_LCD_SCANOUT frame=' in line]
    overlay = [line for line in scanouts if ' overlay=1 ' in line]
    endings = [line for line in lines if 'Z6II_LCD98_TRACE_END ' in line]
    trace = {}
    if endings:
        trace = {k: int(v) for k, v in re.findall(r'(\w+)=(\d+)', endings[-1])}
    return dict(evidence=byte_identity(path), logged_submissions=len(submissions),
                first_complete_configuration_virtual_ns=(
                    int(re.search(r'ns=(\d+)', enabled[0]).group(1)) if enabled else None),
                logged_scanouts=len(scanouts), logged_overlay_scanouts=len(overlay),
                first_scanout=scanouts[0] if scanouts else None,
                first_overlay_scanout=overlay[0] if overlay else None,
                MMIO_trace_completion=trace,
                limits='log event counts are observations; MMIO and USART debug lines may be sampled')


def inspect_run(envelope, output):
    run = envelope / 'run'
    locked_path = envelope / 'prepare/锁定命令与输入.json'
    locked = read(locked_path)
    unified = (run / 'native-unified-result.json').exists()
    raw_path = run / ('native-unified-result.json' if unified else 'EXPEED/结果.json')
    raw = read(raw_path)
    accept_path = envelope / 'acceptance.json'
    acceptance = read(accept_path) if accept_path.exists() else {}
    scenario_path = run / 'native-gpio-scenario-result.json'
    scenario = read(scenario_path)
    binary = locked.get('selected_binary')
    if binary:
        binary = byte_identity(inside(binary['path']), binary)
    else:
        for row in locked.get('build_manifests', []):
            if 'EXPEED' in row['path']:
                manifest = read(inside(row['path']))
                binary = byte_identity(inside(manifest['binary']),
                                       {'sha256': manifest['binary_sha256']})
                break
    samples = []
    if unified:
        for row in raw.get('UI', {}).get('samples', []):
            if row.get('image'):
                samples.append((retained_path(row['image']['path'], envelope), row['image'],
                                row.get('virtual_time_ns_before'), row.get('virtual_time_ns_after'), None))
    else:
        timeline = raw.get('LCD_snapshot_timeline', [])
        unique = {}
        for row in timeline:
            if row.get('png'):
                unique.setdefault(row['png'], row)
        for value, row in unique.items():
            path = retained_path(value, envelope)
            samples.append((path, {'sha256': row['png_sha256']}, None, None, row.get('host_seconds')))
        display = raw.get('engines', {}).get('master', {}).get('display', {})
        if display.get('png') and display['png'] not in unique:
            samples.append((retained_path(display['png'], envelope),
                            {'sha256': display['png_sha256']}, None, None, None))
    frames, distinct = [], {}
    images = output / envelope.name
    for path, expected, before, after, host in samples:
        file_identity = byte_identity(path, expected)
        with Image.open(path) as source:
            rgb = source.convert('RGB')
            extrema = rgb.getextrema()
            pixel_hash = hashlib.sha256(rgb.tobytes()).hexdigest()
            nonblack = any(high > 0 for low, high in extrema)
            uniform = all(low == high for low, high in extrema)
            frame = dict(image=file_identity, size=list(rgb.size), pixel_sha256=pixel_hash,
                         nonblack=nonblack, uniform=uniform,
                         virtual_ns_before=before, virtual_ns_after=after, host_seconds=host)
            frames.append(frame)
            if nonblack and not uniform and pixel_hash not in distinct:
                images.mkdir(exist_ok=True)
                png = images / ('distinct-%02d.png' % len(distinct))
                rgb.save(png)
                if hashlib.sha256(Image.open(png).convert('RGB').tobytes()).hexdigest() != pixel_hash:
                    raise ValueError('Review PNG differs from the original screenshot pixels')
                distinct[pixel_hash] = dict(source=file_identity, review_PNG=byte_identity(png),
                                           pixel_sha256=pixel_hash, visible_content=reviewed_content(pixel_hash),
                                           virtual_ns_before=before, virtual_ns_after=after,
                                           host_seconds=host, role_assignment_verified=False)
    debugger = raw.get('debugger_zero_guest_writes', {}) if unified else acceptance.get('debugger_assistance', {})
    result = dict(run=envelope.name, execution='single-QEMU' if unified else 'legacy-three-process',
                  locked=byte_identity(locked_path), retained_result=byte_identity(raw_path), binary=binary,
                  experiment=locked.get('experiment'), budget_host_seconds=raw.get('budget_host_seconds'),
                  launcher=read(envelope / 'launcher-status.json'),
                  final_evidence=raw.get('final_evidence'), architecture_passed=raw.get('architecture_passed'),
                  zero_host_guest_writes_verified=(debugger.get('verified') is True if unified else
                      debugger.get('status') == 'zero_guest_writes_verified') if debugger else None,
                  Host_guest_write_packets=debugger.get('actual_guest_RAM_register_write_count') if unified else
                      debugger.get('actual_guest_write_packets'),
                  actual_input_schedule=scenario.get('schedule'), input_delivery_complete=scenario.get('complete'),
                  input_events=scenario.get('events'),
                  LCD=lcd_log(run / ('qemu.log' if unified else 'EXPEED/engines/master/qemu.log')),
                  pixels=dict(saved_files=len(frames), nonblack_nonuniform_samples=sum(
                      f['nonblack'] and not f['uniform'] for f in frames), distinct_nonblack_pixels=len(distinct),
                      distinct_pixel_hashes=len({f['pixel_sha256'] for f in frames}),
                      saved_file_scope=('all retained QMP sample files' if unified else
                          'unique retained timeline PNG files plus final entry screendump'),
                      first_nonblack=next((f for f in frames if f['nonblack'] and not f['uniform']), None),
                      frames=frames, review_images=list(distinct.values()),
                      observed_display_stage='nonblack_pixels' if distinct else 'black_only',
                      MENU_verified=False, stable_MENU_verified=False, original_image_pipeline_verified=False),
                  original_authentication_ready=raw.get('original_battery_authentication_completion', {}).get('ready'),
                  battery_observations=battery_observations(raw) if unified else None,
                  original_cmd89_returns=[dict(occurrence=e.get('occurrence'), returned_R0=e.get('returned_R0'),
                                              observation_sequence=e.get('observation_sequence'),
                                              HAL_tick=e.get('HAL_tick'),
                                              TX_hex=e.get('TX_hex'), RX_hex=e.get('RX_hex'))
                                          for e in raw.get('original_cmd89_transaction_returns', [])],
                  retained_acceptance=byte_identity(accept_path) if accept_path.exists() else None,
                  formal_scope=acceptance.get('acceptance_scope'),
                  formal_package_status=acceptance.get('package_runtime_status'),
                  formal_full_camera_status=acceptance.get('full_camera_status'),
                  formal_errors=acceptance.get('errors', []), peer=[])
    for peer_path in run.glob('**/USART1-peer/closed.json'):
        peer = read(peer_path)
        streams = {key: byte_identity(retained_path(row['path'], envelope), row)
                   for key, row in peer.get('streams', {}).items()}
        for stream, counter in (('public_TX', 'public_TX_bytes'), ('synthetic_RX', 'synthetic_RX_bytes')):
            if stream not in streams or streams[stream]['bytes'] != peer.get(counter):
                raise ValueError('Peer counter differs from the complete retained stream: ' + str(peer_path))
        result['peer'].append(dict(evidence=byte_identity(peer_path), streams=streams,
            TX_bytes=peer.get('public_TX_bytes'), RX_bytes=peer.get('synthetic_RX_bytes'),
            replies=peer.get('replies'), protocol_counts=peer.get('protocol_counts'),
            host_turnaround_seconds=peer.get('host_turnaround_seconds'),
            first_transactions=[{k: e.get(k) for k in ('sequence', 'transaction', 'host_monotonic_ns')}
                                for e in peer.get('events', [])[:8]],
            error=peer.get('error'), physical_battery_authentication_verified=False))
    return result


def markdown(report, output):
    complete = [r for r in report['runs'] if r['execution'] == 'single-QEMU' and
                r.get('formal_scope') == 'complete_declared_scenario']
    current = max(complete, key=lambda r: r['run']) if complete else None
    lines = ['# Native 显示回归的固定运行对照', '',
        '旧输入表使用宿主秒；迁移后直接沿用了同一组数字作为虚拟秒。20:40 启动的默认单实例只推进到约 12.17 个虚拟秒，PC5 的 25 秒期限未到，MENU 的 165 秒期限也未到。这是已确认的输入时序迁移错误。', '',
        '21:27 的构建与旧三进程入口组合能够配置 LCD；21:30 的单实例提前交付 PC5 后，120 宿主秒对照恢复 scanout，但保存帧仍为黑。21:34 的 360 宿主秒缩减场景包含 PC5 与 MENU pad，保存了拍摄 OSD 和黄色等待沙漏；它与较短对照的预算不同，不能单独证明 MENU 的因果。21:43 的完整默认场景保存了电池通信错误弹窗。', '',
        '本报告只覆盖下表列出的固定运行。非黑像素、实际画面内容与功能验收分别记录；内容标注只匹配人工检查过的原始 RGB hash，console 的 engine 归属仍未验证。', '']
    if current:
        p = current['pixels']
        content = '；'.join(dict.fromkeys(i['visible_content']['description'] for i in p['review_images'])) or '全黑'
        returns = ' → '.join(str(e['returned_R0']) for e in current['original_cmd89_returns']) or '未观察'
        lines += ['**本报告时间最晚的完整 native 场景：%s。** 保存 %s 帧、%s 种 RGB hash、%s 种非黑非纯色内容：%s。原厂 cmd89 返回顺序为 %s；正式目录状态为 `%s`，整机功能为 `%s`。' % (
            current['run'], p['saved_files'], p['distinct_pixel_hashes'], p['distinct_nonblack_pixels'],
            content, returns, current['formal_package_status'], current['formal_full_camera_status']), '']
    lines += [
        '| 固定运行 | 执行模型 | 最终虚拟秒 | LCD scanout 日志 | 非黑样本 / 保存文件 | 可见内容 | 零 Host 写包 | 正式目录验收 |',
        '|---|---|---:|---:|---:|---|---|---|']
    for r in report['runs']:
        ns = (r.get('final_evidence') or {}).get('virtual_ns')
        seconds = ('%.6f' % (ns / 1e9)) if ns is not None else '独立时钟'
        p = r['pixels']
        content = '；'.join(dict.fromkeys(i['visible_content']['description'] for i in p['review_images'])) or '全黑'
        lines.append('| [%s](../../%s/prepare/锁定命令与输入.json) | %s | %s | %s | %s / %s | %s | %s | %s |' % (
            r['run'], r['run'], r['execution'], seconds, r['LCD']['logged_scanouts'],
            p['nonblack_nonuniform_samples'], p['saved_files'], content,
            r['zero_host_guest_writes_verified'], r['formal_package_status'] or '仅实验'))
    lines += ['', '旧轮最早保存的非黑画面在约 190.804 个宿主秒；1.4 个虚拟秒是显示提交阶段，不是非黑画面的出现时间。各角色旧时钟独立，不能直接与新单实例的共同虚拟秒相减。', '',
              '旧三进程保存文件数包含去重后的 timeline PNG 和最终入口截图；同像素的不同文件分别计数，像素 hash 单独去重。因此旧轮的 6 个保存文件与正式验收采用相同范围。采样记录数、保存文件数和 LCD 日志数分别报告。', '',
              'UART 字节数从完整 TX / RX 文件与 peer 汇总核对；不能把采样上限为 64 的 USART 日志行数当作总字节数。电池 peer 使用声明的外部协议参数，认证返回与物理电池认证分别报告。', '',
              '默认输入表已改为 2、6.5、6.7、8、8.2、10、10.2 个共同虚拟秒。后两组 GPIO 的顺序保留为外部场景输入；这些 pin 的物理身份、输入期限及 hold 时长均未经过真机物理测量。', '',
              '本报告复核文件身份、原始像素与输入记录，并生成像素完全一致的 PNG 预览。完整 RSP / QMP 关联以每轮正式 acceptance 为准；没有 acceptance 的实验不替代整机验收。', '',
              '机器可读证据：[report.json](report.json)。每张预览的来源、SHA、像素 hash 与采样时间均保留在该文件中。', '']
    pair = [next((r for r in report['runs'] if r['run'] == name), None) for name in (
        '20261025-213438-display-same-single-pc5-menu-216c05', '20261025-214323-native-7e01f2')]
    if all(pair):
        lines += ['缩减场景与默认场景在 MENU 的 6.5 秒期限之前已经有电池任务时序差异。默认轮完整 TX 从字节偏移 44（零基）开始多出一次认证请求；原厂认证尾部最终都观察到 ready=1，两次 cmd89 都为同一种请求并返回 R0=0。弹窗不能直接解释为这两次 cmd89 调用失败；目前的比较也不足以直接将弹窗归因于后面的 PG1 / PG2 输入。', '',
                  '| 电池观察 | 21:34 缩减 PC5 + MENU 场景 | 21:43 完整默认场景 |',
                  '|---|---:|---:|']
        observations = [r['battery_observations'] for r in pair]
        peers = [r['peer'][0] for r in pair]
        rows = [('完整 UART TX 字节', [p['TX_bytes'] for p in peers]),
                ('完整 UART RX 字节', [p['RX_bytes'] for p in peers]),
                ('完整串口回复数', [p['replies'] for p in peers]),
                ('认证请求数', [p['protocol_counts']['TX_command_01'] for p in peers]),
                ('保留电池任务观察数', [o['retained_task_events'] for o in observations]),
                ('认证 comparator 返回', [o['comparator_return'] for o in observations]),
                ('原厂认证尾 ready', [r['original_authentication_ready'] for r in pair])]
        for label, values in rows:
            lines.append('| %s | %s | %s |' % (label, values[0], values[1]))
        for kind, label in [('original_battery_authentication_completion', '原厂认证尾共同虚拟秒'),
                            ('original_cmd89_transaction_return', '首次 cmd89 返回共同虚拟秒')]:
            values = [next(e['virtual_time_ns'] / 1e9 for e in o['authentication_and_cmd89_times']
                           if e['kind'] == kind) for o in observations]
            lines.append('| %s | %.6f | %.6f |' % (label, values[0], values[1]))
        lines += ['', '以上电池对照仅涉及 21:34 与 21:43 两个固定场景。电池 peer 使用声明的合成协议输入和 2 毫秒宿主等待。MCU 内串口字节按共同虚拟时间推进；socket 应答到达的虚拟期限仍未保证。保留的不同认证重试与刷新次数是观察事实，弹窗的完整原厂触发链和旧菜单缺失原因仍未知。任务观察数不等于实际总执行次数，认证返回也不等于物理电池认证。', '']
    if current and current['original_cmd89_returns']:
        lines += ['**%s 的完整 cmd89 返回序列**' % current['run'], '',
                  '| 观察序号 | HAL tick | 原厂 R0 | TX | RX |',
                  '|---:|---:|---:|---|---|']
        for event in current['original_cmd89_returns']:
            lines.append('| %s | %s | %s | `%s` | `%s` |' % (
                event['observation_sequence'], event['HAL_tick'], event['returned_R0'],
                event['TX_hex'], event['RX_hex']))
        lines += ['', '成功、失败与重试返回按原始顺序保留；最后一次成功不能覆盖此前失败或补足未执行的另一种必需请求。', '']
    for r in report['runs']:
        if r['formal_errors']:
            lines += ['**%s 的正式验收缺口**：%s。' % (
                r['run'], '；'.join(r['formal_errors'])), '']
        for item in r['pixels']['review_images']:
            png = ROOT / item['review_PNG']['path']
            lines += ['**%s：%s**' % (r['run'], item['visible_content']['description']), '',
                      '![%s 原始 QEMU 像素](%s)' % (r['run'], png.relative_to(output)), '']
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--runs', nargs='+', default=DEFAULT_RUNS, help='Run names in results/')
    parser.add_argument('--output', help='New package-relative report directory')
    args = parser.parse_args()
    output = ROOT / (args.output or ('results/display-regressions/' +
        datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:6]))
    if output.is_absolute() and not output.resolve().is_relative_to(ROOT):
        parser.error('Output must remain inside this package')
    output.mkdir(parents=True, exist_ok=False)
    runs = [inside(ROOT / 'results' / name) for name in args.runs]
    report = dict(schema='z62.native-display-regression-comparison/1', created=now(),
                  auditor=byte_identity(Path(__file__)), camera_access=False, guest_state_writes=0,
                  scope='retained display/input observations; full-camera acceptance is separate',
                  runs=[inspect_run(r, output) for r in runs])
    save(output / 'report.json', report)
    (output / 'report.md').write_text(markdown(report, output))
    print(str(output / 'report.md'), flush=True)
    for r in report['runs']:
        print(r['run'], 'LCD', r['LCD']['logged_scanouts'], 'nonblack',
              r['pixels']['nonblack_nonuniform_samples'], '/', r['pixels']['saved_files'], flush=True)


if __name__ == '__main__':
    main()
