"""Sequential acceptance scenarios and an evidence-derived development snapshot."""
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
import shutil
import uuid

from z62_common import ROOT, now, read, save, identity, profiles
from acceptance import audit
from native_ui_index import snapshot as native_ui_snapshot


def collect(names=None, refresh=True):
    rows = []
    for name in names or profiles():
        pointer = read(ROOT/('results/latest-' + name + '.json'), {})
        if name == 'native':
            display_pointer = read(ROOT/'results/latest-native-display-observation.json', {})
            if display_pointer.get('updated', '') > pointer.get('updated', ''):
                pointer = display_pointer
        if not pointer:
            rows.append(dict(profile=name, status='not_run', camera_functions='not_verified'))
            continue
        envelope = ROOT/'results'/pointer['run']
        try:
            report = audit(envelope) if refresh else read(envelope/'acceptance.json')
            if not report:
                raise ValueError('No completed audit')
            lock = read(envelope/'prepare/锁定命令与输入.json', {})
            registry = report.get('engineering_capabilities', {}).get('task_registry', {}).get('allocated_slots', {})
            display = report['LCD']['display_mode_observations']
            counters = report['imaging']['counters'].get('master', {})
            rows.append(dict(profile=name, run=pointer['run'],
                status=report['package_runtime_status'],
                binary_selection=lock.get('profile', {}).get('binary_selection', 'imported'),
                budget_seconds=lock.get('runtime_budget_seconds'),
                actual_seconds=read(envelope/'launcher-status.json', {}).get('elapsed_seconds'),
                original_entries={r: e['status'] for r, e in report['original_entry_observations'].items()},
                guest_write_packets=report['debugger_assistance']['actual_guest_write_packets'],
                debugger_status=report['debugger_assistance']['status'],
                complete_debugger_capture=report['debugger_assistance'].get(
                    'complete_expected_connection_capture',
                    report['debugger_assistance'].get('complete_six_connection_capture')),
                expected_debugger_connections=report['debugger_assistance'].get('expected_connection_count', 6),
                actual_debugger_connections=report['debugger_assistance'].get('actual_connection_count'),
                execution_model=report.get('execution_model', 'legacy-three-process'),
                native_ui_acceptance=native_ui_snapshot() if name == 'native' else None,
                acceptance_scope=report.get('acceptance_scope', 'complete_declared_scenario'),
                QEMU_instances=report['lifecycle'].get('actual_instance_count', 3),
                architecture=report.get('architecture', {}),
                final_evidence=report.get('final_evidence', {}),
                pending_virtual_input_indices=report.get('external_input_scenario', {}).get('pending_schedule_indices', []),
                task_allocated_slots=registry,
                distinct_nonblack_nonuniform_frames=report['LCD']['distinct_nonblack_nonuniform_frames'],
                display_mode_samples=display['samples'],
                display_mode_distinct_nonblack_frames=display['distinct_nonblack_pixel_hashes'],
                display_cycle_return_observed=display.get('cycle_return_pixel_match_observed'),
                counters=counters, HDMI_nonempty_payloads=len(report['imaging']['HDMI_nonempty_payloads']),
                camera_functions=report['full_camera_status'],
                functional_gates=report['functional_gates'],
                engineering_capabilities=report.get('engineering_capabilities', {}),
                acceptance=identity(envelope/'acceptance.json'),
                acceptance_markdown=str((envelope/'acceptance.md').relative_to(ROOT)),
                errors=report['errors']))
        except Exception as error:
            rows.append(dict(profile=name, run=pointer['run'], status='audit_error',
                             camera_functions='not_verified', error=str(error)))
    return dict(schema='z62.development-progress/1', generated=now(), profiles=rows,
                verified_profile_count=sum(r['status'] == 'verified' for r in rows),
                profile_count=len(rows), camera_functions='not_verified', camera_access=False,
                source='run-local identities, actual QEMU lifecycle, debugger wire bytes, task RAM and saved pixels')


def markdown(report):
    rows = ['# Z6II QEMU 开发进展快照', '',
            '生成时间：`%s`。%d / %d 个 profile 的最新保留运行通过目录运行与证据检查。' %
            (report['generated'], report['verified_profile_count'], report['profile_count']), '',
            '原厂应用入口执行、任务/调度 RAM、native UI 画面、辅助显示和整机功能分别验收。'
            '当前整机功能状态为 **not_verified**。', '',
            '| Profile | 目录运行 | Binary | Host 写包 | 非黑不同帧 | DISP 样本 / 不同帧 | 报告 |',
            '|---|---|---|---:|---:|---|---|']
    for row in report['profiles']:
        link = '[验收](%s/acceptance.md)' % row['run'] if row.get('run') else '尚未运行'
        rows.append('| %s | %s | %s | %s | %s | %s / %s | %s |' % (
            row['profile'], row['status'], row.get('binary_selection', '—'),
            row.get('guest_write_packets') if row.get('guest_write_packets') is not None else '未知',
            row.get('distinct_nonblack_nonuniform_frames', '—'),
            row.get('display_mode_samples', '—'), row.get('display_mode_distinct_nonblack_frames', '—'), link))
    failed = [row for row in report['profiles'] if row['status'] != 'verified']
    if failed:
        rows += ['', '## 本次未通过的项目', '', '| Profile | 实际原因 |', '|---|---|']
        for row in failed:
            reasons = row.get('errors') or [row.get('error', '尚未完成可复查的运行')]
            detail = '；'.join(str(reason) for reason in reasons).replace('|', '\\|').replace('\n', ' ')
            rows.append('| %s | %s |' % (row['profile'], detail))
    unified = [row for row in report['profiles'] if row.get('execution_model') == 'single-qemu-five-cpu']
    if unified:
        rows += ['', '## 单实例观察范围', '',
                 '| Profile | 验收 scope | PID / CPU | 架构 snapshot epoch / virtual ns | final 采样 | 待交付 virtual 输入序号 |',
                 '|---|---|---|---|---|---|']
        for row in unified:
            arch, final = row.get('architecture', {}), row.get('final_evidence', {})
            detail = final.get('status', 'unknown')
            if final.get('missing'):
                detail += ': ' + ', '.join(final['missing'])
            rows.append('| %s | %s | %s / %s | %s / %s | %s | %s |' % (
                row['profile'], row.get('acceptance_scope'), arch.get('pid', '未知'),
                len(arch.get('query_cpus_fast', [])), arch.get('snapshot_epoch', '未知'),
                arch.get('snapshot_virtual_ns', '未知'), detail,
                row.get('pending_virtual_input_indices', [])))
        rows += ['', '只读 QOM 架构观察与主动 debugger fixture 回归分别报告。CNTVCT 实测频率、'
                 '复位隔离及完整原厂运行由各自固定报告验收；输入待交付时保持 incomplete。']
    native_ui = next((row.get('native_ui_acceptance') for row in report['profiles']
                      if row['profile'] == 'native' and row.get('native_ui_acceptance')), None)
    if native_ui:
        rows += ['', '## Native 菜单与曝光功能验收', '',
                 '状态：`%s`。UI 报告、原始运行、锁定输入与源文件、ROM、binary 和图像均按字节身份复核。'
                 % native_ui['status']]
        if native_ui.get('report'):
            link = '../' + native_ui['report']['path'].replace('report.json', 'report.md')
            checks = native_ui['checks']
            rows += ['', '| 原始运行 | 当前 binary 匹配 | 当前 native 环境匹配 | 稳定菜单 | 曝光显示 | 报告 |',
                     '|---|---|---|---|---|---|',
                     '| %s | %s | %s | %s | %s | [UI 验收](%s) |' % (
                         native_ui['run'], native_ui['binary_matches_current'],
                         native_ui['environment_matches_current'], checks['stable-menu'],
                         checks['exposure'], link), '',
                     '只有 binary 与 native 环境均匹配时，该报告才列入 `current_checks`；'
                     '历史通过结果保留，但不认证变更后的配置。菜单通过不代表原厂实时图像、拍照、录像或 HDMI 通过。']
        elif native_ui.get('error'):
            rows += ['', '未采用 UI 功能结论：' + native_ui['error']]
    native = next((row for row in report['profiles'] if row['profile'] == 'native' and
                   row.get('status') == 'verified' and row.get('complete_debugger_capture') and
                   row.get('guest_write_packets') == 0), None)
    if native and native.get('distinct_nonblack_nonuniform_frames', 0):
        rows += ['', 'Native 在实际调试连接记录完整和零 Host RAM / 寄存器写包的条件下保存了 '
                 '%d 个非黑且非纯色的不同帧。菜单与拍摄 OSD 的目视确认、图片及完整验收范围见 '
                 '[功能验收规则](../docs/ACCEPTANCE.md)。' % native['distinct_nonblack_nonuniform_frames']]
    rows += ['', '## 原码与图像链路观察', '',
             '| Profile | 原厂入口 Master / Slave / MCU | 任务分配槽 Master / Slave | RAW / ISP 计数 | 原厂 DMA / video 计数 | HDMI 非空文件 |',
             '|---|---|---|---|---|---:|']
    for row in report['profiles']:
        entries = row.get('original_entries', {})
        registry = row.get('task_allocated_slots', {})
        counters = row.get('counters', {})
        rows.append('| %s | %s | %s / %s | %s / %s | %s / %s | %s |' % (
            row['profile'], ' / '.join(entries.get(role, '未知') for role in ('master', 'slave', 'MCU')),
            registry.get('master') if registry.get('master') is not None else '未知',
            registry.get('slave') if registry.get('slave') is not None else '未知',
            counters.get('raw_frames_total', '未知'), counters.get('isp_frames_total', '未知'),
            counters.get('original_dma_submissions', '未知'), counters.get('original_video_frames', '未知'),
            row.get('HDMI_nonempty_payloads', '未知')))
    rows += ['', '## 观察事实与判定范围', '',
             '- Master / Slave 各自从原厂更新镜像应用入口 `0x10020000` 开始，MCU 从原厂 reset vector 开始。',
             '- 任务表分配槽数和 current/next 根是原始 RAM 观察值；完整 RTOS/TCB 身份与跨端因果链单独验收。',
             '- 单实例 native 要求一个 PID、五核、同一虚拟时钟及两条完整调试连接；历史三进程记录仍按六连接审计。',
             '- Native 要求零 Host RAM/寄存器写包和零未分类 mutation；结构回归的 debugger fixture 单独分类。',
             '- Host 预算与输入的 virtual deadline 分别记录；架构观察不把待交付输入计为成功。',
             '- Assisted 的 RAM/寄存器写包、直接 PC 指派、合成输入及录制 OSD 重放均写入本次报告。',
             '- RAW/ISP/视频计数不单独证明原厂拍照或录像；HDMI 接收器没有非空图像 payload 时保持未验收。', '',
             '自然上电、完整 RTOS/TCB 身份、跨引擎因果、稳定 MENU、原厂 Live View、拍照与存储、录像及 HDMI '
             '的证据缺口分别列在每份验收报告中。辅助场景的已完成标记只证明场景推进，不认证照片或视频规格。', '',
             '每次运行的命令、ROM、binary、源文件快照、输入、SHA256、总线和画面保留在各自结果目录。', '',
             '机器可读快照：[progress.json](progress.json)。']
    return '\n'.join(rows) + '\n'


def status(refresh=True):
    report = collect(refresh=refresh)
    save(ROOT/'results/progress.json', report)
    (ROOT/'results/progress.md').write_text(markdown(report))
    print(markdown(report), flush=True)
    return 0


def accept_suite(args, runner):
    """Run one profile at a time. Exit 0 is harness acceptance, 2 is a native gate gap."""
    architecture_only = bool(getattr(args, 'architecture_only', False))
    if architecture_only and args.profiles != ['native']:
        raise ValueError('--architecture-only requires exactly --profiles native')
    name = datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:6]
    folder = ROOT/'results/suites'/name
    folder.mkdir(parents=True, exist_ok=False)
    result = dict(schema='z62.acceptance-suite/1', started=now(), profiles=args.profiles,
                  binary_selection=args.binary, audit_only=args.audit_only,
                  architecture_only=architecture_only,
                  actual_commands=[], camera_access=False, whole_camera_verified=False)
    save(folder/'suite.json', result)
    failed = False
    if not args.audit_only:
        for profile in args.profiles:
            print('Acceptance scenario: ' + profile, flush=True)
            started = now()
            entry = dict(profile=profile, started=started)
            try:
                code = runner(SimpleNamespace(profile=profile, binary=args.binary,
                                              seconds=args.seconds, full=not args.quick,
                                              architecture_only=architecture_only))
            except Exception as error:
                code = 1
                entry['error'] = type(error).__name__ + ': ' + str(error)
                print('Acceptance scenario failed: ' + entry['error'], flush=True)
            entry.update(finished=now(), exit_code=code)
            result['actual_commands'].append(entry)
            save(folder/'suite.json', result)
            failed = failed or code != 0
    progress = collect(args.profiles, refresh=True)
    result.update(finished=now(), observations=progress,
                  status='verified' if not failed and progress['verified_profile_count'] == len(args.profiles)
                         else 'failed_or_unknown', camera_functions='not_verified')
    for row in progress['profiles']:
        if row.get('acceptance'):
            snapshot = folder/(row['profile']+'-acceptance.json')
            shutil.copy2(ROOT/row['acceptance']['path'], snapshot)
            row['retained_audit_snapshot'] = identity(snapshot)
    save(folder/'suite.json', result)
    save(ROOT/'results/latest-suite.json', dict(path=str(folder.relative_to(ROOT)), updated=now()))
    save(ROOT/'results/progress.json', collect(refresh=False))
    (ROOT/'results/progress.md').write_text(markdown(collect(refresh=False)))
    print('Acceptance suite: ' + str(folder.relative_to(ROOT)), flush=True)
    print('Scenario evidence: ' + result['status'] + '; camera functions: not_verified', flush=True)
    if result['status'] != 'verified':
        return 1
    return 2 if args.strict else 0
