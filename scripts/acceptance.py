"""Read retained run evidence. No guest execution, state writes or camera IO.

Process accounting, original application entry, debugger assistance and camera
functions have separate gates. Missing evidence remains unknown. A mode name,
wrapper exit code or empty receiver cannot prove a camera function.
"""
from pathlib import Path
from collections import Counter
from bisect import bisect_left
import hashlib
import json
import re
from z62_common import ROOT, now, read, save, digest, identity, evidence_path

ROLES = ('master', 'slave', 'MCU')
COUNTERS = ('capture_config_writes', 'capture_address_writes',
            'capture_nonzero_address_writes', 'raw_frames_total', 'isp_frames_total',
            'original_dma_submissions', 'original_video_frames',
            'synthetic_dma_submissions', 'synthetic_video_frames')


def rsp_packets(data):
    """Parse wire packets and verify transmitted checksums, including X escapes."""
    packets, errors, offset = [], [], 0
    while offset < len(data):
        start = data.find(b'$', offset)
        if start < 0:
            break
        end = data.find(b'#', start + 1)
        if end < 0 or end + 3 > len(data):
            errors.append('incomplete RSP packet at offset %d' % start)
            break
        raw = data[start + 1:end]
        try:
            expected = int(data[end + 1:end + 3], 16)
        except ValueError:
            errors.append('invalid RSP checksum at offset %d' % start)
            offset = end + 3
            continue
        if sum(raw) & 255 != expected:
            errors.append('RSP checksum mismatch at offset %d' % start)
        decoded, index = bytearray(), 0
        while index < len(raw):
            if raw[index] == 125:
                index += 1
                if index == len(raw):
                    errors.append('incomplete RSP escape at offset %d' % start)
                    break
                decoded.append(raw[index] ^ 32)
            else:
                decoded.append(raw[index])
            index += 1
        packets.append((start, bytes(decoded)))
        offset = end + 3
    return packets, errors


def audit(envelope):
    envelope = Path(envelope).resolve(strict=True)
    locked = read(envelope / 'prepare/锁定命令与输入.json', {})
    launcher = read(envelope / 'launcher-status.json', {})
    profile = locked.get('profile', {})
    errors, notes, sources, cache = [], [], {}, {}

    def ref(path):
        path = Path(path).resolve(strict=True)
        if path not in cache:
            value = identity(path)
            try:
                value['path'] = str(path.relative_to(envelope))
                value['relative_to'] = 'run_envelope'
            except ValueError:
                value['relative_to'] = 'package_root' if not Path(value['path']).is_absolute() else 'absolute'
            cache[path] = value
        sources[str(path)] = cache[path]
        return dict(cache[path])

    def load(path, required=False):
        path = Path(path)
        if not path.exists():
            if required:
                errors.append('Missing evidence: ' + str(path.relative_to(envelope)))
            return {}
        try:
            value = json.loads(path.read_text())
            ref(path)
            if not isinstance(value, dict):
                raise ValueError('expected a JSON object')
            return value
        except Exception as error:
            errors.append('Invalid evidence %s: %s' % (path.name, error))
            return {}

    def checked(item):
        path = evidence_path(item['path'], envelope, locked)
        try:
            relative = path.relative_to(ROOT)
        except ValueError:
            relative = None
        if relative is not None and relative.parts[0] in ('profiles', 'scripts', 'src'):
            snapshot = envelope/'prepare/execution-sources'/relative
            if snapshot.is_file() and digest(snapshot) == item['sha256']:
                path = snapshot
        actual = ref(path)
        if actual['sha256'] != item['sha256'] or (
                type(item.get('bytes')) is int and actual['bytes'] != item['bytes']):
            raise ValueError('Retained evidence SHA/size changed: ' + str(path))
        return path

    def validate_refs(value):
        if isinstance(value, dict):
            if {'path', 'bytes', 'sha256'} <= value.keys() and type(value['bytes']) is int:
                try:
                    checked(value)
                except Exception as error:
                    errors.append(str(error))
            for item in value.values():
                validate_refs(item)
        elif isinstance(value, list):
            for item in value:
                validate_refs(item)

    unified = (locked.get('execution_model') == 'single-qemu-five-cpu' or
               profile.get('execution_model') == 'single-qemu-five-cpu' or
               str(profile.get('coordinator', '')).endswith('/native_unified_probe.py'))
    if unified:
        return audit_unified(envelope, locked, launcher, profile, errors, notes,
                             sources, ref, load, checked, validate_refs)

    load(envelope / 'run.json', required=True)
    load(envelope / 'prepare/锁定命令与输入.json', required=True)
    load(envelope / 'launcher-status.json', required=True)
    preflight = load(envelope / 'package-preflight.json', required=True)
    run = envelope / 'run'
    raw = load(run / '三端接入结果.json', required=True)
    public = load(run / '运行验收证据.json', required=True)
    ex = load(run / 'EXPEED/结果.json', required=True)
    mcu = load(run / 'MCU/结果.json', required=True)
    if preflight.get('passed') is not True:
        errors.append('Package preflight failed or is incomplete')
    for key in ('coordinator_exit', 'scenario_exit'):
        if launcher.get(key) != 0:
            errors.append('Host launcher %s: %s' % (key, launcher.get(key, 'unknown')))
    if launcher.get('error'):
        errors.append('Host launcher: ' + str(launcher['error']))
    for failure in raw.get('coordinator_status', {}).get('failures', []):
        errors.append('Host runner: ' + json.dumps(failure, ensure_ascii=False, sort_keys=True))
    validate_refs(public)
    validate_refs(locked.get('firmware_manifest', {}))
    validate_refs(locked.get('bus_tool', {}))
    for item in (locked.get('build_manifests', []) + locked.get('input_files', []) +
                 locked.get('execution_files', [])):
        try:
            checked(item)
        except Exception as error:
            errors.append(str(error))
    for item in locked.get('build_manifests', []):
        try:
            manifest = json.loads(checked(item).read_text())
            checked(dict(path=manifest['binary'], sha256=manifest['binary_sha256']))
        except Exception as error:
            errors.append('Build identity: ' + str(error))

    endpoints, records, entries = {}, {}, {}
    for role in ROLES:
        directory = run / ('MCU' if role == 'MCU' else 'EXPEED/engines/' + role)
        endpoint = mcu if role == 'MCU' else load(directory / '结果.json', required=True)
        endpoints[role] = (endpoint, directory)
        ledger = load(directory / 'QEMU-process-lifecycle.json', required=True)
        valid = (ledger.get('schema') == 'z6ii-qemu-process-lifecycle/1' and
                 ledger.get('role') == role and ledger.get('launch') == 'started' and
                 type(ledger.get('pid')) is int and ledger['pid'] > 0 and
                 ledger.get('exit') == 'observed' and type(ledger.get('exit_code')) is int)
        records[role] = dict(status='verified' if valid else 'unknown',
                            launch=ledger.get('launch', 'unknown'), pid=ledger.get('pid'),
                            exit=ledger.get('exit', 'unknown'), exit_code=ledger.get('exit_code'),
                            evidence=ref(directory / 'QEMU-process-lifecycle.json') if ledger else None)
        if role == 'MCU':
            regs = endpoint.get('initial_reset_registers', {})
            entry = (endpoint.get('CPU_reset_SP_PC_verified') is True and
                     endpoint.get('original_ROM_in_memory_verified') is True and
                     regs.get('r13') == '0x20000c08' and regs.get('r15') == '0x080002b4')
            entries[role] = dict(status='observed' if entry else 'not_observed',
                                scope='original MCU reset vector', SP=regs.get('r13'), PC=regs.get('r15'))
        else:
            events = [e for e in endpoint.get('events', []) if e.get('event') == 'initial native entry']
            cores = events[0].get('cores', []) if events else []
            entry = len(cores) == 2 and all(
                c.get('original_instructions_verified') is True and
                c.get('registers', {}).get('r15') == '0x10020000' and
                c.get('instruction_bytes') == c.get('original_bytes') for c in cores)
            entries[role] = dict(status='observed' if entry else 'not_observed',
                                scope='original update-image application entry; Boot ROM omitted',
                                PC='0x10020000', observed_CPU_count=len(cores))
        entries[role]['evidence'] = ref(directory / '结果.json') if endpoint else None
        if entries[role]['status'] != 'observed':
            errors.append('Original entry not observed: ' + role)

    lifecycle = dict(status='verified' if all(x['status'] == 'verified' for x in records.values()) else 'unknown',
                     scope='three owned QEMU processes launched and their actual exits retained',
                     roles=records, exit_zero=all(x['exit_code'] == 0 for x in records.values()),
                     firmware_success_implied=False)

    debugger, writes, qmp_writes, unclassified, protocol_errors = [], [], [], [], []
    assigned_targets = Counter()
    for role, (endpoint, directory) in endpoints.items():
        ledgers = endpoint.get('debugger_API_byte_ledgers', endpoint.get('debugger_byte_ledgers', {}))
        for kind in ('RSP', 'QMP'):
            summary = ledgers.get(kind, {})
            streams = summary.get('streams', {})
            item = dict(role=role, protocol=kind, status='unknown', guest_write_packets=0,
                        external_pad_changes=0, software_breakpoints=0)
            try:
                if set(streams) != {'tx', 'rx'} or summary.get('closed') is not True:
                    raise ValueError('missing closed TX/RX byte ledger')
                paths = {direction: checked(value) for direction, value in streams.items()}
                if not all(paths[direction].stat().st_size > 0 for direction in ('tx', 'rx')):
                    raise ValueError('empty TX/RX byte ledger cannot establish a complete connection')
                item['evidence'] = [ref(p) for p in paths.values()]
                item['tx_bytes'] = streams['tx']['bytes']
                item['rx_bytes'] = streams['rx']['bytes']
                tx = paths['tx'].read_bytes()
                if kind == 'RSP':
                    packets, problems = rsp_packets(tx)
                    protocol_errors.extend('%s RSP: %s' % (role, p) for p in problems)
                    item['packet_count'] = len(packets)
                    for offset, packet in packets:
                        if packet.startswith((b'M', b'X', b'G', b'P')):
                            row = dict(role=role, protocol='RSP', command=packet[:1].decode(),
                                       tx_offset=offset, packet_bytes=len(packet))
                            if packet.startswith((b'M', b'X')):
                                match = re.match(rb'[MX]([0-9a-fA-F]+),([0-9a-fA-F]+):', packet)
                                if not match:
                                    raise ValueError('malformed memory-write packet')
                                row.update(address='0x%x' % int(match[1], 16), bytes=int(match[2], 16))
                            elif packet.startswith(b'G'):
                                register_bytes = bytes.fromhex(packet[1:].decode('ascii'))
                                if role != 'MCU' and len(register_bytes) >= 68:
                                    row['ARM_registers'] = {
                                        name: '0x%x' % int.from_bytes(register_bytes[index*4:index*4+4], 'little')
                                        for name, index in (('r0', 0), ('SP', 13), ('LR', 14), ('PC', 15), ('CPSR', 16))}
                                    if row['ARM_registers']['LR'] == '0x100202b4':
                                        assigned_targets[(role, row['ARM_registers']['PC'])] += 1
                            writes.append(row)
                            item['guest_write_packets'] += 1
                        elif packet.startswith(b'Z0,'):
                            item['software_breakpoints'] += 1
                        elif (re.fullmatch(rb'[g?cs]', packet) or
                              re.fullmatch(rb'[mp][0-9a-fA-F]+(?:,[0-9a-fA-F]+)?', packet) or
                              re.fullmatch(rb'H[gc](?:-1|0|p[0-9a-fA-F]+\.[0-9a-fA-F]+)', packet) or
                              re.fullmatch(rb'[Zz][1234],[0-9a-fA-F]+,[0-9a-fA-F]+', packet) or
                              re.match(rb'^qXfer:[^:]+:read:', packet) or
                              packet.startswith((b'qSupported', b'qfThreadInfo', b'qsThreadInfo',
                                                 b'qC', b'qAttached', b'qThreadExtraInfo', b'qOffsets',
                                                 b'qSymbol:')) or
                              re.fullmatch(rb'vCont;(?:[cs](?::(?:-1|0|p[0-9a-fA-F]+\.[0-9a-fA-F]+))?)(?:;[cs](?::(?:-1|0|p[0-9a-fA-F]+\.[0-9a-fA-F]+))?)*', packet) or
                              packet in (b'QStartNoAckMode', b'vCont?')):
                            pass
                        else:
                            unclassified.append(dict(role=role, protocol='RSP', tx_offset=offset,
                                command=packet[:160].decode('ascii', errors='replace')))
                else:
                    for line in tx.splitlines():
                        if not line.strip():
                            continue
                        command = json.loads(line)
                        execute, arguments = command.get('execute', ''), command.get('arguments', {})
                        row = dict(role=role, command=execute, arguments=arguments)
                        if execute == 'qom-set':
                            prop = arguments.get('property', '')
                            if arguments.get('path') == '/machine' and (
                                    prop == 'pcal-pin-levels' or prop.startswith('gpio-pin-levels-')):
                                item['external_pad_changes'] += 1
                            else:
                                unclassified.append(row)
                        elif execute in ('write-memory', 'set-memory', 'set-register', 'x-debug-write-memory'):
                            qmp_writes.append(row)
                            item['guest_write_packets'] += 1
                        elif execute in ('qmp_capabilities', 'query-status', 'query-cpus-fast',
                                         'qom-get', 'qom-list', 'query-commands', 'screendump',
                                         'pmemsave', 'memsave', 'stop', 'cont', 'quit'):
                            pass
                        else:
                            unclassified.append(dict(protocol='QMP', **row))
                item['status'] = 'complete' if not summary.get('IO_errors') else 'IO_errors'
                if summary.get('IO_errors'):
                    item['IO_errors'] = summary['IO_errors']
            except Exception as error:
                item['error'] = str(error)
                protocol_errors.append('%s %s: %s' % (role, kind, error))
            debugger.append(item)
    complete = len(debugger) == 6 and all(x['status'] == 'complete' for x in debugger) and not protocol_errors
    total_writes = len(writes) + len(qmp_writes)
    no_writes = complete and total_writes == 0 and not unclassified and all(
        item['software_breakpoints'] == 0 for item in debugger)
    assistance = dict(status='zero_guest_writes_verified' if no_writes else (
                         'assistance_observed' if total_writes else 'unknown'),
                      requested_by_profile=profile.get('guest_state_injection'),
                      complete_six_connection_capture=complete,
                      actual_guest_write_packets=total_writes if complete else None,
                      observed_guest_write_packets=total_writes,
                      RSP_write_command_counts={c: sum(w['command'] == c for w in writes) for c in 'MXGP'},
                      memory_write_bytes=sum(w.get('bytes', 0) for w in writes),
                      write_ledger='debugger-writes.json', connections=debugger,
                      host_assigned_call_targets=[dict(role=role, PC=pc, register_assignments=count,
                          evidence_scope='G packet assigns PC and return sentinel; completion is evaluated separately')
                          for (role, pc), count in sorted(assigned_targets.items())],
                      unclassified_mutations=unclassified, parse_errors=protocol_errors,
                      scope='host RSP memory/register packets and QMP mutations; excludes guest MMIO stores')
    if profile.get('guest_state_injection') is False and not no_writes:
        errors.append('Native profile requires complete zero guest-state write evidence')
    if not complete:
        errors.append('All profiles require complete six-connection debugger evidence')
    save(envelope / 'debugger-writes.json', dict(schema='z62.debugger-writes/1', RSP=writes, QMP=qmp_writes,
                                               complete_capture=complete, unclassified=unclassified))

    from audit_battery import audit_battery
    battery, battery_errors = audit_battery(envelope, mcu, assistance, load, checked, ref)
    errors.extend(battery_errors)
    ref(Path(__file__).with_name('audit_battery.py'))

    tasks = {}
    for role in ('master', 'slave'):
        task = ex.get('stopped_task_RAM_observations', {}).get(role, {})
        roots = [r for r in task.get('roots', []) if 'scheduler' in r.get('name', '')]
        tasks[role] = dict(status='observed' if task else 'not_observed',
                           candidate_count=len(task.get('candidates', [])), scheduler_roots=roots,
                           registry=task.get('task_registry'), TCB_identity_verified=False,
                           scope='stopped RAM/task/scheduler-related observation; identity gate separate')
    task_files = []

    def compact_registry(registry):
        if not registry:
            return None
        summary = {k: registry.get(k) for k in ('base', 'count', 'stride', 'complete',
                   'slot_IDs_verified', 'allocated_count', 'state_counts', 'table_sha256')}
        summary['named_tasks'] = [dict(slot=t.get('slot'), name=t['name'], entry=t.get('entry'),
                                      saved_SP=t.get('saved_SP'), raw_state=t.get('raw_state'))
                                  for t in registry.get('tasks', []) if t.get('allocated') and t.get('name')]
        mapping = registry.get('business_mapping', {})
        summary['business_descriptors'] = mapping.get('descriptor_count')
        summary['created_business_descriptors'] = sum(t.get('created') is True
                                                     for t in mapping.get('descriptors', []))
        summary['scope'] = 'observed table geometry and slots; does not certify full RTOS/TCB identity'
        return summary

    for path in sorted(run.glob('EXPEED/engines/*/task-RAM/*.json')):
        document = load(path)
        validate_refs(document)
        role = document.get('role', path.parents[1].name)
        if role in tasks:
            tasks[role].update(status='observed', evidence=ref(path))
            tasks[role]['scheduler_roots'] = [r for r in document.get('roots', [])
                                               if 'scheduler' in r.get('name', '')]
            tasks[role]['candidate_count'] = len(document.get('candidates', []))
            if document.get('task_registry'):
                tasks[role]['registry'] = compact_registry(document['task_registry'])
        task_files.append(ref(path))
    for task in tasks.values():
        if task.get('registry') and 'tasks' in task['registry']:
            task['registry'] = compact_registry(task['registry'])

    frames, frame_errors = [], []
    from PIL import Image
    image_paths = sorted(set(run.glob('EXPEED/engines/master/LCD-timeline/*.png')) |
                         set(run.glob('EXPEED/engines/master/*display.png')) |
                         set(run.glob('EXPEED/engines/master/*disp*.png')) |
                         set(run.glob('EXPEED/engines/master/stage-frames/*.png')))
    for path in image_paths:
        try:
            with Image.open(path) as image:
                rgb = image.convert('RGB')
                pixel_sha = hashlib.sha256(rgb.tobytes()).hexdigest()
                extrema = rgb.getextrema()
                colored = rgb.getcolors(rgb.width * rgb.height)
                frames.append(dict(evidence=ref(path), size=list(rgb.size), pixel_sha256=pixel_sha,
                                   nonblack=any(maximum > 0 for minimum, maximum in extrema),
                                   uniform=all(minimum == maximum for minimum, maximum in extrema),
                                   distinct_colors=len(colored) if colored else None))
        except Exception as error:
            frame_errors.append(str(error))
    errors.extend('Invalid saved LCD image: ' + error for error in frame_errors)
    nonblack = {f['pixel_sha256'] for f in frames if f['nonblack'] and not f['uniform']}
    lcd = dict(status='nonblack_pixels_observed' if nonblack else ('black_or_uniform_only' if frames else 'not_observed'),
               frame_files=len(frames), distinct_pixel_hashes=len({f['pixel_sha256'] for f in frames}),
               distinct_nonblack_nonuniform_frames=len(nonblack), pixel_change_observed=len(nonblack) > 1,
               original_dynamic_image_payload_verified=False, frames=frames, errors=frame_errors,
               host_guest_write_gate=assistance['status'],
               scope='actual saved QEMU pixels; host write gate and profile conditions retained; '
                     'menu navigation and original image-pipeline causality require separate evidence')
    mode_frames = [f for f in frames if 'disp_mode' in f['evidence']['path']]
    lcd['display_mode_observations'] = dict(samples=len(mode_frames),
        distinct_nonblack_pixel_hashes=len({f['pixel_sha256'] for f in mode_frames if f['nonblack'] and not f['uniform']}),
        all_modes_distinct_verified=False, frames=mode_frames)
    first_mode = next((f for f in mode_frames if 'disp_mode0' in f['evidence']['path']), None)
    return_mode = next((f for f in mode_frames if 'disp_mode5' in f['evidence']['path']), None)
    lcd['display_mode_observations']['cycle_return_pixel_match_observed'] = (
        first_mode['pixel_sha256'] == return_mode['pixel_sha256']
        if first_mode and return_mode else None)
    first_five = [f for f in mode_frames if any('disp_mode%d' % index in f['evidence']['path']
                                               for index in range(5))]
    lcd['display_mode_observations']['five_distinct_samples_and_return_observed'] = (
        len(first_five) == 5 and all(f['nonblack'] and not f['uniform'] for f in first_five) and
        len({f['pixel_sha256'] for f in first_five}) == 5 and
        lcd['display_mode_observations']['cycle_return_pixel_match_observed'] is True)
    lcd['display_mode_observations']['mode_semantics_verified'] = False

    counters, counter_evidence, boundaries = {}, [], {}
    for role, (endpoint, directory) in endpoints.items():
        boundaries[role] = dict(first_unmodeled=endpoint.get('first_unmodeled'),
                               first_hardware_boundary=endpoint.get('first_hardware_boundary',
                                                                      endpoint.get('first_hardware_boundary_line')))
        log = directory / 'qemu.log'
        if log.exists():
            found = {}
            with log.open(errors='replace') as stream:
                for line in stream:
                    for key in COUNTERS:
                        match = re.search(r'\b' + key + r'=(\d+)\b', line)
                        if match:
                            found[key] = int(match[1])
            if found:
                counters[role] = found
                counter_evidence.append(ref(log))
    receiver = []
    for path in sorted((run / 'HDMI-receiver').rglob('*.json')) if (run / 'HDMI-receiver').exists() else []:
        value = load(path)
        receiver.append(dict(evidence=ref(path), state=value))
    payloads = [ref(p) for p in sorted((run / 'HDMI-receiver').rglob('*'))
                if p.is_file() and p.suffix in ('.raw', '.bin', '.ppm', '.png') and p.stat().st_size > 0]
    image_pipeline = dict(status='observations_only', counters=counters, counter_evidence=counter_evidence,
                          HDMI_receiver_records=receiver, HDMI_nonempty_payloads=payloads,
                          source='explicit synthetic Bayer/peripheral conditions; see locked profile',
                          firmware_capture_buffers_verified=False, original_RAW_ISP_output_verified=False,
                          original_video_DMA_verified=False)

    gate_specs = [
        ('physical_flash_natural_boot', '原始物理 Flash 与完整自然上电',
         'EXPEED 当前从原厂更新镜像应用入口加载；Flash 为记录材料重建输入，Boot ROM 和物理容器未验收。'),
        ('scheduler_identity', '双引擎 RTOS / TCB 调度身份',
         '报告保留原厂入口、任务 RAM 和调度根观察；完整调度身份与时间因果链仍需独立证据。'),
        ('cross_engine_causality', 'MCU / 双 EXPEED 请求—DMA—ACK—响应因果链',
         '总线计数是观察值；三个端点虚拟时钟独立，未具备完整带内容事务见证。'),
        ('stable_menu', 'MENU 显示、导航、退出、重入',
         '需要原厂输入处理与菜单像素变化、退出重入及资源生命周期对应证据；辅助函数调用不计入。'),
        ('live_view', '原厂 Live View 图像与持续更新',
         '需要原厂提交图像缓冲和连续变化 payload；非黑画面与 OSD 重放不足以通过。'),
        ('photo_capture_storage', '拍照、RAW / ISP 与存储',
         '需要原厂 capture buffer、RAW/ISP 输出、有效照片文件和快门输入的对应证据。'),
        ('movie_recording', '视频模式与录像输出',
         '需要原厂模式切换、开始/停止录像与非空有效媒体；标签和 mode 值不足以通过。'),
        ('hdmi_output', '原厂 HDMI 输出',
         '需要原厂视频 DMA 与接收端非空、变化的原始图像 payload；接收器初始化不是视频输出。'),
    ]
    gates = {key: dict(label=label, status='not_verified', reason=reason)
             for key, label, reason in gate_specs}
    scenario_path = run / 'native-gpio-scenario-result.json'
    scenario = load(scenario_path, required=True)
    validate_refs(scenario)
    for key in ('error', 'failure'):
        if scenario.get(key):
            errors.append('External scenario: ' + str(scenario[key]))
    delivery_key = 'complete' if profile.get('guest_state_injection') is False else 'successful_input_delivery'
    delivery_complete = bool(scenario.get('finished') and scenario.get(delivery_key) is True and
                             not scenario.get('error') and not scenario.get('failure'))
    if not delivery_complete:
        errors.append('Declared input scenario did not finish its selected budget/stages')
    pad_ack_events = [e for e in scenario.get('events', [])
                      if ('ack' in e.get('kind', '').lower() or e.get('acknowledgement') or e.get('ACK'))]
    stage_records = []
    for path in sorted(run.glob('*ready.json')):
        document = load(path)
        stage_records.append(dict(stage=path.stem, evidence=ref(path),
            observed_fields={k: v for k, v in document.items() if isinstance(v, (bool, int, float)) or k.endswith('_pc')},
            interpretation='assisted milestone; does not establish native function acceptance'))
    for endpoint, directory in endpoints.values():
        for key, value in endpoint.items():
            if key.startswith('smart_') and isinstance(value, (dict, bool, int, float)):
                if isinstance(value, dict):
                    value = {k: v for k, v in value.items() if isinstance(v, (bool, int, float)) or k in ('pc', 'batch_pc')}
                stage_records.append(dict(stage=directory.name + ':' + key, observation=value))
    registry_count = {role: (value.get('registry') or {}).get('allocated_count') for role, value in tasks.items()}
    capabilities = {
        'original_battery_protocol': dict(status=battery['status'],
            raw_cmd89_exchanges=len(battery['wire_cmd89_exchanges']),
            original_cmd89_accepted_counts=battery.get('original_cmd89_accepted_counts', {}),
            configuration_timing_status=battery.get('configuration_timing', {}).get('status', 'not_observed'),
            original_authentication_acceptance_observed=battery['original_authentication_acceptance_observed'],
            physical_authentication_verified=False),
        'three_QEMU_processes': dict(status=lifecycle['status'], actual_exit_zero=lifecycle['exit_zero']),
        'original_entries': dict(status='observed' if all(e['status'] == 'observed' for e in entries.values()) else 'not_observed',
                                  roles={role: e['status'] for role, e in entries.items()}),
        'task_registry': dict(status='observed' if all(isinstance(n, int) and n > 0 for n in registry_count.values()) else 'not_observed',
                             allocated_slots=registry_count, certified_RTOS_identity=False),
        'scheduler_related_RAM': dict(status='observed' if all(t['scheduler_roots'] for t in tasks.values()) else 'not_observed',
                                     scope='stopped snapshots; zero current/next words remain zero'),
        'external_pad_delivery': dict(status='observed' if pad_ack_events else 'not_observed',
                                     acknowledged_events=len(pad_ack_events),
                                     QMP_pad_changes=sum(c['external_pad_changes'] for c in debugger),
                                     physical_button_names_verified=False),
        'declared_scenario_delivery': dict(status='delivered' if delivery_complete else 'incomplete',
                                          declared_schedule_events=len(scenario.get('schedule', [])),
                                          selected_schedule_events=sum(e.get('within_budget') is True
                                                                       for e in scenario.get('schedule', [])),
                                          saved_events=len(scenario.get('events', [])),
                                          scope='input delivery and assisted stage bookkeeping; camera functions separate'),
        'assisted_execution': dict(status='observed' if total_writes or assigned_targets else 'not_observed',
                                  host_write_packets=total_writes, assigned_call_targets=len(assigned_targets),
                                  milestone_records=len(stage_records), original_code_completion_verified=False),
        'LCD_pixels': dict(status=lcd['status'], saved_frames=lcd['frame_files'],
                           distinct_nonblack_nonuniform_frames=len(nonblack),
                           assisted=bool(total_writes) if complete else None,
                           host_guest_write_gate=assistance['status']),
        'capture_RAW_ISP': dict(status='counters_observed' if counters else 'unknown', counters=counters,
                               original_pipeline_verified=False),
        'HDMI_payload': dict(status='nonempty_files_observed' if payloads else 'not_observed',
                             nonempty_files=len(payloads), original_video_DMA_verified=False),
    }
    runtime_ok = (preflight.get('passed') is True and launcher.get('coordinator_exit') == 0 and
                  launcher.get('scenario_exit') == 0 and not launcher.get('error') and
                  lifecycle['status'] == 'verified' and lifecycle['exit_zero'] and not errors)
    report = dict(schema='z62.progress-acceptance/1', audited=now(), run=envelope.name,
                  auditor=identity(Path(__file__)),
                  profile=profile.get('name'), profile_kind=profile.get('kind'),
                  audit_completed=bool(locked and launcher.get('finished') and raw and public),
                  package_runtime_status='verified' if runtime_ok else 'failed_or_unknown',
                  lifecycle=lifecycle, original_entry_observations=entries,
                  debugger_assistance=assistance, tasks_and_scheduler=tasks, LCD=lcd,
                  battery=battery,
                  engineering_capabilities=capabilities, assisted_milestones=stage_records,
                  imaging=image_pipeline, bus_counters=public.get('MCU_bus_counters', {}),
                  external_input_scenario=scenario, first_observed_boundaries=boundaries,
                  full_camera_status='not_verified', functional_gates=gates,
                  conditions=dict(application_entry_direct_load=profile.get('application_entry_direct_load'),
                                  physical_flash_dump=profile.get('physical_flash_dump'),
                                  guest_state_injection_requested=profile.get('guest_state_injection'),
                                  synthetic_inputs=profile.get('synthetic_inputs', []),
                                  independent_virtual_clocks=True, camera_access=False),
                  errors=list(dict.fromkeys(errors)), notes=notes, evidence=list(sources.values()))
    save(envelope / 'acceptance.json', report)
    rows = ['# Z6II QEMU 本次运行验收', '',
            '- 运行：`%s`；profile：`%s`。' % (envelope.name, profile.get('name')),
            '- 独立目录运行：**%s**；三进程生命周期：**%s**。' % (report['package_runtime_status'], lifecycle['status']),
            '- 整机功能验收：**not_verified**。各项功能的具体观察与证据缺口见下表。', '',
            '## 观察事实', '', '| 角色 | QEMU PID | 启动 | 实际退出码 | 原厂入口 |',
            '|---|---:|---|---:|---|']
    for role in ROLES:
        item = records[role]
        rows.append('| %s | %s | %s | %s | %s |' % (role, item['pid'], item['launch'],
                                                     item['exit_code'], entries[role]['status']))
    packet_count = str(total_writes) if complete else '未知（记录不完整；已观察 %d）' % total_writes
    rows += ['', 'Debugger：`%s`；RAM／寄存器写包 **%s**；完整六连接记录 `%s`。' % (
        assistance['status'], packet_count, complete),
        '详细写入记录：[debugger-writes.json](debugger-writes.json)。外部 GPIO / PCAL pads 变化单独记录。', '',
        'LCD：`%s`；保存 %d 个帧文件，%d 个像素 hash，%d 个非黑且非纯色的不同帧。' % (
            lcd['status'], lcd['frame_files'], lcd['distinct_pixel_hashes'], len(nonblack)),
        '画面对应的 Host 状态写入检查：`%s`；稳定 MENU 导航及原厂图像链路另行验收。' % assistance['status'],
        'DISP 档位：%d 个命名样本，%d 个非黑像素 hash；名称不构成模式验收。' % (
            len(mode_frames), lcd['display_mode_observations']['distinct_nonblack_pixel_hashes']), '',
        '图像链路计数（未记录字段保持未知）：`%s`。' % json.dumps(counters, ensure_ascii=False),
        'HDMI 非空 payload 文件：%d。' % len(payloads), '', '## 功能验收与未知', '',
        '| 功能 | 状态 | 判定依据 / 缺口 |', '|---|---|---|']
    for gate in gates.values():
        rows.append('| %s | %s | %s |' % (gate['label'], gate['status'], gate['reason']))
    rows += ['', '## 已观察的工程能力', '',
             '| 能力 | 状态 | 本次事实 |', '|---|---|---|']
    for key, value in capabilities.items():
        detail = json.dumps({k: v for k, v in value.items() if k != 'status'}, ensure_ascii=False)
        rows.append('| %s | %s | %s |' % (key, value['status'], detail.replace('|', '\\|')))
    if battery.get('wire'):
        rows += ['', '## 原厂电池协议与返回', '',
                 '状态：`%s`。实际 UART TX %d 帧；原厂认证比较与 ready store：`%s`。'
                 '电池应答使用明确声明的合成输入；物理电池认证及整机上电继续单独验收。' % (
                     battery['status'], battery['wire']['complete_TX_frames'],
                     battery['original_authentication_acceptance_observed']), '',
                 '| 原厂 caller | 完整 TX18 | RX4 | 实际 R0 | 配置重建 |',
                 '|---|---|---|---:|---|']
        for row in battery['original_cmd89_returns']:
            rows.append('| %s | %s | %s | %s | %s |' % (row['entry'], row['TX_hex'],
                         row['RX_hex'], row['returned_R0'], row['config_reconstruction_match']))
        comparison = battery.get('physical_camera_comparison', {})
        configuration = battery.get('configuration_timing', {})
        if configuration.get('timeline'):
            rows += ['', '### 原厂配置与报文时序', '',
                     '配置链审计：`%s`。Flash 参数输入、转换结果与复制返回按真实 SP / LR 配对；'
                     '停止时的 RAM 不替代 caller 时刻的配置。' % configuration['status'], '',
                     '| 观察序号 | 原厂阶段 | PC | HAL tick | Host 秒 | 配置 / 报文 |',
                     '|---:|---|---|---:|---:|---|']
            for event in configuration['timeline']:
                detail = event.get('TX_hex') or event.get('info72_sha256', '')[:16]
                if event.get('group4_address'):
                    detail = '%s, R1=%s, 初始 Flash 相同=%s' % (
                        event['group4_address'], event['correction_R1'], event['group4_matches_initial_firmware_data'])
                rows.append('| %s | %s | %s | %s | %s | %s |' % (
                    event['observation_sequence'], event['phase'], event['entry'], event['HAL_tick'],
                    event['host_elapsed_seconds'], detail))
        if comparison:
            rows += ['', '辅助字段：真机记录 `%s`；本次模拟结束快照 `%s`。二者分别追踪；'
                     '顺序诊断读、停止快照及 caller 时间点各自保留证据范围。' % (
                         ' / '.join(comparison.get('auxiliary2', [])),
                         battery.get('final_stopped_MCU', {}).get('auxiliary2_hex', 'unknown'))]
    rows += ['', '## 推断与范围', '',
             '本报告以本次锁定 binary、ROM、命令和保留证据为依据。原厂应用入口与任务/调度 RAM 的观察'
             '支持执行深度判断；更新镜像入口加载、条件模型与辅助状态写入各自保持明确范围。', '',
             '完整机器证据与 SHA 索引：[acceptance.json](acceptance.json)。']
    if errors:
        rows += ['', '## 运行或证据错误', ''] + ['- ' + error for error in report['errors']]
    previews = [f for f in frames if f['nonblack'] and not f['uniform']][:3]
    if previews:
        rows += ['', '## 本次画面', '']
        for frame in previews:
            path = frame['evidence']['path']
            rows += ['![QEMU 保存画面](%s)' % path, '']
    (envelope / 'acceptance.md').write_text('\n'.join(rows) + '\n')
    return report


def native_wire_packets(data, direction):
    """Account for every wire byte; decode escapes and RSP run-length replies."""
    packets, interrupts, offset = [], [], 0
    while offset < len(data):
        if data[offset] in (43, 45):
            offset += 1
            continue
        if data[offset] == 3 and direction == 'tx':
            interrupts.append(offset)
            offset += 1
            continue
        if data[offset] != 36:
            raise ValueError('Unframed RSP %s byte at %d' % (direction, offset))
        start = offset
        end = data.find(b'#', start + 1)
        if end < 0 or end + 3 > len(data):
            raise ValueError('Incomplete RSP packet at %d' % start)
        raw = data[start + 1:end]
        if (sum(raw) & 255) != int(data[end + 1:end + 3], 16):
            raise ValueError('RSP checksum mismatch at %d' % start)
        decoded, index = bytearray(), 0
        while index < len(raw):
            value = raw[index]
            if value == 125:
                index += 1
                if index >= len(raw):
                    raise ValueError('Incomplete RSP escape')
                decoded.append(raw[index] ^ 32)
            elif value == 42:
                index += 1
                if not decoded or index >= len(raw) or raw[index] < 29:
                    raise ValueError('Invalid RSP run length')
                decoded.extend(bytes([decoded[-1]]) * (raw[index] - 29))
            else:
                decoded.append(value)
            index += 1
        packets.append(dict(offset=start, end_offset=end + 3, payload=bytes(decoded).decode('ascii')))
        offset = end + 3
    return packets, interrupts


def native_byte_capture(run, protocol, summary, checked, ref):
    """Verify closed API capture, contiguous offsets, send attempts and totals."""
    if (summary.get('schema') != 'z6ii-debugger-api-byte-ledger/1' or
            summary.get('connection') != protocol or summary.get('closed') is not True or
            summary.get('complete_successful_IO_capture') is not True or summary.get('IO_errors')):
        raise ValueError(protocol + ' capture is missing, open, or has IO errors')
    streams = {}
    for direction in ('tx', 'rx'):
        item = summary['streams'][direction]
        p = checked(item)
        if p.resolve() != (run / (protocol + '-' + direction + '.bin')).resolve():
            raise ValueError('Debugger stream belongs to another connection')
        streams[direction] = p.read_bytes()
        if not streams[direction]:
            raise ValueError(protocol + ' ' + direction + ' is empty')
    p = run / (protocol + '-io.jsonl')
    if summary.get('IO_ledger'):
        if checked(summary['IO_ledger']).resolve() != p.resolve():
            raise ValueError('Debugger IO ledger belongs to another connection')
    evidence = ref(p)
    events = [json.loads(s) for s in p.read_text().splitlines()]
    totals, pending, last_ns, chunks = dict(tx=0, rx=0), None, -1, dict(tx=[], rx=[])
    for index, row in enumerate(events):
        ns = row.get('host_monotonic_ns')
        if type(ns) is not int or ns < last_ns:
            raise ValueError('Debugger IO timestamps are not ordered')
        last_ns = ns
        event = row.get('event')
        if event in ('sendall_attempt', 'file_write_attempt'):
            if pending is not None or type(row.get('requested_bytes')) is not int:
                raise ValueError('Incomplete or overlapping debugger send attempt')
            pending = row['requested_bytes']
        elif event == 'bytes':
            direction, size = row.get('direction'), row.get('bytes')
            if direction not in totals or type(size) is not int or size < 0 or row.get('offset') != totals[direction]:
                raise ValueError('Debugger stream offsets/lengths are not contiguous')
            if direction == 'tx':
                if pending != size:
                    raise ValueError('Debugger transmitted bytes differ from send attempt')
                pending = None
            chunks[direction].append(row)
            totals[direction] += size
        elif event == 'ledger_closed':
            if index != len(events) - 1 or pending is not None or row.get('errors') or row.get('stream_bytes') != totals:
                raise ValueError('Debugger ledger has an invalid close record')
        else:
            raise ValueError('Unknown or failed debugger IO event: ' + str(event))
    if not events or events[-1].get('event') != 'ledger_closed' or totals != {k: len(v) for k, v in streams.items()}:
        raise ValueError('Debugger IO totals do not match retained streams')
    ends = {direction: [row['offset'] + row['bytes'] for row in rows]
            for direction, rows in chunks.items()}
    def timestamp(direction, end):
        index = bisect_left(ends[direction], end)
        if index < len(chunks[direction]):
            row = chunks[direction][index]
            if row['offset'] < end <= row['offset'] + row['bytes']:
                return row['host_monotonic_ns']
        raise ValueError('Protocol bytes have no actual IO event')
    return streams, timestamp, evidence


def native_protocol_audit(run, raw, checked, ref):
    """Re-read the two actual connections, with explicit CPU and stop ownership."""
    import sys
    from z62_common import HARNESS
    sys.path.insert(0, str(HARNESS))
    from native_unified_probe import CPU_ROLES, resolve_thread_identity
    issues, observation_errors, connections, writes, unknown = [], [], [], [], []
    rsp, qmp, memories, registers, controls, xml, mapping = [], [], [], [], [], {}, {}
    captures = {}
    for name in ('RSP', 'QMP'):
        item = dict(protocol=name, role='unified', status='unknown', guest_write_packets=0,
                    software_breakpoints=0, external_pad_changes=0)
        try:
            streams, timestamp, evidence = native_byte_capture(
                run, name, raw.get('debugger_zero_guest_writes', {}).get(name, {}), checked, ref)
            captures[name] = (streams, timestamp)
            item.update(status='complete', IO_ledger=evidence)
        except Exception as error:
            issues.append(name + ': ' + str(error))
            item['error'] = str(error)
        connections.append(item)
    try:
        streams, timestamp = captures['QMP']
        def objects(direction):
            rows, offset = [], 0
            for line in streams[direction].splitlines(keepends=True):
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError('QMP object is not a dictionary')
                end = offset + len(line)
                rows.append(dict(value=value, offset=offset, end_offset=end,
                                 host_ns=timestamp(direction, end)))
                offset = end
            return rows
        tx, rx = objects('tx'), objects('rx')
        if not rx or 'QMP' not in rx[0]['value']:
            raise ValueError('Actual QMP greeting is missing')
        replies = [r for r in rx if 'return' in r['value'] or 'error' in r['value']]
        if len(replies) + 1 == len(tx) and tx[-1]['value'].get('execute') == 'quit':
            shutdown = [r for r in rx if r['value'].get('event') == 'SHUTDOWN' and
                        r['value'].get('data') == {'guest': False, 'reason': 'host-qmp-quit'}]
            if shutdown:
                replies.append(shutdown[-1])
        if len(tx) != len(replies):
            raise ValueError('QMP commands and actual responses are incomplete')
        for index, (command, response) in enumerate(zip(tx, replies)):
            if response['host_ns'] < command['host_ns'] or (index + 1 < len(tx) and response['host_ns'] > tx[index+1]['host_ns']):
                raise ValueError('QMP serial command/response causality mismatch')
            qmp.append(dict(command=command['value'], response=response['value'],
                            tx_offset=command['offset'], tx_end=command['end_offset'],
                            rx_end=response['end_offset'], host_ns=command['host_ns'], reply_host_ns=response['host_ns']))
        streams, timestamp = captures['RSP']
        tx, interrupts = native_wire_packets(streams['tx'], 'tx')
        rx, unused = native_wire_packets(streams['rx'], 'rx')
        if len(tx) != len(rx):
            raise ValueError('RSP command/reply packet capture is incomplete')
        for index, (command, response) in enumerate(zip(tx, rx)):
            sent, received = timestamp('tx', command['end_offset']), timestamp('rx', response['end_offset'])
            if received < sent or (index + 1 < len(tx) and received > timestamp('tx', tx[index+1]['end_offset'])):
                raise ValueError('RSP command/reply causality mismatch')
            rsp.append(dict(payload=command['payload'], reply=response['payload'],
                            tx_offset=command['offset'], tx_end=command['end_offset'],
                            rx_end=response['end_offset'], host_ns=sent, reply_host_ns=received))
        cpus = next(e['response']['return'] for e in qmp if e['command']['execute'] == 'query-cpus-fast')
        state_reply = next(e['response']['return'] for e in qmp if e['command']['execute'] == 'qom-get'
                          and e['command'].get('arguments') == {'path': '/machine', 'property': 'architecture-state'})
        state = json.loads(state_reply) if isinstance(state_reply, str) else state_reply
        clusters = []
        for e in qmp:
            args = e['command'].get('arguments', {})
            if e['command']['execute'] == 'qom-get' and args.get('property') == 'cluster-id':
                cid = e['response']['return']
                if type(cid) is not int or cid < 0:
                    raise ValueError('Invalid actual CPUCluster id')
                clusters.append(dict(path=args['path'], cluster_id=cid, gdb_pid=cid+1))
        for e in rsp:
            if e['payload'].startswith('qThreadExtraInfo,'):
                tid = e['payload'].split(',', 1)[1]
                detail = resolve_thread_identity(tid, bytes.fromhex(e['reply']).decode('ascii'), cpus, clusters, state['cpus'])
                if tid in mapping or detail['global_cpu'] in {v['global_cpu'] for v in mapping.values()}:
                    raise ValueError('Duplicate actual debugger CPU identity')
                mapping[tid] = detail
        discovered = [tid for e in rsp if e['payload'] in ('qfThreadInfo', 'qsThreadInfo')
                      and e['reply'].startswith('m') for tid in e['reply'][1:].split(',')]
        if set(discovered) != set(mapping) or len(mapping) != 5 or {v['global_cpu'] for v in mapping.values()} != set(CPU_ROLES):
            raise ValueError('Actual five-thread enumeration is incomplete')
        selected, physical, epoch, previous = None, False, 0, None
        for e in rsp:
            payload, reply = e['payload'], e['reply']
            mutation = payload.startswith(('M', 'X', 'G', 'P', 'Z0', 'z0', 'vFlash', 'qRcmd'))
            safe = (payload.startswith(('qSupported:', 'qXfer:features:read:', 'qThreadExtraInfo,', 'Hg')) or
                    payload in ('qfThreadInfo', 'qsThreadInfo', '?', 'vCont?', 'Hc-1', 'vCont;c',
                                'Qqemu.PhyMemMode:0', 'Qqemu.PhyMemMode:1') or
                    re.fullmatch(r'(?:p[0-9a-f]+|m[0-9a-f]+,[0-9a-f]+|[Zz]1,[0-9a-f]+,[24]|vAttach;[0-9a-f]+|vCont;s:p[0-9a-f]+\.[0-9a-f]+)', payload))
            if mutation:
                writes.append(dict(protocol='RSP', offset=e['tx_offset'], payload=payload))
            elif not safe:
                unknown.append(dict(protocol='RSP', offset=e['tx_offset'], payload=payload))
            if payload.startswith('Hg'):
                selected = payload[2:]
                if selected not in mapping or reply != 'OK':
                    raise ValueError('Failed or unknown actual CPU selection')
            if payload.startswith(('p', 'm', 'qXfer:features:read:')):
                if selected not in mapping or previous != 'Hg' + selected:
                    raise ValueError('Every register/memory/XML read must explicitly select its actual CPU')
                cpu = mapping[selected]['global_cpu']
                if payload.startswith('m'):
                    address, length = (int(v, 16) for v in payload[1:].split(','))
                    data = bytes.fromhex(reply)
                    if len(data) != length:
                        raise ValueError('Incomplete actual GDB memory read')
                    memories.append(dict(global_cpu=cpu, address=address, data=data,
                                         address_kind='PA' if physical else 'VA', stop_epoch=epoch))
                elif payload.startswith('p'):
                    if not reply or reply.startswith('E') or set(reply) <= {'x'}:
                        raise ValueError('Unavailable actual register read')
                    data = bytes.fromhex(reply)
                    registers.append(dict(global_cpu=cpu, number=int(payload[1:], 16),
                                          value=int.from_bytes(data, 'little'), bits=len(data)*8, stop_epoch=epoch))
                else:
                    name, window = payload[len('qXfer:features:read:'):].rsplit(':', 1)
                    offset = int(window.split(',')[0], 16)
                    key = (cpu, name)
                    value = xml.setdefault(key, '')
                    if not reply.startswith(('m', 'l')) or len(value.encode()) != offset:
                        raise ValueError('Incomplete actual target XML enumeration')
                    xml[key] += reply[1:]
            if payload.startswith('Qqemu.PhyMemMode:'):
                wanted = payload.endswith(':1')
                if selected not in mapping or reply != 'OK' or wanted == physical:
                    raise ValueError('Invalid CPU-aware PA mode transition')
                physical = wanted
            if payload == 'vCont;c' or payload.startswith('vCont;s:'):
                if physical or (payload == 'vCont;c' and previous != 'Hc-1'):
                    raise ValueError('Execution must restore VA mode and continue the whole VM once')
                if payload.startswith('vCont;s:') and payload.split(':', 1)[1] != selected:
                    raise ValueError('Original step has incorrect CPU ownership')
                controls.append(dict(host_ns=e['host_ns'], running=True, epoch=epoch))
                if not reply.startswith(('T', 'S')):
                    raise ValueError('Original execution lacks its actual stop reply')
                epoch += 1
                controls.append(dict(host_ns=e['reply_host_ns'], running=False, epoch=epoch))
            elif payload == '?':
                if not reply.startswith(('T', 'S')):
                    raise ValueError('Initial stopped state is missing')
                epoch += 1
                controls.append(dict(host_ns=e['reply_host_ns'], running=False, epoch=epoch))
            previous = payload
        if physical:
            raise ValueError('Debugger PA mode was not restored to VA mode')
        def execution_state(ns):
            rows = [e for e in controls if e['host_ns'] <= ns]
            return (rows[-1]['running'], rows[-1]['epoch']) if rows else (False, 0)
        for offset in interrupts:
            if not execution_state(timestamp('tx', offset+1))[0]:
                raise ValueError('Redundant global interrupt while already stopped')
        last_status = None
        for e in qmp:
            name, args = e['command'].get('execute'), e['command'].get('arguments', {})
            running, current_epoch = execution_state(e['host_ns'])
            e.update(running=running, stop_epoch=current_epoch)
            if name == 'query-status' and 'return' in e['response']:
                last_status = e
                actual_running = e['response']['return'].get('running')
                if type(actual_running) is not bool:
                    raise ValueError('Actual QMP running state is absent')
                if actual_running is True and not running:
                    raise ValueError('QMP running state lacks an actual global continue')
                # A hardware breakpoint can stop the VM before the owner has
                # consumed the already queued RSP stop reply. QMP reports the
                # actual state; the RSP receive timestamp is an upper bound.
                if actual_running is False and running and not any(
                        not c['running'] and c['host_ns'] >= e['host_ns'] and c['epoch'] == current_epoch + 1
                        for c in controls):
                    raise ValueError('QMP stop lacks its corresponding actual RSP stop')
            elif name == 'memsave':
                if 'error' in e['response']:
                    observation_errors.append('Actual memsave failed: ' + str(e['response']['error']))
                    continue
                if (running or args.get('cpu-index') not in CPU_ROLES or type(args.get('cpu-index')) is not int or
                    set(args) != {'cpu-index', 'val', 'size', 'filename'} or type(args['val']) is not int or
                    type(args['size']) is not int or args['size'] <= 0 or last_status is None or
                    last_status['response']['return'].get('running') is not False):
                    raise ValueError('memsave requires completed common stop and explicit CPU-selected VA')
            elif name == 'qom-set':
                prop = args.get('property', '')
                if (set(args) != {'path', 'property', 'value'} or args['path'] != '/machine' or
                    not (prop == 'pcal-pin-levels' or re.fullmatch(r'gpio-pin-levels-[A-H]', prop)) or
                    type(args['value']) is not int or args['value'] < 0):
                    writes.append(dict(protocol='QMP', offset=e['tx_offset'], command=e['command']))
                else:
                    connections[1]['external_pad_changes'] += 1
            elif name not in ('qmp_capabilities', 'query-status', 'query-uuid', 'query-cpus-fast',
                              'qom-get', 'qom-list', 'screendump', 'quit'):
                unknown.append(dict(protocol='QMP', offset=e['tx_offset'], command=e['command']))
        if writes or unknown:
            issues.append('Native debugger mutation or unclassified command observed')
    except Exception as error:
        issues.append('Native protocol: ' + str(error))
    complete = len(captures) == 2 and not issues
    assistance = dict(status='zero_guest_writes_verified' if complete and not writes and not unknown else 'unknown',
        requested_by_profile=False, expected_connection_count=2, actual_connection_count=len(captures),
        complete_expected_connection_capture=complete,
        actual_guest_write_packets=len(writes) if complete else None, observed_guest_write_packets=len(writes),
        memory_write_bytes=0 if complete else None, RSP_write_command_counts={c: sum(
            e.get('payload', '').startswith(c) for e in writes if e['protocol'] == 'RSP') for c in 'MXGP'},
        write_ledger='debugger-writes.json', connections=connections, host_assigned_call_targets=[],
        unclassified_mutations=unknown, parse_errors=issues,
        scope='two actual API byte captures; explicit Hg CPU reads, restored PA mode and common execution control; guest MMIO stores separate')
    return dict(assistance=assistance, RSP=rsp, QMP=qmp, memory_reads=memories, register_reads=registers,
                XML=xml, mapping=mapping, controls=controls, writes=writes, unknown=unknown,
                errors=issues, observation_errors=observation_errors)


def native_read_bindings(protocol, raw):
    """Bind retained observations to actual CPU-selected wire replies."""
    import xml.etree.ElementTree as ET
    issues, reads, position, maps = [], [], 0, {}
    chunks = protocol['memory_reads']
    inverse = {v['global_cpu']: tid for tid, v in protocol['mapping'].items()}
    for record in raw.get('debugger_read_records', []):
        try:
            cpu, start, size = record['global_cpu'], int(record['address'], 16), record['bytes']
            if (type(cpu) is not int or cpu not in inverse or type(size) is not int or size <= 0 or
                    record['thread'] != inverse[cpu] or
                    record['role'] != ('master' if cpu < 2 else 'slave' if cpu < 4 else 'MCU')):
                raise ValueError('incorrect CPU, role, thread or read length')
            data = bytearray()
            while len(data) < size:
                chunk = chunks[position]
                if (chunk['global_cpu'] != cpu or chunk['address'] != start + len(data) or
                        chunk['address_kind'] != record['address_kind'] or
                        chunk['stop_epoch'] != record['stop_epoch'] or
                        len(data) + len(chunk['data']) > size):
                    raise ValueError('wire memory chunks differ from their retained read')
                data.extend(chunk['data'])
                position += 1
            if hashlib.sha256(data).hexdigest() != record['sha256']:
                raise ValueError('wire memory SHA differs from retained observation')
            reads.append(dict(record, start=start, data=bytes(data)))
        except (KeyError, IndexError, TypeError, ValueError) as error:
            issues.append('CPU-selected memory binding: ' + str(error))
            break
    if position != len(chunks):
        issues.append('Unassociated actual memory replies: %d' % (len(chunks) - position))
    for cpu in inverse:
        mapping, seen, next_number = {}, set(), 0
        def visit(name):
            nonlocal next_number
            if name in seen:
                return
            seen.add(name)
            value = protocol['XML'][(cpu, name)]
            if 'xi:include' in value and 'xmlns:xi' not in value:
                value = re.sub(r'<target(?=[\s>])',
                               '<target xmlns:xi="http://www.w3.org/2001/XInclude"', value, count=1)
            for element in ET.fromstring(value).iter():
                tag = element.tag.rsplit('}', 1)[-1]
                if tag == 'include':
                    visit(element.attrib['href'])
                elif tag == 'reg':
                    number = int(element.get('regnum', str(next_number)), 0)
                    bits = int(element.attrib['bitsize'])
                    mapping[element.attrib['name']] = (number, bits)
                    next_number = number + 1
        try:
            visit('target.xml')
            maps[cpu] = mapping
        except (KeyError, TypeError, ValueError, ET.ParseError) as error:
            issues.append('Actual target XML CPU%d: %s' % (cpu, error))
    register_values = {}
    for row in protocol['register_reads']:
        key = row['global_cpu'], row['stop_epoch'], row['number'], row['bits']
        register_values.setdefault(key, set()).add(row['value'])

    def memory(cpu, epoch, address, size, kind='VA'):
        matches = [r['data'][address-r['start']:address-r['start']+size] for r in reads
                   if r['global_cpu'] == cpu and r['stop_epoch'] == epoch and r['address_kind'] == kind
                   and r['start'] <= address and address + size <= r['start'] + r['bytes']]
        if not matches or any(value != matches[0] for value in matches):
            raise ValueError('No consistent actual CPU%d %s read at epoch %s, 0x%x/%d' %
                             (cpu, kind, epoch, address, size))
        return matches[0]

    def registers(cpu, epoch, values):
        aliases = {'sp': 'r13', 'lr': 'r14', 'pc': 'r15', 'xpsr': 'cpsr'}
        mapping = {aliases.get(name, name): desc for name, desc in maps.get(cpu, {}).items()}
        if not isinstance(values, dict) or not all('r%d' % i in values for i in range(16)):
            raise ValueError('Incomplete actual core register observation')
        for name, value in values.items():
            number, bits = mapping[name]
            if register_values.get((cpu, epoch, number, bits)) != {int(value, 16)}:
                raise ValueError('CPU%d register %s does not match XML/p replies at epoch %s' %
                                 (cpu, name, epoch))
        return True
    return dict(errors=issues, reads=reads, memory=memory, registers=registers,
                actual_memory_read_count=len(reads), actual_register_read_count=len(protocol['register_reads']))


def native_architecture_binding(raw, protocol, clock_rows, errors):
    """Recompute QOM gates only after matching actual QMP replies and epochs."""
    import copy
    from native_unified_probe import evaluate_architecture
    arch = copy.deepcopy(raw.get('architecture', {}))
    qmp = protocol['QMP']
    by_tx = {e['tx_end']: e for e in qmp}
    binding_errors = []
    def need(condition, text):
        if not condition:
            binding_errors.append(text)
        return bool(condition)
    def bound(row, prop):
        try:
            actual = by_tx[row['QMP_tx_bytes_after']]
            return (actual['command'] == {'execute': 'qom-get',
                    'arguments': {'path': '/machine', 'property': prop}}
                    and actual['rx_end'] == row['QMP_rx_bytes_after']
                    and actual['stop_epoch'] == row['stop_epoch']
                    and actual['running'] is row['running'])
        except (KeyError, TypeError):
            return False
    snapshots = arch.get('QOM_snapshots', [])
    need(bool(snapshots), 'Missing retained QOM architecture snapshots')
    for row in snapshots:
        actual = by_tx.get(row.get('QMP_tx_bytes_after'), {})
        value = actual.get('response', {}).get('return')
        try:
            need(bound(row, 'architecture-state') and value == row.get('raw')
                 and isinstance(value, str) and json.loads(value) == row.get('state'),
                 'QOM snapshot does not bind to actual QMP reply/CPU stop epoch')
        except (TypeError, ValueError):
            need(False, 'Invalid actual QOM JSON string')
    if snapshots:
        need(arch.get('QOM') == snapshots[-1].get('state') and arch.get('QOM_raw') == snapshots[-1].get('raw'),
             'Selected architecture snapshot differs from the last retained QOM reply')
        need(arch.get('snapshot_epoch') == snapshots[-1].get('stop_epoch') and
             arch.get('snapshot_virtual_ns') == snapshots[-1].get('state', {}).get('virtual_ns'),
             'Selected architecture snapshot epoch/time differs from actual QOM')
    actual_queries = [e['response'].get('return') for e in qmp
                      if e['command'].get('execute') == 'query-cpus-fast']
    actual_uuids = [e['response'].get('return') for e in qmp
                   if e['command'].get('execute') == 'query-uuid']
    need(arch.get('query_cpus_fast') in actual_queries and arch.get('QMP_uuid') in actual_uuids,
         'CPU enumeration/UUID does not bind to actual QMP')
    actual_mapping = {v['global_cpu']: (tid, v) for tid, v in protocol['mapping'].items()}
    for row in arch.get('thread_mapping_evidence', []):
        actual = actual_mapping.get(row.get('global_cpu'))
        need(bool(actual) and all(row.get(key) == actual[1].get(key) for key in
             ('global_cpu', 'qom_path', 'thread', 'cluster', 'role', 'local_cpu', 'actual_MPIDR')),
             'Retained multiprocess thread identity differs from actual enumeration')
    need(len(actual_mapping) == 5, 'Actual CPU/thread identity binding is incomplete')
    for gic in arch.get('actual_GICs', []):
        for prop, key in (('num-cpu', 'num_cpu_QOM'), ('first-cpu-index', 'first_cpu_index_QOM')):
            need(any(e['command'] == {'execute': 'qom-get',
                    'arguments': {'path': gic.get('qom_path'), 'property': prop}}
                    and e['response'].get('return') == gic.get(key) for e in qmp),
                 'Actual per-engine GIC QOM property is unbound: ' + prop)
    clock_errors, last = [], -1
    for index, row in enumerate(clock_rows):
        actual = by_tx.get(row.get('QMP_tx_bytes_after'), {})
        value = actual.get('response', {}).get('return')
        if (not bound(row, 'virtual-time-ns') or type(value) is not int or value < 0 or
                value != row.get('virtual_ns') or row.get('sequence') != index + 1):
            clock_errors.append('Virtual clock sample lacks its actual ordered QMP reply')
        if type(value) is int:
            if value < last:
                clock_errors.append('Actual shared virtual clock moved backwards')
            last = value
    need(len(clock_rows) == arch.get('clock_observation_count') and len(clock_rows) >= 2,
         'Virtual clock ledger/count is incomplete')
    binding_errors.extend(clock_errors)
    arch['clock_observation_count'] = len(clock_rows)
    arch['virtual_clock_regressions'] = clock_errors
    for freeze in arch.get('clock_samples', []):
        matches = [r for r in clock_rows if r.get('stop_epoch') == freeze.get('stop_epoch') and r.get('running') is False
                   and r.get('virtual_ns') == freeze.get('first_ns') == freeze.get('second_ns')]
        stopped = any(e['command'].get('execute') == 'query-status'
                      and e.get('stop_epoch') == freeze.get('stop_epoch')
                      and e['response'].get('return') == freeze.get('QMP_status')
                      and e['response'].get('return', {}).get('running') is False for e in qmp)
        need(len(matches) >= 2 and stopped, 'Clock freeze lacks two actual stopped QMP clock observations')
    # Derive advancing samples from actual status replies, rather than owner booleans.
    advancing = []
    clocks_by_tx = [(by_tx.get(r.get('QMP_tx_bytes_after'), {}).get('tx_offset', -1), r) for r in clock_rows]
    for row in qmp:
        if (row['command'].get('execute') == 'query-status' and
                row['response'].get('return', {}).get('running') is True and row.get('running') is True):
            candidates = [r for offset, r in clocks_by_tx if offset < row['tx_offset']
                          and r.get('stop_epoch') == row['stop_epoch'] and r.get('running') is True]
            if candidates:
                advancing.append(dict(virtual_ns=candidates[-1]['virtual_ns'],
                    stop_epoch=row['stop_epoch'], QMP_status=row['response']['return']))
    arch['running_clock_samples'] = advancing
    try:
        arch.update(evaluate_architecture(arch, raw))
    except (KeyError, TypeError, ValueError) as error:
        binding_errors.append('Architecture evaluation: ' + str(error))
        arch['passed'] = False
    initial = raw.get('initial_architecture', {})
    if initial:
        own = next((s for s in snapshots if s.get('phase') == 'initial'), None)
        need(bool(own) and initial.get('QOM') == own.get('state')
             and initial.get('snapshot_epoch') == own.get('stop_epoch')
             and initial.get('snapshot_virtual_ns') == own.get('state', {}).get('virtual_ns'),
             'Initial architecture does not bind to its distinct pre-continue snapshot')
    else:
        need(False, 'Missing durable architecture snapshot before first continue')
    arch['QMP_reply_binding_verified'] = not binding_errors
    arch['binding_errors'] = list(dict.fromkeys(binding_errors))
    arch['passed'] = arch.get('passed') is True and not binding_errors
    arch['active_structure_regression_status'] = 'separate_report_required'
    arch['CNTVCT_measured_frequency_regression_verified'] = False
    errors.extend(arch['binding_errors'])
    return arch


def native_final_inputs(envelope, locked, raw, blobs, checked):
    """Read the exact recipes and plans frozen by the launcher before exec."""
    from native_unified_probe import recipes
    from expeed_task_observer import load_plan
    from loader_runtime_audit import load_reference

    def locked_file(value):
        expected = evidence_path(value, envelope, locked).resolve(strict=True)
        matches = [item for item in locked.get('input_files', [])
                   if evidence_path(item['path'], envelope, locked).resolve() == expected]
        if len(matches) != 1 or checked(matches[0]) != expected:
            raise ValueError('Final input is not frozen exactly once before QEMU launch: ' + str(value))
        return expected

    baseline_file = locked_file(str(envelope / 'prepare/baseline.json'))
    mcu_file = locked_file(str(envelope / 'prepare/mcu.json'))
    if (checked(raw['identities']['baseline_recipe']) != baseline_file or
            checked(raw['identities']['MCU_recipe']) != mcu_file):
        raise ValueError('Final recipes differ from the launch-time locked recipes')
    baseline, _ = recipes(baseline_file, mcu_file)
    task_value, loader_value = (baseline.get('task-observation-plan'),
                                baseline.get('loader-runtime-reference-spec'))
    if not task_value or not loader_value:
        raise ValueError('Native final sampling requires both task and Loader plans')
    task_file, loader_file = locked_file(task_value), locked_file(loader_value)
    plan, _ = load_plan(task_file, blobs)
    if checked(raw['task_observation_plan']) != task_file:
        raise ValueError('Observed task plan differs from the locked plan')
    return plan, load_reference(loader_file, blobs['master'])


def native_saiso_sample_binding(rows, epoch, bound):
    from native_unified_probe import SAISO_FINAL_SAMPLES
    expected = {(address, size, label) for address, size, label in SAISO_FINAL_SAMPLES}
    actual = [(int(row['address'], 16), row['bytes'], row['label']) for row in rows]
    if len(actual) != len(expected) or set(actual) != expected:
        raise ValueError('SAISO final sample set is missing, duplicated or outside the declared extents')
    for row in rows:
        if (row.get('error') or row['global_cpu'] != 0 or row['role'] != 'master'
                or row['stop_epoch'] != epoch):
            raise ValueError('SAISO sample belongs to the wrong engine or stop epoch')
        body = bound['memory'](0, epoch, int(row['address'], 16), row['bytes'])
        if body.hex() != row['raw_hex'] or hashlib.sha256(body).hexdigest() != row['sha256']:
            raise ValueError('SAISO retained bytes differ from actual master VA read')


def native_task_sample_binding(doc, role, plan, epoch, gate, output, bound, checked):
    """Recompute all requested roots and registry summaries from actual replies."""
    from native_unified_probe import ROLE_CPU
    from expeed_task_observer import observe
    # Task reports are sealed while sampling is still in progress. The owner
    # marks the common gate complete only after all later final reads finish.
    sampling_gate = dict(gate, sampling_complete=False)
    if (doc.get('role') != role or doc.get('plan') != plan or doc.get('stop_gate') != sampling_gate
            or doc.get('complete_within_plan') is not True or doc.get('guest_state_written') is not False):
        raise ValueError('Task RAM differs from the locked role plan or common stop: ' + role)
    reads = doc.get('reads', [])
    if not reads:
        raise ValueError('Missing planned task RAM reads: ' + role)
    for index, row in enumerate(reads):
        if row.get('index') != index or not row.get('saved') or row.get('error') or row.get('rejected'):
            raise ValueError('Task RAM lacks a successful saved planned read: ' + role)
        body = bound['memory'](ROLE_CPU[role], epoch, int(row['address'], 16), row['bytes'])
        if len(body) != row['bytes'] or checked(row['saved']).read_bytes() != body:
            raise ValueError('Task RAM file differs from actual role-selected memory reply')

    class RetainedRole:
        running = False
        def __init__(self):
            self.role = role
            self.remote = self
        def memory(self, address, size):
            return bound['memory'](ROLE_CPU[role], epoch, address, size)

    derived = observe(RetainedRole(), plan, output, sampling_gate, retain=False)
    def semantic(value):
        if isinstance(value, dict):
            return {key: semantic(item) for key, item in value.items()
                    if key not in ('host_start_monotonic_ns', 'host_end_monotonic_ns', 'path')}
        if isinstance(value, list):
            return [semantic(item) for item in value]
        return value
    if semantic(derived) != semantic(doc):
        raise ValueError('Task roots, planned read set or registry aggregate differ from actual stopped replay: ' + role)
    if derived.get('failed_read_count') != 0 or derived.get('complete_within_plan') is not True:
        raise ValueError('Actual task RAM replay is incomplete: ' + role)
    return derived


def native_loader_sample_binding(rows, reference, epoch, protocol, bound, checked, envelope, locked):
    expected = {entry['region']: entry for entry in reference['regions']}
    if len(rows) != len(expected) or {row.get('region') for row in rows} != set(expected):
        raise ValueError('Loader final sample set must include both locked original regions exactly once')
    for row in rows:
        entry, args = expected[row['region']], row.get('QMP_arguments', {})
        if (row.get('VA') != entry['address'] or row.get('address_kind') != 'CPU-selected VA'
                or args.get('val') != int(entry['address'], 16) or args.get('size') != entry['bytes']
                or checked(row['reference']) != checked(entry['reference'])):
            raise ValueError('Loader extent or recorded reference differs from the locked original region')
        if (row.get('error') or row.get('global_cpu') != 0 or row.get('stop_epoch') != epoch or
                row.get('complete') is not True or not any(e['command'] == {'execute': 'memsave', 'arguments': args}
                    and e['response'].get('return') == row.get('QMP_return') and 'return' in e['response']
                    and e.get('stop_epoch') == epoch and e.get('running') is False for e in protocol['QMP'])):
            raise ValueError('Loader VA sample lacks actual successful CPU0 memsave in final stop')
        p = checked(row['runtime'])
        if (p != evidence_path(args['filename'], envelope, locked).resolve() or
                p.stat().st_size != entry['bytes'] or args.get('cpu-index') != 0):
            raise ValueError('Loader memsave file/size/CPU differs from actual QMP arguments')
        bound['registers'](0, epoch, row['MMU_registers'])
        matches = digest(p) == entry['reference']['sha256']
        if row.get('full_SHA_matches_recorded_RAM') is not matches:
            raise ValueError('Loader recorded-RAM comparison flag differs from actual SHA')


def native_scenario_binding(scenario, raw, locked, protocol, clock_rows, checked):
    """Verify every delivery against the public schedule and actual QMP set/get."""
    from native_unified_pads import SCHEDULE, make_request, ack_matches, load_schedule, schedule_rows
    result = dict(scenario)
    issues, counts, delivered = [], dict(GPIO=0, PCAL=0), []
    try:
        events = SCHEDULE
        argv = locked.get('scenario_argv', [])
        retained = locked.get('scenario_schedule_input')
        if retained is not None:
            source = checked(retained)
            actual = scenario.get('schedule_input')
            if (not isinstance(argv, list) or argv.count('--schedule') != 1
                    or argv.index('--schedule') + 1 >= len(argv)):
                raise ValueError('Scenario external table lacks one launch-time file argument')
            if (not actual or checked(actual) != source
                    or evidence_path(argv[argv.index('--schedule') + 1], source.parents[1], locked).resolve() != source):
                raise ValueError('Scenario external pad source differs from its frozen launch input')
            events = load_schedule(source)
        elif scenario.get('schedule_input') is not None or '--schedule' in argv:
            raise ValueError('Scenario external table has no launch-time locked identity')
        schedule = schedule_rows(events)
        if scenario.get('schedule') != schedule or locked.get('scenario_schedule') != schedule:
            raise ValueError('Declared virtual schedule differs from the complete locked input table')
        origin, pid, uid = scenario['virtual_origin_ns'], scenario['owner_pid'], scenario['owner_uuid']
        arch = raw['architecture']
        if (type(origin) is not int or origin < 0 or pid != arch.get('pid') or uid != arch.get('expected_uuid')
                or scenario.get('schedule_timebase') != 'QEMU_CLOCK_VIRTUAL'
                or scenario.get('host_sleep_is_guest_time') is not False):
            raise ValueError('Scenario owner or virtual timebase is invalid')
        first_continue = min(e['host_ns'] for e in protocol['controls'] if e['running'])
        if not any(r.get('virtual_ns') == origin and r.get('stop_epoch') == 1 and r.get('running') is False
                   and any(q['tx_end'] == r.get('QMP_tx_bytes_after') and q['host_ns'] < first_continue
                           for q in protocol['QMP']) for r in clock_rows):
            raise ValueError('Scenario origin does not bind to a real pre-continue virtual clock')
        checked(scenario['locked_input_identity'])
        for kind, key in (('GPIO', 'explicit_MCU_gpio_host_input_file'), ('PCAL', 'explicit_MCU_host_input_file')):
            # Compare retained strings; absolute run paths are relocated by checked() elsewhere.
            channel = scenario.get('input_channels', {}).get(kind, {})
            if channel.get('request_path') != locked.get(key):
                raise ValueError('Scenario uses an input channel outside the locked run')
        owner_events = raw.get('external_pad_events', [])
        qsets = [e for e in protocol['QMP'] if e['command'].get('execute') == 'qom-set']
        associated = []
        for index, event in enumerate(scenario.get('events', [])):
            if index >= len(events) or event.get('schedule_index') != index:
                raise ValueError('Scenario input indices are missing, repeated or reordered')
            kind = events[index][1]
            counts[kind] += 1
            expected = make_request(counts[kind], events[index], origin, dict(pid=pid, owner_uuid=uid))
            if event.get('request') != expected:
                raise ValueError('Scenario request changed sequence/deadline/mask/owner')
            if event.get('delivered') is not True:
                if event.get('acknowledgement') or index != len(scenario['events']) - 1:
                    raise ValueError('Incomplete event has a fabricated ACK or later deliveries')
                continue
            ack = event.get('acknowledgement')
            if not ack_matches(expected, ack) or ack not in owner_events:
                raise ValueError('Scenario ACK does not match its owner event and masked input')
            candidates = [e for e in qsets if e['command'].get('arguments') == {
                'path': '/machine', 'property': ack['property'], 'value': ack['requested_levels']}
                and 'return' in e['response'] and e['tx_offset'] not in associated]
            found = None
            for change in candidates:
                before = [e for e in protocol['QMP'] if e['tx_offset'] < change['tx_offset']]
                after = [e for e in protocol['QMP'] if e['tx_offset'] > change['tx_offset']]
                prop = {'execute': 'qom-get', 'arguments': {'path': '/machine', 'property': ack['property']}}
                previous = before[-1] if before else {}
                readback = after[0] if after else {}
                clock_before = before[-2] if len(before) >= 2 else {}
                clock_after = after[1] if len(after) >= 2 else {}
                clock_command = {'execute': 'qom-get', 'arguments': {'path': '/machine', 'property': 'virtual-time-ns'}}
                if (previous.get('command') == readback.get('command') == prop
                        and previous['response'].get('return') == ack['previous_levels']
                        and readback['response'].get('return') == ack['readback']
                        and clock_before.get('command') == clock_after.get('command') == clock_command
                        and clock_before['response'].get('return') == ack['applied_virtual_ns']
                        and clock_after['response'].get('return') == ack['after_virtual_ns']):
                    found = change
                    break
            if not found:
                raise ValueError('Pad ACK does not bind to ordered actual clock/get/set/get/clock replies')
            associated.append(found['tx_offset'])
            delivered.append(index)
        if len(associated) != len(qsets) or len(owner_events) != len(associated):
            raise ValueError('Unassociated or fabricated owner pad deliveries')
        pending = [i for i in range(len(events)) if i not in delivered]
        if scenario.get('pending_schedule_indices') != pending or scenario.get('complete') is not (not pending):
            raise ValueError('Scenario completion/pending fields differ from actual delivered input indices')
        final_ns = clock_rows[-1]['virtual_ns'] if clock_rows else None
        due = [i for i in pending if type(final_ns) is int and origin + int(events[i][0]*1e9) <= final_ns]
        result.update(pending_schedule_indices=pending, delivered_schedule_indices=delivered,
                      overdue_undelivered_indices=due, last_verified_virtual_ns=final_ns)
        if due:
            raise ValueError('Already due virtual inputs were not delivered: ' + str(due))
    except (KeyError, TypeError, ValueError, StopIteration, OSError) as error:
        issues.append('External virtual input binding: ' + str(error))
    result.update(binding_verified=not issues, errors=issues, ACK_is_business_acceptance=False)
    return result, issues


def native_passive_battery_binding(raw, blobs, bound):
    """Replay passive MCU decoders from CPU4 RSP bytes, not saved aggregates."""
    from ex1850_battery_config import ConfigObserver
    from ex1850_battery_task import TaskObserver
    config = ConfigObserver(blobs['MCU']) if raw.get('battery_config_trace_enabled') else None
    task = TaskObserver(blobs['MCU']) if raw.get('battery_task_trace_enabled') else None

    class RetainedMCU:
        def memory(self, pointer, size):
            return bound['memory'](4, self.epoch, pointer, size)

    reader = RetainedMCU()
    config_events, task_events = [], []
    for event in raw.get('observations', []):
        reader.epoch = event['stop_epoch']
        bound['registers'](4, reader.epoch, event['registers'])
        address = int(event['address'], 16)
        actual = reader.memory(address, 4)
        if (actual.hex() != event['original_ROM_bytes'] or
                actual != blobs['MCU'][address - 0x08000000:address - 0x08000000 + 4]):
            raise ValueError('Passive battery original ROM differs from actual CPU4 reply')
        obs = {k: event[k] for k in ('observation_sequence', 'host_elapsed_seconds', 'HAL_tick', 'original_ROM_bytes')}
        for category, observer, output in (('config', config, config_events), ('task', task, task_events)):
            if observer is None or category not in event.get('labels', {}):
                continue
            values = observer.on_stop(reader, address, event['registers'], obs)
            for value in values:
                value.update(global_cpu=4, local_core=0, role='MCU', stop_epoch=reader.epoch,
                             virtual_time_ns=event['virtual_time_ns'])
            if values != event.get('original_battery_' + category + '_events', []):
                raise ValueError('Passive %s output differs from actual CPU4 SRAM/register replay' % category)
            output.extend(values)
            if category == 'config' and task is not None:
                task.activate(values)
        for key in ('original_battery_authentication_comparator', 'original_battery_authentication_completion'):
            if event.get(key):
                value = event[key]
                if reader.memory(int(value['body_address'], 16), 64).hex() != value['body_hex']:
                    raise ValueError('Authentication body differs from actual stopped MCU SRAM')
        row = event.get('original_cmd89_transaction_return')
        if row:
            root = int(row['transaction_root'], 16)
            for pointer, size, key in ((root, 6, 'control_hex'), (root+0x70, 18, 'TX_hex'),
                    (root+0x88, 4, 'RX_hex'), (int(row['body_address'], 16), 64, 'body_hex'),
                    (0x2001f4a0, 72, 'info72_hex'), (0x2000ed99, 2, 'auxiliary2_hex')):
                if reader.memory(pointer, size).hex() != row[key]:
                    raise ValueError('Original cmd89 retained %s differs from actual MCU read' % key)
    if config_events != raw.get('original_battery_config_events', []) or task_events != raw.get('original_battery_task_events', []):
        raise ValueError('Passive config/task aggregate differs from actual stopped replays')
    if task is not None and task.activation != raw.get('battery_task_trace_activation'):
        raise ValueError('Task tracing activation differs from actual nonzero original config copy')
    return dict(config_events=len(config_events), task_events=len(task_events),
                actual_CPU4_reply_binding_verified=True)


def audit_unified(envelope, locked, launcher, profile, errors, notes, sources,
                  ref, load, checked, validate_refs):
    """Audit one owned QEMU without executing it or altering guest evidence."""
    import sys
    from z62_common import HARNESS
    sys.path[:0] = [str(HARNESS), str(HARNESS / 'tools')]
    from native_unified_probe import CPU_ROLES, ROLE_CPU, RAM_SIZE, BOOT_TASK_PCS
    scope = locked.get('acceptance_scope', 'complete_declared_scenario')
    bounded = scope in ('architecture_observation', 'display_observation')
    if scope not in ('complete_declared_scenario', 'architecture_observation', 'display_observation'):
        errors.append('Unknown native acceptance scope: ' + str(scope))
    run = envelope / 'run'
    load(envelope / 'run.json', required=True)
    load(envelope / 'prepare/锁定命令与输入.json', required=True)
    load(envelope / 'launcher-status.json', required=True)
    preflight = load(envelope / 'package-preflight.json', required=True)
    raw = load(run / 'native-unified-result.json', required=True)
    initial_file = load(run / 'native-initial-architecture.json', required=True)
    ledger = load(run / 'QEMU-process-lifecycle.json', required=True)
    if initial_file != raw.get('initial_architecture'):
        errors.append('Durable initial architecture file differs from its retained result')
    if preflight.get('passed') is not True:
        errors.append('Package preflight failed or is incomplete')
    if launcher.get('coordinator_exit') != 0:
        errors.append('Host coordinator exit: ' + str(launcher.get('coordinator_exit')))
    for key in ('error', 'failure'):
        if launcher.get(key):
            errors.append('Host launcher: ' + str(launcher[key]))
        if raw.get(key):
            errors.append('Unified owner: ' + str(raw[key]))
    if (locked.get('machine') != 'nikon-z6ii-native' or locked.get('QEMU_instances') != 1
            or locked.get('CPU_count') != 5 or locked.get('debugger_connection_count') != 2
            or locked.get('CPU_roles') != {'master': [0, 1], 'slave': [2, 3], 'MCU': [4]}
            or locked.get('clock') != 'QEMU_CLOCK_VIRTUAL' or
            locked.get('guest_state_injection') is not False or raw.get('nonce_bridge') is not False
            or raw.get('guest_RAM_or_register_fixtures') or raw.get('MCU_packet_replay')):
        errors.append('Locked native one-instance/zero-injection contract is incomplete')
    validate_refs(raw)
    validate_refs(locked.get('firmware_manifest', {}))
    validate_refs(locked.get('bus_tool', {}))
    for item in locked.get('input_files', []) + locked.get('execution_files', []) + locked.get('build_manifests', []):
        try:
            checked(item)
        except (OSError, KeyError, TypeError, ValueError) as error:
            errors.append('Locked input/source identity: ' + str(error))
    build_ids = []
    for item in locked.get('build_manifests', []):
        try:
            manifest = json.loads(checked(item).read_text())
            binary = checked(dict(path=manifest['binary'], sha256=manifest['binary_sha256']))
            build_ids.append((str(binary), manifest['binary_sha256']))
        except (OSError, KeyError, TypeError, ValueError) as error:
            errors.append('Build identity: ' + str(error))
    if len(build_ids) != 2 or len(set(build_ids)) != 1:
        errors.append('Native EXPEED and MCU manifests must select the same binary')
    command = raw.get('command', [])
    def option(name):
        values = [command[i+1] for i, value in enumerate(command[:-1]) if value == name]
        if len(values) != 1:
            raise ValueError('Expected one actual QEMU option ' + name)
        return values[0]
    try:
        if (option('-smp') != '5' or option('-accel') != 'tcg,thread=single' or
                not option('-machine').startswith('nikon-z6ii-native,slave-firmware=') or
                not option('-icount').startswith('shift=') or ',sleep=off' not in option('-icount') or
                '-S' not in command):
            raise ValueError('QEMU command lacks five-CPU single-thread TCG/icount configuration')
        for role, value in (('master', option('-bios')), ('slave', option('-machine').split('slave-firmware=', 1)[1]),
                            ('MCU', option('-kernel'))):
            if checked(raw['identities'][role + '_ROM']) != evidence_path(value, envelope, locked):
                raise ValueError('Actual original ROM argument differs for ' + role)
        if checked(raw['identities']['QEMU']) != evidence_path(command[0], envelope, locked):
            raise ValueError('Actual QEMU argv binary differs from retained identity')
        if build_ids and raw['identities']['QEMU']['sha256'] != build_ids[0][1]:
            raise ValueError('Actual QEMU differs from selected EXPEED/MCU manifests')
        devices = [command[i+1] for i, v in enumerate(command[:-1]) if v == '-device']
        if devices != ['loader,addr=0x10020000,cpu-num=%d' % i for i in range(4)]:
            raise ValueError('Initial loaders must set only E6 CPU0..3 to original application entry')
        if ledger.get('command_sha256') != hashlib.sha256(json.dumps(command, ensure_ascii=False).encode()).hexdigest():
            raise ValueError('Lifecycle command SHA does not match actual argv')
        if option('-uuid') != raw.get('architecture', {}).get('expected_uuid'):
            raise ValueError('QEMU UUID argv differs from its actual owner')
    except (OSError, KeyError, IndexError, TypeError, ValueError) as error:
        errors.append('Actual native invocation: ' + str(error))
    life_valid = (ledger.get('schema') == 'z6ii-qemu-process-lifecycle/1' and ledger.get('role') == 'unified'
                  and ledger.get('launch') == 'started' and type(ledger.get('pid')) is int and ledger['pid'] > 0
                  and ledger.get('exit') == 'observed' and type(ledger.get('exit_code')) is int
                  and ledger == raw.get('QEMU_lifecycle') and ledger.get('pid') == raw.get('architecture', {}).get('pid'))
    lifecycle = dict(status='verified' if life_valid else 'unknown', actual_instance_count=1 if life_valid else None,
        pid=ledger.get('pid'), launch=ledger.get('launch'), exit=ledger.get('exit'), exit_code=ledger.get('exit_code'),
        exit_zero=life_valid and ledger.get('exit_code') == 0,
        scope='one owned QEMU lifecycle; firmware success is evaluated separately', firmware_success_implied=False)
    if not life_valid or not lifecycle['exit_zero']:
        errors.append('Unified QEMU lifecycle is incomplete or actual exit is nonzero: ' + str(ledger.get('exit_code')))
    protocol = native_protocol_audit(run, raw, checked, ref)
    assistance = protocol['assistance']
    errors.extend(protocol['errors'])
    notes.extend(protocol['observation_errors'])
    save(envelope / 'debugger-writes.json', dict(schema='z62.native-debugger-wire-audit/1',
        actual_guest_write_packets=assistance['actual_guest_write_packets'], writes=protocol['writes'],
        unknown=protocol['unknown'], errors=protocol['errors'], expected_connection_count=2))
    ref(envelope / 'debugger-writes.json')
    bound = native_read_bindings(protocol, raw)
    errors.extend(bound['errors'])
    entries, blobs = {}, {}
    try:
        for role in ROLES:
            blobs[role] = checked(raw['identities'][role + '_ROM']).read_bytes()
        actual = raw.get('initial_entries', [])
        if len(actual) != 5 or {e.get('global_cpu') for e in actual} != set(CPU_ROLES):
            raise ValueError('Initial five-core observations are incomplete')
        for role in ROLES:
            cores = [e for e in actual if e.get('role') == role]
            for e in cores:
                cpu, local = e['global_cpu'], e['local_core']
                if CPU_ROLES[cpu] != (role, local) or protocol['mapping'].get(e['thread'], {}).get('global_cpu') != cpu:
                    raise ValueError('Initial entry read belongs to another engine/core')
                regs, pc = e['registers'], int(e['registers']['r15'], 16)
                bound['registers'](cpu, 1, regs)
                base = 0x08000000 if role == 'MCU' else 0x10020000
                body = bound['memory'](cpu, 1, pc, 32)
                if (pc != (0x080002b4 if role == 'MCU' else base) or body != blobs[role][pc-base:pc-base+32]
                        or body.hex() != e['instruction_bytes'] or body.hex() != e['original_bytes']):
                    raise ValueError('Initial actual instructions differ from the selected original ROM')
                if role == 'MCU':
                    full = bound['memory'](4, 1, base, len(blobs[role]))
                    if int(regs['r13'], 16) != 0x20000c08 or full != blobs[role]:
                        raise ValueError('Original MCU full initial ROM/reset SP mismatch')
                    p = run / 'MCU/initial-simulated-FLASH.bin'
                    if p.read_bytes() != full:
                        raise ValueError('Saved initial MCU ROM differs from actual selected CPU read')
                    ref(p)
            if len(cores) != (1 if role == 'MCU' else 2):
                raise ValueError('Incorrect initial per-engine core count')
            entries[role] = dict(status='observed', global_CPUs=[e['global_cpu'] for e in cores],
                observed_CPU_count=len(cores), scope='original MCU reset' if role == 'MCU' else
                'original update-image application entry; physical Boot ROM/Flash cold boot unverified')
    except (OSError, KeyError, TypeError, ValueError) as error:
        errors.append('Original entry reply binding: ' + str(error))
    for role in ROLES:
        entries.setdefault(role, dict(status='not_observed', observed_CPU_count=0))
    clock_rows = []
    try:
        p = checked(raw['virtual_clock_observation_ledger'])
        clock_rows = [json.loads(s) for s in p.read_text().splitlines()]
    except (OSError, KeyError, TypeError, ValueError) as error:
        errors.append('Actual virtual clock ledger: ' + str(error))
    arch = native_architecture_binding(raw, protocol, clock_rows, errors)
    if arch.get('passed') is not True:
        errors.append('Required read-only native architecture observations did not all pass')
    observer_path = run / 'native-original-observations.jsonl'
    observations = []
    boot_observations = []
    if observer_path.exists():
        try:
            ref(observer_path)
            observations = [json.loads(s) for s in observer_path.read_text().splitlines()]
            if len(observations) != raw.get('original_observation_count'):
                raise ValueError('Original observer count differs from actual retained event ledger')
            for index, event in enumerate(observations):
                cpu, epoch = event['global_cpu'], event['stop_epoch']
                role, local = CPU_ROLES[cpu]
                if (event['index'] != index or event['role'] != role or event['local_core'] != local
                        or protocol['mapping'].get(event['thread'], {}).get('global_cpu') != cpu
                        or event.get('guest_state_written') is not False):
                    raise ValueError('Observer CPU/role/sequence or zero-write metadata is incorrect')
                bound['registers'](cpu, epoch, event['registers'])
                if int(event['registers']['r15'], 16) & ~1 != int(event['PC'], 16):
                    raise ValueError('Observer PC differs from the actual selected-core register')
                if event.get('original_ROM_verified') is True:
                    pc = int(event['PC'], 16)
                    base = 0x08000000 if role == 'MCU' else 0x10020000
                    body = bound['memory'](cpu, epoch, pc, 4)
                    if (body != blobs[role][pc-base:pc-base+4] or
                            body.hex() != event['original_ROM_bytes'] or body.hex() != event['actual_ROM_bytes']):
                        raise ValueError('Observer original bytes differ in the selected engine AddressSpace')
                if role == 'MCU' and 'HAL_tick' in event:
                    tick = int.from_bytes(bound['memory'](4, epoch, 0x20020400, 4), 'little')
                    if tick != event['HAL_tick']:
                        raise ValueError('MCU HAL tick differs from its actual stopped SRAM')
            if [e for e in observations if e['role'] == 'MCU' and 'observation_sequence' in e] != raw.get('observations', []):
                raise ValueError('Battery observation list differs from CPU4 original observer ledger')
            boot_observations = [e for e in observations if e.get('original_ROM_verified') is True
                                 and int(e['PC'], 16) in BOOT_TASK_PCS]
            if raw.get('original_boot_task_observations') != boot_observations:
                raise ValueError('Boot task aggregate differs from actual bound original observer ledger')
        except (OSError, KeyError, TypeError, ValueError) as error:
            errors.append('Original observer reply binding: ' + str(error))
    else:
        errors.append('Missing actual original observer ledger')
    final = dict(raw.get('final_evidence', {}))
    gate = raw.get('common_stop', {})
    epoch = gate.get('stop_epoch')
    sample_errors = []
    tasks = {role: dict(status='not_observed', scheduler_roots=[]) for role in ('master', 'slave')}
    try:
        if gate.get('complete') is not True or epoch != arch.get('snapshot_epoch'):
            raise ValueError('Final common stop is missing or not the final architecture epoch')
        if not any(e['command'].get('execute') == 'query-status' and e.get('stop_epoch') == epoch
                   and e['response'].get('return', {}).get('running') is False for e in protocol['QMP']):
            raise ValueError('Final common stop lacks actual stopped QMP status')
        if any(gate.get('roles', {}).get(r, {}).get('global_cpu') != c or
               gate.get('roles', {}).get(r, {}).get('pause_confirmed') is not True for r, c in ROLE_CPU.items()):
            raise ValueError('Final samples have incorrect per-role CPU ownership')
        regs = raw.get('final_core_registers', [])
        if len(regs) != 5 or {r.get('global_cpu') for r in regs} != set(CPU_ROLES):
            raise ValueError('Final actual five-core registers are incomplete')
        for row in regs:
            cpu = row['global_cpu']
            if CPU_ROLES[cpu] != (row['role'], row['local_core']):
                raise ValueError('Final register role/local core is incorrect')
            bound['registers'](cpu, epoch, row['registers'])
        ram = raw['MCU_final_SRAM']
        if ram['stop_epoch'] != epoch or ram.get('address_kind') != 'CPU4 VA' or ram.get('bytes') != RAM_SIZE:
            raise ValueError('Final MCU SRAM has wrong CPU/epoch or incomplete original extent')
        if checked(ram).read_bytes() != bound['memory'](4, epoch, 0x20000000, ram['bytes']):
            raise ValueError('Final MCU SRAM differs from actual CPU4 memory replies')
        native_saiso_sample_binding(raw.get('SAISO_UI_RAM', []), epoch, bound)
        plan, loader_reference = native_final_inputs(envelope, locked, raw, blobs, checked)
        if set(raw.get('task_RAM', {})) != set(plan['roles']):
            raise ValueError('Final task RAM must contain both locked E6 roles exactly once')
        for role, item in raw.get('task_RAM', {}).items():
            if role not in tasks or item.get('error'):
                raise ValueError('Final task RAM sample is incomplete: ' + role)
            p = evidence_path(item['report'], envelope, locked)
            doc = load(p, required=True)
            if (doc.get('role') != role or doc.get('complete_within_plan') is not True
                    or item.get('selected_global_cpu') != ROLE_CPU[role] or item.get('common_stop_epoch') != epoch
                    or item.get('complete_within_plan') is not True or doc.get('guest_state_written') is not False):
                raise ValueError('Task RAM lacks completed CPU-selected common stop/plan')
            derived = native_task_sample_binding(doc, role, plan['roles'][role], epoch,
                gate, p.parent, bound, checked)
            registry = derived.get('task_registry', {})
            tasks[role] = dict(status='observed', evidence=ref(p), registry={k: v for k, v in registry.items() if k != 'tasks'},
                              scheduler_roots=[r for r in derived.get('roots', []) if 'scheduler' in r.get('name', '')],
                              candidate_count=len(derived.get('candidates', [])), common_stop_epoch=epoch,
                              actual_stopped_bytes_recomputed=True)
        loader = raw.get('Loader_payloads', {}).get('regions', [])
        native_loader_sample_binding(loader, loader_reference, epoch, protocol, bound, checked, envelope, locked)
        if gate.get('sampling_complete') is not True:
            raise ValueError('Owner did not retain completed final sampling')
    except (OSError, KeyError, TypeError, ValueError) as error:
        sample_errors.append(str(error))
    final_available = bool(arch.get('QMP_reply_binding_verified') and any(
        s.get('phase') == 'final' and s.get('running') is False and s.get('stop_epoch') == arch.get('snapshot_epoch')
        for s in arch.get('QOM_snapshots', [])))
    missing = []
    if gate.get('complete') is not True:
        missing.append('final_common_stop')
    if sample_errors:
        missing.append('final_registers_SRAM_task_RAM_and_Loader_samples')
    if not final_available:
        missing.append('final_QOM')
    final.update(available=final_available, complete=not missing,
        status='collected' if not missing else 'final_samples_incomplete', missing=missing,
        stop_epoch=arch.get('snapshot_epoch') if final_available else None,
        virtual_ns=arch.get('snapshot_virtual_ns') if final_available else None,
        sampling_errors=sample_errors, historical_snapshot_epoch=raw.get('initial_architecture', {}).get('snapshot_epoch'),
        historical_snapshot_virtual_ns=raw.get('initial_architecture', {}).get('snapshot_virtual_ns'),
        historical_snapshot_substituted_for_final=False)
    if missing:
        errors.append('Final evidence incomplete: ' + ', '.join(missing))
    if raw.get('host_operation_completed') is not True:
        errors.append('Unified owner did not complete its actual observation operation')
    # Re-run passive decoders using only wire-bound SRAM at each CPU4 stop.
    try:
        native_passive_battery_binding(raw, blobs, bound)
    except (OSError, KeyError, TypeError, ValueError) as error:
        errors.append('Passive battery reply binding: ' + str(error))
    from audit_battery import audit_battery
    battery, battery_errors = audit_battery(envelope, raw, assistance, load, checked, ref)
    functional_battery_errors = [e for e in battery_errors if e.startswith((
        'Required original cmd89 return not observed:', 'Original MCU authentication comparator/ready-store acceptance not observed'))
        or e in battery.get('original_cmd89_functional_errors', [])]
    errors.extend(e for e in battery_errors if e not in functional_battery_errors or not bounded)
    if bounded and functional_battery_errors:
        notes += ['Battery function remains unverified: ' + e for e in functional_battery_errors]
    scenario = load(run / 'native-gpio-scenario-result.json', required=True)
    validate_refs(scenario)
    scenario, scenario_errors = native_scenario_binding(scenario, raw, locked, protocol, clock_rows, checked)
    errors.extend(scenario_errors)
    delivery_complete = scenario.get('binding_verified') is True and scenario.get('complete') is True and not scenario.get('error')
    pending_allowed = (scope == 'architecture_observation' and scenario.get('binding_verified') is True
        and bool(scenario.get('pending_schedule_indices')) and not scenario.get('overdue_undelivered_indices')
        and launcher.get('coordinator_exit') == 0 and launcher.get('scenario_exit') == 1
        and lifecycle['exit_zero'] and scenario.get('error') in (
            'RuntimeError: Unified owner ended before the full virtual schedule was delivered',
            'TimeoutError: Host safety budget expired with virtual events still pending'))
    if not delivery_complete and not pending_allowed:
        errors.append('Declared virtual input scenario was not delivered and is not a verified bounded pending schedule')
    if delivery_complete and launcher.get('scenario_exit') != 0:
        errors.append('Delivered scenario has a nonzero actual host exit')
    if pending_allowed:
        notes.append('Architecture scope only: full declared virtual input schedule remains incomplete')
    frames = []
    try:
        from PIL import Image
        for item in raw.get('UI', {}).get('samples', []):
            if not item.get('image'):
                continue
            p = checked(item['image'])
            if not any(e['command'] == {'execute': 'screendump', 'arguments': {'filename': str(p)}}
                       or (e['command'].get('execute') == 'screendump' and evidence_path(
                           e['command'].get('arguments', {}).get('filename', ''), envelope, locked) == p)
                       for e in protocol['QMP'] if 'return' in e['response']):
                raise ValueError('Saved UI frame does not bind to an actual QMP screendump')
            with Image.open(p) as image:
                rgb = image.convert('RGB')
                extrema = rgb.getextrema()
                frames.append(dict(evidence=ref(p), size=list(rgb.size), pixel_sha256=hashlib.sha256(rgb.tobytes()).hexdigest(),
                    nonblack=any(b > 0 for a, b in extrema), uniform=all(a == b for a, b in extrema),
                    role_assignment_verified=False))
    except (OSError, KeyError, TypeError, ValueError) as error:
        errors.append('Saved unified UI evidence: ' + str(error))
    nonblack = {f['pixel_sha256'] for f in frames if f['nonblack'] and not f['uniform']}
    lcd = dict(status='nonblack_pixels_observed' if nonblack else 'black_or_uniform_only' if frames else 'not_observed',
        frame_files=len(frames), distinct_pixel_hashes=len({f['pixel_sha256'] for f in frames}),
        distinct_nonblack_nonuniform_frames=len(nonblack), pixel_change_observed=len(nonblack) > 1,
        original_dynamic_image_payload_verified=False, frames=frames, host_guest_write_gate=assistance['status'],
        display_mode_observations=dict(samples=0, distinct_nonblack_pixel_hashes=0, all_modes_distinct_verified=False,
                                      cycle_return_pixel_match_observed=None, mode_semantics_verified=False),
        scope='actual QMP display console pixels; engine assignment and original UI input handling remain unverified')
    counters = {}
    log = run / 'qemu.log'
    if log.exists():
        ref(log)
        for line in log.read_text(errors='replace').splitlines():
            role = re.search(r'\brole=(master|slave|MCU)\b', line)
            if role:
                for key in COUNTERS:
                    found = re.search(r'\b' + key + r'=(\d+)\b', line)
                    if found:
                        counters.setdefault(role[1], {})[key] = int(found[1])
    reasons = {
        'physical_flash_natural_boot': '物理 Flash / Boot ROM 自然冷启动未验证；E6 当前从更新镜像应用入口加载。',
        'scheduler_identity': '任务/调度 RAM 是观察值；RTOS / TCB 完整身份仍需独立证据。',
        'cross_engine_causality': '共享时钟和 canonical RAMBlock 支持架构观察；还需带内容、方向、时间的请求—DMA—ACK—响应见证。',
        'stable_menu': '稳定菜单导航、退出及重入尚未验收；历史三进程菜单图片不替代本次统一运行。',
        'live_view': '原厂图像缓冲与持续变化 image / LCD payload 尚未验收。',
        'photo_capture_storage': '原厂 capture、RAW / ISP、有效照片及存储因果尚未验收。',
        'movie_recording': 'movie-disp 用户明确未完成；原厂模式切换和有效录像媒体尚未验收。',
        'hdmi_output': '需要原厂 video DMA 与非空变化的 HDMI payload；接收器初始化不能证明输出。'}
    gates = {k: dict(label=k, status='not_verified', reason=v) for k, v in reasons.items()}
    counts = {role: task.get('registry', {}).get('allocated_count') for role, task in tasks.items()}
    capabilities = dict(
        one_QEMU_five_CPUs=dict(status='observed' if arch.get('passed') else 'unknown',
                              PID=lifecycle['pid'], active_structure_regression_included=False),
        task_registry=dict(status='observed' if all(type(v) is int and v > 0 for v in counts.values()) else 'not_observed',
                           allocated_slots=counts, certified_RTOS_identity=False),
        declared_scenario_delivery=dict(status='delivered' if delivery_complete else 'incomplete',
            declared_schedule_events=len(locked.get('scenario_schedule', [])), delivered_schedule_events=len(scenario.get('delivered_schedule_indices', [])),
            pending_schedule_indices=scenario.get('pending_schedule_indices', []), bounded_pending_allowed=pending_allowed),
        original_battery_protocol=dict(status=battery['status'], required_TX_relaxed=False,
            original_cmd89_accepted_counts=battery.get('original_cmd89_accepted_counts', {}),
            physical_authentication_verified=False),
        LCD_pixels=dict(status=lcd['status'], saved_frames=len(frames), engine_assignment_verified=False))
    runtime_ok = (not errors and lifecycle['exit_zero'] and arch.get('passed') is True and final['complete']
                  and assistance['status'] == 'zero_guest_writes_verified' and (delivery_complete or pending_allowed))
    report = dict(schema='z62.progress-acceptance/1', audited=now(), run=envelope.name, auditor=identity(Path(__file__)),
        profile=profile.get('name'), profile_kind=profile.get('kind'), execution_model='single-qemu-five-cpu',
        acceptance_scope=scope, audit_completed=bool(locked and launcher.get('finished') and raw),
        package_runtime_status='verified' if runtime_ok else 'failed_or_unknown',
        lifecycle=lifecycle, original_entry_observations=entries, debugger_assistance=assistance,
        architecture=arch, initial_architecture=initial_file, final_evidence=final,
        tasks_and_scheduler=tasks, LCD=lcd, battery=battery, engineering_capabilities=capabilities,
        imaging=dict(status='observations_only', counters=counters, HDMI_nonempty_payloads=[],
                     firmware_capture_buffers_verified=False, original_RAW_ISP_output_verified=False,
                     original_video_DMA_verified=False),
        external_input_scenario=scenario, first_observed_boundaries=dict(
            first_unmodeled=raw.get('first_unmodeled'), SPI2_DMA_memory_boundaries=raw.get('SPI2_DMA_memory_boundaries', [])),
        original_boot_task_observations=boot_observations,
        virtual_wire_wait_events=raw.get('virtual_wire_wait_events', []),
        full_camera_status='not_verified', functional_gates=gates,
        conditions=dict(camera_access=False, application_entry_direct_load=True, physical_flash_dump=False,
            synthetic_inputs=profile.get('synthetic_inputs', []), independent_virtual_clocks=False,
            physical_reset_or_clock_frequency_verified=False, debugger_fixture_regression_included=False),
        reply_binding=dict(actual_memory_read_count=bound['actual_memory_read_count'],
                           actual_register_read_count=bound['actual_register_read_count'], errors=bound['errors']),
        errors=list(dict.fromkeys(errors)), notes=list(dict.fromkeys(notes)), evidence=list(sources.values()))
    save(envelope / 'acceptance.json', report)
    rows = ['# Z6II 单 QEMU native 本次验收', '',
        '运行：%s；scope：%s；目录运行与证据：**%s**；整机功能：**not_verified**。' %
        (envelope.name, scope, report['package_runtime_status']), '',
        '一个实际 PID：%s；QMP CPU 数：%d；完整两连接：%s；实际 guest 写包：%s。' %
        (lifecycle['pid'], len(arch.get('query_cpus_fast', [])), assistance['complete_expected_connection_capture'],
         assistance['actual_guest_write_packets']), '',
        '架构 snapshot epoch / virtual ns：%s / %s。final：%s；缺失：%s。' %
        (arch.get('snapshot_epoch'), arch.get('snapshot_virtual_ns'), final['status'], final['missing']),
        '初始 snapshot 保留在首次 continue 之前；初始 / 历史快照不替代缺失的 final QOM。', '',
        'Final 采样校验错误：%s。' % final.get('sampling_errors', []), '',
        '完整输入表：%s；已交付序号：%s；待交付：%s；已到期未交付：%s。' %
        (capabilities['declared_scenario_delivery']['status'], scenario.get('delivered_schedule_indices', []),
         scenario.get('pending_schedule_indices', []), scenario.get('overdue_undelivered_indices', [])),
        'Host 预算与 virtual 输入期限分别记录；pad ACK 只证明外设输入交付。', '',
        '只读 QOM / debugger 架构观察与主动写入 fixture 回归分别验收；CNTVCT 实测频率仍需独立回归报告。', '',
        '| 原厂入口角色 | 观察状态 | CPU 数 |', '|---|---|---:|']
    for role in ROLES:
        rows.append('| %s | %s | %s |' % (role, entries[role]['status'], entries[role]['observed_CPU_count']))
    rows += ['', '| 架构只读检查 | 结果 |', '|---|---|']
    rows += ['| %s | %s |' % (key, value) for key, value in arch.get('checks', {}).items()]
    rows += ['', '| 功能 | 状态 | 依据 / 缺口 |', '|---|---|---|']
    rows += ['| %s | %s | %s |' % (key, value['status'], value['reason']) for key, value in gates.items()]
    rows += ['', '电池状态：%s；两种完整 0x89 的 required_TX 保持原合同；未执行到的功能保持未验证。' %
             battery['status'], '', '原始边界：%s。' % json.dumps(report['first_observed_boundaries'], ensure_ascii=False)]
    if report['errors']:
        rows += ['', '## 运行或证据缺口', ''] + ['- ' + e for e in report['errors']]
    if report['notes']:
        rows += ['', '## 观察范围', ''] + ['- ' + e for e in report['notes']]
    rows += ['', '完整身份、原始返回及证据索引：[acceptance.json](acceptance.json)。']
    (envelope / 'acceptance.md').write_text('\n'.join(rows) + '\n')
    return report
