import os
"""Load the local Probe and coordinate Movie LiveView + Multi-DISP verification."""
import importlib.util
import json
import struct
import time
from pathlib import Path
import sys

DIRECTORY = Path(__file__).resolve().parent
PORT = Path(__file__).resolve().parents[2] / 'src/harness'
PLAN_PATH = (PORT.parents[1] / 'inputs/assisted/movie_disp_writes.json')
RUN_ROOT = Path(os.environ['Z62_RUN_DIR'])
sys.path.insert(0, str(PORT))
spec = importlib.util.spec_from_file_location("probe_z6ii", DIRECTORY / "probe_z6ii.py")
probe = importlib.util.module_from_spec(spec)
sys.modules["probe_z6ii"] = probe
spec.loader.exec_module(probe)

def call_fixture_smp(remote, packet, function, payload, arguments, thumb=True, timeout=4.0, enabled_bps=None, hit_counts=None, core="p01.01"):
    thread = core if core else packet.split("thread:")[1].split(";")[0]
    remote.command("Hg" + thread)
    saved = remote.command("g")
    regs_bytes = bytearray.fromhex(saved)
    scratch = (struct.unpack_from("<I", regs_bytes, 52)[0] - len(payload) - 7) & ~7
    original_scratch = remote.memory(scratch, len(payload))
    assert remote.command(f"M{scratch:x},{len(payload):x}:" + payload.hex()) == "OK"

    func_addr = scratch if (function is None or function == "scratch") else function
    registers = [(i, scratch + v[1] if isinstance(v, tuple) else v) for i, v in enumerate(arguments)]
    registers += [(13, scratch), (14, 0x100202B4), (15, func_addr & ~1)]
    for reg, value in registers:
        struct.pack_into("<I", regs_bytes, 4 * reg, value)
    cpsr = struct.unpack_from("<I", regs_bytes, 64)[0]
    new_cpsr = (cpsr | 0x20) if thumb else (cpsr & ~0x20)
    struct.pack_into("<I", regs_bytes, 64, new_cpsr)

    assert remote.command("Z1,100202b4,4") == "OK"
    assert remote.command("G" + regs_bytes.hex()) == "OK"

    t_end = time.monotonic() + timeout
    after = None
    pc = 0
    ret_thread = thread
    while time.monotonic() < t_end:
        remote.send("c")
        returned = remote.receive()
        if "thread:" not in returned:
            break
        ret_thread = returned.split("thread:")[1].split(";")[0]
        remote.command("Hg" + ret_thread)
        after = remote.registers()
        pc = int(after["r15"], 16) & ~1
        if pc == 0x100202B4:
            break
        if pc in (0x10103610, 0x1010365c, 0x10103600):
            print(f">>> [ABORT in call_fixture_smp] pc={hex(pc)}, lr={after['r14']}, sp={after['r13']}", flush=True)
            break
        if enabled_bps and pc in enabled_bps:
            if hit_counts is not None:
                hit_counts[pc] = hit_counts.get(pc, 0) + 1
            assert remote.command(f"z1,{pc:x},2") == "OK"
            assert remote.command("Hc" + ret_thread) == "OK"
            remote.send("s")
            remote.receive()
            assert remote.command("Hc-1") == "OK"
            assert remote.command(f"Z1,{pc:x},2") == "OK"

    remote.command("Hg" + ret_thread)
    remote.command("z1,100202b4,4")
    output = remote.memory(scratch, len(payload))
    remote.command(f"M{scratch:x},{len(payload):x}:" + original_scratch.hex())
    remote.command("G" + saved)
    return {
        "return_cpu": ret_thread,
        "return_r0": after["r0"] if after else "0",
        "output": output.hex(),
        "pc": hex(pc) if after else "0",
    }

def pause_at_boot_task(master, enabled_bps, hit_counts, timeout=5.0):
    remote = master.remote
    ack = remote.byte()
    assert ack == ord("+"), f"Unexpected RSP byte before pause: {ack}"
    remote.sock.sendall(bytes([3]))
    stop_reply = remote.receive()
    assert stop_reply.startswith(("T", "S")), f"Unexpected stop reply: {stop_reply}"
    master.running = False
    ret_thread = stop_reply.split("thread:")[1].split(";")[0]
    remote.command("Hg" + ret_thread)
    pc = int(remote.registers()["r15"], 16) & ~1
    had_bp = 0x10200190 in enabled_bps
    if pc != 0x10200190:
        if not had_bp:
            assert remote.command("Z1,10200190,2") == "OK"
        t_end = time.monotonic() + timeout
        while time.monotonic() < t_end:
            remote.send("c")
            stop_reply = remote.receive()
            if "thread:" not in stop_reply:
                break
            ret_thread = stop_reply.split("thread:")[1].split(";")[0]
            remote.command("Hg" + ret_thread)
            pc = int(remote.registers()["r15"], 16) & ~1
            if pc == 0x10200190:
                break
            if pc in enabled_bps:
                hit_counts[pc] = hit_counts.get(pc, 0) + 1
                assert remote.command(f"z1,{pc:x},2") == "OK"
                assert remote.command("Hc" + ret_thread) == "OK"
                remote.send("s")
                remote.receive()
                assert remote.command("Hc-1") == "OK"
                assert remote.command(f"Z1,{pc:x},2") == "OK"
    if pc == 0x10200190:
        hit_counts[0x10200190] = hit_counts.get(0x10200190, 0) + 1
        assert remote.command("z1,10200190,2") == "OK"
        assert remote.command("Hc" + ret_thread) == "OK"
        remote.send("s")
        step_reply = remote.receive()
        assert remote.command("Hc-1") == "OK"
        if had_bp:
            assert remote.command("Z1,10200190,2") == "OK"
        if "thread:" in step_reply:
            stop_reply = step_reply
        else:
            stop_reply = f"T05thread:{ret_thread};"
    elif not had_bp:
        remote.command("z1,10200190,2")
    return stop_reply

def write_chunked(remote, addr, hex_str):
    data = bytes.fromhex(hex_str)
    for off in range(0, len(data), 512):
        part = data[off:off + 512]
        res = remote.command(f"M{addr + off:x},{len(part):x}:" + part.hex())
        assert res == "OK", f"RSP write failed at {addr + off:#x}: {res}"

def save_named_lcd(master, out_dir, stem):
    from PIL import Image
    out_dir.mkdir(parents=True, exist_ok=True)
    ppm_path = out_dir / f"{stem}.ppm"
    png_path = out_dir / f"{stem}.png"
    master.monitor.command("screendump", {"filename": str(ppm_path)})
    with Image.open(ppm_path) as im:
        im.save(png_path)
    return str(png_path)

def send_key_action(remote, packet, action_index, label, timeout=5.0, enabled_bps=None, hit_counts=None):
    words = [0, 0, 0, 0, 10, 0, 0, 0]
    words[action_index // 32] = 1 << (action_index % 32)
    payload = struct.pack("<8I", *words)
    return call_fixture_smp(
        remote, packet, 0x1076b7fe, payload,
        [("scratch", 0), 5, ("scratch", 20)], thumb=True, timeout=timeout,
        enabled_bps=enabled_bps, hit_counts=hit_counts,
    )

def execute_key_sequence(remote, current_packet, keys, timeout=5.0, enabled_bps=None, hit_counts=None):
    results = []
    pkt = current_packet
    for k in keys:
        res = send_key_action(remote, pkt, k, f"seq-key-{k}", timeout=timeout, enabled_bps=enabled_bps, hit_counts=hit_counts)
        pkt = f"T05thread:{res['return_cpu']};"
        results.append(res)
    return pkt, results

nb_path = PORT / "natural_boot.py"
src = nb_path.read_text(encoding="utf-8")
src = src.replace("24 if args.peer_business_trace_only else", "240 if args.peer_business_trace_only else")
src = src.replace("12 if address == 0x10200CAC else 3)", "12 if address == 0x10200CAC else 200)")
unexp_target = 'p.snapshot("unexpected passive stop", reply)\n                    report["engines"][role]["unexpected_stop"] = regs\n                    continue'
unexp_replacement = 'p.snapshot("unexpected passive stop", reply)\n                    report["engines"][role]["unexpected_stop"] = regs\n                    p.remote.send("c")\n                    p.running = True\n                    continue'
assert unexp_target in src, "Failed to locate unexpected passive stop in natural_boot.py"
src = src.replace(unexp_target, unexp_replacement, 1)
target = "        while startup_pending or time.monotonic() - start < args.seconds:\n"
replacement = """        scheme_a_injected = False
        scheme_a_plan = json.loads((PORT.parents[1] / 'inputs/assisted/movie_disp_writes.json').read_text(encoding="utf-8"))
        lvctrl_hex = scheme_a_plan["lvctrl_hex"]
        hist_hex = scheme_a_plan["hist_hex"]
        run_root = Path(os.environ['Z62_RUN_DIR'])
        disp_screens_dir = run_root / "movie-disp-screens"
        dma1_done_at = None
        next_ram_poll = None
        idle_count_at_inject = None
        applv_ready_signaled = False
        idle_count_at_applv = None
        fill_count_at_applv = None
        menu_ready_signaled = False
        idle_count_at_menu = None
        fill_count_at_menu = None
        liveview_snapshot_taken = False
        liveview_ready_at = None
        liveview_signaled = False
        disp_step = 0
        disp_next_action_at = None
        disp_max_wait_at = None
        disp_last_fill_count = 0
        disp_last_idle_count = 0
        disp_records = []
        while startup_pending or time.monotonic() - start < args.seconds:
            if not startup_pending:
                elapsed_now = time.monotonic() - start
                if (run_root / "native-gpio-scenario-result.json").exists():
                    report["smart_early_exit_seconds"] = round(elapsed_now, 4)
                    break
                if dma1_done_at is None and counts["master"].get(0x1038C104, 0) >= 2:
                    dma1_done_at = elapsed_now
                    next_ram_poll = elapsed_now + 10.0
                    report["smart_stage1_dma1_done_seconds"] = round(elapsed_now, 4)
                if (dma1_done_at is not None and not scheme_a_injected and
                        elapsed_now >= next_ram_poll):
                    master = engines.get("master")
                    if (master is not None and master.process.poll() is None and
                            master.running and b"$" not in master.remote.buffer):
                        ack = master.remote.byte()
                        assert ack == ord("+"), f"Unexpected RSP byte before poll pause: {ack}"
                        master.remote.sock.sendall(bytes([3]))
                        stop_reply = master.remote.receive()
                        assert stop_reply.startswith(("T", "S")), f"Unexpected stop reply: {stop_reply}"
                        master.running = False
                        row53_in_val = struct.unpack("<I", master.remote.memory(0xC1876518, 4))[0]
                        prop_1810 = struct.unpack("<I", master.remote.memory(0xC253DC68, 4))[0]
                        sysctl_44 = struct.unpack("<I", master.remote.memory(0xC18694F4, 4))[0]
                        ticks_48m = struct.unpack("<Q", master.remote.memory(0x04266008, 8))[0]
                        poll_rec = dict(
                            host_seconds=round(time.monotonic() - start, 4),
                            virtual_ms=round(ticks_48m / 48000.0, 3),
                            row53_in_val=hex(row53_in_val),
                            prop_1810=hex(prop_1810),
                            sysctl_44=hex(sysctl_44),
                        )
                        report.setdefault("scheme_a_ram_polls", []).append(poll_rec)
                        if row53_in_val != 0xFFFFFFFF and prop_1810 != 0xFFFFFFFF:
                            written_total = 0
                            for item in scheme_a_plan["writes"]:
                                addr = int(item["address"])
                                write_chunked(master.remote, addr, item["hex"])
                                written_total += len(item["hex"]) // 2
                            scheme_a_injected = True
                            idle_count_at_inject = counts["master"].get(0x10200190, 0)
                            report["scheme_a_upstream_injection"] = dict(
                                host_seconds=round(time.monotonic() - start, 4),
                                virtual_ms=poll_rec["virtual_ms"],
                                stop_reply=stop_reply,
                                writes_count=len(scheme_a_plan["writes"]),
                                written_bytes=written_total,
                            )
                            (run_root / "scheme-a-injected.json").write_text(
                                json.dumps(report["scheme_a_upstream_injection"], indent=2),
                                encoding="utf-8",
                            )
                        master.remote.send("c")
                        master.running = True
                        next_ram_poll = time.monotonic() - start + 2.5
                if (scheme_a_injected and not applv_ready_signaled and
                        (run_root / "pc5-closed.json").exists() and
                        counts["master"].get(0x102DE4EC, 0) >= 12 and
                        counts["master"].get(0x10200190, 0) > idle_count_at_inject):
                    master = engines.get("master")
                    if (master is not None and master.process.poll() is None and
                            master.running and b"$" not in master.remote.buffer):
                        ack = master.remote.byte()
                        assert ack == ord("+"), f"Unexpected RSP byte before stage3 pause: {ack}"
                        master.remote.sock.sendall(bytes([3]))
                        stop_reply = master.remote.receive()
                        assert stop_reply.startswith(("T", "S")), f"Unexpected stop reply: {stop_reply}"
                        master.running = False
                        assert master.remote.command("Mc253d72c,4:01000000") == "OK"
                        assert master.remote.command("Mc253e618,4:01000000") == "OK"
                        assert master.remote.command("Mc181dc0d,1:00") == "OK"
                        assert master.remote.command("M10931550,4:01000000") == "OK"
                        master.remote.send("c")
                        master.running = True
                        applv_ready_signaled = True
                        idle_count_at_applv = counts["master"].get(0x10200190, 0)
                        fill_count_at_applv = counts["master"].get(0x102DE4EC, 0)
                        next_lcd_snapshot = 0.0
                        info = dict(
                            host_seconds=round(elapsed_now, 4),
                            idle_hits=idle_count_at_applv,
                            fill_hits=fill_count_at_applv,
                        )
                        report["smart_stage3_applv_idle"] = info
                        (run_root / "applv-idle-ready.json").write_text(
                            json.dumps(info, indent=2), encoding="utf-8"
                        )
                if (applv_ready_signaled and not menu_ready_signaled and
                        (run_root / "menu-released.json").exists() and
                        counts["master"].get(0x102DE4EC, 0) >= fill_count_at_applv + 7 and
                        counts["master"].get(0x10200190, 0) > idle_count_at_applv):
                    master = engines.get("master")
                    if (master is not None and master.process.poll() is None and
                            master.running and b"$" not in master.remote.buffer):
                        ack = master.remote.byte()
                        assert ack == ord("+"), f"Unexpected RSP byte before stage4 pause: {ack}"
                        master.remote.sock.sendall(bytes([3]))
                        stop_reply = master.remote.receive()
                        assert stop_reply.startswith(("T", "S")), f"Unexpected stop reply: {stop_reply}"
                        master.running = False
                        assert master.remote.command("Mc253d72c,4:01000000") == "OK"
                        assert master.remote.command("Mc253e618,4:01000000") == "OK"
                        assert master.remote.command("Mc181dc0d,1:00") == "OK"
                        assert master.remote.command("M10931550,4:01000000") == "OK"
                        master.remote.send("c")
                        master.running = True
                        menu_ready_signaled = True
                        idle_count_at_menu = counts["master"].get(0x10200190, 0)
                        fill_count_at_menu = counts["master"].get(0x102DE4EC, 0)
                        next_lcd_snapshot = 0.0
                        info = dict(
                            host_seconds=round(elapsed_now, 4),
                            idle_hits=idle_count_at_menu,
                            fill_hits=fill_count_at_menu,
                        )
                        report["smart_stage4_menu_idle"] = info
                        (run_root / "menu-idle-ready.json").write_text(
                            json.dumps(info, indent=2), encoding="utf-8"
                        )
                if (menu_ready_signaled and not liveview_snapshot_taken and
                        (run_root / "pg1-released.json").exists() and
                        counts["master"].get(0x102DE4EC, 0) >= fill_count_at_menu + 2 and
                        counts["master"].get(0x10200190, 0) > idle_count_at_menu):
                    liveview_snapshot_taken = True
                    disp_next_action_at = elapsed_now + 1.2
                    disp_max_wait_at = elapsed_now + 2.0
                    disp_last_fill_count = counts["master"].get(0x102DE4EC, 0)
                    disp_last_idle_count = counts["master"].get(0x10200190, 0)
                    next_lcd_snapshot = 0.0
                if (liveview_snapshot_taken and not liveview_signaled and
                        elapsed_now >= disp_next_action_at and
                        ((counts["master"].get(0x102DE4EC, 0) >= disp_last_fill_count + 2) or
                         elapsed_now >= disp_max_wait_at)):
                    master = engines.get("master")
                    if (master is not None and master.process.poll() is None and
                            master.running and b"$" not in master.remote.buffer):
                        stop_reply = pause_at_boot_task(master, enabled["master"], counts["master"])

                        gui_canvas = struct.unpack("<I", master.remote.memory(0xC181DC24, 4))[0]
                        movie_flag = master.remote.memory(0xC202BF80, 1)[0]
                        curr_disp = master.remote.memory(0xC202C0DE, 1)[0]
                        prop_3b17 = struct.unpack("<I", master.remote.memory(0xC2578400, 4))[0]
                        movie_res = master.remote.memory(0xC202C12E, 1)[0]
                        mic_state = master.remote.memory(0xC202C0EC, 1)[0]
                        fxdx_state = master.remote.memory(0xC202C0CC, 1)[0]
                        rec_ok = struct.unpack("<I", master.remote.memory(0xC202C0E8, 4))[0]
                        rem_sec = struct.unpack("<H", master.remote.memory(0xC202C148, 2))[0]
                        audio_mode = master.remote.memory(0xC202C266, 1)[0]
                        hist_en = master.remote.memory(0xC202BD18, 1)[0]
                        hist_scale = struct.unpack("<I", master.remote.memory(0xC202BD3C, 4))[0]
                        horizon_state = list(struct.unpack("<7I", master.remote.memory(0xC18216B0, 28)))

                        stem_map = {
                            0: "photo_disp0_baseline",
                            1: "movie_disp0_standard",
                            2: "movie_disp1_simplified",
                            3: "movie_disp2_histogram",
                            4: "movie_disp3_horizon",
                            5: "movie_disp0_wrap",
                            6: "movie_4k60p_dx_crop",
                            7: "movie_1080_120p_hfr",
                            8: "movie_1080_slowmotion",
                        }
                        png_saved = save_named_lcd(master, disp_screens_dir, stem_map[disp_step])
                        rec = dict(
                            step=disp_step,
                            stem=stem_map[disp_step],
                            host_seconds=round(elapsed_now, 4),
                            fill_hits=counts["master"].get(0x102DE4EC, 0),
                            idle_hits=counts["master"].get(0x10200190, 0),
                            gui_canvas_C181DC24=hex(gui_canvas),
                            movie_flag_C202BF80=movie_flag,
                            curr_disp_C202C0DE=curr_disp,
                            prop_3B17_C2578400=prop_3b17,
                            movie_res_C202C12E=hex(movie_res),
                            mic_C202C0EC=hex(mic_state),
                            fxdx_C202C0CC=hex(fxdx_state),
                            rec_ok_C202C0E8=rec_ok,
                            rem_sec_C202C148=rem_sec,
                            audio_mode_C202C266=hex(audio_mode),
                            hist_enable_C202BD18=hist_en,
                            hist_scale_C202BD3C=hex(hist_scale),
                            horizon_C18216B0=horizon_state,
                            png=png_saved,
                        )
                        print(f">>> [MOVIE DISP STEP {disp_step}] {rec}", flush=True)

                        if disp_step == 0:
                            disp_last_fill_count = counts["master"].get(0x102DE4EC, 0)
                            for item in scheme_a_plan["movie_writes"]:
                                write_chunked(master.remote, int(item["address"]), item["hex"])
                            assert master.remote.command("Mc181ddbc,4:00000000") == "OK"
                            assert master.remote.command("Mc181dc10,4:00000000") == "OK"
                            assert master.remote.command("Mc181dc14,4:00000000") == "OK"
                            assert master.remote.command("Mc202be68,4:01000000") == "OK"
                            assert master.remote.command("Mc202bda4,4:01000000") == "OK"
                            assert master.remote.command("Mc202bde0,4:01000000") == "OK"
                            assert master.remote.command("Mc202bd85,1:01") == "OK"
                            assert master.remote.command("Mc202bd0e,1:01") == "OK"
                            assert master.remote.command("M10931550,4:01000000") == "OK"
                            call_res = call_fixture_smp(
                                master.remote, stop_reply, 0x104E4258, bytes(16), [0],
                                thumb=True, timeout=4.0,
                                enabled_bps=enabled["master"], hit_counts=counts["master"],
                            )
                            rec["action_call"] = call_res
                            disp_records.append(rec)
                            disp_last_idle_count = counts["master"].get(0x10200190, 0)
                            master.remote.send("c")
                            master.running = True
                            disp_step += 1
                            next_lcd_snapshot = 0.0
                            now_rel = time.monotonic() - start
                            disp_next_action_at = now_rel + 2.5
                            disp_max_wait_at = now_rel + 3.5
                        elif disp_step == 1:
                            # Transition to Movie DISP 1 (Simplified)
                            disp_last_fill_count = counts["master"].get(0x102DE4EC, 0)
                            assert master.remote.command("Mc2578400,4:01000000") == "OK"
                            assert master.remote.command("Mc2578404,4:01000000") == "OK"
                            assert master.remote.command("Mc202c0de,1:01") == "OK"
                            assert master.remote.command("Mc23b9328,1:09") == "OK"
                            assert master.remote.command("Mc202c6a8,1:09") == "OK"
                            assert master.remote.command("Mc253dc70,4:00000000") == "OK"
                            assert master.remote.command("Mc253dc74,4:01000000") == "OK"
                            assert master.remote.command("Mc202deec,1:01") == "OK"
                            assert master.remote.command("Mc202bd18,1:00") == "OK"
                            assert master.remote.command("Mc181ddbc,4:00000000") == "OK"
                            assert master.remote.command("Mc181dc10,4:00000000") == "OK"
                            assert master.remote.command("Mc181dc14,4:00000000") == "OK"
                            assert master.remote.command("Mc202be68,4:01000000") == "OK"
                            assert master.remote.command("Mc202bda4,4:01000000") == "OK"
                            assert master.remote.command("Mc202bde0,4:01000000") == "OK"
                            assert master.remote.command("Mc202bd85,1:01") == "OK"
                            step_res = call_fixture_smp(
                                master.remote, stop_reply, 0x104E4258, bytes(16), [0],
                                thumb=True, timeout=4.0,
                                enabled_bps=enabled["master"], hit_counts=counts["master"],
                            )
                            rec["action_call"] = step_res
                            disp_records.append(rec)
                            disp_last_idle_count = counts["master"].get(0x10200190, 0)
                            master.remote.send("c")
                            master.running = True
                            disp_step += 1
                            next_lcd_snapshot = 0.0
                            now_rel = time.monotonic() - start
                            disp_next_action_at = now_rel + 2.5
                            disp_max_wait_at = now_rel + 3.5
                        elif disp_step == 2:
                            # Transition to Movie DISP 2 (Histogram)
                            disp_last_fill_count = counts["master"].get(0x102DE4EC, 0)
                            assert master.remote.command("Mc2578400,4:02000000") == "OK"
                            assert master.remote.command("Mc2578404,4:02000000") == "OK"
                            assert master.remote.command("Mc202c0de,1:02") == "OK"
                            assert master.remote.command("Mc23b9328,1:0e") == "OK"
                            assert master.remote.command("Mc202c6a8,1:0e") == "OK"
                            assert master.remote.command("Mc253dc70,4:01000000") == "OK"
                            assert master.remote.command("Mc253dc74,4:01000000") == "OK"
                            assert master.remote.command("Mc202deec,1:01") == "OK"
                            assert master.remote.command("Mc202bd18,1:01") == "OK"
                            assert master.remote.command("Mc202bd5c,1:00") == "OK"
                            assert master.remote.command("Mc202bd3c,4:400a0000") == "OK"
                            write_chunked(master.remote, 0xC202CACC, hist_hex)
                            write_chunked(master.remote, 0xC202E384, hist_hex)
                            assert master.remote.command("Mc181ddbc,4:00000000") == "OK"
                            assert master.remote.command("Mc181dc10,4:00000000") == "OK"
                            assert master.remote.command("Mc181dc14,4:00000000") == "OK"
                            assert master.remote.command("Mc202be68,4:01000000") == "OK"
                            assert master.remote.command("Mc202bda4,4:01000000") == "OK"
                            assert master.remote.command("Mc202bde0,4:01000000") == "OK"
                            assert master.remote.command("Mc202bd85,1:01") == "OK"
                            step_res = call_fixture_smp(
                                master.remote, stop_reply, 0x104E4258, bytes(16), [0],
                                thumb=True, timeout=4.0,
                                enabled_bps=enabled["master"], hit_counts=counts["master"],
                            )
                            rec["action_call"] = step_res
                            disp_records.append(rec)
                            disp_last_idle_count = counts["master"].get(0x10200190, 0)
                            master.remote.send("c")
                            master.running = True
                            disp_step += 1
                            next_lcd_snapshot = 0.0
                            now_rel = time.monotonic() - start
                            disp_next_action_at = now_rel + 2.5
                            disp_max_wait_at = now_rel + 3.5
                        elif disp_step == 3:
                            # Transition to Movie DISP 3 (Dual-Axis Virtual Horizon)
                            disp_last_fill_count = counts["master"].get(0x102DE4EC, 0)
                            assert master.remote.command("Mc2578400,4:03000000") == "OK"
                            assert master.remote.command("Mc2578404,4:03000000") == "OK"
                            assert master.remote.command("Mc202c0de,1:03") == "OK"
                            assert master.remote.command("Mc23b9328,1:09") == "OK"
                            assert master.remote.command("Mc202c6a8,1:09") == "OK"
                            assert master.remote.command("Mc253dc70,4:00000000") == "OK"
                            assert master.remote.command("Mc253dc74,4:00000000") == "OK"
                            assert master.remote.command("Mc202deec,1:00") == "OK"
                            assert master.remote.command("Mc202c1a8,4:00000000") == "OK"
                            assert master.remote.command("Mc202bd18,1:00") == "OK"
                            assert master.remote.command("Mc181ddbc,4:00000000") == "OK"
                            assert master.remote.command("Mc181dc10,4:00000000") == "OK"
                            assert master.remote.command("Mc181dc14,4:00000000") == "OK"
                            assert master.remote.command("Mc202be68,4:01000000") == "OK"
                            assert master.remote.command("Mc202bda4,4:01000000") == "OK"
                            assert master.remote.command("Mc202bde0,4:01000000") == "OK"
                            assert master.remote.command("Mc202bd85,1:01") == "OK"
                            step_res = call_fixture_smp(
                                master.remote, stop_reply, 0x104E4258, bytes(16), [0],
                                thumb=True, timeout=4.0,
                                enabled_bps=enabled["master"], hit_counts=counts["master"],
                            )
                            rec["action_call"] = step_res
                            disp_records.append(rec)
                            disp_last_idle_count = counts["master"].get(0x10200190, 0)
                            master.remote.send("c")
                            master.running = True
                            disp_step += 1
                            next_lcd_snapshot = 0.0
                            now_rel = time.monotonic() - start
                            disp_next_action_at = now_rel + 2.5
                            disp_max_wait_at = now_rel + 3.5
                        elif disp_step == 4:
                            # Transition to Movie DISP 0 Wrap-around (Standard Detailed)
                            disp_last_fill_count = counts["master"].get(0x102DE4EC, 0)
                            assert master.remote.command("Mc2578400,4:00000000") == "OK"
                            assert master.remote.command("Mc2578404,4:00000000") == "OK"
                            assert master.remote.command("Mc202c0de,1:00") == "OK"
                            assert master.remote.command("Mc23b9328,1:0e") == "OK"
                            assert master.remote.command("Mc202c6a8,1:0e") == "OK"
                            assert master.remote.command("Mc253dc70,4:00000000") == "OK"
                            assert master.remote.command("Mc253dc74,4:01000000") == "OK"
                            assert master.remote.command("Mc202deec,1:01") == "OK"
                            assert master.remote.command("Mc202bd18,1:00") == "OK"
                            assert master.remote.command("Mc202c0ec,1:15") == "OK"
                            assert master.remote.command("Mc202df58,1:06") == "OK"
                            assert master.remote.command("Mc202c12e,1:06") == "OK"
                            assert master.remote.command("Mc202df14,1:00") == "OK"
                            assert master.remote.command("Mc202c0cc,1:00") == "OK"
                            assert master.remote.command("Mc202df18,4:00000000") == "OK"
                            assert master.remote.command("Mc202c0d0,4:00000000") == "OK"
                            assert master.remote.command("Mc202c4b2,1:ff") == "OK"
                            assert master.remote.command("Mc202c4cc,2:ffff") == "OK"
                            assert master.remote.command("Mc202c470,1:ff") == "OK"
                            assert master.remote.command("Mc202c450,1:ff") == "OK"
                            assert master.remote.command("Mc181ddbc,4:00000000") == "OK"
                            assert master.remote.command("Mc181dc10,4:00000000") == "OK"
                            assert master.remote.command("Mc181dc14,4:00000000") == "OK"
                            assert master.remote.command("Mc202be68,4:01000000") == "OK"
                            assert master.remote.command("Mc202bda4,4:01000000") == "OK"
                            assert master.remote.command("Mc202bde0,4:01000000") == "OK"
                            assert master.remote.command("Mc202bd85,1:01") == "OK"
                            step_res = call_fixture_smp(
                                master.remote, stop_reply, 0x104E4258, bytes(16), [0],
                                thumb=True, timeout=4.0,
                                enabled_bps=enabled["master"], hit_counts=counts["master"],
                            )
                            rec["action_call"] = step_res
                            disp_records.append(rec)
                            disp_last_idle_count = counts["master"].get(0x10200190, 0)
                            master.remote.send("c")
                            master.running = True
                            disp_step += 1
                            next_lcd_snapshot = 0.0
                            now_rel = time.monotonic() - start
                            disp_next_action_at = now_rel + 2.5
                            disp_max_wait_at = now_rel + 3.5
                        elif disp_step == 5:
                            # Step 5: After saving movie_disp0_wrap, configure 4K 60p DX crop (res=0x00, DX=1)
                            disp_last_fill_count = counts["master"].get(0x102DE4EC, 0)
                            assert master.remote.command("Mc202df58,1:00") == "OK"
                            assert master.remote.command("Mc202c12e,1:00") == "OK"
                            assert master.remote.command("Mc202df14,1:01") == "OK"
                            assert master.remote.command("Mc202c0cc,1:01") == "OK"
                            assert master.remote.command("Mc202df18,4:01000000") == "OK"
                            assert master.remote.command("Mc202c0d0,4:01000000") == "OK"
                            assert master.remote.command("Mc253dc28,4:01000000") == "OK"
                            assert master.remote.command("Mc202c0ec,1:15") == "OK"
                            assert master.remote.command("Mc202c4b2,1:ff") == "OK"
                            assert master.remote.command("Mc202c4cc,2:ffff") == "OK"
                            assert master.remote.command("Mc202c470,1:ff") == "OK"
                            assert master.remote.command("Mc202c450,1:ff") == "OK"
                            assert master.remote.command("Mc181ddbc,4:00000000") == "OK"
                            assert master.remote.command("Mc181dc10,4:00000000") == "OK"
                            assert master.remote.command("Mc181dc14,4:00000000") == "OK"
                            assert master.remote.command("Mc202be68,4:01000000") == "OK"
                            assert master.remote.command("Mc202bda4,4:01000000") == "OK"
                            assert master.remote.command("Mc202bde0,4:01000000") == "OK"
                            assert master.remote.command("Mc202bd85,1:01") == "OK"
                            step_res = call_fixture_smp(
                                master.remote, stop_reply, 0x104E4258, bytes(16), [0],
                                thumb=True, timeout=4.0,
                                enabled_bps=enabled["master"], hit_counts=counts["master"],
                            )
                            rec["action_call"] = step_res
                            disp_records.append(rec)
                            disp_last_idle_count = counts["master"].get(0x10200190, 0)
                            master.remote.send("c")
                            master.running = True
                            disp_step += 1
                            next_lcd_snapshot = 0.0
                            now_rel = time.monotonic() - start
                            disp_next_action_at = now_rel + 2.5
                            disp_max_wait_at = now_rel + 3.5
                        elif disp_step == 6:
                            # Step 6: After saving movie_4k60p_dx_crop, configure 1080 120p FX (res=0x0a, FX=0)
                            disp_last_fill_count = counts["master"].get(0x102DE4EC, 0)
                            assert master.remote.command("Mc202df58,1:0a") == "OK"
                            assert master.remote.command("Mc202c12e,1:0a") == "OK"
                            assert master.remote.command("Mc202df14,1:00") == "OK"
                            assert master.remote.command("Mc202c0cc,1:00") == "OK"
                            assert master.remote.command("Mc202df18,4:00000000") == "OK"
                            assert master.remote.command("Mc202c0d0,4:00000000") == "OK"
                            assert master.remote.command("Mc253dc28,4:00000000") == "OK"
                            assert master.remote.command("Mc202c0ec,1:15") == "OK"
                            assert master.remote.command("Mc202c4b2,1:ff") == "OK"
                            assert master.remote.command("Mc202c4cc,2:ffff") == "OK"
                            assert master.remote.command("Mc202c470,1:ff") == "OK"
                            assert master.remote.command("Mc202c450,1:ff") == "OK"
                            assert master.remote.command("Mc181ddbc,4:00000000") == "OK"
                            assert master.remote.command("Mc181dc10,4:00000000") == "OK"
                            assert master.remote.command("Mc181dc14,4:00000000") == "OK"
                            assert master.remote.command("Mc202be68,4:01000000") == "OK"
                            assert master.remote.command("Mc202bda4,4:01000000") == "OK"
                            assert master.remote.command("Mc202bde0,4:01000000") == "OK"
                            assert master.remote.command("Mc202bd85,1:01") == "OK"
                            step_res = call_fixture_smp(
                                master.remote, stop_reply, 0x104E4258, bytes(16), [0],
                                thumb=True, timeout=4.0,
                                enabled_bps=enabled["master"], hit_counts=counts["master"],
                            )
                            rec["action_call"] = step_res
                            disp_records.append(rec)
                            disp_last_idle_count = counts["master"].get(0x10200190, 0)
                            master.remote.send("c")
                            master.running = True
                            disp_step += 1
                            next_lcd_snapshot = 0.0
                            now_rel = time.monotonic() - start
                            disp_next_action_at = now_rel + 2.5
                            disp_max_wait_at = now_rel + 3.5
                        elif disp_step == 7:
                            # Step 7: After saving movie_1080_120p_hfr, configure 1080 30p x4★ slow motion (res=0x1c, mic=0, rem=449s)
                            disp_last_fill_count = counts["master"].get(0x102DE4EC, 0)
                            assert master.remote.command("Mc202df58,1:1c") == "OK"
                            assert master.remote.command("Mc202c12e,1:1c") == "OK"
                            assert master.remote.command("Mc202c0ec,1:00") == "OK"
                            assert master.remote.command("Mc202e05c,4:28da0600") == "OK"
                            assert master.remote.command("Mc202c148,2:c101") == "OK"
                            assert master.remote.command("Mc202c4b2,1:ff") == "OK"
                            assert master.remote.command("Mc202c4cc,2:ffff") == "OK"
                            assert master.remote.command("Mc202c470,1:ff") == "OK"
                            assert master.remote.command("Mc202c450,1:ff") == "OK"
                            assert master.remote.command("Mc181ddbc,4:00000000") == "OK"
                            assert master.remote.command("Mc181dc10,4:00000000") == "OK"
                            assert master.remote.command("Mc181dc14,4:00000000") == "OK"
                            assert master.remote.command("Mc202be68,4:01000000") == "OK"
                            assert master.remote.command("Mc202bda4,4:01000000") == "OK"
                            assert master.remote.command("Mc202bde0,4:01000000") == "OK"
                            assert master.remote.command("Mc202bd85,1:01") == "OK"
                            step_res = call_fixture_smp(
                                master.remote, stop_reply, 0x104E4258, bytes(16), [0],
                                thumb=True, timeout=4.0,
                                enabled_bps=enabled["master"], hit_counts=counts["master"],
                            )
                            rec["action_call"] = step_res
                            disp_records.append(rec)
                            disp_last_idle_count = counts["master"].get(0x10200190, 0)
                            master.remote.send("c")
                            master.running = True
                            disp_step += 1
                            next_lcd_snapshot = 0.0
                            now_rel = time.monotonic() - start
                            disp_next_action_at = now_rel + 2.5
                            disp_max_wait_at = now_rel + 3.5
                        else:
                            disp_records.append(rec)
                            master.remote.send("c")
                            master.running = True
                            liveview_signaled = True
                            next_lcd_snapshot = 0.0
                            info = dict(
                                host_seconds=round(elapsed_now, 4),
                                idle_hits=counts["master"].get(0x10200190, 0),
                                fill_hits=counts["master"].get(0x102DE4EC, 0),
                                lcd_frames=len(report["LCD_snapshot_timeline"]),
                                movie_disp_states=disp_records,
                            )
                            report["smart_stage5_liveview_ready"] = info
                            (run_root / "liveview-ui-ready.json").write_text(
                                json.dumps(info, indent=2), encoding="utf-8"
                            )
"""
assert target in src, "Failed to locate main while loop in natural_boot.py"
patched_src = src.replace(target, replacement, 1)
g = {
    "__name__": "__main__",
    "__file__": str(nb_path),
    "struct": struct,
    "call_fixture_smp": call_fixture_smp,
    "pause_at_boot_task": pause_at_boot_task,
    "write_chunked": write_chunked,
    "save_named_lcd": save_named_lcd,
    "send_key_action": send_key_action,
    "execute_key_sequence": execute_key_sequence,
}
g["PORT"] = PORT
exec(compile(patched_src, str(nb_path), "exec"), g)
