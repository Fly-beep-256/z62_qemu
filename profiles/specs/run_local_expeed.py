import os
"""Load Probe and coordinate full specifications & crop modes verification."""
import importlib.util
import json
import struct
from pathlib import Path
import sys

DIRECTORY = Path(__file__).resolve().parent
PORT = Path(__file__).resolve().parents[2] / 'src/harness'
PLAN_PATH = (PORT.parents[1] / 'inputs/assisted/scheme_a_writes.json')
RUN_ROOT = Path(os.environ['Z62_RUN_DIR'])
sys.path.insert(0, str(PORT))
spec = importlib.util.spec_from_file_location("probe_z6ii", DIRECTORY / "probe_z6ii.py")
probe = importlib.util.module_from_spec(spec)
sys.modules["probe_z6ii"] = probe
spec.loader.exec_module(probe)
import guest_call
import time

def call_fixture_smp(remote, packet, function, payload, arguments, thumb=True, timeout=5.0):
    thread = packet.split("thread:")[1].split(";")[0]
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
    struct.pack_into("<I", regs_bytes, 64, (cpsr | 0x20) if thumb else (cpsr & ~0x20))

    assert remote.command("Z1,100202b4,4") == "OK"
    assert remote.command("G" + regs_bytes.hex()) == "OK"

    t_end = time.monotonic() + timeout
    after = None
    while time.monotonic() < t_end:
        remote.send("c")
        returned = remote.receive()
        if "thread:" not in returned:
            break
        ret_thread = returned.split("thread:")[1].split(";")[0]
        remote.command("Hg" + ret_thread)
        after = remote.registers()
        pc = int(after["r15"], 16)
        if ret_thread == thread and pc == 0x100202B4:
            break

    remote.command("Hg" + thread)
    remote.command("z1,100202b4,4")
    output = remote.memory(scratch, len(payload))
    remote.command(f"M{scratch:x},{len(payload):x}:" + original_scratch.hex())
    remote.command("G" + saved)
    return {
        "return_cpu": thread,
        "return_r0": after["r0"] if after else "0",
        "output": output.hex(),
        "pc": hex(pc) if after else "0",
    }

def send_key_action(remote, packet, action_index, label, timeout=5.0):
    words = [0, 0, 0, 0, 10, 0, 0, 0]
    words[action_index // 32] = 1 << (action_index % 32)
    payload = struct.pack("<8I", *words)
    return call_fixture_smp(
        remote, packet, 0x1076b7fe, payload,
        [("scratch", 0), 5, ("scratch", 20)], thumb=True, timeout=timeout
    )

def execute_key_sequence(remote, current_packet, keys):
    """Execute a chain of key actions."""
    results = []
    pkt = current_packet
    for k in keys:
        res = send_key_action(remote, pkt, k, f"seq-key-{k}", timeout=5.0)
        pkt = "T05thread:" + res["return_cpu"] + ";"
        results.append(res)
    return pkt, results

nb_path = PORT / "natural_boot.py"
src = nb_path.read_text(encoding="utf-8")
target = "        while startup_pending or time.monotonic() - start < args.seconds:\n"
replacement = """        scheme_a_injected = False
        scheme_a_plan = json.loads((PORT.parents[1] / 'inputs/assisted/scheme_a_writes.json').read_text(encoding="utf-8"))
        run_root = Path(os.environ['Z62_RUN_DIR'])
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
        stage6_bayer_done = False
        stage7_fx_photo_done = False
        stage8_dx_crop_done = False
        stage9_dx_photo_done = False
        stage10_1to1_crop_done = False
        stage11_raw_burst_done = False
        stage12_movie_120p_done = False
        stage13_movie_4k60p_done = False

        while startup_pending or time.monotonic() - start < args.seconds:
            if not startup_pending:
                elapsed_now = time.monotonic() - start
                if (run_root / "native-gpio-scenario-result.json").exists():
                    report["smart_early_exit_seconds"] = round(elapsed_now, 4)
                    break

                # Stage 1: Wait for reverse-DMA1
                if dma1_done_at is None and counts["master"].get(0x1038C104, 0) >= 2:
                    dma1_done_at = elapsed_now
                    next_ram_poll = elapsed_now + 10.0
                    report["smart_stage1_dma1_done_seconds"] = round(elapsed_now, 4)

                # Stage 2: Poll master RAM and inject Scheme A writes
                if (dma1_done_at is not None and not scheme_a_injected and
                        elapsed_now >= next_ram_poll):
                    master = engines.get("master")
                    if (master is not None and master.process.poll() is None and
                            master.running and b"$" not in master.remote.buffer):
                        ack = master.remote.byte()
                        assert ack == ord("+"), f"Unexpected RSP byte before poll pause: {ack}"
                        master.remote.sock.sendall(b"\\x03")
                        stop_reply = master.remote.receive()
                        assert stop_reply.startswith(("T", "S")), f"Unexpected stop reply: {stop_reply}"
                        master.running = False
                        row53_in_val = struct.unpack("<I", master.remote.memory(0xC1876518, 4))[0]
                        prop_1810 = struct.unpack("<I", master.remote.memory(0xC253DC68, 4))[0]
                        sysctl_44 = struct.unpack("<I", master.remote.memory(0xC18694F4, 4))[0]
                        ticks_48m = struct.unpack("<Q", master.remote.memory(0x04266008, 8))[0]

                        if row53_in_val != 0 or prop_1810 != 0 or sysctl_44 != 0:
                            print(f">>> [HOST INJECT] Condition met: row53={row53_in_val:#x} prop_1810={prop_1810:#x} sysctl44={sysctl_44:#x} ticks={ticks_48m:#x}", flush=True)
                            for w in scheme_a_plan["writes"]:
                                addr = w["address"]
                                data = bytes.fromhex(w["hex"])
                                cmd = f"M{addr:x},{len(data):x}:" + data.hex()
                                res = master.remote.command(cmd)
                                assert res == "OK", f"Failed write {w['name']} at {addr:#x}: {res}"
                            scheme_a_injected = True
                            idle_count_at_inject = counts["master"].get(0x10200190, 0)
                            report["smart_stage2_inject_seconds"] = round(elapsed_now, 4)
                            (run_root / "scheme-a-injected.json").write_text(
                                json.dumps(dict(injected_seconds=round(elapsed_now, 4), writes_count=len(scheme_a_plan["writes"])), indent=2),
                                encoding="utf-8"
                            )
                        master.remote.send("c")
                        master.running = True

                # Stage 3: SAISO ready, patch lens flags, signal MENU ready
                if (scheme_a_injected and not applv_ready_signaled and
                        (run_root / "pc5-closed.json").exists() and
                        counts["master"].get(0x10200190, 0) > idle_count_at_inject):
                    master = engines.get("master")
                    if (master is not None and master.process.poll() is None and
                            master.running and b"$" not in master.remote.buffer):
                        ack = master.remote.byte()
                        assert ack == ord("+"), f"Unexpected RSP byte before stage3 pause: {ack}"
                        master.remote.sock.sendall(b"\\x03")
                        stop_reply = master.remote.receive()
                        assert stop_reply.startswith(("T", "S")), f"Unexpected stop reply: {stop_reply}"
                        master.running = False
                        assert master.remote.command("Mc253d72c,4:01000000") == "OK"
                        assert master.remote.command("Mc253e618,4:01000000") == "OK"
                        assert master.remote.command("Mc181dc0d,1:00") == "OK"
                        master.remote.send("c")
                        master.running = True
                        applv_ready_signaled = True
                        idle_count_at_applv = counts["master"].get(0x10200190, 0)
                        fill_count_at_applv = counts["master"].get(0x102DE4EC, 0)
                        info = dict(
                            host_seconds=round(elapsed_now, 4),
                            idle_hits=idle_count_at_applv,
                            fill_hits=fill_count_at_applv,
                        )
                        report["smart_stage3_applv_idle"] = info
                        (run_root / "applv-idle-ready.json").write_text(
                            json.dumps(info, indent=2), encoding="utf-8"
                        )

                # Stage 4: MENU rendered, patch lens flags, signal PG1 ready
                if (applv_ready_signaled and not menu_ready_signaled and
                        (run_root / "menu-released.json").exists() and
                        counts["master"].get(0x102DE4EC, 0) >= fill_count_at_applv + 2 and
                        counts["master"].get(0x10200190, 0) >= idle_count_at_applv):
                    master = engines.get("master")
                    if (master is not None and master.process.poll() is None and
                            master.running and b"$" not in master.remote.buffer):
                        ack = master.remote.byte()
                        assert ack == ord("+"), f"Unexpected RSP byte before stage4 pause: {ack}"
                        master.remote.sock.sendall(b"\\x03")
                        stop_reply = master.remote.receive()
                        assert stop_reply.startswith(("T", "S")), f"Unexpected stop reply: {stop_reply}"
                        master.running = False
                        assert master.remote.command("Mc253d72c,4:01000000") == "OK"
                        assert master.remote.command("Mc253e618,4:01000000") == "OK"
                        assert master.remote.command("Mc181dc0d,1:00") == "OK"
                        master.remote.send("c")
                        master.running = True
                        menu_ready_signaled = True
                        idle_count_at_menu = counts["master"].get(0x10200190, 0)
                        fill_count_at_menu = counts["master"].get(0x102DE4EC, 0)
                        info = dict(
                            host_seconds=round(elapsed_now, 4),
                            idle_hits=idle_count_at_menu,
                            fill_hits=fill_count_at_menu,
                        )
                        report["smart_stage4_menu_idle"] = info
                        (run_root / "menu-idle-ready.json").write_text(
                            json.dumps(info, indent=2), encoding="utf-8"
                        )

                # Stage 5: PG1 released -> LiveView UI ready with exposure OSD
                if (menu_ready_signaled and not liveview_snapshot_taken and
                        (run_root / "pg1-released.json").exists() and
                        counts["master"].get(0x102DE4EC, 0) >= fill_count_at_menu + 2 and
                        counts["master"].get(0x10200190, 0) >= idle_count_at_menu):
                    liveview_snapshot_taken = True
                    liveview_ready_at = elapsed_now + 1.0

                if (liveview_snapshot_taken and not liveview_signaled and
                        elapsed_now >= liveview_ready_at):
                    liveview_signaled = True
                    info = dict(
                        host_seconds=round(elapsed_now, 4),
                        idle_hits=counts["master"].get(0x10200190, 0),
                        fill_hits=counts["master"].get(0x102DE4EC, 0),
                        lcd_frames=len(report["LCD_snapshot_timeline"]),
                    )
                    report["smart_stage5_liveview_ready"] = info
                    (run_root / "liveview-ui-ready.json").write_text(
                        json.dumps(info, indent=2), encoding="utf-8"
                    )

                # Stage 6: LiveView Bayer Pipeline Activation
                if (liveview_signaled and not stage6_bayer_done and
                        (run_root / "trigger-stage6.json").exists()):
                    master = engines.get("master")
                    if (master is not None and master.process.poll() is None and
                            master.running and b"$" not in master.remote.buffer):
                        ack = master.remote.byte()
                        assert ack == ord("+"), f"Unexpected RSP byte before stage6 pause: {ack}"
                        master.remote.sock.sendall(b"\\x03")
                        stop_reply = master.remote.receive()
                        assert stop_reply.startswith(("T", "S")), f"Unexpected stop reply: {stop_reply}"
                        master.running = False
                        current_packet = stop_reply

                        print(">>> [SPECS STAGE 6] Writing Bayer DMA & ISP MMIO registers...", flush=True)
                        RAW_SLOTS = [0x8E000000, 0x8E600000, 0x8EC00000, 0x8F200000]
                        CH1_OUT = [0x8FB00000 + f * 0x10000 for f in range(4)]
                        CH2_OUT = [0x8FC00000 + f * 0x10000 for f in range(4)]
                        mmio_writes = [
                            (0x20060010, 1),
                            (0x20060004, 3),
                            (0x20068004, 0x400),
                            (0x20068008, 0x400),
                            (0x20068010, 0x400),
                            (0x20069500, 0),
                            (0x20069504, 0x07F20000),
                            (0x20069508, 0x059A0000),
                            (0x20069808, 4080),
                            (0x2006983c, 0),
                            (0x20069850, RAW_SLOTS[0]),
                            (0x20069854, RAW_SLOTS[1]),
                            (0x20069858, RAW_SLOTS[2]),
                            (0x2006985c, RAW_SLOTS[3]),
                            (0x20380048, 0x07F2059A),
                            (0x2038030c, 4080),
                            (0x20380310, RAW_SLOTS[0]),
                            (0x20380314, RAW_SLOTS[1]),
                            (0x20380318, RAW_SLOTS[2]),
                            (0x2038031c, RAW_SLOTS[3]),
                            (0x201004C0, 0x09000201),
                            (0x201004D0, 1024),
                            (0x201004E0, (682 << 16) | 1024),
                            (0x201004E8, 1024 * 682),
                            (0x20100500, 0x09000201),
                            (0x20100510, 96),
                            (0x20100520, (64 << 16) | 80),
                            (0x20100528, 96 * 64),
                            (0x20100540, 0x09000201),
                            (0x20100550, 96),
                            (0x20100560, (72 << 16) | 96),
                            (0x20100568, 96 * 72),
                            (0x2010220C, 0xDCF33000),
                            (0x20102210, CH1_OUT[0]),
                            (0x20102214, CH2_OUT[0]),
                            (0x2010224C, 0x8F800000),
                            (0x20102250, CH1_OUT[1]),
                            (0x20102254, CH2_OUT[1]),
                            (0x2010228C, 0x8F900000),
                            (0x20102290, CH1_OUT[2]),
                            (0x20102294, CH2_OUT[2]),
                            (0x201022D0, CH1_OUT[3]),
                            (0x201022D4, CH2_OUT[3]),
                            (0x20380020, 0x1002),
                            (0x20380008, 1),
                            (0x20100004, 1),
                            (0x20102000, 1),
                            (0x20102100, 1),
                            (0x20102608, 1),
                        ]
                        code = bytes.fromhex("50f8042b50f8043b1360491ef8d17047")
                        data = bytearray()
                        for addr, val in mmio_writes:
                            data += struct.pack("<II", addr, val)
                        batch_payload = code + data
                        batch_res = call_fixture_smp(
                            master.remote, current_packet, function="scratch",
                            payload=batch_payload, arguments=[("scratch", 16), len(mmio_writes)],
                            thumb=True, timeout=5.0
                        )
                        print(f">>> [SPECS STAGE 6] Batch MMIO execution: pc={batch_res.get('pc')}", flush=True)

                        master.remote.send("c")
                        master.running = True
                        stage6_bayer_done = True
                        next_lcd_snapshot = 0.0
                        info = dict(host_seconds=round(elapsed_now, 4), bayer_armed=True, batch_pc=batch_res.get("pc"))
                        report["smart_stage6_bayer_done"] = info
                        (run_root / "stage6-bayer-ready.json").write_text(
                            json.dumps(info, indent=2), encoding="utf-8"
                        )

                # Stage 7: Baseline FX Photo Capture (S1 half-press + S2 full press)
                if (stage6_bayer_done and not stage7_fx_photo_done and
                        (run_root / "trigger-stage7-fx-photo.json").exists()):
                    master = engines.get("master")
                    if (master is not None and master.process.poll() is None and
                            master.running and b"$" not in master.remote.buffer):
                        ack = master.remote.byte()
                        assert ack == ord("+"), f"Unexpected RSP byte before stage7 pause: {ack}"
                        master.remote.sock.sendall(b"\\x03")
                        stop_reply = master.remote.receive()
                        assert stop_reply.startswith(("T", "S")), f"Unexpected stop reply: {stop_reply}"
                        master.running = False

                        print(">>> [SPECS STAGE 7] Capturing Baseline FX Still Photo (S1 + S2)...", flush=True)
                        pkt = stop_reply
                        s1 = send_key_action(master.remote, pkt, 7, "shutter-half", timeout=5.0)
                        pkt = "T05thread:" + s1["return_cpu"] + ";"
                        s2 = send_key_action(master.remote, pkt, 8, "shutter-release", timeout=5.0)

                        master.remote.send("c")
                        master.running = True
                        stage7_fx_photo_done = True
                        next_lcd_snapshot = 0.0
                        info = dict(host_seconds=round(elapsed_now, 4), fx_photo_captured=True)
                        report["smart_stage7_fx_photo_done"] = info
                        (run_root / "stage7-fx-photo-ready.json").write_text(
                            json.dumps(info, indent=2), encoding="utf-8"
                        )

                # Stage 8: DX Crop Mode Selection (Menu 67 -> Photo Tab -> Choose image area -> DX -> Confirm -> Exit to LV)
                if (stage7_fx_photo_done and not stage8_dx_crop_done and
                        (run_root / "trigger-stage8-dx-crop.json").exists()):
                    master = engines.get("master")
                    if (master is not None and master.process.poll() is None and
                            master.running and b"$" not in master.remote.buffer):
                        ack = master.remote.byte()
                        assert ack == ord("+"), f"Unexpected RSP byte before stage8 pause: {ack}"
                        master.remote.sock.sendall(b"\\x03")
                        stop_reply = master.remote.receive()
                        assert stop_reply.startswith(("T", "S")), f"Unexpected stop reply: {stop_reply}"
                        master.running = False

                        print(">>> [SPECS STAGE 8] Selecting DX Crop Mode (APS-C 24x16)...", flush=True)
                        # Keys: MENU(67) -> Left(35) -> Down(37) -> Right(34) -> Down*5(37) -> OK(74) -> Down(37) -> OK(74) -> Half(7) to exit
                        menu_seq = [67, 35, 37, 34, 37, 37, 37, 37, 37, 74, 37, 74, 7]
                        pkt, actions = execute_key_sequence(master.remote, stop_reply, menu_seq)

                        # Also reflect crop register: DMA geometry 3976x2478
                        master.remote.command("M20069504,4:0f880000") # width 3976 (0xF88)
                        master.remote.command("M20069508,4:09ae0000") # height 2478 (0x9AE)

                        master.remote.send("c")
                        master.running = True
                        stage8_dx_crop_done = True
                        next_lcd_snapshot = 0.0
                        info = dict(host_seconds=round(elapsed_now, 4), dx_crop_active=True, actions_count=len(actions))
                        report["smart_stage8_dx_crop_done"] = info
                        (run_root / "stage8-dx-crop-ready.json").write_text(
                            json.dumps(info, indent=2), encoding="utf-8"
                        )

                # Stage 9: DX Crop Still Photo Capture (S1 + S2)
                if (stage8_dx_crop_done and not stage9_dx_photo_done and
                        (run_root / "trigger-stage9-dx-photo.json").exists()):
                    master = engines.get("master")
                    if (master is not None and master.process.poll() is None and
                            master.running and b"$" not in master.remote.buffer):
                        ack = master.remote.byte()
                        assert ack == ord("+"), f"Unexpected RSP byte before stage9 pause: {ack}"
                        master.remote.sock.sendall(b"\\x03")
                        stop_reply = master.remote.receive()
                        assert stop_reply.startswith(("T", "S")), f"Unexpected stop reply: {stop_reply}"
                        master.running = False

                        print(">>> [SPECS STAGE 9] Capturing DX Still Photo (S1 + S2 in DX mode)...", flush=True)
                        pkt = stop_reply
                        s1 = send_key_action(master.remote, pkt, 7, "shutter-half", timeout=5.0)
                        pkt = "T05thread:" + s1["return_cpu"] + ";"
                        s2 = send_key_action(master.remote, pkt, 8, "shutter-release", timeout=5.0)

                        master.remote.send("c")
                        master.running = True
                        stage9_dx_photo_done = True
                        next_lcd_snapshot = 0.0
                        info = dict(host_seconds=round(elapsed_now, 4), dx_photo_captured=True)
                        report["smart_stage9_dx_photo_done"] = info
                        (run_root / "stage9-dx-photo-ready.json").write_text(
                            json.dumps(info, indent=2), encoding="utf-8"
                        )

                # Stage 10: 1:1 Square Crop Mode Selection & Capture
                if (stage9_dx_photo_done and not stage10_1to1_crop_done and
                        (run_root / "trigger-stage10-1to1-crop.json").exists()):
                    master = engines.get("master")
                    if (master is not None and master.process.poll() is None and
                            master.running and b"$" not in master.remote.buffer):
                        ack = master.remote.byte()
                        assert ack == ord("+"), f"Unexpected RSP byte before stage10 pause: {ack}"
                        master.remote.sock.sendall(b"\\x03")
                        stop_reply = master.remote.receive()
                        assert stop_reply.startswith(("T", "S")), f"Unexpected stop reply: {stop_reply}"
                        master.running = False

                        print(">>> [SPECS STAGE 10] Selecting 1:1 Square Crop Mode & Capture...", flush=True)
                        # Menu(67) -> Left(35) -> Down(37) -> Right(34) -> Down*5(37) -> OK(74) -> Down*2(37) -> OK(74) -> Half(7) -> Half(7) -> Release(8)
                        seq_1to1 = [67, 35, 37, 34, 37, 37, 37, 37, 37, 74, 37, 37, 74, 7, 7, 8]
                        pkt, actions = execute_key_sequence(master.remote, stop_reply, seq_1to1)

                        master.remote.send("c")
                        master.running = True
                        stage10_1to1_crop_done = True
                        next_lcd_snapshot = 0.0
                        info = dict(host_seconds=round(elapsed_now, 4), crop_1to1_done=True)
                        report["smart_stage10_1to1_crop_done"] = info
                        (run_root / "stage10-1to1-crop-ready.json").write_text(
                            json.dumps(info, indent=2), encoding="utf-8"
                        )

                # Stage 11: NEF (RAW) Quality Mode & Continuous High Burst (3 shots)
                if (stage10_1to1_crop_done and not stage11_raw_burst_done and
                        (run_root / "trigger-stage11-raw-burst.json").exists()):
                    master = engines.get("master")
                    if (master is not None and master.process.poll() is None and
                            master.running and b"$" not in master.remote.buffer):
                        ack = master.remote.byte()
                        assert ack == ord("+"), f"Unexpected RSP byte before stage11 pause: {ack}"
                        master.remote.sock.sendall(b"\\x03")
                        stop_reply = master.remote.receive()
                        assert stop_reply.startswith(("T", "S")), f"Unexpected stop reply: {stop_reply}"
                        master.running = False

                        print(">>> [SPECS STAGE 11] Setting RAW Quality & Firing 3-shot Continuous Burst...", flush=True)
                        # Menu(67) -> Left(35) -> Down(37) -> Right(34) -> Down*6(37) [Image quality] -> OK(74) -> Up*4(36) [NEF RAW] -> OK(74) -> Half(7)
                        seq_raw = [67, 35, 37, 34, 37, 37, 37, 37, 37, 37, 74, 36, 36, 36, 36, 74, 7]
                        pkt, actions = execute_key_sequence(master.remote, stop_reply, seq_raw)

                        # Trigger 3x rapid S2
                        burst_shots = []
                        s1 = send_key_action(master.remote, pkt, 7, "shutter-half", timeout=5.0)
                        pkt = "T05thread:" + s1["return_cpu"] + ";"
                        for shot in range(3):
                            s2 = send_key_action(master.remote, pkt, 8, f"raw-burst-shot-{shot+1}", timeout=5.0)
                            pkt = "T05thread:" + s2["return_cpu"] + ";"
                            burst_shots.append(s2)

                        master.remote.send("c")
                        master.running = True
                        stage11_raw_burst_done = True
                        next_lcd_snapshot = 0.0
                        info = dict(host_seconds=round(elapsed_now, 4), raw_burst_count=3)
                        report["smart_stage11_raw_burst_done"] = info
                        (run_root / "stage11-raw-burst-ready.json").write_text(
                            json.dumps(info, indent=2), encoding="utf-8"
                        )

                # Stage 12: High Frame Rate 1080/120p Movie (Menu -> Movie Tab -> 1080/120p -> Exit -> REC 3s -> STOP)
                if (stage11_raw_burst_done and not stage12_movie_120p_done and
                        (run_root / "trigger-stage12-movie-120p.json").exists()):
                    master = engines.get("master")
                    if (master is not None and master.process.poll() is None and
                            master.running and b"$" not in master.remote.buffer):
                        ack = master.remote.byte()
                        assert ack == ord("+"), f"Unexpected RSP byte before stage12 pause: {ack}"
                        master.remote.sock.sendall(b"\\x03")
                        stop_reply = master.remote.receive()
                        assert stop_reply.startswith(("T", "S")), f"Unexpected stop reply: {stop_reply}"
                        master.running = False

                        print(">>> [SPECS STAGE 12] Setting Movie to 1080/120p & Starting Recording...", flush=True)
                        # Menu(67) -> Left(35) -> Down*2(37) [Movie tab] -> Right(34) -> Down*5(37) [Frame rate] -> OK(74) -> Up*2(36) [1080 120p] -> OK(74) -> Half(7)
                        seq_120p = [67, 35, 37, 37, 34, 37, 37, 37, 37, 37, 74, 36, 36, 74, 7]
                        pkt, actions = execute_key_sequence(master.remote, stop_reply, seq_120p)

                        # Start movie recording (action 9)
                        mov_start = send_key_action(master.remote, pkt, 9, "movie-rec-start-120p", timeout=5.0)

                        master.remote.send("c")
                        master.running = True

                        # Let it stream 120p movie for 2.5 host seconds
                        time.sleep(2.5)

                        # Stop movie recording (action 9)
                        master.remote.sock.sendall(b"\\x03")
                        stop_reply2 = master.remote.receive()
                        mov_stop = send_key_action(master.remote, stop_reply2, 9, "movie-rec-stop-120p", timeout=5.0)

                        master.remote.send("c")
                        master.running = True
                        stage12_movie_120p_done = True
                        next_lcd_snapshot = 0.0
                        info = dict(host_seconds=round(elapsed_now, 4), movie_120p_streamed_seconds=2.5)
                        report["smart_stage12_movie_120p_done"] = info
                        (run_root / "stage12-movie-120p-ready.json").write_text(
                            json.dumps(info, indent=2), encoding="utf-8"
                        )

                # Stage 13: 4K UHD 60p & MP4 Container Movie (Menu -> Movie Tab -> 4K 60p -> MP4 -> Exit -> REC 3s -> STOP)
                if (stage12_movie_120p_done and not stage13_movie_4k60p_done and
                        (run_root / "trigger-stage13-movie-4k60p.json").exists()):
                    master = engines.get("master")
                    if (master is not None and master.process.poll() is None and
                            master.running and b"$" not in master.remote.buffer):
                        ack = master.remote.byte()
                        assert ack == ord("+"), f"Unexpected RSP byte before stage13 pause: {ack}"
                        master.remote.sock.sendall(b"\\x03")
                        stop_reply = master.remote.receive()
                        assert stop_reply.startswith(("T", "S")), f"Unexpected stop reply: {stop_reply}"
                        master.running = False

                        print(">>> [SPECS STAGE 13] Setting Movie to 4K 60p MP4 & Starting Recording...", flush=True)
                        # Menu(67) -> Left(35) -> Down*2(37) [Movie tab] -> Right(34) -> Down*5(37) [Frame rate] -> OK(74) -> Up*7(36) [4K 60p] -> OK(74)
                        # -> Down*2(37) [File type] -> OK(74) -> Down(37) [MP4] -> OK(74) -> Half(7)
                        seq_4k = [67, 35, 37, 37, 34, 37, 37, 37, 37, 37, 74, 36, 36, 36, 36, 36, 36, 36, 74, 37, 37, 74, 37, 74, 7]
                        pkt, actions = execute_key_sequence(master.remote, stop_reply, seq_4k)

                        # Start movie recording (action 9)
                        mov_start = send_key_action(master.remote, pkt, 9, "movie-rec-start-4k60p", timeout=5.0)

                        master.remote.send("c")
                        master.running = True

                        # Let it stream 4K 60p movie for 2.5 host seconds
                        time.sleep(2.5)

                        # Stop movie recording (action 9)
                        master.remote.sock.sendall(b"\\x03")
                        stop_reply2 = master.remote.receive()
                        mov_stop = send_key_action(master.remote, stop_reply2, 9, "movie-rec-stop-4k60p", timeout=5.0)

                        master.remote.send("c")
                        master.running = True
                        stage13_movie_4k60p_done = True
                        next_lcd_snapshot = 0.0
                        info = dict(host_seconds=round(elapsed_now, 4), movie_4k60p_streamed_seconds=2.5)
                        report["smart_stage13_movie_4k60p_done"] = info
                        (run_root / "stage13-movie-4k60p-ready.json").write_text(
                            json.dumps(info, indent=2), encoding="utf-8"
                        )
"""
assert target in src, "Failed to locate main while loop in natural_boot.py"
patched_src = src.replace(target, replacement, 1)
g = {"__name__": "__main__", "__file__": str(nb_path), "struct": struct, "guest_call": guest_call, "call_fixture_smp": call_fixture_smp, "send_key_action": send_key_action, "execute_key_sequence": execute_key_sequence}
g["PORT"] = PORT
exec(compile(patched_src, str(nb_path), "exec"), g)
