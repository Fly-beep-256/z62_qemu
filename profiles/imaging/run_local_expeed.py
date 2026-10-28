import os
"""Load Probe and coordinate 8-stage verification: SAISO, Bayer LiveView, Photo Capture, Movie Rec."""
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
        stage7_photo_done = False
        stage8_movie_started = False
        stage8_movie_done = False

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
                                data = bytes.fromhex(item["hex"])
                                for off in range(0, len(data), 512):
                                    part = data[off:off + 512]
                                    res = master.remote.command(f"M{addr + off:x},{len(part):x}:" + part.hex())
                                    assert res == "OK", f"RSP write failed at {addr + off:#x}: {res}"
                                written_total += len(data)
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
                        counts["master"].get(0x102DE4EC, 0) >= fill_count_at_applv + 6 and
                        counts["master"].get(0x10200190, 0) > idle_count_at_applv):
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
                        counts["master"].get(0x10200190, 0) > idle_count_at_menu):
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

                # Stage 6: LiveView Bayer Pipeline Activation & Background Rendering
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

                        # MMIO Hardware Config: Arm Bayer DMA and ISP to render into LCD Background (0xDCF33000 / 0xDCFDD800)
                        print(">>> [IMAGING STAGE 6] Writing Bayer DMA & ISP MMIO registers...", flush=True)
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
                            (0x201022CC, 0x8FA00000),
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
                        print(f">>> [IMAGING STAGE 6] Batch MMIO execution: pc={batch_res.get('pc')}", flush=True)

                        master.remote.send("c")
                        master.running = True
                        stage6_bayer_done = True
                        next_lcd_snapshot = 0.0
                        info = dict(host_seconds=round(elapsed_now, 4), bayer_armed=True, batch_pc=batch_res.get("pc"))
                        report["smart_stage6_bayer_done"] = info
                        (run_root / "stage6-bayer-ready.json").write_text(
                            json.dumps(info, indent=2), encoding="utf-8"
                        )

                # Stage 7: Still Photo (拍照) Trigger
                if (stage6_bayer_done and not stage7_photo_done and
                        (run_root / "trigger-stage7.json").exists()):
                    master = engines.get("master")
                    if (master is not None and master.process.poll() is None and
                            master.running and b"$" not in master.remote.buffer):
                        ack = master.remote.byte()
                        assert ack == ord("+"), f"Unexpected RSP byte before stage7 pause: {ack}"
                        master.remote.sock.sendall(b"\\x03")
                        stop_reply = master.remote.receive()
                        assert stop_reply.startswith(("T", "S")), f"Unexpected stop reply: {stop_reply}"
                        master.running = False

                        print(">>> [IMAGING STAGE 7] Dispatching Shutter S1 half-press then S2 full-press...", flush=True)
                        current_packet = stop_reply
                        try:
                            s1_res = send_key_action(master.remote, current_packet, 7, "shutter-half", timeout=5.0)
                            current_packet = "T05thread:" + s1_res["return_cpu"] + ";"
                            print(f">>> [IMAGING STAGE 7] S1 half-press res: {s1_res.get('pc')}", flush=True)
                            report["shutter_s1_action"] = s1_res

                            s2_res = send_key_action(master.remote, current_packet, 8, "shutter-release", timeout=5.0)
                            print(f">>> [IMAGING STAGE 7] S2 release res: {s2_res.get('pc')}", flush=True)
                            report["shutter_s2_action"] = s2_res
                        except Exception as e:
                            print(f">>> Shutter release fixture note: {e}", flush=True)

                        master.remote.send("c")
                        master.running = True
                        stage7_photo_done = True
                        next_lcd_snapshot = 0.0
                        info = dict(host_seconds=round(elapsed_now, 4), photo_triggered=True)
                        report["smart_stage7_photo_done"] = info
                        (run_root / "stage7-photo-ready.json").write_text(
                            json.dumps(info, indent=2), encoding="utf-8"
                        )

                # Stage 8: Movie Recording (录像) Start / Stop
                if (stage7_photo_done and not stage8_movie_started and
                        (run_root / "trigger-stage8-start.json").exists()):
                    master = engines.get("master")
                    if (master is not None and master.process.poll() is None and
                            master.running and b"$" not in master.remote.buffer):
                        ack = master.remote.byte()
                        assert ack == ord("+"), f"Unexpected RSP byte before stage8 start pause: {ack}"
                        master.remote.sock.sendall(b"\\x03")
                        stop_reply = master.remote.receive()
                        assert stop_reply.startswith(("T", "S")), f"Unexpected stop reply: {stop_reply}"
                        master.running = False

                        print(">>> [IMAGING STAGE 8] Dispatching Movie REC Start (action 9)...", flush=True)
                        try:
                            mov_res = send_key_action(master.remote, stop_reply, 9, "movie-rec-start", timeout=5.0)
                            report["movie_start_action"] = mov_res
                            print(f">>> [IMAGING STAGE 8] Movie REC start res: {mov_res.get('pc')}", flush=True)
                        except Exception as e:
                            print(f">>> Movie REC start note: {e}", flush=True)

                        master.remote.send("c")
                        master.running = True
                        stage8_movie_started = True
                        next_lcd_snapshot = 0.0
                        info = dict(host_seconds=round(elapsed_now, 4), movie_started=True)
                        report["smart_stage8_movie_started"] = info
                        (run_root / "stage8-movie-started.json").write_text(
                            json.dumps(info, indent=2), encoding="utf-8"
                        )

                if (stage8_movie_started and not stage8_movie_done and
                        (run_root / "trigger-stage8-stop.json").exists()):
                    master = engines.get("master")
                    if (master is not None and master.process.poll() is None and
                            master.running and b"$" not in master.remote.buffer):
                        ack = master.remote.byte()
                        assert ack == ord("+"), f"Unexpected RSP byte before stage8 stop pause: {ack}"
                        master.remote.sock.sendall(b"\\x03")
                        stop_reply = master.remote.receive()
                        assert stop_reply.startswith(("T", "S")), f"Unexpected stop reply: {stop_reply}"
                        master.running = False

                        print(">>> [IMAGING STAGE 8] Dispatching Movie REC Stop (action 9)...", flush=True)
                        try:
                            stop_res = send_key_action(master.remote, stop_reply, 9, "movie-rec-stop", timeout=5.0)
                            report["movie_stop_action"] = stop_res
                            print(f">>> [IMAGING STAGE 8] Movie REC stop res: {stop_res.get('pc')}", flush=True)
                        except Exception as e:
                            print(f">>> Movie REC stop note: {e}", flush=True)

                        master.remote.send("c")
                        master.running = True
                        stage8_movie_done = True
                        next_lcd_snapshot = 0.0
                        info = dict(host_seconds=round(elapsed_now, 4), movie_completed=True)
                        report["smart_stage8_movie_done"] = info
                        (run_root / "stage8-movie-ready.json").write_text(
                            json.dumps(info, indent=2), encoding="utf-8"
                        )
"""
assert target in src, "Failed to locate main while loop in natural_boot.py"
patched_src = src.replace(target, replacement, 1)
g = {"__name__": "__main__", "__file__": str(nb_path), "struct": struct, "guest_call": guest_call, "call_fixture_smp": call_fixture_smp, "send_key_action": send_key_action}
g["PORT"] = PORT
exec(compile(patched_src, str(nb_path), "exec"), g)
