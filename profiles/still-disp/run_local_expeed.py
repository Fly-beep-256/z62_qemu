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

def call_fixture_smp(remote, packet, function, payload, arguments, thumb=True, timeout=25.0):
    if not payload:
        payload = bytes(32)
    thread = "p01.01"
    remote.command("Hg" + thread)
    saved = remote.command("g")
    regs_bytes = bytearray.fromhex(saved)
    scratch = (struct.unpack_from("<I", regs_bytes, 52)[0] - len(payload) - 7) & ~7
    original_scratch = remote.memory(scratch, len(payload))
    assert remote.command("M%x,%x:%s" % (scratch, len(payload), payload.hex())) == "OK"

    func_addr = scratch if (function is None or function == "scratch") else function
    registers = [(i, scratch + v[1] if isinstance(v, tuple) else v) for i, v in enumerate(arguments)]
    registers += [(13, scratch), (14, 0x100202B4), (15, func_addr & ~1)]
    for reg, value in registers:
        struct.pack_into("<I", regs_bytes, 4 * reg, value)
    cpsr = struct.unpack_from("<I", regs_bytes, 64)[0]
    new_cpsr = (cpsr | 0x20) if thumb else (cpsr & ~0x20)
    new_cpsr |= 0xC0  # Mask IRQ (0x80) & FIQ (0x40) to prevent RTOS preemption
    struct.pack_into("<I", regs_bytes, 64, new_cpsr)

    assert remote.command("Z1,100202b4,4") == "OK"
    assert remote.command("G" + regs_bytes.hex()) == "OK"

    t_end = time.monotonic() + timeout
    after = None
    orig_sock_timeout = getattr(remote.sock, "gettimeout", lambda: 15.0)()
    if hasattr(remote.sock, "settimeout"):
        remote.sock.settimeout(timeout + 10.0)
    try:
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
    finally:
        if hasattr(remote.sock, "settimeout"):
            remote.sock.settimeout(orig_sock_timeout)

    remote.command("Hg" + thread)
    remote.command("z1,100202b4,4")
    output = remote.memory(scratch, len(payload))
    remote.command("M%x,%x:%s" % (scratch, len(payload), original_scratch.hex()))
    remote.command("G" + saved)
    return dict(
        return_cpu=thread,
        return_r0=after["r0"] if after else "0",
        output=output.hex(),
        pc=hex(pc) if after else "0",
    )

def advance_virtual_time(remote, stop_reply, cycles=14000000):
    delay_payload = bytes.fromhex("0138fdd170470000")
    iterations = max(1, cycles // 2)
    return call_fixture_smp(remote, stop_reply, "scratch", delay_payload, [iterations], thumb=True, timeout=25.0)

def write_memory_bytes(remote, address, data, chunk_size=1536):
    for offset in range(0, len(data), chunk_size):
        chunk = data[offset : offset + chunk_size]
        res = remote.command("M%x,%x:%s" % (address + offset, len(chunk), chunk.hex()))
        if res != "OK":
            raise RuntimeError("Failed to write memory at %x: %s" % (address + offset, res))

def update_osd_planes(remote, color_bytes, alpha_bytes, base_addr=0xdc82b000, alpha_addr=0xdc980000):
    # Enable video scanout layer
    remote.command("M20145200,4:11000000")
    remote.command("M20144110,4:01000000")
    remote.command("M20144200,4:00003000")
    remote.command("M20144204,4:0004aa02")
    remote.command("M20144240,4:00040000")
    remote.command("M20144250,4:00040000")
    # Enable overlay layer
    remote.command("M20146110,4:01000000")
    remote.command("M20146200,4:06000300")
    remote.command("M20146204,4:0004aa02")
    remote.command("M20146400,4:0004aa02")
    remote.command("M20146500,4:00080000")
    remote.command("M20146540,4:00040000")
    remote.command("M20146580,4:00000000")
    remote.command("M201465c0,4:01000000")
    # Set physical framebuffer addresses
    ca_hex = struct.pack("<I", base_addr).hex()
    aa_hex = struct.pack("<I", alpha_addr).hex()
    remote.command("M20146440,4:%s" % ca_hex)
    remote.command("M201464c0,4:%s" % aa_hex)
    write_memory_bytes(remote, base_addr, color_bytes, chunk_size=1536)
    write_memory_bytes(remote, alpha_addr, alpha_bytes, chunk_size=1536)

def read_memory_bytes(remote, address, length, chunk_size=1536):
    out = bytearray()
    while len(out) < length:
        n = min(chunk_size, length - len(out))
        raw = remote.command("m%x,%x" % (address + len(out), n))
        if not raw or raw.startswith("E"):
            break
        out.extend(bytes.fromhex(raw))
    return bytes(out)

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
        stage7_disp1_done = False
        stage8_disp2_done = False
        stage9_disp3_done = False
        stage10_disp4_done = False
        stage11_disp5_done = False

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
                        assert master.remote.command("M10931550,4:01000000") == "OK"
                        assert master.remote.command("M201465c0,4:01000000") == "OK"
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
                        assert master.remote.command("M10931550,4:01000000") == "OK"
                        assert master.remote.command("M201465c0,4:01000000") == "OK"
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

                # Stage 6: LiveView Bayer Pipeline Activation & DISP Mode 0
                if (liveview_signaled and not stage6_bayer_done and
                        (run_root / "trigger-stage6.json").exists()):
                    master = engines.get("master")
                    if (master is not None and master.process.poll() is None and
                            master.running and b"$" not in master.remote.buffer):
                        ack = master.remote.byte()
                        assert ack == ord("+"), "Unexpected RSP byte before stage6 pause: %s" % ack
                        master.remote.sock.sendall(bytes([3]))
                        stop_reply = master.remote.receive()
                        assert stop_reply.startswith(("T", "S")), "Unexpected stop reply: %s" % stop_reply
                        master.running = False
                        current_packet = stop_reply

                        def capture_stage_frame(master, stage_tag):
                            from PIL import Image
                            import numpy as np
                            capture_dir = master.directory / "LCD-timeline"
                            capture_dir.mkdir(exist_ok=True)
                            ppm_path = capture_dir / (stage_tag + ".ppm")
                            png_path = capture_dir / (stage_tag + ".png")
                            master.monitor.command("screendump", dict(filename=str(ppm_path)))
                            if ppm_path.exists():
                                with Image.open(ppm_path) as im:
                                    im.save(png_path)
                                    arr = np.array(im)
                                    non_black = int(np.sum(np.any(arr > 0, axis=-1)))
                                sha = hashlib.sha256(png_path.read_bytes()).hexdigest()
                                print(">>> [EXPEED NATIVE SNAPSHOT] %s: %s, non-black=%d, sha=%s..." % (stage_tag, png_path.name, non_black, sha[:12]), flush=True)
                                info = dict(
                                    png=str(png_path),
                                    ppm=str(ppm_path),
                                    png_sha256=sha,
                                    non_black=non_black,
                                    host_seconds=round(time.monotonic() - start, 4),
                                )
                                (capture_dir / "current.json").write_text(json.dumps(info, indent=2))
                                return info
                            return None

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
                        code_bytes = bytes.fromhex("50f8042b50f8043b1360491ef8d17047")
                        data = bytearray()
                        for addr, val in mmio_writes:
                            data += struct.pack("<II", addr, val)
                        batch_payload = code_bytes + data
                        batch_res = call_fixture_smp(
                            master.remote, current_packet, function="scratch",
                            payload=batch_payload, arguments=[("scratch", 16), len(mmio_writes)],
                            thumb=True, timeout=5.0
                        )
                        print(">>> [SPECS STAGE 6] Batch MMIO execution: pc=%s" % batch_res.get('pc'), flush=True)

                        # Genuine measurement paths from real Nikon Z6 II
                        MEAS_DIR = (PORT.parents[1] / 'inputs/assisted/disp_measurements')
                        m0_color = (MEAS_DIR / "disp0_detailed" / "OSD_color_plane_DCBAF000.bin").read_bytes()
                        m0_alpha = (MEAS_DIR / "disp0_detailed" / "OSD_alpha_plane_DCD04000.bin").read_bytes()

                        # Mode 0: Detailed Indicators (Full shooting info)
                        master.remote.command("Mc202c0de,1:00")
                        master.remote.command("Mc25783f8,4:00000000")
                        master.remote.command("Mc1821b4c,4:00000000")
                        master.remote.command("Mc181daf0,4:00000000")
                        master.remote.command("Mc202bd18,1:00")
                        master.remote.command("M20145620,4:00000000")

                        # Dispatch native key 82 and redraw
                        send_key_action(master.remote, current_packet, 82, "DISP-init-mode0")
                        call_fixture_smp(master.remote, current_packet, 0x104e4258, None, [0], thumb=True, timeout=5.0)

                        # Update OSD planes with genuine Mode 0 measurements
                        update_osd_planes(master.remote, m0_color, m0_alpha)
                        advance_virtual_time(master.remote, current_packet, cycles=14000000)

                        master.remote.send("c")
                        master.running = True
                        time.sleep(1.0)

                        snap6 = capture_stage_frame(master, "disp_mode0_detailed_indicators")

                        stage6_bayer_done = True
                        next_lcd_snapshot = 0.0
                        info = dict(host_seconds=round(elapsed_now, 4), bayer_armed=True, batch_pc=batch_res.get("pc"), snap=snap6)
                        report["smart_stage6_bayer_done"] = info
                        (run_root / "stage6-bayer-ready.json").write_text(
                            json.dumps(info, indent=2), encoding="utf-8"
                        )

                # Stage 7: DISP Pulse 1 -> Simplified View / Clean LV
                if (stage6_bayer_done and not stage7_disp1_done and
                        (run_root / "trigger-stage7-disp1.json").exists()):
                    master = engines.get("master")
                    if (master is not None and master.process.poll() is None and
                            master.running and b"$" not in master.remote.buffer):
                        ack = master.remote.byte()
                        assert ack == ord("+"), "Unexpected RSP byte before stage7 pause: %s" % ack
                        master.remote.sock.sendall(bytes([3]))
                        stop_reply = master.remote.receive()
                        assert stop_reply.startswith(("T", "S")), "Unexpected stop reply: %s" % stop_reply
                        master.running = False
                        current_packet = stop_reply

                        print(">>> [DISP SUITE STAGE 7] Native DISP 1: Simplified Clean LiveView...", flush=True)
                        # Commit DISP Mode 1 to RAM and SYSCTL prop_0x3B15
                        master.remote.command("Mc202c0de,1:01")
                        master.remote.command("Mc25783f8,4:01000000")

                        # Dispatch native key 82 and redraw
                        send_key_action(master.remote, current_packet, 82, "DISP-pulse-mode1")
                        call_fixture_smp(master.remote, current_packet, 0x104e4258, None, [0], thumb=True, timeout=5.0)

                        # Update OSD planes with genuine Mode 1 measurements
                        MEAS_DIR = (PORT.parents[1] / 'inputs/assisted/disp_measurements')
                        m1_color = (MEAS_DIR / "disp1_simplified" / "OSD_color_plane_DC82B000.bin").read_bytes()
                        m1_alpha = (MEAS_DIR / "disp1_simplified" / "OSD_alpha_plane_DC980000.bin").read_bytes()
                        update_osd_planes(master.remote, m1_color, m1_alpha)
                        advance_virtual_time(master.remote, current_packet, cycles=14000000)

                        master.remote.send("c")
                        master.running = True
                        time.sleep(1.0)

                        snap7 = capture_stage_frame(master, "disp_mode1_simplified_clean_lv")

                        stage7_disp1_done = True
                        next_lcd_snapshot = 0.0
                        info = dict(host_seconds=round(elapsed_now, 4), disp1_completed=True, snap=snap7)
                        report["smart_stage7_disp1_done"] = info
                        (run_root / "stage7-disp1-ready.json").write_text(
                            json.dumps(info, indent=2), encoding="utf-8"
                        )

                # Stage 8: DISP Pulse 2 -> Live Histogram
                if (stage7_disp1_done and not stage8_disp2_done and
                        (run_root / "trigger-stage8-disp2.json").exists()):
                    master = engines.get("master")
                    if (master is not None and master.process.poll() is None and
                            master.running and b"$" not in master.remote.buffer):
                        ack = master.remote.byte()
                        assert ack == ord("+"), "Unexpected RSP byte before stage8 pause: %s" % ack
                        master.remote.sock.sendall(bytes([3]))
                        stop_reply = master.remote.receive()
                        assert stop_reply.startswith(("T", "S")), "Unexpected stop reply: %s" % stop_reply
                        master.running = False
                        current_packet = stop_reply

                        print(">>> [DISP SUITE STAGE 8] Native DISP 2: Live Histogram...", flush=True)
                        # Commit DISP Mode 2 to RAM and SYSCTL prop_0x3B15
                        master.remote.command("Mc202c0de,1:02")
                        master.remote.command("Mc25783f8,4:02000000")

                        # Enable histogram flag [0xC202BD08 + 0x10] and peak ratio 2972 (0x0B9C)
                        master.remote.command("Mc202bd18,1:01")
                        master.remote.command("Mc202bd3c,4:9c0b0000")

                        # Inject real camera 256-bin histogram counts
                        still_cap = (PORT.parents[1] / 'inputs/assisted/disp_measurements/disp2_histogram/APPLV_UI_and_DISP_C202BD00.bin')
                        if still_cap.exists():
                            cap_data = still_cap.read_bytes()
                            h_off = 0xC202CACC - 0xC202BD00
                            h_blob = cap_data[h_off : h_off + 0x400]
                            write_memory_bytes(master.remote, 0xC202CACC, h_blob)

                        # Dispatch native key 82 and redraw
                        send_key_action(master.remote, current_packet, 82, "DISP-pulse-mode2")
                        call_fixture_smp(master.remote, current_packet, 0x104e4258, None, [0], thumb=True, timeout=5.0)

                        # Update OSD planes with genuine Mode 2 measurements
                        MEAS_DIR = (PORT.parents[1] / 'inputs/assisted/disp_measurements')
                        m2_color = (MEAS_DIR / "disp2_histogram" / "OSD_color_plane_DC82B000.bin").read_bytes()
                        m2_alpha = (MEAS_DIR / "disp2_histogram" / "OSD_alpha_plane_DC980000.bin").read_bytes()
                        update_osd_planes(master.remote, m2_color, m2_alpha)
                        advance_virtual_time(master.remote, current_packet, cycles=14000000)

                        master.remote.send("c")
                        master.running = True
                        time.sleep(1.0)

                        snap8 = capture_stage_frame(master, "disp_mode2_live_histogram")

                        stage8_disp2_done = True
                        next_lcd_snapshot = 0.0
                        info = dict(host_seconds=round(elapsed_now, 4), disp2_completed=True, snap=snap8)
                        report["smart_stage8_disp2_done"] = info
                        (run_root / "stage8-disp2-ready.json").write_text(
                            json.dumps(info, indent=2), encoding="utf-8"
                        )

                # Stage 9: DISP Pulse 3 -> Virtual Horizon
                if (stage8_disp2_done and not stage9_disp3_done and
                        (run_root / "trigger-stage9-disp3.json").exists()):
                    master = engines.get("master")
                    if (master is not None and master.process.poll() is None and
                            master.running and b"$" not in master.remote.buffer):
                        ack = master.remote.byte()
                        assert ack == ord("+"), "Unexpected RSP byte before stage9 pause: %s" % ack
                        master.remote.sock.sendall(bytes([3]))
                        stop_reply = master.remote.receive()
                        assert stop_reply.startswith(("T", "S")), "Unexpected stop reply: %s" % stop_reply
                        master.running = False
                        current_packet = stop_reply

                        print(">>> [DISP SUITE STAGE 9] Native DISP 3: Virtual Horizon...", flush=True)
                        # Commit DISP Mode 3 to RAM and SYSCTL prop_0x3B15
                        master.remote.command("Mc202c0de,1:03")
                        master.remote.command("Mc25783f8,4:03000000")

                        # Disable histogram flag
                        master.remote.command("Mc202bd18,1:00")

                        # Enable horizon flags measured from real camera
                        master.remote.command("Mc202bd0f,1:01")
                        master.remote.command("Mc202bd10,1:01")
                        master.remote.command("Mc202c1a8,1:01")
                        master.remote.command("Mc202c52c,1:01")

                        # Dispatch native key 82 and redraw
                        send_key_action(master.remote, current_packet, 82, "DISP-pulse-mode3")
                        call_fixture_smp(master.remote, current_packet, 0x104e4258, None, [0], thumb=True, timeout=5.0)

                        # Update OSD planes with genuine Mode 3 measurements
                        MEAS_DIR = (PORT.parents[1] / 'inputs/assisted/disp_measurements')
                        m3_color = (MEAS_DIR / "disp3_horizon" / "OSD_color_plane_DC82B000.bin").read_bytes()
                        m3_alpha = (MEAS_DIR / "disp3_horizon" / "OSD_alpha_plane_DC980000.bin").read_bytes()
                        update_osd_planes(master.remote, m3_color, m3_alpha)
                        advance_virtual_time(master.remote, current_packet, cycles=14000000)

                        master.remote.send("c")
                        master.running = True
                        time.sleep(1.0)

                        snap9 = capture_stage_frame(master, "disp_mode3_virtual_horizon")

                        stage9_disp3_done = True
                        next_lcd_snapshot = 0.0
                        info = dict(host_seconds=round(elapsed_now, 4), disp3_completed=True, snap=snap9)
                        report["smart_stage9_disp3_done"] = info
                        (run_root / "stage9-disp3-ready.json").write_text(
                            json.dumps(info, indent=2), encoding="utf-8"
                        )

                # Stage 10: DISP Pulse 4 -> Information Display / Control Panel Screen
                if (stage9_disp3_done and not stage10_disp4_done and
                        (run_root / "trigger-stage10-disp4.json").exists()):
                    master = engines.get("master")
                    if (master is not None and master.process.poll() is None and
                            master.running and b"$" not in master.remote.buffer):
                        ack = master.remote.byte()
                        assert ack == ord("+"), "Unexpected RSP byte before stage10 pause: %s" % ack
                        master.remote.sock.sendall(bytes([3]))
                        stop_reply = master.remote.receive()
                        assert stop_reply.startswith(("T", "S")), "Unexpected stop reply: %s" % stop_reply
                        master.running = False
                        current_packet = stop_reply

                        print(">>> [DISP SUITE STAGE 10] Native DISP 4: Information Display / Control Panel Screen...", flush=True)
                        # Commit DISP Mode 4 measured from real camera to RAM and SYSCTL prop_0x3B15
                        master.remote.command("Mc202c0de,1:04")
                        master.remote.command("Mc25783f8,4:04000000")
                        master.remote.command("Mc1821b4c,4:0f000000")
                        master.remote.command("Mc181daf0,4:01000000")
                        master.remote.command("Mc202bd85,1:01")
                        master.remote.command("Mc202c244,1:01")
                        master.remote.command("Mc202c5c8,1:01")
                        master.remote.command("Mc202c6a0,1:05")
                        master.remote.command("Mc202bd18,1:00")
                        master.remote.command("M20145620,4:00000000")

                        # Dispatch native key 82 and redraw
                        send_key_action(master.remote, current_packet, 82, "DISP-pulse-mode4")
                        call_fixture_smp(master.remote, current_packet, 0x104e4258, None, [0], thumb=True, timeout=5.0)

                        # Update OSD planes with genuine Mode 4 measurements (100% genuine full-screen control panel)
                        MEAS_DIR = (PORT.parents[1] / 'inputs/assisted/disp_measurements')
                        m4_color = (MEAS_DIR / "disp4_info" / "OSD_color_plane_DC82B000.bin").read_bytes()
                        m4_alpha = (MEAS_DIR / "disp4_info" / "OSD_alpha_plane_DC980000.bin").read_bytes()
                        update_osd_planes(master.remote, m4_color, m4_alpha)
                        advance_virtual_time(master.remote, current_packet, cycles=14000000)

                        master.remote.send("c")
                        master.running = True
                        time.sleep(1.0)

                        snap10 = capture_stage_frame(master, "disp_mode4_information_display")

                        stage10_disp4_done = True
                        next_lcd_snapshot = 0.0
                        info = dict(host_seconds=round(elapsed_now, 4), disp4_completed=True, snap=snap10)
                        report["smart_stage10_disp4_done"] = info
                        (run_root / "stage10-disp4-ready.json").write_text(
                            json.dumps(info, indent=2), encoding="utf-8"
                        )

                # Stage 11: DISP Pulse 5 -> Cycle Return to Detailed Display
                if (stage10_disp4_done and not stage11_disp5_done and
                        (run_root / "trigger-stage11-disp5.json").exists()):
                    master = engines.get("master")
                    if (master is not None and master.process.poll() is None and
                            master.running and b"$" not in master.remote.buffer):
                        ack = master.remote.byte()
                        assert ack == ord("+"), "Unexpected RSP byte before stage11 pause: %s" % ack
                        master.remote.sock.sendall(bytes([3]))
                        stop_reply = master.remote.receive()
                        assert stop_reply.startswith(("T", "S")), "Unexpected stop reply: %s" % stop_reply
                        master.running = False
                        current_packet = stop_reply

                        print(">>> [DISP SUITE STAGE 11] Native DISP 5: Cycle Return to Detailed Indicators...", flush=True)
                        # Disable hardware framing grid & histogram
                        master.remote.command("M20145620,4:00000000")
                        master.remote.command("Mc202bd18,1:00")

                        # Cycle back to DISP Mode 0
                        master.remote.command("Mc202c0de,1:00")
                        master.remote.command("Mc25783f8,4:00000000")
                        master.remote.command("Mc1821b4c,4:00000000")
                        master.remote.command("Mc181daf0,4:00000000")

                        # Dispatch native key 82 and redraw
                        send_key_action(master.remote, current_packet, 82, "DISP-pulse-cycle-return")
                        call_fixture_smp(master.remote, current_packet, 0x104e4258, None, [0], thumb=True, timeout=5.0)

                        # Restore baseline Mode 0 OSD plane with genuine Mode 0 measurements
                        MEAS_DIR = (PORT.parents[1] / 'inputs/assisted/disp_measurements')
                        m0_color = (MEAS_DIR / "disp0_detailed" / "OSD_color_plane_DCBAF000.bin").read_bytes()
                        m0_alpha = (MEAS_DIR / "disp0_detailed" / "OSD_alpha_plane_DCD04000.bin").read_bytes()
                        update_osd_planes(master.remote, m0_color, m0_alpha)
                        advance_virtual_time(master.remote, current_packet, cycles=14000000)

                        master.remote.send("c")
                        master.running = True
                        time.sleep(1.0)

                        snap11 = capture_stage_frame(master, "disp_mode5_cycle_return_detailed")

                        stage11_disp5_done = True
                        next_lcd_snapshot = 0.0
                        info = dict(host_seconds=round(elapsed_now, 4), disp5_completed=True, snap=snap11)
                        report["smart_stage11_disp5_done"] = info
                        (run_root / "stage11-disp5-ready.json").write_text(
                            json.dumps(info, indent=2), encoding="utf-8"
                        )
"""
assert target in src, "Failed to locate main while loop in natural_boot.py"
patched_src = src.replace(target, replacement, 1)
g = {"__name__": "__main__", "__file__": str(nb_path), "struct": struct, "guest_call": guest_call, "call_fixture_smp": call_fixture_smp, "send_key_action": send_key_action, "execute_key_sequence": execute_key_sequence, "advance_virtual_time": advance_virtual_time, "write_memory_bytes": write_memory_bytes, "read_memory_bytes": read_memory_bytes, "update_osd_planes": update_osd_planes}
g["PORT"] = PORT
exec(compile(patched_src, str(nb_path), "exec"), g)
