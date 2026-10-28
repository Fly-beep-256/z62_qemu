"""Multi-Mode and specifications permutations scenario runner."""
import argparse
import json
from pathlib import Path
import sys
import time

from local_support import PORT, identity, now, save

sys.path.insert(0, str(PORT))
from menu_ocr import recognize


def read_json(path):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--prepare-dir", type=Path, required=True)
    ap.add_argument("--run-dir", type=Path, required=True)
    ap.add_argument("--safety-timeout", type=float, default=255.0)
    args = ap.parse_args()

    prepare = args.prepare_dir.resolve(strict=True)
    run = args.run_dir
    locked_path = prepare / "锁定命令与输入.json"
    pcal_state = run / "MCU/pcal-host-state.json"
    gpio_state = run / "MCU/gpio-host-state.json"

    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        locked, ps, gs = read_json(locked_path), read_json(pcal_state), read_json(gpio_state)
        if locked and ps and gs and gs.get("running") is True:
            break
        time.sleep(0.1)
    assert locked and ps and gs and gs.get("running") is True
    pcal_input = Path(locked["explicit_MCU_host_input_file"])
    gpio_input = Path(locked["explicit_MCU_gpio_host_input_file"])
    origin = gs["host_monotonic_ns"] / 1e9
    hard_deadline = origin + args.safety_timeout
    events, images = [], {}
    result_path = run / "native-gpio-scenario-result.json"
    lcd = run / "EXPEED/engines/master/LCD-timeline/current.json"

    def display():
        current = read_json(lcd)
        if not current or not current.get("png"):
            return current
        digest = current["png_sha256"]
        if digest not in images:
            images[digest] = dict(
                png=current["png"],
                ppm=current.get("ppm"),
                png_sha256=digest,
            )
        return dict(**images[digest], capture_host_seconds=current.get("host_seconds", 0))

    def wait_for_frame_change(last_digest, timeout=3.5):
        t_end = time.monotonic() + timeout
        while time.monotonic() < t_end:
            cur = display()
            if cur and cur.get("png_sha256") and cur.get("png_sha256") != last_digest:
                return cur
            time.sleep(0.15)
        return display()

    def wait_until(target):
        while time.monotonic() < target:
            state = read_json(gpio_state)
            if state and state.get("running") is False:
                raise RuntimeError("MCU stopped before scenario completion")
            time.sleep(min(0.1, max(0.001, target - time.monotonic())))

    def wait_for_milestone(milestone_path: Path, label: str):
        expeed_log = run / "EXPEED-host.log"
        while time.monotonic() < hard_deadline:
            state = read_json(gpio_state)
            if state and state.get("running") is False:
                raise RuntimeError(f"MCU stopped while waiting for {label}")
            if expeed_log.exists() and "Traceback " in expeed_log.read_text(errors="replace"):
                raise RuntimeError(f"EXPEED host runner failed while waiting for {label}")
            data = read_json(milestone_path)
            if data is not None:
                return data
            time.sleep(0.1)
        raise TimeoutError(f"Timed out waiting for milestone {label}: {milestone_path}")

    def drive(kind, mask, levels, label, port="G"):
        path, state_path = (pcal_input, pcal_state) if kind == "PCAL" else (gpio_input, gpio_state)
        previous = read_json(state_path)
        command = dict(sequence=previous["sequence"] + 1, mask=mask, levels=levels, label=label)
        if kind == "GPIO":
            command["port"] = port
        temporary = path.with_suffix(".pending")
        save(temporary, command)
        temporary.replace(path)
        ack_deadline = time.monotonic() + 15
        while time.monotonic() < ack_deadline:
            ack = read_json(state_path)
            if ack and ack["sequence"] == command["sequence"]:
                events.append(
                    dict(
                        kind="external_pad_ack",
                        pad_kind=kind,
                        request=command,
                        acknowledgement=ack,
                        host_elapsed=round(time.monotonic() - origin, 3),
                        LCD=display(),
                        ACK_is_business_acceptance=False,
                    )
                )
                return
            if ack and ack.get("running") is False:
                raise RuntimeError("MCU exited before GPIO acknowledgement")
            time.sleep(0.1)
        raise TimeoutError("External pad ACK: " + label)

    result = dict(
        schema="z6ii.native-disp-modes-scenario/1",
        started=now(),
        run=str(run),
        arguments={k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()},
        script=identity(__file__),
        disp_mode0_detailed_indicators=False,
        disp_mode1_simplified_view=False,
        disp_mode2_virtual_horizon=False,
        disp_mode3_live_histogram=False,
        disp_mode4_framing_grid=False,
        disp_mode5_cycle_return=False,
        successful_input_delivery=False,
        legacy_completion_flags_are_function_results=False,
        functional_acceptance_implied=False,
    )
    try:
        # Stage 2: Wait for Scheme A injection, close PC5
        inject_info = wait_for_milestone(run / "scheme-a-injected.json", "scheme-a-injected")
        wait_until(time.monotonic() + 0.2)
        drive("GPIO", 0x20, 0, "PC5-original-startup-high-window:close-low", port="C")
        save(run / "pc5-closed.json", dict(host_elapsed=round(time.monotonic() - origin, 3), inject=inject_info))

        # Stage 3: Wait for SAISO + APPLV idle, press MENU
        applv_info = wait_for_milestone(run / "applv-idle-ready.json", "applv-idle-ready")
        wait_until(time.monotonic() + 1.0)
        drive("PCAL", 0x200, 0, "native-MENU:low")
        wait_until(time.monotonic() + 1.4)
        drive("PCAL", 0x200, 0x200, "native-MENU:release")
        save(run / "menu-released.json", dict(host_elapsed=round(time.monotonic() - origin, 3), applv=applv_info))

        # Stage 4: Wait for MENU render & idle, press PG1 to transition to LiveView
        menu_info = wait_for_milestone(run / "menu-idle-ready.json", "menu-idle-ready")
        events.append(
            dict(
                kind="LCD_after_input",
                label="native-MENU-rendered",
                host_elapsed=round(time.monotonic() - origin, 3),
                milestone=menu_info,
                observed=display(),
            )
        )
        wait_until(time.monotonic() + 0.5)
        drive("GPIO", 0x02, 0, "native-PG1:low", port="G")
        wait_until(time.monotonic() + 4.0)
        drive("GPIO", 0x02, 0x02, "native-PG1:release", port="G")
        save(run / "pg1-released.json", dict(host_elapsed=round(time.monotonic() - origin, 3), menu=menu_info))

        # Stage 5: Wait for LiveView UI OSD ready
        lv_info = wait_for_milestone(run / "liveview-ui-ready.json", "liveview-ui-ready")
        wait_until(time.monotonic() + 0.5)
        events.append(
            dict(
                kind="LCD_after_input",
                label="native-PG1-liveview-ready",
                host_elapsed=round(time.monotonic() - origin, 3),
                milestone=lv_info,
                observed=display(),
            )
        )

        # Stage 6: Trigger LiveView Bayer Activation -> DISP Mode 0 (Indicators On Detailed)
        print(">>> Triggering Stage 6: Bayer LiveView Activation (Mode 0: Detailed Indicators)...", flush=True)
        save(run / "trigger-stage6.json", dict(host_elapsed=round(time.monotonic() - origin, 3)))
        bayer_info = wait_for_milestone(run / "stage6-bayer-ready.json", "stage6-bayer-ready")
        wait_until(time.monotonic() + 3.0)
        m0_disp = display()
        last_digest = m0_disp.get("png_sha256") if m0_disp else None
        events.append(
            dict(
                kind="LCD_disp_mode",
                label="Mode0-Detailed-Indicators-On",
                host_elapsed=round(time.monotonic() - origin, 3),
                milestone=bayer_info,
                observed=m0_disp,
            )
        )
        result["disp_mode0_detailed_indicators"] = True
        print(">>> Mode 0 (Detailed Indicators On) Captured: %s" % (m0_disp.get('png') if m0_disp else None), flush=True)

        # Stage 7: Trigger DISP Pulse 1 -> Simplified View / Clean LV
        print(">>> Triggering Stage 7: DISP Pulse 1 (Clean LV / Simplified Display)...", flush=True)
        save(run / "trigger-stage7-disp1.json", dict(host_elapsed=round(time.monotonic() - origin, 3)))
        disp1_info = wait_for_milestone(run / "stage7-disp1-ready.json", "stage7-disp1-ready")
        m1_disp = wait_for_frame_change(last_digest, timeout=3.0)
        last_digest = m1_disp.get("png_sha256") if m1_disp else last_digest
        events.append(
            dict(
                kind="LCD_disp_mode",
                label="Mode1-Simplified-Clean-LV",
                host_elapsed=round(time.monotonic() - origin, 3),
                milestone=disp1_info,
                observed=m1_disp,
            )
        )
        result["disp_mode1_simplified_view"] = True
        print(">>> Mode 1 (Simplified Display) Captured: %s" % (m1_disp.get('png') if m1_disp else None), flush=True)

        # Stage 8: Trigger DISP Pulse 2 -> Virtual Horizon
        print(">>> Triggering Stage 8: DISP Pulse 2 (Virtual Horizon)...", flush=True)
        save(run / "trigger-stage8-disp2.json", dict(host_elapsed=round(time.monotonic() - origin, 3)))
        disp2_info = wait_for_milestone(run / "stage8-disp2-ready.json", "stage8-disp2-ready")
        m2_disp = wait_for_frame_change(last_digest, timeout=3.0)
        last_digest = m2_disp.get("png_sha256") if m2_disp else last_digest
        events.append(
            dict(
                kind="LCD_disp_mode",
                label="Mode2-Virtual-Horizon",
                host_elapsed=round(time.monotonic() - origin, 3),
                milestone=disp2_info,
                observed=m2_disp,
            )
        )
        result["disp_mode2_virtual_horizon"] = True
        print(">>> Mode 2 (Virtual Horizon) Captured: %s" % (m2_disp.get('png') if m2_disp else None), flush=True)

        # Stage 9: Trigger DISP Pulse 3 -> Live Histogram
        print(">>> Triggering Stage 9: DISP Pulse 3 (Live Histogram)...", flush=True)
        save(run / "trigger-stage9-disp3.json", dict(host_elapsed=round(time.monotonic() - origin, 3)))
        disp3_info = wait_for_milestone(run / "stage9-disp3-ready.json", "stage9-disp3-ready")
        m3_disp = wait_for_frame_change(last_digest, timeout=3.0)
        last_digest = m3_disp.get("png_sha256") if m3_disp else last_digest
        events.append(
            dict(
                kind="LCD_disp_mode",
                label="Mode3-Live-Histogram",
                host_elapsed=round(time.monotonic() - origin, 3),
                milestone=disp3_info,
                observed=m3_disp,
            )
        )
        result["disp_mode3_live_histogram"] = True
        print(">>> Mode 3 (Live Histogram) Captured: %s" % (m3_disp.get('png') if m3_disp else None), flush=True)

        # Stage 10: Trigger DISP Pulse 4 -> Framing Grid / Info Screen
        print(">>> Triggering Stage 10: DISP Pulse 4 (Framing Grid / Info Screen)...", flush=True)
        save(run / "trigger-stage10-disp4.json", dict(host_elapsed=round(time.monotonic() - origin, 3)))
        disp4_info = wait_for_milestone(run / "stage10-disp4-ready.json", "stage10-disp4-ready")
        m4_disp = wait_for_frame_change(last_digest, timeout=3.0)
        last_digest = m4_disp.get("png_sha256") if m4_disp else last_digest
        events.append(
            dict(
                kind="LCD_disp_mode",
                label="Mode4-Framing-Grid-or-Info",
                host_elapsed=round(time.monotonic() - origin, 3),
                milestone=disp4_info,
                observed=m4_disp,
            )
        )
        result["disp_mode4_framing_grid"] = True
        print(">>> Mode 4 (Framing Grid / Info Screen) Captured: %s" % (m4_disp.get('png') if m4_disp else None), flush=True)

        # Stage 11: Trigger DISP Pulse 5 -> Return to Detailed Display
        print(">>> Triggering Stage 11: DISP Pulse 5 (Return to Detailed Display)...", flush=True)
        save(run / "trigger-stage11-disp5.json", dict(host_elapsed=round(time.monotonic() - origin, 3)))
        disp5_info = wait_for_milestone(run / "stage11-disp5-ready.json", "stage11-disp5-ready")
        m5_disp = wait_for_frame_change(last_digest, timeout=3.0)
        events.append(
            dict(
                kind="LCD_disp_mode",
                label="Mode5-Cycle-Return-Detailed",
                host_elapsed=round(time.monotonic() - origin, 3),
                milestone=disp5_info,
                observed=m5_disp,
            )
        )
        result["disp_mode5_cycle_return"] = True
        print(">>> Mode 5 (Cycle Return) Captured: %s" % (m5_disp.get('png') if m5_disp else None), flush=True)

        result["successful_input_delivery"] = (
            result.get("disp_mode0_detailed_indicators", False) and
            result.get("disp_mode1_simplified_view", False) and
            result.get("disp_mode2_virtual_horizon", False) and
            result.get("disp_mode3_live_histogram", False) and
            result.get("disp_mode4_framing_grid", False) and
            result.get("disp_mode5_cycle_return", False)
        )
        print(">>> DISP scenario stages completed; pixel and function checks are in acceptance.md", flush=True)

    except Exception as error:
        result["failure"] = type(error).__name__ + ": " + str(error)

    result.update(finished=now(), events=events, distinct_original_LCD_images=list(images.values()))
    save(result_path, result)
    print(
        json.dumps(
            dict(
                result=str(result_path),
                success=result["successful_input_delivery"],
                mode0_detailed=result.get("disp_mode0_detailed_indicators", False),
                mode1_clean=result.get("disp_mode1_simplified_view", False),
                mode2_horizon=result.get("disp_mode2_virtual_horizon", False),
                mode3_histogram=result.get("disp_mode3_live_histogram", False),
                mode4_grid=result.get("disp_mode4_framing_grid", False),
                mode5_cycle=result.get("disp_mode5_cycle_return", False),
                images=len(images),
            ),
            ensure_ascii=False,
        )
    )
    return 0 if result["successful_input_delivery"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
