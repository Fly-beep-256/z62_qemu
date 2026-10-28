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
        schema="z6ii.native-specs-permutations-scenario/1",
        started=now(),
        run=str(run),
        arguments={k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()},
        script=identity(__file__),
        LiveView_bayer_rendered=False,
        FX_photo_completed=False,
        DX_crop_completed=False,
        DX_photo_completed=False,
        Square_1to1_crop_completed=False,
        RAW_burst_completed=False,
        Movie_120p_completed=False,
        Movie_4K60p_MP4_completed=False,
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

        # Stage 6: Trigger LiveView Bayer DMA & ISP Pipeline
        print(">>> Triggering Stage 6: Bayer LiveView Activation...", flush=True)
        save(run / "trigger-stage6.json", dict(host_elapsed=round(time.monotonic() - origin, 3)))
        bayer_info = wait_for_milestone(run / "stage6-bayer-ready.json", "stage6-bayer-ready")
        wait_until(time.monotonic() + 2.5)
        events.append(
            dict(
                kind="LCD_after_imaging",
                label="LiveView-Bayer-ISP-rendered",
                host_elapsed=round(time.monotonic() - origin, 3),
                milestone=bayer_info,
                observed=display(),
            )
        )
        result["LiveView_bayer_rendered"] = True

        # Stage 7: Trigger Baseline FX Photo Capture
        print(">>> Triggering Stage 7: Baseline FX Photo Capture...", flush=True)
        save(run / "trigger-stage7-fx-photo.json", dict(host_elapsed=round(time.monotonic() - origin, 3)))
        fx_photo_info = wait_for_milestone(run / "stage7-fx-photo-ready.json", "stage7-fx-photo-ready")
        wait_until(time.monotonic() + 2.0)
        events.append(
            dict(
                kind="LCD_after_imaging",
                label="FX-Photo-Captured",
                host_elapsed=round(time.monotonic() - origin, 3),
                milestone=fx_photo_info,
                observed=display(),
            )
        )
        result["FX_photo_completed"] = True

        # Stage 8: Trigger DX Crop Mode Selection
        print(">>> Triggering Stage 8: DX Crop Mode Selection...", flush=True)
        save(run / "trigger-stage8-dx-crop.json", dict(host_elapsed=round(time.monotonic() - origin, 3)))
        dx_crop_info = wait_for_milestone(run / "stage8-dx-crop-ready.json", "stage8-dx-crop-ready")
        wait_until(time.monotonic() + 2.5)
        events.append(
            dict(
                kind="LCD_after_imaging",
                label="DX-Crop-Mode-Active",
                host_elapsed=round(time.monotonic() - origin, 3),
                milestone=dx_crop_info,
                observed=display(),
            )
        )
        result["DX_crop_completed"] = True

        # Stage 9: Trigger DX Crop Still Photo Capture
        print(">>> Triggering Stage 9: DX Crop Still Photo Capture...", flush=True)
        save(run / "trigger-stage9-dx-photo.json", dict(host_elapsed=round(time.monotonic() - origin, 3)))
        dx_photo_info = wait_for_milestone(run / "stage9-dx-photo-ready.json", "stage9-dx-photo-ready")
        wait_until(time.monotonic() + 2.0)
        events.append(
            dict(
                kind="LCD_after_imaging",
                label="DX-Photo-Captured",
                host_elapsed=round(time.monotonic() - origin, 3),
                milestone=dx_photo_info,
                observed=display(),
            )
        )
        result["DX_photo_completed"] = True

        # Stage 10: Trigger 1:1 Square Crop Selection & Capture
        print(">>> Triggering Stage 10: 1:1 Square Crop Selection & Capture...", flush=True)
        save(run / "trigger-stage10-1to1-crop.json", dict(host_elapsed=round(time.monotonic() - origin, 3)))
        crop1to1_info = wait_for_milestone(run / "stage10-1to1-crop-ready.json", "stage10-1to1-crop-ready")
        wait_until(time.monotonic() + 2.0)
        events.append(
            dict(
                kind="LCD_after_imaging",
                label="Square-1to1-Crop-Captured",
                host_elapsed=round(time.monotonic() - origin, 3),
                milestone=crop1to1_info,
                observed=display(),
            )
        )
        result["Square_1to1_crop_completed"] = True

        # Stage 11: Trigger NEF (RAW) Quality & Continuous 3x High Burst
        print(">>> Triggering Stage 11: RAW Quality & Continuous 3x High Burst...", flush=True)
        save(run / "trigger-stage11-raw-burst.json", dict(host_elapsed=round(time.monotonic() - origin, 3)))
        raw_burst_info = wait_for_milestone(run / "stage11-raw-burst-ready.json", "stage11-raw-burst-ready")
        wait_until(time.monotonic() + 2.5)
        events.append(
            dict(
                kind="LCD_after_imaging",
                label="RAW-Burst-Captured",
                host_elapsed=round(time.monotonic() - origin, 3),
                milestone=raw_burst_info,
                observed=display(),
            )
        )
        result["RAW_burst_completed"] = True

        # Stage 12: Trigger High Frame Rate 1080/120p Movie Recording
        print(">>> Triggering Stage 12: High Frame Rate 1080/120p Movie...", flush=True)
        save(run / "trigger-stage12-movie-120p.json", dict(host_elapsed=round(time.monotonic() - origin, 3)))
        movie_120p_info = wait_for_milestone(run / "stage12-movie-120p-ready.json", "stage12-movie-120p-ready")
        wait_until(time.monotonic() + 2.0)
        events.append(
            dict(
                kind="LCD_after_imaging",
                label="Movie-120p-Completed",
                host_elapsed=round(time.monotonic() - origin, 3),
                milestone=movie_120p_info,
                observed=display(),
            )
        )
        result["Movie_120p_completed"] = True

        # Stage 13: Trigger 4K UHD 60p & MP4 Container Movie Recording
        print(">>> Triggering Stage 13: 4K UHD 60p MP4 Movie...", flush=True)
        save(run / "trigger-stage13-movie-4k60p.json", dict(host_elapsed=round(time.monotonic() - origin, 3)))
        movie_4k_info = wait_for_milestone(run / "stage13-movie-4k60p-ready.json", "stage13-movie-4k60p-ready")
        wait_until(time.monotonic() + 2.0)
        events.append(
            dict(
                kind="LCD_after_imaging",
                label="Movie-4K60p-MP4-Completed",
                host_elapsed=round(time.monotonic() - origin, 3),
                milestone=movie_4k_info,
                observed=display(),
            )
        )
        result["Movie_4K60p_MP4_completed"] = True

        result["successful_input_delivery"] = True
        print(">>> All specifications and crop mode permutations completed successfully!", flush=True)

    except Exception as error:
        result["failure"] = type(error).__name__ + ": " + str(error)

    result.update(finished=now(), events=events, distinct_original_LCD_images=list(images.values()))
    save(result_path, result)
    print(
        json.dumps(
            dict(result=str(result_path), success=result["successful_input_delivery"],
                 bayer=result["LiveView_bayer_rendered"], fx_photo=result["FX_photo_completed"],
                 dx_crop=result["DX_crop_completed"], dx_photo=result["DX_photo_completed"],
                 square_1to1=result["Square_1to1_crop_completed"], raw_burst=result["RAW_burst_completed"],
                 movie_120p=result["Movie_120p_completed"], movie_4k60p=result["Movie_4K60p_MP4_completed"],
                 images=len(images)),
            ensure_ascii=False,
        )
    )
    return 0 if result["successful_input_delivery"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
