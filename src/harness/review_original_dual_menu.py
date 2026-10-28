"""Audit saved menu frames after both guests close; no firmware execution.

A script finishing, colored pixels, or clean CPU fault registers do not prove
menu stability. Check actual categories, inner page, exit and re-entry, retaining
the source images and explicit diagnostic/natural-boot distinction.
"""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
from zoneinfo import ZoneInfo

from PIL import Image, ImageChops
from menu_ocr import recognize

CATEGORIES = {"PLAYBACK MENU", "PHOTO SHOOTING MENU", "MOVIE SHOOTING MENU",
              "CUSTOM SETTING MENU", "SETUP MENU", "RETOUCH MENU", "MY MENU"}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    directory = args.directory.resolve(strict=True)
    output = directory / "菜单图像与稳定性复核.json"
    if output.exists():
        raise FileExistsError(output)
    session_path = directory / "菜单逐步记录.json"
    result_path = directory / "结果.json"
    session = json.loads(session_path.read_text())
    result = json.loads(result_path.read_text())
    assert result.get("owned_QEMU_exited") is True, "Close owned guests before OCR"
    frames = []
    for row in session.get("steps", []):
        screenshot = row["screenshot"]
        png, ppm = Path(screenshot["png"]), Path(screenshot["ppm"])
        with Image.open(png) as a, Image.open(ppm) as b:
            pixels_match = (a.size == b.size and
                ImageChops.difference(a.convert("RGB"), b.convert("RGB")).getbbox() is None)
        identity_ok = pixels_match and digest(ppm) == screenshot["sha256"]
        try:
            ocr = recognize(png) if screenshot["distinct_colors"] > 1 else dict(rows=[], skipped="single-color")
        except Exception as error:
            ocr = dict(rows=[], error=str(error))
        words = " ".join(item["text"] for item in ocr.get("rows", [])).upper()
        normalized = re.sub(r"\s+", " ", words)
        titles = sorted(title for title in CATEGORIES if title in normalized)
        frames.append(dict(label=row["label"], png=str(png), png_sha256=digest(png),
            original_PPM_identity_and_png_pixels_match=identity_ok,
            sys_state=row["state"]["sys_state"], OCR=ocr, detected_categories=titles,
            original_Error_UI_detected="TURN CAMERA OFF" in normalized,
            visible_menu_title=bool(titles)))
    by_label = {row["label"]: row for row in frames}
    observed = sorted({title for row in frames for title in row["detected_categories"]})
    errors = [row["label"] for row in frames if row["original_Error_UI_detected"]]
    checks = []

    def check(name, passed):
        checks.append(dict(name=name, passed=bool(passed)))

    check("all saved images retain source identity", bool(frames) and all(
        row["original_PPM_identity_and_png_pixels_match"] for row in frames))
    check("OCR covers all colored saved frames", all("error" not in row["OCR"] for row in frames))
    check("original firmware Error UI absent", not errors)
    check("all seven actual menu categories rendered", set(observed) == CATEGORIES)
    first, down = by_label.get("01-menu-enter", {}), by_label.get("02-menu-down", {})
    check("MENU entered and navigation changes pixels", first.get("visible_menu_title") and
          down.get("visible_menu_title") and first.get("png_sha256") != down.get("png_sha256"))
    inner, back = by_label.get("08-item-enter", {}), by_label.get("09-item-back", {})
    check("inner page opened and returned", inner and not inner.get("visible_menu_title") and
          not inner.get("original_Error_UI_detected") and inner.get("OCR", {}).get("rows") and
          back.get("visible_menu_title"))
    baseline = by_label.get("00-before-menu", {}).get("sys_state")
    for label in ("10-menu-exit", "11-after-exit-stability", "13-half-exit"):
        row = by_label.get(label, {})
        check(label + " restores pre-menu state and removes menu", row and
              not row.get("visible_menu_title") and not row.get("original_Error_UI_detected") and
              row.get("sys_state") == baseline)
    reenter = by_label.get("12-menu-reenter", {})
    check("MENU re-entry renders normal menu", reenter.get("visible_menu_title") and
          reenter.get("sys_state") == first.get("sys_state"))
    cpu = session.get("final_original_CPU_states", {})
    check("both original guests have final CPU snapshots", set(cpu) == {"master", "slave"})
    for role, snapshot in cpu.items():
        check(role + " final CPU fault statuses zero", all(
            int(value, 16) == 0 for core in snapshot["cores"]
            for key, value in core["system_registers"].items() if key.startswith(("DFSR", "IFSR"))))
    plan = session.get("diagnostic_menu_plan", "traversal")
    traversal_checks = {"all seven actual menu categories rendered", "inner page opened and returned"}
    plan_checks = [row for row in checks if plan == "traversal" or row["name"] not in traversal_checks]
    review = dict(recorded_at=datetime.now(ZoneInfo("Asia/Shanghai")).isoformat(),
        read_only_saved_evidence_analysis=True, QEMU_executions=0, camera_operations=0,
        source_session=str(session_path), source_session_sha256=digest(session_path),
        source_result=str(result_path), source_result_sha256=digest(result_path),
        review_script=str(Path(__file__).resolve()), review_script_sha256=digest(__file__),
        OCR_script_sha256=digest(Path(__file__).with_name("menu_ocr.py")),
        runner_completed_field=session.get("completed"),
        runner_completed_is_not_menu_acceptance=True,
        actual_categories_observed=observed, missing_categories=sorted(CATEGORIES - set(observed)),
        original_Error_UI_steps=errors, checks=checks,
        diagnostic_menu_plan=plan, diagnostic_plan_checks=plan_checks,
        diagnostic_plan_passed=all(c["passed"] for c in plan_checks),
        diagnostic_menu_traversal_passed=all(c["passed"] for c in checks),
        full_natural_camera_boot_verified=False,
        synthetic_application_inputs=session.get("synthetic_application_inputs"),
        synthetic_persistent_TEMP=session.get("synthetic_persistent_TEMP"),
        observed_frames=frames,
        limitations=["OCR is inferred text; inspect saved images for visual confirmation",
                     "Diagnostic guest calls, TEMP and MCU replay do not qualify as natural boot",
                     "State restoration is a bounded menu check, not continuous live-view verification"])
    output.write_text(json.dumps(review, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({k: review[k] for k in ("actual_categories_observed", "missing_categories",
        "original_Error_UI_steps", "diagnostic_menu_traversal_passed", "full_natural_camera_boot_verified")},
        ensure_ascii=False))
    print("Review:", output)


if __name__ == "__main__":
    main()
