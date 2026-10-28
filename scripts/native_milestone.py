"""Source-bound v0.0.2 native method; no physical-camera operations."""

import argparse
import json
import math
from pathlib import Path
import shlex
import sys

from z62_common import ROOT, digest, identity, read


VERSION = "0.0.2"
BASELINE = Path("profiles/baselines/native-v0.0.2")


def contained_file(root, value):
    path = Path(value)
    if ".." in path.parts:
        raise ValueError("Parent traversal is not a milestone input: " + str(path))
    resolved = (path if path.is_absolute() else root / path).resolve(strict=True)
    if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
        raise ValueError("Milestone input must be a file inside this package: " + str(path))
    return resolved


def verify_public(root=ROOT):
    root = root.resolve()
    manifest_file = contained_file(root, BASELINE / "manifest.json")
    manifest = json.loads(manifest_file.read_text())
    if (manifest.get("schema") != "z62.native-milestone/1"
            or manifest.get("version") != VERSION
            or manifest.get("research_checkpoint") != "V44"
            or manifest.get("guest_state_injection") is not False
            or manifest.get("camera_access") is not False
            or (root / "VERSION").read_text().strip() != VERSION):
        raise ValueError("The v0.0.2 native milestone contract differs")
    records = manifest["files"]
    paths = [item["path"] for item in records]
    if len(paths) != len(set(paths)):
        raise ValueError("Duplicate milestone source identities")
    if len(manifest["model_sources"]) != 119 or not set(manifest["model_sources"]).issubset(paths):
        raise ValueError("The milestone requires all 119 native model source identities")
    for item in records:
        path = contained_file(root, item["path"])
        if path.stat().st_size != item["bytes"] or digest(path) != item["sha256"]:
            raise ValueError("v0.0.2 source/input identity changed: " + item["path"])
    execution = {str(p.relative_to(root)) for p in (root / "src/harness").rglob("*.py")}
    expected = {p for p in paths if p.startswith("src/harness/") and p.endswith(".py")}
    if execution != expected:
        raise ValueError("The native harness source set differs from v0.0.2")
    plan = json.loads(contained_file(root, BASELINE / "ui-observation-plan.json").read_text())
    pads = json.loads(contained_file(root, BASELINE / "external-pad-schedule.json").read_text())
    if (plan.get("ROM_sha256") != manifest["firmware_sha256"]
            or len(plan.get("sites", [])) != 64 or plan.get("guest_state_injection") is not False
            or len(pads.get("schedule", [])) != 25
            or manifest["virtual_seconds"] != 34
            or manifest["models"] != {"isp_commit": "next-frame-ae-v4", "image_status": "pending-v1"}):
        raise ValueError("The v0.0.2 observation or explicit device-model contract differs")
    return manifest, dict(
        version=VERSION, research_checkpoint="V44", manifest=identity(manifest_file, root),
        source_recipe_verified=True, checked_file_count=len(records),
        compiled_model_source_count=len(manifest["model_sources"]),
        observation_sites=64, external_input_edges=25,
        runtime_verified=False, camera_access=False, guest_state_injection=False,
        scope="Original numerical exposure and LCD observation; metering remains pending")


def selected_inputs(args, manifest, root=ROOT, require=False):
    defaults = manifest["local_input_defaults"]
    selection = root / manifest["local_input_selection"]
    supplied = {}
    if selection.exists():
        supplied = json.loads(contained_file(root, selection).read_text())
        if set(supplied) != {"persistent_input", "mcu_rtc_backup_input"}:
            raise ValueError("Local selection requires exactly the two documented input paths")
    values = {}
    for key in ("persistent_input", "mcu_rtc_backup_input"):
        value = getattr(args, key, None) or supplied.get(key) or defaults[key]
        path = Path(value)
        if require:
            path = contained_file(root, path)
        elif path.is_absolute():
            if not path.resolve().is_relative_to(root.resolve()):
                raise ValueError("Printed input path must stay inside the package")
        elif ".." in path.parts:
            raise ValueError("Printed input path must stay inside the package")
        values[key] = path
    return values


def command(manifest, inputs, seconds):
    return ["./z62", "run", "--profile", "native", "--binary", "rebuilt",
            "--seconds", format(seconds, "g"), "--virtual-seconds", "34", "--display-observation",
            "--ui-plan", str(BASELINE / "ui-observation-plan.json"),
            "--pad-schedule", str(BASELINE / "external-pad-schedule.json"),
            "--isp-commit-model", manifest["models"]["isp_commit"],
            "--image-status-model", manifest["models"]["image_status"],
            "--persistent-input", str(inputs["persistent_input"]), "--persistent-output",
            "--mcu-rtc-backup-input", str(inputs["mcu_rtc_backup_input"]),
            "--mcu-rtc-backup-output"]


def verify_runtime(manifest, inputs, root=ROOT):
    sys.path.insert(0, str(root / "src/harness"))
    from persistent_input import inspect_spec as inspect_persistent
    from rtc_backup_input import inspect_spec as inspect_rtc
    from native_ui_observer import load_plan
    from native_unified_pads import load_schedule
    from native_unified_probe import verify_unified_manifest

    firmware = {}
    for role, filename in (("master", "master-original-with-crc.bin"),
                           ("slave", "slave-original-with-crc.bin"),
                           ("MCU", "ex1850_012000.bi.bin")):
        path = contained_file(root, "inputs/firmware/" + filename)
        if digest(path) != manifest["firmware_sha256"][role]:
            raise ValueError("v0.0.2 firmware identity differs for " + role)
        firmware[role] = path.read_bytes()
    load_plan(root / BASELINE / "ui-observation-plan.json", firmware)
    load_schedule(root / BASELINE / "external-pad-schedule.json")
    selection = read(root / "artifacts/rebuilt/latest.json")
    if not selection:
        raise ValueError("No prepared rebuilt selection; see docs/NATIVE-v0.0.2.md")
    models = {item["path"].removeprefix("src/qemu/"): item["sha256"]
              for item in manifest["files"] if item["path"] in manifest["model_sources"]}
    selected_binary = contained_file(root, selection["binary"]["path"])
    if digest(selected_binary) != selection["binary"]["sha256"]:
        raise ValueError("Selected QEMU binary identity changed")
    binaries = set()
    for key in ("EXPEED_manifest", "MCU_manifest"):
        item = selection[key]
        path = contained_file(root, item["path"])
        if digest(path) != item["sha256"]:
            raise ValueError("Selected QEMU build manifest changed: " + key)
        data = json.loads(path.read_text())
        verify_unified_manifest(data)
        actual = {name: value["sha256"] for name, value in data["unified_native_model_sources"].items()}
        if actual != models:
            raise ValueError("Selected QEMU compiled another native model source set")
        binaries.add((data["binary"], data["binary_sha256"]))
    if binaries != {(selection["binary"]["path"], selection["binary"]["sha256"])}:
        raise ValueError("The native domains do not select the same QEMU")
    persistent, _ = inspect_persistent(inputs["persistent_input"], "master")
    rtc, _ = inspect_rtc(inputs["mcu_rtc_backup_input"])
    for key, value in manifest["persistent_input_identity"].items():
        if persistent.get(key) != value:
            raise ValueError("Persistent payload differs from the retained v0.0.2 input: " + key)
    if rtc["sha256"] != manifest["rtc_bank_sha256"]:
        raise ValueError("RTC bank differs from the retained v0.0.2 input")
    return dict(QEMU=identity(selected_binary, root),
                persistent_manifest=identity(inputs["persistent_input"], root),
                persistent_payload_sha256=persistent["sha256"],
                RTC_manifest=identity(inputs["mcu_rtc_backup_input"], root),
                RTC_bank_sha256=rtc["sha256"], RTC_producer_evidence_verified=True,
                source_bound_runtime_inputs_verified=True, runtime_verified=False,
                binary_equals_reference=selection["binary"]["sha256"] == manifest["reference_build"]["QEMU_sha256"])


def add_arguments(parser):
    parser.add_argument("--baseline", choices=("v0.0.2",), default="v0.0.2")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--check-only", action="store_true", help="Check published sources and plans; no runtime or firmware required")
    modes.add_argument("--print-command", action="store_true", help="Print the explicit experimental launch recipe without running QEMU")
    modes.add_argument("--preflight-only", action="store_true", help="Check prepared firmware, source-bound build and retained inputs without running QEMU")
    parser.add_argument("--persistent-input", type=Path, help="Package-local, independently prepared retained Flash input manifest")
    parser.add_argument("--mcu-rtc-backup-input", type=Path, help="Package-local RTC manifest with all original producer evidence")
    parser.add_argument("--seconds", type=float, default=1800, help="Host safety budget; the milestone virtual window remains 34 seconds")


def run_milestone(args, run_callback, doctor_callback, root=ROOT):
    try:
        if not math.isfinite(args.seconds) or not 1 <= args.seconds <= 1800:
            raise ValueError("Host safety budget must be finite and within 1..1800 seconds")
        manifest, checked = verify_public(root)
        print("Z62 QEMU v0.0.2 / V44 native exposure milestone", flush=True)
        print("Explicit hypotheses: next-frame-ae-v4, pending-v1. Changing-light metering and RAW/ISP completion remain pending.", flush=True)
        if args.check_only:
            print(json.dumps(checked, indent=2), flush=True)
            return 0
        inputs = selected_inputs(args, manifest, root, require=not args.print_command)
        print("Effective recipe: " + shlex.join(command(manifest, inputs, args.seconds)), flush=True)
        if args.print_command:
            return 0
        checked.update(verify_runtime(manifest, inputs, root))
        if args.preflight_only:
            doctor = doctor_callback(quiet=True)
            checked["package_runtime_dependencies_verified"] = doctor["passed"]
            print(json.dumps(checked, indent=2), flush=True)
            if not doctor["passed"]:
                for item in doctor["checks"]:
                    if not item["passed"]:
                        print("FAIL " + item["name"] + ": " + item["error"], file=sys.stderr)
            return 0 if doctor["passed"] else 1
        launch = argparse.Namespace(
            command="run", profile="native", binary="rebuilt", seconds=args.seconds,
            virtual_seconds=34.0, full=False, architecture_only=False, display_observation=True,
            ui_plan=BASELINE / "ui-observation-plan.json", pad_schedule=BASELINE / "external-pad-schedule.json",
            tg_clock_model=None, isp_commit_model="next-frame-ae-v4", image_status_model="pending-v1",
            persistent_input=inputs["persistent_input"], persistent_output=True,
            mcu_rtc_retained=None, mcu_rtc_backup_input=inputs["mcu_rtc_backup_input"],
            mcu_rtc_backup_output=True, native_milestone=checked)
        return run_callback(launch)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("Native v0.0.2 preflight failed: " + str(error), file=sys.stderr)
        print("Use --check-only for the source distribution; prepared runtime instructions: docs/NATIVE-v0.0.2.md", file=sys.stderr)
        return 1
