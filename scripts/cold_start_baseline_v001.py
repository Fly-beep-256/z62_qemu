"""Verify or launch the frozen v0.01 native menu/OSD baseline."""

import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
BASELINE = Path("profiles/baselines/native-menu-v0.01")
COMMAND = [
    "./z62", "run", "--profile", "native", "--binary", "rebuilt",
    "--seconds", "1200", "--virtual-seconds", "34", "--display-observation",
    "--ui-plan", str(BASELINE / "ui-observation-plan.json"),
    "--pad-schedule", str(BASELINE / "external-pad-schedule.json"),
]


def contained_file(relative):
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("Expected a package-relative input: " + str(path))
    resolved = (ROOT / path).resolve(strict=True)
    if not resolved.is_relative_to(ROOT) or not resolved.is_file():
        raise ValueError("Input is not a file inside this package: " + str(path))
    return resolved


def read_json(relative):
    return json.loads(contained_file(relative).read_text(encoding="utf-8"))


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def verify_inputs():
    lock = read_json(BASELINE / "manifest.json")
    if (lock.get("schema") != "z62.cold-start-baseline/1"
            or lock.get("version") != "0.01"
            or lock.get("launch_argv") != COMMAND):
        raise ValueError("The v0.01 baseline manifest or launch contract has changed")
    for record in lock["files"]:
        path = contained_file(record["path"])
        if path.stat().st_size != record["bytes"] or digest(path) != record["sha256"]:
            raise ValueError("Frozen input identity differs: " + record["path"])

    expected_sources = set(lock["execution_paths"])
    for directory in ("src/harness", "profiles/native"):
        actual = {str(path.relative_to(ROOT)) for path in (ROOT / directory).rglob("*.py")}
        expected = {path for path in expected_sources if path.startswith(directory + "/")}
        if actual != expected:
            raise ValueError("Execution source set changed in " + directory)

    selection = read_json("artifacts/rebuilt/latest.json")
    expected = lock["selected_build"]
    if selection.get("directory") != expected["directory"]:
        raise ValueError("The native launcher selects another build: "
                         + str(selection.get("directory"))
                         + "; v0.01 requires " + expected["directory"])
    for key in ("binary", "EXPEED_manifest", "MCU_manifest", "build_status"):
        record = selection.get(key, {})
        if any(record.get(field) != value for field, value in expected[key].items()):
            raise ValueError("The selected build record differs from v0.01: " + key)
    status = read_json(expected["build_status"]["path"])
    bus = selection.get("bus_binary") or status.get("bus_binary", {})
    if any(bus.get(field) != value for field, value in lock["bus_binary"].items()):
        raise ValueError("The selected MCU wire tool differs from v0.01")
    return lock


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--verify-only", action="store_true",
                        help="Check baseline identities without launching QEMU")
    args = parser.parse_args(argv)
    try:
        lock = verify_inputs()
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("Baseline v0.01 preflight failed: " + str(error), file=sys.stderr)
        return 1
    print("Verified native menu/OSD baseline v0.01: %d files, %d execution sources."
          % (len(lock["files"]), len(lock["execution_paths"])), flush=True)
    print("Launch command: " + shlex.join(COMMAND), flush=True)
    if args.verify_only:
        return 0
    return subprocess.run(COMMAND, cwd=ROOT, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
