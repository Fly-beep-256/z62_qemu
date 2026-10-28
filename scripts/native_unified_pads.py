# SPDX-License-Identifier: GPL-2.0-or-later
"""Declare external pad deadlines to the existing unified QEMU owner.

No QEMU, QMP or GDB connection is opened here. Host polling observes the
owner's actual virtual clock; it never supplies guest time. A delivered pad
readback is not original MENU handling, a physical button identity, or a
complete camera acceptance. The complete schedule must be acknowledged.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import time

# The legacy 25/165/... deadlines were host seconds, not virtual seconds.
# PC5 at 2 s restores LCD scanout in the 120-host-second observation. The
# 360-host-second reduced scenario 20261025-213438 also includes MENU at
# 6.5/6.7 s and saves OSD then an hourglass. That is not a single-variable
# MENU comparison. The full scenario 20261025-214323 saves a battery error
# dialog. Subsequent GPIO pairs retain the declared external input order.
# These deadlines and pin labels are not measured physical camera timings.
SCHEDULE = [(2, "GPIO", 0x20, 0, "PC5:close-low", "C"),
            (6.5, "PCAL", 0x200, 0, "MENU-pad:low", None),
            (6.7, "PCAL", 0x200, 0x200, "MENU-pad:release", None),
            (8, "GPIO", 0x02, 0, "PG1:low", "G"),
            (8.2, "GPIO", 0x02, 0x02, "PG1:release", "G"),
            (10, "GPIO", 0x04, 0, "PG2:low", "G"),
            (10.2, "GPIO", 0x04, 0x04, "PG2:release", "G")]


def schedule_rows(events):
    return [dict(at_virtual_seconds=e[0], pad_kind=e[1], mask=e[2],
                 levels=e[3], label=e[4], port=e[5]) for e in events]


def load_schedule(path):
    """Read a frozen table of external pads; no guest state or key mapping."""
    document = json.loads(Path(path).read_text())
    if not isinstance(document, dict) or document.get("timebase") != "QEMU_CLOCK_VIRTUAL":
        raise ValueError("External pads require QEMU_CLOCK_VIRTUAL")
    rows = document.get("schedule")
    if not isinstance(rows, list) or not 1 <= len(rows) <= 256:
        raise ValueError("External pad schedule requires 1..256 events")
    events, previous = [], -1
    fields = ("at_virtual_seconds", "pad_kind", "mask", "levels", "label", "port")
    for row in rows:
        if isinstance(row, dict):
            if set(row) != set(fields):
                raise ValueError("External pad event has missing or extra fields")
            row = [row[key] for key in fields]
        if not isinstance(row, (list, tuple)) or len(row) != 6:
            raise ValueError("External pad event requires six fields")
        seconds, kind, mask, levels, label, port = row
        if (type(seconds) not in (int, float) or not math.isfinite(seconds)
                or not 0 <= seconds <= 3600 or seconds < previous):
            raise ValueError("External pad deadlines must be finite and ordered")
        if kind not in ("GPIO", "PCAL"):
            raise ValueError("External pad kind must be GPIO or PCAL")
        width = 0xffff if kind == "GPIO" else 0xffffff
        if (type(mask) is not int or not 0 < mask <= width
                or type(levels) is not int or levels < 0 or levels & ~mask):
            raise ValueError("External pad levels must fit their nonzero mask")
        if (kind == "GPIO" and port not in tuple("ABCDEFGH")
                or kind == "PCAL" and port is not None):
            raise ValueError("External GPIO requires port A..H; PCAL has no GPIO port")
        if not isinstance(label, str) or not label or len(label) > 120:
            raise ValueError("External pad label must contain 1..120 characters")
        events.append(tuple(row))
        previous = seconds
    return events


def utc():
    return datetime.now(timezone.utc).isoformat()


def read(p):
    try:
        return json.loads(Path(p).read_text())
    except FileNotFoundError:
        return None


def save(p, value):
    p = Path(p)
    temporary = p.with_name(p.name + ".scenario-writing")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    temporary.replace(p)


def identity(p):
    p = Path(p).resolve(strict=True)
    raw = p.read_bytes()
    return dict(path=str(p), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def make_request(sequence, event, origin, owner=None):
    seconds, kind, mask, levels, label, port = event
    request = dict(schema="z62.virtual-pad-request/1", sequence=sequence,
                   pad_kind=kind, mask=mask, levels=levels, label=label,
                   at_virtual_ns=origin + int(seconds * 1_000_000_000))
    if port is not None:
        request["port"] = port
    if owner is not None:
        request.update(owner_pid=owner["pid"], owner_uuid=owner["owner_uuid"])
    return request


def ack_matches(request, state):
    if not isinstance(state, dict):
        return False
    prop = ("gpio-pin-levels-" + request.get("port", "")
            if request.get("pad_kind") == "GPIO" else "pcal-pin-levels")
    integers = ("previous_levels", "requested_levels", "readback", "applied_virtual_ns",
                "after_virtual_ns", "lateness_ns", "requested_virtual_ns")
    if any(type(state.get(key)) is not int for key in integers):
        return False
    wanted = (state["previous_levels"] & ~request["mask"]) | request["levels"]
    return (state.get("sequence") == request["sequence"] and state.get("request") == request
            and state.get("owner_pid") == request.get("owner_pid")
            and type(request.get("owner_pid")) is int and request["owner_pid"] > 0
            and state.get("owner_uuid") == request.get("owner_uuid") and bool(request.get("owner_uuid"))
            and state.get("property") == prop and state.get("delivered") is True
            and state.get("readback_verified") is True and not state.get("error")
            and state["requested_levels"] == state["readback"] == wanted
            and state["requested_virtual_ns"] == request["at_virtual_ns"]
            and state["applied_virtual_ns"] >= request["at_virtual_ns"]
            and state["after_virtual_ns"] >= state["applied_virtual_ns"]
            and state["lateness_ns"] == state["applied_virtual_ns"] - request["at_virtual_ns"])


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    ap.add_argument("--prepare-dir", type=Path, required=True)
    ap.add_argument("--run-dir", type=Path, required=True)
    ap.add_argument("--safety-timeout", type=float, default=120)
    ap.add_argument("--startup-timeout", type=float, default=200)
    ap.add_argument("--schedule", type=Path, help="Frozen external pad input table")
    args = ap.parse_args(argv)
    if args.safety_timeout <= 0 or args.startup_timeout <= 0:
        ap.error("Timeouts must be positive host seconds")
    run = args.run_dir.resolve(strict=True)
    schedule = load_schedule(args.schedule) if args.schedule is not None else SCHEDULE
    result = run / "native-gpio-scenario-result.json"
    report = dict(schema="z62.native-unified-pad-scenario/1", started=utc(),
                  script=identity(__file__), schedule_timebase="QEMU_CLOCK_VIRTUAL",
                  budget_host_seconds=args.safety_timeout, startup_host_seconds=args.startup_timeout,
                  host_sleep_is_guest_time=False, guest_state_writes=0,
                  physical_button_names_verified=False, ACK_is_business_acceptance=False,
                  schedule=schedule_rows(schedule),
                  events=[], complete=False, pending_schedule_indices=list(range(len(schedule))))
    if args.schedule is not None:
        report["schedule_input"] = identity(args.schedule)
    save(result, report)
    host_deadline = time.monotonic() + args.startup_timeout
    state_path = run / "native-unified-state.json"
    try:
        while True:
            state = read(state_path)
            if state and state.get("ready") is True:
                if state.get("active") is not True:
                    raise RuntimeError("Unified owner ended before scenario attached")
                break
            if state and state.get("active") is False:
                raise RuntimeError("Unified owner stopped before external input attachment")
            if time.monotonic() >= host_deadline:
                raise TimeoutError("Host budget expired waiting for the unified owner")
            time.sleep(0.025)
        host_deadline = time.monotonic() + args.safety_timeout
        locked_file = args.prepare_dir / "锁定命令与输入.json"
        locked = read(locked_file)
        if not locked:
            raise ValueError("Missing retained locked input paths")
        report["locked_input_identity"] = identity(locked_file)
        if locked.get("scenario_schedule") != report["schedule"]:
            raise ValueError("External pad table differs from the launch-time contract")
        if args.schedule is not None:
            retained = locked.get("scenario_schedule_input", {})
            if (retained.get("sha256") != report["schedule_input"]["sha256"]
                    or retained.get("bytes") != report["schedule_input"]["bytes"]):
                raise ValueError("External pad input identity differs from the launch-time contract")
        origin = state.get("virtual_origin_ns")
        if type(origin) is not int or origin < 0:
            raise ValueError("Missing actual common virtual time origin")
        report["virtual_origin_ns"] = origin
        if type(state.get("pid")) is not int or state["pid"] <= 0 or not state.get("owner_uuid"):
            raise ValueError("Missing actual unified owner PID/UUID")
        owner = {"pid": state["pid"], "owner_uuid": state["owner_uuid"]}
        report.update(owner_pid=owner["pid"], owner_uuid=owner["owner_uuid"])
        channels = state.get("input_channels", {})
        expected = {"GPIO": "explicit_MCU_gpio_host_input_file",
                    "PCAL": "explicit_MCU_host_input_file"}
        for kind, key in expected.items():
            if kind not in channels or "request_path" not in channels[kind] or key not in locked:
                raise ValueError("Owner/locked input channel is absent: " + kind)
            if Path(channels[kind]["request_path"]).resolve() != Path(locked[key]).resolve():
                raise ValueError("Owner uses a different declared external input file: " + kind)
        report["input_channels"] = channels
        for index, event in enumerate(schedule):
            kind = event[1]
            channel = channels[kind]
            previous = read(channel["state_path"])
            if not previous or type(previous.get("sequence")) is not int:
                raise ValueError("Actual input channel sequence is missing")
            request = make_request(previous["sequence"] + 1, event, origin, owner)
            report["events"].append(dict(schedule_index=index, request=request,
                                         submitted_host_ns=time.monotonic_ns(), delivered=False))
            save(result, report)
            # Submit before the deadline. The owner compares to the actual QOM
            # clock and reports polling lateness; no exact timer claim is made.
            save(channel["request_path"], request)
            while True:
                acknowledgement = read(channel["state_path"])
                if ack_matches(request, acknowledgement):
                    report["events"][-1].update(delivered=True, acknowledgement=acknowledgement)
                    report["pending_schedule_indices"].remove(index)
                    save(result, report)
                    break
                if (acknowledgement and acknowledgement.get("sequence") == request["sequence"]
                        and acknowledgement.get("error")):
                    raise RuntimeError("External input rejected: " + acknowledgement["error"])
                state = read(state_path)
                if not state or state.get("active") is not True:
                    report["last_actual_virtual_ns"] = state.get("virtual_time_ns") if state else None
                    raise RuntimeError("Unified owner ended before the full virtual schedule was delivered")
                if state.get("pid") != owner["pid"] or state.get("owner_uuid") != owner["owner_uuid"]:
                    raise RuntimeError("Unified input owner changed during the scenario")
                if time.monotonic() >= host_deadline:
                    report["host_budget_truncated"] = True
                    report["last_actual_virtual_ns"] = state.get("virtual_time_ns")
                    raise TimeoutError("Host safety budget expired with virtual events still pending")
                time.sleep(0.01)
        report["complete"] = not report["pending_schedule_indices"] and len(report["events"]) == len(schedule)
        report["status"] = "declared_external_inputs_delivered; camera_function_not_implied"
    except BaseException as exc:
        report["status"] = "scenario_incomplete"
        report["error"] = type(exc).__name__ + ": " + str(exc)
    finally:
        report["finished"] = utc()
        save(result, report)
    print(report["status"], flush=True)
    return int(not report["complete"])


if __name__ == "__main__":
    raise SystemExit(main())
