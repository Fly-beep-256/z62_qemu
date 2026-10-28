"""Recompute retained native AE boundaries without executing or changing a guest."""
import argparse
from collections import Counter
from pathlib import Path

from z62_common import ROOT, evidence_path, identity, read, save


def sample(event, label):
    for value in event.get("samples", []):
        if value.get("label") == label and "raw_hex" in value:
            return value, bytes.fromhex(value["raw_hex"])
    return {}, b""


def word(raw, offset=0, signed=False):
    if len(raw) < offset + 4:
        return None
    return int.from_bytes(raw[offset:offset + 4], "little", signed=signed)


def event_ref(event):
    return {key: event.get(key) for key in (
        "PC", "role", "global_cpu", "local_core", "window",
        "observation_sequence", "stop_epoch", "virtual_time_ns")}


def context_key(event):
    value, _ = sample(event, "context_header")
    return event.get("global_cpu"), value.get("address")


def ae_state(event):
    _, raw = sample(event, "exposure_state")
    _, selector = sample(event, "context_frame_selector")
    _, context = sample(event, "context_header")
    _, threshold = sample(event, "context_sequence_threshold")
    return dict(ae_byte_02=raw[2] if len(raw) > 2 else None,
                ae_word_40=word(raw, 0x40), ae_word_50=word(raw, 0x50),
                ae_word_58=word(raw, 0x58), ae_word_68=word(raw, 0x68),
                frame_selector=selector[0] if selector else None,
                context_sequence=word(context, signed=True),
                sequence_threshold=word(threshold, signed=True))


def pairs(events, start_pc, end_pc, same_context=False):
    """Match a start to the next selected end on that core; retain unmatched starts."""
    pending, found = {}, []
    for event in events:
        pc = int(event["PC"], 16)
        key = context_key(event) if same_context else event.get("global_cpu")
        if pc == start_pc:
            if key in pending:
                found.append(dict(start=event_ref(pending[key]), end=None,
                                  reason="another start before the selected end"))
            pending[key] = event
        elif pc == end_pc and key in pending:
            start = pending.pop(key)
            found.append(dict(start=event_ref(start), end=event_ref(event),
                              delta_virtual_ns=event["virtual_time_ns"] - start["virtual_time_ns"],
                              start_state=ae_state(start), end_state=ae_state(event)))
    found.extend(dict(start=event_ref(event), end=None,
                      reason="no subsequent selected end in retained coverage")
                 for event in pending.values())
    return found


def analyze(envelope):
    locked_path = envelope / "prepare/锁定命令与输入.json"
    result_path = envelope / "run/native-unified-result.json"
    log_path = envelope / "run/native-original-observations.jsonl"
    plan_path = envelope / "prepare/ui-observation-plan.json"
    locked, result, plan = read(locked_path), read(result_path), read(plan_path)
    if not all(isinstance(value, dict) for value in (locked, result, plan)):
        raise ValueError("A complete retained result, locked input and UI plan are required")
    events = sorted(result.get("original_ui_events", []),
                    key=lambda value: value["observation_sequence"])
    rom_entry = next(value for value in locked["firmware_manifest"]["images"]
                     if value["role"] == "master")
    rom_path = evidence_path(rom_entry["path"], envelope, locked)
    rom = rom_path.read_bytes()
    rom_identity = identity(rom_path)
    if rom_identity["sha256"] != rom_entry["sha256"]:
        raise ValueError("Master ROM identity differs from the run's locked input")
    for event in events:
        if event.get("role") != "master":
            continue
        offset = int(event["PC"], 16) - 0x10020000
        expected = bytes.fromhex(event["original_ROM_bytes"])
        if rom[offset:offset + len(expected)] != expected:
            raise ValueError("Retained original instruction differs from ROM: " + event["PC"])
    binary_entry = locked["selected_binary"]
    binary_identity = identity(evidence_path(binary_entry["path"], envelope, locked))
    if binary_identity["sha256"] != binary_entry["sha256"]:
        raise ValueError("Selected binary differs from the locked run identity")
    counts = Counter(event["PC"].lower() for event in events)
    by_window = Counter((event["PC"].lower(), event.get("window")) for event in events)
    coverage = []
    for site in plan["sites"]:
        pc = site["address"].lower()
        coverage.append(dict(PC=pc, label=site["label"], retained_hits=counts[pc],
                             active_windows=site.get("active_windows"),
                             hit_limit_per_window=site.get("max_hits_per_window"),
                             counts_by_window={window["label"]: by_window[pc, window["label"]]
                                               for window in plan.get("windows", [])}))
    exits = pairs(events, 0x1023134e, 0x1023143c, same_context=True)
    output_samples = [dict(event=event_ref(event), words=[word(raw, offset) for offset in (0, 4, 8)])
                      for event in events
                      for _, raw in [sample(event, "exposure_outputs")] if len(raw) == 12]
    final_outputs = next((value for value in result.get("SAISO_UI_RAM", [])
                          if value["label"] == "properties_180x"), None)
    segments = {}
    for first, second in ((0x1032168c, 0x10321ce0), (0x10321ce0, 0x10321ce4),
                          (0x10321ce6, 0x10321cea), (0x10321d7e, 0x10321d82)):
        segments[f"{first:08X}-{second:08X}"] = pairs(events, first, second)
    files = [locked_path, result_path, plan_path, log_path]
    return dict(schema="z62.native-exposure-boundary-analysis/1",
                envelope=identity(locked_path)["path"].removesuffix("/prepare/锁定命令与输入.json"),
                evidence_identities=[identity(path) for path in files if path.is_file()],
                master_ROM=rom_identity, binary=binary_identity,
                architecture_passed=result.get("architecture_passed"),
                debugger_zero_guest_writes=result.get("debugger_zero_guest_writes"),
                final_virtual_ns=result.get("final_evidence", {}).get("virtual_ns"),
                original_instruction_bytes_verified=True, retained_events=len(events),
                site_coverage=coverage, selector_to_exit_pairs=exits,
                callback_segments=segments, exposure_output_samples=output_samples,
                final_exposure_outputs=final_outputs,
                limitations=[
                    "No retained hit is bounded by installed windows and per-window hit limits.",
                    "Pairing records order on a selected core; it does not identify RTOS thread ownership.",
                    "Samples at a store instruction precede execution of that instruction.",
                    "This script reads existing evidence; it performs no QEMU or physical-camera operation."])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--envelope", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    envelope = args.envelope if args.envelope.is_absolute() else ROOT / args.envelope
    output = args.output if args.output.is_absolute() else ROOT / args.output
    report = analyze(envelope.resolve(strict=True))
    save(output, report)
    print("Saved", identity(output)["path"], "with", report["retained_events"],
          "events and", len(report["selector_to_exit_pairs"]), "selector/exit pairs")


if __name__ == "__main__":
    main()
