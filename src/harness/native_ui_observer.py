# SPDX-License-Identifier: GPL-2.0-or-later
"""Bounded, CPU-selected original MENU/SAISO observations on the common clock.

The plan binds every site to the retained ROM. Each virtual-time window gets
its own hit budget, so initialization cannot exhaust all post-input evidence.
Only ROM and declared SRAM/DDR reads are allowed. This collector neither owns
a debugger nor delivers inputs, resumes CPUs, writes state, or certifies UI.
"""
from collections import Counter
import hashlib
import json
from pathlib import Path


ROM_BASES = {"master": 0x10020000, "slave": 0x10020000, "MCU": 0x08000000}
RAM_RANGES = {"master": (0xc0000000, 0xd0000000),
              "slave": (0xc0000000, 0xd0000000), "MCU": (0x20000000, 0x20040000)}
REGISTERS = {"r"+str(i) for i in range(16)}
MAX_EVENT_BYTES = 16384


def number(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def validate_source(source, role):
    """Validate a bounded RAM pointer expression, without reading the guest."""
    if ("register" in source) == ("address" in source):
        raise ValueError("UI sample needs exactly one address source")
    if "register" in source:
        if source["register"] not in REGISTERS:
            raise ValueError("Invalid UI sample pointer register")
    else:
        lo, hi = RAM_RANGES[role]
        if not lo <= number(source["address"]) < hi:
            raise ValueError("UI fixed source is outside selected role RAM")
    steps = source.get("path", [])
    if not isinstance(steps, list) or len(steps) > 3:
        raise ValueError("UI source path requires at most three steps")
    for step in steps:
        if set(step) - {"offset", "dereference"}:
            raise ValueError("Unknown UI pointer path operation")
        offset = number(step.get("offset", 0))
        if not -65536 <= offset <= 65536 or type(step.get("dereference", False)) is not bool:
            raise ValueError("Invalid UI pointer path step")


def ram_read(reader, role, pointer, size, trace):
    lo, hi = RAM_RANGES[role]
    if not lo <= pointer <= hi-size:
        raise ValueError("pointer_outside_declared_RAM; no read attempted")
    raw = reader.memory(pointer, size)
    if len(raw) != size:
        raise ValueError("Incomplete UI RAM read")
    trace.append(dict(address=hex(pointer), bytes=size, raw_hex=raw.hex(),
                      sha256=hashlib.sha256(raw).hexdigest()))
    return raw


def resolve_source(source, reader, role, registers, trace):
    pointer = number(registers[source["register"]]) if "register" in source else number(source["address"])
    for step in source.get("path", []):
        pointer += number(step.get("offset", 0))
        if step.get("dereference", False):
            pointer = int.from_bytes(ram_read(reader, role, pointer, 4, trace), "little")
    return pointer


def load_plan(filename, blobs):
    filename = Path(filename).resolve(strict=True)
    raw = filename.read_bytes()
    plan = json.loads(raw)
    if plan.get("schema") not in {"z62.native-ui-observation-plan/1", "z62.native-ui-observation-plan/2",
                                  "z62.native-ui-observation-plan/3", "z62.native-ui-observation-plan/4"}:
        raise ValueError("Unsupported native UI observation plan")
    extended = not plan["schema"].endswith("/1")
    windows = plan.get("windows", [])
    if not windows or windows[0].get("start_virtual_ns") != 0:
        raise ValueError("UI observation windows must start at virtual zero")
    starts = [w["start_virtual_ns"] for w in windows]
    if any(type(s) is not int or s < 0 for s in starts) or starts != sorted(set(starts)):
        raise ValueError("UI observation windows must be strictly increasing")
    labels = [w["label"] for w in windows]
    if any(not isinstance(label, str) or not label for label in labels) or len(set(labels)) != len(labels):
        raise ValueError("UI observation windows need unique nonempty labels")
    sites, keys = plan.get("sites", []), set()
    if not sites or len(sites) > 64:
        raise ValueError("UI observation requires 1..64 bounded original sites")
    for site in sites:
        role, address = site["role"], number(site["address"])
        access = site.get("access", "execute")
        if role not in ROM_BASES or (role, address) in keys:
            raise ValueError("Invalid, duplicate or unaligned UI observation site")
        keys.add((role, address))
        blob = blobs[role]
        if hashlib.sha256(blob).hexdigest() != plan["ROM_sha256"][role]:
            raise ValueError("UI observation ROM identity differs for " + role)
        if access == "write":
            if not plan["schema"].endswith(("/3", "/4")):
                raise ValueError("RAM write observations require UI plan schema /3 or /4")
            size = site.get("bytes")
            lo, hi = RAM_RANGES[role]
            if type(size) is not int or size not in (1, 2, 4, 8) or not lo <= address <= hi-size:
                raise ValueError("Write watchpoint must be a bounded selected-role RAM range")
        elif access == "execute":
            offset = address - ROM_BASES[role]
            if (address & 1 or not 0 <= offset <= len(blob)-4 or
                    blob[offset:offset+4].hex() != site["original_ROM_bytes"]):
                raise ValueError("UI observation instruction bytes differ at " + hex(address))
        else:
            raise ValueError("UI observation access must be execute or write")
        if type(site["max_hits_per_window"]) is not int or not 1 <= site["max_hits_per_window"] <= 32:
            raise ValueError("UI observation hit budget must be 1..32")
        if "registers_equal" in site:
            conditions = site["registers_equal"]
            if (not plan["schema"].endswith("/4") or access != "execute" or
                    not isinstance(conditions, dict) or not 1 <= len(conditions) <= 8):
                raise ValueError("Register selection requires schema /4 and 1..8 execute-site conditions")
            for register, value in conditions.items():
                if (register not in REGISTERS or type(value) not in (int, str) or
                        not 0 <= number(value) <= 0xffffffff):
                    raise ValueError("Invalid UI register-selection condition")
            attempts = site.get("max_attempts_per_window")
            if (type(attempts) is not int or
                    not site["max_hits_per_window"] <= attempts <= 256):
                raise ValueError("Register selection needs a bounded attempt budget within hits..256")
        elif "max_attempts_per_window" in site:
            raise ValueError("An attempt budget requires explicit register-selection conditions")
        if "active_windows" in site:
            active = site["active_windows"]
            if (not extended or not isinstance(active, list) or not active or
                    any(not isinstance(label, str) or label not in labels for label in active) or
                    len(set(active)) != len(active)):
                raise ValueError("UI site active_windows requires unique schema /2 window labels")
        samples = site.get("samples", [])
        if len(samples) > 32 or sum(s["bytes"] for s in samples) > MAX_EVENT_BYTES:
            raise ValueError("UI event exceeds its sample or byte budget")
        for sample in samples:
            size = sample["bytes"]
            if type(size) is not int or not 1 <= size <= 1024:
                raise ValueError("UI observation sample must be 1..1024 bytes")
            if not extended and any(key in sample for key in ("path", "bytes_from", "when_count_exceeds")):
                raise ValueError("Indirect samples require UI plan schema /2")
            validate_source(sample, role)
            if "address" in sample and not sample.get("path"):
                lo, hi = RAM_RANGES[role]
                if not lo <= number(sample["address"]) <= hi-size:
                    raise ValueError("UI fixed sample is outside selected role RAM")
            for key in ("bytes_from", "when_count_exceeds"):
                if key in sample:
                    validate_source(sample[key], role)
                    if not sample[key].get("path", []) or not sample[key]["path"][-1].get("dereference"):
                        raise ValueError("UI length/count must come from a recorded RAM word")
            if "bytes_from" in sample and not 1 <= number(sample["bytes_from"].get("scale", 1)) <= 16:
                raise ValueError("UI array element scale must be 1..16")
            if "when_count_exceeds" in sample and not 0 <= number(sample["when_count_exceeds"]["threshold"]) < 32:
                raise ValueError("UI element index must be 0..31")
    return plan, dict(path=str(filename), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


class UIObserver:
    def __init__(self, filename, blobs):
        self.plan, self.identity = load_plan(filename, blobs)
        self.counts, self.attempts, self.events, self.window_index = Counter(), Counter(), [], 0
        self.points = {(s["role"], number(s["address"])): s for s in self.plan["sites"]}

    def advance(self, now):
        old = self.window_index
        while (self.window_index+1 < len(self.plan["windows"]) and
               now >= self.plan["windows"][self.window_index+1]["start_virtual_ns"]):
            self.window_index += 1
        return self.window_index != old

    def sites(self, access="execute"):
        label = self.plan["windows"][self.window_index]["label"]
        return {key: site["label"] for key, site in self.points.items()
                if site.get("access", "execute") == access and
                ("active_windows" not in site or label in site["active_windows"]) and
                ("registers_equal" not in site or
                 self.attempts[(self.window_index, *key)] < site["max_attempts_per_window"]) and
                self.counts[(self.window_index, *key)] < site["max_hits_per_window"]}

    def write_sites(self):
        return {key: dict(label=label, bytes=self.points[key]["bytes"])
                for key, label in self.sites("write").items()}

    def on_stop(self, reader, role, address, registers, observation):
        site = self.points[(role, address)]
        window = self.plan["windows"][self.window_index]
        if "active_windows" in site and window["label"] not in site["active_windows"]:
            raise ValueError("UI site is inactive in the current observation window")
        key = (self.window_index, role, address)
        conditions = site.get("registers_equal")
        selected = True
        if conditions is not None:
            if self.attempts[key] >= site["max_attempts_per_window"]:
                raise ValueError("UI register-selection attempt budget exhausted")
            self.attempts[key] += 1
            selected = all(number(registers[register]) == number(value)
                           for register, value in conditions.items())
        if selected:
            self.counts[key] += 1
        event = dict(schema="z62.native-ui-original-event/1", label=site["label"],
                     window=window["label"], window_index=self.window_index,
                     occurrence_in_window=self.counts[key], samples=[], **observation)
        if conditions is not None:
            event.update(register_selection_conditions=conditions, register_selection_matched=selected,
                         attempt_in_window=self.attempts[key])
            if not selected:
                event["sample_status"] = "register_selection_not_matched; no sample RAM read attempted"
                self.events.append(event)
                return event
        if site.get("access") == "write":
            event.update(observation_kind="RAM-write-watchpoint", watched_address=hex(address),
                         watched_bytes=site["bytes"])
        for sample in site.get("samples", []):
            trace = []
            item = dict(label=sample["label"], bytes=sample["bytes"],
                        address_source=sample.get("register", "fixed selected-role RAM"))
            try:
                if "when_count_exceeds" in sample:
                    guard = sample["when_count_exceeds"]
                    count = resolve_source(guard, reader, role, registers, trace)
                    item["observed_element_count"] = count
                    if count <= number(guard["threshold"]):
                        item.update(status="element_not_present; no payload read attempted", pointer_reads=trace)
                        event["samples"].append(item)
                        continue
                requested = sample["bytes"]
                if "bytes_from" in sample:
                    source = sample["bytes_from"]
                    requested = resolve_source(source, reader, role, registers, trace) * number(source.get("scale", 1))
                    item.update(requested_bytes=requested, truncated=requested > sample["bytes"])
                size = min(requested, sample["bytes"])
                item["bytes"] = size
                if size == 0:
                    item.update(status="empty_array; no payload read attempted", raw_hex="",
                                sha256=hashlib.sha256(b"").hexdigest())
                else:
                    pointer = resolve_source(sample, reader, role, registers, trace)
                    item["address"] = hex(pointer)
                    lo, hi = RAM_RANGES[role]
                    if lo <= pointer <= hi-size:
                        raw = reader.memory(pointer, size)
                        if len(raw) != size:
                            raise ValueError("Incomplete UI RAM read")
                        item.update(raw_hex=raw.hex(), sha256=hashlib.sha256(raw).hexdigest())
                    else:
                        item["status"] = "pointer_outside_declared_RAM; no read attempted"
            except Exception as exc:
                item["error"] = type(exc).__name__ + ": " + str(exc)
            if sample.get("path") or "bytes_from" in sample or "when_count_exceeds" in sample:
                item["pointer_reads"] = trace
            event["samples"].append(item)
        self.events.append(event)
        return event

    def completion(self):
        return dict(plan=self.identity, observed_events=len(self.events),
                    selected_events=sum(e.get("register_selection_matched", True) for e in self.events),
                    register_selection_attempts=[dict(window=self.plan["windows"][w]["label"], role=role,
                        address=hex(address), attempts=attempts,
                        max_attempts=self.points[(role, address)]["max_attempts_per_window"],
                        selected_hits=self.counts[(w, role, address)],
                        attempt_limit_reached=attempts >= self.points[(role, address)]["max_attempts_per_window"])
                        for (w, role, address), attempts in sorted(self.attempts.items())],
                    windows=self.plan["windows"], last_window_index=self.window_index,
                    site_windows=[dict(role=role, address=hex(address), active_windows=site["active_windows"])
                                  for (role, address), site in self.points.items() if "active_windows" in site],
                    write_watchpoints=[dict(role=role, address=hex(address), bytes=site["bytes"])
                                       for (role, address), site in self.points.items() if site.get("access") == "write"],
                    hit_counts=[dict(window=self.plan["windows"][w]["label"], role=role,
                                     address=hex(address), hits=hits,
                                     max_hits=self.points[(role, address)]["max_hits_per_window"])
                                for (w, role, address), hits in sorted(self.counts.items())],
                    guest_state_written=False, peripheral_MMIO_read_by_debugger=False,
                    MENU_or_exposure_acceptance_implied=False)
