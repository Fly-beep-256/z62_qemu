"""Optional stopped EXPEED RAM observations, bounded by an explicit plan.

The optional registry mode reads the original kernel's TCB table and event-flag
wait objects. The default RAM-pointer mode remains a candidate heuristic.
Neither mode unwinds call chains, resumes CPUs or writes guest state. Stop
times are separate host observations.
"""
from collections import deque
from pathlib import Path
import hashlib
import json
import time
import traceback

RAM_WINDOWS = {
    "master": ((0xC1800000, 0x0134B000), (0xC2B4C000, 0x0008C000),
               (0xC2BE0000, 0x052E9000), (0xC7EF0000, 0xD000)),
    "slave": ((0xC1000000, 0x008C0000), (0xC18CC000, 0x00059000),
              (0xC1930000, 0x05694000), (0xC70F0000, 0xD000)),
}
LIMIT_CEILINGS = dict(max_candidates=512, max_depth=2, max_edges=8192,
                      max_stacks=128, stack_before=64, stack_after=1024,
                      max_requested_bytes=1024*1024)
# Addresses come from each original ROM's task-index and flag-wait handlers:
# Master 1010611c/10111540/10111678; Slave 10037af0/10042f14/10043040.
REGISTRY_LAYOUTS = {
    "master": dict(task_base_pointer=0xC18AD81C, task_count=0xC18AD820,
                   flag_count_and_base=0xC18AEC38,
                   flag_wait_specs=[0xC18AEC48, 0xC18AEC54]),
    "slave": dict(task_base_pointer=0xC1016850, task_count=0xC1016854,
                  flag_count_and_base=0xC1017C50,
                  flag_wait_specs=[0xC1017C60, 0xC1017C6C]),
}


BUSINESS_WRAPPERS = {"master": 0x103DEBBD, "slave": 0x1006CB81}


def save(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def address(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def ram_window(role, start, length):
    if length <= 0 or start < 0 or start + length > 0x100000000:
        return None
    return next(((base, size) for base, size in RAM_WINDOWS[role]
                 if base <= start and start + length <= base + size), None)


def load_plan(path, blobs):
    path = Path(path).resolve(strict=True)
    body = path.read_bytes()
    plan = json.loads(body)
    if plan.get("schema") != "z6ii-stopped-task-observation/1" or set(plan.get("roles", {})) != set(RAM_WINDOWS):
        raise ValueError("Task observation needs the explicit two-role RAM plan")
    for role, item in plan["roles"].items():
        if hashlib.sha256(blobs[role]).hexdigest() != item["original_ROM_sha256"]:
            raise ValueError(f"Task observation original ROM identity mismatch: {role}")
        actual = tuple((address(w["base"]), address(w["bytes"])) for w in item["RAM_windows"])
        if actual != RAM_WINDOWS[role]:
            raise ValueError(f"Task observation cannot expand the known RAM windows: {role}")
        limits = item["limits"]
        if set(limits) != set(LIMIT_CEILINGS):
            raise ValueError("Task observation requires every explicit bound")
        for key, maximum in LIMIT_CEILINGS.items():
            value = limits[key]
            if type(value) is not int or not 0 <= value <= maximum or (
                    key not in ("max_depth", "stack_before") and value == 0):
                raise ValueError(f"Invalid observation bound {role}/{key}")
        if item.get("candidate_header_bytes") != 256 or item.get("saved_SP_offset") != 0xBC:
            raise ValueError("Saved-context observation requires the reviewed +0xbc/256-byte candidate")
        names = set()
        total = 0
        for root in item["roots"]:
            start, length = address(root["address"]), address(root["bytes"])
            if root["name"] in names or not ram_window(role, start, length) or start % 4 or length % 4:
                raise ValueError(f"Invalid or non-RAM observation root: {role}/{root['name']}")
            names.add(root["name"])
            total += length
        if total > limits["max_requested_bytes"] // 2:
            raise ValueError("Task roots consume too much of the bounded observation budget")
        registry = item.get("registry")
        if registry is not None:
            if registry.get("schema") != "z6ii-original-task-registry/1":
                raise ValueError("Unknown original task registry layout")
            if registry.get("layout") != REGISTRY_LAYOUTS[role] or item.get("pointer_chasing") is not False:
                raise ValueError("Registry observation requires original addresses and no pointer chasing")
            for key, maximum in (("max_slots", 4096), ("max_flags", 4096), ("read_chunk_bytes", 2048)):
                value = registry.get(key)
                if type(value) is not int or not 1 <= value <= maximum:
                    raise ValueError(f"Invalid original registry bound {role}/{key}")
            if registry["read_chunk_bytes"] % 4 or not isinstance(registry.get("stack_name_patterns"), list):
                raise ValueError("Registry chunks and stack-name selection must be explicit")
        if registry is not None and registry.get("business_descriptors") is not None:
            validate_business_descriptors(role, registry["business_descriptors"], blobs[role])
    return plan, dict(path=str(path), bytes=len(body), sha256=hashlib.sha256(body).hexdigest())


def validate_business_descriptors(role, descriptors, original):
    if not isinstance(descriptors, list) or not 1 <= len(descriptors) <= 512:
        raise ValueError("Business descriptors require a bounded original table")
    names, addresses = set(), set()
    for desc in descriptors:
        start, offset = address(desc["address"]), address(desc["original_image_offset"])
        raw = original[offset:offset+28]
        name = raw[16:28].split(b"\0", 1)[0].decode("ascii")
        if (len(raw) != 28 or name != desc["name"] or
                raw[:26].hex() != desc["original_prefix26_hex"] or name in names or
                start in addresses or start % 4 or not ram_window(role, start, 28)):
            raise ValueError("Business descriptor differs from the original ROM")
        mapped = False
        for pos in range(0x14000, 0x14400, 16):
            source, destination, size, initializer = [int.from_bytes(original[pos+i:pos+i+4], "little")
                                                    for i in (0, 4, 8, 12)]
            if initializer == 0x1002006C and source-0x10020000 <= offset < source-0x10020000+size:
                mapped = start == destination+offset-(source-0x10020000)
                break
        if not mapped:
            raise ValueError("Business descriptor address differs from original scatter copy")
        names.add(name)
        addresses.add(start)
    ordered = sorted(addresses)
    if any(b-a != 28 for a, b in zip(ordered, ordered[1:])):
        raise ValueError("Business descriptors must be one original contiguous table")


def observe_business_tasks(role, config, registry, report, allocated, read):
    descriptors = config["business_descriptors"]
    mapping = registry["business_mapping"] = dict(descriptor_count=len(descriptors),
        descriptors=[], errors=[], mapped_count=0, exact_object_bytes=32,
        wrapper_entry=hex(BUSINESS_WRAPPERS[role]), pointer_chasing=False)
    first = min(address(d["address"]) for d in descriptors)
    length = len(descriptors)*28
    parts = []
    for offset in range(0, length, config["read_chunk_bytes"]):
        size = min(config["read_chunk_bytes"], length-offset)
        raw = read("business-descriptors", first+offset, size, "original business task descriptor table")
        if raw is None:
            raise RuntimeError("Original business descriptor table could not be read")
        parts.append(raw)
    descriptor_table = b"".join(parts)
    by_slot = {t["slot"]: t for t in allocated}
    by_task = {}
    for desc in descriptors:
        offset = address(desc["address"])-first
        raw = descriptor_table[offset:offset+28]
        slot = int.from_bytes(raw[0x1A:0x1C], "little")
        row = dict(name=desc["name"], address=hex(address(desc["address"])), runtime_slot=slot)
        mapping["descriptors"].append(row)
        if raw[:26].hex() != desc["original_prefix26_hex"]:
            mapping["errors"].append(dict(**row, error="runtime original descriptor prefix changed"))
        elif slot == 0:
            row["created"] = False
        elif slot not in by_slot or address(by_slot[slot]["entry"]) != BUSINESS_WRAPPERS[role]:
            mapping["errors"].append(dict(**row, error="descriptor slot is not an allocated wrapper task"))
        elif slot in by_task:
            mapping["errors"].append(dict(**row, error="two original descriptors share a runtime task slot"))
        else:
            row["created"] = True
            by_task[slot] = row
    for task in allocated:
        if address(task["entry"]) != BUSINESS_WRAPPERS[role]:
            continue
        ptr = address(task["exinf"])
        if not ram_window(role, ptr, 32):
            mapping["errors"].append(dict(slot=task["slot"], error="exact exinf object outside original RAM"))
            continue
        raw = read("business-exinf", ptr, 32, f"original wrapper exinf for TCB {task['address']}")
        if raw is None:
            continue
        object_ID = int.from_bytes(raw[:4], "little")
        task["business_object"] = dict(address=hex(ptr), read_index=len(report["reads"])-1,
            object_task_ID=hex(object_ID), business_entry=hex(int.from_bytes(raw[4:8], "little")),
            object_ID_matches=object_ID == address(task["task_ID"]))
        if object_ID != address(task["task_ID"]):
            mapping["errors"].append(dict(slot=task["slot"], error="exact exinf object task ID differs from TCB"))
            continue
        row = by_task.get(task["slot"])
        if row:
            task["business_name"] = row["name"]
            task["business_descriptor"] = row["address"]
            row.update(TCB=task["address"], task_ID=task["task_ID"], exinf=task["exinf"],
                       business_entry=task["business_object"]["business_entry"], verified=True)
            mapping["mapped_count"] += 1
    mapping["unmapped_wrapper_slots"] = [t["slot"] for t in allocated
        if address(t["entry"]) == BUSINESS_WRAPPERS[role] and not t.get("business_name")]
    mapping["complete_within_original_descriptors"] = not mapping["errors"] and all(
        not row.get("created") or row.get("verified") for row in mapping["descriptors"])


def observe_registry(role, item, report, read):
    """Read only the real table, saved contexts and exact event-flag objects."""
    config = item["registry"]
    layout = REGISTRY_LAYOUTS[role]
    registry = report["task_registry"] = dict(layout=layout, stride=0xD8, tasks=[],
        complete=False, slot_IDs_verified=False, flag_waits=[], wait_specs=[])
    roots = {}
    for name, ptr in (("task-base-pointer", layout["task_base_pointer"]),
                      ("task-count", layout["task_count"]),
                      ("flag-count-and-base", layout["flag_count_and_base"])):
        body = read("registry-root", ptr, 8 if name == "flag-count-and-base" else 4, name)
        if body is None:
            raise RuntimeError("Original registry root could not be read: " + name)
        roots[name] = [int.from_bytes(body[i:i+4], "little") for i in range(0, len(body), 4)]
    base, count = roots["task-base-pointer"][0], roots["task-count"][0]
    flag_count, flag_base = roots["flag-count-and-base"]
    registry.update(base=hex(base), count=count, flag_base=hex(flag_base), flag_count=flag_count)
    if not 1 <= count <= config["max_slots"] or not ram_window(role, base, count*0xD8):
        raise RuntimeError("Original TCB table is outside the explicit slot/RAM bounds")
    if not 1 <= flag_count <= config["max_flags"] or not ram_window(role, flag_base, flag_count*0x20):
        raise RuntimeError("Original event-flag table is outside the explicit slot/RAM bounds")
    chunks = []
    for offset in range(0, count*0xD8, config["read_chunk_bytes"]):
        length = min(config["read_chunk_bytes"], count*0xD8-offset)
        body = read("TCB-table", base+offset, length, f"original TCB table offset {offset:#x}")
        if body is None:
            raise RuntimeError("Original TCB table chunk could not be read")
        chunks.append(body)
    table = b"".join(chunks)
    registry["table_sha256"] = hashlib.sha256(table).hexdigest()
    for index in range(count):
        body = table[index*0xD8:(index+1)*0xD8]
        word = lambda offset: int.from_bytes(body[offset:offset+4], "little")
        task_ID = word(8)
        state = body[0x2B]
        task = dict(slot=index+1, address=hex(base+index*0xD8), task_ID=hex(task_ID),
            slot_ID_matches=(task_ID & 0xFFFF) == index+1 and ((task_ID >> 24) & 15) == 1,
            allocated=state != 0, raw_state=state, name_bytes=body[0xCC:0xD4].hex(),
            name=body[0xCC:0xD4].split(b"\0", 1)[0].decode("ascii", errors="replace"),
            entry=hex(word(0x14)), attributes=hex(word(0x10)), exinf=hex(word(0xC)),
            priorities=list(body[0x28:0x2B]), wait_spec=hex(word(0x30)), wait_object_ID=hex(word(0x34)),
            wait_return_pointer=hex(word(0x40)), wait_arguments=[hex(word(p)) for p in (0x44, 0x48, 0x4C)],
            queue_links=[hex(word(0)), hex(word(4))], saved_SP=hex(word(0xBC)),
            user_stack_bytes=word(0x1C), system_stack_bytes=word(0x20),
            user_stack_top=hex(word(0xB4)), system_stack_top=hex(word(0xB8)),
            context_words=[hex(word(p)) for p in (0xC0, 0xC4)], CPU_affinity=hex(word(0xD4)))
        registry["tasks"].append(task)
    registry["slot_IDs_verified"] = all(task["slot_ID_matches"] for task in registry["tasks"])
    if not registry["slot_IDs_verified"]:
        raise RuntimeError("Original registry contains a TCB slot/ID mismatch")
    allocated = [t for t in registry["tasks"] if t["allocated"]]
    registry["allocated_count"] = len(allocated)
    registry["state_counts"] = {str(s): sum(t["raw_state"] == s for t in allocated)
                                for s in sorted({t["raw_state"] for t in allocated})}
    if config.get("business_descriptors"):
        observe_business_tasks(role, config, registry, report, allocated, read)
    patterns = [str(s).upper() for s in config["stack_name_patterns"]]
    chosen = sorted(allocated, key=lambda t: (
        not any(p in t.get("business_name", t["name"]).upper() for p in patterns),
        t["raw_state"] not in (2, 6), t["slot"]))
    for task in chosen:
        if task["raw_state"] in (0, 8) or len(report["stacks"]) >= item["limits"]["max_stacks"]:
            continue
        sp = address(task["saved_SP"])
        window = ram_window(role, sp, 4) if sp % 4 == 0 else None
        if window is None:
            task["saved_SP_in_explicit_RAM"] = False
            continue
        task["saved_SP_in_explicit_RAM"] = True
        window_base, window_size = window
        first = max(window_base, sp-item["limits"]["stack_before"])
        last = min(window_base+window_size, sp+item["limits"]["stack_after"])
        body = read("task-stack", first, last-first, f"TCB {task['address']} task {task['name']} saved SP")
        report["stacks"].append(dict(task_ID=task["task_ID"], name=task["name"], TCB=task["address"],
            business_name=task.get("business_name"),
            saved_SP=hex(sp), address=hex(first), bytes=last-first,
            read_index=len(report["reads"])-1, captured=body is not None, unwound=False))
    specs, flags = {}, {}
    for task in allocated:
        if task["raw_state"] not in (2, 6):
            continue
        spec = address(task["wait_spec"])
        if spec not in specs and ram_window(role, spec, 12):
            body = read("wait-spec", spec, 12, f"original wait specification for {task['name']}")
            specs[spec] = body
            registry["wait_specs"].append(dict(address=hex(spec), read_index=len(report["reads"])-1,
                words=[hex(int.from_bytes(body[i:i+4], "little")) for i in (0, 4, 8)] if body else None))
        if spec not in layout["flag_wait_specs"]:
            continue
        object_ID = address(task["wait_object_ID"])
        slot = object_ID & 0xFFFF
        if not 1 <= slot <= flag_count:
            task["flag_wait_error"] = "flag ID exceeds original table"
            continue
        ptr = flag_base+(slot-1)*0x20
        if ptr not in flags:
            flags[ptr] = read("event-flag", ptr, 0x20, f"original event flag {object_ID:#x}")
        body = flags[ptr]
        if body is None:
            continue
        flag_ID = int.from_bytes(body[8:12], "little")
        pattern = int.from_bytes(body[0x14:0x18], "little")
        mask, mode = [address(s) for s in task["wait_arguments"][:2]]
        registry["flag_waits"].append(dict(task_ID=task["task_ID"], name=task["name"], TCB=task["address"],
            business_name=task.get("business_name"),
            object_address=hex(ptr), requested_object_ID=hex(object_ID), actual_object_ID=hex(flag_ID),
            object_ID_matches=object_ID == flag_ID,
            queue_links=[hex(int.from_bytes(body[i:i+4], "little")) for i in (0, 4)],
            attributes=hex(int.from_bytes(body[0x10:0x14], "little")), current_pattern=hex(pattern),
            requested_mask=hex(mask), wait_mode=hex(mode),
            predicate_satisfied_at_snapshot=bool(pattern & mask) if mode & 1 else pattern & mask == mask))
    registry["complete"] = True


def pause_both(engines, path):
    """Send all interrupts, collect all replies, confirm QMP, then allow reads."""
    result = dict(schema="z6ii-two-EXPEED-stop/1", expected_roles=["master", "slave"],
                  host_start_monotonic_ns=time.monotonic_ns(), roles={}, complete=False,
                  scope="two_EXPEED_only; MCU_runner_stops_separately",
                  simultaneous_snapshot=False, peer_clocks_synchronized=False)
    failures = []
    save(path, result)
    try:
        if set(engines) != {"master", "slave"}:
            raise RuntimeError("Both original EXPEED engines must exist before the stop gate")
        for role in ("master", "slave"):
            p = engines[role]
            item = result["roles"][role] = dict(host_send_start_monotonic_ns=time.monotonic_ns(),
                                              was_running=p.running)
            try:
                if p.process is None or p.process.poll() is not None:
                    raise RuntimeError("EXPEED process exited before stopped RAM observation")
                if p.running:
                    # The last c can still have an unread bare ACK when the
                    # finite run ends immediately after a breakpoint resume.
                    # Receive that real ACK before sending Ctrl-C; preserve
                    # the existing stop reply and independent protocol audit.
                    ack = p.remote.byte()
                    item["continue_ACK_observed"] = ack == ord("+")
                    item["continue_ACK_host_monotonic_ns"] = time.monotonic_ns()
                    if ack != ord("+"):
                        raise RuntimeError("Pending RSP continue was not acknowledged")
                    p.remote.sock.sendall(b"\x03")
                    item["interrupt_sent"] = True
                else:
                    item["interrupt_sent"] = False
                item["host_send_end_monotonic_ns"] = time.monotonic_ns()
            except Exception:
                item["send_error"] = traceback.format_exc()
                failures.append(role + ": stop send failed")
            save(path, result)
        for role in ("master", "slave"):
            p, item = engines[role], result["roles"][role]
            if "send_error" in item:
                continue
            item["host_reply_start_monotonic_ns"] = time.monotonic_ns()
            try:
                reply = p.remote.receive() if item["interrupt_sent"] else p.remote.command("?")
                item["stop_reply"] = reply
                item["host_reply_end_monotonic_ns"] = time.monotonic_ns()
                if not reply.startswith(("T", "S")):
                    raise RuntimeError("RSP did not return an actual stop reply: " + reply)
                p.running = False
            except Exception:
                item["reply_error"] = traceback.format_exc()
                failures.append(role + ": stop reply failed")
            save(path, result)
        for role in ("master", "slave"):
            p, item = engines[role], result["roles"][role]
            if "send_error" in item or "reply_error" in item:
                continue
            item["host_status_start_monotonic_ns"] = time.monotonic_ns()
            try:
                item["QMP_status"] = status = p.monitor.command("query-status")
                item["host_status_end_monotonic_ns"] = time.monotonic_ns()
                if status.get("running") is not False or status.get("status") not in ("paused", "debug"):
                    raise RuntimeError("EXPEED QMP does not confirm a stopped CPU")
                item["pause_confirmed"] = True
            except Exception:
                item["status_error"] = traceback.format_exc()
                failures.append(role + ": QMP pause confirmation failed")
            save(path, result)
        if failures:
            raise RuntimeError("; ".join(failures))
        result["complete"] = True
        result["RAM_read_gate_monotonic_ns"] = time.monotonic_ns()
        return result
    finally:
        result["failures"] = failures
        result["host_end_monotonic_ns"] = time.monotonic_ns()
        save(path, result)


def observe(p, item, out, stop_gate, *, retain=True):
    """Collect a bounded plan, or replay it over retained bytes without file IO.

    retain=False is for the offline auditor: the same roots, table chunks and
    derived task fields are recomputed through its wire-bound memory reader.
    """
    role = p.role
    if not stop_gate.get("complete") or p.running:
        raise RuntimeError("Task RAM observation requires the completed two-EXPEED stop gate")
    out = Path(out)
    if retain:
        out.mkdir(parents=True, exist_ok=False)
    limits = item["limits"]
    report = dict(schema="z6ii-stopped-task-RAM/1", role=role, plan=item,
                  host_start_monotonic_ns=time.monotonic_ns(), stop_gate=stop_gate,
                  reads=[], roots=[], pointer_edges=[], candidates=[], stacks=[],
                  requested_bytes=0, successful_bytes=0, skipped={},
                  candidates_are_verified_tasks=False, guest_state_written=False,
                  global_snapshot_clock=False, complete_within_plan=False)
    target = out / "任务RAM观察.json"
    queue, queued, visited = deque(), set(), set()
    failure_count = 0

    def checkpoint():
        if retain:
            save(target, report)

    def skip(name):
        report["skipped"][name] = report["skipped"].get(name, 0) + 1

    def read(kind, start, length, reason):
        nonlocal failure_count
        event = dict(index=len(report["reads"]), kind=kind, address=hex(start), bytes=length,
                     reason=reason, host_start_monotonic_ns=time.monotonic_ns())
        report["reads"].append(event)
        if not ram_window(role, start, length):
            event["rejected"] = "outside explicit RAM"
            skip("non_RAM_read_rejected")
            event["host_end_monotonic_ns"] = time.monotonic_ns()
            return None
        if report["requested_bytes"] + length > limits["max_requested_bytes"]:
            event["rejected"] = "requested-byte budget"
            skip("byte_budget_read_rejected")
            event["host_end_monotonic_ns"] = time.monotonic_ns()
            return None
        report["requested_bytes"] += length
        try:
            body = p.remote.memory(start, length)
            if len(body) != length:
                raise RuntimeError("short stopped RAM observation")
            path = out / f"read{event['index']:04d}-{kind}-{start:08x}-{length:06x}.bin"
            if retain:
                path.write_bytes(body)
            event["saved"] = dict(path=str(path), bytes=len(body), sha256=hashlib.sha256(body).hexdigest())
            report["successful_bytes"] += length
            return body
        except Exception:
            failure_count += 1
            event["error"] = traceback.format_exc()
            return None
        finally:
            event["host_end_monotonic_ns"] = time.monotonic_ns()

    def pointers(body, base, source, depth):
        for offset in range(0, len(body)-3, 4):
            pointer = int.from_bytes(body[offset:offset+4], "little")
            if pointer % 4 or not ram_window(role, pointer, item["candidate_header_bytes"]):
                continue
            if len(report["pointer_edges"]) < limits["max_edges"]:
                report["pointer_edges"].append(dict(source=source, slot=hex(base+offset),
                    offset=hex(offset), value=hex(pointer), candidate_depth=depth))
            else:
                skip("edge_limit")
            if pointer in queued or pointer in visited:
                continue
            if len(queued) + len(visited) >= limits["max_candidates"]:
                skip("candidate_limit")
                continue
            queue.append((pointer, depth))
            queued.add(pointer)

    try:
        for root in item["roots"]:
            start, length = address(root["address"]), address(root["bytes"])
            body = read("root", start, length, root["name"])
            observed = dict(**root, read_index=len(report["reads"])-1)
            if body is not None:
                if root.get("scheduler_table"):
                    observed["actual_words"] = [hex(int.from_bytes(body[i:i+4], "little"))
                                                for i in range(0, len(body), 4)]
                if item.get("pointer_chasing", True):
                    pointers(body, start, "root:" + root["name"], 0)
            report["roots"].append(observed)
        checkpoint()
        if item.get("registry") is not None:
            observe_registry(role, item, report, read)
        while queue:
            start, depth = queue.popleft()
            queued.remove(start)
            visited.add(start)
            body = read("candidate", start, item["candidate_header_bytes"], f"RAM pointer depth {depth}")
            candidate = dict(address=hex(start), depth=depth, read_index=len(report["reads"])-1,
                             verified_task=False)
            report["candidates"].append(candidate)
            if body is None:
                continue
            sp = int.from_bytes(body[0xBC:0xC0], "little")
            candidate["saved_SP_candidate"] = hex(sp)
            candidate["context_words_C0_C4"] = [hex(int.from_bytes(body[i:i+4], "little")) for i in (0xC0, 0xC4)]
            window = ram_window(role, sp, 64) if sp % 4 == 0 else None
            candidate["saved_SP_in_explicit_RAM"] = window is not None
            if window is not None:
                if len(report["stacks"]) < limits["max_stacks"]:
                    base, size = window
                    first, last = max(base, sp-limits["stack_before"]), min(base+size, sp+limits["stack_after"])
                    stack = read("saved-stack", first, last-first, f"candidate {start:#x} +0xbc={sp:#x}")
                    report["stacks"].append(dict(candidate=hex(start), saved_SP=hex(sp),
                        address=hex(first), bytes=last-first, read_index=len(report["reads"])-1,
                        captured=stack is not None, unwound=False))
                else:
                    skip("stack_limit")
            if depth < limits["max_depth"]:
                pointers(body, start, f"candidate:{start:#x}", depth+1)
            else:
                skip("depth_limit")
            if len(report["candidates"]) % 32 == 0:
                checkpoint()
        report["complete_within_plan"] = True
    finally:
        report["failed_read_count"] = failure_count
        report["host_end_monotonic_ns"] = time.monotonic_ns()
        checkpoint()
    if not retain:
        return report
    body = target.read_bytes()
    return dict(path=str(target), bytes=len(body), sha256=hashlib.sha256(body).hexdigest(),
                candidate_count=len(report["candidates"]), stack_count=len(report["stacks"]),
                requested_bytes=report["requested_bytes"], successful_bytes=report["successful_bytes"],
                failed_read_count=failure_count, complete_within_plan=report["complete_within_plan"],
                registry_summary={k: v for k, v in report.get("task_registry", {}).items()
                                  if k in ("complete", "slot_IDs_verified", "count", "allocated_count", "state_counts")},
                scheduler_tables=[root for root in report["roots"] if root.get("scheduler_table")])
