"""Evidence scopes for bounded runs. This module never runs a guest or camera.

Process termination, original entry observations, protocol transactions, and
camera acceptance are independent. An empty process set cannot pass a gate.
Schema v1 deliberately cannot certify a native transaction or MENU cycle:
those require a separately reviewed, content-bearing witness collector.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path


SCHEMA = "z6ii-bounded-run-evidence/1"
EXPECTED_QEMU_ROLES = ("master", "slave", "MCU")
FORBIDDEN_AGGREGATES = {"all_exits", "all_owned_QEMU_exits_verified"}
ACCEPTANCE_KEYS = {"cross_instance_causal_execution",
                   "original_Flash_loader_input_and_generation",
                   "native_bidirectional_request_DMA_ACK_response_wait",
                   "full_natural_camera_boot",
                   "stable_MENU_entry_exit_reentry_with_resource_lifecycle"}


def save_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + ".writing")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    temporary.replace(path)


def identity(path):
    path = Path(path).resolve(strict=True)
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return {"path": str(path), "bytes": path.stat().st_size,
            "sha256": digest.hexdigest()}


def checked_json(path, expected=None):
    ref = identity(path)
    if expected is not None and ref != expected:
        raise ValueError("Retained evidence identity changed: " + str(path))
    return json.loads(Path(path).read_text()), ref


class ProcessLedger:
    """Persist launch attempt before Popen; persist actual PID and wait result.

    A preflight exception leaves not_attempted; a Popen exception leaves
    attempted_unknown. Neither can be inferred from missing result files.
    """

    def __init__(self, directory, role):
        self.path = Path(directory) / "QEMU-process-lifecycle.json"
        self.record = {"schema": "z6ii-qemu-process-lifecycle/1", "role": role,
                       "scope": "this owned QEMU process only",
                       "launch": "not_attempted", "pid": None,
                       "exit": "not_applicable", "exit_code": None}
        self._save()

    def _save(self):
        self.record["updated_UTC"] = datetime.now(timezone.utc).isoformat()
        save_json(self.path, self.record)

    def attempting(self, command):
        self.record.update(launch="attempted_unknown", exit="unknown",
                           command_sha256=hashlib.sha256(
                               json.dumps(command, ensure_ascii=False).encode()).hexdigest())
        self._save()

    def started(self, process):
        self.record.update(launch="started", pid=process.pid, exit="not_observed")
        self._save()

    def closed(self, process):
        if process is not None:
            code = process.poll()
            self.record.update(launch="started", pid=process.pid,
                               exit="observed" if code is not None else "not_observed",
                               exit_code=code)
        self._save()
        return dict(self.record)


def process_summary(records, expected=EXPECTED_QEMU_ROLES):
    """Never infer missing roles or process cleanup from a wrapper return code."""
    if set(records) != set(expected) or not expected:
        raise ValueError("Expected process roles must be explicit and nonempty")
    started = [r for r in expected if records[r]["launch"] == "started"]
    unattempted = [r for r in expected if records[r]["launch"] == "not_attempted"]
    unknown = [r for r in expected if records[r]["launch"] not in
               ("started", "not_attempted")]
    exited = [r for r in started if records[r]["exit"] == "observed"]
    if len(started) == len(expected):
        launch_coverage = "complete"
    elif unknown:
        launch_coverage = "unknown"
    elif started:
        launch_coverage = "partial"
    else:
        launch_coverage = "none"
    if unknown or len(exited) != len(started):
        exit_coverage = "incomplete_or_unknown"
    elif started:
        exit_coverage = "confirmed_for_started_processes"
    else:
        exit_coverage = "no_started_processes"
    return {"scope": "owned QEMU process launch and termination; no firmware acceptance",
            "expected_roles": list(expected), "started_roles": started,
            "not_attempted_roles": unattempted, "unknown_launch_roles": unknown,
            "exit_observed_roles": exited, "launch_coverage": launch_coverage,
            "exit_coverage": exit_coverage,
            "firmware_success_implied": False}


def _endpoint_record(role, raw, ref, ledger_path=None, prelaunch_proof=None):
    record = {"role": role, "scope": "owned QEMU process only",
              "launch": "unknown", "pid": None, "exit": "unknown",
              "exit_code": None, "evidence": [ref] if ref else []}
    if ledger_path is not None and Path(ledger_path).exists():
        ledger, ledger_ref = checked_json(ledger_path)
        if ledger.get("schema") != "z6ii-qemu-process-lifecycle/1" or ledger["role"] != role:
            raise ValueError("Wrong process ledger role/schema")
        record.update({k: ledger[k] for k in ("launch", "pid", "exit", "exit_code")})
        record["evidence"].append(ledger_ref)
        record["basis"] = "persisted_Popen_and_wait_ledger"
    elif raw is not None:
        code = raw.get("QEMU_exit_code") if role == "MCU" else raw.get("exit_code")
        # Legacy Probe.close emits self.process.returncode, or None if no Popen.
        # A genuine integer code is evidence; a command string or aggregate is not.
        if type(code) is int:
            record.update(launch="started", exit="observed", exit_code=code,
                          basis="retained_per_process_returncode; legacy_PID_not_retained")
    if prelaunch_proof is not None:
        proof, proof_ref = checked_json(prelaunch_proof)
        if (proof.get("role") != role or proof.get("QEMU_launch_not_reached") is not True
                or not proof.get("evidence")):
            raise ValueError("Unsupported prelaunch proof")
        for source in proof["evidence"]:
            if identity(source["path"]) != source:
                raise ValueError("Prelaunch evidence changed")
        if record["launch"] == "started":
            raise ValueError("Prelaunch proof contradicts observed QEMU exit")
        record.update(launch="not_attempted", exit="not_applicable",
                      basis="reviewed_prelaunch_control_flow_failure")
        record["evidence"].append(proof_ref)
    return record


def _entry_observation(role, raw, ref):
    result = {"scope": "original MCU reset vector" if role == "MCU" else
              "original update-image application entry; physical boot ROM omitted",
              "status": "not_observed", "evidence": [ref] if ref else []}
    if raw is None:
        return result
    if role == "MCU":
        if raw.get("CPU_reset_SP_PC_verified") is True:
            regs = raw.get("initial_reset_registers", {})
            if (regs.get("r13") != "0x20000c08" or
                    regs.get("r15") != "0x080002b4" or
                    raw.get("original_ROM_in_memory_verified") is not True):
                raise ValueError("MCU original-entry claim lacks reset/ROM evidence")
            result.update(status="observed", initial_SP=regs["r13"], initial_PC=regs["r15"])
    else:
        initial = [e for e in raw.get("events", []) if e.get("event") == "initial native entry"]
        cores = initial[0].get("cores", []) if initial else []
        if cores and all(c.get("original_instructions_verified") is True and
                         c.get("registers", {}).get("r15") == "0x10020000" and
                         c.get("instruction_bytes") == c.get("original_bytes")
                         for c in cores):
            result.update(status="observed", initial_PC="0x10020000",
                          observed_CPU_count=len(cores))
    return result


def normalize_run(directory, number, prelaunch_proofs=None):
    """Build a bounded public record from retained endpoint evidence.

    Missing files stay unknown. False legacy aggregates are never evidence of
    residual processes. True aggregates and exit code zero never certify boot.
    """
    directory = Path(directory).resolve(strict=True)
    raw, raw_ref = checked_json(directory / "三端接入结果.json")
    ex = mcu = None
    ex_ref = mcu_ref = None
    if (directory / "EXPEED/结果.json").exists():
        ex, ex_ref = checked_json(directory / "EXPEED/结果.json",
                               raw.get("processes", {}).get("EXPEED", {}).get("result"))
    if (directory / "MCU/结果.json").exists():
        mcu, mcu_ref = checked_json(directory / "MCU/结果.json",
                                 raw.get("processes", {}).get("MCU", {}).get("result"))
    processes, entries, stops = {}, {}, {}
    proofs = prelaunch_proofs or {}
    for role in EXPECTED_QEMU_ROLES:
        endpoint, endpoint_ref = mcu, mcu_ref
        ledger = directory / "MCU/QEMU-process-lifecycle.json"
        if role != "MCU":
            engine = (ex or {}).get("engines", {}).get(role)
            endpoint = endpoint_ref = None
            ledger = None
            if engine is not None:
                output = Path(engine["output"])
                endpoint, endpoint_ref = checked_json(output / "结果.json")
                ledger = output / "QEMU-process-lifecycle.json"
                if endpoint.get("exit_code") != engine.get("exit_code"):
                    raise ValueError("Probe and parent returncodes disagree")
        processes[role] = _endpoint_record(role, endpoint, endpoint_ref, ledger, proofs.get(role))
        entries[role] = _entry_observation(role, endpoint, endpoint_ref)
        stops[role] = {"first_unmodeled": (endpoint or {}).get("first_unmodeled"),
                       "first_hardware_boundary": (endpoint or {}).get(
                           "first_hardware_boundary_line" if role == "MCU" else
                           "first_hardware_boundary"),
                       "evidence": [endpoint_ref] if endpoint_ref else []}
    for document in (raw, ex or {}, mcu or {}):
        if (document.get("menu_verified") is True or
                document.get("full_power_on_boot_verified") is True or
                document.get("full_native_MCU_boot_verified") is True):
            raise ValueError("Schema v1 has no reviewed full-boot/MENU witness collector")
    ex = ex or {}
    fixtures = ex.get("guest_RAM_or_register_fixtures", [])
    region47_requested = ex.get("diagnostic_region47_RAM_seed_requested") is True
    region47_performed = ex.get("diagnostic_region47_RAM_seed_performed") is True
    resource_input = ex.get("diagnostic_master_resource_RAM_input")
    resource_performed = ex.get("diagnostic_master_resource_RAM_replay_performed") is True
    region47_fixtures = [f for f in fixtures if "regions" not in f]
    resource_fixtures = [f for f in fixtures if "regions" in f]
    if region47_performed and (not region47_requested or not region47_fixtures):
        raise ValueError("RAM seed claim lacks requested input and actual fixture evidence")
    if region47_fixtures and not region47_performed:
        raise ValueError("Unclassified RAM/register fixture; cannot publish as no-seed")
    if resource_performed and (not resource_input or len(resource_fixtures) != 1):
        raise ValueError("Recorded resource RAM replay lacks requested input and one actual fixture")
    if resource_fixtures and not resource_performed:
        raise ValueError("Unclassified recorded resource RAM fixture")
    if resource_performed:
        fixture = resource_fixtures[0]
        specification, unused_ref = checked_json(resource_input["spec"]["path"], resource_input["spec"])
        if (specification.get("schema") != "z6ii.recorded-master-resource-RAM/2" or
                fixture.get("input_spec") != resource_input["spec"] or
                fixture.get("execution_point") != specification["execution_point"]["address"] or
                resource_input.get("regions") != specification["regions"] or
                fixture.get("all_resource_destinations_prechecked_before_any_write") is not True or
                fixture.get("original_common_Thumb_runtime_entry_verified") is not True or
                fixture.get("original_CPU_state_unchanged") is not True or
                fixture.get("original_firmware_instructions_modified") is not False or
                fixture.get("software_ready_or_callback_written") is not False or
                fixture.get("physical_Flash_container_loaded") is not False):
            raise ValueError("Recorded resource RAM fixture does not match its explicit diagnostic input")
        expected = [(r["region"], r["address"], r["bytes"], r["pass1"]["sha256"])
                    for r in specification["regions"]]
        actual = [(r["region"], r["address"], r["bytes"], r["sha256"])
                  for r in fixture["regions"]]
        if (actual != expected or any(
                r.get("classification") != "recorded_runtime_RAM_body" or
                r.get("readback_equal") is not True or
                r.get("source_loader_generation_omitted") is not True or
                r.get("resource_table_or_ready_flag_written") is not False
                for r in fixture["regions"])):
            raise ValueError("Recorded resource RAM extents or readback evidence mismatch")
    seed_requested = region47_requested or bool(resource_input)
    seed_performed = region47_performed or resource_performed
    seed_status = "performed" if seed_performed else (
        "not_observed_before_failure" if ex.get("error") else "not_performed")
    bus = raw.get("stopped_bus")
    counts = None
    if bus is not None:
        counts = {k: bus[k] for k in ("shifted_bytes", "dma_transferred", "master_ack_edges")}
    runner_evidence = {}
    for role in ("EXPEED", "MCU"):
        runner = raw.get("processes", {}).get(role, {})
        runner_evidence[role] = {"scope": "host Python runner; not QEMU",
                                 "pid": runner.get("pid"),
                                 "exit_code": runner.get("exit_code"),
                                 "evidence": [raw_ref]}
    cleanup = process_summary(processes)
    if cleanup["launch_coverage"] != "complete":
        outcome = "launch_incomplete_or_unknown"
    elif any(v["first_hardware_boundary"] for v in stops.values()):
        outcome = "conditional_execution_blocked"
    elif ex.get("error") or (mcu or {}).get("error"):
        outcome = "harness_error"
    else:
        outcome = "budget_ended_without_camera_acceptance"
    record = {"schema": SCHEMA, "run_number": number, "directory": str(directory),
              "run_outcome": outcome, "raw_result": raw_ref,
              "host_runners": runner_evidence, "QEMU_processes": processes,
              "QEMU_process_accounting": cleanup, "original_entry_observations": entries,
              "first_observed_stop_by_endpoint": stops,
              "global_first_event_order": "unknown; independent virtual clocks",
              "RAM_seed": {"scope": "diagnostic RAM replay only; original Loader execution and persistent-input provenance require separate evidence",
                           "requested": seed_requested, "status": seed_status,
                           "region47_requested": region47_requested,
                           "region47_performed": region47_performed,
                           "recorded_master_resources_requested": bool(resource_input),
                           "recorded_master_resources_performed": resource_performed,
                           "actual_fixture_count": len(fixtures), "actual_fixtures": fixtures,
                           "evidence": [ex_ref] if ex_ref else []},
              "MCU_auxiliary_power": {
                  "scope": "explicit synthetic external-power configuration; separate from EXPEED diagnostic RAM replay",
                  "requested": raw.get("MCU_auxiliary_power_requested", False),
                  "run": (mcu or {}).get("MCU_auxiliary_power"),
                  "actual_host_guest_state_write_count": (mcu or {}).get("actual_host_guest_state_write_count", 0),
                  "natural_battery_authentication_verified": False,
                  "full_natural_boot_verified": False},
              "observations": {"GDB_count": len(ex.get("observations", [])),
                               "TCG_source50_enabled": ex.get("source50_TCG_trace") is True,
                               "seed_only_GDB_set": ex.get("conditional_seed_only_observers") is True},
              "MCU_bus_counters": {"scope": "stopped bus aggregate counters only",
                                  "status": "observed" if counts is not None else "not_observed",
                                  "counts": counts, "evidence": [raw_ref] if counts is not None else []},
              "acceptance": {
                  "cross_instance_causal_execution": "not_verified",
                  "original_Flash_loader_input_and_generation": "not_verified",
                  "native_bidirectional_request_DMA_ACK_response_wait": "not_verified",
                  "full_natural_camera_boot": "not_verified",
                  "stable_MENU_entry_exit_reentry_with_resource_lifecycle": "not_verified"},
              "legacy_process_aggregates_used_for_acceptance": False,
              "camera_access_in_this_run": raw.get("camera_access") is True,
              "conditions": {"legacy_known_state_host_wait_ms": raw.get("known_state_host_wait_ms_hypothesis"),
                             "GPIO_pairing_hypothesis": raw.get("GPIO_pairing_hypothesis"),
                             "independent_virtual_clocks": raw.get("relative_virtual_clocks_synchronized") is not True}}
    validate(record)
    return record


def validate(record, verify_files=True):
    """Validate field scopes and evidence identities before publishing."""
    if record.get("schema") != SCHEMA or type(record.get("run_number")) is not int:
        raise ValueError("Unknown evidence schema or run number")
    def walk(value):
        if isinstance(value, dict):
            if FORBIDDEN_AGGREGATES & value.keys():
                raise ValueError("Ambiguous process aggregate forbidden in public evidence")
            if {"path", "bytes", "sha256"} <= value.keys() and verify_files:
                actual = identity(value["path"])
                if any(actual[k] != value[k] for k in ("path", "bytes", "sha256")):
                    raise ValueError("Published evidence identity changed")
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)
    walk(record)
    processes = record["QEMU_processes"]
    if set(processes) != set(EXPECTED_QEMU_ROLES):
        raise ValueError("Expected three QEMU roles absent")
    for role, process in processes.items():
        if process["role"] != role or process["scope"] != "owned QEMU process only":
            raise ValueError("Process kind/role scope mismatch")
        if process["launch"] == "started":
            if not process["evidence"]:
                raise ValueError("QEMU launch lacks endpoint evidence")
            if process["exit"] == "observed" and type(process["exit_code"]) is not int:
                raise ValueError("QEMU termination lacks an actual returncode")
        elif process["exit"] == "observed" or process["exit_code"] is not None:
            raise ValueError("Unlaunched QEMU cannot have observed termination")
    if record["QEMU_process_accounting"] != process_summary(processes):
        raise ValueError("Process accounting must be derived from endpoint evidence")
    seed = record["RAM_seed"]
    if seed["status"] == "performed" and (
            not seed["requested"] or seed["actual_fixture_count"] < 1 or not seed["evidence"]):
        raise ValueError("Requested RAM is not evidence of actual RAM seed")
    if seed["actual_fixture_count"] != len(seed["actual_fixtures"]):
        raise ValueError("Fixture count and retained evidence disagree")
    if set(record["acceptance"]) != ACCEPTANCE_KEYS:
        raise ValueError("High-level acceptance groups must be explicit and nonempty")
    if any(value != "not_verified" for value in record["acceptance"].values()):
        raise ValueError("High-level acceptance needs a reviewed transaction/MENU witness schema")
    return record
