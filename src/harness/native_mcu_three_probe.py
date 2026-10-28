"""Bounded original MCU/reset + master/slave entry, fresh shared bus, no replay.

Reuses explicit recorded peripheral conditions. Separate virtual clocks and
GPIO pairing remain hypotheses. This host coordinator does not write guest
registers, synthesize protocol packets, or relax either endpoint's guards.
An explicitly selected child diagnostic RAM seed is retained as a fixture;
it is never attributed to original Flash loading or full natural startup.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from run_evidence import normalize_run, save_json
from mcu_wire_contract import manifest_abi, validate_bus


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def identity(path):
    path = Path(path).resolve(strict=True)
    return dict(path=str(path), bytes=path.stat().st_size,
                sha256=hashlib.sha256(path.read_bytes()).hexdigest())


def replace_option(argv, name, value):
    if name in argv:
        argv[argv.index(name) + 1] = str(value)
    else:
        argv.extend((name, str(value)))


def remove_replay_and_menu(argv):
    out, index = [], 0
    while index < len(argv):
        arg = argv[index]
        if arg in ("--exmcu-transport", "--menu-session"):
            index += 1
        elif arg.startswith("--exmcu-") or arg in ("--menu-plan", "--menu-config-region", "--tg-event-test"):
            index += 2
        else:
            out.append(arg)
            index += 1
    return out


def check_host_stop(directory, report):
    """A run-local host request changes scheduling only, never a bus or guest."""
    path = directory / "host-stop-request.json"
    if path.exists():
        request = json.loads(path.read_text())
        report["host_stop_request"] = dict(source=identity(path), request=request)
        raise RuntimeError("host stop requested: " + str(request.get("reason", "unspecified")))


def wait_mcu_attachment(directory, bus, process, report, timeout=90):
    """Wait for QEMU's original fresh-bus guard to pass on this exact bus."""
    path = directory / "MCU/qemu.log"
    deadline = time.monotonic() + timeout
    expected = "EX1850_MCU_WIRE_ATTACHED path=" + str(bus) + " SPI_RX="
    while True:
        check_host_stop(directory, report)
        content = path.read_text(errors="replace") if path.exists() else ""
        for line in content.splitlines():
            if "EX1850_MCU_WIRE_ATTACHED path=" in line:
                if expected not in line:
                    raise RuntimeError("MCU attached to a different bus: " + line)
                if process.poll() is not None:
                    raise RuntimeError("MCU runner exited after attachment: " + str(process.returncode))
                return dict(path=str(path), line=line, timeout_seconds=timeout,
                            observed_host_monotonic_ns=time.monotonic_ns(),
                            readiness_supplied=False, guest_state_written=False,
                            original_fresh_bus_guard_passed=True)
        failures = [line for line in content.splitlines()
                    if "EX1850_MCU_WIRE_BOUNDARY" in line or "EX1850_UNMODELED" in line]
        if failures:
            raise RuntimeError("MCU stopped before attachment: " + failures[0])
        if process.poll() is not None:
            raise RuntimeError("MCU runner exited before attachment: " + str(process.returncode))
        if time.monotonic() >= deadline:
            raise TimeoutError("MCU actual QEMU attachment was not observed within " + str(timeout) + "s")
        time.sleep(0.05)


def stop_owned_runner(process):
    """Give the Python owner time to close its QEMU and persist lifecycle."""
    actions = []
    if process.poll() is None:
        try:
            os.kill(process.pid, signal.SIGINT)
            actions.append(dict(target="runner_PID_only", pid=process.pid, signal="SIGINT"))
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            for sig, name in ((signal.SIGTERM, "SIGTERM"), (signal.SIGKILL, "SIGKILL")):
                try:
                    os.killpg(process.pid, sig)
                    actions.append(dict(target="owned_runner_process_group_after_timeout",
                                        pgid=process.pid, signal=name))
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=5)
                    break
                except subprocess.TimeoutExpired:
                    pass
    return dict(actions=actions, exit_code=process.poll(), graceful_owner_first=True)


def coordinator_status(report):
    """Host execution/accounting only; never certify firmware or camera boot."""
    failures = []
    expected_runners = ("MCU", "EXPEED")
    processes = report.get("processes", {})
    for role in expected_runners:
        child = processes.get(role)
        if child is None:
            failures.append(dict(reason="host_runner_not_started", role=role))
            continue
        if type(child.get("exit_code")) is not int or child["exit_code"] != 0:
            failures.append(dict(reason="host_runner_failed_or_exit_unknown", role=role,
                                 exit_code=child.get("exit_code")))
        if not child.get("result"):
            failures.append(dict(reason="endpoint_result_missing", role=role))
        if child.get("error"):
            failures.append(dict(reason="endpoint_harness_error", role=role,
                                 error=child["error"]))
        codes = ({"MCU": child.get("QEMU_exit_code")} if role == "MCU" else
                 {name: engine.get("exit_code") for name, engine in
                  child.get("engine_boundaries", {}).items()})
        required = {"MCU"} if role == "MCU" else {"master", "slave"}
        if set(codes) != required:
            failures.append(dict(reason="QEMU_endpoint_result_missing", role=role,
                                 expected=sorted(required), observed=sorted(codes)))
        for name, code in codes.items():
            if type(code) is not int or code != 0:
                failures.append(dict(reason="QEMU_failed_or_exit_unknown", role=name,
                                     exit_code=code))
    if report.get("owned_runner_processes_exited") is not True:
        failures.append(dict(reason="host_runner_termination_incomplete_or_unknown"))
    for key in ("host_envelope_timeout", "host_runner_error", "evidence_processing_error"):
        if report.get(key):
            failures.append(dict(reason=key, detail=report[key]))
    accounting = report.get("QEMU_process_accounting", {})
    if accounting.get("launch_coverage") != "complete":
        failures.append(dict(reason="QEMU_launch_incomplete_or_unknown", accounting=accounting))
    if accounting.get("exit_coverage") != "confirmed_for_started_processes":
        failures.append(dict(reason="QEMU_termination_incomplete_or_unknown", accounting=accounting))
    expected_qemu = {"master", "slave", "MCU"}
    if (set(accounting.get("expected_roles", [])) != expected_qemu or
            set(accounting.get("started_roles", [])) != expected_qemu or
            set(accounting.get("exit_observed_roles", [])) != expected_qemu):
        failures.append(dict(reason="QEMU_role_accounting_incomplete", accounting=accounting))
    if report.get("bus_inspection_exit_code") != 0:
        failures.append(dict(reason="stopped_bus_inspection_missing_or_failed",
                             exit_code=report.get("bus_inspection_exit_code")))
    return dict(schema="z6ii-three-runner-host-status/1", exit_code=int(bool(failures)),
                passed=not failures, failures=failures,
                scope="host runners, real QEMU lifecycle and stopped bus inspection only",
                firmware_success_implied=False, whole_camera_verified=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--baseline-command-json", required=True, type=Path)
    parser.add_argument("--mcu-profile-json", required=True, type=Path)
    parser.add_argument("--qemu-manifest", required=True, type=Path)
    parser.add_argument("--mcu-manifest", required=True, type=Path)
    parser.add_argument("--mcu-auxiliary-power-spec", type=Path,
                        help="Source-bound one-shot external-power configuration experiment; not battery authentication")
    parser.add_argument("--bus-tool", required=True, type=Path)
    parser.add_argument("--seconds", type=float, default=8)
    parser.add_argument("--poll-ns", type=int, required=True)
    parser.add_argument("--known-wait-ms", type=int, default=0)
    parser.add_argument("--resource-startup-barrier", action="store_true",
                        help="Hold Slave and MCU until initial recorded Master resources are verified")
    parser.add_argument("--startup-barrier-timeout", type=float, default=60)
    parser.add_argument("--run-number", type=int,
                        help="Actual experiment registry number; zero denotes unregistered")
    args = parser.parse_args()
    if not 1 <= args.seconds <= 1200 or not 1 <= args.poll_ns <= 1000000:
        parser.error("explicit 1..1200s host runtime budgets and 1..1000000ns poll required")
    if not 0 <= args.known_wait_ms <= 5000:
        parser.error("known-state host wait requires0..5000ms")
    if not 1 <= args.startup_barrier_timeout <= 180:
        parser.error("initial resource startup barrier requires1..180s")
    master_manifest = json.loads(args.qemu_manifest.read_text())
    mcu_manifest = json.loads(args.mcu_manifest.read_text())
    wire_abi = manifest_abi(master_manifest)
    if manifest_abi(mcu_manifest) != wire_abi:
        parser.error("Master and MCU manifests require the same shared-bus ABI")
    directory = args.output_dir.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    run_number = args.run_number if args.run_number is not None else (
        int(directory.name.partition("-")[0]) if directory.name.partition("-")[0].isdecimal() else 0)
    port = Path(__file__).resolve().parent
    workspace = port.parents[1]
    profile = json.loads(args.mcu_profile_json.read_text())
    bus = directory / "cold-mcu-wire.bus"
    tool = args.bus_tool.resolve(strict=True)
    cold = subprocess.run([str(tool), "create-cold", str(bus)], capture_output=True, text=True, check=True)
    validate_bus(bus, master_manifest)
    report = dict(created_UTC=datetime.now(timezone.utc).isoformat(), camera_access=False,
                  original_firmware_instructions_modified=False,
                  host_firmware_instruction_patches=False,
                  original_firmware_instructions_modified_scope="host patches only; MCU guest Flash stores reported per endpoint",
                  diagnostic_function_calls=[], guest_RAM_or_register_fixtures=[],
                  replay_packets=[], conditional_MCU_peripheral_profile=profile,
                  GPIO_pairing_hypothesis="pb14_pd12_pe3_pg6",
                  relative_virtual_clocks_synchronized=False,
                  poll_ns_hypothesis=args.poll_ns, menu_verified=False,
                  known_state_host_wait_ms_hypothesis=args.known_wait_ms,
                  host_causality_experiment=bool(args.known_wait_ms),
                  physical_latency_verified=False,
                  full_power_on_boot_verified=False,
                  cold_bus=identity(bus), cold_bus_reset=json.loads(cold.stdout),
                  native_mcu_wire_abi=wire_abi,
                  sources=[identity(Path(__file__)), identity(Path(__file__).with_name("run_evidence.py")),
                           identity(Path(__file__).with_name("mcu_wire_contract.py")),
                           identity(tool), identity(args.baseline_command_json),
                           identity(args.mcu_profile_json), identity(args.qemu_manifest), identity(args.mcu_manifest)],
                  intended_QEMU_roles=["master", "slave", "MCU"],
                  report_semantics="endpoint evidence; host runner completion is not camera acceptance",
                  run_number=run_number, processes={})
    mcu_argv = [sys.executable, str(port / "run_exmcu_qemu_reset.py"), "--manifest", str(args.mcu_manifest.resolve()),
                "--output-dir", str(directory / "MCU"), "--label", "native-live-reset",
                "--seconds", str(args.seconds), *profile["arguments"]]
    report["MCU_auxiliary_power_requested"] = bool(args.mcu_auxiliary_power_spec)
    report["MCU_auxiliary_power"] = None
    report["actual_host_MCU_guest_state_write_count"] = 0
    if args.mcu_auxiliary_power_spec:
        mcu_argv.extend(("--auxiliary-power-spec", str(args.mcu_auxiliary_power_spec.resolve(strict=True))))
        report["sources"].extend((identity(args.mcu_auxiliary_power_spec),
                                  identity(port / "ex1850_auxiliary_power.py")))
    dual_argv = remove_replay_and_menu(json.loads(args.baseline_command_json.read_text())["argv"])
    replace_option(dual_argv, "--seconds", args.seconds)
    replace_option(dual_argv, "--label", "native-live-master-slave")
    replace_option(dual_argv, "--output-dir", directory / "EXPEED")
    replace_option(dual_argv, "--qemu-build-manifest", args.qemu_manifest.resolve())
    replace_option(dual_argv, "--mcu-wire-path", bus)
    replace_option(dual_argv, "--mcu-wire-poll-ns", args.poll_ns)
    replace_option(dual_argv, "--mcu-wire-known-wait-ms", args.known_wait_ms)
    startup_gate = None
    if args.resource_startup_barrier:
        if '--diagnostic-master-resource-ram' not in dual_argv:
            parser.error('Initial startup barrier requires explicit recorded Master resource RAM')
        from startup_barrier import create, release, fail
        startup_gate = directory / 'initial-resource-startup-barrier'
        report['initial_resource_startup_barrier'] = create(startup_gate, args.startup_barrier_timeout)
        report['sources'].append(identity(port / 'startup_barrier.py'))
        replace_option(mcu_argv, '--initial-resource-startup-barrier', startup_gate)
        replace_option(dual_argv, '--initial-resource-startup-barrier', startup_gate)
    processes, logs = {}, {}
    started = time.monotonic()
    try:
        # The MCU guard requires fresh core/SRAM. Its owner may precompute an
        # external battery peer, so Popen order alone is not attachment order.
        for role, argv in (("MCU", mcu_argv), ("EXPEED", dual_argv)):
            env = {k: v for k, v in os.environ.items()
                   if not k.startswith(("Z6II_EXMCU_", "Z6II_MCU_WIRE_", "Z6II_SOURCE50_TCG_"))}
            if role == "MCU":
                env.update(Z6II_MCU_WIRE_PATH=str(bus),
                           Z6II_MCU_WIRE_PAIRING="pb14_pd12_pe3_pg6",
                           Z6II_MCU_WIRE_POLL_NS=str(args.poll_ns))
            logs[role] = (directory / (role + "-host.log")).open("w")
            process = subprocess.Popen(argv, cwd=workspace, env=env, stdout=logs[role],
                                       stderr=subprocess.STDOUT, start_new_session=True)
            processes[role] = process
            report["processes"][role] = dict(argv=argv, pid=process.pid,
                host_launch_elapsed_seconds=round(time.monotonic() - started, 6))
            save(directory / "执行命令.json", report)
            if role == "MCU":
                report["MCU_actual_attachment_before_EXPEED"] = wait_mcu_attachment(
                    directory, bus, process, report)
                save(directory / "执行命令.json", report)
        save(directory / "执行命令.json", report)
        if startup_gate:
            while True:
                check_host_stop(directory, report)
                released = release(startup_gate, list(processes.values()))
                if released is not None:
                    report['initial_resource_startup_release'] = released
                    break
                time.sleep(0.02)
        # Allow bounded setup, stopped captures and streaming log processing.
        # The guest execution budget remains args.seconds.
        report["host_postprocessing_allowance_seconds"] = 60
        deadline = time.monotonic() + args.seconds + report["host_postprocessing_allowance_seconds"]
        while any(p.poll() is None for p in processes.values()) and time.monotonic() < deadline:
            check_host_stop(directory, report)
            time.sleep(0.1)
        if any(p.poll() is None for p in processes.values()):
            report["host_envelope_timeout"] = True
    except BaseException as exc:
        report["host_runner_error"] = type(exc).__name__ + ": " + str(exc)
        if startup_gate and not (startup_gate / 'release.json').exists():
            fail(startup_gate, exc)
    finally:
        for role, process in processes.items():
            report["processes"][role]["host_termination"] = stop_owned_runner(process)
            report["processes"][role]["exit_code"] = process.returncode
            logs[role].close()
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        for role in processes:
            result_path = directory / role / "结果.json"
            if result_path.exists():
                report["processes"][role]["result"] = identity(result_path)
                try:
                    child = json.loads(result_path.read_text())
                except Exception as exc:
                    report["processes"][role]["error"] = type(exc).__name__ + ": " + str(exc)
                    continue
                if child.get("guest_RAM_or_register_fixtures"):
                    report["guest_RAM_or_register_fixtures"].extend(child["guest_RAM_or_register_fixtures"])
                    report["conditional_diagnostic_RAM_seed_performed"] = True
                report["processes"][role]["owned_QEMU_exited"] = child.get("owned_QEMU_exited")
                report["processes"][role]["first_unmodeled"] = child.get("first_unmodeled")
                report["processes"][role]["error"] = child.get("error")
                report["processes"][role]["first_hardware_boundary_line"] = child.get("first_hardware_boundary_line")
                report["processes"][role]["native_wire_boundary_lines"] = child.get("native_wire_boundary_lines", [])
                report["processes"][role]["QEMU_exit_code"] = child.get("QEMU_exit_code")
                if role == "MCU":
                    report["MCU_auxiliary_power"] = child.get("MCU_auxiliary_power")
                    report["actual_host_MCU_guest_state_write_count"] = child.get("actual_host_guest_state_write_count")
                    report["processes"][role]["FLASH_observation"] = {key: child.get(key) for key in (
                        "FLASH_functional_experiment_enabled", "FLASH_explicit_functional_inputs",
                        "FLASH_source_input_file_unchanged", "initial_simulated_FLASH_snapshot",
                        "current_simulated_FLASH_snapshot", "FLASH_event_counts",
                        "original_FLASH_save_requests", "original_FLASH_save_callbacks")}
                if "engines" in child:
                    report["processes"][role]["engine_boundaries"] = {
                        name: {key: engine.get(key) for key in (
                            "exit_code", "first_unmodeled", "first_hardware_boundary",
                            "native_wire_boundary_lines", "native_wire_ACK_write_lines",
                            "native_wire_known_wait_lines")}
                        for name, engine in child["engines"].items()}
        report["owned_runner_processes_exited"] = bool(processes) and all(
            p.poll() is not None for p in processes.values())
        report["host_runner_accounting"] = {
            "scope": "host Python runners only; QEMU launch/termination checked separately",
            "expected_roles": ["MCU", "EXPEED"], "started_roles": list(processes),
            "exit_observed_roles": [role for role, p in processes.items() if p.poll() is not None]}
        # Persist the raw result before deriving endpoint evidence. Missing
        # child files remain unknown; an empty set never satisfies cleanup.
        save(directory / "三端接入结果.json", report)
        try:
            preliminary = normalize_run(directory, run_number)
            report["QEMU_process_accounting"] = preliminary["QEMU_process_accounting"]
        except Exception as exc:
            report["evidence_processing_error"] = type(exc).__name__ + ": " + str(exc)
        report["bus_inspection_gate_scope"] = "all evidenced started QEMU processes exited and no unknown launch"
        if report.get("QEMU_process_accounting", {}).get("exit_coverage") == "confirmed_for_started_processes":
            captured = subprocess.run([str(tool), "inspect-stopped", str(bus)],
                                      capture_output=True, text=True)
            report["bus_inspection_exit_code"] = captured.returncode
            if captured.returncode == 0:
                report["stopped_bus"] = json.loads(captured.stdout)
            else:
                report["bus_inspection_error"] = captured.stderr
        report["final_bus"] = identity(bus)
        report["coordinator_status"] = coordinator_status(report)
        save(directory / "三端接入结果.json", report)
        try:
            save_json(directory / "运行验收证据.json", normalize_run(directory, run_number))
        except Exception as exc:
            report["evidence_processing_error"] = type(exc).__name__ + ": " + str(exc)
            report["coordinator_status"] = coordinator_status(report)
            save(directory / "三端接入结果.json", report)
    print(json.dumps(dict(output=str(directory), processes=report["processes"],
                          stopped_bus=report.get("stopped_bus"),
                          coordinator_status=report["coordinator_status"]), ensure_ascii=False))
    return report["coordinator_status"]["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
