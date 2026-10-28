"""Menus on an already booted original master while its original slave runs.

Uses the verified external TEMP/menu-gate experiment's diagnostic inputs.
No scripted peer, original firmware patch, direct capture-ready write or
timeout interception. Both original guests retain their native RTOS state.
"""
import hashlib
import json
from pathlib import Path
import struct
import traceback

import guest_call
from application_z6ii import Application
from host_env import ROOT

KEYS = {"half": 7, "right": 34, "left": 35, "up": 36, "down": 37,
        "menu": 67, "play": 68, "i": 72, "ok": 74}


def input_state(remote):
    raw = remote.memory(0xc1811e50, 100)
    forward = remote.memory(0xc1811eb4, 0x60)
    owner = remote.memory(0xc1818be0, 0x160)
    current = struct.unpack_from("<I", owner, 0x154)[0]
    return dict(all_initialized=struct.unpack_from("<I", raw)[0],
        forwarding_enabled=struct.unpack_from("<I", raw, 4)[0],
        inhibit=struct.unpack_from("<I", forward, 8)[0],
        deferred=struct.unpack_from("<I", forward, 12)[0],
        sys_state=owner[0x158], state_obj=hex(current),
        substate=struct.unpack("<I", remote.memory(current + 0x108, 4))[0]
            if 0xc0000000 <= current < 0xd0000000 else None,
        application_precheck_c18696f0=remote.memory(0xc18696f0, 4).hex(),
        gui_mode_gate=remote.memory(0xc181a6e4, 4).hex(),
        gui_service_state=remote.memory(0xc181b400, 4).hex(),
        capture_state=remote.memory(0xc18694b0, 0x100).hex())


def run_session(engines, enabled, directory, report, plan="traversal", extra_regions=(),
                sensor_dependency_trace=False):
    config_regions = tuple(dict.fromkeys((8, 0x11, 0x35, 0x18, *extra_regions)))
    if any(not 0 <= region <= 0x50 for region in config_regions):
        raise ValueError("Original resource regions must be 0..0x50")
    master, slave = engines["master"], engines["slave"]
    if any(p.process.poll() is not None for p in (master, slave)):
        raise RuntimeError("Original dual menu session requires both original guests alive")
    for role, p in engines.items():
        assert not p.running
        for address in enabled[role]:
            assert p.remote.command(f"z1,{address:x},2") == "OK"
        enabled[role].clear()
    reference = ROOT / "outputs/Z6II全机研究/20261017-外部菜单进展核查/接收原件/01-test_menu_temp.py"
    session = report["original_dual_menu_session"] = dict(
        original_master_and_slave=True, original_slave_running_during_master_calls=True,
        scripted_peer=False, original_instruction_bytes_modified=False,
        full_natural_camera_boot_verified=False, synthetic_application_inputs=True,
        external_menu_reference=str(reference),
        external_menu_reference_sha256=hashlib.sha256(reference.read_bytes()).hexdigest(),
        steps=[], synthetic_persistent_TEMP=True,
        direct_application_precheck_or_capture_ready_writes=False)
    session["diagnostic_menu_plan"] = plan
    session["diagnostic_original_config_regions"] = [hex(region) for region in config_regions]
    session["sensor_dependency_trace_enabled"] = sensor_dependency_trace
    persistent = master.persistent_input or {}
    recorded_parent11 = any(int(row["address"], 0) == 0x132C0000 and
        row["bytes"] == 0x1FFFC and row["source_sha256"] ==
        "633870b12df9f13ee5fe2a7770455cca7115d35ecd4ad581c03aa5090decfca9"
        for row in persistent.get("recorded_payload_ranges", []))
    session["recorded_parent11_input_available"] = recorded_parent11
    session["conditional_persistent_input"] = persistent.get("conditional_composite_flash_input", False)
    session["inferred_storage_ranges"] = persistent.get("inferred_storage_ranges", [])
    session["synthetic_persistent_TEMP"] = not recorded_parent11
    path = directory / "菜单逐步记录.json"

    def save():
        path.write_text(json.dumps(session, ensure_ascii=False, indent=2) + "\n")

    def slave_checkpoint(label):
        if slave.running:
            slave.remote.sock.sendall(b"\x03")
            packet = slave.remote.receive()
            slave.running = False
        else:
            packet = slave.remote.command("?")
        snap = slave.snapshot(label, packet)
        result = dict(label=label, cores=snap["cores"],
            counter=slave.remote.memory(0x04266008, 8).hex(),
            pipeline_manager=slave.remote.memory(0xc1000e98, 0x18).hex(),
            queue=slave.remote.memory(0xc1006f68, 0x30).hex())
        session.setdefault("slave_checkpoints", []).append(result)
        result["CPU_fault_statuses"] = [{"thread": core["thread"],
            "registers": {k: v for k, v in core["system_registers"].items()
                          if k.startswith(("DFSR", "IFSR"))}}
            for core in snap["cores"]]
        result["nonzero_CPU_fault_status_observed"] = any(
            int(value, 16) for core in result["CPU_fault_statuses"]
            for value in core["registers"].values())
        save()
        if result["nonzero_CPU_fault_status_observed"]:
            session.update(completed=False, error="Original slave CPU fault status is nonzero; keep guest paused and stop menu validation")
            save()
            raise RuntimeError(session["error"])
        slave.remote.send("c")
        slave.running = True
        return result

    for role, engine in report["engines"].items():
        faults = [value for core in engine.get("final_CPU_fault_registers", [])
                  for name, value in core["registers"].items() if name.startswith(("DFSR", "IFSR"))]
        if any(int(value, 16) for value in faults):
            session.update(completed=False, error=f"Original {role} CPU fault status is nonzero before menu validation")
            save()
            raise RuntimeError(session["error"])
    slave_checkpoint("original slave before attached master application")
    app = Application("original-dual-menu", "menu", probe=master)

    def wait(ms, label):
        app.call("native wait " + label, 0x103dec94, bytes(8), [ms], host_timeout=120)
        app.checkpoint(0x10200190, "native idle " + label)

    def capture(label):
        row = dict(label=label, state=input_state(master.remote),
                   screenshot=app.screenshot(label), slave_process_alive=slave.process.poll() is None)
        # Never hold master paused for host OCR while its peer advances.
        # review_original_dual_menu.py performs image/exit/Error-UI acceptance
        # after the owning coordinator has closed both original guests.
        row["OCR"] = dict(rows=[], deferred_until_both_original_guests_close=True)
        words = " ".join(item["text"] for item in row["OCR"].get("rows", [])).lower()
        row["original_Error_UI_detected"] = "turn camera off" in words
        session["steps"].append(row)
        save()
        print("Original dual menu step:", label, "state:", row["state"]["sys_state"],
              "colors:", row["screenshot"]["distinct_colors"], flush=True)
        if row["original_Error_UI_detected"]:
            raise RuntimeError("Original firmware rendered Error UI; stop menu plan at " + label)
        if label == "01-menu-enter" and row["screenshot"]["distinct_colors"] <= 1:
            raise RuntimeError("Original MENU was not rendered; stop traversal at the first single-color frame")
        return row

    def key(name, label, ms=1000):
        app.key(KEYS[name], label)
        wait(ms, label)
        return capture(label)

    def original_exception_entry(remote, registers):
        """Retain the original exception context before the diagnostic logger.

        Fault registers can be zero for an original software exception. Run30
        reached101034fc while its native48MHz counter still advanced; a longer
        host timeout cannot make that original fatal loop return.
        """
        context = int(registers["r1"], 16)
        event = dict(registers=registers, original_callback="0x10202498",
                     callback_kind=int(registers["r0"], 16),
                     context_address=hex(context), intercepted_or_replaced=False)
        if 0xc0000000 <= context < 0xd0000000 - 0x100:
            data = app.dump("original-exception-context", context, 0x100)
            event["raw_context"] = data.hex()
            event["context_words"] = [hex(x) for x in struct.unpack("<64I", data)]
        session["original_native_exception"] = event
        master.running = False
        snapshot = master.snapshot("original native exception before logger", remote.command("?"))
        app.timeout_context(snapshot)
        event["CPU_snapshot"] = snapshot
        event["input_state"] = input_state(remote)
        event["screenshot"] = app.screenshot("original-exception-before-logger")
        save()
        raise RuntimeError("Original master exception callback reached10202498; original context saved, menu validation stopped")

    def original_panel_configuration(remote, registers):
        root = remote.memory(0xc1808500, 0x18)
        holder = struct.unpack_from("<I", root, 4)[0]
        row = dict(registers=registers, panel_root=root.hex(), holder=hex(holder),
                   observation_only=True, original_return_or_argument_replaced=False)
        if 0xc0000000 <= holder < 0xd0000000 - 0x18:
            row["holder_bytes"] = remote.memory(holder, 0x18).hex()
        argument = int(registers["r0"], 16)
        if 0xc0000000 <= argument < 0xd0000000 - 0x80:
            row["argument_bytes"] = remote.memory(argument, 0x80).hex()
        session.setdefault("original_panel_configuration_observations", []).append(row)
        save()

    def original_region_load_dependency(remote, registers):
        if int(registers["r5"], 16) not in config_regions:
            return
        row = dict(registers=registers, observation_only=True,
            configuration_startup=remote.memory(0xc185e548, 0x24).hex(),
            GENNOR_lifecycle=remote.memory(0xc1875304, 0x20).hex())
        for name in ("r0", "r4", "r6"):
            pointer = int(registers[name], 16)
            if 0xc0000000 <= pointer < 0xd0000000 - 0x40:
                row[name + "_descriptor_bytes"] = remote.memory(pointer, 0x40).hex()
        session.setdefault("original_region_load_dependencies", []).append(row)
        save()

    def subscription_snapshot(label):
        data = app.dump(label + "-original-region-subscribers", 0xc20a3348, 0x51 * 0x30)
        rows = []
        for ident in range(0x51):
            record = data[ident * 0x30:(ident + 1) * 0x30]
            callbacks = struct.unpack_from("<10I", record)
            count = struct.unpack_from("<H", record, 0x2c)[0]
            if count or ident in (0x11, 0x12, 0x13, 0x18, 0x35, 0x50):
                rows.append(dict(region=hex(ident), count=count,
                    callbacks=[hex(v) for v in callbacks],
                    lifecycle_flags=hex(struct.unpack_from("<I", record, 0x28)[0])))
        result = dict(label=label, rows=rows, observation_only=True)
        session.setdefault("original_region_subscriber_snapshots", []).append(result)
        save()
        return result

    def original_child_dispatch(remote, registers):
        row = dict(registers=registers, observation_only=True)
        if registers["r15"] == "0x103c1bb6":
            row["original_load_result"] = registers["r0"]
        if registers["r15"] == "0x103c1c30":
            row["subscriber_snapshot"] = subscription_snapshot("original-region11-child-dispatch")
        session.setdefault("original_child_configuration_dispatch", []).append(row)
        save()

    def original_lcd_wait(remote, registers):
        sp = int(registers["r13"], 16)
        row = dict(registers=registers, observation_only=True,
            original_wait_or_result_replaced=False,
            counter_48MHz_raw=remote.memory(0x04266008, 8).hex(),
            LCD_configuration_eventflag_object=remote.memory(0xc1875330, 4).hex(),
            stack_address=hex(sp), stack_64bytes=remote.memory(sp, 64).hex())
        if registers["r15"] == "0x10205226":
            row.update(original_wait_result=registers["r0"],
                original_wait_output_flags=remote.memory(sp + 0x1c, 4).hex())
        session.setdefault("original_LCD_configuration_wait_observations", []).append(row)
        save()

    def original_policy_check(remote, registers):
        row = dict(registers=registers, observation_only=True,
            original_result_replaced=False, state=input_state(remote),
            power_property_state=remote.memory(0xc185deec, 0x10).hex(),
            TEMP_root=remote.memory(0xc1807f70, 0x10).hex(),
            TEMP_bytes=remote.memory(0xc8152100, 0x50).hex(),
            counter_48MHz_raw=remote.memory(0x04266008, 8).hex())
        raw = remote.memory(0xc18696f0, 0x90)
        row["original_condition_owner_bytes"] = raw.hex()
        row["original_condition_bitmaps"] = []
        for offset in (0x38, 0x40, 0x48, 0x50, 0x58):
            count, pointer = struct.unpack_from("<2I", raw, offset)
            bitmap = dict(descriptor=hex(0xc18696f0 + offset), bits=count, pointer=hex(pointer))
            length = ((count + 31) // 32) * 4
            if 0 < count <= 512 and 0xc0000000 <= pointer < 0xd0000000 - length:
                data = remote.memory(pointer, length)
                bitmap.update(raw=data.hex(), set_bits=[i for i in range(count)
                    if data[i // 8] & (1 << (i % 8))])
            row["original_condition_bitmaps"].append(bitmap)
        if registers["r15"] in ("0x1022906e", "0x1022900c"):
            row["condition_bit_request"] = int(registers["r0"], 16)
            row["condition_operation"] = "set" if registers["r15"] == "0x1022906e" else "clear"
        if registers["r15"] == "0x10228f32":
            row["original_new_precheck_byte_to_store"] = registers["r4"]
        if registers["r15"] == "0x103f36c8":
            row["original_capture_wait_result"] = registers["r0"]
            row["original_capture_wait_flags"] = remote.memory(int(registers["r13"], 16), 4).hex()
        session.setdefault("original_application_policy_observations", []).append(row)
        save()

    def original_condition_source(remote, registers):
        """Retain the native error event and its producer, without changing it.

        Run38's already saved native stack contains041000B0/value0 and the
        lower error-registry callback return1035B037. These are error-domain
        messages; the bitmap index alone does not identify a physical device.
        """
        pc = int(registers["r15"], 16)
        if pc == 0x103ee5cc and int(registers["r0"], 16) not in (0x041000b0, 0x041000b1):
            return
        sp = int(registers["r13"], 16)
        raw = remote.memory(sp, 0x200)
        row = dict(registers=registers, observation_only=True,
            original_event_or_error_replaced=False,
            counter_48MHz_raw=remote.memory(0x04266008, 8).hex(),
            stack_address=hex(sp), stack_bytes=raw.hex(),
            stack_words=[hex(v) for v in struct.unpack("<128I", raw)],
            lower_error_registry=remote.memory(0xc1866cd4, 0x60).hex(),
            lower_failure_state=remote.memory(0xc1868290, 0x1b0).hex(),
            lower_pending_failure_descriptor=remote.memory(0xc23d96ec, 0x10).hex())
        if pc in (0x103eeca6, 0x103eecbe):
            row.update(original_error_value=registers["r0"],
                original_message=hex(struct.unpack_from("<I", raw, 0x3c)[0]),
                original_payload_word=hex(struct.unpack_from("<I", raw, 0x40)[0]))
        if pc == 0x103970b4:
            pointer = int(registers["r0"], 16)
            if 0xc0000000 <= pointer < 0xd0000000 - 16:
                data = remote.memory(pointer, 16)
                row["failure_descriptor"] = dict(address=hex(pointer), raw=data.hex(),
                    error_identifier=data[0], auxiliary=hex(struct.unpack_from("<I", data, 4)[0]),
                    class_mask=hex(struct.unpack_from("<H", data, 8)[0]))
        session.setdefault("original_condition_source_observations", []).append(row)
        save()

    def original_sensor_parameters(remote, registers):
        """Observe the original region50 binding and native version check.

        The two version bytes come from the guest's actual resource; this
        observer supplies no resource bytes, pointers, version or return value.
        """
        pc = int(registers["r15"], 16)
        root = remote.memory(0xc18a7798, 0x30)
        pointer = struct.unpack_from("<I", root, 0x14)[0]
        row = dict(registers=registers, observation_only=True,
                   original_arguments_bytes_or_result_replaced=False,
                   parameter_owner_bytes=root.hex(), current_pointer=hex(pointer),
                   counter_48MHz_raw=remote.memory(0x04266008, 8).hex())
        pointers = {"current": pointer}
        if pc in (0x102d8322, 0x102fadb8):
            pointers["original_binding_argument"] = int(registers["r0"], 16)
        row["resources"] = {}
        for label, candidate in pointers.items():
            resource = row["resources"][label] = dict(pointer=hex(candidate))
            if not 0xc0000000 <= candidate <= 0xd0000000 - 0xce018:
                resource["bounded_RAM_read_available"] = False
                continue
            try:
                header = remote.memory(candidate, 0x40)
                version_bytes = remote.memory(candidate + 0xce014, 2)
                version = (version_bytes[0] << 4) | (version_bytes[1] >> 4)
                resource.update(bounded_RAM_read_available=True, header=header.hex(),
                    version_address=hex(candidate + 0xce014), version_bytes=version_bytes.hex(),
                    decoded_version=hex(version),
                    static_original_check_would_accept=0x150 <= version <= 0x15f)
            except ValueError as error:
                resource["unmapped_debugger_read"] = str(error)
        if pc in (0x10302066, 0x10302072):
            row["original_check_return_r0"] = registers["r0"]
        session.setdefault("original_sensor_parameter_observations", []).append(row)
        save()

    sensor_wait_entries = {}
    parent_load_entries = {}

    def original_parent_source(remote, registers):
        pc, sp = int(registers["r15"], 16), int(registers["r13"], 16)
        selected = {0xC185ED84: ("parent11", 0x132C0000, 0x1FFFC,
                "633870b12df9f13ee5fe2a7770455cca7115d35ecd4ad581c03aa5090decfca9"),
            0xC185F468: ("region50", 0x13E80000, 0x168000,
                "3131474120fa6a149b14709932bce810f9d801c2aabca01eda75e26bcc62fb93")}
        if pc == 0x103C1AF2:
            descriptor = int(registers["r0"], 16)
            if descriptor not in selected:
                return
            name, source, length, expected = selected[descriptor]
            raw = remote.memory(descriptor, 0x18)
            destination = struct.unpack_from("<I", raw, 8)[0]
            row = dict(registers=registers, phase="entry", name=name,
                descriptor=hex(descriptor), descriptor_bytes=raw.hex(),
                source_address=hex(source), destination=hex(destination),
                payload_bytes=length, expected_payload_sha256=expected,
                observation_only=True, original_return_or_arguments_replaced=False)
            parent_load_entries[sp] = row
        elif pc == 0x103C1B44:
            # Original103C1AF2 pushes only LR. At103C1B44 its34h locals
            # have been released, but the4-byte saved LR is still stacked.
            entry = parent_load_entries.pop(sp + 4, None)
            if not entry:
                return
            row = dict(entry, registers=registers, phase="return", original_loader_return_r0=registers["r0"])
            destination, length = int(entry["destination"], 16), entry["payload_bytes"]
            if int(registers["r0"], 16) == 1 and 0xC0000000 <= destination <= 0xD0000000-length:
                data = app.dump("loaded-" + entry["name"] + "-" + str(len(session.get("original_parent_source_observations", []))), destination, length)
                row.update(loaded_payload_sha256=hashlib.sha256(data).hexdigest(),
                    loaded_payload_matches_recorded_camera_RAM=hashlib.sha256(data).hexdigest() == entry["expected_payload_sha256"])
                if entry["name"] == "parent11":
                    row["loaded_TEMP_sha256"] = hashlib.sha256(data[0xA100:0xA200]).hexdigest()
            else:
                row["loaded_payload_matches_recorded_camera_RAM"] = False
        elif pc == 0x103E321E:
            address = int(registers["r1"], 16)
            if (int(registers["r0"], 16) != 0xC185E5D4 or
                address not in (0x132DFFFC, 0x13FFFFFC) or int(registers["r2"], 16) != 4):
                return
            row = dict(registers=registers, phase="marker compare", source_address=hex(address),
                actual_source_bytes=remote.memory(address, 4).hex(), observation_only=True,
                inferred_marker_condition=True, original_return_or_arguments_replaced=False)
        else:
            return
        session.setdefault("original_parent_source_observations", []).append(row)
        save()

    def original_sensor_dependency(remote, registers):
        pc = int(registers["r15"], 16)
        # Resource50 has the original descriptorC185F468 and parentC185EB7C.
        # Observe only this parent in shared backend validation functions.
        if pc == 0x102a97f6 and int(registers["r4"], 16) == 0:
            return
        if pc in (0x102a9308, 0x102a9732, 0x102a97f6):
            sp = int(registers["r13"], 16)
            descriptor = int(registers["r2"], 16) if pc == 0x102a9308 else None
            if pc in (0x102a9732, 0x102a97f6):
                descriptor = int(registers["r4"], 16)
            if not descriptor or not 0xc0000000 <= descriptor <= 0xd0000000 - 0x34:
                return
            raw = remote.memory(descriptor, 0x34)
            # Backend selection receives a complete load job instead of the
            # shorter validation descriptor; its source is at+10h as well.
            source = struct.unpack_from("<I", raw, 0x10 if pc in (0x102a9732, 0x102a97f6) else 4)[0]
            if source != 0x13e80000:
                return
            row = dict(registers=registers, observation_only=True,
                original_resource_validation_or_return_replaced=False,
                descriptor_address=hex(descriptor), descriptor_bytes=raw.hex(),
                stack_bytes=remote.memory(sp, 0x60).hex(),
                source_address=hex(source), source_header=remote.memory(source, 0x40).hex(),
                source_version_bytes=remote.memory(source + 0xce014, 2).hex(),
                source_parameter_payload_tail=remote.memory(source + 0x168000 - 16, 16).hex(),
                counter_48MHz_raw=remote.memory(0x04266008, 8).hex())
            extent = struct.unpack_from("<I", raw, 0xc if pc == 0x102a9308 else 0x18)[0]
            if 4 <= extent <= 0x14000000 - source:
                row.update(required_container_extent_bytes=extent,
                    required_container_ENDM_address=hex(source + extent - 4),
                    required_container_ENDM_bytes=remote.memory(source + extent - 4, 4).hex(),
                    copied_parameter_payload_tail_is_container_ENDM=extent == 0x168000)
            if pc == 0x102a97f6:
                row["original_selected_bank_or_minus_one"] = registers["r0"]
            if pc == 0x102a9732:
                row["original_single_source_validation_return_r0"] = registers["r0"]
            session.setdefault("original_sensor_resource_validation_observations", []).append(row)
        else:
            sp = int(registers["r13"], 16)
            row = dict(registers=registers, observation_only=True,
                original_wait_or_irq_result_replaced=False,
                stack_bytes=remote.memory(sp, 0x60).hex(),
                counter_48MHz_raw=remote.memory(0x04266008, 8).hex(),
                original_sensor_control=remote.memory(0xc18a75d8, 0x160).hex(),
                original_SIF_owner=remote.memory(0xc1809700, 0x50).hex(),
                original_TG_driver_and_callbacks=remote.memory(0xc1806d54, 0x50).hex(),
                original_TG_readable_registers={hex(address): remote.memory(address, 4).hex()
                    for address in (0x20060000, 0x20060008, 0x20060010,
                        0x20060018, 0x20060020, 0x20060034, 0x20060038,
                        0x20060040, 0x20060044, 0x2006004c, 0x20060050)})
            if pc == 0x102df2c8:
                row.update(original_gate_mask=registers["r1"],
                           original_gate_set_or_clear_argument=registers["r2"],
                           semantic_scope="original set/clear aliases; not a sensor-frame observation")
            if pc in (0x102df04c, 0x102d7ed4, 0x102d7f1a):
                row["original_TG_callback_or_IRQ_entry"] = hex(pc)
            if pc == 0x102d7ed4:
                row["original_IRQ87_cause_argument"] = registers["r1"]
            if pc == 0x102db6e6:
                output_address = int(registers["r2"], 16)
                row.update(requested_flags=registers["r1"],
                           original_timeout_parameter=registers["r3"],
                           output_address=registers["r2"],
                           output_memory_before_original_wait=remote.memory(output_address, 4).hex())
                sensor_wait_entries[sp] = dict(row)
            if pc == 0x102db6ea:
                row.update(original_wait_return_r0=registers["r0"],
                           output_memory_after_original_wait=remote.memory(sp, 4).hex(),
                           output_memory_is_valid_completion_flags=int(registers["r0"], 16) != 0,
                           original_error_accumulator_before_timeout=registers["r6"])
                entry = sensor_wait_entries.pop(sp, None)
                if entry:
                    before = entry["output_memory_before_original_wait"]
                    row.update(output_memory_before_original_wait=before,
                               output_memory_unchanged_by_original_wait=
                                   before == row["output_memory_after_original_wait"],
                               original_timeout_parameter=entry["original_timeout_parameter"],
                               elapsed_counter_ticks_48MHz=
                                   (int.from_bytes(bytes.fromhex(row["counter_48MHz_raw"]), "little") -
                                    int.from_bytes(bytes.fromhex(entry["counter_48MHz_raw"]), "little")) % (1 << 64))
                    row["elapsed_virtual_ms_from_48MHz_counter"] = row["elapsed_counter_ticks_48MHz"] / 48000
            if pc in (0x102db6f0, 0x102db844):
                row["original_error_accumulator"] = registers["r6" if pc == 0x102db6f0 else "r5"]
            session.setdefault("original_sensor_setup_dependency_observations", []).append(row)
        save()

    app.initialization_observers = {0x10202498: original_exception_entry,
        0x102d8322: original_sensor_parameters,
        0x102fadb8: original_sensor_parameters,
        0x10302048: original_sensor_parameters,
        0x10302066: original_sensor_parameters,
        0x10302072: original_sensor_parameters,
        0x104d9f1a: original_panel_configuration, 0x104840ac: original_panel_configuration,
        0x103c1b70: original_region_load_dependency,
        0x103c1b8a: original_region_load_dependency,
        0x103c1bae: original_region_load_dependency,
        0x103c1bbe: original_region_load_dependency,
        0x103c1bb6: original_child_dispatch,
        0x103c1c30: original_child_dispatch,
        0x103c1c3e: original_child_dispatch,
        0x102051b4: original_lcd_wait,
        0x1020521c: original_lcd_wait,
        0x10205226: original_lcd_wait,
        0x10205236: original_lcd_wait,
        0x10205264: original_lcd_wait,
        0x1020d384: original_policy_check,
        0x103f3688: original_policy_check,
        0x103f3698: original_policy_check,
        0x103f36a4: original_policy_check,
        0x103f36d4: original_policy_check,
        0x103c13c4: original_policy_check,
        0x10228f32: original_policy_check,
        0x1022906e: original_policy_check,
        0x1022900c: original_policy_check,
        0x103f36c8: original_policy_check,
        0x103eeca6: original_condition_source,
        0x103eecbe: original_condition_source,
        0x1022916a: original_condition_source,
        0x103970b4: original_condition_source,
        0x103970c8: original_condition_source,
        0x1035b004: original_condition_source,
        0x1039b774: original_condition_source}
    sensor_points = {0x102a9308, 0x102a9732, 0x102a97f6,
                     0x102db6e6, 0x102db6ea, 0x102db6ec, 0x102db6f0, 0x102db844,
                     0x10296a1c, 0x102df2c8, 0x102df04c, 0x102d7ed4, 0x102d7f1a}
    if sensor_dependency_trace:
        app.initialization_observers.update({pc: original_sensor_dependency for pc in sensor_points})
        app.initialization_observers.update({pc: original_parent_source for pc in (0x103C1AF2, 0x103C1B44, 0x103E321E)})
    previous_repeat = set(guest_call.TRACE_REPEAT)
    guest_call.TRACE_REPEAT = previous_repeat | {
        0x103c1c3e, 0x102051b4, 0x10205226, 0x10205236, 0x10205264,
        0x104d9f1a, 0x104840ac, 0x1020d384, 0x103f3688, 0x103f3698,
        0x103f36a4, 0x103f36d4, 0x10228f32, 0x1022906e, 0x1022900c,
        0x103f36c8, 0x103eeca6, 0x103eecbe, 0x1022916a,
        0x103970b4, 0x103970c8, 0x1035b004, 0x1039b774,
        0x102d8322, 0x102fadb8, 0x10302048, 0x10302066, 0x10302072}
    if sensor_dependency_trace:
        guest_call.TRACE_REPEAT |= sensor_points | {0x103C1AF2, 0x103C1B44, 0x103E321E}

    try:
        app.checkpoint(0x10200190, "attached original master native idle")
        subscription_snapshot("original-boot-before-diagnostic-inputs")
        session["diagnostic_initialization_order"] = [
            "original configuration loads while original LCD5000ms wait is pending",
            "settle already configured MCU packet replay through original transport",
            "application diagnostic inputs after replay consumers"]
        if not recorded_parent11:
            temp = bytearray(0x100)
            temp[:4] = b"TEMP"
            for off in (0x24, 0x28, 0x2c):
                struct.pack_into("<i", temp, off, 1000)
            for off in (0x30, 0x34, 0x38, 0x3c, 0x40):
                struct.pack_into("<i", temp, off, -1000)
            assert master.remote.command("Mc8152100,100:" + temp.hex()) == "OK"
            session["TEMP_fixture"] = dict(address="0xc8152100", bytes=len(temp),
                sha256=hashlib.sha256(temp).hexdigest(), original_factory_values_available=False)
        # Native MCU transport already ran during dual boot. Do not replay the
        # same callback or allocate image memory again in this attached session.
        for region in config_regions:
            app.call(f"original region{region:02x} load diagnostic", 0x103c1b5e, bytes(8), [region])
        # The marker comparator is general-purpose; its selected source
        # observations are complete once the explicit loads have returned.
        app.initialization_observers.pop(0x103E321E, None)
        # Match the preserved reference's native500ms settle between region
        # loads and controller/GUI inputs. Observe the actual factory-pointer
        # producer; never install a pointer or replace an original result.
        wait(500, "region notifications before controller inputs")
        subscription_snapshot("after-original-region-notifications")
        panel_root = master.remote.memory(0xc1808500, 0x18)
        holder = struct.unpack_from("<I", panel_root, 4)[0]
        configuration = struct.unpack("<I", master.remote.memory(holder, 4))[0]
        session["panel_after_original_region_settle"] = dict(root=panel_root.hex(),
            holder=hex(holder), configuration=hex(configuration),
            configuration_pointer_supplied_by_harness=False)
        save()
        if not configuration:
            raise RuntimeError("Original panel configuration producer remains pending after region loads; stop before its null consumer")
        # In run36, SYS/KEY/power replay at1/2/3s arrived after application
        # fixtures and changed the original application prerequisite to2.
        # Let those original consumers finish before the diagnostic comparison.
        # This is an original timer wait, not a retry or return-value override.
        wait(3500, "original MCU replay consumers before application diagnostic inputs")
        session["state_before_application_diagnostic_inputs"] = input_state(master.remote)
        app.initialize_application_inputs()
        app.call("diagnostic controller status07 via original callback", 0x10204e3c,
                 bytes([7]) + bytes(51), [0x04100007, ("scratch", 0)])
        app.call("diagnostic GUI service state via original producer", 0x10698424, bytes(8), [0])
        wait(3500, "settle original input deferral")
        capture("00-before-menu")
        app.call("verified original mode2 GUI gate", 0x10247d2a, bytes(8), [2])
        key("menu", "01-menu-enter", 3000)
        key("down", "02-menu-down", 2000)
        if plan == "traversal":
            key("left", "03-category-column")
            # Category navigation wraps. Traverse a full cycle from the
            # observed initial page; titles are verified from saved images.
            for n in range(8):
                key("down", f"06-category-{n+2}", 1000)
            key("right", "07-category-items")
            key("ok", "08-item-enter")
            key("left", "09-item-back")
        key("menu", "10-menu-exit", 2000)
        wait(3000, "exit stability")
        capture("11-after-exit-stability")
        key("menu", "12-menu-reenter", 2000)
        key("half", "13-half-exit", 2000)
        slave_checkpoint("original slave after menu navigation and exit")
        menu_frames = [row for row in session["steps"] if row["label"] != "00-before-menu"]
        if not menu_frames or all(row["screenshot"]["distinct_colors"] <= 1 for row in menu_frames):
            raise RuntimeError("No original menu pixels were observed; diagnostic traversal cannot pass")
        session["completed"] = True
        session["plan_execution_completed"] = True
        session["stable_menu_acceptance_pending_saved_frame_review"] = True
    except Exception as error:
        session.update(completed=False, error=str(error), traceback=traceback.format_exc())
        raise
    finally:
        guest_call.TRACE_REPEAT = previous_repeat
        report["diagnostic_function_calls"] = app.calls
        report["guest_RAM_or_register_fixtures"] = list(app.calls)
        if session.get("TEMP_fixture"):
            report["guest_RAM_or_register_fixtures"].append(session["TEMP_fixture"])
        # natural_boot's engine snapshots precede this attached session. Save
        # actual post-menu states before the owning coordinator closes guests.
        # In run30 the earlier zero DFSR concealed a later native Data Abort.
        session["final_original_CPU_states"] = {}
        for role, engine in engines.items():
            if engine.process.poll() is not None:
                continue
            try:
                if engine.running:
                    engine.remote.sock.sendall(b"\x03")
                    packet = engine.remote.receive()
                    engine.running = False
                else:
                    packet = engine.remote.command("?")
                snapshot = engine.snapshot("original dual menu final " + role, packet)
                session["final_original_CPU_states"][role] = snapshot
                faults = [{"thread": core["thread"], "registers": {
                    name: value for name, value in core["system_registers"].items()
                    if name.startswith(("DFAR", "IFAR", "DFSR", "IFSR"))}}
                    for core in snapshot["cores"]]
                report["engines"][role]["pre_menu_CPU_fault_registers"] = report["engines"][role].get("final_CPU_fault_registers")
                report["engines"][role]["final_CPU_fault_registers"] = faults
                report["engines"][role]["final_CPU_snapshot_scope"] = "after original dual attached menu session"
                if session.get("completed") and any(int(value, 16)
                    for core in faults for name, value in core["registers"].items()
                    if name.startswith(("DFSR", "IFSR"))):
                    session.update(completed=False, error="Original " + role + " CPU fault observed at final menu check")
                    report["error"] = session["error"]
            except Exception as error:
                session.setdefault("final_snapshot_errors", {})[role] = str(error)
                session["completed"] = False
                report.setdefault("error", "Original dual final CPU snapshot incomplete")
        save()
