"""Identity-locked offline Z6II application experiments, with explicit inputs.

The guest runs original instructions. Hardware replies and diagnostic register/
RAM inputs are recorded separately. Screenshots do not constitute live-view
frames, and an action acknowledgement does not constitute a recorded movie.
No physical camera, USB/PTP, or host device passthrough is accessed.
"""
import argparse
import hashlib
import json
import socket
import struct
import time
import traceback

import guest_call
from probe_z6ii import Probe

SYSTEM_REPORT = bytes.fromhex(
    "000100000200000000000000000000000000000002000000000000000000000000000000")


class Application:
    def __init__(self, label, stage="boot", readiness_inputs=False, probe=None):
        if probe is not None and probe.role != "master":
            raise ValueError("Application requires the original master firmware")
        self.p = probe if probe is not None else Probe(
            "master", label, assisted=True, link_test_peer=True, graphics_capture=True)
        self.stage = stage
        self.readiness_inputs = readiness_inputs
        self.initialization_observers = None
        self.packet = None
        self.calls = self.p.report.setdefault("application_calls", [])
        self.p.report["application_uses_existing_probe"] = probe is not None
        self.p.report.update(application_stage=stage, original_menu_verified=False,
                             continuous_liveview_verified=False, native_movie_file_verified=False)

    def checkpoint(self, address, label):
        e = self.p.run_to(address, label, thumb=True,
                          observers=self.initialization_observers)
        self.packet = e["stop_reply"]
        return e

    def call(self, name, address, payload, args, observers=None, host_timeout=None):
        if observers is None:
            observers = self.initialization_observers
        expected = self.p.blob[address-0x10020000:address-0x10020000+16]
        actual = self.p.remote.memory(address, 16)
        assert actual == expected, (name, actual.hex(), expected.hex())
        self.p.report["register_or_ram_fixture"] = True
        print(f"Z6II application diagnostic: {name} at {address:08x}", flush=True)
        c = {"name": name, "function": hex(address), "completed": False,
             "original_instructions_verified": True}
        if self.p.report.get("application_uses_existing_probe"):
            c["counter_before"] = self.p.remote.memory(0x04266008, 8).hex()
        started = time.monotonic()
        self.calls.append(c)
        previous_timeout = self.p.remote.sock.gettimeout()
        if host_timeout is not None:
            if not 0 < host_timeout <= 120:
                raise ValueError("Bounded host RSP timeout must be at most120 seconds")
            self.p.remote.sock.settimeout(host_timeout)
            c["host_RSP_budget_seconds"] = host_timeout
            c["firmware_timeout_or_timer_modified"] = False
        try:
            result = guest_call.call_fixture(self.p.remote, self.packet, address,
                                             payload, args, observers=observers)
        except socket.timeout:
            self.p.remote.sock.sendall(b"\x03")
            stopped = self.p.remote.receive()
            self.p.running = False
            event = self.p.snapshot("bounded application call timeout: " + name, stopped)
            c.update(timeout=True, incomplete_fixture=guest_call.ACTIVE_FIXTURE)
            c["host_seconds"] = round(time.monotonic() - started, 4)
            if "counter_before" in c:
                c["counter_after"] = self.p.remote.memory(0x04266008, 8).hex()
            self.timeout_context(event)
            budget = host_timeout if host_timeout is not None else previous_timeout
            raise RuntimeError(name + f" did not return within {budget} host seconds; CPU and stack observations saved")
        finally:
            self.p.remote.sock.settimeout(previous_timeout)
        c.update(result, completed=True)
        c["host_seconds"] = round(time.monotonic() - started, 4)
        if "counter_before" in c:
            c["counter_after"] = self.p.remote.memory(0x04266008, 8).hex()
        self.packet = self.p.remote.command("?")
        return c

    def timeout_context(self, event):
        observations = self.p.report.setdefault("timeout_context", [])
        for core in event["cores"]:
            self.p.remote.command("Hg" + core["thread"])
            regs = core["registers"]
            item = {"thread": core["thread"], "registers": regs,
                    "kind": "paused CPU and raw stack observations; pointer candidates are not a verified unwind"}
            for label, address, length in (
                    ("stack", int(regs["r13"], 16), 0x300),
                    ("pc-window", max(0x10020000, int(regs["r15"], 16) - 0x40), 0x80),
                    ("lr-window", max(0x10020000, (int(regs["r14"], 16) & ~1) - 0x40), 0x80)):
                try:
                    data = self.dump("timeout-" + core["thread"].replace(".", "-") + "-" + label,
                                     address, length)
                    if label == "stack":
                        item["rom_pointer_candidates"] = [
                            {"offset": hex(i), "value": hex(struct.unpack_from("<I", data, i)[0])}
                            for i in range(0, len(data) - 3, 4)
                            if 0x10020000 <= (struct.unpack_from("<I", data, i)[0] & ~1)
                            < 0x10020000 + len(self.p.blob)]
                except (ValueError, OSError) as error:
                    item.setdefault("unreadable", {})[label] = str(error)
            observations.append(item)

    def state(self, label):
        for name, address, length in (("system-object", 0xc1818be0, 0x400),
                                      ("system-state-objects", 0xc18194fc, 0x900),
                                      ("gui-state", 0xc181c530, 0x70),
                                      ("input-state", 0xc1811bb0, 0x40),
                                      ("input-consumer", 0xc1f7a5ac, 0x180),
                                      ("input-report", 0xc1f7a720, 52)):
            self.dump(label + "-" + name, address, length)

    def memory_mapping(self, label, addresses):
        page_table = self.dump(label + "-native-page-table", 0xc2b54000, 0x4000)
        observations = []
        for address in addresses:
            descriptor = struct.unpack_from("<I", page_table, (address >> 20) * 4)[0]
            item = {"virtual_address": hex(address), "l1_descriptor": hex(descriptor)}
            if descriptor & 3 == 2 and not descriptor & (1 << 18):
                physical = (descriptor & 0xfff00000) | (address & 0xfffff)
                item["physical_address"] = hex(physical)
                item["virtual_bytes"] = self.dump(label + "-virtual-" + f"{address:08x}",
                                                   address, 64).hex()
                filename = self.p.directory / (label + "-physical-" + f"{physical:08x}" + ".bin")
                self.p.monitor.command("pmemsave", {"val": physical, "size": 64,
                                                    "filename": str(filename)})
                item["physical_bytes"] = filename.read_bytes().hex()
                item["same_bytes"] = item["virtual_bytes"] == item["physical_bytes"]
            observations.append(item)
        self.p.report.setdefault("memory_mapping_observations", []).append({
            "label": label, "kind": "original runtime L1 descriptors and debugger versus physical reads",
            "addresses": observations})

    def dump(self, name, address, length):
        data = self.p.remote.memory(address, length)
        path = self.p.directory / (name + ".bin")
        path.write_bytes(data)
        self.p.report.setdefault("ram_observations", []).append({
            "name": name, "address": hex(address), "bytes": length,
            "sha256": hashlib.sha256(data).hexdigest(), "path": str(path), "hex": data.hex()})
        return data

    def screenshot(self, label):
        path = self.p.directory / (label + ".ppm")
        self.p.monitor.command("screendump", {"filename": str(path)})
        from PIL import Image
        with Image.open(path) as im:
            im.save(path.with_suffix(".png"))
            colors = im.getcolors(im.width * im.height)
            record = {"label": label, "ppm": str(path), "png": str(path.with_suffix(".png")),
                      "size": list(im.size), "distinct_colors": len(colors) if colors else None,
                      "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                      "kind": "QEMU display output; content requires verification"}
        self.p.report.setdefault("screenshots", []).append(record)
        return record

    def initialize(self):
        self.p.boot_task()
        self.checkpoint(0x10637d16, "native Z6II UI resource allocation")
        config = self.call("native mode2 image configuration", 0x103156e8,
                           bytes(12), [2, 0, ("scratch", 0)])
        self.call("native image memory initialization", 0x103033f0,
                  bytes.fromhex(config["output"]), [("scratch", 0)])
        self.checkpoint(0x10200190, "native boot-task idle")
        self.p.report["application_boot_checkpoint_reached"] = True
        self.dump("system-object", 0xc1818be0, 0x180)
        self.dump("input-report", 0xc1f7a720, 52)
        if self.stage == "boot":
            self.screenshot("boot-display")
            return
        self.initialize_application_inputs()

    def initialize_application_inputs(self):
        """Submit labeled application inputs after an existing native boot.

        An attached master does not restart either original engine or repeat
        image allocation. Its slave must be kept running by the coordinator.
        """
        self.call("112-byte synthetic power report", 0x103fbe1e,
                  bytes(112), [0x43090010, ("scratch", 0)])
        # Original1020e3a2 explicitly copies36 bytes for03040002; this
        # report's values are diagnostic fixtures derived from the Z6 donor.
        self.call("36-byte synthetic system state", 0x10204e30,
                  SYSTEM_REPORT, [0x03040002, ("scratch", 0)])
        # Original1043a1b2 is the GUI event-loop body, with the donor's
        # checkpoint at1026b558 corresponding to1043a1c2. Identity-checked
        # original calls1063717a/10637284/10637328 confirm the mapping.
        self.checkpoint(0x1043a1c2, "native GUI event loop before synthetic power input")
        self.state("before-power-input")
        report = bytearray(self.p.remote.memory(0xc1f7a720, 52))
        struct.pack_into("<I", report, 0, struct.unpack_from("<I", report)[0] | 0x200)
        self.call("synthetic power switch input", 0x1038dc0c,
                  bytes(report), [("scratch", 0)])
        self.checkpoint(0x10200190, "native boot-task idle after power input")
        # Compare consumers, not numeric IDs: donor02000001 dispatches to
        # state vtable+18 at1005c4c0. Z6II02000003 dispatches to that same
        # vtable slot at1020cbd8. Added Z6II IDs0/1 shifted this notification;
        #1020d590(02000001) is a different lifecycle event, not this donor call.
        self.call("native application state notification 02000003", 0x1020d5fa,
                  bytes(8), [0xc1818be0, 0])
        self.checkpoint(0x10200190, "native boot-task idle after application-ready")
        self.state("after-application-ready")
        if self.readiness_inputs:
            self.p.report["readiness_inputs"] = {
                "kind": "synthetic diagnostic controller and service inputs, not real hardware readiness",
                "controller_event": "0x04100007", "controller_report_first_byte": 7,
                "controller_event_evidence": "1020e422 subtracts04100000 then7; TBB entry0 at1020e43a goes1020e4f6",
                "controller_consumer": "0x1020f7c0 requires low3 bits set",
                "service_event": "0x05040016", "service_value": 0,
                "service_producer": "0x10698424", "service_consumer": "0x1020e0e8 -> 0x02000004",
                "readiness_bitmap_written_directly": False}
            self.call("synthetic controller low3 status bits via original callback", 0x10204e3c,
                      bytes([7]) + bytes(51), [0x04100007, ("scratch", 0)],
                      observers={0x1020f7c0: lambda remote, regs: None})
            self.call("synthetic service state via original GUI producer", 0x10698424,
                      bytes(8), [0])
            self.checkpoint(0x10200190, "native boot-task idle after diagnostic readiness inputs")
            self.call("native wait after diagnostic readiness inputs", 0x103dec94,
                      bytes(8), [200], observers={0x1020cc1c: lambda remote, regs: None,
                                                 0x1020cbde: lambda remote, regs: None})
            self.state("after-readiness-inputs")
        self.p.report["application_inputs_submitted"] = True

    def key(self, action_index, label):
        # Original10931030 action records specify the MENU bank/mask.
        words = [0, 0, 0, 0, 10, 0, 0, 0]
        words[action_index // 32] = 1 << (action_index % 32)
        payload = struct.pack("<8I", *words)
        c = self.call("native key action " + label, 0x1076b7fe, payload,
                      [("scratch", 0), 5, ("scratch", 20)])
        self.checkpoint(0x10200190, "native idle after " + label)
        return c

    def run(self):
        self.initialize()
        if self.stage == "boot":
            return
        if self.stage == "menu":
            self.key(67, "MENU")
            self.call("native wait for menu drawing", 0x103dec94, bytes(8), [1000])
            self.state("after-menu-drawing")
            self.memory_mapping("after-menu-drawing", [0xce8dff90, 0xce95ff90])
            self.screenshot("menu-action-display")
        elif self.stage == "lv":
            c = self.call("native StartLV", 0x1076a330, bytes(32),
                          [("scratch", 0), 0, ("scratch", 16)])
            self.p.report["startlv_action"] = c
            self.call("native wait for live-view", 0x103dec94, bytes(8), [1000])
            self.screenshot("startlv-action-display")
        elif self.stage == "movie":
            c = self.call("native movie-start action", 0x1076ab22, bytes(32),
                          [("scratch", 0), 0, ("scratch", 16)])
            self.p.report["movie_start_action"] = c
            self.call("native wait during movie", 0x103dec94, bytes(8), [1000])
            self.call("native movie-end action", 0x1076ab80, bytes(32),
                      [("scratch", 0), 0, ("scratch", 16)])
            self.screenshot("movie-action-display")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", default="application")
    parser.add_argument("--stage", choices=["boot", "menu", "lv", "movie"], default="boot")
    parser.add_argument("--readiness-inputs", action="store_true",
                        help="explicit diagnostic controller and GUI-service reports; no readiness bitmap override")
    args = parser.parse_args()
    app = Application(args.label, args.stage, args.readiness_inputs)
    try:
        app.run()
        app.p.report["requested_experiment_completed"] = True
    except Exception as e:
        app.p.report.update(error=str(e), traceback=traceback.format_exc(),
                            incomplete_fixture=guest_call.ACTIVE_FIXTURE)
    finally:
        app.p.close()


if __name__ == "__main__":
    main()
