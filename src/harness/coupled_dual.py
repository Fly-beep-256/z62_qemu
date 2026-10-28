"""Two original Z6II engines using run-local shared queue RAM, without copies.

This is a bounded protocol diagnostic: original RTOS boot, original sender and
receiver, explicit cached-header/pointer and return-callback fixtures. Native
handshake, interrupt delivery, cache coherency and camera startup remain unknown.
The backing is newly created for each run; it contains no factory configuration.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import struct
import subprocess
import time
import traceback

from diagnose_dual import Diagnostic
from host_env import ROOT, WORK

OUT = ROOT / "outputs/Z6II双EXPEED6分析/QEMU运行/共享互连接续"
MAGIC = b"Z6II-QUEUE-v1\0\0\0"
HEADER_SIZE, STRIDE, WINDOW, QUEUE_BYTES = 0x10000, 0x10000, 0xD000, 0xC618
SHAS = {
    "master": "bb83613121f843d65101da936d942acdc513d86dbd3abc26259d0d870d03f5d4",
    "slave": "3fd8c2cbdf57fadb03f6d69b596b58a8703efdd61ae82572d5afeea0241a9ed5",
}
NOTIFY = {
    "master": {"isr": 0x102DF730, "callback": 0x1038A488, "register": 0x102E0A6C,
               "enable_irq": 0x103A2A88, "bank_write": 0x102E11A0, "delay": 0x103DEC94},
    "slave": {"isr": 0x1006AD80, "callback": 0x10060F40, "register": 0x1006C0BC,
              "enable_irq": 0x10066B2C, "bank_write": 0x1006C7F0, "delay": 0x1006CC58},
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def create_backing(path, notifications=False, gpio=False, wire=False, phy=False, stop=False, lanes=False):
    assert STRIDE % os.sysconf("SC_PAGE_SIZE") == 0
    assert not gpio or notifications
    assert not wire or gpio
    assert not phy or wire
    assert not stop or phy
    assert not lanes or stop
    flags = int(gpio) | (int(wire) << 1) | (int(phy) << 2) | (int(stop) << 3) | (int(lanes) << 4)
    version = 3 if gpio else 2 if notifications else 1
    magic = b"Z6II-QUEUE-v3\0\0\0" if gpio else b"Z6II-QUEUE-v2\0\0\0" if notifications else MAGIC
    header = (magic + struct.pack("<IIII", version, WINDOW, STRIDE, 2) +
              SHAS["master"].encode() + SHAS["slave"].encode() + secrets.token_hex(16).encode())
    assert len(header) == 192
    if gpio:
        # V1/V2 keep their exact layout/behavior. V3 explicitly identifies
        # GPIO and optional wire/PHY hypotheses in unmapped transport metadata.
        header += struct.pack("<I", flags)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.ftruncate(fd, HEADER_SIZE + (3 if notifications else 2) * STRIDE)
        assert os.pwrite(fd, header, 0) == len(header)
        os.fsync(fd)
    finally:
        os.close(fd)
    data = path.read_bytes()
    assert data[len(header):] == bytes(len(data) - len(header))
    return {"path": str(path), "new_exclusive_file": True, "initial_sha256": digest(data),
            "header_sha256": digest(data[:HEADER_SIZE]), "bytes": len(data),
            "host_page_size": os.sysconf("SC_PAGE_SIZE"), "guest_window_bytes": WINDOW,
            "guest_queue_bytes": QUEUE_BYTES, "slot_stride": STRIDE,
            "camera_persistent_input": False, "run_nonce": header[160:192].decode(),
            "layout_version": version, "interconnect_hypothesis_flags": flags,
            "shared_event_control_offset": 0x30000 if notifications else None}


def negative_start_checks(backing, directory, report):
    manifest = json.loads((WORK / "z6ii/build-manifest.json").read_text())
    binary = Path(manifest["binary"])
    assert digest(binary.read_bytes()) == manifest["binary_sha256"]
    model_name = "nikon-z6ii-master-coupled" + ("-notify" if report["notifications"] else "")
    variants = []
    for name, mutate in [
        ("header", lambda d: d.__setitem__(slice(0, 16), b"X" * 16)),
        ("firmware_identity", lambda d: d.__setitem__(32, ord("0"))),
        ("size", lambda d: d.pop()),
        ("permission", lambda d: None),
    ]:
        path = directory / ("negative-" + name + ".bin")
        data = bytearray(backing.read_bytes())
        mutate(data)
        with path.open("xb") as f:
            f.write(data)
        path.chmod(0o644 if name == "permission" else 0o600)
        variants.append((name, model_name, path, "master"))
    link = directory / "negative-symlink.bin"
    link.symlink_to(backing.name)
    variants.extend([
        ("symlink", model_name, link, "master"),
        ("wrong_role", model_name, backing, "slave"),
        ("missing_path", model_name, None, "master"),
        ("non_coupled_model", "nikon-z6ii-master-protocol", backing, "master"),
    ])
    for name, model, path, role in variants:
        env = dict(os.environ)
        env.pop("Z6II_QUEUE_BACKING", None)
        env.pop("Z6II_QUEUE_ROLE", None)
        env.pop("Z6II_LINK_TEST_PEER", None)
        env.pop("Z6II_QUEUE_AUTO_IRQ", None)
        env.pop("Z6II_LINK_CONFIGURATION", None)
        for key in ("Z6II_COUPLED_GPIO", "Z6II_GPIO_CONNECTION", "Z6II_COUPLED_PHY", "Z6II_COUPLED_STOP", "Z6II_COUPLED_LANES"):
            env.pop(key, None)
        if path is not None:
            env["Z6II_QUEUE_BACKING"] = str(path)
        env["Z6II_QUEUE_ROLE"] = role
        command = [str(binary), "-M", model, "-smp", "2", "-S", "-display", "none",
                   "-nodefaults", "-nic", "none", "-bios", str(ROOT / "inputs/firmware/master-original-with-crc.bin")]
        result = subprocess.run(command, env=env, capture_output=True, timeout=10)
        stderr = result.stderr.decode(errors="replace")
        (directory / ("negative-" + name + ".log")).write_text(stderr)
        passed = result.returncode != 0 and ("backing identity/layout/ownership mismatch" in stderr or
                 "require an absolute backing path and matching role" in stderr or
                 "restricted to explicit coupled machine models" in stderr)
        report["checks"].append({"name": "reject_" + name, "passed": passed,
                                 "returncode": result.returncode, "log": "negative-" + name + ".log"})
        assert passed, name


class Exchange:
    def __init__(self, engines, report):
        self.engines, self.report = engines, report
        self.identifier = 0x640000

    def check(self, name, passed, **evidence):
        self.report["checks"].append(dict(name=name, passed=bool(passed), **evidence))
        assert passed, name

    def send(self, source, payload):
        target = "slave" if source == "master" else "master"
        sender, receiver = self.engines[source], self.engines[target]
        queue = sender.profile["queue"]
        cursor = sender.words(queue + 8, 1)[0]
        counter = sender.words(sender.profile["state"] + 0xC, 1)[0]
        self.identifier += 1
        result = sender.call("native sender into shared queue", sender.profile["send"],
                             [2, self.identifier, len(payload), ("scratch", 0)], payload or bytes(16))
        expected = struct.pack("<IBBH", self.identifier, 2, counter & 0xFF, len(payload)) + payload
        self.check("native_send_accepted", int(result["return_r0"], 16) == 1,
                   source=source, identifier=hex(self.identifier))
        local = sender.p.remote.memory(queue, QUEUE_BYTES)
        mapped = int(receiver.p.report["mapped_peer_queue"], 16)
        peer = receiver.p.remote.memory(mapped, QUEUE_BYTES)
        self.check("peer_sees_native_write_without_copy", local == peer and
                   local[24 + 264 * cursor:24 + 264 * cursor + len(expected)] == expected and
                   sender.words(queue + 8, 1)[0] == (cursor + 1) % 192,
                   source=source, identifier=hex(self.identifier), write_before=cursor,
                   local_sha256=digest(local), peer_sha256=digest(peer))
        event = {"source": source, "target": target, "identifier": hex(self.identifier),
                 "payload_bytes": len(payload), "payload_sha256": digest(payload), "packet": expected.hex(),
                 "write_index_before": cursor, "counter": counter & 0xFF,
                 "host_queue_copy": False, "host_read_cursor_copy": False,
                 "original_sender_executed": True, "original_receiver_executed": False}
        self.report["messages"].append(event)
        if self.report["notifications"]:
            self.check("sender_bank0_matches_peer_bank1", sender.words(0x20136004, 1)[0] == 1 and
                       receiver.words(0x2013E004, 1)[0] == 1 and receiver.words(0x2013D020, 1)[0] == 0x8000,
                       source=source, target=target)
        return event

    def receive(self, target, expected, resume_with_unmask=False):
        source = "slave" if target == "master" else "master"
        receiver, sender = self.engines[target], self.engines[source]
        irq_observed = []
        isr_entries = []
        if self.report["notifications"]:
            prof = NOTIFY[target]
            def observe_irq(remote, regs):
                irq_observed.append({"r0": regs["r0"], "r1": regs["r1"]})
            def observe_isr(remote, regs):
                isr_entries.append(dict(regs))
            if self.report["automatic_GIC_delivery"]:
                observed = receiver.receive_observed(2, entry_function=prof["bank_write"] if resume_with_unmask else prof["delay"],
                                                      entry_arguments=[0x2013D024, 1, 0x8000] if resume_with_unmask else [1],
                                                      observers={prof["callback"]: observe_irq, prof["isr"]: observe_isr})
            else:
                observed = receiver.receive_observed(2, entry_function=prof["isr"], entry_arguments=[],
                                                      observers={prof["callback"]: observe_irq})
            expected_irq_calls = 0 if self.report["automatic_GIC_delivery"] and not expected else 1
            self.check("native_ISR_passes_irq127_and_expected_status", len(irq_observed) == expected_irq_calls and
                       all(int(v["r0"], 16) == 127 and int(v["r1"], 16) == (0x8000 if expected else 0)
                           for v in irq_observed),
                       target=target, observations=irq_observed)
            if self.report["automatic_GIC_delivery"]:
                self.check("automatic_native_ISR_entry_observed_without_ISR_call_fixture",
                           len(isr_entries) == expected_irq_calls, target=target, entries=isr_entries)
            self.check("native_callback_clears_peer_event_and_link_status",
                       sender.words(0x20136004, 1)[0] == 0 and receiver.words(0x2013E004, 1)[0] == 0 and
                       receiver.words(0x2013D020, 1)[0] == 0, target=target)
        else:
            observed = receiver.receive_observed(2)
        self.check("native_receiver_dispatches_exact_ordered_packets",
                   [v["packet"] for v in observed] == [v["packet"] for v in expected],
                   source=source, target=target, packets=len(observed))
        queue = sender.profile["queue"]
        mapped = int(receiver.p.report["mapped_peer_queue"], 16)
        self.check("receiver_ack_visible_at_sender_without_copy",
                   sender.p.remote.memory(queue + 16, 8) == receiver.p.remote.memory(mapped + 16, 8) and
                   sender.words(queue + 16, 1)[0] == sender.words(queue + 8, 1)[0],
                   source=source, read_index=sender.words(queue + 16, 1)[0])
        for event, callback in zip(expected, observed):
            event.update(callback=callback, original_receiver_executed=True)
            if self.report["notifications"]:
                event.update(original_ISR_executed=True, ISR_entry_is_diagnostic_fixture=True,
                             native_ISR_arguments=irq_observed, physical_camera_IRQ_observed=False)
                if self.report["automatic_GIC_delivery"]:
                    event.update(ISR_entry_is_diagnostic_fixture=False, simulated_hardware_IRQ_delivered=True,
                                 timing_is_functional_polling_hypothesis=True, native_ISR_entries=isr_entries)
        return observed

    def reject(self, source, name, arguments, payload):
        d = self.engines[source]
        before = d.p.remote.memory(d.profile["queue"], QUEUE_BYTES)
        result = d.call(name, d.profile["send"], arguments, payload)
        self.check(name, int(result["return_r0"], 16) == 0 and
                   d.p.remote.memory(d.profile["queue"], QUEUE_BYTES) == before,
                   source=source, return_r0=result["return_r0"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", default="shared-queues")
    parser.add_argument("--quick", action="store_true", help="skip capacity/wrap stress; retain basic and negative checks")
    parser.add_argument("--notifications", action="store_true", help="opt-in peer event-bank model; explicit native ISR entry, no GIC injection")
    parser.add_argument("--auto-irq", action="store_true", help="opt-in functional 1us polling to GIC; native IRQ entry instead of ISR call fixture")
    parser.add_argument("--link-configuration", action="store_true", help="opt-in observed link register latches alongside shared notifications")
    args = parser.parse_args()
    if args.auto_irq and not args.notifications:
        parser.error("--auto-irq requires --notifications")
    directory = OUT / (time.strftime("%Y%m%d-%H%M%S") + "-" + args.label)
    directory.mkdir(parents=True, exist_ok=False)
    backing = directory / "ephemeral-queues.bin"
    report = {"camera_access": False, "instruction_bytes_modified": False, "passed": False,
              "mode": "two original firmware guests; run-local MAP_SHARED queue transport",
              "natural_handshake_completed": False, "peer_irq_emulated": args.auto_irq,
              "electrical_interconnect_emulated": False, "cache_coherency_emulated": False,
              "full_boot": False, "normal_menu": False, "continuous_liveview": False,
              "original_movie_file": False, "real_factory_TEMP": False,
              "checks": [], "messages": [], "quick": args.quick, "notifications": args.notifications,
              "native_ISR_entry_is_diagnostic_fixture": args.notifications and not args.auto_irq,
              "automatic_GIC_delivery": args.auto_irq, "functional_poll_period_ns": 1000 if args.auto_irq else None,
              "link_configuration_latches": args.link_configuration,
              "global_lockstep": False, "physical_latency_known": False}
    engines = {}
    try:
        report["backing"] = create_backing(backing, args.notifications)
        header_before = backing.read_bytes()[:HEADER_SIZE]
        negative_start_checks(backing, directory, report)
        for role in ("master", "slave"):
            d = engines[role] = Diagnostic(role, args.label, protocol=True, shared_queue=backing,
                                          coupled_notifications=args.notifications, automatic_peer_irq=args.auto_irq,
                                          link_configuration=args.link_configuration)
            report[role] = {"probe_directory": str(d.p.directory), "pid": d.p.process.pid,
                            "build_sha256": d.p.manifest["binary_sha256"],
                            "original_firmware_sha256": digest(d.p.blob)}
            assert digest(d.p.blob) == SHAS[role]
            d.start()
            d.prepare_translation()
        x = Exchange(engines, report)
        for role, d in engines.items():
            x.reject(role, "unready_peer_remains_rejected", [2, 0x640000, 1, ("scratch", 0)], b"X")
            other = engines["slave" if role == "master" else "master"]
            mapped = int(d.p.report["mapped_peer_queue"], 16)
            x.check("other_native_queue_header_already_visible", d.p.remote.memory(mapped, 24) ==
                    other.p.remote.memory(other.profile["queue"], 24), role=role)
            d.write("cached peer pointer fixture; natural physical handshake is absent",
                    d.profile["state"] + 8, struct.pack("<I", mapped))
            d.write("cache actual peer initialized header; no queue transport copy",
                    d.profile["state"] + 0x28, d.p.remote.memory(mapped, 8))
            if args.notifications:
                handle = d.words(d.profile["state"] + 4, 1)[0]
                prof = NOTIFY[role]
                d.call("original hardware driver callback registration; full handshake remains absent",
                       prof["register"], [handle, prof["callback"] | 1])
                x.check("original_driver_uses_queue_ISR_callback", d.words(handle + 8, 1)[0] == prof["callback"] | 1,
                        role=role, handle=hex(handle))
                if args.auto_irq:
                    d.call("original message callback registration before any automatic interrupt",
                           d.profile["register"], [2, d.profile["return_callback"] | 1])
                    d.call("original IRQ127 enable helper; diagnostic arguments", prof["enable_irq"], [127, -1 & 0xFFFFFFFF])
                    d.call("original register-store helper unmasks only queue status bit15; diagnostic arguments",
                           prof["bank_write"], [0x2013D024, 1, 0x8000])
                    x.check("original_GIC_IRQ127_enable_and_link_mask_readback",
                            bool(d.words(0x2C00110C, 1)[0] & 0x80000000) and d.words(0x2013D024, 1)[0] == 0x8000,
                            role=role, gic_enable=hex(d.words(0x2C00110C, 1)[0]))
        # Audit mapping identity without modifying any used queue payload/header.
        for role, d in engines.items():
            other = engines["slave" if role == "master" else "master"]
            queue, offset = d.profile["queue"], QUEUE_BYTES + 8
            mapped = int(other.p.report["mapped_peer_queue"], 16)
            saved = d.p.remote.memory(queue + offset, 8)
            opposite_before = other.p.remote.memory(other.profile["queue"] + offset, 8)
            sentinel = b"MAS-TEST" if role == "master" else b"SLA-TEST"
            d.write("shared-mapping identity probe in unused queue padding", queue + offset, sentinel)
            x.check("only_correct_peer_slot_aliases_local_queue", other.p.remote.memory(mapped + offset, 8) == sentinel and
                    other.p.remote.memory(other.profile["queue"] + offset, 8) == opposite_before, role=role)
            d.write("restore unused queue padding mapping probe", queue + offset, saved)
            private = d.profile["receiver"] + 0x80
            other_private = other.profile["receiver"] + 0x80
            saved_private = d.p.remote.memory(private, 8)
            other_before = other.p.remote.memory(other_private, 8)
            d.write("temporary private RAM isolation probe; restored while both guests paused", private, sentinel)
            x.check("engine_private_RAM_remains_independent", other.p.remote.memory(other_private, 8) == other_before, role=role)
            d.write("restore private RAM isolation probe", private, saved_private)
        for role, payload in [("master", b"MASTER_TO_SLAVE\0\x01"), ("slave", b"SLAVE_TO_MASTER\0\x02"),
                              ("master", bytes(range(256))), ("slave", b"")]:
            event = x.send(role, payload)
            if args.notifications and not args.auto_irq:
                d = engines[event["target"]]
                mapped = int(d.p.report["mapped_peer_queue"], 16)
                for irq, status in [(126, 0x8000), (127, 0)]:
                    before = d.p.remote.memory(mapped + 16, 8)
                    d.call("original callback rejects wrong IRQ or missing bit15", NOTIFY[event["target"]]["callback"], [irq, status])
                    x.check("invalid_notification_does_not_drain_queue", d.p.remote.memory(mapped + 16, 8) == before,
                            irq=irq, status=hex(status), target=event["target"])
            x.receive(event["target"], [event])
            print(json.dumps({"stage": "basic", "source": role, "bytes": len(payload), "passed": True}), flush=True)
        for role in engines:
            x.reject(role, "reject_type_eleven", [11, 0x64, 8, ("scratch", 0)], bytes(8))
            x.reject(role, "reject_257_bytes", [2, 0x64, 257, ("scratch", 0)], bytes(range(256)) + b"X")
            x.reject(role, "reject_nonempty_null_payload", [2, 0x64, 1, 0], bytes(16))
        if args.auto_irq:
            for source in engines:
                target = "slave" if source == "master" else "master"
                d = engines[target]
                prof = NOTIFY[target]
                d.call("original register-store helper masks simulated queue IRQ", prof["bank_write"], [0x2013D024, 1, 0])
                event = x.send(source, b"MASKED_PENDING_EVENT")
                mapped = int(d.p.report["mapped_peer_queue"], 16)
                cursor_before = d.p.remote.memory(mapped + 16, 8)
                isr = []
                def record_masked(remote, regs):
                    isr.append(dict(regs))
                observed = d.receive_observed(2, entry_function=prof["delay"], entry_arguments=[1],
                                               observers={prof["isr"]: record_masked})
                x.check("masked_event_remains_pending_without_ISR_or_queue_drain", observed == [] and isr == [] and
                        d.p.remote.memory(mapped + 16, 8) == cursor_before and d.words(0x2013E004, 1)[0] == 1,
                        target=target)
                x.receive(target, [event], resume_with_unmask=True)
        if not args.quick:
            for role, d in engines.items():
                pending = []
                for n in range(191):
                    pending.append(x.send(role, struct.pack("<II", n, n ^ 0x5A5A1234)))
                    if n % 16 == 0:
                        print(json.dumps({"stage": "capacity", "source": role, "pending": n + 1}), flush=True)
                x.reject(role, "native_191_slot_full_queue_rejected", [2, 0x64, 8, ("scratch", 0)], bytes(8))
                target = "slave" if role == "master" else "master"
                x.receive(target, pending)
                last = x.send(role, b"AFTER_FULL_DRAIN")
                x.receive(target, [last])
                x.check("native_cursor_wrapped_without_host_cursor_fixture",
                        any(e["write_index_before"] == 191 for e in report["messages"] if e["source"] == role), role=role)
                x.receive(target, [])
        for role, d in engines.items():
            d.state("after original shared queue exchange")
            d.p.report["diagnostic_completed"] = True
            x.check("no_queue_or_cursor_transport_RAM_fixture", all(
                not (d.profile["queue"] <= int(f["address"], 16) < d.profile["queue"] + QUEUE_BYTES or
                     int(d.p.report["mapped_peer_queue"], 16) <= int(f["address"], 16) <
                     int(d.p.report["mapped_peer_queue"], 16) + QUEUE_BYTES)
                for f in d.p.report.get("ram_fixtures", [])), role=role)
            report[role]["event_latches_local_only"] = [hex(d.words(a + 4, 1)[0]) for a in (0x20136000, 0x2013E000)]
            (directory / (role + "-queue-final.bin")).write_bytes(d.p.remote.memory(d.profile["queue"], QUEUE_BYTES))
        final = backing.read_bytes()
        x.check("transport_header_unmodified", final[:HEADER_SIZE] == header_before)
        x.check("both_queue_stride_tails_unmapped_unmodified", all(
            final[HEADER_SIZE + slot * STRIDE + WINDOW:HEADER_SIZE + (slot + 1) * STRIDE] == bytes(STRIDE - WINDOW)
            for slot in (0, 1)))
        report["backing"]["final_sha256"] = digest(final)
        report["passed"] = True
    except Exception as error:
        report.update(error=str(error), traceback=traceback.format_exc())
    finally:
        for role, d in engines.items():
            d.close()
            report[role]["owned_process_exit_code"] = d.p.process.poll()
        report["all_owned_QEMU_exited"] = all(d.p.process.poll() is not None for d in engines.values())
        (directory / "结果.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        print(json.dumps({"output": str(directory), "passed": report["passed"], "messages": len(report["messages"]),
                          "checks": len(report["checks"]), "error": report.get("error")}, ensure_ascii=False), flush=True)
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
