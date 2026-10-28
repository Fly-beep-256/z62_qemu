"""Version-locked dual-engine diagnostics inside QEMU; no camera connection.

Native boot runs first. Every active call is explicitly recorded as a diagnostic
register/stack fixture and uses unchanged original ARM/Thumb instructions.
"""
import argparse
import hashlib
import json
import socket
import struct
import sys
import traceback

from host_env import ROOT, WORK
from probe_z6ii import Probe
import guest_call as fixture

PROFILES = {
    "master": {
        "state": 0xc1808930, "config": 0xc18aa50c,
        "queue": 0xc7ef0000, "peer": 0xc70f0000,
        "callbacks": 0xc1d19e48, "receiver": 0xc1d19e74,
        "configure": 0x1038a1e8, "initialize": 0x1038a210,
        "send": 0x1038a72e, "receive": 0x1038a38c,
        "register": 0x1038a86a, "mapper": 0x1038a4ec,
        "translate_config": 0x1038a572,
        "handshake": 0x1038a666,
        "hardware_initialize": 0x102e0a72,
        "service_table": 0xc18aedc8,
        "driver": 0x102df7c4, "return_callback": 0x1038a23a,
    },
    "slave": {
        "state": 0xc1006f68, "config": 0xc1014b98,
        "queue": 0xc70f0000, "peer": 0xc7ef0000,
        "callbacks": 0xc144f400, "receiver": 0xc144f42c,
        "configure": 0x10060ca0, "initialize": 0x10060cc8,
        "send": 0x100611e6, "receive": 0x10060e44,
        "register": 0x10061322, "mapper": 0x10060fa4,
        "translate_config": 0x1006102a,
        "handshake": 0x1006111e,
        "hardware_initialize": 0x1006c0c2,
        "service_table": 0xc1017e08,
        "driver": 0x1006ae14, "return_callback": 0x10060cf2,
    },
}


class Diagnostic:
    def __init__(self, role, label, protocol=False, shared_queue=None, coupled_notifications=False,
                 automatic_peer_irq=False, link_configuration=False,
                 coupled_gpio=False, gpio_connection=False, coupled_phy=False, coupled_stop=False,
                 coupled_lanes=False):
        self.p = Probe(role, label, protocol_diagnostic=protocol, shared_queue=shared_queue,
                       coupled_notifications=coupled_notifications, automatic_peer_irq=automatic_peer_irq,
                       link_configuration=link_configuration, coupled_gpio=coupled_gpio,
                       gpio_connection=gpio_connection, coupled_phy=coupled_phy, coupled_stop=coupled_stop,
                       coupled_lanes=coupled_lanes)
        self.profile = PROFILES[role]
        self.calls = self.p.report["diagnostic_calls"] = []
        self.p.report["diagnostic_scope"] = (
            "Original firmware routines called from a paused native RTOS task; "
            "synthetic register/stack inputs, no camera I/O or instruction patching. "
            "Not a claim of natural boot reaching these routines."
        )
        self.packet = None
        self.protocol = protocol

    def words(self, address, count):
        return list(struct.unpack("<" + "I" * count, self.p.remote.memory(address, count * 4)))

    def state(self, label):
        prof = self.profile
        data = {"label": label,
                "state_words": [hex(v) for v in self.words(prof["state"], 12)],
                "queue_header": self.p.remote.memory(prof["queue"], 24).hex(),
                "config_words": [hex(v) for v in self.words(prof["config"], 4)],
                "callback_words": [hex(v) for v in self.words(prof["callbacks"], 11)],
                "receiver_words": [hex(v) for v in self.words(prof["receiver"], 7)]}
        if prof["service_table"]:
            data["services"] = {hex(code): hex(self.words(prof["service_table"] + 4 * code, 1)[0])
                                for code in (0xe8, 0x151)}
        self.p.report.setdefault("protocol_state", []).append(data)
        print(json.dumps(data, ensure_ascii=False), flush=True)
        return data

    def call(self, name, function, arguments, payload=b"\0" * 16,
             thumb=True, observers=None):
        self.p.report["register_or_ram_fixture"] = True
        record = {"name": name, "function": hex(function), "completed": False}
        self.calls.append(record)
        original = self.p.blob[function - 0x10020000:function - 0x10020000 + 16]
        actual = self.p.remote.memory(function, 16)
        if len(original) != 16 or actual != original:
            raise AssertionError("Original instruction identity at diagnostic function")
        record.update(instruction_bytes=actual.hex(), original_instructions_verified=True)
        if observers:
            verified = []
            for address in observers:
                expected = self.p.blob[address - 0x10020000:address - 0x10020000 + 16]
                observed = self.p.remote.memory(address, 16)
                if len(expected) != 16 or observed != expected:
                    raise AssertionError("Original observer instruction identity")
                verified.append({"address": hex(address), "bytes": observed.hex(), "original_instructions_verified": True})
            record["observer_instructions"] = verified
        print(f"diagnostic {self.p.role}: {name} at {function:08x}", flush=True)
        try:
            result = fixture.call_fixture(self.p.remote, self.packet, function, payload,
                                          arguments, thumb=thumb, observers=observers)
        except socket.timeout:
            self.p.remote.sock.sendall(b"\x03")
            stopped = self.p.remote.receive()
            self.p.running = False
            self.p.snapshot("bounded diagnostic timeout", stopped)
            self.state("protocol state at diagnostic timeout")
            raise
        record.update(result, completed=True, register_context_restored=True)
        self.packet = "T05thread:" + result["return_cpu"] + ";"
        self.p.running = False
        print(json.dumps({"name": name, "return_r0": result["return_r0"],
                          "cpu": result["return_cpu"]}, ensure_ascii=False), flush=True)
        return result

    def write(self, name, address, data):
        """Record every explicit guest RAM fixture, including original bytes."""
        original = self.p.remote.memory(address, len(data))
        for offset in range(0, len(data), 2048):
            part = data[offset:offset + 2048]
            assert self.p.remote.command(f"M{address+offset:x},{len(part):x}:" + part.hex()) == "OK"
        assert self.p.remote.memory(address, len(data)) == data
        record = {"name": name, "address": hex(address), "bytes": len(data),
                  "before_sha256": hashlib.sha256(original).hexdigest(),
                  "after_sha256": hashlib.sha256(data).hexdigest(),
                  "scope": "QEMU guest RAM only; explicit synthetic diagnostic state"}
        if len(data) <= 64:
            record.update(before=original.hex(), after=data.hex())
        else:
            number = len(self.p.report.get("ram_fixtures", []))
            before, after = f"fixture-{number:03d}-before.bin", f"fixture-{number:03d}-after.bin"
            (self.p.directory / before).write_bytes(original)
            (self.p.directory / after).write_bytes(data)
            record.update(before_file=before, after_file=after)
        self.p.report.setdefault("ram_fixtures", []).append(record)
        self.p.report["register_or_ram_fixture"] = True

    def check(self, name, passed, evidence):
        self.p.report.setdefault("protocol_checks", []).append(
            {"name": name, "passed": bool(passed), "evidence": evidence})
        if not passed:
            raise AssertionError(name + ": " + json.dumps(evidence))

    def protocol_checks(self):
        prof = self.profile
        queue = prof["queue"]
        empty = self.p.remote.memory(queue, 0xc618)
        payload = struct.pack("<II", 0x12345678, 0x9abcdef0)
        result = self.call("reject send before peer header is cached", prof["send"],
                           [2, 0x64, len(payload), ("scratch", 0)], payload)
        self.check("unready send leaves local queue unchanged",
                   int(result["return_r0"], 16) == 0 and self.p.remote.memory(queue, 0xc618) == empty,
                   {"return_r0": result["return_r0"]})
        self.prepare_translation()
        mapped = int(self.p.report["mapped_peer_queue"], 16)
        for name, address, length, expected_result in [
            ("last byte within region zero", 0xcfffffff, 1, 0x4fffffff),
            ("range exceeds region zero", 0xcfffffff, 2, 0xffffffff),
            ("address precedes region zero", 0xbfffffff, 1, 0xffffffff)]:
            result = self.call(name, prof["mapper"], [0, address, length])
            self.check(name, int(result["return_r0"], 16) == expected_result,
                       {"return_r0": result["return_r0"], "expected": hex(expected_result)})
        # Handshake and physical transport are not implemented. Install only
        # the exact cached header/pointer fields that full native setup writes.
        self.write("peer pointer after diagnostic window translation", prof["state"] + 8,
                   struct.pack("<I", mapped))
        self.write("peer header cache fixture; hardware handshake remains absent", prof["state"] + 0x28,
                   self.p.remote.memory(queue, 8))
        result = self.call("native send eight-byte diagnostic message", prof["send"],
                           [2, 0x64, len(payload), ("scratch", 0)], payload)
        packet = self.p.remote.memory(queue + 24, 16)
        expected_packet = struct.pack("<IBBH", 0x64, 2, 0, len(payload)) + payload
        header = self.words(queue, 6)
        self.check("original sender produces exact message fields and payload",
                   int(result["return_r0"], 16) == 1 and packet == expected_packet and header[2] == 1,
                   {"return_r0": result["return_r0"], "packet": packet.hex(),
                    "expected_packet": expected_packet.hex(), "write_index": header[2]})
        for name, args, bytes_ in [
            ("reject message type eleven", [11, 0x65, 8, ("scratch", 0)], payload),
            ("reject 257-byte payload", [2, 0x65, 257, ("scratch", 0)], bytes(range(256)) + b"X"),
            ("reject null nonempty payload", [2, 0x65, 1, 0], b"\0" * 16)]:
            before = self.p.remote.memory(queue, 0xc618)
            result = self.call(name, prof["send"], args, bytes_)
            self.check(name, int(result["return_r0"], 16) == 0 and
                       self.p.remote.memory(queue, 0xc618) == before,
                       {"return_r0": result["return_r0"]})
        # Input is a byte-for-byte queue snapshot produced by original send.
        outgoing = self.p.remote.memory(queue, 0xc618)
        self.write("explicit outgoing-to-peer queue snapshot for receiver fixture", mapped, outgoing)
        observed = self.receive_observed(2)
        peer_header = self.words(mapped, 6)
        scratch = self.p.remote.memory(prof["receiver"] + 0x1c, 264)
        self.check("receiver callback gets exact sender packet; advances read pointer; clears scratch",
                   len(observed) == 1 and observed[0]["packet"] == expected_packet.hex()
                   and peer_header[4] == 1 and scratch == bytes(264),
                   {"callbacks": observed, "read_index": peer_header[4], "scratch_cleared": scratch == bytes(264)})
        self.state("after original send and receive diagnostics")
        self.ring_checks(mapped)

    def ring_checks(self, mapped):
        prof = self.profile
        queue = prof["queue"]
        # Set a near-wrap empty state without sending191uninteresting messages.
        # Native send/receive alone must perform192 ->0 index transitions.
        self.write("near-wrap empty queue cursors fixture", queue + 8, struct.pack("<II", 191, 0))
        self.write("near-wrap empty read cursor fixture", queue + 16, struct.pack("<II", 191, 0))
        counter = self.words(prof["state"] + 0xc, 1)[0]
        result = self.call("native sender wraps slot191 to zero", prof["send"],
                           [2, 0x660001, 0, 0])
        packet = self.p.remote.memory(queue + 24 + 191 * 264, 8)
        expected = struct.pack("<IBBH", 0x660001, 2, counter & 0xff, 0)
        self.check("sender ring wraps without changing pending packet",
                   int(result["return_r0"], 16) == 1 and self.words(queue + 8, 1)[0] == 0
                   and packet == expected,
                   {"packet": packet.hex(), "write_index_after": self.words(queue + 8, 1)[0]})
        self.write("near-wrap snapshot for native receiver", mapped, self.p.remote.memory(queue, 0xc618))
        observed = self.receive_observed(2)
        self.check("receiver ring wraps191 to zero", len(observed) == 1 and observed[0]["packet"] == expected.hex()
                   and self.words(mapped + 16, 1)[0] == 0,
                   {"callbacks": observed, "read_index_after": self.words(mapped + 16, 1)[0]})
        # Full means next_write==read. This checks original RTOS waits and
        # diagnostic counters, not just static arithmetic.
        self.write("full191-pending queue write cursor fixture", queue + 8, struct.pack("<II", 0, 0))
        self.write("full191-pending queue read cursor fixture", queue + 16, struct.pack("<II", 1, 0))
        before = self.p.remote.memory(queue, 0xc618)
        retries_before = self.words(prof["state"] + 0x1c, 1)[0]
        result = self.call("native full-queue bounded wait and rejection", prof["send"],
                           [2, 0x660002, 0, 0])
        retries = self.words(prof["state"] + 0x1c, 1)[0] - retries_before
        self.check("full queue is rejected after thirty native waits",
                   int(result["return_r0"], 16) == 0 and self.p.remote.memory(queue, 0xc618) == before
                   and retries == 30,
                   {"return_r0": result["return_r0"], "native_wait_count": retries})
        self.state("after ring-wrap and full-queue checks")

    def prepare_translation(self):
        prof = self.profile
        records, count = self.words(prof["config"] + 8, 2)
        result = self.call("native translation record initialization", prof["translate_config"],
                           [records, count])
        self.check("translation record initialization succeeds",
                   int(result["return_r0"], 16) == 1, {"return_r0": result["return_r0"]})
        result = self.call("map configured peer queue", prof["mapper"],
                           [0, prof["peer"], 0xc618])
        mapped = int(result["return_r0"], 16)
        expected = 0x470f0000 if self.p.role == "master" else 0x47ef0000
        self.check("native peer queue translation matches stored window", mapped == expected,
                   {"input": hex(prof["peer"]), "mapped": hex(mapped), "expected": hex(expected)})
        self.p.report["mapped_peer_queue"] = hex(mapped)
        return mapped

    def receive_observed(self, message_type=2, entry_function=None, entry_arguments=None, observers=None):
        prof = self.profile
        observed = []
        callback = prof["return_callback"]
        original_callback = self.p.remote.memory(callback, 2)
        self.check("diagnostic callback is original harmless BX LR", original_callback == b"\x70\x47",
                   {"address": hex(callback), "bytes": original_callback.hex()})
        current = self.words(prof["callbacks"] + message_type * 4, 1)[0]
        if current != callback | 1:
            result = self.call("register original return callback for diagnostic message type",
                               prof["register"], [message_type, callback | 1])
            self.check("native callback registration succeeds", int(result["return_r0"], 16) == 1,
                       {"return_r0": result["return_r0"], "message_type": message_type})

        def observe(remote, registers):
            pointer = int(registers["r0"], 16)
            packet_header = remote.memory(pointer, 8)
            length = struct.unpack_from("<H", packet_header, 6)[0]
            observed.append({"pointer": hex(pointer), "packet": remote.memory(pointer, 8 + length).hex()})

        previous_repeat = set(fixture.TRACE_REPEAT)
        fixture.TRACE_REPEAT.add(callback)
        try:
            self.call("native alternate entry observes receiver dispatch" if entry_function else
                      "native receiver copies packet and dispatches registered callback",
                      entry_function or prof["receive"],
                      [0] if entry_arguments is None else entry_arguments,
                      observers={**(observers or {}), callback: observe})
        finally:
            fixture.TRACE_REPEAT = previous_repeat
        return observed

    def start(self):
        event = self.p.boot_task()
        event = self.p.run_to(0x102000be if self.p.role == "master" else 0x10052ffa,
                             "native interrupt and application tables installed", thumb=True)
        self.packet = event["stop_reply"]
        self.state("native boot task before diagnostic calls")
        self.call("native protocol configuration and RTOS locks", self.profile["configure"],
                  [self.profile["config"]])
        self.state("after native protocol configuration")
        self.call("native protocol driver and outgoing queue initialization",
                  self.profile["initialize"], [])
        self.state("after native outgoing queue initialization")

    def run(self):
        self.start()
        if self.protocol:
            self.protocol_checks()
        self.p.report["diagnostic_completed"] = True

    def close(self):
        if fixture.ACTIVE_FIXTURE is not None:
            self.p.report["incomplete_fixture"] = fixture.ACTIVE_FIXTURE
        self.p.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=PROFILES, default="master")
    parser.add_argument("--label", default="dual-diagnostic")
    parser.add_argument("--protocol", action="store_true",
                        help="enable explicit peer snapshot and event-register hypotheses")
    parser.add_argument("--handshake-probe", action="store_true",
                        help="record native full-handshake dependencies or first unmodeled access")
    parser.add_argument("--hardware-init-probe", action="store_true",
                        help="call original role-specific hardware initializer and record boundary")
    args = parser.parse_args()
    d = Diagnostic(args.role, args.label, args.protocol)
    try:
        if args.handshake_probe:
            d.start()
            points = ([0x102e0e3e, 0x102e0e2e, 0x1035d37a]
                      if args.role == "master" else [])
            observed = []
            def observe(remote, registers):
                observed.append(dict(registers))
            d.p.report["handshake_observations"] = observed
            d.call("original full handshake dependency probe",
                   d.profile["handshake"], [], observers={a: observe for a in points})
            d.p.report["handshake_call_returned"] = True
        elif args.hardware_init_probe:
            d.start()
            handle = d.words(d.profile["state"] + 4, 1)[0]
            config_role = d.words(d.profile["config"], 1)[0]
            d.call("original role-specific hardware initializer boundary",
                   d.profile["hardware_initialize"], [handle, 0 if config_role else 1,
                                                       1 if config_role else 0, 1])
            d.p.report["hardware_initialize_call_returned"] = True
        else:
            d.run()
    except Exception as error:
        d.p.report["error"] = str(error)
        d.p.report["traceback"] = traceback.format_exc()
    finally:
        d.close()
    if d.p.report.get("error"):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
