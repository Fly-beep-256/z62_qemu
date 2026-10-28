# SPDX-License-Identifier: GPL-2.0-or-later
"""One owner for the native five-CPU QEMU, its debugger, and virtual deadlines.

This entry point consumes the existing coordinator recipes; it never executes
their old runner commands. E6 CPU0/1 and CPU2/3 retain separate memory domains;
CPU4 enters the original MCU reset vector. Debugger reads always select a real
discovered global thread. No pmemsave, RAM replay, register writes, callbacks,
or nonce bridge are used.

Runtime QOM contracts: /machine virtual-time-ns is an integer;
architecture-state is a JSON string containing actual cpus/domains/gics.
Shared RAM identities belong to each E6 domain's shared_apertures. Private
RAM and MCU local reset observations are separate, required evidence items.
Missing evidence stays unverified.
PA reads require the manifest-frozen CPU-aware Qqemu.PhyMemMode implementation;
otherwise only VA reads are used. External input ACKs do not certify MENU.
"""
import argparse
import copy
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import select
import socket
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True
from host_env import ROOT, WORK, environment
from run_evidence import ProcessLedger, identity, save_json
from debugger_byte_ledger import ByteLedger, audited_qmp, audited_remote
from meaningful_qemu_log import MeaningfulQemuLog
from firmware_constants import BASE as MCU_BASE, RAM as MCU_RAM, RAM_SIZE, INPUT, EXPECTED_SHA

sys.path.insert(0, str(WORK / "tools"))
from interactive import QMP, free_port
from rsp import Remote

ENTRY = 0x10020000
CPU_ROLES = {0: ("master", 0), 1: ("master", 1),
             2: ("slave", 0), 3: ("slave", 1), 4: ("MCU", 0)}
ROLE_CPU = {"master": 0, "slave": 2, "MCU": 4}
MACHINE = "nikon-z6ii-native"
SAISO_FINAL_SAMPLES = (
    (0xc253dc28, 12, "properties_180x"),
    (0xc253dc68, 4, "property_1810"),
    (0xc253d850, 0x228, "AE_state"),
    (0xc253e230, 0x138, "gate_state"),
    (0xc1876508, 0x30, "publish_state"),
    (0xc1875350, 0x68, "workspace"),
    (0xc181d9e4, 0xe4, "APPLV_state"),
    (0xc185f484, 0x38, "AESEF_request_control"),
    (0xc20f29d4, 0x2c, "AESEF_task_owner"),
    (0xc1887cb0, 0x80, "AE_qualification_owner"),
    (0xc25dad24, 0x40, "AE_request_queues"),
    (0xc25db174, 4, "AE_mask80_claim"),
    (0xc20f4008, 0x40, "AESEF_work_state"),
    (0xc20f2a00, 488, "AE_default_input"),
    # Additional declared DDR reads at the same final common stop.  These
    # distinguish a V marker from downstream readiness and one-shot consume.
    (0xc23e2d30, 0x80, "V_readiness"),
    (0xc23e2b7c, 0x20, "W_request"),
    (0xc1868a70, 0x100, "shooting_state"),
    (0xc23e2404, 0x40, "callback_registry"),
    (0xc18694b0, 0xa0, "V_start_time_gates"),
    (0xc25784a8, 4, "property_3C06"),
    (0xc2574f80, 0x20, "saved_V_property_record"),
)
BOOT_TASK_PCS = (0x10200034, 0x10200042, 0x10052f74, 0x10052f7e)


def utc():
    return datetime.now(timezone.utc).isoformat()


def path(value, run=None):
    value = str(value).replace("@RUN@", str(run or ROOT))
    p = Path(value)
    return (p if p.is_absolute() else ROOT / p).resolve()


def read_json(p):
    return json.loads(Path(p).read_text())


def error_text(exc):
    return type(exc).__name__ + ": " + str(exc)


def resolve_thread_identity(tid, extra_info, cpus, clusters, qom_cpus):
    """Map a discovered thread by QEMU's reported CPU identity, never its TID.

    In multiprocess mode QEMU reports the CPU QOM type and canonical path
    component; in single-process mode it reports CPU#<global cpu_index>.
    The inferior is cross-checked against the actual CPUCluster ancestry.
    MPIDR is an E6 QOM observation, not a required raw GDB register. Cortex-M
    has no architectural MPIDR; its QOM mp_affinity is deliberately ignored.
    """
    match = re.fullmatch(r"p([0-9a-f]+)\.([0-9a-f]+)", tid)
    if match is None:
        raise ValueError("Expected an actual multiprocess GDB thread: " + tid)
    inferior = int(match[1], 16)
    owners = [c for c in clusters if c.get("gdb_pid") == inferior]
    if len(owners) != 1:
        raise ValueError("Thread inferior does not identify one actual QOM cluster")
    cluster = owners[0]
    members = [c for c in cpus if c.get("qom-path", "").startswith(cluster["path"] + "/")]
    state = {c.get("global_cpu_index"): c for c in qom_cpus}
    global_match = re.fullmatch(r"CPU#([0-9]+) \[(?:halted\s*|running)\]", extra_info)
    component_match = re.fullmatch(r"(\S+) (\S+) \[(?:halted\s*|running)\]", extra_info)
    if global_match:
        candidates = [c for c in members if c.get("cpu-index") == int(global_match[1])]
        basis = "qThreadExtraInfo actual global CPU index"
    elif component_match:
        model, component = component_match.groups()
        candidates = [c for c in members if c.get("qom-path", "").rsplit("/", 1)[-1] == component
                      and state.get(c.get("cpu-index"), {}).get("cpu_type") == model]
        basis = "qThreadExtraInfo actual CPU QOM type/component + inferior QOM ancestry"
    else:
        raise ValueError("Unrecognized actual qThreadExtraInfo CPU identity: " + extra_info)
    if len(candidates) != 1:
        raise ValueError("Actual thread extra info does not uniquely match a QMP/QOM CPU")
    query = candidates[0]
    cpu = query["cpu-index"]
    if cpu not in CPU_ROLES:
        raise ValueError("Thread reports a CPU outside the five-core native contract")
    role, local = CPU_ROLES[cpu]
    actual = state.get(cpu, {})
    if (actual.get("qom_path") != query["qom-path"] or actual.get("role") != role
            or actual.get("local_cpu") != local
            or actual.get("QEMU_cluster_index") != cluster.get("cluster_id")):
        raise ValueError("QMP CPU, QOM engine role and cluster identity disagree")
    mpidr = actual.get("MPIDR") if role != "MCU" else None
    if role != "MCU" and (type(mpidr) is not int or mpidr < 0 or (mpidr & 0xffffff) != local):
        raise ValueError("Actual E6 QOM MPIDR disagrees with its local core")
    return {"global_cpu": cpu, "qom_path": query["qom-path"], "thread": tid,
            "cluster": cluster, "role": role, "local_cpu": local,
            "RSP_extra_info": extra_info, "actual_MPIDR": mpidr,
            "MPIDR_source": "QOM architecture-state E6 CPU" if role != "MCU" else None,
            "guest_MPIDR_instruction_read_verified": False,
            "MCU_architectural_MPIDR_claimed": False,
            "basis": basis + "; no fixed TID arithmetic"}


class Recipe:
    """Strict option reader: unknown/replay options cannot silently disappear."""
    def __init__(self, argv, flags, values, repeated=()):
        self.data = {}
        i = 0
        while i < len(argv):
            token = argv[i]
            name, sep, attached = token.partition("=")
            if name in flags:
                if sep or name in self.data:
                    raise ValueError("Duplicate or valued flag: " + token)
                self.data[name] = True
                i += 1
            elif name in values or name in repeated:
                if not sep:
                    i += 1
                    if i >= len(argv) or argv[i].startswith("--"):
                        raise ValueError("Missing recipe value: " + name)
                    attached = argv[i]
                if name in repeated:
                    self.data.setdefault(name, []).append(attached)
                else:
                    if name in self.data:
                        raise ValueError("Duplicate recipe option: " + name)
                    self.data[name] = attached
                i += 1
            else:
                raise ValueError("Unsupported native recipe option (not executed): " + token)

    def get(self, name, default=None):
        return self.data.get("--" + name, default)

    def integer(self, name, default):
        return int(str(self.get(name, default)), 0)


BASE_FLAGS = set("""integrated peer-buffer-section peer-data-section peer-dma-section
slave-dma-section peer-parameter-section peer-business-trace-only peer-parameter-trace
display-config-trace quiet-observers slave-2b20-control-latch slave-fill-channel1
master-fill-channel1 slave-access-ready-line parameter-require-recorded-body
expeed-byte-ledger stop-both-before-snapshot boot-tcg-trace graphics-capture
qemu-exception-trace source50-tcg-trace master-persistent-output""".split())
BASE_VALUES = set("""seconds label output-dir qemu-build-manifest icount-shift
shared-event-poll-ns slave-pipeline-mode slave-sdhci-mode slave-filesystem
slave-card-capacity-mib master-persistent-input slave-persistent-input
parameter-source-reference-spec loader-runtime-reference-spec task-observation-plan
lcd-snapshot-interval mcu-wire-path mcu-wire-poll-ns mcu-wire-known-wait-ms
ui-observation-plan""".split())
MCU_FLAGS = set("""observe battery-config-trace battery-task-trace gpio-masked-readpin
i2c-max77711 without-hse without-lse debug-warp-audit flash-request-trace""".split())
MCU_VALUES = set("""label output-dir manifest seconds i2c-bus i2c-slave pcal-pin-levels
adc-vref-mv flash-mode flash-vdd-mv flash-nwrp flash-erase-ns flash-program-ns
nvic-write-trace debug-clock-guard pcal-host-input-file gpio-host-input-file
usart1-battery-spec usart1-peer-max-replies usart1-battery-clock rtc-retained
rtc-backup-input""".split())
MCU_REPEATED = set("""observe-address i2c-absent-address gpio-pin-levels
gpio-pin-known-mask adc-channel-mv rng-public-word pcal-pin-event""".split())


def recipes(baseline_file, mcu_file):
    baseline, mcu = read_json(baseline_file), read_json(mcu_file)
    argv = baseline if isinstance(baseline, list) else baseline.get("argv")
    if not isinstance(argv, list) or "src/harness/natural_boot.py" not in [
            str(v).replace(str(ROOT) + "/", "") for v in argv[:2]]:
        raise ValueError("Baseline must be the retained natural_boot recipe, not an arbitrary command")
    baseline = Recipe(argv[2:], {"--" + n for n in BASE_FLAGS},
                      {"--" + n for n in BASE_VALUES})
    if not baseline.get("integrated"):
        raise ValueError("Unified native requires the integrated original-entry recipe")
    mcu = Recipe(mcu["arguments"], {"--" + n for n in MCU_FLAGS},
                 {"--" + n for n in MCU_VALUES}, {"--" + n for n in MCU_REPEATED})
    if mcu.get("battery-task-trace") and not mcu.get("battery-config-trace"):
        raise ValueError("Battery task tracing requires real configuration completion tracing")
    if mcu.get("flash-request-trace"):
        raise ValueError("Unified flash-request-trace collector is not implemented; option cannot be ignored")
    return baseline, mcu


class PacketRemote(Remote):
    """Keep partial asynchronous RSP packets across host polling iterations."""
    def __init__(self, port):
        super().__init__(port)
        self.packet = None
        self.check = bytearray()

    def receive_ready(self, timeout=0):
        deadline = time.monotonic() + timeout
        while True:
            if not self.buffer:
                remaining = max(0, deadline - time.monotonic())
                if not select.select([self.sock], [], [], remaining)[0]:
                    return None
                chunk = self.sock.recv(65536)
                if not chunk:
                    raise EOFError("QEMU closed RSP")
                self.buffer.extend(chunk)
            c = self.buffer.pop(0)
            if self.packet is None:
                if c == ord("$"):
                    self.packet = bytearray()
                    self.check.clear()
                continue                         # real ACKs remain in the byte ledger
            if self.check or c == ord("#"):
                self.check.append(c)
                if len(self.check) != 3:
                    continue
                raw = bytes(self.packet)
                self.packet = None
                if sum(raw) % 256 != int(bytes(self.check[1:]), 16):
                    raise ValueError("RSP checksum")
                self.sock.sendall(b"+")
                out = bytearray()
                it = iter(raw)
                for b in it:
                    if b == ord("*"):
                        out.extend(bytes([out[-1]]) * (next(it) - 29))
                    elif b == ord("}"):
                        out.append(next(it) ^ 0x20)
                    else:
                        out.append(b)
                return out.decode("ascii")
            self.packet.append(c)

    def receive(self):
        answer = self.receive_ready(self.sock.gettimeout() or 5)
        if answer is None:
            raise TimeoutError("RSP reply not received")
        return answer


class RoleRemote:
    """Restricted read facade for existing passive observers; no resume/write API."""
    def __init__(self, owner, cpu):
        self.owner, self.cpu = owner, cpu

    def memory(self, address, length):
        return self.owner.read_va(self.cpu, address, length)

    def registers(self):
        return self.owner.registers(self.cpu)


class RoleView:
    def __init__(self, owner, role):
        self.role, self.owner = role, owner
        self.remote = RoleRemote(owner, ROLE_CPU[role])

    @property
    def running(self):
        return self.owner.running


class UnifiedSession:
    def __init__(self, run, process, qmp_port, gdb_port, instance_uuid):
        self.run, self.process, self.running = run, process, False
        self.rsp_ledger = ByteLedger(run, "RSP", scope="one native five-CPU debugger connection")
        self.qmp_ledger = ByteLedger(run, "QMP", scope="one native machine QMP connection")
        self.remote = self.monitor = None
        self.commands = Counter()
        self.reads, self.control, self.threads, self.xml_regs = [], [], {}, {}
        self.stop_epoch, self.last_packet = 0, None
        self.pa_supported = None
        self.pa_manifest_verified = False
        self.last_clock = None
        self.architecture = {"schema": "z62.native-architecture/1", "passed": False,
                             "QOM": None, "checks": {}, "clock_samples": [], "running_clock_samples": []}
        try:
            self.remote = audited_remote(PacketRemote)(gdb_port, self.rsp_ledger)
            self.monitor = audited_qmp(QMP)(qmp_port, self.qmp_ledger)
            self.command("qSupported:multiprocess+;xmlRegisters=arm")
            actual_uuid = self.qmp("query-uuid")
            if actual_uuid.get("UUID", "").lower() != instance_uuid.lower():
                raise ValueError("QMP endpoint does not identify the owned QEMU UUID")
            self.architecture.update(pid=process.pid, expected_uuid=instance_uuid, QMP_uuid=actual_uuid,
                                     query_cpus_fast=self.qmp("query-cpus-fast"))
            cpus = self.architecture["query_cpus_fast"]
            if sorted(c["cpu-index"] for c in cpus) != list(CPU_ROLES):
                raise ValueError("Actual query-cpus-fast must contain global CPU0..4 exactly")
            self.read_architecture_qom()
            self.discover_threads(cpus)
            self.last_packet = self.command("?")
            if not self.last_packet.startswith(("S", "T")):
                raise ValueError("No original stopped reset/entry state: " + self.last_packet)
            self.stop_epoch += 1
            self.freeze("initial")
        except BaseException as exc:
            # Construction can fail after real CPU/QOM observations. Retain
            # that partial epoch without turning it into a final snapshot.
            exc.partial_architecture = copy.deepcopy(self.architecture)
            try:
                self.close()
            except Exception as cleanup:
                exc.debugger_cleanup_error = error_text(cleanup)
            exc.partial_debugger_ledgers = {"RSP": self.rsp_ledger.summary(), "QMP": self.qmp_ledger.summary()}
            for name, value in exc.partial_debugger_ledgers.items():
                value["IO_ledger"] = identity(run / (name + "-io.jsonl"))
            raise

    def command(self, payload):
        safe = (payload.startswith(("qSupported:", "qXfer:features:read:", "qThreadExtraInfo,", "Hg"))
                or payload in ("qfThreadInfo", "qsThreadInfo", "?", "vCont?", "Hc-1",
                               "Qqemu.PhyMemMode:0", "Qqemu.PhyMemMode:1")
                or re.fullmatch(r"(?:p[0-9a-f]+|[Zz]1,[0-9a-f]+,[24]|[Zz]2,[0-9a-f]+,[1248]|vAttach;[0-9a-f]+)", payload))
        if not safe or self.running:
            raise RuntimeError("Unsafe or running-state debugger command: " + payload)
        self.commands[payload.split(",")[0].split(":")[0]] += 1
        return self.remote.command(payload)

    def qmp(self, name, arguments=None):
        allowed = {"query-cpus-fast", "query-status", "query-uuid", "qom-get", "qom-list",
                   "screendump", "memsave", "quit"}
        if name not in allowed:
            raise ValueError("Not a read/lifecycle QMP operation: " + name)
        if name == "memsave" and (self.running or not arguments or
                                  arguments.get("cpu-index") not in CPU_ROLES):
            raise ValueError("VA memsave requires a stopped explicitly selected global CPU")
        self.commands["QMP:" + name] += 1
        return self.monitor.command(name, arguments)

    def clock(self):
        value = self.qmp("qom-get", {"path": "/machine", "property": "virtual-time-ns"})
        if type(value) is not int or value < 0:
            raise ValueError("virtual-time-ns must be the actual nonnegative QEMU clock integer")
        sample = {"sequence": self.architecture.get("clock_observation_count", 0) + 1,
                  "virtual_ns": value, "stop_epoch": self.stop_epoch, "running": self.running,
                  "host_monotonic_ns": time.monotonic_ns(),
                  "QMP_tx_bytes_after": self.qmp_ledger.offsets["tx"],
                  "QMP_rx_bytes_after": self.qmp_ledger.offsets["rx"]}
        if self.last_clock is not None and value < self.last_clock["virtual_ns"]:
            self.architecture.setdefault("virtual_clock_regressions", []).append(
                {"before": self.last_clock, "after": sample})
        self.last_clock = sample
        self.architecture["clock_observation_count"] = sample["sequence"]
        self.architecture["last_clock_observation"] = sample
        with (self.run / "native-virtual-clock-observations.jsonl").open("a") as output:
            output.write(json.dumps(sample) + "\n")
        return value

    def read_architecture_qom(self, label="discovery"):
        for prop in ("architecture-state",):
            try:
                raw = self.qmp("qom-get", {"path": "/machine", "property": prop})
                parsed = json.loads(raw) if isinstance(raw, str) else raw
                if not isinstance(parsed, dict):
                    raise ValueError("Architecture QOM must be JSON object")
                self.architecture.update(QOM=parsed, QOM_property=prop, QOM_raw=raw)
                self.architecture.setdefault("QOM_snapshots", []).append(
                    {"stop_epoch": self.stop_epoch, "running": self.running, "phase": label,
                     "observed_UTC": utc(), "raw": raw, "state": parsed,
                     "QMP_tx_bytes_after": self.qmp_ledger.offsets["tx"],
                     "QMP_rx_bytes_after": self.qmp_ledger.offsets["rx"]})
                return
            except Exception as exc:
                self.architecture.setdefault("QOM_errors", []).append(
                    {"property": prop, "phase": label, "stop_epoch": self.stop_epoch,
                     "observed_UTC": utc(), "error": error_text(exc)})
                raise

    def discover_threads(self, cpus):
        def discover():
            found, answer = [], self.command("qfThreadInfo")
            while answer.startswith("m"):
                found.extend(answer[1:].split(","))
                answer = self.command("qsThreadInfo")
            if answer != "l":
                raise ValueError("Incomplete RSP thread discovery: " + answer)
            return found
        # CPUCluster ids determine inferior PIDs in the system gdbstub. Global
        # CPU/thread-number arithmetic is deliberately not used to assign cores.
        clusters, queue = [], [("/machine", 0)]
        while queue:
            parent, depth = queue.pop(0)
            for child in self.qmp("qom-list", {"path": parent}):
                kind = child.get("type", "")
                child_path = parent + "/" + child["name"]
                if kind == "child<cpu-cluster>":
                    cid = self.qmp("qom-get", {"path": child_path, "property": "cluster-id"})
                    if type(cid) is not int or cid < 0:
                        raise ValueError("Invalid actual CPU cluster-id")
                    clusters.append({"path": child_path, "cluster_id": cid, "gdb_pid": cid + 1})
                elif kind.startswith("child<") and depth < 2:
                    queue.append((child_path, depth + 1))
        self.architecture["GDB_clusters"] = clusters
        if len(clusters) != 3 or len({c["cluster_id"] for c in clusters}) != 3:
            raise ValueError("Three actual QOM CPUClusters are required; no thread id guesses")
        for cluster in clusters:
            reply = self.command(f"vAttach;{cluster['gdb_pid']:x}")
            if not reply.startswith(("T", "S")):
                raise ValueError("Cannot attach actual QOM CPU cluster: " + reply)
        found = discover()
        if len(found) != 5 or len(set(found)) != 5:
            raise ValueError("RSP must discover all five actual threads")
        mapping_evidence = []
        self.architecture["discovered_RSP_threads"] = found
        self.architecture["thread_mapping_evidence"] = mapping_evidence
        self.architecture["RSP_extra_info"] = {}
        qom_cpus = (self.architecture.get("QOM") or {}).get("cpus", [])
        for tid in found:
            answer = self.command("qThreadExtraInfo," + tid)
            try:
                extra = bytes.fromhex(answer).decode("ascii")
            except (ValueError, UnicodeError) as exc:
                raise ValueError("Invalid qThreadExtraInfo response for " + tid) from exc
            evidence = resolve_thread_identity(tid, extra, cpus, clusters, qom_cpus)
            cpu = evidence["global_cpu"]
            if cpu in self.threads:
                raise ValueError("Duplicate CPU identity in actual discovered GDB threads")
            evidence["RSP_extra_info_hex"] = answer
            self.threads[cpu] = tid
            mapping_evidence.append(evidence)
            self.architecture["RSP_extra_info"][cpu] = extra
        if set(self.threads) != set(CPU_ROLES):
            raise ValueError("Incomplete actual CPU/thread mapping")
        self.architecture["RSP_threads"] = dict(self.threads)

    def select_cpu(self, cpu):
        if self.running or cpu not in self.threads:
            raise RuntimeError("CPU read requires the common stopped epoch and discovered thread")
        if self.command("Hg" + self.threads[cpu]) != "OK":
            raise ValueError("Global thread selection failed")

    def xml(self, cpu, name):
        text, offset = "", 0
        while True:
            self.select_cpu(cpu)
            answer = self.command(f"qXfer:features:read:{name}:{offset:x},fff")
            if not answer.startswith(("m", "l")):
                return None
            text += answer[1:]
            offset += len(answer[1:].encode())
            if answer.startswith("l"):
                return text
            if offset > 1024 * 1024:
                raise ValueError("Unbounded debugger XML")

    def register_map(self, cpu):
        if cpu in self.xml_regs:
            return self.xml_regs[cpu]
        registers, seen, next_number = {}, set(), 0
        def visit(name):
            nonlocal next_number
            if name in seen:
                return
            seen.add(name)
            raw = self.xml(cpu, name)
            if raw is None:
                return
            (self.run / f"cpu{cpu}-{Path(name).name}").write_text(raw)
            # QEMU's generated target.xml uses xi:include without always
            # declaring the prefix. Preserve raw XML; bind only that prefix
            # for parsing, without loading external entities or URLs.
            parsed = raw
            if "xi:include" in raw and "xmlns:xi" not in raw:
                parsed = re.sub(r"<target(?=[\s>])", '<target xmlns:xi="http://www.w3.org/2001/XInclude"', raw, count=1)
            for element in ET.fromstring(parsed).iter():
                tag = element.tag.rsplit("}", 1)[-1]
                if tag == "include":
                    visit(element.attrib["href"])
                elif tag == "reg":
                    number = int(element.get("regnum", str(next_number)), 0)
                    registers[element.attrib["name"]] = (number, int(element.attrib["bitsize"]))
                    next_number = number + 1
        visit("target.xml")
        self.xml_regs[cpu] = registers
        return registers

    def registers(self, cpu, system=False):
        mapping, result = self.register_map(cpu), {}
        aliases = {"sp": "r13", "lr": "r14", "pc": "r15", "xpsr": "cpsr"}
        wanted = {f"r{i}" for i in range(16)} | {"sp", "lr", "pc", "cpsr", "xpsr"}
        for name, (number, bits) in mapping.items():
            if name not in wanted and not (system and name.upper().startswith(
                    ("MPIDR", "SCTLR", "TTBR", "TTBCR", "VBAR", "CBAR", "DACR", "CNTFRQ"))):
                continue
            self.select_cpu(cpu)
            raw = self.command(f"p{number:x}")
            if raw and not raw.startswith("E") and not set(raw) <= {"x"}:
                value = bytes.fromhex(raw)
                if len(value) * 8 != bits:
                    raise ValueError("Short CPU register read: " + name)
                result[aliases.get(name, name)] = f"0x{int.from_bytes(value, 'little'):0{bits//4}x}"
        if not all(f"r{i}" in result for i in range(16)):
            raise ValueError("Missing actual core register XML/p reads for CPU" + str(cpu))
        return result

    def _read(self, cpu, address, size, physical=False):
        if type(address) is not int or type(size) is not int or address < 0 or not 0 < size <= 128 * 1024 * 1024:
            raise ValueError("Invalid bounded debugger read")
        self.select_cpu(cpu)
        mode_changed = False
        try:
            if physical:
                if not self.pa_manifest_verified:
                    raise ValueError("PA read requires the selected build's frozen CPU-address-space GDB source")
                reply = self.command("Qqemu.PhyMemMode:1")
                self.pa_supported = reply == "OK"
                if not self.pa_supported:
                    raise ValueError("CPU-aware physical debugger mode not available")
                mode_changed = True
            body = bytearray()
            while len(body) < size:
                self.select_cpu(cpu)             # every m packet selects its AddressSpace
                count = min(4096, size - len(body))
                self.commands["m:PA" if physical else "m:VA"] += 1
                raw = self.remote.command(f"m{address+len(body):x},{count:x}")
                if raw.startswith("E"):
                    raise ValueError("Debugger memory read: " + raw)
                chunk = bytes.fromhex(raw)
                if len(chunk) != count:
                    raise ValueError("Short debugger read")
                body.extend(chunk)
        finally:
            if mode_changed:
                self.select_cpu(cpu)
                if self.command("Qqemu.PhyMemMode:0") != "OK":
                    raise RuntimeError("Could not restore debugger VA mode")
        self.reads.append({"global_cpu": cpu, "role": CPU_ROLES[cpu][0], "thread": self.threads[cpu],
                           "address": hex(address), "bytes": size, "address_kind": "PA" if physical else "VA",
                           "stop_epoch": self.stop_epoch, "sha256": hashlib.sha256(body).hexdigest()})
        return bytes(body)

    def read_va(self, cpu, address, size):
        return self._read(cpu, address, size)

    def read_pa(self, cpu, address, size):
        return self._read(cpu, address, size, True)

    def freeze(self, label):
        status = self.qmp("query-status")
        if status.get("running") is not False:
            raise ValueError("Common stop not confirmed by QMP")
        first = self.clock()
        time.sleep(0.025)                 # host observation separation only
        second = self.clock()
        sample = {"phase": label, "first_ns": first, "second_ns": second,
                  "frozen": first == second, "QMP_status": status, "stop_epoch": self.stop_epoch}
        self.architecture["clock_samples"].append(sample)
        if not sample["frozen"]:
            raise ValueError("Stopped QEMU virtual clock advanced")
        return sample

    def resume(self):
        if self.running:
            raise RuntimeError("Only one owner may resume the VM")
        self.command("Hc-1")
        self.commands["vCont;c"] += 1
        self.remote.send("vCont;c")
        self.running = True
        self.control.append({"action": "continue_all", "host_ns": time.monotonic_ns(), "stop_epoch": self.stop_epoch})

    def receive_stop(self, timeout=0):
        if not self.running:
            return None
        packet = self.remote.receive_ready(timeout)
        if packet is None:
            return None
        self.running = False
        self.last_packet = packet
        if not packet.startswith(("S", "T")):
            raise RuntimeError("QEMU did not stop normally: " + packet)
        self.stop_epoch += 1
        self.control.append({"action": "stop", "packet": packet, "stop_epoch": self.stop_epoch})
        return packet

    def interrupt(self):
        if self.running:
            self.remote.sock.sendall(b"\x03")
            self.control.append({"action": "one_global_interrupt", "host_ns": time.monotonic_ns()})
            packet = self.receive_stop(5)
            if packet is None:
                raise TimeoutError("Global interrupt reply missing")
        return self.freeze("final" if self.stop_epoch > 1 else "stopped")

    def stopped_cpu(self, packet):
        match = re.search(r"(?:^|;)thread:([^;]+);", packet[3:])
        if match is None:
            match = re.search(r"thread:([^;]+);", packet)
        if match is None:
            raise ValueError("Stop lacks an actual thread; PC/role cannot be inferred")
        reverse = {tid: cpu for cpu, tid in self.threads.items()}
        if match[1] not in reverse:
            raise ValueError("Unknown stopping thread: " + match[1])
        return reverse[match[1]]

    def step_original(self, cpu):
        before = self.clock()
        self.select_cpu(cpu)
        self.commands["vCont;s"] += 1
        self.remote.send("vCont;s:" + self.threads[cpu])
        self.running = True
        packet = self.receive_stop(5)
        if packet is None:
            self.interrupt()
            raise TimeoutError("Original instruction step did not stop")
        if self.stopped_cpu(packet) != cpu:
            raise RuntimeError("Single instruction step stopped on another CPU; event not attributed")
        self.control.append({"action": "step_original_instruction", "global_cpu": cpu,
                             "stop_epoch": self.stop_epoch, "packet": packet,
                             "virtual_before_ns": before, "virtual_after_ns": self.clock()})
        return packet

    def set_input(self, prop, value):
        if prop != "pcal-pin-levels" and not re.fullmatch(r"gpio-pin-levels-[A-H]", prop):
            raise ValueError("Only declared external GPIO/PCAL inputs may be set")
        self.commands["QMP:external-pad-set"] += 1
        return self.monitor.command("qom-set", {"path": "/machine", "property": prop, "value": value})

    def close(self):
        errors = []
        resources = ([self.remote.sock] if self.remote is not None else [])
        if self.monitor is not None:
            resources.extend([self.monitor.file, self.monitor.socket])
        for resource in resources:
            try:
                resource.close()
            except Exception as exc:
                errors.append(error_text(exc))
        for ledger in (self.rsp_ledger, self.qmp_ledger):
            try:
                ledger.finish()
            except Exception as exc:
                errors.append(error_text(exc))
        if errors:
            raise RuntimeError("Debugger cleanup: " + "; ".join(errors))


class BreakpointUnion:
    """Z1 is global to every TCG CPU; desired sites are a role-aware union."""
    def __init__(self, session):
        self.s = session
        self.installed = set()
        self.desired = {}

    def replace(self, sites):
        self.desired = sites
        addresses = {address for role, address in sites}
        for address in sorted(self.installed - addresses):
            if self.s.command(f"z1,{address:x},2") != "OK":
                raise ValueError("Breakpoint removal failed")
        for address in sorted(addresses - self.installed):
            if self.s.command(f"Z1,{address:x},2") != "OK":
                raise ValueError("Breakpoint insertion failed")
        self.installed = addresses

    def step(self, cpu, address):
        removed = address in self.installed
        if removed and self.s.command(f"z1,{address:x},2") != "OK":
            raise ValueError("Cannot resume original breakpoint instruction")
        try:
            return self.s.step_original(cpu)
        finally:
            if removed and address in self.installed:
                if self.s.command(f"Z1,{address:x},2") != "OK":
                    raise ValueError("Cannot restore shared breakpoint union")


class WriteWatchpointUnion:
    """Passive Z2 traps are global; the actual stopping thread owns the write."""
    def __init__(self, session):
        self.s = session
        self.installed = set()
        self.desired = {}

    def replace(self, sites):
        sizes = {}
        for (role, address), site in sites.items():
            if address in sizes and sizes[address] != site["bytes"]:
                raise ValueError("Coincident role watchpoints need the same range size")
            sizes[address] = site["bytes"]
        ranges = set(sizes.items())
        for address, size in sorted(self.installed - ranges):
            if self.s.command(f"z2,{address:x},{size:x}") != "OK":
                raise ValueError("Write watchpoint removal failed")
        for address, size in sorted(ranges - self.installed):
            if self.s.command(f"Z2,{address:x},{size:x}") != "OK":
                raise ValueError("Write watchpoint insertion failed")
        self.desired, self.installed = sites, ranges

    def step(self, cpu, pc, breakpoints):
        # An original wide store can touch several watched ranges. All other
        # CPUs remain stopped while this one original instruction executes.
        ranges = sorted(self.installed)
        for address, size in ranges:
            if self.s.command(f"z2,{address:x},{size:x}") != "OK":
                raise ValueError("Cannot suspend write watchpoint for original step")
        try:
            return breakpoints.step(cpu, pc)
        finally:
            for address, size in ranges:
                if self.s.command(f"Z2,{address:x},{size:x}") != "OK":
                    raise ValueError("Cannot restore write watchpoint union")


def pairs(recipe, option, port=False):
    result = {}
    for entry in recipe.get(option, []):
        key, value = entry.split("=", 1)
        key = key.upper() if port else int(key, 0)
        value = int(value, 0)
        if key in result or (port and (key not in "ABCDEFGH" or not 0 <= value <= 0xffff)):
            raise ValueError("Invalid/duplicate external input: " + entry)
        result[key] = value
    return result


def verify_unified_manifest(manifest):
    """Check the selected build's frozen contract, without invoking a binary."""
    arch = manifest.get("unified_native_architecture", {})
    required = {"machine": MACHINE, "qemu_instances": 1, "CPUs": 5,
                "virtual_clock": "QEMU_CLOCK_VIRTUAL", "private_address_spaces": 3,
                "QEMU_CPU_clusters": 3, "EXPEED_generic_timer_exact_frequency": True}
    if any(arch.get(k) != v for k, v in required.items()):
        raise ValueError("Selected build lacks the frozen native five-CPU architecture contract")
    if any(arch.get("domains", {}).get(role, {}).get("global_CPUs") != cores for role, cores in
           (("master", [0, 1]), ("slave", [2, 3]), ("MCU", [4]))):
        raise ValueError("Selected manifest CPU domain ranges differ")
    sources = manifest.get("unified_native_model_sources", {})
    retained = {}
    for name, item in sources.items():
        actual = identity(path(item["path"]))
        if actual["sha256"] != item["sha256"]:
            raise ValueError("Frozen unified source SHA differs: " + name)
        retained[name] = actual
    item = retained.get("gdbstub/system.c")
    if not item or not re.search(r"address_space_rw\s*\(\s*cpu_get_address_space\s*\(\s*cpu\s*,\s*0\s*\)",
                                Path(item["path"]).read_text()):
        raise ValueError("Frozen selected-CPU physical GDB implementation is missing")
    if not all(name in retained for name in ("target/arm/cpu.c", "target/arm/cpu.h", "target/arm/helper.c")):
        raise ValueError("Frozen exact-frequency ARM generic timer sources are missing")
    return {"architecture": arch, "sources": retained,
            "CPU_selected_PA_GDB_source_verified": True, "runtime_verified": False}


def prepare_native(args, run, baseline, mcu, report):
    from coupled_dual import create_backing, SHAS
    from probe_z6ii import peer_data_layout, peer_parameter_layout
    from persistent_input import prepare
    from parameter_source_reference import inspect_spec
    from loader_runtime_audit import load_reference
    from mcu_wire_contract import validate_bus, manifest_abi
    manifest_file = args.qemu_manifest.resolve(strict=True)
    manifest = read_json(manifest_file)
    mcu_manifest_file = args.mcu_manifest.resolve(strict=True)
    mcu_manifest = read_json(mcu_manifest_file)
    binary = path(manifest["binary"])
    binary_id = identity(binary)
    if binary_id["sha256"] != manifest["binary_sha256"]:
        raise ValueError("Selected unified QEMU binary SHA256 differs from its manifest")
    report["selected_unified_build_contract"] = verify_unified_manifest(manifest)
    report["identities"] = {"QEMU": binary_id, "QEMU_manifest": identity(manifest_file),
        "MCU_reference_manifest": identity(mcu_manifest_file),
        "baseline_recipe": identity(args.baseline_command_json), "MCU_recipe": identity(args.mcu_profile_json),
        "MCU_reference_manifest_is_not_a_second_process": True}
    blobs = {}
    for role in ("master", "slave", "MCU"):
        directory = run / role
        directory.mkdir()
        source = INPUT if role == "MCU" else ROOT / f"inputs/firmware/{role}-original-with-crc.bin"
        blobs[role] = source.read_bytes()
        ref = identity(source)
        if ref["sha256"] != (EXPECTED_SHA if role == "MCU" else SHAS[role]):
            raise ValueError("Original firmware input identity differs: " + role)
        report["identities"][role + "_ROM"] = ref
    env = environment()
    inherited = {k: v.replace("@RUN@", str(run)) for k, v in env.items() if k.startswith("Z6II_")}
    # The unified process has exactly one global MCU environment. E6 options
    # are role-scoped; shell leftovers cannot select replay or stale backings.
    for key in list(env):
        if key.startswith(("Z6II_", "Z62_MASTER_", "Z62_SLAVE_", "EX1850_")):
            env.pop(key)
    env["Z6_VERIFY_CPSR_HFLAGS"] = "1"
    report["cold_backings"] = []
    queue = run / "two-ended-queues.bin"
    report["cold_backings"].append(create_backing(queue, notifications=True, gpio=True,
                                                  wire=True, phy=True, stop=True, lanes=True))
    extents = {}
    def extent(key, filename, size):
        p = run / filename
        with p.open("xb") as stream:
            stream.truncate(size)
        report["cold_backings"].append({"path": str(p), "bytes": size,
             "classification": "fresh zero cold transport/RAM backing; not runtime RAM replay",
             "guest_state_write": False})
        extents[key] = str(p)
    if baseline.get("peer-buffer-section"):
        extent("Z6II_PEER_BUFFER_SECTION", "peer-buffer-section.bin", 0x100000)
    if baseline.get("peer-data-section"):
        extent("Z6II_PEER_DATA_SECTION", "peer-data-section.bin", peer_data_layout(manifest))
    parameter_size, dma_offset = peer_parameter_layout(manifest) if baseline.get("peer-parameter-section") else (None, None)
    if parameter_size:
        extent("Z6II_PEER_PARAMETER_SECTION", "peer-parameter-section.bin", parameter_size)
    if baseline.get("peer-dma-section"):
        if dma_offset is not None:
            extents["Z6II_PEER_DMA_SECTION"] = extents["Z6II_PEER_PARAMETER_SECTION"]
        else:
            extent("Z6II_PEER_DMA_SECTION", "peer-dma-section.bin", 0x100000)
    if baseline.get("slave-dma-section"):
        extent("Z6II_SLAVE_DMA_SECTION", "slave-dma-section.bin", 0x300000)
    report["parameter_DMA_view_offset"] = dma_offset
    bus = run / "cold-mcu-wire.bus"
    tool = args.bus_tool.resolve(strict=True)
    created = subprocess.run([str(tool), "create-cold", str(bus)], cwd=ROOT,
                             capture_output=True, text=True, check=True, timeout=30)
    validate_bus(bus, manifest)
    if manifest_abi(manifest) != manifest_abi(mcu_manifest):
        raise ValueError("Selected MCU wire ABI differs from MCU reference manifest")
    initial_bus = run / "cold-mcu-wire-initial.bus"
    with initial_bus.open("xb") as stream:
        stream.write(bus.read_bytes())
    report["MCU_wire"] = {"path": str(bus), "initial": identity(initial_bus), "tool": identity(tool),
        "create_stdout": created.stdout, "create_stderr": created.stderr,
        "known_wait_ms": args.known_wait_ms, "known_wait_timebase": "QEMU_CLOCK_VIRTUAL",
        "physical_reset_gate_verified": False, "physical_wire_contract_verified": False}
    wire = {"Z6II_MCU_WIRE_PATH": str(bus), "Z6II_MCU_WIRE_PAIRING": "pb14_pd12_pe3_pg6",
            "Z6II_MCU_WIRE_POLL_NS": str(args.poll_ns),
            "Z6II_MCU_WIRE_KNOWN_WAIT_MS": str(args.known_wait_ms)}
    env.update(wire)                       # MCU consumes the existing global wire contract
    parameter_env = {}
    if baseline.get("parameter-source-reference-spec"):
        ref, parameter_env = inspect_spec(path(baseline.get("parameter-source-reference-spec"), run), manifest)
        report["parameter_source_reference"] = ref
    for role in ("master", "slave"):
        settings = {k: v for k, v in inherited.items() if not k.startswith(
            ("Z6II_MCU_WIRE_", "Z6II_EXMCU_", "Z6II_QUEUE_", "Z6II_PERSISTENT_"))
            and k not in ("Z6II_PEER_BUFFER_SECTION", "Z6II_PEER_DATA_SECTION",
                          "Z6II_PEER_DMA_SECTION", "Z6II_PEER_PARAMETER_SECTION", "Z6II_SLAVE_DMA_SECTION")}
        settings.update(extents, Z6II_QUEUE_BACKING=str(queue), Z6II_QUEUE_ROLE=role,
            Z6II_QUEUE_AUTO_IRQ="1", Z6II_LINK_CONFIGURATION="1", Z6II_COUPLED_GPIO="1",
            Z6II_GPIO_CONNECTION="1", Z6II_COUPLED_PHY="1", Z6II_COUPLED_STOP="1", Z6II_COUPLED_LANES="1",
            Z6II_SHARED_EVENT_POLL_NS=str(baseline.integer("shared-event-poll-ns", args.poll_ns)))
        if role == "master":
            settings.update(wire)
        if baseline.get("parameter-require-recorded-body"):
            settings["Z6II_PARAMETER_REQUIRE_RECORDED_BODY"] = "1"
        settings.update(parameter_env)
        if baseline.get(role + "-fill-channel1"):
            settings["Z6II_" + role.upper() + "_FILL_CHANNEL1"] = "1"
        if role == "slave":
            for option in ("slave-2b20-control-latch", "slave-access-ready-line"):
                if baseline.get(option):
                    settings["Z6II_" + option.upper().replace("-", "_")] = "1"
            for option in ("slave-pipeline-mode", "slave-sdhci-mode"):
                if baseline.get(option):
                    settings["Z6II_" + option.upper().replace("-", "_")] = baseline.get(option)
        persistent = baseline.get(role + "-persistent-input")
        if persistent:
            prepared = prepare(path(persistent, run), role, run / role)
            report.setdefault("persistent_inputs", {})[role] = prepared
            settings.update(Z6II_PERSISTENT_INPUT_FILE=prepared["snapshot"],
                            Z6II_PERSISTENT_INPUT_BASE=prepared["base"],
                            Z6II_PERSISTENT_INPUT_SHA256=prepared["sha256"])
        if role == "master" and baseline.get("master-persistent-output"):
            # Research export of the per-run flash at exit; never an input to this run.
            settings["Z6II_PERSISTENT_OUTPUT_FILE"] = str(run / role / "final-persistent-flash.bin")
        settings["Z6II_BOOT_TCG_TRACE"] = "1" if baseline.get("boot-tcg-trace") else "0"
        settings["Z6II_BOOT_TCG_TRACE_ROLE"] = role
        settings["Z6II_BOOT_TCG_TRACE_OUT"] = str(run / role / "original-boot-observation.log")
        settings["Z6II_SOURCE50_TCG_TRACE"] = "1" if role == "master" and baseline.get("source50-tcg-trace") else "0"
        settings["Z6II_SOURCE50_TCG_TRACE_ROLE"] = role
        settings["Z6II_SOURCE50_TCG_TRACE_OUT"] = str(run / role / "original-source50-observation.log")
        if baseline.get("graphics-capture"):
            graphics = run / role / "graphics"
            graphics.mkdir()
            settings["Z6II_GRAPHICS_DUMP_DIR"] = str(graphics)
        env.update({"Z62_" + role.upper() + "_" + k: str(v) for k, v in settings.items()})
    gpio, known, adc = pairs(mcu, "gpio-pin-levels", True), pairs(mcu, "gpio-pin-known-mask", True), pairs(mcu, "adc-channel-mv")
    if not set(known) <= set(gpio) or any(not 0 <= c <= 15 or not 0 <= mv <= 5000 for c, mv in adc.items()):
        raise ValueError("MCU external GPIO/ADC declaration is invalid")
    words = [int(v, 0) for v in mcu.get("rng-public-word", [])]
    if any(not 0 <= w <= 0xffffffff for w in words):
        raise ValueError("Public RNG input must contain uint32 words")
    env.update(EX1850_HSE_PRESENT="0" if mcu.get("without-hse") else "1",
        EX1850_LSE_PRESENT="0" if mcu.get("without-lse") else "1",
        EX1850_I2C_BUS_MODE=mcu.get("i2c-bus", "strict"), EX1850_I2C_SLAVE_MODE=mcu.get("i2c-slave", "strict"),
        EX1850_I2C_MAX77711="1" if mcu.get("i2c-max77711") else "0",
        EX1850_I2C_ABSENT_ADDRESSES=",".join(hex(int(v, 0)) for v in mcu.get("i2c-absent-address", [])),
        EX1850_I2C_REQUEST_PATH=str(run / "MCU" / "unprovided-I2C-request.json"),
        EX1850_GPIO_PIN_LEVELS=",".join(f"{p}={hex(v)}" for p, v in sorted(gpio.items())),
        EX1850_GPIO_PIN_KNOWN_MASKS=",".join(f"{p}={hex(v)}" for p, v in sorted(known.items())),
        EX1850_GPIO_MASKED_READPIN="1" if mcu.get("gpio-masked-readpin") else "0",
        EX1850_ADC_PIN_MV=",".join(f"{c}={v}" for c, v in sorted(adc.items())),
        EX1850_DEBUG_CLOCK_GUARD="1" if mcu.get("debug-clock-guard", "on") == "on" else "0",
        EX1850_DEBUG_WARP_AUDIT="1" if mcu.get("debug-warp-audit") else "0",
        EX1850_BOUNDARY_SRAM_PATH=str(run / "MCU" / "boundary-SRAM.bin"),
        EX1850_BOUNDARY_FLASH_PATH=str(run / "MCU" / "boundary-simulated-FLASH.bin"),
        EX1850_FLASH_FUNCTIONAL="1" if mcu.get("flash-mode", "strict") == "functional" else "0")
    if adc:
        vref = mcu.integer("adc-vref-mv", 0)
        if not 0 < vref <= 5000:
            raise ValueError("Declared ADC pins require a valid reference voltage")
        env["EX1850_ADC_VREF_MV"] = str(vref)
    if mcu.get("pcal-pin-levels") is not None:
        levels = mcu.integer("pcal-pin-levels", 0)
        if not 0 <= levels <= 0xffffff:
            raise ValueError("PCAL levels must fit 24 bits")
        env["EX1850_PCAL_PIN_LEVELS"] = hex(levels)
    if mcu.get("pcal-pin-event"):
        from run_exmcu_qemu_reset import pcal_pin_event
        env["EX1850_PCAL_PIN_EVENTS"] = ",".join(f"{t}:{hex(mask)}:{hex(levels)}"
            for t, mask, levels in (pcal_pin_event(v) for v in mcu.get("pcal-pin-event")))
    if words:
        env["EX1850_PUBLIC_RNG_WORDS"] = ",".join(hex(w) for w in words)
    if mcu.get("rtc-retained") is not None:
        # Explicit research input: a battery-retained RTC domain, never the host clock.
        if not re.fullmatch(r"\d{14},(0x)?[0-9a-fA-F]{1,8}", mcu.get("rtc-retained")):
            raise ValueError("rtc-retained must be YYYYMMDDhhmmss,BKP19")
        env["EX1850_RTC_RETAINED"] = mcu.get("rtc-retained")
    if mcu.get("rtc-backup-input") is not None:
        from rtc_backup_input import prepare as prepare_rtc_backup
        backup = prepare_rtc_backup(path(mcu.get("rtc-backup-input"), run), run / "MCU" / "rtc-backup-input")
        retained = mcu.get("rtc-retained")
        if retained is not None and int(retained.split(",")[1], 16) != backup["words"][19]:
            raise ValueError("rtc-retained BKP19 differs from the complete imported RTC bank")
        report["MCU_RTC_backup_input"] = backup
        env["EX1850_RTC_BACKUP_INPUT_FILE"] = backup["snapshot"]
        env["EX1850_RTC_BACKUP_INPUT_SHA256"] = backup["sha256"]
    if mcu.get("flash-mode", "strict") == "functional":
        for option, key, default in (("flash-vdd-mv", "VDD_MV", 3300), ("flash-nwrp", "NWRP", 0xfff),
                ("flash-erase-ns", "ERASE_NS", 50000000), ("flash-program-ns", "PROGRAM_NS", 40000)):
            value = mcu.integer(option, default)
            env["EX1850_FLASH_" + key] = hex(value) if key == "NWRP" else str(value)
    gdb_port, qmp_port = free_port(), free_port()
    instance_uuid = str(uuid.uuid4())
    command = [str(binary), "-machine", MACHINE + ",slave-firmware=" + str(path("inputs/firmware/slave-original-with-crc.bin")),
        "-smp", "5", "-bios", str(path("inputs/firmware/master-original-with-crc.bin")), "-kernel", str(INPUT),
        "-display", "none", "-monitor", "none", "-serial", "none", "-nic", "none",
        "-accel", "tcg,thread=single", "-icount", f"shift={baseline.integer('icount-shift', 3)},align=off,sleep=off",
        "-S", "-gdb", f"tcp:127.0.0.1:{gdb_port}", "-qmp", f"tcp:127.0.0.1:{qmp_port},server=on,wait=off",
        "-uuid", instance_uuid]
    for cpu in range(4):
        command.extend(["-device", f"loader,addr=0x10020000,cpu-num={cpu}"])
    if baseline.get("slave-sdhci-mode") in ("empty-card", "fat-card"):
        from virtual_sd import create
        for channel in range(2):
            medium = run / "slave" / f"fresh-sd{channel}.raw"
            info = create(medium, formatted=baseline.get("slave-sdhci-mode") == "fat-card",
                filesystem=baseline.get("slave-filesystem", "FAT32"),
                capacity_bytes=baseline.integer("slave-card-capacity-mib", 4096) * 1024 * 1024)
            command.extend(["-drive", f"if=none,id=z6ii_slave_sd{channel},format=raw,file={medium}"])
            report.setdefault("virtual_SD_cards", []).append(info)
    if baseline.get("qemu-exception-trace"):
        command.extend(["-d", "int,guest_errors", "-D", "/dev/fd/1"])
    if mcu.get("nvic-write-trace", "off") == "on":
        command.extend(["-trace", "enable=nvic_sysreg_write"])
    loader = None
    if baseline.get("loader-runtime-reference-spec"):
        loader = load_reference(path(baseline.get("loader-runtime-reference-spec"), run), blobs["master"])
    peer = None
    if mcu.get("usart1-battery-spec"):
        from ex1850_battery_peer import SerialBatteryPeer, load_spec
        from ex1850_battery_wire import VirtualBatteryPeer
        specification = path(mcu.get("usart1-battery-spec"), run)
        spec, _ = load_spec(specification)
        report["battery_input"] = {"specification": identity(specification),
            "required_TX": spec.get("native_cmd89_acceptance", {}).get("required_TX"), "strict_original_spec": True,
            "nonce_bridge": False, "physical_battery_authentication_verified": False}
        report["USART1_battery_specification"] = identity(specification)
        battery_clock = mcu.get("usart1-battery-clock", "virtual")
        if battery_clock == "virtual":
            peer = VirtualBatteryPeer(run / "MCU" / "USART1-peer", specification, words,
                                      mcu.integer("usart1-peer-max-replies", 4096))
            env.update(peer.environment)
            report["battery_input"].update(clock="QEMU_CLOCK_VIRTUAL",
                contracts_compiled_before_guest_start=True,
                compiled_contracts=identity(peer.table_path),
                turnaround_ns=2_000_000, physical_turnaround_verified=False)
        elif battery_clock == "host":
            peer = SerialBatteryPeer(run / "MCU" / "USART1-peer", specification, words,
                                      mcu.integer("usart1-peer-max-replies", 4096))
            command.extend(["-chardev", peer.chardev])
            report["battery_input"].update(clock="host_monotonic", diagnostic_comparison_only=True)
        else:
            raise ValueError("usart1-battery-clock must be virtual or host")
    report["effective_environment"] = {k: v for k, v in env.items() if k.startswith(
        ("Z62_MASTER_", "Z62_SLAVE_", "Z6II_MCU_WIRE_", "EX1850_", "Z6_VERIFY_"))}
    report["command"] = command
    return dict(manifest=manifest, blobs=blobs, command=command, env=env, peer=peer,
        gdb_port=gdb_port, qmp_port=qmp_port, instance_uuid=instance_uuid, loader=loader,
        gpio=gpio, known={p: known.get(p, 0xffff) for p in gpio}, bus=bus, tool=tool)


class PadInputs:
    def __init__(self, session, mcu, prepared):
        self.s = session
        self.events, self.channels = [], {}
        self.gpio, self.known = prepared["gpio"], prepared["known"]
        for kind, option, filename in (("GPIO", "gpio-host-input-file", "gpio-host-state.json"),
                                       ("PCAL", "pcal-host-input-file", "pcal-host-state.json")):
            if mcu.get(option):
                self.channels[kind] = {"request_path": str(path(mcu.get(option), session.run)),
                    "state_path": str(session.run / "MCU" / filename), "sequence": 0}
                self.publish(kind, {"sequence": 0, "running": False, "delivered": False})

    def public_channels(self):
        return {kind: {k: v for k, v in item.items() if k.endswith("_path")}
                for kind, item in self.channels.items()}

    def publish(self, kind, state):
        state.update(host_monotonic_ns=time.monotonic_ns(),
                     virtual_time_ns=self.s.clock(), guest_state_written=False,
                     owner_pid=self.s.process.pid, owner_uuid=self.s.architecture["expected_uuid"])
        save_json(self.channels[kind]["state_path"], state)

    def poll(self):
        for kind, channel in self.channels.items():
            request_file = Path(channel["request_path"])
            if not request_file.exists():
                continue
            request = read_json(request_file)
            if not isinstance(request, dict):
                raise ValueError("External pad request must be an object")
            sequence = request.get("sequence")
            if type(sequence) is not int or sequence < 0:
                raise ValueError("External pad sequence is missing/invalid")
            if sequence <= channel["sequence"]:
                continue
            record = {"sequence": sequence, "request": request, "delivered": False,
                      "readback_verified": False, "running": self.s.running}
            try:
                if (request.get("schema") != "z62.virtual-pad-request/1"
                        or request.get("owner_pid") != self.s.process.pid
                        or request.get("owner_uuid") != self.s.architecture["expected_uuid"]):
                    raise ValueError("External pad request lacks this actual QEMU owner identity")
                if sequence != channel["sequence"] + 1 or request.get("pad_kind") != kind:
                    raise ValueError("External pad sequence/kind does not match its channel")
                deadline = request.get("at_virtual_ns")
                mask, levels = request.get("mask"), request.get("levels")
                if (type(deadline) is not int or deadline < 0 or type(mask) is not int or type(levels) is not int
                        or mask <= 0 or levels < 0 or levels & ~mask):
                    raise ValueError("Explicit virtual deadline and masked external levels are required")
                if kind == "GPIO":
                    port = request.get("port")
                    if port not in self.gpio or mask > 0xffff or mask & ~self.known[port]:
                        raise ValueError("GPIO mask exceeds explicitly supplied known input bits")
                    prop = "gpio-pin-levels-" + port
                else:
                    if mask > 0xffffff:
                        raise ValueError("PCAL mask exceeds 24 external input bits")
                    prop = "pcal-pin-levels"
                before = self.s.clock()
                if before < deadline:
                    continue
                old = self.s.qmp("qom-get", {"path": "/machine", "property": prop})
                if type(old) is not int:
                    raise ValueError("Actual external pin levels are not an integer")
                new = (old & ~mask) | levels
                record["QMP_return"] = self.s.set_input(prop, new)
                observed = self.s.qmp("qom-get", {"path": "/machine", "property": prop})
                after = self.s.clock()
                record.update(property=prop, previous_levels=old, requested_levels=new, readback=observed,
                    readback_verified=observed == new, delivered=observed == new,
                    applied_virtual_ns=before, after_virtual_ns=after,
                    lateness_ns=before-deadline, requested_virtual_ns=deadline,
                    ACK_is_original_business_acceptance=False, exact_virtual_timer_delivery=False)
                if not record["readback_verified"]:
                    raise ValueError("External pin QOM readback differs")
            except Exception as exc:
                record["error"] = error_text(exc)
            channel["sequence"] = sequence
            self.events.append(record)
            self.publish(kind, record)
            save_json(self.s.run / "native-unified-pad-events.json", self.events)

    def finish(self):
        for kind, channel in self.channels.items():
            try:
                previous = read_json(channel["state_path"])
                previous["running"] = False
                previous.update(owner_closed_UTC=utc(), final_virtual_time_sampled=False,
                                virtual_time_scope="retained last real sample; no final QOM read")
                save_json(channel["state_path"], previous)
            except Exception as exc:
                self.events.append({"pad_kind": kind, "closure_error": error_text(exc)})


def initial_observation(session, prepared, report):
    entries = []
    report["initial_entries"] = entries
    for cpu, (role, local) in CPU_ROLES.items():
        regs = session.registers(cpu, system=True)
        base = MCU_BASE if role == "MCU" else ENTRY
        pc = int(regs["r15"], 16)
        source = prepared["blobs"][role]
        actual = session.read_va(cpu, pc, 32)
        offset = pc - base
        expected = source[offset:offset+32] if 0 <= offset <= len(source)-32 else b""
        entry = {"global_cpu": cpu, "local_core": local, "role": role, "thread": session.threads[cpu],
                 "registers": regs, "instruction_bytes": actual.hex(), "original_bytes": expected.hex(),
                 "original_instructions_verified": bool(expected) and actual == expected}
        if role == "MCU":
            entry["original_entry_verified"] = (pc == 0x080002b4 and int(regs["r13"], 16) == 0x20000c08
                                                  and entry["original_instructions_verified"])
            # Before first continue the array is not busy: full initial ROM
            # verification is safe; subsequent busy-array reads are avoided.
            rom = session.read_va(cpu, MCU_BASE, len(source))
            entry["full_initial_ROM_verified"] = rom == source
            (session.run / "MCU" / "initial-simulated-FLASH.bin").write_bytes(rom)
        else:
            entry["original_entry_verified"] = pc == ENTRY and entry["original_instructions_verified"]
            entry["E6_MPIDR_QOM"] = next(c["MPIDR"] for c in session.architecture["QOM"]["cpus"]
                                          if c["global_cpu_index"] == cpu)
            entry["MPIDR_source"] = "read-only QOM architecture-state; raw GDB XML may omit MPIDR"
            entry["XML_MPIDR_aliases"] = {n: v for n, v in regs.items() if n.upper().startswith("MPIDR")}
            entry["guest_MPIDR_instruction_read_verified"] = False
        entries.append(entry)
    report["initial_entries"] = entries
    if not all(e["original_entry_verified"] for e in entries) or not entries[-1].get("full_initial_ROM_verified"):
        raise ValueError("An actual original entry/reset or ROM window did not match")
    report["MCU_original_reset_verified"] = True


def evaluate_architecture(arch, report):
    """Recompute read-only architecture gates from retained observations.

    Used by the runner and the offline acceptance reader. Fixture writes and
    active IRQ/reset isolation tests belong to a separate structural run.
    """
    qom = arch.get("QOM") or {}
    checks = {}
    queries = arch.get("query_cpus_fast", [])
    cpus = qom.get("cpus", [])
    cpu_map = {c.get("global_cpu_index"): c for c in cpus if isinstance(c, dict)}
    query_map = {c.get("cpu-index"): c for c in queries if isinstance(c, dict)}
    checks["actual_machine_contract"] = (qom.get("schema") == "z62.native-machine-state/1"
        and qom.get("machine") == MACHINE and qom.get("observation_only") is True)
    checks["five_actual_CPUs"] = (len(queries) == len(cpus) == 5
        and set(query_map) == set(cpu_map) == set(CPU_ROLES)
        and all(cpu_map[i].get("qom_path") == query_map[i].get("qom-path") for i in CPU_ROLES))
    checks["one_owned_PID_and_QMP_UUID"] = (type(arch.get("pid")) is int and arch["pid"] > 0
        and qom.get("pid") == arch["pid"] and bool(arch.get("expected_uuid"))
        and arch.get("QMP_uuid", {}).get("UUID", "").lower() == arch["expected_uuid"].lower())
    mapping = arch.get("thread_mapping_evidence", [])
    threads = {str(k): v for k, v in arch.get("RSP_threads", {}).items()}
    def mapping_matches(m):
        try:
            actual = resolve_thread_identity(m["thread"], m["RSP_extra_info"], queries,
                                             arch.get("GDB_clusters", []), cpus)
            return (all(m.get(k) == actual.get(k) for k in
                        ("global_cpu", "qom_path", "thread", "cluster", "role", "local_cpu", "actual_MPIDR"))
                    and bytes.fromhex(m["RSP_extra_info_hex"]).decode("ascii") == m["RSP_extra_info"])
        except (KeyError, TypeError, ValueError, UnicodeError):
            return False
    checks["five_actual_GDB_threads_mapped"] = (len(mapping) == len(threads) == 5
        and {m.get("global_cpu") for m in mapping} == set(CPU_ROLES)
        and len({m.get("thread") for m in mapping}) == 5
        and all(threads.get(str(m["global_cpu"])) == m.get("thread")
            and re.fullmatch(r"p[0-9a-f]+\.[0-9a-f]+", m.get("thread", ""))
            and m.get("role") == CPU_ROLES[m["global_cpu"]][0]
            and m.get("local_cpu") == CPU_ROLES[m["global_cpu"]][1]
            and m.get("qom_path") == query_map.get(m["global_cpu"], {}).get("qom-path")
            and m.get("qom_path", "").startswith(m.get("cluster", {}).get("path", "!") + "/")
            and int(m["thread"][1:].split(".")[0], 16) == m.get("cluster", {}).get("gdb_pid")
            and m.get("cluster", {}).get("gdb_pid") == m.get("cluster", {}).get("cluster_id", -2) + 1
            and cpu_map.get(m["global_cpu"], {}).get("QEMU_cluster_index") == m.get("cluster", {}).get("cluster_id")
            and mapping_matches(m)
            for m in mapping))
    tids = [c.get("thread-id") for c in queries]
    checks["actual_single_TCG_host_thread"] = all(type(t) is int and t > 0 for t in tids) and len(set(tids)) == 1
    entries = report.get("initial_entries", [])
    checks["original_entries_all_five"] = (len(entries) == 5
        and {e.get("global_cpu") for e in entries} == set(CPU_ROLES)
        and all(e.get("original_entry_verified") is True and e.get("original_instructions_verified") is True
            and len(e.get("instruction_bytes", "")) == 64
            and e.get("instruction_bytes") == e.get("original_bytes")
            and int(e.get("registers", {}).get("r15", "0"), 16) == (0x080002b4 if e.get("role") == "MCU" else ENTRY)
            for e in entries))
    def e6_mpidr_matches(e):
        try:
            cpu = e["global_cpu"]
            role, local = CPU_ROLES[cpu]
            actual = cpu_map[cpu]
            value = actual.get("MPIDR")
            aliases = {n: v for n, v in e.get("registers", {}).items() if n.upper().startswith("MPIDR")}
            return (role != "MCU" and type(value) is int and value >= 0
                and (value & 0xffffff) == local and actual.get("local_cpu") == local
                and e.get("E6_MPIDR_QOM") == value
                and all((int(v, 16) & 0xffffff) == local for v in aliases.values()))
        except (KeyError, TypeError, ValueError):
            return False
    e6_entries = [e for e in entries if e.get("role") in ("master", "slave")]
    checks["E6_local_MPIDR_0_1"] = (len(e6_entries) == 4
        and {e.get("global_cpu") for e in e6_entries} == set(range(4))
        and all(e6_mpidr_matches(e) for e in e6_entries))
    arch["MPIDR_observation_scope"] = "actual E6 QOM values; guest MRC validation belongs to separate architecture regression"
    arch["MCU_architectural_MPIDR_claimed"] = False
    domains = qom.get("domains", [])
    domain_map = {d.get("role"): d for d in domains if isinstance(d, dict)}
    roots = [d.get("memory_root_qom_path") for d in domain_map.values()]
    checks["three_private_memory_roots"] = (set(domain_map) == set(ROLE_CPU) and all(roots) and len(set(map(str, roots))) == 3)
    checks["CPU_AddressSpace_belongs_to_role"] = (len(cpu_map) == 5 and all(
        c.get("role") == role and c.get("local_cpu") == local
        and c.get("cpu_memory_root_qom_path") == domain_map.get(role, {}).get(
            "cpu_memory_root_qom_path" if role == "MCU" else "memory_root_qom_path")
        and (domain_map.get(role, {}).get("cpu_root_layers_board_memory") is True if role == "MCU"
             else c.get("cpu_root_matches_owner") is True)
        for i, (role, local) in CPU_ROLES.items() for c in [cpu_map.get(i, {})]))
    blocks, private_complete = {}, set(domain_map) == set(ROLE_CPU)
    for role in ROLE_CPU:
        d = domain_map.get(role, {})
        rows = d.get("private_RAMBlocks", []) if role != "MCU" else [{
            "ram_backing_id": d.get("private_ram_backing_id"), "mapped_address": d.get("private_ram_address"),
            "bytes": d.get("private_ram_bytes"), "QEMU_ram_offset": d.get("private_ram_QEMU_offset")}]
        good = bool(rows) and all(isinstance(r, dict) and isinstance(r.get("ram_backing_id"), str)
            and bool(r["ram_backing_id"]) and all(type(r.get(k)) is int and r[k] >= 0
            for k in ("mapped_address", "QEMU_ram_offset")) and type(r.get("bytes")) is int and r["bytes"] > 0 for r in rows)
        private_complete &= good and d.get("private_ram_backing_id") == rows[0].get("ram_backing_id") if rows else False
        blocks[role] = rows if good else []
    private_ids = {role: {b["ram_backing_id"] for b in rows} for role, rows in blocks.items()}
    private_distinct = all(private_ids[a].isdisjoint(private_ids[b]) for a, b in
                           (("master", "slave"), ("master", "MCU"), ("slave", "MCU")))
    offsets_distinct = all(x["QEMU_ram_offset"] + x["bytes"] <= y["QEMU_ram_offset"]
        or y["QEMU_ram_offset"] + y["bytes"] <= x["QEMU_ram_offset"]
        for a, b in (("master", "slave"), ("master", "MCU"), ("slave", "MCU"))
        for x in blocks[a] for y in blocks[b])
    checks["three_private_RAM_backing_identities"] = bool(private_complete and private_distinct and offsets_distinct)
    shared, shared_complete = {}, True
    for role in ("master", "slave"):
        rows = domain_map.get(role, {}).get("shared_apertures")
        if not isinstance(rows, list) or not rows:
            shared_complete = False
            continue
        for row in rows:
            if (not isinstance(row, dict) or not isinstance(row.get("ram_backing_id"), str)
                    or not row.get("ram_backing_id") or row.get("same_RAMBlock") is not True
                    or not all(type(row.get(k)) is int and row[k] >= 0 for k in
                        ("offset", "bytes", "backing_bytes", "mapped_address"))
                    or row.get("bytes", 0) <= 0 or row["offset"] + row["bytes"] > row["backing_bytes"]):
                shared_complete = False
                continue
            shared.setdefault(row["ram_backing_id"], []).append(dict(row, role=role))
    checks["shared_apertures_use_canonical_RAMBlocks"] = (shared_complete and bool(shared)
        and type(qom.get("shared_RAMBlock_count")) is int and len(shared) == qom["shared_RAMBlock_count"]
        and all({r["role"] for r in rows} == {"master", "slave"}
            and len({r["backing_bytes"] for r in rows}) == 1 for rows in shared.values())
        and set(shared).isdisjoint(set().union(*private_ids.values())))
    checks["all_domains_use_QEMU_CLOCK_VIRTUAL"] = (set(domain_map) == set(ROLE_CPU)
        and qom.get("clock") == "QEMU_CLOCK_VIRTUAL" and all(d.get("clock") == "QEMU_CLOCK_VIRTUAL" for d in domain_map.values())
        and all(domain_map.get(r, {}).get("counter_frequency_hz") == 48000000 for r in ("master", "slave")))
    checks["E6_generic_timer_exact_48MHz_conversion"] = (set(cpu_map) == set(range(5))
        and all(cpu_map[i].get("generic_timer_frequency_hz") == 48000000
                and cpu_map[i].get("generic_timer_exact_frequency") is True for i in range(4)))
    mcu = domain_map.get("MCU", {})
    checks["MCU_and_master_share_one_wire_bus_object"] = mcu.get("single_wire_bus_object") is True
    reset_fields = ("SYSRESETREQ_count", "local_reset_count", "system_reset_count", "last_reset_virtual_ns")
    checks["MCU_local_reset_route_and_counters_observable"] = (mcu.get("SYSRESETREQ_connected_to_MCU_domain") is True
        and type(mcu.get("reset_pending")) is bool and all(type(mcu.get(k)) is int and mcu[k] >= 0 for k in reset_fields)
        and all(type(cpu_map.get(i, {}).get(k)) is int and cpu_map[i][k] >= 0 for i in range(4)
                for k in ("system_reset_count", "last_system_reset_virtual_ns")))
    roms = {e["role"]: e["instruction_bytes"] for e in entries if e["local_core"] == 0 and e["role"] != "MCU"}
    checks["same_VA_role_ROM_reads_match_private_inputs"] = (set(roms) == {"master", "slave"}
        and len(entries) == 5 and all(e["original_instructions_verified"] for e in entries if e["role"] != "MCU"))
    # ROM entries can share an initial trampoline. Distinct backing metadata
    # and complete role input identities carry isolation evidence in that case.
    arch["role_entry_ROM_bytes_differ"] = len(set(roms.values())) == 2
    actual_gics = arch.get("actual_GICs", [])
    checks["two_private_GICs_local_two_CPUs"] = (len(actual_gics) == 2 and
        len({g.get("qom_path") for g in actual_gics if g.get("qom_path")}) == 2 and
        {(g.get("role"), g.get("first_cpu_index"), g.get("num_cpu")) for g in actual_gics}
        == {("master", 0, 2), ("slave", 2, 2)} and all(
            not g.get("QOM_errors") and g.get("num_cpu_QOM") == g.get("num_cpu")
            and g.get("first_cpu_index_QOM") == g.get("first_cpu_index") for g in actual_gics))
    freezes = arch.get("clock_samples", [])
    def frozen(phase):
        return any(s.get("phase") == phase and type(s.get("first_ns")) is int
            and s.get("first_ns") == s.get("second_ns") and s.get("QMP_status", {}).get("running") is False for s in freezes)
    initial_times = [s["first_ns"] for s in freezes if s.get("phase") == "initial" and type(s.get("first_ns")) is int]
    advancing = [s for s in arch.get("running_clock_samples", []) if type(s.get("virtual_ns")) is int
                 and s.get("QMP_status", {}).get("running") is True]
    checks["initial_stop_clock_frozen"] = frozen("initial")
    checks["continued_virtual_clock_advanced"] = bool(initial_times) and any(s["virtual_ns"] > initial_times[0] for s in advancing)
    checks["observed_virtual_clock_monotonic"] = (arch.get("clock_observation_count", 0) >= 2
        and not arch.get("virtual_clock_regressions"))
    checks["final_stop_clock_frozen"] = frozen("final")
    resets = {"status": "not_observed", "actual_local_reset_behavior_verified": False,
              "SRAM_Flash_RTC_and_master_ACK_retention_verified": False, "count_transitions": []}
    states = [s.get("state", {}) for s in arch.get("QOM_snapshots", [])]
    for before, after in zip(states, states[1:]):
        a = next((d for d in before.get("domains", []) if d.get("role") == "MCU"), {})
        b = next((d for d in after.get("domains", []) if d.get("role") == "MCU"), {})
        if not all(type(d.get(k)) is int for d in (a, b) for k in reset_fields):
            continue
        delta = b["local_reset_count"] - a["local_reset_count"]
        if delta > 0:
            ca = {c.get("global_cpu_index"): c for c in before.get("cpus", [])}
            cb = {c.get("global_cpu_index"): c for c in after.get("cpus", [])}
            isolated = (b["SYSRESETREQ_count"] > a["SYSRESETREQ_count"] and b["system_reset_count"] == a["system_reset_count"]
                and all(type(ca.get(i, {}).get("system_reset_count")) is int
                    and ca[i]["system_reset_count"] == cb.get(i, {}).get("system_reset_count") for i in range(4)))
            resets["count_transitions"].append({"before_virtual_ns": before.get("virtual_ns"),
                "after_virtual_ns": after.get("virtual_ns"), "local_reset_delta": delta,
                "E6_system_reset_counts_unchanged": isolated, "reset_pending_after": b.get("reset_pending")})
    if resets["count_transitions"]:
        resets["status"] = "local_reset_count_transition_observed"
    return {"checks": checks, "passed": bool(checks) and all(v is True for v in checks.values()),
        "private_RAMBlocks_observed": blocks, "canonical_shared_RAMBlocks_observed": shared,
        "MCU_local_reset_observation": resets, "RAM_mutation_isolation_test_performed": False,
        "active_GIC_SGI_PPI_and_reset_isolation_regression_included": False,
        "isolation_scope": "read-only CPU ownership and actual RAMBlock identities; active fixture regression is separate",
        "clock_is_physical_frequency_or_reset_proof": False}


def architecture_checks(session, report, phase="final"):
    arch = session.architecture
    session.read_architecture_qom(phase)
    actual_gics = []
    for gic in (arch.get("QOM") or {}).get("gics", []):
        item = dict(gic)
        for prop, key in (("num-cpu", "num_cpu_QOM"), ("first-cpu-index", "first_cpu_index_QOM")):
            try:
                item[key] = session.qmp("qom-get", {"path": gic["qom_path"], "property": prop})
            except Exception as exc:
                item.setdefault("QOM_errors", []).append(error_text(exc))
        actual_gics.append(item)
    arch["actual_GICs"] = actual_gics
    arch.update(evaluate_architecture(arch, report))
    arch.update(evidence_phase=phase, snapshot_epoch=session.stop_epoch,
                snapshot_virtual_ns=arch["QOM"].get("virtual_ns"), snapshot_observed_UTC=utc())
    future = {"continued_virtual_clock_advanced", "final_stop_clock_frozen"}
    arch["initial_snapshot_checks"] = {k: v for k, v in arch["checks"].items() if k not in future}
    arch["initial_snapshot_verified"] = bool(arch["initial_snapshot_checks"]) and all(
        v is True for v in arch["initial_snapshot_checks"].values())
    arch["final_evidence_available"] = phase == "final"
    return arch


class NativeObservations:
    def __init__(self, session, baseline, mcu, prepared, report):
        from natural_boot import OBSERVERS, PEER_BUSINESS_OBSERVERS, PEER_PARAMETER_OBSERVERS, DISPLAY_CONFIG_OBSERVERS
        from ex1850_battery_config import ConfigObserver, POINTS as CONFIG_POINTS, MAX_HITS
        from ex1850_battery_task import TaskObserver, POINTS as TASK_POINTS
        self.s, self.blobs, self.report = session, prepared["blobs"], report
        from native_ui_observer import UIObserver
        self.ui = UIObserver(path(baseline.get("ui-observation-plan"), session.run), self.blobs) \
            if baseline.get("ui-observation-plan") else None
        self.config = ConfigObserver(self.blobs["MCU"]) if mcu.get("battery-config-trace") else None
        self.task = TaskObserver(self.blobs["MCU"]) if mcu.get("battery-task-trace") else None
        self.config_points, self.task_points, self.max_hits = CONFIG_POINTS, TASK_POINTS, MAX_HITS
        self.generic = {role: dict(PEER_BUSINESS_OBSERVERS[role] if baseline.get("peer-business-trace-only")
                                   else OBSERVERS[role]) for role in ("master", "slave")}
        for role, sites in (("master", (0x10200034, 0x10200042)), ("slave", (0x10052f74, 0x10052f7e))):
            self.generic[role].update({a: OBSERVERS[role][a] for a in sites})
        if baseline.get("peer-parameter-trace"):
            self.generic["slave"].update(PEER_PARAMETER_OBSERVERS)
        if baseline.get("display-config-trace"):
            self.generic["master"].update(DISPLAY_CONFIG_OBSERVERS)
        self.generic["MCU"] = {int(v, 0): "recipe-selected original MCU instruction" for v in mcu.get("observe-address", [])}
        self.counts = Counter()
        self.events = []
        self.breakpoints = BreakpointUnion(session)
        self.write_watchpoints = WriteWatchpointUnion(session)
        self.started_host = time.monotonic()
        self.report.update(original_battery_config_events=[], original_battery_task_events=[],
            original_ui_events=[], original_RAM_write_events=[], ui_observation_plan=self.ui.identity if self.ui else None,
            original_cmd89_transaction_returns=[], observations=[], observation_limits=[], unassigned_stops=[],
            battery_config_trace_enabled=self.config is not None, battery_task_trace_enabled=self.task is not None,
            battery_config_trace_limit_reached=[], battery_task_trace_limit_reached=[])
        self.sync()

    def sites(self):
        sites = {}
        for role, points in self.generic.items():
            for address, label in points.items():
                limit = 32 if role == "MCU" and address in (0x08023ed4, 0x08023fae, 0x080244e0, 0x080247cc) else (4 if role != "MCU" else 1)
                if self.counts[("generic", role, address)] < limit:
                    sites[(role, address)] = {"generic": label}
        for category, observer, points, active in (("config", self.config, self.config_points, True),
                ("task", self.task, self.task_points, self.task is not None and self.task.activation is not None)):
            if observer is None or not active:
                continue
            for address in set(points) | observer.return_points():
                if self.counts[(category, "MCU", address)] < self.max_hits:
                    sites.setdefault(("MCU", address), {})[category] = points.get(address, "paired original return")
        if self.ui is not None:
            for key, label in self.ui.sites().items():
                sites.setdefault(key, {})["ui"] = label
        return sites

    def sync(self):
        self.breakpoints.replace(self.sites())
        self.write_watchpoints.replace(self.ui.write_sites() if self.ui is not None else {})

    def advance(self, now):
        if self.ui is not None and self.ui.advance(now):
            was_running = self.s.running
            # Z1/z1 are debugger commands and must only run at a confirmed
            # common stop. Time-window renewal can also happen between hits.
            frozen = self.s.interrupt() if was_running else None
            stopped_now = self.s.clock()
            self.ui.advance(stopped_now)
            self.sync()
            self.report.setdefault("UI_window_rearm_controls", []).append(
                dict(window_index=self.ui.window_index, virtual_time_ns=stopped_now,
                     was_running=was_running, common_stop=frozen,
                     guest_state_written=False))
            if was_running:
                self.s.resume()

    def stop(self, packet):
        cpu = self.s.stopped_cpu(packet)
        role, local = CPU_ROLES[cpu]
        regs = self.s.registers(cpu)
        address = int(regs["r15"], 16) & ~1
        now = self.s.clock()
        watched = re.search(r"(?:^|;)watch:([0-9a-f]+);", packet[3:])
        if watched:
            watched_address = int(watched[1], 16)
            ranges = [size for pointer, size in self.write_watchpoints.installed if pointer == watched_address]
            if len(ranges) != 1:
                raise RuntimeError("Write stop does not identify an installed watched range")
            watched_size = ranges[0]
            self.advance(now)
            self.write_stop(packet, cpu, role, local, regs, address, now, watched_address, watched_size)
            return
        self.advance(now)
        labels = self.breakpoints.desired.get((role, address), {})
        event = dict(index=len(self.events), stop_epoch=self.s.stop_epoch, virtual_time_ns=now,
            global_cpu=cpu, local_core=local, role=role, thread=self.s.threads[cpu], PC=hex(address),
            registers=regs, labels=labels, stop_reply=packet, guest_state_written=False)
        if not labels:
            event["classification"] = "foreign-domain-breakpoint" if address in self.breakpoints.installed else "unassigned-stop"
            self.report["unassigned_stops"].append(event)
            if address not in self.breakpoints.installed:
                raise RuntimeError("Unexpected CPU stop; no event was assigned by coincident PC")
            self.events.append(event)
            self.write_event(event)
            self.breakpoints.step(cpu, address)
            self.sync()
            return
        base = MCU_BASE if role == "MCU" else ENTRY
        offset = address - base
        source = self.blobs[role]
        if not 0 <= offset <= len(source)-4:
            raise ValueError("Observer site is outside its own original ROM")
        original = source[offset:offset+4]
        actual = self.s.read_va(cpu, address, 4)
        event.update(original_ROM_bytes=original.hex(), actual_ROM_bytes=actual.hex(), original_ROM_verified=actual == original)
        if actual != original:
            raise ValueError("Original site bytes differ in selected CPU AddressSpace")
        reader = RoleRemote(self.s, cpu)
        obs = {"observation_sequence": len(self.events), "host_elapsed_seconds": time.monotonic()-self.started_host,
               "HAL_tick": int.from_bytes(reader.memory(0x20020400, 4), "little") if role == "MCU" else None,
               "original_ROM_bytes": actual.hex()}
        event.update(obs, address=hex(address))
        if "generic" in labels:
            self.counts[("generic", role, address)] += 1
        if "ui" in labels:
            item = self.ui.on_stop(reader, role, address, regs,
                dict(observation_sequence=event["observation_sequence"], role=role,
                     global_cpu=cpu, local_core=local, stop_epoch=self.s.stop_epoch,
                     virtual_time_ns=now, PC=hex(address), registers=regs,
                     original_ROM_bytes=actual.hex(), original_ROM_verified=True,
                     guest_state_written=False))
            self.report["original_ui_events"].append(item)
            event["original_ui_event"] = item
        if role == "MCU":
            self.battery_return(reader, address, regs, event)
            for category, observer in (("config", self.config), ("task", self.task)):
                if category not in labels:
                    continue
                new_events = observer.on_stop(reader, address, regs, obs)
                self.counts[(category, role, address)] += 1
                for item in new_events:
                    item.update(global_cpu=cpu, local_core=local, role=role,
                                stop_epoch=self.s.stop_epoch, virtual_time_ns=now)
                self.report["original_battery_" + category + "_events"].extend(new_events)
                event["original_battery_" + category + "_events"] = new_events
                if category == "config" and self.task is not None:
                    self.task.activate(new_events)   # actual nonzero original copy completion only
                    self.report["battery_task_trace_activation"] = self.task.activation
                if self.counts[(category, role, address)] >= self.max_hits:
                    self.report["observation_limits"].append({"observer": category, "entry": hex(address), "max_hits": self.max_hits})
                    self.report["battery_" + category + "_trace_limit_reached"].append(hex(address))
            self.report["observations"].append(event)
        self.events.append(event)
        self.write_event(event)
        self.sync()                                  # preserves every observer's return-site union
        self.breakpoints.step(cpu, address)
        self.sync()

    def write_stop(self, packet, cpu, role, local, regs, pc, now, watched_address, watched_size):
        labels = self.write_watchpoints.desired.get((role, watched_address))
        event = dict(index=len(self.events), observation_sequence=len(self.events),
            observation_kind="RAM-write-watchpoint", stop_epoch=self.s.stop_epoch,
            virtual_time_ns=now, global_cpu=cpu, local_core=local, role=role,
            thread=self.s.threads[cpu], PC=hex(pc), registers=regs, stop_reply=packet,
            watched_address=hex(watched_address), watched_bytes=watched_size,
            stop_before_access=True, guest_state_written=False)
        base = MCU_BASE if role == "MCU" else ENTRY
        offset = pc-base
        source = self.blobs[role]
        if 0 <= offset <= len(source)-4:
            original = source[offset:offset+4]
            actual = self.s.read_va(cpu, pc, 4)
            event.update(original_ROM_bytes=original.hex(), actual_ROM_bytes=actual.hex(),
                         original_ROM_verified=actual == original)
            if actual != original:
                raise ValueError("Write observer instruction differs from its role's original ROM")
        else:
            event.update(original_ROM_verified=False, writer_attribution="PC outside retained original ROM")
        if labels:
            before = self.s.read_va(cpu, watched_address, watched_size)
            event["watched_before_hex"] = before.hex()
            item = self.ui.on_stop(RoleRemote(self.s, cpu), role, watched_address, regs, dict(event))
            event["original_ui_event"] = item
            self.report["original_ui_events"].append(item)
        else:
            event["classification"] = "foreign-domain-or-inactive-write-watchpoint"
        step_reply = self.write_watchpoints.step(cpu, pc, self.breakpoints)
        event.update(after_original_instruction_stop=step_reply, after_stop_epoch=self.s.stop_epoch,
                     after_virtual_time_ns=self.s.clock())
        if labels:
            after = self.s.read_va(cpu, watched_address, watched_size)
            event["watched_after_hex"] = after.hex()
            event["value_changed"] = before != after
            item.update(watched_before_hex=before.hex(), watched_after_hex=after.hex(),
                        value_changed=before != after, after_stop_epoch=self.s.stop_epoch,
                        after_virtual_time_ns=self.s.clock())
        self.events.append(event)
        self.report["original_RAM_write_events"].append(event)
        self.write_event(event)
        self.sync()

    def write_event(self, event):
        with (self.s.run / "native-original-observations.jsonl").open("a") as output:
            output.write(json.dumps(event, ensure_ascii=False) + "\n")

    def battery_return(self, reader, address, regs, event):
        def ram(pointer, size):
            if not MCU_RAM <= pointer <= MCU_RAM + RAM_SIZE - size:
                raise ValueError("Battery return read outside original MCU SRAM")
            return reader.memory(pointer, size)
        if address in (0x08023ed4, 0x08023fae):
            pointer = int(regs["r4"], 16)
            raw = ram(pointer, 64)
            context = dict(entry=hex(address), body_address=hex(pointer), body_hex=raw.hex(), ready=raw[0],
                comparator_result_stored=int.from_bytes(raw[4:8], "little"),
                error=int.from_bytes(raw[0x14:0x18], "little", signed=True), battery_type=raw[0x29], status=raw[0x2c],
                original_ROM_bytes=event["original_ROM_bytes"], guest_state_written=False, live_nonce_or_H_read=False)
            if address == 0x08023ed4:
                key = "original_battery_authentication_comparator"
                context.update(comparator_return=int(regs["r0"], 16), scope="original comparator bool before body+4 store")
            else:
                key = "original_battery_authentication_completion"
                context.update(scope="original authentication tail after ready store; R0 excluded")
            event[key] = self.report[key] = context
        if address in (0x080244e0, 0x080247cc):
            source = self.blobs["MCU"]
            if source[address-MCU_BASE:address-MCU_BASE+2] != bytes.fromhex("0446"):
                raise ValueError("Original cmd89 caller instruction differs")
            root = int.from_bytes(source[0x23934:0x23938], "little")
            pointer = int(regs["r5"], 16)
            control, tx, rx, body = ram(root, 6), ram(root+0x70, 18), ram(root+0x88, 4), ram(pointer, 64)
            context = dict(schema="original-cmd89-transaction-return/1", entry=hex(address),
                occurrence=self.counts[("generic", "MCU", address)], observation_sequence=event["observation_sequence"],
                host_elapsed_seconds=event["host_elapsed_seconds"], HAL_tick=event["HAL_tick"],
                builder_entry="0x080243dc" if address == 0x080244e0 else "0x080246c4",
                common_validator="0x08023824", returned_R0=int(regs["r0"], 16),
                transaction_root=hex(root), control_hex=control.hex(), TX_hex=tx.hex(), RX_hex=rx.hex(),
                original_instruction_bytes="0446", body_address=hex(pointer), body_hex=body.hex(), ready=body[0],
                error=int.from_bytes(body[0x14:0x18], "little", signed=True), body_mode=body[0x2e],
                info72_address="0x2001f4a0", info72_hex=ram(0x2001f4a0, 72).hex(),
                auxiliary2_address="0x2000ed99", auxiliary2_hex=ram(0x2000ed99, 2).hex(),
                guest_state_written=False, live_nonce_or_H_read=False,
                scope="original validator returned to its real caller; strict synthetic battery input unchanged")
            event["original_cmd89_transaction_return"] = context
            self.report["original_cmd89_transaction_returns"].append(context)

    def finish(self):
        if self.ui is not None:
            self.report["ui_observation_completion"] = self.ui.completion()
        self.report["original_observation_count"] = len(self.events)
        self.report["original_boot_task_observations"] = [e for e in self.events if e.get("original_ROM_verified") and
            int(e["PC"], 0) in BOOT_TASK_PCS]
        if self.config is not None:
            self.report["battery_config_trace_completion"] = dict(observed_events=len(self.config.events),
                unmatched_conversion_entries=sum(len(v) for v in self.config.conversions.values()),
                unmatched_copy_entries=sum(len(v) for v in self.config.copies.values()),
                pending_return_points=[hex(p) for p in sorted(self.config.return_points())],
                guest_state_written=False, peripheral_MMIO_read_by_debugger=False)
        if self.task is not None:
            self.report["battery_task_trace_activation"] = self.task.activation
            self.report["battery_task_trace_completion"] = self.task.completion()


def stopped_evidence(session, baseline, prepared, report):
    status = session.qmp("query-status")
    stopped = session.running is False and status.get("running") is False
    if not stopped:
        raise RuntimeError("Final reads require the actual common stopped QEMU state")
    gate = {"schema": "z62.native-common-stop/1", "complete": stopped, "stop_epoch": session.stop_epoch,
            "virtual_time_ns": session.clock(), "sequential_reads_while_common_clock_frozen": True,
            "QMP_status": status, "sampling_complete": False, "simultaneous_sampling_claim": False,
            "roles": {role: {"pause_confirmed": True, "global_cpu": cpu} for role, cpu in ROLE_CPU.items()}}
    report["common_stop"] = gate
    if float(baseline.get("lcd-snapshot-interval", 0)) > 0:
        sample = {"virtual_time_ns_before": gate["virtual_time_ns"],
                  "source": "QMP default display console", "evidence_phase": "final_common_stop",
                  "role_assignment_verified": False, "MENU_acceptance_implied": False}
        try:
            p = session.run / f"native-console-{len(report['UI']['samples']):04d}.ppm"
            sample["QMP_return"] = session.qmp("screendump", {"filename": str(p)})
            sample["image"] = identity(p)
            sample["virtual_time_ns_after"] = session.clock()
        except Exception as exc:
            sample["error"] = error_text(exc)
        report["UI"]["samples"].append(sample)
    if baseline.get("task-observation-plan"):
        from expeed_task_observer import load_plan, observe
        plan, plan_identity = load_plan(path(baseline.get("task-observation-plan"), session.run), prepared["blobs"])
        report["task_observation_plan"] = plan_identity
        report["task_RAM"] = {}
        for role in ("master", "slave"):
            target = session.run / role / "final-task-RAM"
            try:
                value = observe(RoleView(session, role), plan["roles"][role], target, gate)
                report["task_RAM"][role] = {"report": str(target / "任务RAM观察.json"),
                    "common_stop_epoch": session.stop_epoch, "selected_global_cpu": ROLE_CPU[role],
                    "collector_global_snapshot_clock_field_is_legacy": True,
                    "complete_within_plan": value.get("complete_within_plan") if isinstance(value, dict) else None}
            except Exception as exc:
                report["task_RAM"][role] = {"error": error_text(exc), "report": str(target / "任务RAM观察.json")}
    loader = prepared["loader"]
    if loader:
        report["Loader_payloads"] = {"reference": loader, "regions": [], "physical_Flash_cold_boot_verified": False}
        for entry in loader["regions"]:
            p = session.run / "master" / ("region" + entry["region"] + "-runtime-VA.bin")
            item = {"region": entry["region"], "VA": entry["address"], "global_cpu": 0, "reference": entry["reference"],
                    "stop_epoch": session.stop_epoch, "address_kind": "CPU-selected VA"}
            try:
                item["MMU_registers"] = session.registers(0, system=True)
                arguments = {"val": int(entry["address"], 0), "size": entry["bytes"], "filename": str(p), "cpu-index": 0}
                item["QMP_return"] = session.qmp("memsave", arguments)
                item["QMP_arguments"] = arguments
                actual = identity(p)
                item.update(runtime=actual, complete=actual["bytes"] == entry["bytes"],
                            full_SHA_matches_recorded_RAM=actual["bytes"] == entry["bytes"] and
                            actual["sha256"] == entry["reference"]["sha256"])
            except Exception as exc:
                item["error"] = error_text(exc)
            report["Loader_payloads"]["regions"].append(item)
        rows = report["Loader_payloads"]["regions"]
        report["Loader_payloads"]["all_payloads_match_recorded_RAM"] = bool(rows) and all(
            r.get("full_SHA_matches_recorded_RAM") is True for r in rows)
    p = session.run / "MCU" / "final-SRAM.bin"
    try:
        p.write_bytes(session.read_va(4, MCU_RAM, RAM_SIZE))
        report["MCU_final_SRAM"] = dict(identity(p), address_kind="CPU4 VA", stop_epoch=session.stop_epoch)
        report["budget_SRAM_snapshot"] = report["MCU_final_SRAM"]
    except Exception as exc:
        report["MCU_final_SRAM"] = {"available": False, "error": error_text(exc)}
    report["SAISO_UI_RAM"] = []
    for address, size, label in SAISO_FINAL_SAMPLES:
        item = dict(label=label, address=hex(address), bytes=size, global_cpu=0, role="master", stop_epoch=session.stop_epoch)
        try:
            raw = session.read_va(0, address, size)
            item.update(raw_hex=raw.hex(), sha256=hashlib.sha256(raw).hexdigest())
        except Exception as exc:
            item["error"] = error_text(exc)
        report["SAISO_UI_RAM"].append(item)
    report["final_core_registers"] = []
    for cpu, (role, local) in CPU_ROLES.items():
        item = {"global_cpu": cpu, "role": role, "local_core": local}
        try:
            item["registers"] = session.registers(cpu, system=True)
        except Exception as exc:
            item["error"] = error_text(exc)
        report["final_core_registers"].append(item)
    expected_tasks = {"master", "slave"} if baseline.get("task-observation-plan") else set()
    expected_loader = {e["region"] for e in loader["regions"]} if loader else set()
    task_rows = report.get("task_RAM", {})
    loader_rows = report.get("Loader_payloads", {}).get("regions", [])
    gate["sampling_complete"] = ("sha256" in report["MCU_final_SRAM"]
        and report["MCU_final_SRAM"].get("bytes") == RAM_SIZE
        and len(report["final_core_registers"]) == len(CPU_ROLES)
        and all("registers" in item for item in report["final_core_registers"])
        and len(report["SAISO_UI_RAM"]) == len(SAISO_FINAL_SAMPLES)
        and all("error" not in item for item in report["SAISO_UI_RAM"])
        and set(task_rows) == expected_tasks
        and all(item.get("complete_within_plan") is True for item in task_rows.values())
        and len(loader_rows) == len(expected_loader)
        and {item.get("region") for item in loader_rows} == expected_loader
        and all(item.get("complete") is True for item in loader_rows))


def final_evidence_status(report, architecture, status):
    """QOM availability and completion of all requested final samples differ."""
    gate = report.get("common_stop", {})
    missing = []
    if gate.get("complete") is not True:
        missing.append("final_common_stop")
    if gate.get("sampling_complete") is not True:
        missing.append("final_registers_SRAM_task_RAM_and_Loader_samples")
    if architecture.get("final_evidence_available") is not True:
        missing.append("final_QOM")
    return {"available": architecture.get("final_evidence_available") is True,
            "complete": not missing, "status": status if not missing else "final_samples_incomplete",
            "stop_epoch": architecture.get("snapshot_epoch"),
            "virtual_ns": architecture.get("snapshot_virtual_ns"),
            "common_stop_complete": gate.get("complete") is True,
            "sampling_complete": gate.get("sampling_complete") is True, "missing": missing}


def debugger_write_audit(session):
    """Audit actual retained outgoing protocol bytes, not default zero counters."""
    rsp, qmp = session.rsp_ledger.summary(), session.qmp_ledger.summary()
    for name, value in (("RSP", rsp), ("QMP", qmp)):
        value["IO_ledger"] = identity(session.run / (name + "-io.jsonl"))
    raw = Path(rsp["streams"]["tx"]["path"]).read_bytes()
    packets, cursor, complete = [], 0, True
    while True:
        start = raw.find(b"$", cursor)
        if start < 0:
            break
        end = raw.find(b"#", start+1)
        if end < 0 or end+3 > len(raw):
            complete = False
            break
        payload = raw[start+1:end]
        if sum(payload) % 256 != int(raw[end+1:end+3], 16):
            complete = False
        packets.append(payload)
        cursor = end+3
    forbidden_rsp = [p.decode(errors="replace") for p in packets if p.startswith((b"M", b"X", b"P", b"G", b"vFlash", b"qRcmd"))
                     or p.startswith(b"Q") and p not in (b"Qqemu.PhyMemMode:0", b"Qqemu.PhyMemMode:1")]
    qmp_commands = [json.loads(line) for line in Path(qmp["streams"]["tx"]["path"]).read_bytes().splitlines()]
    forbidden_qmp = [v for v in qmp_commands if v.get("execute") in ("pmemsave", "human-monitor-command") or
        v.get("execute") == "qom-set" and v.get("arguments", {}).get("property") != "pcal-pin-levels" and
        not re.fullmatch(r"gpio-pin-levels-[A-H]", v.get("arguments", {}).get("property", ""))]
    verified = (bool(packets) and bool(qmp_commands) and complete and not forbidden_rsp and not forbidden_qmp
                and rsp["complete_successful_IO_capture"] and qmp["complete_successful_IO_capture"])
    return {"schema": "z62.native-debugger-zero-writes/1", "verified": bool(verified),
        "actual_guest_RAM_register_write_count": 0 if verified else None,
        "RSP_packets": len(packets), "QMP_commands": len(qmp_commands), "forbidden_RSP_packets": forbidden_rsp,
        "forbidden_QMP_commands": forbidden_qmp, "RSP": rsp, "QMP": qmp,
        "scope": "the two actual complete debugger connections; initial original-entry loader configuration is separate",
        "Qqemu_PhyMemMode_changes_debugger_addressing_only": True,
        "external_pad_QOM_sets_are_guest_peripheral_inputs": True, "device_internal_guest_write_audit_implied": False}


def run_main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    ap.add_argument("--output-dir", type=Path, required=True)
    ap.add_argument("--baseline-command-json", type=Path, required=True)
    ap.add_argument("--mcu-profile-json", type=Path, required=True)
    ap.add_argument("--qemu-manifest", type=Path, required=True)
    ap.add_argument("--mcu-manifest", type=Path, required=True)
    ap.add_argument("--mcu-auxiliary-power-spec", type=Path)
    ap.add_argument("--bus-tool", type=Path, required=True)
    ap.add_argument("--seconds", type=float, default=8)
    ap.add_argument("--virtual-seconds", type=float,
                    help="Observation limit since the common virtual clock origin; seconds is the host safety limit")
    ap.add_argument("--poll-ns", type=int, required=True)
    ap.add_argument("--known-wait-ms", type=int, default=0)
    ap.add_argument("--resource-startup-barrier", action="store_true")
    ap.add_argument("--startup-barrier-timeout", type=float, default=60)
    ap.add_argument("--run-number", type=int, default=0)
    args = ap.parse_args(argv)
    if not math.isfinite(args.seconds) or args.seconds <= 0 or args.poll_ns <= 0 or args.known_wait_ms < 0:
        ap.error("Host seconds/poll-ns must be positive; known-wait-ms must be nonnegative")
    if args.virtual_seconds is not None and (not math.isfinite(args.virtual_seconds) or
                                             not 1e-9 <= args.virtual_seconds <= 1200):
        ap.error("Virtual observation limit must be finite and within 1ns..1200s")
    os.chdir(ROOT)
    run = args.output_dir.resolve()
    run.mkdir(parents=True, exist_ok=True)
    if any((run / name).exists() for name in ("QEMU-process-lifecycle.json", "native-unified-result.json")):
        raise RuntimeError("A unified run must use a fresh output directory")
    lifecycle = ProcessLedger(run, "unified")
    report = {"schema": "z62.native-unified-result/1", "started": utc(), "run_number": args.run_number,
        "machine": MACHINE, "budget_host_seconds": args.seconds, "one_owner": True,
        "observation_budget": {"host_safety_seconds": args.seconds,
            "requested_virtual_seconds": args.virtual_seconds, "virtual_limit_reached": False,
            "stop_reason": "not_stopped", "timebase": "QEMU_CLOCK_VIRTUAL_since_owner_origin"},
        "camera_access": False, "status": "preflight", "host_operation_completed": False,
        "architecture": {"passed": False}, "debugger_zero_guest_writes": {"verified": False, "actual_guest_RAM_register_write_count": None},
        "boundaries": {"movie_disp_completed": False, "stable_MENU_entry_exit_reentry_verified": False,
            "E6_physical_Flash_cold_boot_verified": False, "full_natural_camera_boot_verified": False,
            "physical_reset_and_clock_relationship_verified": False, "hardware_unknowns_resolved": False},
        "guest_RAM_or_register_fixtures": [], "MCU_packet_replay": [], "nonce_bridge": False,
        "initial_CPU_loader_configuration": {"global_CPUs": [0, 1, 2, 3], "entry": hex(ENTRY), "MCU_reset_overridden": False},
        "DMA_PA_samples": {"status": "not_sampled", "pmemsave_used": False}, "UI": {"accepted": False, "samples": []}}
    report["harness_identity_at_start"] = identity(__file__)
    report["final_evidence"] = {"available": False, "complete": False, "status": "not_collected",
        "missing": ["final_common_stop", "final_QOM", "final_registers", "final_SRAM_and_task_RAM"]}
    target, state_path = run / "native-unified-result.json", run / "native-unified-state.json"
    save_json(target, report)
    session = process = log = pads = observations = prepared = None
    try:
        if args.resource_startup_barrier or args.mcu_auxiliary_power_spec:
            raise ValueError("RAM startup barrier/auxiliary configuration injection is incompatible with native zero-writes")
        baseline, mcu = recipes(args.baseline_command_json, args.mcu_profile_json)
        prepared = prepare_native(args, run, baseline, mcu, report)
        log = MeaningfulQemuLog(run / "qemu.log")
        lifecycle.attempting(prepared["command"])
        process = subprocess.Popen(prepared["command"], env=prepared["env"], cwd=run,
                                   stdout=log, stderr=subprocess.STDOUT)
        lifecycle.started(process)
        session = UnifiedSession(run, process, prepared["qmp_port"], prepared["gdb_port"], prepared["instance_uuid"])
        report["architecture"] = session.architecture
        session.pa_manifest_verified = report["selected_unified_build_contract"]["CPU_selected_PA_GDB_source_verified"] is True
        initial_observation(session, prepared, report)
        initial = copy.deepcopy(architecture_checks(session, report, "initial"))
        save_json(run / "native-initial-architecture.json", initial)
        report["initial_architecture"] = initial
        report["initial_architecture_evidence"] = identity(run / "native-initial-architecture.json")
        save_json(target, report)              # durable evidence before the first continue
        if initial["initial_snapshot_verified"] is not True:
            raise ValueError("Initial observed native architecture contract failed")
        if prepared["peer"] is not None:
            prepared["peer"].wait_connected()
        observations = NativeObservations(session, baseline, mcu, prepared, report)
        pads = PadInputs(session, mcu, prepared)
        origin = session.clock()
        virtual_end = origin + int(args.virtual_seconds * 1_000_000_000) if args.virtual_seconds is not None else None
        report["observation_budget"].update(virtual_origin_ns=origin, virtual_deadline_ns=virtual_end)
        state = {"schema": "z62.native-unified-state/1", "ready": True, "active": True,
                 "pid": process.pid, "owner_uuid": prepared["instance_uuid"],
                 "virtual_origin_ns": origin, "virtual_time_ns": origin,
                 "virtual_deadline_ns": virtual_end,
                 "input_channels": pads.public_channels(), "running": False, "host_sleep_is_guest_time": False}
        save_json(state_path, state)
        for kind in pads.channels:
            pads.publish(kind, {"sequence": 0, "running": True, "delivered": False})
        report["status"] = "observing_original_native_code"
        save_json(target, report)
        end = time.monotonic() + args.seconds
        screenshot_interval = float(baseline.get("lcd-snapshot-interval", 0))
        next_screenshot = time.monotonic() + screenshot_interval if screenshot_interval > 0 else float("inf")
        session.resume()
        while time.monotonic() < end:
            if process.poll() is not None:
                raise RuntimeError("Owned QEMU exited during the observation budget: " + str(process.returncode))
            if (run / "host-stop-request.json").exists():
                report["host_stop_request"] = read_json(run / "host-stop-request.json")
                raise RuntimeError("Explicit host stop requested")
            packet = session.receive_stop(0)
            if packet:
                observations.stop(packet)
                if not session.running:
                    session.resume()
            pads.poll()
            clock = session.clock()
            observations.advance(clock)
            if clock > origin:
                session.architecture["advanced_virtual_time_observed"] = True
            if session.running and len(session.architecture["running_clock_samples"]) < 64:
                status = session.qmp("query-status")
                session.architecture["running_clock_samples"].append(
                    {"virtual_ns": clock, "QMP_status": status, "stop_epoch": session.stop_epoch,
                     "host_monotonic_ns": time.monotonic_ns()})
            state.update(running=session.running, virtual_time_ns=clock, host_monotonic_ns=time.monotonic_ns())
            save_json(state_path, state)
            if virtual_end is not None and clock >= virtual_end:
                report["observation_budget"].update(virtual_limit_reached=True, stop_reason="virtual_limit_reached")
                break
            if time.monotonic() >= next_screenshot:
                sample = {"virtual_time_ns_before": clock, "source": "QMP default display console",
                          "role_assignment_verified": False, "MENU_acceptance_implied": False}
                try:
                    p = run / f"native-console-{len(report['UI']['samples']):04d}.ppm"
                    sample["QMP_return"] = session.qmp("screendump", {"filename": str(p)})
                    sample["image"] = identity(p)
                    sample["virtual_time_ns_after"] = session.clock()
                except Exception as exc:
                    sample["error"] = error_text(exc)
                report["UI"]["samples"].append(sample)
                next_screenshot = time.monotonic() + screenshot_interval
            time.sleep(0.01)                          # host polling, never a guest time increment
        session.interrupt()
        stopped_clock = session.clock()
        budget = report["observation_budget"]
        budget.update(observed_stop_virtual_ns=stopped_clock, elapsed_virtual_ns=stopped_clock-origin)
        if virtual_end is not None and stopped_clock >= virtual_end:
            budget.update(virtual_limit_reached=True, stop_reason="virtual_limit_reached")
        elif budget["stop_reason"] == "not_stopped":
            budget["stop_reason"] = ("host_safety_limit_before_virtual_limit" if virtual_end is not None else "host_limit_reached")
        stopped_evidence(session, baseline, prepared, report)
        session.freeze("final")
        report["architecture"] = architecture_checks(session, report)
        report["final_evidence"] = final_evidence_status(report, report["architecture"], "collected")
        budget_complete = virtual_end is None or budget["virtual_limit_reached"]
        report["host_operation_completed"] = report["final_evidence"]["complete"] and budget_complete
        report["status"] = ("bounded_original_code_observation_completed; functional_gates_pending"
                            if report["host_operation_completed"] else
                            "native_virtual_limit_incomplete" if not budget_complete else "native_final_samples_incomplete")
    except BaseException as exc:
        report["observation_budget"]["stop_reason"] = "observation_failure"
        report["error"] = error_text(exc)
        report["status"] = "native_unified_observation_incomplete"
        if session is None and hasattr(exc, "partial_architecture"):
            report["architecture"] = exc.partial_architecture
            report["architecture"]["evidence_phase"] = "incomplete_initial_discovery"
        if hasattr(exc, "debugger_cleanup_error"):
            report.setdefault("cleanup_errors", []).append(exc.debugger_cleanup_error)
        if hasattr(exc, "partial_debugger_ledgers"):
            report["partial_debugger_ledgers"] = exc.partial_debugger_ledgers
    finally:
        def cleanup(label, operation):
            try:
                return True, operation()
            except Exception as exc:
                report.setdefault("cleanup_errors", []).append(label + ": " + error_text(exc))
                return False, None

        if session is not None:
            alive = process.poll() is None
            if alive and not report["final_evidence"]["available"]:
                stopped, _ = cleanup("final common interrupt", session.interrupt)
                if stopped:
                    cleanup("final stopped evidence", lambda: stopped_evidence(session, baseline, prepared, report))
                    obtained, arch = cleanup("final architecture", lambda: architecture_checks(session, report))
                    if obtained:
                        report["architecture"] = arch
                        report["final_evidence"] = final_evidence_status(report, arch, "collected_during_failure_cleanup")
            if observations is not None:
                cleanup("retained observer closure", observations.finish)
            if pads is not None:
                cleanup("retained external input closure", pads.finish)
                report["external_pad_events"] = pads.events
            report["debugger_read_records"] = session.reads
            report["global_execution_control"] = session.control
            if not report["final_evidence"]["available"]:
                # Evaluation uses explicitly retained historical observations;
                # no failed QOM call is replaced with a fictitious final state.
                report["architecture"] = session.architecture
                evaluated, retained = cleanup("historical architecture evaluation",
                    lambda: evaluate_architecture(session.architecture, report))
                if evaluated:
                    report["architecture"].update(retained)
                report["architecture"].update(passed=False, final_evidence_available=False,
                    evidence_phase="historical_snapshot_with_running_clock_observations")
                report["final_evidence"].update(status="unavailable", QEMU_exit_code=process.poll(),
                    last_complete_snapshot_epoch=report.get("initial_architecture", {}).get("snapshot_epoch"),
                    last_complete_snapshot_virtual_ns=report.get("initial_architecture", {}).get("snapshot_virtual_ns"),
                    initial_snapshot_used_for_final_acceptance=False)
            if process.poll() is None:
                cleanup("QMP quit", lambda: session.qmp("quit"))
        if process is not None:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        report["QEMU_lifecycle"] = lifecycle.closed(process)
        if session is not None:
            cleanup("debugger ledger close", session.close)
            try:
                report["debugger_zero_guest_writes"] = debugger_write_audit(session)
            except Exception as exc:
                report["debugger_zero_guest_writes"] = {"verified": False, "actual_guest_RAM_register_write_count": None, "error": error_text(exc)}
        if prepared is not None and prepared["peer"] is not None:
            try:
                report["USART1_peer"] = prepared["peer"].finish()
            except Exception as exc:
                report["USART1_peer"] = {"error": error_text(exc)}
        if log is not None:
            log.close()
            report["QEMU_log"] = identity(run / "qemu.log")
            content = (run / "qemu.log").read_text(errors="replace")
            report["first_unmodeled"] = next((line for line in content.splitlines() if "UNMODELED" in line or "WIRE_BOUNDARY" in line), None)
            report["SPI2_DMA_memory_boundaries"] = [line for line in content.splitlines() if "SPI2_DMA_MEMORY_BOUNDARY" in line]
            report["virtual_wire_wait_events"] = [line for line in content.splitlines() if "Z62_WIRE_VIRTUAL_WAIT_" in line]
            if process is not None and process.returncode == 66:
                report["native_execution_boundary"] = {"exit_code": 66, "first_unmodeled": report["first_unmodeled"],
                    "integration_bug_excluded": False, "final_QOM_available": report["final_evidence"]["available"],
                    "original_execution_depth_is_separate_from_full_hardware_completion": True}
                report["status"] = "native_boundary_exit66; final_evidence_incomplete"
        report["role_observer_logs"] = {}
        for role in ("master", "slave"):
            p = run / role / "original-boot-observation.log"
            report["role_observer_logs"][role] = identity(p) if p.exists() else {"status": "not_emitted"}
        if prepared is not None:
            try:
                result = subprocess.run([str(prepared["tool"]), "inspect-stopped", str(prepared["bus"])],
                    capture_output=True, text=True, check=True, timeout=30)
                report["stopped_wire_inspection"] = {"stdout": result.stdout, "stderr": result.stderr,
                    "final_bus": identity(prepared["bus"]), "scope": "model bus evidence; physical causality not certified"}
            except Exception as exc:
                report["stopped_wire_inspection"] = {"error": error_text(exc)}
        report["finished"] = utc()
        report["harness_identity"] = identity(__file__)
        report["harness_source_unchanged"] = report["harness_identity"] == report["harness_identity_at_start"]
        if not report["harness_source_unchanged"]:
            report.setdefault("cleanup_errors", []).append("Harness source changed during this run")
        clock_file = run / "native-virtual-clock-observations.jsonl"
        if clock_file.exists():
            report["virtual_clock_observation_ledger"] = identity(clock_file)
        report["architecture_passed"] = report["architecture"].get("passed") is True
        report["functional_gates_relaxed"] = False
        save_json(state_path, {"schema": "z62.native-unified-state/1", "ready": False, "active": False,
                              "running": False, "status": report["status"], "finished": report["finished"]})
        save_json(target, report)
    print(report["status"], flush=True)
    return int(not (report["host_operation_completed"] and report["architecture_passed"]
                    and report["final_evidence"].get("complete") is True
                    and report["debugger_zero_guest_writes"]["verified"]
                    and report["QEMU_lifecycle"].get("exit_code") == 0 and not report.get("cleanup_errors")))


def main(argv=None):
    return run_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
