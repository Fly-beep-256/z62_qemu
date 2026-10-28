"""Retain the complete MCU RTC bank from a closed, commonly stopped run.

This is an opt-in device input, not a RAM replay or a physical-camera dump.
The 80 bytes must equal the final side-effect-free QOM bank of an identified
earlier run. Calendar continuity and complete power-off are separate claims.
"""
import hashlib
import json
from pathlib import Path
import struct

SCHEMA = "z62.ex1850-rtc-backup-input/1"
BANK_SCHEMA = "z62.ex1850-rtc-backup-bank/1"
EVIDENCE_NAMES = {
    "native_result": "source-native-unified-result.json",
    "locked_run": "source-locked-run.json",
    "QOM": "source-final-QOM.json",
    "EXPEED_manifest": "source-EXPEED-build-manifest.json",
    "MCU_manifest": "source-MCU-build-manifest.json",
}


def _identity(path, data=None):
    path = Path(path).resolve(strict=True)
    data = path.read_bytes() if data is None else data
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def _json(data):
    return json.loads(data.decode("utf-8"))


def _bound_file(item, directory):
    if not isinstance(item, dict):
        raise ValueError("RTC backup evidence identity must be an object")
    path = Path(item["path"])
    if not path.is_absolute():
        path = directory / path
    path = path.resolve(strict=True)
    if not path.is_file():
        raise ValueError("RTC backup evidence must be a regular file")
    data = path.read_bytes()
    if len(data) != item.get("bytes") or hashlib.sha256(data).hexdigest() != item.get("sha256"):
        raise ValueError("RTC backup evidence length or SHA-256 changed: " + str(path))
    return _identity(path, data), data


def _producer_file(item, envelope, locked):
    """Locked producer artifact paths are relative to its package, not run."""
    if not isinstance(item, dict):
        raise ValueError("RTC backup producer identity must be an object")
    path = Path(item["path"])
    if not path.is_absolute():
        root_text = locked.get("package_root_at_run")
        if not isinstance(root_text, str) or not Path(root_text).is_absolute():
            raise ValueError("Relative RTC producer artifacts require the locked absolute package root")
        root = Path(root_text).resolve(strict=True)
        if not root.is_dir():
            raise ValueError("RTC backup producer package root must be a directory")
        path = (root / path).resolve(strict=True)
        if not path.is_relative_to(root):
            raise ValueError("Relative RTC backup producer artifact escapes the locked package")
        item = dict(item, path=str(path))
    return _bound_file(item, envelope)


def _final_bank(report):
    if report.get("machine") != "nikon-z6ii-native" or report.get("camera_access") is not False:
        raise ValueError("RTC backup source must be a native offline QEMU run")
    if (report.get("host_operation_completed") is not True
            or report.get("architecture_passed") is not True
            or report.get("harness_source_unchanged") is not True
            or report.get("cleanup_errors")):
        raise ValueError("RTC backup source run did not close with complete verified evidence")
    lifecycle = report.get("QEMU_lifecycle", {})
    if lifecycle.get("exit") != "observed" or lifecycle.get("exit_code") != 0:
        raise ValueError("RTC backup source QEMU must have an observed normal exit")
    audit = report.get("debugger_zero_guest_writes", {})
    if audit.get("verified") is not True or audit.get("actual_guest_RAM_register_write_count") != 0:
        raise ValueError("RTC backup source requires a completed debugger zero-write audit")
    gate, final = report.get("common_stop", {}), report.get("final_evidence", {})
    arch = report.get("architecture", {})
    if (gate.get("complete") is not True or gate.get("sampling_complete") is not True
            or gate.get("QMP_status", {}).get("running") is not False
            or gate.get("sequential_reads_while_common_clock_frozen") is not True
            or final.get("available") is not True or final.get("complete") is not True
            or arch.get("final_evidence_available") is not True
            or arch.get("evidence_phase") != "final"):
        raise ValueError("RTC backup source requires actual final common-stop QOM evidence")
    snapshots = arch.get("QOM_snapshots", [])
    if not snapshots:
        raise ValueError("RTC backup source has no recorded QOM snapshot")
    snapshot, qom = snapshots[-1], arch.get("QOM", {})
    raw = snapshot.get("raw")
    if (snapshot.get("phase") != "final" or snapshot.get("running") is not False
            or not isinstance(raw, str) or _json(raw.encode()) != qom
            or snapshot.get("state") != qom or arch.get("QOM_raw") != raw):
        raise ValueError("RTC backup source final raw and parsed QOM disagree")
    epoch, virtual_ns = gate.get("stop_epoch"), gate.get("virtual_time_ns")
    if (type(epoch) is not int or epoch < 0 or type(virtual_ns) is not int or virtual_ns < 0
            or any(v != epoch for v in (snapshot.get("stop_epoch"), arch.get("snapshot_epoch"), final.get("stop_epoch")))
            or any(v != virtual_ns for v in (qom.get("virtual_ns"), arch.get("snapshot_virtual_ns"), final.get("virtual_ns")))
            or qom.get("clock") != "QEMU_CLOCK_VIRTUAL"):
        raise ValueError("RTC backup source QOM, final evidence and common-stop epoch/time differ")
    domains = [d for d in qom.get("domains", []) if d.get("role") == "MCU"]
    if len(domains) != 1:
        raise ValueError("RTC backup source must identify exactly one MCU domain")
    bank = domains[0].get("RTC_backup_bank", {})
    words = bank.get("words")
    if (bank.get("schema") != BANK_SCHEMA or bank.get("source") != "EX1850RTC.backup"
            or bank.get("bytes") != 80 or bank.get("byte_order") != "little"
            or bank.get("read_side_effects") is not False
            or not isinstance(words, list) or len(words) != 20
            or any(type(w) is not int or not 0 <= w <= 0xffffffff for w in words)):
        raise ValueError("RTC backup source must contain the actual complete 20-word bank")
    return bank, struct.pack("<20I", *words), raw.encode("utf-8"), epoch, virtual_ns


def _build_bindings(report, locked, manifests):
    identities = report.get("identities", {})
    selected = locked.get("selected_binary", {})
    if (locked.get("execution_model") != "single-qemu-five-cpu"
            or locked.get("camera_access") is not False
            or locked.get("guest_state_injection") is not False
            or locked.get("QEMU_instances") != 1 or locked.get("CPU_count") != 5
            or identities.get("QEMU", {}).get("sha256") != selected.get("sha256")
            or not isinstance(selected.get("sha256"), str) or len(selected["sha256"]) != 64):
        raise ValueError("RTC backup producer result and locked native binary disagree")
    for name, identity_key in (("EXPEED_manifest", "QEMU_manifest"),
                               ("MCU_manifest", "MCU_reference_manifest")):
        raw = manifests[name]
        digest = hashlib.sha256(raw).hexdigest()
        if (identities.get(identity_key, {}).get("sha256") != digest
                or digest not in {v.get("sha256") for v in locked.get("build_manifests", [])}
                or _json(raw).get("binary_sha256") != selected["sha256"]):
            raise ValueError("RTC backup producer build manifest differs from the locked binary")
    return selected


def inspect_spec(spec_path):
    spec_path = Path(spec_path).resolve(strict=True)
    spec_raw = spec_path.read_bytes()
    spec = _json(spec_raw)
    if (spec.get("schema") != SCHEMA or spec.get("role") != "MCU"
            or spec.get("analysis_only") is not True
            or spec.get("emulator_run_product") is not True
            or spec.get("physical_camera_backup_dump") is not False
            or spec.get("calendar_continuity_verified") is not False
            or spec.get("guest_RAM_or_register_patch") is not False):
        raise ValueError("RTC backup input must explicitly identify an analysis-only device run product")
    evidence = spec.get("evidence", {})
    if set(evidence) != set(EVIDENCE_NAMES):
        raise ValueError("RTC backup input requires all five producer evidence files")
    files, payloads = {}, {}
    for name in EVIDENCE_NAMES:
        files[name], payloads[name] = _bound_file(evidence[name], spec_path.parent)
    report, locked = _json(payloads["native_result"]), _json(payloads["locked_run"])
    bank, expected, raw_qom, epoch, virtual_ns = _final_bank(report)
    selected = _build_bindings(report, locked, payloads)
    image, data = _bound_file(spec.get("image", {}), spec_path.parent)
    if (len(data) != 80 or data != expected or spec.get("words") != bank["words"]
            or spec.get("byte_order") != "little" or payloads["QOM"] != raw_qom
            or spec.get("source_stop_epoch") != epoch or spec.get("source_virtual_ns") != virtual_ns
            or spec.get("source_envelope_at_run") != locked.get("envelope_at_run")):
        raise ValueError("RTC backup input bytes or producer metadata differ from the final QOM bank")
    result = dict(schema=SCHEMA, role="MCU", bytes=80, sha256=image["sha256"],
                  words=bank["words"], byte_order="little", source_manifest=str(spec_path),
                  source_manifest_sha256=hashlib.sha256(spec_raw).hexdigest(), source_image=image["path"],
                  evidence_files=files, source_stop_epoch=epoch, source_virtual_ns=virtual_ns,
                  source_envelope_at_run=locked["envelope_at_run"], source_QEMU=selected,
                  supplied_at_device_initialization=True, guest_RAM_or_register_patch=False,
                  complete_bank_identity_verified=True, calendar_continuity_verified=False,
                  complete_shutdown_verified=False, physical_camera_backup_dump=False,
                  analysis_only=True, emulator_run_product=True, camera_operations=0)
    return result, data


def prepare(spec_path, directory):
    result, data = inspect_spec(spec_path)
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    snapshot = directory / "supplied-rtc-backup-bank.bin"
    with snapshot.open("xb") as output:
        output.write(data)
    spec_data = Path(result["source_manifest"]).read_bytes()
    if hashlib.sha256(spec_data).hexdigest() != result["source_manifest_sha256"]:
        raise ValueError("RTC backup input manifest changed during preparation")
    manifest_snapshot = directory / "supplied-rtc-backup-manifest.json"
    with manifest_snapshot.open("xb") as output:
        output.write(spec_data)
    frozen = {}
    for name, item in result["evidence_files"].items():
        _, raw = _bound_file(item, directory)
        target = directory / EVIDENCE_NAMES[name]
        with target.open("xb") as output:
            output.write(raw)
        frozen[name] = _identity(target, raw)
    portable = _json(spec_data)
    portable["image"] = dict(_identity(snapshot, data), path=snapshot.name)
    portable["evidence"] = {name: dict(item, path=EVIDENCE_NAMES[name]) for name, item in frozen.items()}
    portable_path = directory / "rtc-backup-input.json"
    with portable_path.open("x") as output:
        output.write(json.dumps(portable, ensure_ascii=False, indent=2) + "\n")
    inspect_spec(portable_path)
    result.update(snapshot=str(snapshot.resolve()), source_manifest_snapshot=str(manifest_snapshot.resolve()),
                  evidence_snapshots=frozen, frozen_manifest=_identity(portable_path),
                  host_source_file_modified=False)
    return result


def export_bank(envelope, directory):
    envelope, directory = Path(envelope).resolve(strict=True), Path(directory)
    result_path = envelope / "run/native-unified-result.json"
    result_raw = result_path.read_bytes()
    report = _json(result_raw)
    bank, data, raw_qom, epoch, virtual_ns = _final_bank(report)
    locked_path = envelope / "prepare/锁定命令与输入.json"
    locked_raw = locked_path.read_bytes()
    locked = _json(locked_raw)
    if locked.get("envelope_at_run") != str(envelope):
        raise ValueError("RTC backup producer envelope differs from the locked run")
    payloads = dict(native_result=result_raw, locked_run=locked_raw, QOM=raw_qom)
    for name, key in (("EXPEED_manifest", "QEMU_manifest"), ("MCU_manifest", "MCU_reference_manifest")):
        _, payloads[name] = _producer_file(report["identities"][key], envelope, locked)
    _build_bindings(report, locked, payloads)
    # Check the selected live producer binary once more before freezing the
    # evidence. Import later validates the retained result and manifests.
    _producer_file(locked["selected_binary"], envelope, locked)
    directory.mkdir(parents=True, exist_ok=False)
    evidence = {}
    for name, raw in payloads.items():
        target = directory / EVIDENCE_NAMES[name]
        with target.open("xb") as output:
            output.write(raw)
        evidence[name] = dict(_identity(target, raw), path=target.name)
    image = directory / "final-rtc-backup-bank.bin"
    with image.open("xb") as output:
        output.write(data)
    spec = dict(schema=SCHEMA, role="MCU", image=dict(_identity(image, data), path=image.name),
                byte_order="little", words=bank["words"], evidence=evidence,
                source_envelope_at_run=locked["envelope_at_run"], source_stop_epoch=epoch,
                source_virtual_ns=virtual_ns, analysis_only=True, emulator_run_product=True,
                physical_camera_backup_dump=False, calendar_continuity_verified=False,
                complete_shutdown_verified=False, guest_RAM_or_register_patch=False)
    target = directory / "rtc-backup-input.json"
    with target.open("x") as output:
        output.write(json.dumps(spec, ensure_ascii=False, indent=2) + "\n")
    result, _ = inspect_spec(target)
    return dict(result, manifest=str(target.resolve()), source_result=_identity(result_path, result_raw))
