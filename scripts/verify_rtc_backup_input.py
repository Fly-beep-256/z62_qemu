"""Contract regressions using synthetic files, never a camera or a guest."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "src/harness"))
from rtc_backup_input import export_bank, inspect_spec, prepare


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n")


def identity(path):
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def fixture(directory, relative_artifacts=False):
    binary = directory / "contract-test-binary.bin"
    binary.write_bytes(b"synthetic RTC persistence contract fixture, not executable\n")
    manifests = []
    for name in ("EXPEED", "MCU"):
        path = directory / (name + "-build-manifest.json")
        save(path, dict(binary=str(binary), binary_sha256=identity(binary)["sha256"]))
        manifests.append(identity(path))
    words = [0x10203000 + i for i in range(20)]
    words[3], words[19] = 0x10000000, 0x0201
    qom = dict(clock="QEMU_CLOCK_VIRTUAL", virtual_ns=20600000123,
               domains=[dict(role="MCU", RTC_backup_bank=dict(
                   schema="z62.ex1850-rtc-backup-bank/1", source="EX1850RTC.backup",
                   byte_order="little", bytes=80, words=words, read_side_effects=False))])
    raw = json.dumps(qom)
    arch = dict(final_evidence_available=True, evidence_phase="final", QOM=qom, QOM_raw=raw,
                snapshot_epoch=1234, snapshot_virtual_ns=qom["virtual_ns"], QOM_snapshots=[dict(
                    phase="final", running=False, stop_epoch=1234, raw=raw, state=qom)])
    report = dict(machine="nikon-z6ii-native", camera_access=False, host_operation_completed=True,
                  architecture_passed=True, harness_source_unchanged=True, architecture=arch,
                  QEMU_lifecycle=dict(exit="observed", exit_code=0),
                  debugger_zero_guest_writes=dict(verified=True, actual_guest_RAM_register_write_count=0),
                  common_stop=dict(complete=True, sampling_complete=True, stop_epoch=1234,
                                   virtual_time_ns=qom["virtual_ns"], QMP_status=dict(running=False),
                                   sequential_reads_while_common_clock_frozen=True),
                  final_evidence=dict(available=True, complete=True, stop_epoch=1234, virtual_ns=qom["virtual_ns"]),
                  identities=dict(QEMU=identity(binary), QEMU_manifest=manifests[0], MCU_reference_manifest=manifests[1]))
    locked = dict(selected_binary=identity(binary), build_manifests=manifests,
                  execution_model="single-qemu-five-cpu", camera_access=False, guest_state_injection=False,
                  QEMU_instances=1, CPU_count=5, envelope_at_run=str(directory),
                  package_root_at_run=str(directory))
    if relative_artifacts:
        locked["selected_binary"]["path"] = binary.name
        report["identities"]["QEMU"]["path"] = binary.name
        for key in ("QEMU_manifest", "MCU_reference_manifest"):
            report["identities"][key]["path"] = Path(report["identities"][key]["path"]).name
    save(directory / "run/native-unified-result.json", report)
    save(directory / "prepare/锁定命令与输入.json", locked)
    return report, words


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    checks = []
    with tempfile.TemporaryDirectory(prefix="rtc-bank-contract-", dir=ROOT / "build") as temp:
        base = Path(temp)
        source = base / "synthetic-source"
        source.mkdir()
        original, words = fixture(source)

        def reject(name, operation):
            try:
                operation()
            except (ValueError, FileNotFoundError):
                checks.append(dict(name=name, passed=True))
            else:
                raise AssertionError("Invalid evidence was accepted: " + name)

        exported = export_bank(source, base / "export")
        spec_path = Path(exported["manifest"])
        observed, data = inspect_spec(spec_path)
        assert data == struct.pack("<20I", *words) and observed["words"] == words
        checks.append(dict(name="all_20_words_exported_including_17_18_19", passed=True))
        frozen = prepare(spec_path, base / "frozen")
        frozen_result, frozen_bytes = inspect_spec(frozen["frozen_manifest"]["path"])
        second = prepare(frozen["frozen_manifest"]["path"], base / "second")
        assert frozen_bytes == data == Path(second["snapshot"]).read_bytes()
        assert frozen_result["source_stop_epoch"] == observed["source_stop_epoch"]
        checks.append(dict(name="frozen_provenance_is_portable_and_roundtrips", passed=True))
        result_path = source / "run/native-unified-result.json"
        mutations = {
            "boundary_exit66": lambda r: r["QEMU_lifecycle"].update(exit_code=66),
            "missing_final_QOM": lambda r: r["architecture"].update(final_evidence_available=False),
            "initial_QOM_mislabeled_as_final": lambda r: r["architecture"]["QOM_snapshots"][-1].update(phase="initial"),
            "QOM_sample_while_running": lambda r: r["architecture"]["QOM_snapshots"][-1].update(running=True),
            "mismatched_common_stop_epoch": lambda r: r["common_stop"].update(stop_epoch=1235),
            "mismatched_common_stop_clock": lambda r: r["common_stop"].update(virtual_time_ns=99),
            "incomplete_zero_write_audit": lambda r: r["debugger_zero_guest_writes"].update(verified=False),
            "changed_source_during_run": lambda r: r.update(harness_source_unchanged=False),
        }
        for name, mutate in mutations.items():
            candidate = copy.deepcopy(original)
            mutate(candidate)
            save(result_path, candidate)
            reject(name, lambda name=name: export_bank(source, base / name))
        save(result_path, original)
        spec_original = json.loads(spec_path.read_text())
        image = spec_path.parent / spec_original["image"]["path"]
        corrupted = bytearray(data)
        corrupted[17 * 4] ^= 1
        image.write_bytes(corrupted)
        altered = copy.deepcopy(spec_original)
        altered["image"] = dict(identity(image), path=image.name)
        altered["words"] = list(struct.unpack("<20I", corrupted))
        save(spec_path, altered)
        reject("edited_bank_rehashed_but_not_from_source_QOM", lambda: inspect_spec(spec_path))
        image.write_bytes(data[:76])
        altered["image"] = dict(identity(image), path=image.name)
        save(spec_path, altered)
        reject("truncated_19_word_bank_rehashed", lambda: inspect_spec(spec_path))
        image.write_bytes(data)
        save(spec_path, spec_original)
        qom_path = spec_path.parent / spec_original["evidence"]["QOM"]["path"]
        qom_path.write_text("{}")
        altered = copy.deepcopy(spec_original)
        altered["evidence"]["QOM"] = dict(identity(qom_path), path=qom_path.name)
        save(spec_path, altered)
        reject("substituted_QOM_rehashed", lambda: inspect_spec(spec_path))
        save(spec_path, spec_original)
        reject("evidence_digest_mismatch", lambda: inspect_spec(spec_path))
        relative = base / "package-relative-source"
        relative.mkdir()
        fixture(relative, relative_artifacts=True)
        relative_export = export_bank(relative, base / "package-relative-export")
        relative_bank, relative_bytes = inspect_spec(relative_export["manifest"])
        assert relative_bytes == data and relative_bank["words"] == words
        checks.append(dict(name="actual_launcher_package_relative_artifacts_resolve_at_locked_root", passed=True))
        relative_locked_path = relative / "prepare/锁定命令与输入.json"
        relative_locked = json.loads(relative_locked_path.read_text())
        relative_locked.pop("package_root_at_run")
        save(relative_locked_path, relative_locked)
        reject("relative_artifacts_without_locked_package_root", lambda:
               export_bank(relative, base / "missing-package-root"))
        locked_path = source / "prepare/锁定命令与输入.json"
        locked = json.loads(locked_path.read_text())
        locked["selected_binary"]["sha256"] = "0" * 64
        save(locked_path, locked)
        reject("producer_binary_manifest_disagreement", lambda: export_bank(source, base / "bad-build"))
    report = dict(schema="z62.ex1850-rtc-backup-contract-regression/1", passed=True,
                  synthetic_contract_fixtures=True, QEMU_started=False, camera_access=False,
                  observed_hardware_bank_claimed=False, checks=checks)
    if args.out:
        save(args.out.resolve(), report)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
