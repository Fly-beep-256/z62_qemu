"""Identity-checked offline flash inputs; no camera transport or guest calls.

Supplied bytes populate a bounded external-flash window. Explicitly inferred
storage ranges must be marked analysis-only and are never labeled camera data.
This helper does not generate bytes, change versions or certify provenance.
Original firmware accepts or rejects the contents through its own checks.
"""
import argparse
import hashlib
import json
from pathlib import Path

FLASH_END = 0x14000000
ROM_END = {"master": 0x12520000, "slave": 0x10920000}


def inspect_spec(spec_path, role=None):
    spec_path = Path(spec_path).resolve(strict=True)
    spec = json.loads(spec_path.read_text())
    if spec.get("schema") != 1:
        raise ValueError("Persistent-input manifest requires schema 1")
    supplied_role = spec.get("role")
    if supplied_role not in ROM_END or (role and supplied_role != role):
        raise ValueError("Persistent-input manifest role does not match the EXPEED")
    image_path = Path(spec["image_path"])
    if not image_path.is_absolute():
        image_path = spec_path.parent / image_path
    image_path = image_path.resolve(strict=True)
    if not image_path.is_file():
        raise ValueError("Persistent input must be a regular file")
    size = image_path.stat().st_size
    if not 0 < size <= FLASH_END - ROM_END[supplied_role] or size != spec["bytes"]:
        raise ValueError("Persistent-input length differs from manifest or flash bounds")
    base = int(spec["base"], 0) if isinstance(spec["base"], str) else spec["base"]
    if not isinstance(base, int) or not ROM_END[supplied_role] <= base <= FLASH_END - size:
        raise ValueError("Persistent input would overlap original ROM or exceed flash")
    data = image_path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    expected = spec.get("sha256")
    if not isinstance(expected, str) or digest != expected.lower():
        raise ValueError("Persistent-input SHA-256 does not match recorded bytes")
    inferred = spec.get("inferred_storage_ranges", [])
    if not isinstance(inferred, list):
        raise ValueError("Inferred storage ranges must be an explicit list")
    padding = spec.get("unacquired_padding_ranges", [])
    if not isinstance(padding, list):
        raise ValueError("Unacquired padding ranges must be an explicit list")
    if (inferred or padding) and spec.get("analysis_only") is not True:
        raise ValueError("Inferred storage bytes require an analysis-only manifest")
    if (inferred or padding or spec.get("analysis_only") is True) and spec.get("complete_physical_flash_dump") is True:
        raise ValueError("An analysis-only or inferred input cannot claim a complete physical Flash dump")
    coverage = []
    for item in inferred:
        if not isinstance(item, dict) or not isinstance(item.get("basis"), str) or not item["basis"]:
            raise ValueError("Each inferred range requires its analysis basis")
        address = item.get("address")
        if isinstance(address, str):
            address = int(address, 0)
        if not isinstance(address, int) or isinstance(address, bool):
            raise ValueError("Inferred range address must be an integer")
        try:
            supplied = bytes.fromhex(item["hex"])
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("Inferred ranges require exact supplied hexadecimal bytes") from error
        if not supplied or not base <= address <= base + size - len(supplied):
            raise ValueError("Inferred storage range is outside the supplied image")
        if data[address-base:address-base+len(supplied)] != supplied:
            raise ValueError("Inferred storage bytes do not match the supplied image")
        coverage.append((address, address + len(supplied), "inferred"))
    for item in padding:
        if not isinstance(item, dict) or not isinstance(item.get("basis"), str) or not item["basis"]:
            raise ValueError("Each padding range requires its analysis basis")
        address, length = item.get("address"), item.get("bytes")
        if isinstance(address, str):
            address = int(address, 0)
        if any(not isinstance(v, int) or isinstance(v, bool) for v in (address, length)):
            raise ValueError("Padding range address and length must be integers")
        try:
            fill = bytes.fromhex(item["fill_hex"])
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("Padding ranges require a single fill byte") from error
        if len(fill) != 1 or length <= 0 or not base <= address <= base + size - length:
            raise ValueError("Padding range or fill byte is invalid")
        if data[address-base:address-base+length] != fill * length:
            raise ValueError("Unacquired padding does not match the supplied image")
        coverage.append((address, address + length, "unacquired padding"))
    recorded = spec.get("recorded_payload_ranges", [])
    if not isinstance(recorded, list):
        raise ValueError("Recorded payload ranges must be an explicit list")
    for item in recorded:
        if not isinstance(item, dict):
            raise ValueError("Recorded payload range must be an object")
        address, length = item.get("address"), item.get("bytes")
        if isinstance(address, str):
            address = int(address, 0)
        if any(not isinstance(v, int) or isinstance(v, bool) for v in (address, length)):
            raise ValueError("Recorded payload range address and length must be integers")
        if length <= 0 or not base <= address <= base + size - length:
            raise ValueError("Recorded payload is outside the supplied image")
        source = Path(item["source_path"])
        if not source.is_absolute():
            source = spec_path.parent / source
        original = source.resolve(strict=True).read_bytes()
        if len(original) != length or hashlib.sha256(original).hexdigest() != item.get("source_sha256"):
            raise ValueError("Recorded payload source identity differs from manifest")
        if data[address-base:address-base+length] != original:
            raise ValueError("Recorded payload bytes changed in the composite image")
        coverage.append((address, address + length, "recorded payload"))
    # Bytes produced by an earlier emulator run of the unmodified original firmware (for
    # example a first boot that programmed its own storage). They are neither camera data
    # nor invented bytes, and are only allowed in an explicitly analysis-only manifest.
    products = spec.get("emulator_run_product_ranges", [])
    if not isinstance(products, list):
        raise ValueError("Emulator run-product ranges must be an explicit list")
    if products and spec.get("analysis_only") is not True:
        raise ValueError("Emulator run-product bytes require an analysis-only manifest")
    for item in products:
        if not isinstance(item, dict) or not isinstance(item.get("basis"), str) or not item["basis"]:
            raise ValueError("Each emulator run-product range requires its analysis basis")
        address, length = item.get("address"), item.get("bytes")
        if isinstance(address, str):
            address = int(address, 0)
        if any(not isinstance(v, int) or isinstance(v, bool) for v in (address, length)):
            raise ValueError("Run-product range address and length must be integers")
        if length <= 0 or not base <= address <= base + size - length:
            raise ValueError("Run-product range is outside the supplied image")
        source = Path(item["source_path"])
        if not source.is_absolute():
            source = spec_path.parent / source
        original = source.resolve(strict=True).read_bytes()
        if len(original) != length or hashlib.sha256(original).hexdigest() != item.get("source_sha256"):
            raise ValueError("Run-product source identity differs from manifest")
        if data[address-base:address-base+length] != original:
            raise ValueError("Run-product bytes changed in the composite image")
        coverage.append((address, address + length, "emulator run product"))
    ordered_coverage = sorted(coverage)
    if any(left[1] > right[0] for left, right in zip(ordered_coverage, ordered_coverage[1:])):
        raise ValueError("Declared persistent-input byte ranges overlap")
    if spec.get("conditional_composite_flash_input") is True:
        cursor = base
        for start, end, _ in ordered_coverage:
            if start != cursor:
                raise ValueError("Every composite byte must be identified as recorded, inferred, or padding")
            cursor = end
        if cursor != base + size:
            raise ValueError("Composite byte classification does not cover the whole input")
    acquisition_path = spec.get("acquisition_report")
    acquisition = None
    if acquisition_path:
        acquisition_path = Path(acquisition_path)
        if not acquisition_path.is_absolute():
            acquisition_path = spec_path.parent / acquisition_path
        acquisition_path = acquisition_path.resolve(strict=True)
        acquisition_data = acquisition_path.read_bytes()
        acquisition_digest = hashlib.sha256(acquisition_data).hexdigest()
        if acquisition_digest != spec.get("acquisition_report_sha256"):
            raise ValueError("Acquisition report SHA-256 differs from the input manifest")
        acquisition = dict(path=str(acquisition_path), bytes=len(acquisition_data), sha256=acquisition_digest)
    result = dict(schema=1, role=supplied_role, base=hex(base), bytes=len(data), sha256=digest,
        source_manifest=str(spec_path), source_manifest_sha256=hashlib.sha256(spec_path.read_bytes()).hexdigest(),
        source_image=str(image_path), claimed_origin=spec.get("origin"),
        source_provenance_independently_verified=False,
        original_ROM_overlap=False, camera_operations=0,
        supplied_as_flash_device_input=True, guest_RAM_or_register_patch=False,
        resource_bytes_or_version_manufactured=bool(inferred or padding),
        contains_inferred_storage_bytes=bool(inferred),
        inferred_storage_ranges=inferred,
        contains_unacquired_padding=bool(padding),
        unacquired_padding_ranges=padding,
        recorded_payload_ranges=recorded,
        conditional_composite_flash_input=spec.get("conditional_composite_flash_input") is True,
        inferred_storage_byte_count=sum(b-a for a,b,k in coverage if k == "inferred"),
        unacquired_padding_byte_count=sum(b-a for a,b,k in coverage if k == "unacquired padding"),
        recorded_payload_byte_count=sum(b-a for a,b,k in coverage if k == "recorded payload"),
        emulator_run_product_ranges=products,
        emulator_run_product_byte_count=sum(b-a for a,b,k in coverage if k == "emulator run product"),
        analysis_only=spec.get("analysis_only") is True,
        complete_physical_flash_dump_claimed=spec.get("complete_physical_flash_dump") is True)
    if acquisition:
        result["acquisition_report"] = acquisition
    if supplied_role == "master" and base <= 0x13e80000 and base + len(data) >= 0x13fe8000:
        offset = 0x13e80000 - base
        version_bytes = data[offset + 0xce014:offset + 0xce016]
        version = (version_bytes[0] << 4) | (version_bytes[1] >> 4)
        parent_marker_offset = 0x13fffffc - base
        parent_marker_available = base <= 0x13e80000 and base + len(data) >= 0x14000000
        result["sensor_region50_static_checks"] = dict(
            version_bytes=version_bytes.hex(), decoded_version=hex(version),
            original_version_criterion_met=0x150 <= version <= 0x15f,
            parameter_payload_ENDM_present=data[offset + 0x167ffc:offset + 0x168000] == b"ENDM",
            parameter_payload_ENDM_offset="0x167ffc",
            declared_original_parent_container_extent_bytes=0x180000,
            declared_original_parent_container_ENDM_address="0x13fffffc",
            parent_container_ENDM_bytes_available=parent_marker_available,
            parent_container_ENDM_present=(data[parent_marker_offset:parent_marker_offset+4] == b"ENDM"
                if parent_marker_available else None),
            full_original_resource_validation_executed=False,
            note="The copied parameter-payload tail at +167FFC is distinct from the stock parent-container marker at +17FFFC")
    return result, data


def prepare(spec_path, role, directory):
    result, data = inspect_spec(spec_path, role)
    # Keep the original manifest and any digest-bound acquisition report in
    # every run. A later report update must not erase historical provenance.
    manifest_data = Path(result["source_manifest"]).read_bytes()
    if hashlib.sha256(manifest_data).hexdigest() != result["source_manifest_sha256"]:
        raise ValueError("Persistent-input manifest changed before it was snapshotted")
    acquisition = result.get("acquisition_report")
    acquisition_data = None
    if acquisition:
        acquisition_data = Path(acquisition["path"]).read_bytes()
        if hashlib.sha256(acquisition_data).hexdigest() != acquisition["sha256"]:
            raise ValueError("Acquisition report changed before it was snapshotted")
    manifest_snapshot = Path(directory) / "supplied-persistent-manifest.json"
    with manifest_snapshot.open("xb") as output:
        output.write(manifest_data)
    result["source_manifest_snapshot"] = str(manifest_snapshot.resolve())
    if acquisition:
        acquisition_snapshot = Path(directory) / "supplied-persistent-acquisition-report.json"
        with acquisition_snapshot.open("xb") as output:
            output.write(acquisition_data)
        result["acquisition_report_snapshot"] = str(acquisition_snapshot.resolve())
    snapshot = Path(directory) / "supplied-persistent-flash.bin"
    with snapshot.open("xb") as output:
        output.write(data)
    result["snapshot"] = str(snapshot.resolve())
    result["host_source_file_modified"] = False
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    result, _ = inspect_spec(args.manifest)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
