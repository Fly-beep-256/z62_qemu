"""Shared-bus identity checks before launching native MCU/EXPEED peers."""
from pathlib import Path
import re
import struct

WIRE_MAGIC = 0x3157434D
WIRE_BYTES = 0x41000
SUPPORTED_ABIS = (1, 2)


def abi_from_header(path):
    match = re.search(r"^#define MCU_WIRE_ABI ([0-9]+)$",
                      Path(path).read_text(), re.MULTILINE)
    if not match or int(match[1]) not in SUPPORTED_ABIS:
        raise ValueError("Unsupported MCU wire header ABI")
    return int(match[1])


def manifest_abi(manifest):
    # Historical manifests predate this field and describe the ABI1 core.
    abi = manifest.get("native_mcu_wire_abi", 1)
    if type(abi) is not int or abi not in SUPPORTED_ABIS:
        raise ValueError("Selected manifest has an unsupported MCU wire ABI")
    return abi


def validate_bus(path, manifest):
    path = Path(path).resolve(strict=True)
    expected = manifest_abi(manifest)
    if not path.is_file() or path.stat().st_size != WIRE_BYTES:
        raise ValueError("Native MCU wire requires an existing regular bus file")
    with path.open("rb") as stream:
        header = stream.read(12)
    if len(header) != 12:
        raise ValueError("Truncated native MCU wire header")
    magic, abi, size = struct.unpack("<III", header)
    if (magic, abi, size) != (WIRE_MAGIC, expected, WIRE_BYTES):
        raise ValueError(f"Native MCU wire header does not match selected ABI{expected}")
    return path
