"""Coordinate MCU + EXPEED with synchronized early exit on scenario completion."""
from pathlib import Path
import sys

DIRECTORY = Path(__file__).resolve().parent
PORT = Path(__file__).resolve().parents[2] / 'src/harness'
sys.path.insert(0, str(PORT))

tp_path = PORT / "native_mcu_three_probe.py"
src = tp_path.read_text(encoding="utf-8")
target = 'str(port / "run_exmcu_qemu_reset.py")'
replacement = repr(str(DIRECTORY / "run_local_mcu.py"))
assert target in src, "Failed to locate run_exmcu_qemu_reset.py in native_mcu_three_probe.py"
patched_src = src.replace(target, replacement, 1)
g = {"__name__": "__main__", "__file__": str(tp_path)}
exec(compile(patched_src, str(tp_path), "exec"), g)
