"""Run MCU QEMU reset harness with synchronized early exit when scenario finishes."""
from pathlib import Path
import sys

PORT = Path(__file__).resolve().parents[2] / 'src/harness'
sys.path.insert(0, str(PORT))

mcu_path = PORT / "run_exmcu_qemu_reset.py"
src = mcu_path.read_text(encoding="utf-8")
target = "        while process.poll() is None and time.monotonic() < end:\n"
replacement = """        while process.poll() is None and time.monotonic() < end:
            if (directory.parent / "native-gpio-scenario-result.json").exists():
                report["smart_early_exit_seconds"] = round(time.monotonic() - continued, 4)
                break
"""
assert target in src, "Failed to locate main while loop in run_exmcu_qemu_reset.py"
patched_src = src.replace(target, replacement, 1)
g = {"__name__": "__main__", "__file__": str(mcu_path)}
exec(compile(patched_src, str(mcu_path), "exec"), g)
