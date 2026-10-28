"""Self-contained project paths and deterministic host environment."""
import os
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / "src/harness"
HOST = ROOT / "runtime/build"
PYTHON = ROOT / "runtime/python/bin/python3.12"
SOURCE = ROOT / "src/qemu"
def environment():
    env = dict(os.environ)
    env.update(PATH=str(ROOT / "runtime/build/bin") + ":/usr/bin:/bin:/usr/sbin:/sbin",
               PYTHONPATH=str(WORK) + os.pathsep + str(WORK / "tools"),
               PYTHONDONTWRITEBYTECODE="1")
    return env
