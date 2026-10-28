"""Original Z6II 1.70 MCU identity; no emulator imports or execution."""
from host_env import ROOT
BASE = 0x08000000
RAM = 0x20000000
RAM_SIZE = 0x40000
EXPECTED_SHA = "4314c17d9a6676a4254aa4d74d4aa35411e3a793ea7056c06f9c83f160da3cb1"
INPUT = ROOT / "inputs/firmware/ex1850_012000.bi.bin"
