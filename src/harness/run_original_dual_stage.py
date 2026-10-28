"""Reproducible original two-engine experiments using the preserved MCU inputs."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

from host_env import ROOT, WORK


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", required=True)
    parser.add_argument("--mode", choices=("config", "complete"), default="complete")
    parser.add_argument("--seconds", type=float, default=20)
    parser.add_argument("--icount-shift", type=int, choices=range(9), default=3)
    parser.add_argument("--shared-event-poll-ns", type=int, choices=(1000, 10000, 100000), default=1000)
    parser.add_argument("--slave-access-ready-line", action="store_true")
    parser.add_argument("--slave-sdhci-mode", choices=("no-card", "empty-card", "fat-card"))
    parser.add_argument("--slave-filesystem", choices=("FAT16", "FAT32"), default="FAT16")
    parser.add_argument("--slave-card-capacity-mib", type=int, choices=(256, 4096), default=256)
    parser.add_argument("--master-persistent-input", type=Path)
    parser.add_argument("--slave-persistent-input", type=Path)
    parser.add_argument("--menu", action="store_true")
    parser.add_argument("--menu-plan", choices=("traversal", "reentry"), default="traversal")
    parser.add_argument("--menu-config-region", type=lambda s: int(s, 0),
                        action="append", default=[],
                        help="Additional original resource loads for a diagnostic comparison")
    parser.add_argument("--sensor-dependency-trace", action="store_true")
    parser.add_argument("--display-config-trace", action="store_true")
    parser.add_argument("--peer-data-section", action="store_true")
    parser.add_argument("--peer-dma-section", action="store_true")
    parser.add_argument("--slave-dma-section", action="store_true")
    parser.add_argument("--slave-fill-channel1", action="store_true")
    parser.add_argument("--master-fill-channel1", action="store_true")
    args = parser.parse_args()
    if args.menu_config_region and not args.menu:
        parser.error("Additional diagnostic regions require --menu")
    if any(not 0 <= value <= 0x50 for value in args.menu_config_region):
        parser.error("Original resource regions must be 0..0x50")
    prior = ROOT / "outputs/Z6II全机研究/20261017-主板硬件与双EXPEED接入/双EXPEED运行/03-300控制锁存假设/结果.json"
    original = json.loads(prior.read_text())
    output = ROOT / "outputs/Z6II全机研究/20261017-原双端菜单接入/运行" / args.label
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise FileExistsError(output)
    command = [sys.executable, str(WORK / "natural_boot.py"), "--integrated",
               "--peer-buffer-section", "--peer-business-trace-only",
               "--slave-2b20-control-latch", "--slave-pipeline-mode", args.mode,
               "--shared-event-poll-ns", str(args.shared_event_poll_ns),
               "--icount-shift", str(args.icount_shift), "--seconds", str(args.seconds),
               "--exmcu-transport", "--quiet-observers", "--label", args.label,
               "--output-dir", str(output)]
    packets = {
        "EX_MCU_input_packet": "--exmcu-packet",
        "EX_MCU_SYS_version_packet": "--exmcu-sys-version-packet",
        "EX_MCU_SYS_C_initialized_packet": "--exmcu-sys-state-packet",
        "EX_MCU_GPIO_sampled_KEY_packet": "--exmcu-key-packet",
        "EX_MCU_C_initialized_power_packet": "--exmcu-power-packet",
        "EX_MCU_service0D_native_GPIO_reply": "--exmcu-service0d-packet",
    }
    for key, flag in packets.items():
        if original.get(key):
            command.extend((flag, original[key]))
    command.extend(("--exmcu-packet-delay-ms", "500", "--exmcu-sys-delay-ms", "1000",
                    "--exmcu-key-delay-ms", "2000", "--exmcu-power-delay-ms", "3000"))
    if args.menu:
        command.append("--menu-session")
        command.extend(("--menu-plan", args.menu_plan))
        for region in args.menu_config_region:
            command.extend(("--menu-config-region", hex(region)))
    if args.display_config_trace:
        command.append("--display-config-trace")
    if args.sensor_dependency_trace:
        command.append("--sensor-dependency-trace")
    if args.peer_data_section:
        command.append("--peer-data-section")
    if args.peer_dma_section:
        command.append("--peer-dma-section")
    if args.slave_dma_section:
        command.append("--slave-dma-section")
    if args.slave_fill_channel1:
        command.append("--slave-fill-channel1")
    if args.master_fill_channel1:
        command.append("--master-fill-channel1")
    if args.slave_access_ready_line:
        command.append("--slave-access-ready-line")
    if args.slave_sdhci_mode:
        command.extend(("--slave-sdhci-mode", args.slave_sdhci_mode))
    command.extend(("--slave-filesystem", args.slave_filesystem))
    command.extend(("--slave-card-capacity-mib", str(args.slave_card_capacity_mib)))
    if args.master_persistent_input:
        command.extend(("--master-persistent-input", str(args.master_persistent_input.resolve(strict=True))))
    if args.slave_persistent_input:
        command.extend(("--slave-persistent-input", str(args.slave_persistent_input.resolve(strict=True))))
    print("Original dual-engine run:", args.label, "mode:", args.mode, flush=True)
    result = subprocess.run(command, cwd=WORK)
    if output.exists():
        (output / "执行命令.json").write_text(json.dumps(dict(argv=command,
            prior_input_report=str(prior), exit_code=result.returncode),
            ensure_ascii=False, indent=2) + "\n")
    print("Output:", output, "exit:", result.returncode, flush=True)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
