# Z6II / Z62 QEMU 独立工作目录

Historical prepared-package notes from 2026-10-25. Current source-distribution and native exposure instructions are in [Native method v0.0.2](NATIVE-v0.0.2.md); the later V44 run has its own acceptance scope. Runtime, firmware and raw results described below are local prepared material and are excluded from the Git source distribution.

**Native cold-start guide v0.01:** [Native Cold-Start Guide](COLD-START-BASELINE-v0.01.md) covers preparation, the menu input scenario, and display verification using project-relative paths and user-supplied firmware.

本目录汇集目前已经实现的 QEMU 源码、运行产物、原厂固件模块、运行输入、Python / OCR / 动态库、离线构建工具以及验收入口。默认 `native` 使用一个 `nikon-z6ii-native` QEMU 实例，同时执行主 E6 两核、从 E6 两核和 MCU 一核。后续开发和运行以本目录为根。

**独立目录运行、共同虚拟时间架构和完整相机功能分别验收。** 单实例保留三个芯片域的处理器、私有地址空间、中断和复位关系。原厂应用入口、任务 / 调度 RAM、历史菜单与拍摄 OSD、辅助显示均有工程产物；整机功能仍有未验收项目。架构与回归入口见 [ARCHITECTURE.md](docs/ARCHITECTURE.md)。

## 启动与检查

本次随包运行环境适用于 **macOS Apple Silicon / arm64**。启动使用随包 Python，不需要激活虚拟环境、安装 Homebrew 或从网络下载依赖。

```sh
./z62 doctor --full
./launch.sh --profile native --architecture-only
./verify.sh latest-native
./z62 status --cached
```

本轮开发基线为 `provenance/package-manifest-native-display-recovery-20261025.json`。`provenance/package-manifest.json` 是指向该文件的包内相对 symlink；完整 `doctor` 核对本版源码、配置、运行库与文档。该版修正外部输入时基、CLI 的期限提示和显示对照报告，QEMU binary 继续使用 `20261025-201014-433b85` 构建。此前命名基线与 21:04 搬迁 / 离线重编译报告按当时身份保留，各轮运行仍按其自身 manifest 复查。`status --cached` 汇总结果而不改写历史验收。

2026-10-25 21:43 的 [最新完整 native 验收](results/20261025-214323-native-7e01f2/acceptance.md) 通过单实例架构、完整最终采样、两条调试连接及零 Host 写包检查，7 个外部事件全部交付。约 364 个宿主秒推进到 12.086 个虚拟秒，178 个保存帧中 55 个非黑帧的实际内容是 **电池无法通信弹窗**。完整场景仍返回 `1`，缺少另一种必需 `0x89` 原厂调用；中文菜单与稳定导航仍未恢复。

[固定显示对照](results/display-regressions/20261025-220134-a8a8c8/report.md) 保留旧三进程菜单、20:40 全黑轮及三个定位实验。黑屏轮把旧宿主秒直接作为虚拟期限，连 PC5 都未交付。提前交付 PC5 后恢复 scanout；360 宿主秒的缩减 PC5 + MENU 场景出现拍摄 OSD，随后是黄色等待沙漏。缩减场景和默认场景在 MENU 前已有认证重试与任务时序差异，不能把差异直接归因于按键。各张图的可见内容、原始像素 hash、完整 UART 字节和验收缺口均在对照报告中。

`native` 默认观察 120 个宿主秒，`--full` 使用 360 个宿主秒；启动、收尾和证据审计另需时间。E6 从原厂更新镜像应用入口运行，MCU 从原厂 reset vector 运行。验收要求一个 QEMU PID、五个 CPU、三个私有芯片域、共同 `QEMU_CLOCK_VIRTUAL`、完整两条 RSP / QMP 连接及零 Host RAM / 寄存器写包。

`--architecture-only` 明确选择有界原厂代码与架构观察；尚未到期的外部输入仍列为待交付。观察显示使用 `./launch.sh --profile native --full`，120 宿主秒通常只覆盖较早阶段。当前完整输入期限为共同虚拟时间 2、6.5、6.7、8、8.2、10、10.2 秒，分别交付 PC5、MENU、PG1、PG2 场景输入；pin 的物理身份和持续时长仍待测量。完整场景要求全部交付并保留电池功能条件，宿主预算不保证显示或功能完成。

启动与批量验收默认使用 `artifacts/rebuilt/latest.json` 选择的本目录编译产物。单实例 `native` 要求新构建；历史辅助 profiles 可以使用 `--binary imported` 复现保留的旧构建。

需要查看当前照片 DISP 的辅助演示时：

```sh
./launch.sh --profile still-disp
./verify.sh latest-still-disp
```

运行采用无窗口执行与观测，实际画面保存到结果目录。单实例 native 的调试器由一个 owner 控制，所有 RAM / 寄存器读取显式选择对应 CPU。辅助 profiles 保留历史三进程路径，会调用原厂函数、写入 RAM / 寄存器并使用合成输入或录制 OSD；写包数量与范围写进每次验收报告。`movie-disp` 仍未完成。

## 功能验收与进展

```sh
./accept.sh --profiles all --binary rebuilt
./accept.sh --profiles all --audit-only
./accept.sh --profiles native --architecture-only --quick
./verify.sh latest-native --strict
./z62 status --cached
```

`accept` 默认顺序运行全部六个 profiles，保留 suite 结果及每个运行的审计快照。`--profiles native still-disp` 可选择部分入口；`--audit-only` 只复查保留结果；`--quick` 让 native 使用默认 120 个宿主秒预算。`--architecture-only` 仅用于 native，明确保留未完成的完整输入表。

| 退出码 | 含义 |
|---|---|
| `0` | 本次目录运行与证据检查通过；各整机功能的状态仍需阅读报告 |
| `1` | 启动、进程、依赖、哈希、证据或场景检查失败 / 不完整 |
| `2` | 使用 `--strict` 时，证据检查通过，但整机功能仍未全部验收 |

直接阅读：[实际开发进展](results/progress.md)、[机器可读进展](results/progress.json)、[功能验收规则](docs/ACCEPTANCE.md)。新的运行不会覆盖上一轮，`latest-<profile>.json` 仅更新选择指针。

连接真机时可单独使用包内的 [电池与 MCU 配置查询](docs/CAMERA-BATTERY.md)。它保留正常 PTP 查询及已知诊断读取的全部原始返回，结果与 QEMU 验收分别保存；顺序 RAM 缓存和离线重建报文按各自证据范围记录。

## 独立开发与离线编译

```sh
./z62 build --jobs 2
./launch.sh --profile native --architecture-only --binary rebuilt
runtime/python/bin/python3.12 -B -E -s scripts/architecture_regression.py
./accept.sh --profiles all --binary rebuilt
```

完整 QEMU 10.2.4 源码位于 `src/qemu/`，本机模型位于 `src/qemu/hw/arm/` 和 `src/qemu/hw/arm/saiso-ex1850/`。`build` 使用随包 Meson、Ninja、pkgconf、头文件及库；编译器和 macOS SDK 使用系统 Apple Command Line Tools。构建设置禁用网络下载。结构回归使用显式标记的合成 RAM fixture，结果与零写包原厂 native 运行分别保存。

随包历史二进制保存在 `artifacts/formal-expeed/`、`artifacts/formal-mcu/` 与 `artifacts/qemu/`。每次新编译保存在 `artifacts/rebuilt/<build-id>/`，`--binary rebuilt` 按 `latest.json` 锁定其 manifest、binary 与 wire tool 的 SHA256。原有二进制不被覆盖。

开发入口与源码位置详见 [DEVELOPMENT.md](docs/DEVELOPMENT.md)。

## 目录

| 位置 | 用途 |
|---|---|
| `z62`、`launch.sh`、`verify.sh`、`accept.sh` | 相对路径 CLI、启动、复查与批量验收入口 |
| `src/qemu/` | 完整 QEMU 与已经实现的 Nikon / EX1850 / BA2 模型源码 |
| `src/harness/`、`src/wire/` | 单实例 owner、原厂入口观察、历史辅助协调、调试连接及总线源码 |
| `profiles/` | 六个相对路径运行配置与明确披露的辅助场景 |
| `inputs/` | 原厂模块、重建 Flash / 参数参照、合成输入与 OSD 记录 |
| `runtime/` | 随包 Python、库、OCR 及离线构建依赖 |
| `artifacts/`、`bin/` | 锁定二进制、模型快照、构建身份及 wire host |
| `results/` | 运行原始证据、画面、验收结果、进展与 suite |
| `provenance/` | 整理来源、历史参照、适配记录、交付基线哈希 |
| `build/` | 可重新生成的编译缓存；搬迁后自动重新配置 |
| `docs/` | 操作说明、验收范围、输入真实性和开发导航 |

## 路径与证据

入口根据自身文件的位置确定包根目录，所有 CLI 子命令在该目录解析配置和输入参照。即使从其他工作目录调用，包内相对路径也按工程根目录解析。运行时生成的绝对命令与路径会保留在本次 `prepare/锁定命令与输入.json`，用于说明当时实际执行的命令；搬迁后复查根据原根目录映射到当前副本，不改写原始运行证据。

操作流程与搬迁验证见 [RUNNING.md](docs/RUNNING.md)；输入真实性见 [INPUTS.md](docs/INPUTS.md)。来源档案中的旧绝对路径仅记录历史来源。本次交付的静态身份见 [package-manifest.json](provenance/package-manifest.json)，独立性实测见 [relocation-test.json](provenance/relocation-test.json)。

当前开发版静态身份见 [package-manifest-native-display-recovery-20261025.json](provenance/package-manifest-native-display-recovery-20261025.json)。真机采集与 QEMU 启动独立，离线对照和验收脚本均从本目录的相对路径运行。
