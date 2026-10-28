# 开发导航

## Current release — v0.0.2 / V44

The named `./z62 native` method now records the source-bound numerical exposure/LCD milestone. See [the native guide](NATIVE-v0.0.2.md) and [published evidence](evidence/native-v0.0.2.json). Low-level native defaults and the historical v0.01 manifest retain their separate scope.

The new method is implemented in `scripts/native_milestone.py` and registered by `scripts/z62.py`. Its manifest binds 181 files, including 119 model sources; runtime preflight compares both build manifests, all firmware fingerprints and retained Flash/RTC input evidence. The named run freezes its manifest, version and method source into the execution boundary.

Source-release regressions are available without private firmware:

```sh
python3 tests/native_milestone_regression.py
./z62 native --check-only
```

`tests/z6ii-image-input-state.c` and `tests/z6ii-image-submission-state.c` cover input-state and conservative request ownership. Retained exposure regression requires a prepared installation and an actual closed run; its 16 checks include wire-bound RAM/register/clock rejection. The published native build omits upstream ROM projects and boot blobs, preserves offline DTC/keycode/SoftFloat source dependencies and uses `--disable-install-blobs`.

The detailed prepared-package build notes below originate from 2026-10-25. Current metering, RAW/ISP and strict MENU gates remain pending; use the v0.0.2 guide for the current observation recipe.

## 源码位置

| 需要推进的部分 | 入口位置 |
|---|---|
| EXPEED Master / Slave 板型、内存和外设接入 | `src/qemu/hw/arm/nikon-z6ii.c` |
| 单实例三芯片域、配置隔离和共享 RAM backing | `src/qemu/hw/arm/nikon-z6ii-engine.[ch]`；架构说明见 [ARCHITECTURE.md](ARCHITECTURE.md) |
| 芯片内 GIC CPU 路由、精确 48 MHz Generic Timer | `src/qemu/hw/cpu/a15mpcore.c`、`src/qemu/hw/intc/arm_gic*.c`、`src/qemu/target/arm/` |
| EXPEED 外设、DDR、参数与双引擎链路 | 同目录的 `nikon-z6ii-*.h` |
| 合成 Bayer 和功能 ISP 实现 | `nikon-z6ii-bayer-*`、`nikon-z6ii-functional-isp.h` |
| HDMI 控制 / DDC / PHY / DMA / receiver | `nikon-z6ii-hdmi*` |
| BA2 原码解释执行与候选控制器模型 | `ba2-*`、`nikon-z6ii-ba2-qemu.h` |
| EX1850 MCU reset 板型和外设 | `src/qemu/hw/arm/saiso-ex1850/nikon-ex1850-reset.c` 与该目录头文件 |
| MCU 深睡 / NVIC 与 TCG 时钟保护 | `src/qemu/hw/intc/armv7m_nvic.c`、`src/qemu/accel/tcg/icount-common.c` |
| 单实例 owner、显式 CPU 读取、共同停止与原厂观察 | `src/harness/native_unified_probe.py`、`scripts/native_unified_pads.py` |
| 历史三进程辅助运行 | `src/harness/native_mcu_three_probe.py`、`natural_boot.py`、`run_exmcu_qemu_reset.py` |
| MCU / EXPEED 共享 wire 总线 | `src/wire/` 与 QEMU 模型 wire 头文件 |
| Host 辅助显示与规格实验 | `profiles/<name>/probe_z6ii.py` 及 `run_local_gpio_scenario.py` |
| 构建、启动、证据审计 | `scripts/build.py`、`z62.py`、`acceptance.py`、`progress.py` |
| 主动结构回归与合成 RAM-only 程序 | `scripts/architecture_regression.py`、`tests/architecture/` |

完整上游源码和本机模型已经一起保存。历史生成脚本及补丁快照作为来源参照保留，当前离线构建直接编译包内已经生成的源码，不回调旧工程生成器。

## 构建

```sh
./z62 build --jobs 2
runtime/python/bin/python3.12 -B -E -s scripts/architecture_regression.py
./z62 run --profile native --architecture-only --binary rebuilt
./z62 run --profile native --full --binary rebuilt
./z62 accept --profiles all --binary rebuilt
```

构建只针对 `arm-softmmu`，禁用不需要的 GUI、网络下载及额外组件。Meson、Ninja、pkgconf、Python bootstrap、库和头文件随包提供，Clang / SDK 来自 Apple Command Line Tools。

每个 `artifacts/rebuilt/<build-id>/` 包含构建日志、命令、源树文件清单与 tree SHA、编译产物、冻结的模型源码、EXPEED / MCU manifests 和 wire tool。构建验证版本及 Nikon 板型，包括 `nikon-z6ii-native`，然后更新 `artifacts/rebuilt/latest.json`。单实例的两个 manifests 必须选择同一个 binary。编译通过后还要做动态架构回归与零写包原厂运行。

结构回归显式写入合成 RAM 程序，通过实际 guest 指令验证 MPIDR、私有内存、共享 backing、SGI/PPI、CNTVCT、SysTick 与 MCU 局部复位；不会作为原厂固件功能通过的依据。普通 native 运行不加载这些程序，其调试器 facade 拒绝 RAM / 寄存器写入。两类结果分别保存在 `results/architecture-regressions/` 与原厂运行目录。

`build/qemu-arm/` 只存生成缓存。同目录增量编译可以复用；根目录或工具链条件变化时重新配置；`--clean` 只清除此缓存。历史运行继续按本次锁定的不可变构建目录复查。

## 建议推进顺序

先确认 native 的原厂入口、任务 RAM、外设边界与跨端事务，再补足自然启动及业务状态的因果链。对调度、MENU、capture 和 HDMI 的改动，应记录原厂代码的触发、原始调用参数、结果缓冲、设备事件与画面 / 媒体，而不仅是场景标签和计数。

模型中的 `candidate`、`synthetic`、`observed` 范围继续保留。辅助 Host 调用可用于探索原厂函数和显示层，但其结果应进入 assisted 报告，不能把 Host 写好的队列、寄存器或 frame buffer 当成 native 功能已实现。

并发保持克制，批量验收顺序运行。默认 native 每轮启动一个 QEMU，历史辅助场景仍为三进程。本次架构整合未操作实体相机。

## 身份与交付基线

`provenance/package-manifest.json` 封存交付时的静态文件；可变的结果、构建缓存、重编译选择指针与 Python cache 不进入该清单。最新 rebuild 由独立 build manifest、源码 inventory 和 doctor 验证。

发生源码更改后，以新的构建目录及新的验收结果记录进展。旧结果的 `prepare/execution-sources/` 用于严格匹配其实际运行源码，避免后续适配把旧运行的证据身份破坏。

完成修改、重编译和运行验证后，可使用 `scripts/seal_package.py --output provenance/package-manifest-development-01.json` 生成新的静态基线，再以 `./z62 doctor --full --baseline provenance/package-manifest-development-01.json` 检查。旧交付基线保留；默认检查仍与交付时的静态文件比较。
