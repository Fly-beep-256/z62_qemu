# Z7 II 社区源码与 Z6 II 固定运行对照

Historical community/run comparison. The current Z6II source milestone is [v0.0.2 / V44](NATIVE-v0.0.2.md); statements below remain bound to their dated historical runs. Local raw reports referenced below are omitted from the Git distribution.

**历史范围：** 本文下方固定对照的是 2026-10-25 12:30 的三进程运行 `20261025-123046-native-f2d0f9`。其中的“本机菜单 / OSD”“三个独立时钟”和缺失报文结论仅属于该旧运行。当前默认 native 已整合为一个 QEMU、五核、三个私有芯片域和共同虚拟时间，见 [ARCHITECTURE.md](ARCHITECTURE.md) 与 [21:43 当前完整默认验收](../results/20261025-214323-native-7e01f2/acceptance.md)。该轮已交付全部 7 个外部输入，完整 UART TX / RX 为 171 / 314 字节，非黑画面实际为电池通信错误弹窗；新单实例中文菜单和稳定导航仍未恢复，另一种必需 `0x89` 原厂返回仍缺失。20:40 全黑轮及输入时基修复见 [显示回归报告](../results/display-regressions/20261025-220134-a8a8c8/report.md)。下方旧证据和配套 JSON 按原身份保留。

后续核查了包内的 Z6、Z8、Z9 社区参照。Z8 [native-mcu.md](../provenance/community/z8-reference-20261025/sources/docs/native-mcu.md#L305-L314) 记录其 inspected boot 在 USART1 发出单个 NUL；这可以与本机原厂单字节事务做源码 / 模型层面的对照，不能解释 Z6II 的物理电池协议。Z9 的外部时钟与合成回复也不能替代本机原厂请求和返回。最新真机读取、原厂 `00` 来源纠正与逐运行差异见 [CAMERA-BATTERY.md](CAMERA-BATTERY.md)。

比较日期：2026-10-25。输入身份复核时间：2026-10-25T05:03:00.521860+00:00。机器可读配套文件：[provenance/community/z72-comparison-20261025.json](../provenance/community/z72-comparison-20261025.json)，schema 为 `z62.community-z72-comparison/1`。

本旁支只形成源码/现存报告对照，不实施移植。社区在有限实验条件下留有原厂菜单打开与部分导航证据；本机固定 native 运行已有中文菜单/OSD、严格电池 peer 和两轮原厂参数转换/复制。社区通用 `0x89` ACK、guest nonce 桥以及菜单报告的成功字段，均不能替代本机缺失报文或完整相机功能验收。

## 范围与证据身份

- 社区来源：[https://github.com/JKWTCN/z72-qemu](https://github.com/JKWTCN/z72-qemu)；本地参考目录为 `provenance/community/z72-qemu-reference`。
- 预期及实测 HEAD 均为 `f5f4ba31b324de5abf6f24d399afff878ffd949a`；origin 为 `https://github.com/JKWTCN/z72-qemu.git`。作者/提交者 JKWTCN，提交时间 `2026-10-24T13:28:45+08:00`，主题 `feat(research): reproduce GetDeviceInfo operation advertisement`。参考工作树在身份读取时干净。
- Git 仅使用 `/Library/Developer/CommandLineTools/usr/bin/git`，只读元数据，不 fetch、不改 checkout。
- 社区目标是 **Z7 II C1.70**；本机是 **Z6 II C1.70**。固件输入、私有地址与功能验收不能互换。
- 本机对照固定为 `results/20261025-123046-native-f2d0f9/`。此前 `results/latest-native.json` 指向该 run，更新时间为 `2026-10-25T04:36:49.901026+00:00`；本文件不跟随 alias 移动。
- 用户后来告知主线已启动 `20261025-125630-native-2e62e7`，新增配置后启用的被动轮询/复合更新任务追踪，并通过配置 SP/LR/输出三类负例。这是用户补充信息，本旁支未读取新 run，也未用它替换已核实基准。
- 本任务没有运行社区脚本、启动 QEMU、构建项目、访问相机、重复联网、修改 memory，或修改任何源码、配置、运行报告；写入范围只有本 Markdown 与配套 JSON。主 agent 的共享目录改动独立于本旁支。

**观察事实**指实际读取的源码、Git/字节身份、已保存报告与此前直接查看的固定像素；报告所述行为仅在其输入条件内成立。**推断**指设计迁移价值与有限因果解释。**未知**指尚未完成的物理时序、版本绑定或功能验收。保存于 HEAD 的报告不等于该报告执行了这一 HEAD 的构建。

参考仓库启用了 sparse checkout。`qemu/nikon-z72-controller.h`、`qemu/nikon-z72-profile.h`、`tools/menu_navigation_probe.py`、`tests/test_controller_battery.py` 在索引中标记 `S`，当前未展开；本任务未读取或执行它们。它们不是仓库缺失依赖，本任务没有验证构建。

## UART：每字节虚拟时钟与本机已有串行接收

**观察事实。** [qemu/nikon-z72-controller-battery.c:233](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/qemu/nikon-z72-controller-battery.c#L233-L234) 定义 `BATTERY_BYTE_NS=1145834`，即 `ceil(11 × 10^9 / 9600)` ns。11 个线路位对应 start + 8 data + parity + stop。[qemu/nikon-z72-controller-battery.c:269](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/qemu/nikon-z72-controller-battery.c#L269-L293) 使用 `QEMU_CLOCK_VIRTUAL`，首字节与后续字节均延后一字节周期；仅当 `qemu_chr_be_can_write()>0` 才投递并递增 `reply_pos`。不能消费时保留字节并重排 timer，不把回复一次性灌入接收端。

整机 reset 清理未完成请求与排队回复，见 [qemu/nikon-z72-controller-battery.c:239](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/qemu/nikon-z72-controller-battery.c#L239-L244)。[research/z7ii/battery_serial.md:29](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/research/z7ii/battery_serial.md#L29-L50) 说明独立 controller reset 不重置外部 peer、peer 默认关闭且无迁移状态支持。这些是实验模型的复位域和保存状态边界。

本机已有下列能力，且配套 JSON 对应到固定 build/执行源码快照：

| 本机位置 | 已具备行为 |
| --- | --- |
| [src/qemu/hw/arm/saiso-ex1850/ex1850-usart1-chardev.h](../src/qemu/hw/arm/saiso-ex1850/ex1850-usart1-chardev.h#L33) | 按 256 字节队列剩余容量提供 can_read。 |
| [src/qemu/hw/arm/saiso-ex1850/ex1850-usart1-rx-core.h](../src/qemu/hw/arm/saiso-ex1850/ex1850-usart1-rx-core.h#L65) | 按 guest BRR/PCLK 与完整帧格式计算接收 deadline，逐帧投递。 |
| [src/qemu/hw/arm/saiso-ex1850/ex1850-usart1-board.h](../src/qemu/hw/arm/saiso-ex1850/ex1850-usart1-board.h#L13) | TX/RX deadline 合并，使用 MCU 所属 QEMU 虚拟时钟；RCC/APB2 推导 PCLK2，IRQ37。 |
| [src/qemu/hw/arm/saiso-ex1850/ex1850-usart2-core.h](../src/qemu/hw/arm/saiso-ex1850/ex1850-usart2-core.h#L65) | BRR/OVER8、数据/校验位置与 STOP 位计算供串口时序使用。 |
| [src/harness/ex1850_usart1_peer.py](../src/harness/ex1850_usart1_peer.py#L80) | Host turnaround 默认为 `0.002` 秒，相关延迟路径见 148–162、185–192 行。 |

本机在断连、reset、receiver/clock disable、格式/时钟变化时清除队列及 inflight，社区 peer 在暂时不能消费时保留回复字节。两者覆盖的状态并不相同，不能把社区等待消费策略直接当成真实线路的 overrun/丢字节行为。2 ms 是本机声明的 Host wall-clock 策略，不是实测电池延迟，也不证明 Host 与 guest 的时钟顺序。**不能称本机没有串口时序。**

**推断 / 可迁移设计。** 有价值的是逐字节事件、timer deadline、消费条件、队列保留/丢弃与复位域的可审计记录。应在现有 BRR/PCLK 模型上作证据对照，不能仅通过加入社区常数就宣称时序正确。**未知：**实物线路延迟、实际背压/overrun、串行 DMA 和跨时钟排序仍未由这些策略验收。

## 双引擎：私有地址视图、共享 RAM 与时钟

**观察事实。** [qemu/nikon-z72.c:2415](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/qemu/nikon-z72.c#L2415-L2442) 与 [qemu/nikon-z72.c:2640](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/qemu/nikon-z72.c#L2640-L2777) 将 master/slave 放在同一个 QEMU machine 中，每个引擎各两核、各自 private MemoryRegion/GIC；两块各 1 MiB 的 message RAM 及 peer bus alias 共用 backing。可选 controller 有私有 view，形成第五执行槽。端点使用同一 machine 的虚拟事件时间域。

源码也保留边界：2640–2643 行说明 physical timing 与 payload lane transfers 未建模，2685–2687 行把 readiness wiring 标为从互补原厂路径推断。[tools/dual_boot_probe.py:222](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/tools/dual_boot_probe.py#L222-L231) 已描述当前通知连接；不能据旧报告断言当前源码仍无通知。

本机固定运行是 **master、slave、MCU 三个 QEMU 进程，虚拟时钟独立**。[results/20261025-123046-native-f2d0f9/acceptance.json](../results/20261025-123046-native-f2d0f9/acceptance.json) 的 `lifecycle.status=verified` 证明三个归属进程启动且保留了实际退出；`firmware_success_implied=false`，不以退出码代替原厂功能成功。`functional_gates.cross_engine_causality.status=not_verified`：完整带内容的请求—DMA—ACK—响应见证仍不足。

**推断 / 可迁移设计。** private view + shared backing/alias 可以作为地址映射与统一虚拟事件架构的参考，但改成同进程并不自动证明物理时序或跨端因果。本旁支没有更改三进程方案，也没有移植这些区域。若继续三进程，仍需保留端点时间、事务内容及因果连接，而不只比较计数或宿主时间。

## 0x89：社区通用 ACK 与本机严格合同

**观察事实。** [qemu/nikon-z72-controller-battery.c:359](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/qemu/nikon-z72-controller-battery.c#L359-L405) 按 `p[2]+4` 消费完整帧并检查 XOR；对 **任意合法 cmd=0x89、len=14 的帧**回复 `02060004`，没有完整 payload 白名单。[research/z7ii/battery_serial.md:24](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/research/z7ii/battery_serial.md#L24-L27) 说明设置 ACK 只表示模型接收受支持报文，尚未模拟全部电池侧效果。

本机 [src/harness/ex1850_battery_peer.py](../src/harness/ex1850_battery_peer.py#L94) 普通请求按 `self.exact.get(frame)` 完整匹配，未知请求报错，不猜回复。[inputs/specs/battery-native-20261025.json](../inputs/specs/battery-native-20261025.json#L557) 与 [scripts/audit_battery.py](../scripts/audit_battery.py#L48)、[scripts/audit_battery.py](../scripts/audit_battery.py#L209) 保留两条完整 `required_TX` 并要求逐条出现原厂成功返回；验收入口见 [scripts/acceptance.py](../scripts/acceptance.py#L309)。

| 必须保留的完整 TX | 固定运行线路/原厂结果 |
| --- | --- |
| A：`02890e00000000080000000000000101068b` | 线路 exchange seq 8/11，两次 RX=`02060004`；原厂返回 R0=0，accepted count=2。 |
| B：`02890ec800c8000400000000000101010181` | 缺少所要求的原厂返回；固定 acceptance 唯一 error。 |

固定 [results/20261025-123046-native-f2d0f9/acceptance.json](../results/20261025-123046-native-f2d0f9/acceptance.json) 审计时间为 `2026-10-25T04:39:37.759937+00:00`，唯一错误原文：

```text
Required original cmd89 return not observed: 02890ec800c8000400000000000101010181
```

**本机 ACK 白名单与 required_TX 不得放宽。** 社区通用 ACK 既不能证明 B 已发送/已由原厂成功返回，也不能补足电池设置物理效果。

本机参数链的时间关系如下。此表采用配置/原厂观察序号，不能与线路 exchange seq 8/11 混淆。

| 原厂配置/调用事件 | observation seq | MCU HAL_tick |
| --- | --- | --- |
| 首次转换完成 | 1 → 2 | 607 |
| 首次复制完成 | 3 → 4 | 607 |
| A 第一次原厂成功返回 | 15 | 1865 |
| A 第二次原厂成功返回 | 16 | 1969 |
| 第二次转换完成 | 17 → 18 | 3217 |
| 第二次复制完成 | 19 → 20 | 3217 |

两组 conversion/copy 配对及 source→cache/info 均 `verified`，`guest_state_supplied=false`，链状态为 `verified_original_configuration_chain`。初始 info SHA256 为 `834a709ba2534ebe3ee1397fd4f7bd288b2acc1d20a08d6c862dcd99b6f04400`，首轮完成为 `39b0f4064fa23d25980564a7de1e7723bb3dc3d2c8422c0653448e62a38e7226`，第二轮完成为 `2c6b3f35e8672827c1399a85b62f6f8b577080f7be8c40039a88871b4defdf7d`。

**观察事实：**第二轮完整参数更新发生在两次 A 成功返回之后。不能描述为“参数没有转换/复制”或“peer 完全不 ACK”。**推断边界：**这一顺序并不足以认定 B 缺失的唯一原因；本旁支不介入主线新增追踪及负例工作。

## nonce bridge 与实验电池报告

**观察事实。** [qemu/nikon-z72-controller-battery.c:39](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/qemu/nikon-z72-controller-battery.c#L39-L40)、[qemu/nikon-z72-controller-battery.c:295](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/qemu/nikon-z72-controller-battery.c#L295-L333) 从 guest `0x2001F446` 读取 18 字节 nonce，从 `0x2001F458` 读取 18 字节 published 值，对比 challenge 前 17 字节并重算、校验 published 后生成回复；不一致时静默。这依赖控制器的私有 RAM，地址绑定该社区控制器输入。

[research/z7ii/battery_serial.md:35](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/research/z7ii/battery_serial.md#L35-L50) 已明示该桥不能从串行请求独立推导真实电池应答。“不写 guest RAM/不改固件”与“读取 guest 私有状态”可以同时成立，前者不能消除后者的局限。**不能把该桥称为仅靠线路实现的真实电池认证，也不能直接搬入 Z6 II 严格 peer 验收。**

[artifacts/battery_peer_validation/report.json](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/artifacts/battery_peer_validation/report.json) 留有 `passed=true`、`battery_exchange_verified=true`、`experimental_nonce_bridge=true`，`factory_calibration=false`、`firmware_modified=false`、`full_boot_verified=false`、`menu_verified=false`。输入启用 battery peer、关闭 supply peer；12 个窗口，`instruction_time="shift=0,sleep=off"`，最长连续观察约 `5.192245583333333` 虚拟秒，引擎/控制器 fault 记录为零。

[tools/battery_boot_probe.py:106](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/tools/battery_boot_probe.py#L106-L123) 保留实验桥和未完成标志并生成实验参数；201–205 行的电池状态门槛是 battery_status=`0x02`、policy_flags=0、timeout=30 秒、control_ready_bitmap=15。这是该部分判据，不能替代探针的全部图形/持续运行检查或相机功能验收。本任务仅读源码/报告，没有执行探针。

本机 peer 的输入范围见 [src/harness/ex1850_battery_peer.py](../src/harness/ex1850_battery_peer.py#L1)：公开 TX、immutable spec 与声明的外部 RNG 重建，不读取 guest 私有 RAM。固定运行记录 comparator_return=1、completion_ready=1、completion_error=0，`original_authentication_acceptance_observed=true`，同时 `physical_authentication_verified=false`。原厂比较接受与真实电池认证是不同证据层级。

## 最新菜单报告：已打开与稳定重入的边界

**观察事实。** [artifacts/menu_navigation_validation/report.json](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/artifacts/menu_navigation_validation/report.json) 是本次采用的具体菜单报告，`passed=true`、`menu_opened=true`，但 `full_boot_verified=false`，`resource_header_only=true`、`sync_pulse_supplied=true`，`firmware_modified=false`、`runtime_state_written=false`。这些显式实验资源/同步输入应与成功字段一起保留。报告方法对照见 [research/z7ii/controller_keys.md:246](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/research/z7ii/controller_keys.md#L246-L263)。

menu pin=9；一次 sweep 顺序为 `[4,5,6,7,3,8]`。下表的像素差均相对已打开菜单的基线：

| pin | changed_pixels | 报告观察 |
| --- | ---: | --- |
| 4 | 60906 | 高亮下移一项，底部说明变化。 |
| 5 | 0 | 在 pin 4 之后回到基线；基线差为零不表示按键无效。 |
| 6 | 0 | 位于最左标签时向左无可见变化。 |
| 7 | 49213 | 向右切换标签，标题和列表重绘。 |
| 3 | 0 | 确认位到达引擎；顶层标签页无可见变化。 |
| 8 | 39600 | 前台切换为播放应用 index 2。 |

报告明确：**关闭菜单后不能重新打开**；上/左映射依据一次 sweep 的返回基线/无变化，适用范围有限；确认位虽到达引擎，顶层标签页没有可见变化。这能支持有限导航，不能支持稳定重入或确认业务效果。pin 5 的零基线差尤其不能解释成上键无效。

社区菜单与电池报告保存了固件 SHA，却未保存对应 QEMU binary/build SHA；文件字节已核实属于当前 HEAD，不等于已核实报告执行的是当前 HEAD 的构建。菜单探针处于未展开状态，本任务未读/未运行。

本机固定运行已有实际 native 中文菜单/OSD 像素，`LCD.frame_files=6`，有 3 种非黑非均匀画面，`host_guest_write_gate=zero_guest_writes_verified`；本旁支此前直接查看的两张图片为：

| 固定图片 | 视觉观察 | bytes / SHA256 |
| --- | --- | --- |
| [results/20261025-123046-native-f2d0f9/run/EXPEED/engines/master/LCD-timeline/frame091.png](../results/20261025-123046-native-f2d0f9/run/EXPEED/engines/master/LCD-timeline/frame091.png) | 中文“播放菜单”，含“删除”等条目。 | 52612 / `a5b22e45ab063285d94e0645cd24ec57635f7aed347f02b583591b713824a167` |
| [results/20261025-123046-native-f2d0f9/run/EXPEED/engines/master/LCD-timeline/frame089.png](../results/20261025-123046-native-f2d0f9/run/EXPEED/engines/master/LCD-timeline/frame089.png) | 拍摄 OSD，画面中心黑色。 | 14055 / `169283dba895bf27ce9d4ec991aa0b71cbfaacbbd7a6ab253741038d393a2e7b` |

这证明保存的菜单/OSD 输出，`stable_menu` 与 `original_dynamic_image_payload_verified` 仍未验收。稳定导航、确认、退出/多轮重入应建立外部输入→原厂解码→前台→帧差→资源生命周期的证据链。用户明确 **movie-disp 未完成**，不可据前台名称、mode 值或 OSD 推定完成。

## 历史报告不能覆盖当前源码或新菜单证据

[artifacts/dual_boot_validation/report.json](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/artifacts/dual_boot_validation/report.json) 日期是 `2026-10-11`，说明来自公开前私有 research revision。其 binary SHA256 为 `b02bc5478c8ae7b4b82e2da4c974de16bffddab97a9ca44b1322473882c020b6`；记录的 `qemu/nikon-z72.c` SHA256 为 `6c093c2adf66597a89795a26ca4e73bf271e6d94f36ee8c376e6cccbae3f55a0`，与当前 HEAD 的 `c40074dc2f62d928a9e59a943c9a0dfe655e53e3f037d10bcdf4e0e17294c03c` 不同。旧报告的“doorbell 未建模”“菜单未验证”不能覆盖当前通知源码和较新的具体菜单报告，也不能用旧 passed 字段替当前源码提供验收。

[research/z7ii/kernel_handoff.md:314](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/research/z7ii/kernel_handoff.md#L314-L340) 是历史里程碑；381–386 行说明早期替代字段已移除，历史记录不能当成当前模型或完整启动依据。README、architecture 和 battery_serial 也包含不同阶段的状态描述，应与具体报告分层读取。

[artifacts/controller_battery_uart_validation/report.json](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/artifacts/controller_battery_uart_validation/report.json) 是较早的 USART 窗口/IRQ/隔离报告：当时仅 file backend、没有响应 peer，且 exact line timing/DMA 未建模。它不能用来否定当前社区 byte pump，亦不能据此误称本机没有串口时序。

## 本机已具备、可迁移设计与仍未知

| 分类 | 对照结论 / 后续证据方向 |
| --- | --- |
| 本机已具备 | BRR/PCLK 串行接收、TX/RX deadline 合并、2 ms Host 策略、完整 TX 白名单与两条 required_TX、固定输入/构建/执行源码快照。已有原厂配置链及中文菜单/OSD 输出。 |
| 可迁移设计 | 每字节虚拟事件与背压/丢弃记录；peer/controller reset 域及生命周期证据；private view/shared backing 架构参考；菜单输入、解码、前台、像素差及退出重入的验证方法。 |
| 不能迁入验收 | guest nonce 桥、所有合法 0x89 通用 ACK；以 mode、进程正常退出或单张菜单图替代严格报文与完整相机功能。 |
| 仍未知 | 实机线路/设置效果、三进程时钟因果、B 缺失充分原因、稳定菜单重入、完整自然 Flash 启动与调度身份、Live View、capture/RAW/ISP、movie-disp/录像与 HDMI。 |

固定 `full_camera_status=not_verified`，八个 `functional_gates` 全部 `not_verified`。capture 地址/配置、RAW/ISP、original video/DMA 计数为零，HDMI 无非空 payload。可见菜单/OSD和电池部分接受不改变这些门槛。本任务没有新增功能验收结论，也没有宣称已经移植。

## 本机固定输入身份

以下为实际重新计算字节数与 SHA256、并与 locked/build 记录核对的输入。两个 build manifest 选择同一 binary；QEMU 版本 `10.2.4`，记录的 build source-tree SHA256 为 `79a5fb74b52d2c6ac727927c9b2ba26c1f3c50531b01118ec1c7f251325c28a4`。该 tree 标识来自 manifest，不是把当前共享源码树重新当作固定构建树。

| 文件 / 输入 | bytes | SHA256 |
| --- | ---: | --- |
| [results/20261025-123046-native-f2d0f9/acceptance.json](../results/20261025-123046-native-f2d0f9/acceptance.json) | 329655 | `dd808fef7038da42bf6e97de6d92fb6d8444641934624ea6306e4cfcc4bef383` |
| [results/20261025-123046-native-f2d0f9/prepare/锁定命令与输入.json](../results/20261025-123046-native-f2d0f9/prepare/锁定命令与输入.json) | 22125 | `6a64248577dbecaeaa5d0200f5a162eb38f56f1c50aa02fdc5eb9ab4c146a1f4` |
| [results/20261025-123046-native-f2d0f9/run.json](../results/20261025-123046-native-f2d0f9/run.json) | 175 | `434083c64748829eda77d5d66bdc5986b80571da01e20a1966803c42b5d6e141` |
| [inputs/specs/battery-native-20261025.json](../inputs/specs/battery-native-20261025.json) | 24072 | `87103a0217e62b800d9a766d7301825af9994287c3714f53e4240dd89ae5de5f` |
| [artifacts/rebuilt/20261025-101647-7cae64/EXPEED-build-manifest.json](../artifacts/rebuilt/20261025-101647-7cae64/EXPEED-build-manifest.json) | 29636 | `d604839f14071456e0ad8ae1b33c26fac0b5659f9891783adf28a6fb49d9a8f7` |
| [artifacts/rebuilt/20261025-101647-7cae64/MCU-build-manifest.json](../artifacts/rebuilt/20261025-101647-7cae64/MCU-build-manifest.json) | 29528 | `05cd8b056f9a3ee5c2d8e63be3ef7f2e76006b24eea8c58925c1b467f101b996` |
| [artifacts/rebuilt/20261025-101647-7cae64/qemu-system-arm](../artifacts/rebuilt/20261025-101647-7cae64/qemu-system-arm) | 9258736 | `67241785eb024b0933d1aeb910a166d51ca74d94f7588510b620a3cbb27f547a` |
| master：[inputs/firmware/master-original-with-crc.bin](../inputs/firmware/master-original-with-crc.bin) | 38750138 | `bb83613121f843d65101da936d942acdc513d86dbd3abc26259d0d870d03f5d4` |
| slave：[inputs/firmware/slave-original-with-crc.bin](../inputs/firmware/slave-original-with-crc.bin) | 8832194 | `3fd8c2cbdf57fadb03f6d69b596b58a8703efdd61ae82572d5afeea0241a9ed5` |
| MCU：[inputs/firmware/ex1850_012000.bi.bin](../inputs/firmware/ex1850_012000.bi.bin) | 524288 | `4314c17d9a6676a4254aa4d74d4aa35411e3a793ea7056c06f9c83f160da3cb1` |

相关源码以固定快照身份绑定；源码读取时的当前文件与快照比较结果列在末列。主 agent 后续修改当前源文件不改变本固定输入的含义。

| 原源码 relative path | 固定 build / execution 快照 | 快照 SHA256 | 读取时当前字节对照 |
| --- | --- | --- | --- |
| `src/qemu/hw/arm/saiso-ex1850/ex1850-usart1-chardev.h` | [固定快照](../artifacts/rebuilt/20261025-101647-7cae64/model-sources/src/qemu/hw/arm/saiso-ex1850/ex1850-usart1-chardev.h) | `7f7f2c364c89d8a40e4418a0e6a8ff8d307742c81595248bc947d460bc6e38c1` | 一致 |
| `src/qemu/hw/arm/saiso-ex1850/ex1850-usart1-board.h` | [固定快照](../artifacts/rebuilt/20261025-101647-7cae64/model-sources/src/qemu/hw/arm/saiso-ex1850/ex1850-usart1-board.h) | `eb0294afef47f781a30332aa14fa5feb9278154809b2e7783f3428404d8923a9` | 一致 |
| `src/qemu/hw/arm/saiso-ex1850/ex1850-usart1-rx-core.h` | [固定快照](../artifacts/rebuilt/20261025-101647-7cae64/model-sources/src/qemu/hw/arm/saiso-ex1850/ex1850-usart1-rx-core.h) | `a48a8cb518012ba3725c516e2cce235c311417f20e12ca08dc9a7e175d6143b3` | 一致 |
| `src/qemu/hw/arm/saiso-ex1850/ex1850-usart2-core.h` | [固定快照](../artifacts/rebuilt/20261025-101647-7cae64/model-sources/src/qemu/hw/arm/saiso-ex1850/ex1850-usart2-core.h) | `036ac1db3f8c12db6625c0f63d7cf7cc12a5af1ac2d12ac3da0045977a07225d` | 一致 |
| `src/harness/coupled_dual.py` | [固定快照](../results/20261025-123046-native-f2d0f9/prepare/execution-sources/src/harness/coupled_dual.py) | `4d3522f5683a8eeebd4ba67fe186c0e5420c4c8ead5342d52a7af2010817560a` | 一致 |
| `src/harness/ex1850_battery_config.py` | [固定快照](../results/20261025-123046-native-f2d0f9/prepare/execution-sources/src/harness/ex1850_battery_config.py) | `1f8aed273d6e1c8711cbe203b487b133ec4986a337ee89e134dbcc80d4f758fb` | 一致 |
| `src/harness/ex1850_battery_peer.py` | [固定快照](../results/20261025-123046-native-f2d0f9/prepare/execution-sources/src/harness/ex1850_battery_peer.py) | `e3e3e55a2407f588c58c41da2f001f2d9c059856022c11796aa11f7ab9ab7832` | 一致 |
| `src/harness/ex1850_usart1_peer.py` | [固定快照](../results/20261025-123046-native-f2d0f9/prepare/execution-sources/src/harness/ex1850_usart1_peer.py) | `0fe5d5c96f7f7837175cc0df3533bcb53875372e102e51f515179aaf13e10832` | 一致 |

完整 JSON 同时保存审计器身份、配置观察与线路两套序号、报告判据、局限、source/report 引用及未执行声明。后续主线运行应另立输入与验收身份，本文件仅覆盖指定固定 run。

## 社区用到的文件、来源与许可

下表 17 个文件均以实际字节计算 SHA256 与 Git blob SHA1，并核对 HEAD/索引一致。`publication-manifest.json` 有 398 个条目，其中本次其余 16 个文件的 SHA256 与条目匹配；manifest 不列自身，不把这说成 17 个 manifest 条目均匹配。

各来源链接均固定到 commit **`f5f4ba31b324de5abf6f24d399afff878ffd949a`**；配套 JSON 每条记录单独保存 relative_path、bytes、SHA256、commit、来源 URL、blob 身份和许可说明。

[NOTICE.md:3](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/NOTICE.md#L3-L20) 记载 WonderLantern Z6/Z7、R3tr0ooo 等贡献。overlay/tools/tests/documentation 默认 **GPL-2.0-or-later**；三个本次读取的 qemu overlay 文件头也有相同 SPDX。[COPYING](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/COPYING) 是 GPL v2 正文，QEMU 上游仍保留逐文件许可。本任务未验证仓库所有逐文件许可证；项目许可不授予 Nikon 固件权利。本对照不复制固件、候选二进制或算法原始字节。

| 社区 relative path / 固定来源 URL | bytes | SHA256 | 许可说明 |
| --- | ---: | --- | --- |
| [README.zh-CN.md](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/README.zh-CN.md) | 18916 | `7579849e15ebbeccb3524a59d755442b07ffe8f0b894122b533b595411282360` | GPL-2.0-or-later；NOTICE 默认 |
| [NOTICE.md](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/NOTICE.md) | 1543 | `43e50a435803f73b7bdfdefdc5bcb5355f8d784bdaa709c893701dc81e6f86a3` | GPL-2.0-or-later；NOTICE 默认 |
| [COPYING](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/COPYING) | 17880 | `dd3ce02338c3a48abb6ba59b48809f7108a8bd242cb0cc8be90daafa30707c28` | GPL v2 正文；仓库默认 GPL-2.0-or-later |
| [publication-manifest.json](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/publication-manifest.json) | 43949 | `a565387daa01f248feaff0806ae05399e2d49ffbca995a716d81ecb384ec0594` | GPL-2.0-or-later；NOTICE 默认 |
| [docs/architecture.md](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/docs/architecture.md) | 11688 | `1596b7403b9c1ad4966892998160d199c85c0223a12e48d11e8a85f651d1b104` | GPL-2.0-or-later；NOTICE 默认 |
| [research/z7ii/battery_serial.md](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/research/z7ii/battery_serial.md) | 5564 | `f648ab6ec403a674338a636e500b50345104adb26a84c3939bf45dce65bf2c1d` | GPL-2.0-or-later；NOTICE 默认 |
| [research/z7ii/controller_keys.md](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/research/z7ii/controller_keys.md) | 35372 | `5f04ba276bf77bdcea7271e3c928af6686da0b5cc8f862cdca9606eb45cd3fa2` | GPL-2.0-or-later；NOTICE 默认 |
| [research/z7ii/kernel_handoff.md](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/research/z7ii/kernel_handoff.md) | 28046 | `7f80c139274a514f95331e86788def3ea9e754ba4780887a0d8b0b8571956c4c` | GPL-2.0-or-later；NOTICE 默认 |
| [qemu/nikon-z72.c](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/qemu/nikon-z72.c) | 124216 | `c40074dc2f62d928a9e59a943c9a0dfe655e53e3f037d10bcdf4e0e17294c03c` | GPL-2.0-or-later；文件 SPDX |
| [qemu/nikon-z72-controller.c](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/qemu/nikon-z72-controller.c) | 35339 | `a3ce09ae09828bfe66e50641eed8d1caa17c3010b54c6d097fb994469ad31e12` | GPL-2.0-or-later；文件 SPDX |
| [qemu/nikon-z72-controller-battery.c](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/qemu/nikon-z72-controller-battery.c) | 14765 | `a48fa6d28da7316a306525af69363fbe1ee1cb434b80aeb0c390e0e293dcf6b7` | GPL-2.0-or-later；文件 SPDX |
| [tools/dual_boot_probe.py](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/tools/dual_boot_probe.py) | 11104 | `addd6f77d977190cc954c5afd2288046055ff6645f98d5f13534cb31b0e5042c` | GPL-2.0-or-later；文件 SPDX |
| [tools/battery_boot_probe.py](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/tools/battery_boot_probe.py) | 14267 | `1c5429257309c3c08dd2f9fc0a1b34117b2333dbfaddfc17c3b5f80f63ebf2f8` | GPL-2.0-or-later；文件 SPDX |
| [artifacts/dual_boot_validation/report.json](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/artifacts/dual_boot_validation/report.json) | 3604 | `be591b8474687e7b22adf285b9c49d14c76deb1a0429f1abdc17fb95daeb4ec2` | GPL-2.0-or-later；NOTICE 默认 |
| [artifacts/controller_battery_uart_validation/report.json](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/artifacts/controller_battery_uart_validation/report.json) | 1865 | `278d4df442f6245a85be9e6c32de524f86866e8e93c84c49f327e5b41fa7f9c5` | GPL-2.0-or-later；NOTICE 默认 |
| [artifacts/battery_peer_validation/report.json](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/artifacts/battery_peer_validation/report.json) | 37473 | `fdcce2caa56a07acecd5bf3d813f6ed1d1664aba564dab4fe3b7230f649e1ef6` | GPL-2.0-or-later；NOTICE 默认 |
| [artifacts/menu_navigation_validation/report.json](https://github.com/JKWTCN/z72-qemu/blob/f5f4ba31b324de5abf6f24d399afff878ffd949a/artifacts/menu_navigation_validation/report.json) | 8294 | `88b57bd4bc7ad87bcd22f29df98b430937e4817082c84cb2116d5d3660d5309d` | GPL-2.0-or-later；NOTICE 默认 |

本旁支检查仅限输入身份、JSON 可解析、引用/哈希及上述固定字段一致性；没有重跑社区或本机运行验收。
