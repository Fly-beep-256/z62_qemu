# 功能验收规则与当前覆盖范围

## v0.0.2 acceptance scope

[The V44 native milestone](NATIVE-v0.0.2.md) verifies original numerical exposure publication and exact reviewed LCD text under explicit `next-frame-ae-v4` / `pending-v1` hypotheses. Its source-bound run completed the 34-second virtual window with both actual debugger streams, final common-stop sampling and zero guest RAM/register writes.

`./z62 native --check-only` checks published source identities and plans only. `--preflight-only` checks prepared dependencies and input/build identities without a firmware run. `./z62 exposure-verify` replays actual RSP/QMP replies and verifies original publication and reviewed LCD pixels; it preserves `changing_light_metering_feedback_verified=false`, `RAW_ISP_frame_completion_verified=false` and `full_camera_verified=false`.

The current strict MENU delay exceeds the unchanged 3-second criterion, so stable MENU/reentry remain false. Existing whole-camera criteria and the broad UI exposure gate are not relaxed. The 2026-10-25 historical runs discussed below retain their own fixed identities; current evidence is [the v0.0.2 summary](evidence/native-v0.0.2.json).

验收入口是 `./z62 accept`；保留证据复查入口是 `./z62 verify`。两者使用同一个 `scripts/acceptance.py`，按本次锁定 binary / ROM / 输入 / 源码与原始运行文件生成报告。

## 已自动检查的内容

| 层级 | 实际检查 |
|---|---|
| 目录运行 | 包内依赖和输入 preflight；协调器 / 场景实际退出码；native 单个 QEMU PID 与实际退出；历史辅助场景按三进程复查 |
| 输入与构建身份 | ROM、binary、build manifests、wire tool、输入及源文件快照 SHA / size；证据文件引用身份 |
| 原厂入口 | 双 EXPEED 各两核 `0x10020000` 原厂指令字节；MCU 原厂 ROM、reset SP / PC |
| Debugger | native 两条 RSP / QMP TX / RX 与 IO 顺序、checksum、实际五核 thread 发现、显式 CPU 选择、RAM / 寄存器写包及未分类 mutation |
| Native | 一个实例、五核、三个地址空间、两个 GIC 和 MCU NVIC、共同虚拟时间推进 / 暂停冻结、完整两连接、零 Host RAM / 寄存器写包 |
| 任务 / 调度观察 | 启动前锁定双 E6 任务计划；从实际 CPU 读取字节重算全部根、读集合、表几何、分配槽数与候选 current / next 根；零值仍按零值保存 |
| 辅助调用 | 实际 `M / X / G / P` 包、写入地址与总量；`G` 中 PC / SP / LR 及 Host 指派函数目标 |
| 外部输入 | 实际 owner PID / UUID、虚拟期限、QOM pad 写入 / readback、ACK、迟到与待交付序号 |
| 显示 | QEMU 实际 PNG，RGB 像素 hash、尺寸、非黑 / 非纯色、不同帧及 DISP cycle 像素观察 |
| Capture / RAW / ISP / video | 原始日志明确出现的计数；缺失字段保留未知 |
| HDMI | receiver 状态和非空原始 payload 文件；空 receiver 不算输出 |

`--architecture-only` 明确选择 `architecture_observation`，仍要求原厂入口与完整 final 采样、共同时间、两条完整连接和零写包。尚未到期的完整场景事件保留为 pending；已经到期却未交付的输入不能通过。未使用该选项时，native 还要求全部 7 个虚拟输入事件交付。宿主预算与虚拟期限分别记录。

原厂 MCU 的非零电池调用返回只有在原厂 ROM、实际 R0、完整 TX、停止时配置和实际 CPU4 读取全部核对后，才记为已观察的功能失败。它保留在 `battery.original_cmd89_returns`、`battery.errors` 和架构验收备注中，不计入成功次数；完整功能场景仍失败。损坏的字节、伪造 R0、缺失请求或声称成功却没有收到合同 RX 的情况始终阻断验收，包括 `--architecture-only`。

主动结构回归见 [ARCHITECTURE.md](ARCHITECTURE.md)，使用明确披露的合成 RAM fixture。它通过实际 guest 指令测试 CPU / 内存 / IRQ / 时钟 / 复位关系，与零写包原厂 native 的只读架构观察分别报告。

native 最终证据要求完整五核寄存器、256 KiB MCU SRAM、七项 SAISO / UI RAM、双 E6 任务计划以及 Loader 0B / 0C 两个区域。样本必须绑定同一最终暂停 epoch 的实际 RSP / QMP 回复；遗漏区域、任务根、读取文件或篡改汇总会使验收失败。可运行 `runtime/python/bin/python3.12 -B -E -s scripts/native_evidence_regression.py`，离线复算真实样本并测试内存中的损坏副本，不改写原始运行。

`debugger-writes.json` 保留每个写包的角色、协议、偏移、长度与地址。完整记录中的零写包才能支持 native 判定；缺连接不能被解释为“没有写入”。外部 GPIO / PCAL pad 改变是明确输入，ACK 本身不能证明 MENU 或快门业务处理完成。

Host `G` 包指定了 PC 与返回 sentinel 时，报告记为辅助函数调用目标。指派次数不能替代原厂代码实际完成次数。`*_completed=true` 等旧场景字段只用于协调收尾，报告不会据此判定照片、视频或显示档位功能通过。

## 整机功能通过需要的证据

| 功能 | 需要补足的实际证据 |
|---|---|
| 完整自然上电 | 原始物理 Boot ROM / Flash / Loader 链、自然 MCU / 双 EXPEED 初始化与入口因果 |
| 完整调度身份 | 经原厂代码结构及动态行为确认的 RTOS / TCB、调度切换与业务等待对象 |
| 跨引擎因果 | 带内容、方向及时间关联的请求 — DMA — ACK — 响应事务；仅计数不足 |
| 稳定 MENU | 原厂输入处理、MENU 像素、导航选择变化、退出重入及对应资源生命周期 |
| 原厂 Live View | 原厂代码提交的图像缓冲，持续变化的原始 image / LCD payload 与对应输入 |
| 照片与存储 | 原厂 capture buffer、RAW / ISP 输出、有效照片文件及快门输入的完整对应 |
| 录像 | 原厂模式切换、开始 / 停止录制、非空有效媒体及原始视频缓冲对应 |
| HDMI | 原厂视频 DMA、接收端非空且变化的原始画面 payload 和链路因果 |

当前脚本能复验已经保存的入口、调试、任务 RAM、图像和计数证据。这一版本缺少上述完整因果见证和媒体验收器的项目保持 `not_verified`，报告列明具体缺口。后续功能推进需要增加实际采集与验证规则；直接写成功旗标不能通过验收。

## 退出码与使用方法

```sh
./z62 accept --profiles all --audit-only
./z62 verify latest-native --strict
```

证据 / 运行失败返回 `1`；证据完整但 `--strict` 要求的整机功能未全部通过返回 `2`；未使用 strict 的目录运行与证据检查通过返回 `0`。整机功能的状态始终写在报告中，因此普通 `0` 不等于整机相机已实现。

## 事实、推断和未知

双端原厂应用入口、任务分配槽和调度根是直接观察的工程深度。默认 native 已统一为同一个 QEMU 虚拟时间，保留三个芯片域。Boot ROM omitted、物理 Flash 未验收、物理 PLL / 复位时序和未确认的 TCB 身份仍限制更高层判断。

历史三进程 360 秒 native 运行保存了中文播放菜单与拍摄 OSD，同时具备完整六连接记录和零 Host RAM / 寄存器写包。这支持该固定运行的原厂应用输出菜单画面判断。新单实例的菜单与 OSD 必须用其自己的实际像素和输入因果验收，历史画面不替代新结果。稳定导航、退出重入与输入因果仍需补足，因此 `stable_menu` 保持未验收。

旧日志约 1.4 个虚拟秒的 LCD 提交是显示配置阶段；最早保存的非黑菜单在约 190.804 个宿主秒。旧三个角色的时钟独立，不能与新共同虚拟秒直接相减。20:40 单实例全黑轮只推进到约 12.166 个虚拟秒，把宿主秒误用为虚拟期限后，25 秒 PC5 与 165 秒 MENU 均未交付。当前输入表已改为 2、6.5、6.7、8、8.2、10、10.2 个虚拟秒，物理 pin 身份和时长仍按未知保留。

21:43 的 [最新默认完整场景](../results/20261025-214323-native-7e01f2/acceptance.md) 已交付全部 7 个事件并恢复非黑画面，实际是 **电池不能通信弹窗**。178 个保存帧中 55 个非黑帧只有一种像素内容，不能判为拍摄 OSD 或中文菜单恢复。两个已观察 `0x89` 返回均为 0，但它们是同一种请求；另一种 required_TX 未出现，完整场景继续返回 1。

21:34 缩减 PC5 + MENU 对照保存了拍摄 OSD，然后转为黄色等待沙漏。它与较短 PC5 对照的宿主预算不同，且与默认场景在 MENU 前已有认证重试和电池任务时序差异；不能据此单独证明 MENU 成功，目前的比较也不足以直接将默认弹窗归因于后面的 PG1 / PG2。具体内容、原始 RGB hash 和完整 UART 计数见 [固定显示对照](../results/display-regressions/20261025-220134-a8a8c8/report.md)。

![最新默认单实例 native 的电池通信错误弹窗](../results/display-regressions/20261025-220134-a8a8c8/20261025-214323-native-7e01f2/distinct-00.png)

![缩减单实例场景的拍摄 OSD，中心图像仍为黑色](../results/display-regressions/20261025-220134-a8a8c8/20261025-213438-display-same-single-pc5-menu-216c05/distinct-00.png)

对应历史固定运行：[三进程 native 验收报告](../results/20261025-102519-native-ac56ad/acceptance.md)。菜单图可见“播放菜单”，黄色选中“删除”；拍摄 OSD 可见 A、MF、FX、NORM、电池及剩余张数 485，中心图像区域为黑色。

![native 原厂应用输出的菜单](../results/20261025-102519-native-ac56ad/run/EXPEED/engines/master/LCD-timeline/frame019.png)

![native 原厂应用输出的拍摄 OSD](../results/20261025-102519-native-ac56ad/run/EXPEED/engines/master/LCD-timeline/frame023.png)

辅助 profiles 的非黑 UI 画面支持辅助显示实现的判断；合成 Bayer、Host 写入和 OSD replay 同时披露。RAW / ISP 计数即使都大于零，仍需要原厂提交缓冲与有效输出文件才能报告完整原厂拍照链。规格名称、crop 标签与 mode 数值不能证明输出照片或视频已经符合该规格。
