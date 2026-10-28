# 真机电池与 MCU 配置对照

真机采集是独立的查询入口，不是 QEMU 启动的前置条件。只有连接唯一一台 `04B0:044C`、身份为 `Z 6_2 V1.70` 的机身时，脚本才进入已经使用过的 Nikon 诊断流程。启动或验收 QEMU 不会自动访问机身。

从本目录执行：

```sh
runtime/python/bin/python3.12 -B -E -s scripts/camera_battery_read.py \
  --config-trace --classification-trace --passes 6 --interval 0.25 \
  --cache-samples 256 --cache-interval 0.02
```

入口按自身位置确定包根目录，输出保存为 `results/camera-battery-<时间>/`。完整采样次数限制为 1–12，间隔限制为 0–5 秒；额外 UART 缓存采样限制为 0–256 次，间隔为 0–0.25 秒，合计间隔等待最多 60 秒。每次执行创建新目录，保留 PTP 命令、USB bulk 返回、独立 payload、`transactions.json`、`summary.json` 和哈希 manifest。正常结束和异常收尾都会尝试退出诊断、关闭所属会话并释放 USB。

| 请求 | 用途与范围 |
|---|---|
| `1002`、`1001`、`1003` | 打开所属 PTP 会话、核对机身身份、关闭会话 |
| `1015(5001)`、`1015(500E)` | 正常模式的电量和曝光模式查询 |
| `942B()` | 已有 Nikon 正常模式缓存查询 |
| `94FD(F001)`、`94FD(F002)` | 已知诊断入口和退出；会改变诊断状态 |
| `94FF(F044,address,length)` | 固定 MCU ROM / SRAM 窗口的读取，每次最多 128 字节 |

`--config-trace` 还读取已观察的 group4 指针槽 `0x2000E7F0`、它指向的受限 360 字节配置源，以及原厂转换函数的代码窗口。脚本不请求机身复位，不写 MCU / E6 内存或 Flash，不发送电池串口命令。`0x89` 是 MCU 与电池之间的报文字段；本脚本通过 PTP 读取相关缓存，不将它作为一个 PTP 操作码发送。

`--classification-trace` 读取原厂分类函数窗口、`0x2001F734` 的 8 字节输入、`0x2001FB69` 的 body-state 和 `0x2001F69C` 的缓存分类，并从原厂分支重算候选结果。body-state 与 `0x2001FB6E` 的 body-mode 分开保存；静态重算不替代真机实际调用时点。`--cache-samples` 在同一次所属 PTP 会话中增加较快的固定窗口读取，保持变化或不完整的缓存原样。

结果属于 **进入 F001 后的顺序诊断读取**。前后控制字段一致、长度一致、校验一致的缓存对可以记录为一致缓存；读取过程中变化的缓存保持不完整。它没有线级 UART 时间戳，也不构成原子快照、真机自然冷启动、原厂函数执行时点或电池硬件效果的证明。

`reconstructed_cmd89_candidates` 使用真实配置字节和两个显式 READPIN 分支进行离线重建。未直接观测的 READPIN 保持未知，重建报文不会写入机身或 QEMU，也不会被计作实际发送的 `0x89`。与 native 的配置字节一致只能确认该配置快照；地址空间、初始化顺序、UART 收发时间、重试原因和完整跨芯片因果仍需各自的证据。

2026-10-25 20:27 的最新采集见 [camera-battery-20261025-202728](../results/camera-battery-20261025-202728/summary.json)：正常电量返回 `64`，即 100%；912 个 PTP 命令、4515 个 manifest 文件及 9 个 MCU 原厂代码窗口均保留。6 次完整采样加 256 次缓存采样共 262 次，206 次缓存完整一致，56 次变化或不完整，完整真机 `0x89` 缓存对为 0。六轮分类输入均为全零、body-state 为 2、缓存分类为 1，离线原厂逻辑重算也为 1。F002、CloseSession 与 USB 释放成功。

历史单实例对照 [20261025-204048-native-66e010](../results/20261025-204048-native-66e010/acceptance.md) 保留五核、三个私有芯片域、共同虚拟时间与零 Host 写包。两次原厂配置转换中，第二次的 360 字节源及 72 字节复制缓存与真机相同；首次默认配置不相同。该轮分类调用输入首字节为 `01`、调用时 body-state 为 0，原厂返回分类 3；最终 body-state / 缓存分类为 5 / 3。UART TX / RX 均为 0，没有完整 `0x89` 返回。分支差异的充分原因未知，下方真机对照命令继续绑定这一历史运行。

2026-10-25 21:43 的 [当前完整默认 native](../results/20261025-214323-native-7e01f2/acceptance.md) 已交付全部 7 个外部输入，完整 UART TX / RX 为 171 / 314 字节，两次同种 `02890ec800c8000400000000000101010181` 原厂调用均返回 R0=0。另一种必需请求仍未观察到，正式场景返回 1。178 个保存帧中 55 个非黑帧实际为电池通信错误弹窗；缩减 PC5 + MENU 场景出现 OSD 后转为等待沙漏。输入时基修复、原始像素、认证重试及共同虚拟时间对照见 [显示回归报告](../results/display-regressions/20261025-220134-a8a8c8/report.md)。外部合成电池 peer 的返回不替代物理认证，弹窗的完整原厂触发链仍未知。

此前 [20261025-202817-native-d9b6cb](../results/20261025-202817-native-d9b6cb/acceptance.md) 确实保留 TX / RX 274 / 481 字节和两次 `02890ec800c8000400000000000101010181` 的原厂成功返回；另一 required_TX 仍未观察到。该轮在 TX 偏移 0 有一个帧外 `00`，偏移 64 位于普通帧内部。其旧验收因 UART 审计条件错误而失败，旧报告保留；[修正后的独立回归](../results/evidence-regressions/20261025-204014-3a07f8/result.json) 验证了原厂 `0x08024964` 初始化零字节、TX 长度 1 / 预期 RX 长度 0、调用栈、HAL、DR 写入与时间顺序。这里证明字节来源，物理协议用途仍未知。原厂静态证据见 [battery-uart-single-zero-rea-20261025.json](../provenance/battery-uart-single-zero-rea-20261025.json)。

离线对照入口仅读取保留数据，不连接相机、不启动 QEMU、不改写输入运行：

```sh
runtime/python/bin/python3.12 -B -E -s scripts/native_evidence_regression.py \
  --run results/20261025-204048-native-66e010
runtime/python/bin/python3.12 -B -E -s scripts/camera_native_comparison.py \
  --camera results/camera-battery-20261025-202728 \
  --native results/20261025-204048-native-66e010 \
  --regression results/evidence-regressions/20261025-204719-39a0b9/result.json \
  --assisted results/20261025-104451-still-disp-458fc4
```

已有 native 原始证据回归见 [20261025-204719-39a0b9](../results/evidence-regressions/20261025-204719-39a0b9/result.json)。新的回归会输出另一个目录，对照时应使用那一轮的路径；回归必须精确绑定选择的 native run，其他 run 的 passing 报告会被拒绝。对照核验原始 PTP 容器 / payload、manifest、ROM、分类、配置、最终 SRAM 和实际图像，每次生成新报告与 PNG。`passed` 表示证据对照成功，完整相机门槛仍按 native 验收。

最新 [离线对照报告](../results/camera-comparisons/20261025-205213-6de9fc/comparison.md) 与 [实际画面对照图](../results/camera-comparisons/20261025-205213-6de9fc/comparison.png) 保存在 `results/camera-comparisons/`，实际 native 黑帧与历史辅助 still-disp 分栏标注。辅助图保留 8453 个 Host 写包，不能作为本次 native 菜单。光圈依赖镜头，无镜头时 `F---` 合理；`movie-disp` 未完成。更早采集 [camera-battery-20261025-161033](../results/camera-battery-20261025-161033/summary.json) 按原身份保留。相关架构范围见 [ARCHITECTURE.md](ARCHITECTURE.md)，功能判定见 [ACCEPTANCE.md](ACCEPTANCE.md)。
