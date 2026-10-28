# 输入真实性与来源

## Source distribution and v0.0.2 retained inputs

The Git source release excludes all `inputs/`, raw `results/`, runtime binaries and build artifacts. Input paths described below belong to a separately prepared local installation. See [Native method v0.0.2](NATIVE-v0.0.2.md) for exact firmware fingerprints and the retained Flash/RTC identities used by V44.

The named method requires analysis-only composite Flash input and an 80-byte RTC bank whose complete original producer evidence passes `rtc_backup_input.inspect_spec`. No payload is generated to satisfy preflight. Its local selection remains in ignored `inputs/local/native-v0.0.2/inputs.json` or can be supplied with explicit package-local arguments.

The earlier input table below describes the prepared-package research inputs and their evidence boundaries; it is not a list of files shipped by Git.

所有实际输入在包内，运行配置用相对路径。源目录与整理身份保存在 `provenance/`；每次运行再次锁定其具体输入与 SHA256。

| 输入类别 | 位置 | 证据范围 |
|---|---|---|
| 原厂 Z6II C1.70 Master 更新模块 | `inputs/firmware/master-original-with-crc.bin` | 原厂更新镜像应用代码；不是完整物理 Flash dump |
| 原厂 Z6II C1.70 Slave 更新模块 | `inputs/firmware/slave-original-with-crc.bin` | 原厂更新镜像应用代码；不是物理 Boot ROM |
| EX1850 MCU 固件 | `inputs/firmware/ex1850_012000.bi.bin` | 原厂 reset vector 与 ROM 字节 |
| Flash 重建规范与记录 payload | `inputs/specs/descriptor-flash.json`、`inputs/reference/` | descriptor-derived 重建输入，包含记录材料；不得称为原始物理 Flash 容器 |
| Loader、参数及任务参照 | `inputs/specs/loader-reference.json`、`parameter-reference.json`、`tasks.json` | 只读身份 / 内容 / 观察计划；任务身份认证另行验证 |
| 供电与公开 RNG credential | `inputs/specs/battery.json` 及 MCU recipe | 有明确模型条件的合成 peer；不证明原厂物理认证 |
| ADC / GENADC / POST68 / Bayer / EDID | `inputs/reference/` 与环境 recipe | 明确合成诊断、图像与 sink 输入；不能据此证明真实传感器或 HDMI 输出 |
| BA2 ISA、buffer / controller / IRQ policy | `profiles/*/environment.json` | 已实现或条件 candidate 模型；保留各 policy 的原有范围 |
| Host 辅助 OSD、RAM 与函数调用输入 | `inputs/assisted/`、`profiles/*/probe_z6ii.py` | 辅助显示 / 原厂函数探索；必须记录写包与 replay |
| 外部 GPIO / PCAL pad 序列 | native 使用 `scripts/native_unified_pads.py`；历史辅助场景保留原脚本 | 按共同虚拟时间交付电平输入；物理按钮命名与业务映射尚未全部确认 |

原厂模块身份记录在 `inputs/firmware/manifest.json`。打包与 Mach-O 依赖路径适配改变的是本机程序的装载元数据 / 签名，原厂固件模块指令字节不随之修改。

Master / Slave 当前都从 `0x10020000` 的原厂更新镜像应用入口直接装载，MCU reset 为 SP `0x20000c08`、PC `0x080002b4`。报告明确区分这种执行与从物理上电、Boot ROM、完整 Flash / Loader 自然到达应用入口的验收。

`native` 禁止 Host RAM / 寄存器写入，但其外设与输入仍有合成 / 条件模型；零调试写包不能把这些模型升级为真机材料。辅助 profiles 更进一步使用 Host 原厂函数调用和状态写入，其具体数量及地址以本次 `debugger-writes.json` 为准。

`inputs/reference/` 中的历史 binary 文件只作为只读 SHA / 来源参照；实际可执行 QEMU 由 `artifacts/` 的 selected manifests 决定。不能依据旧二进制名称、旧 cwd 或文件 mtime 判断本次实际使用的构建。
