# Native TG 输入周期模型

`sdes-input-v3` 在同一个 `QEMU_CLOCK_VIRTUAL` 计时器上生成 IRQ87 的两个周期原因位。原厂应用自行处理 ISR、CAPTG 和后续任务。模型不读取 guest PC／任务状态来决定事件，也不填写曝光属性、AE 输入或原厂成功标记。

原厂 ROM 合同来自锁定 Master 更新镜像，SHA256 为 `bb83613121f843d65101da936d942acdc513d86dbd3abc26259d0d870d03f5d4`：

- `102DF294` 写 `20060000/04`、`20060008/0C` 的 set／clear 别名；global stop 是第一组的低两位。
- `102DF2C8` 写 `20060010/14` 输入启停。只有输入启用且 global stop 清除时才启动周期。
- ISR `102DF04C` 在 `102DF054/058` 读取并 W1C `20060044`，随后通过注册回调传递原始 status。IRQ87 的 enable 控制中断线，原因位仍可锁存。
- 回调 `102D7ED4` 的 `102D7EEC` 把 cause `80` 转为 `02010001`，另在原厂 countdown 到零时设置 flag4；`102D7F0E` 把 cause `10` 转为 `02010002`，另处理 flag8。
- CAPTG `1026E662` 在原厂状态 4／5／6／7／8／9／19 且 callback 非空时，可以把 `02010001` 转为 `04200141`。实际 callback `10399E21` 的 `10399E20` 入口会走原厂 dispatch，相关分支可投递 owner `C23D8D80` 的 mask800。模型不代替这些检查。
- SDES 回调 `102D7E26` 比较的是 `41081004` 和 `41081005`；`02010001` 是其带 gate 的输出。历史 observation plan 的两个 label 错把输出当比较常量；旧锁定记录保留，新 plan 使用正确名称。

周期为 33,333,333 ns；第一个 cause80 安排在输入启用后半个周期，cause10 在完整周期 deadline。后续 deadline 按同一周期递增。这是为了核验原厂事件路径而作的功能模型假设。实际传感器速率、两个原因位的物理意义、相位和硬件门控完整性仍未测得。F001 后顺序读取的真机 RAM 不能认证这些物理时序。

输入停止时，尚未产生 cause80 的下一周期取消；已经开始的周期只在原 deadline 收尾一次，不再启动新周期。global stop 取消任一阶段，不清除尚未 W1C 的 status。停止期间重新启用输入可继续当前收尾周期；从停止状态启用时重新建立 deadline。

v1／v2 的单 cause10 行为保留。诊断 `Z6II_TG_EVENT_TEST` 与周期模型互斥。native 选择 v3；其他辅助 profile 保留自己的配置。Bayer 数据是否存在和原厂 DMA／曝光生产是否发生分别验收，TG 原因位不等于图像帧或曝光成功。

权威编译源为 `src/qemu/hw/arm/nikon-z6ii-devices.h`。`scripts/build.py` 直接编译并冻结 contained QEMU 源，不运行历史 overlay generator；`src/harness/z6ii/` 中的旧 header 保留为历史引用。
