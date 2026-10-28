# Nikon Z 6 / Z 6II / Z 7II Motherboard & Component Architecture Survey

[Back to README](../README.md) · [Attribution & Safety Notice](../NOTICE.md)

This document summarizes our early hardware survey correlating official Nikon platform specifications, public teardown disclosures, third-party repair component databases, and manufacturer datasheets across the **Nikon Z 6**, **Nikon Z 6II (`Z62`)**, and **Nikon Z 7II (`Z72`)** mainboards.

Nikon's specification identifies **Dual EXPEED 6**. The current `nikon-z6ii-native` QEMU implementation represents those two application-engine domains with **two CPU cores each**, plus one **STM32F412-class ARM Cortex-M4** controller. These five emulated CPUs describe the implementation, not a verified physical core count or a complete factory Bill of Materials (BOM). User-confirmed Z 6II board photographs also show a separate **Renesas `R5F56519AD` (RX651)**, whose firmware and connections are not yet mapped into the machine.

---

## 1. Evidence Tier Methodology

Public teardown imagery and repair-part databases identify several key integrated-circuit families, but Nikon does not publish factory schematics, boardviews, PCB component designators (`U*`/`IC*`), or custom silicon ordering numbers. Every hardware claim in this project is classified into one of three evidence tiers:

- **Tier A (Datasheet-Matched Part Number)**: Top marking or repair-database entry directly matches an official semiconductor manufacturer part number with verified electrical function (does not imply access to Nikon's board-level schematic or assembly revision).
- **Tier B (Verified IC Family / Series)**: Visible package marking or cross-referenced repair record confirms the IC family and primary subsystem role, while exact ordering suffixes, package variants, or pin-level assignments remain unconfirmed.
- **Tier C (Short Top-Code / Unconfirmed Candidate)**: Public sources record only an abbreviated package marking or tentative mapping insufficient for independent manufacturer part confirmation.

Evidence origin is recorded separately from the tier: a **direct photo** establishes readable package text, a **repair database** supplies a catalog classification, a **manufacturer document** describes an IC family, and **QEMU behavior** describes this project's implementation. None alone establishes the photographed board's pin wiring, device ownership, or boot role.

---

## 2. Cross-Generation Platform Comparison (Z 6 vs. Z 6II vs. Z 7II)

| Camera Platform | Official Image Processing System | Sensor Resolution | Public PCB Imagery Availability | Key Recorded Board-Level IC Markings |
| :--- | :--- | :---: | :--- | :--- |
| **Nikon Z 6** | Single **EXPEED 6** | 24.5 MP | Side A & Side B repair PCB photos available | `ADP5080 0033`, `TPS63061`, `MMA8452` (`263 8452`), `WM8962E`, `STM32F412`, `R5F56519AD`, `DSP STACKED` |
| **Nikon Z 6II (`Z62`)** | **Dual EXPEED 6** | 24.5 MP | Two user-confirmed `2920 × 1436` board PNGs; several package markings are directly readable | Photo: `R5F56519AD`, `SPANSION GL256S10FHV2`, `Nikon E1-223`, `D65490 / 0225`, `L6524 / 20 01 03 / ZSD005`, and an ST logo. Repair records additionally list `STM32F412`, `MAX77711B`, `1016` (`AP1016N`), `BD9867`, `DS184`, `TE4424RX`, `1MW Wi-Fi`, and LCD-flex `CQ0` / `R1205L811C` |
| **Nikon Z 7II (`Z72`)** | **Dual EXPEED 6** | 45.7 MP | Side A & Side B repair PCB photos + Kolari teardown | `DSP STACKED` (Dual EXPEED 6), `MT52L256M64D2LZ-107 WT:B` (`D9TBZ`), `NT6CL512F64AH-H1`, `STM32F412`, `MAX77711B`, `TPS63061`, `MMA8452`, `WM8962B`, `PI5USB30` |

### Structural Teardown Observations

- **Transition from Single to Dual EXPEED 6**: Nikon specifies one EXPEED 6 for the first-generation Z 6 and two for the Z 6II and Z 7II. The Z 6II and Z 7II also have CFexpress Type B / XQD and UHS-II SD card slots. Processor count in the product specification does not disclose each processor's physical CPU core count.
- **Sub-Board Partitioning**: Certain peripheral functions are separated from the main PCB; for example, the LCD backlight driver (`CQ0`, listed alongside `R1205L811C`) is located on the **LCD flex board** rather than the main processor board, and audio I/O on Z-series bodies uses dedicated sub-assembly routing.

---

## 3. Nikon Z 6II (`Z62`) Component Identification & Evidence Table

The two supplied Z 6II photographs permit direct reading of several package markings. The table distinguishes those readings from repair-catalog labels, semiconductor-family matches, and QEMU modeling choices. Photo position alone does not establish PCB designators, electrical connections, or the same assembly revision across both images.

| Subsystem Role | Recorded Marking | Matched IC Family / Candidate | Tier | Functional Description & Emulation Relevance |
| :--- | :--- | :--- | :---: | :--- |
| **Primary Application Processors** | Official specification: **Dual EXPEED 6**; `DSP STACKED` in repair records | Nikon EXPEED 6; `EX1850` is the project/firmware engine label | **Official platform; implementation detail** | QEMU models Master (`CPU 0/1`) and Slave (`CPU 2/3`) as two ARM application-engine clusters with two emulated cores each. Neither the product specification nor these photos verifies that physical core topology. |
| **Modeled system-control MCU** | `STM32F412` in repair records; ST logo visible in PNG1 | STMicroelectronics **STM32F412** Cortex-M4 family | **Tier B; exact photo code unresolved** | QEMU's `CPU 4` is an STM32F412-class Cortex-M4 model with 256 KiB modeled SRAM, NVIC, SysTick, RCC and USART/DMA. The photo does not independently resolve the complete ST ordering code or prove every assigned Nikon-specific duty. |
| **Additional MCU, board role unresolved** | `R5F56519AD` directly readable in PNG1 | Renesas **RX651** 32-bit MCU series | **Direct photo + Tier B family match** | A distinct controller from the modeled Cortex-M4. Its firmware, reset relationship, buses and responsibilities are not established; no RX651 CPU is currently modeled. |
| **External Flash package** | `SPANSION GL256S10FHV2` directly readable in PNG2 | Spansion / Infineon **S29GL-S** parallel NOR family | **Direct photo + family match** | The package is present, but the photos do not identify its bus owner, address mapping or which firmware contents it stores. An earlier provisional `NANYA` label for this package was incorrect. |
| **Nikon-marked IC, role unresolved** | `Nikon E1-223 / 007636` directly readable in PNG2 | Nikon top marking; exact device type unknown | **Direct photo; role unknown** | An earlier provisional `Micron` label for this package was incorrect. No memory, image-processing or actuator role is assigned from this marking alone. |
| **Multi-Phase Core PMIC** | `MAX77711B` | Analog Devices / Maxim **MAX77711** family | **Tier B** | Configurable 4-phase buck regulator family shared by Z 6II and Z 7II dual-EXPEED mainboards for high-current core/memory rails (`B` suffix unconfirmed). |
| **Actuator-driver marking** | `D65490 / 0225` directly readable in PNG1 | `D65490` repair-database entry | **Direct photo + Tier C function** | Photo-parts classifies `D65490` as “Zoom driver, OIS driver, Mirror charge driver.” This is a catalog category, not proof that this mirrorless board has a mirror drive or that this chip drives a particular Z 6II motor. ROHM attribution and decoding `0225` as a production date remain unverified. |
| **Motor / Actuator Driver** | `1016` | Mapped in repair records to **AP1016N** | **Tier C** | Listed as a dual H-bridge motor/actuator driver candidate; retained at Tier C pending independent manufacturer datasheet verification of the short package code. |
| **I²C/SMBus GPIO expander** | Q-like symbol, `L6524 / 20 01 03 / ZSD005` directly readable in PNG1 | NXP **PCAL6524HE**; manufacturer Table 1 maps `L6524` to HUQFN32 / SOT1426-1 (5 × 5 × 0.56 mm) | **Direct photo + Tier A manufacturer marking match** | Provides 24 GPIOs via an Fm+ I²C/SMBus interface. `VDD(I2C-bus)` (0.8–3.6 V) and `VDD(P)` (1.65–5.5 V) support distinct I²C-interface and GPIO-port voltage domains; level translation occurs between these domains. `PCAL6524HEHP` and `PCAL6524HEAZ` are listed orderable packing variants, which the photo cannot distinguish. The board's bus owner, address-pin setting, actual supply rails, GPIO/interrupt/reset wiring and meanings of the two additional marking lines remain unknown. |
| **Display Bridge / Serializer Candidates** | `DS184` (cf. `DSI84` on Z 7II), `LVDS301` | Display interface / bridge markings | **Tier C** | Short package markings recorded on Z 6II / Z 7II boards; exact vendor ordering numbers remain unconfirmed. |
| **Other power / analog / logic markings** | `BD9867`, `TE4424RX` | Unconfirmed vendor part numbers | **Tier C** | Short codes retained as repair-database clues without speculative BOM substitution. |
| **Wireless Module** | `1MW Wi-Fi` | Murata / Cypress `Type 1MW` class Wi-Fi/BT module label | **Tier C** | Functional module label rather than a complete Nikon ordering part number. |
| **LCD Flex Backlight Driver** | `CQ0` / `R1205L811C` | Located on **LCD flex board** (off-mainboard) | **Tier C** | Explicitly noted in repair records as residing on the LCD flex assembly rather than the main PCB. |

### 3.1 E-Commerce Replacement Board Imagery & Coordinate Boundary (`Z 6II`)

While `photo-parts.com.ua` catalogs some IC markings for the `Nikon Z6 mark II`, its corresponding `"Nikon Z6 mark II PCB"` photo directory is empty. To supplement board-outline reference, our survey collected commercial replacement motherboard photos from **Taobao** and **AliExpress**:

<p align="center">
  <img src="../assets/z62-taobao-motherboard.jpg" alt="Nikon Z 6II (Z62) Replacement Motherboard Reference Photo (Taobao Overview)" width="32%" />
  <img src="../assets/z62-taobao-motherboard-1.png" alt="Nikon Z 6II (Z62) Replacement Motherboard Reference Photo 1 (Taobao Side View A)" width="33%" />
  <img src="../assets/z62-taobao-motherboard-2.png" alt="Nikon Z 6II (Z62) Replacement Motherboard Reference Photo 2 (Taobao Side View B)" width="33%" />
</p>

- **Taobao Replacement Mainboard Photos (`../assets/z62-taobao-motherboard.jpg`, `../assets/z62-taobao-motherboard-1.png`, `../assets/z62-taobao-motherboard-2.png`)**: The user explicitly identified the two `2920 × 1436` PNGs as Z 6II boards. PNG1 SHA-256 is `4500f0eef42f3854ff62861295bb46ed2b0c7f6e0af5ca7b36c82fde6b1f56eb`; PNG2 SHA-256 is `99ffaf05d90eced787d215d9a9ba83e708c4747f92121a64f40199be9f855b70`. Their package text supports the direct-photo rows above. The `1200 × 1600` `"Z62主板"` overview provides board-layout context. The two PNGs are not proven to depict the same physical assembly or revision; visible `2024 01-02 A7` / `UMT-KS 2V 94V-0` board text is not interpreted as Nikon's assembly revision or camera manufacture date.
- **Verified numbered overlays**: In this source tree, `docs/assets/hardware/z62-user-board-20261025/annotations/board-1-annotated.png` labels **1** Renesas RX651, **2** ST controller and **3** `L6524` / PCAL6524HE. `board-2-annotated.png` labels **4** Spansion Flash and **5** Nikon E1-223. The adjacent `manifest.json` records source/output hashes and marker coordinates. The numbers locate visible packages; they do not establish electrical connections or chip responsibilities.
- **AliExpress Reference Image A (`Item 1005013051978470`)**: Storefront display resolution `960 × 960` (`1000 × 1000` uncropped CDN file), depicting the Z 6II replacement PCB outline and major component regions.
- **AliExpress Reference Image B (`Item 1005010161490916`)**: `800 × 800` CDN image associated via Google Images indexing (the storefront detail page redirected to a login wall during verification, preventing gallery inspection).
- **Watermarked Screenshot (`Shop108460`)**: A separate watermarked seller screenshot examined during the survey was excluded from component analysis because its original storefront source could not be independently verified.

**Methodological Limitation**: These are replacement-part images rather than a traced schematic. PNG1 is sufficient to read and locate `R5F56519AD`, `D65490` and `L6524` within the image, and PNG2 is sufficient to read `SPANSION GL256S10FHV2` and `Nikon E1-223`. Image position does not identify nets, pin assignments, device ownership or QEMU address maps. Other short codes such as `BD9867`, `MAX77711B`, `R1205L811C`, `DS184` and `TE4424RX` remain without verified board coordinates in this evidence set.

---

## 4. Sibling Dual-EXPEED 6 (`Z 7II`) & Single-EXPEED 6 (`Z 6`) Cross-Reference

Because the Z 6II and Z 7II share the same generation **Dual EXPEED 6** platform and firmware architecture (`eg1850` / `eg1840`), verified markings from the Z 7II and Z 6 mainboards provide essential context for memory, sensor/IMU, and power modeling:

| Recorded Marking | Observed On | Matched Part / Family | Tier | Architectural Significance |
| :--- | :---: | :--- | :---: | :--- |
| `MT52L256M64D2LZ-107 WT:B` (`D9TBZ`) | Z 7II | **Micron LPDDR3 SDRAM** (256M × 64, dual-channel PoP/discrete class) | **Tier B** | Confirms high-bandwidth LPDDR3 memory architecture paired with the EXPEED 6 processors. |
| `NT6CL512F64AH-H1` | Z 7II | **Nanya LPDDR3 SDRAM** (512M × 64 class) | **Tier B** | Listed alongside Micron LPDDR3 in Z 7II database records (alternate vendor source or per-engine pairing). |
| `TPS63061` | Z 6, Z 7II | **Texas Instruments TPS63061** | **Tier A** | High-efficiency buck-boost DC/DC converter confirmed against TI product documentation. |
| `ADP5080 0033` | Z 6 | **Analog Devices ADP5080** | **Tier A** | Multi-rail integrated PMIC for Li-ion systems (`0033` suffix observed in Z 6 repair cases; `ADP50800029` discussed only as an unverified repair comparison). |
| `263 8452` (`MMA8452`) | Z 6, Z 7II | **NXP / Freescale MMA8452** 3-axis accelerometer (`MMA8452Q` candidate) | **Tier B** | Hardware tilt/orientation sensor underlying the dual-axis electronic Virtual Horizon (`DISP 3`, Widget `0x3F`). |
| `WM8962E` / `WM8962B` | Z 6 / Z 7II | **Cirrus Logic WM8962** stereo audio codec family | **Tier B** | Hardware audio codec backing microphone level metering and audio path initialization. |
| `R5F56519AD` | Z 6 repair photo; **Z 6II supplied PNG1** | **Renesas RX651 (`R5F56519AD`)** MCU series | **Tier B + direct Z 6II photo** | Also directly readable on Z 6II. Its presence is not limited to the Z 6 sibling reference, and its Nikon-specific role remains unknown. |
| `PI5USB30` | Z 7II | **Diodes / Pericom PI5USB30** series candidate | **Tier C** | USB 3.0 / Type-C signal switch or controller marking candidate. |

---

## 5. Primary Public Sources

1. **Nikon Official Product Specifications**:
   - Nikon Z 6 (`https://imaging.nikon.com/imaging/lineup/mirrorless/z_6/`) — Single EXPEED 6, 24.5 MP.
   - Nikon Z 6II (`https://imaging.nikon.com/imaging/lineup/mirrorless/z_6_2/`) — Dual EXPEED 6, 24.5 MP.
   - Nikon Z 7II (`https://imaging.nikon.com/imaging/lineup/mirrorless/z_7_2/`) — Dual EXPEED 6, 45.7 MP.
2. **Public Teardown & PCB Disassembly Reports**:
   - Kolari Vision Nikon Z 6 Disassembly & Teardown (`https://kolarivision.com/nikon-z6-disassembly-teardown/`).
   - Kolari Vision Nikon Z 7II Disassembly & Teardown (`https://kolarivision.com/nikon-z7-ii-disassembly-and-teardown/`).
3. **Third-Party Repair Component Databases & E-Commerce Outline References**:
   - Photo-parts IC marking registries for Nikon Z 6, Nikon Z 6 Mark II, and Nikon Z 7 Mark II (`https://photo-parts.com.ua/`).
   - [Photo-parts `D65490` profile](https://photo-parts.com.ua/parts/part_profile.php?part=3754) — catalog function labels only; its model list does not independently establish Z 6II use, which is instead supported by PNG1.
   - Taobao Z 6II Replacement Motherboard Photos (`assets/z62-taobao-motherboard.jpg` [`1200 × 1600`], `assets/z62-taobao-motherboard-1.png` [`2920 × 1436`], and `assets/z62-taobao-motherboard-2.png` [`2920 × 1436`]).
   - AliExpress Z 6II Replacement Motherboard Listing A (`Item 1005013051978470`, `1000 × 1000` CDN reference image; macro board outline only).
   - AliExpress Z 6II Replacement Motherboard Listing B (`Item 1005010161490916`, `800 × 800` Google-indexed CDN reference image; macro board outline only).
4. **Semiconductor Manufacturer Datasheets**:
   - STMicroelectronics `STM32F412` (ARM Cortex-M4 MCU with 256 KiB SRAM).
   - Analog Devices / Maxim `MAX77711` (4-phase configurable buck regulator) & `ADP5080`.
   - Texas Instruments `TPS63061` (buck-boost converter).
   - Cirrus Logic `WM8962` (low-power stereo codec).
   - [NXP PCAL6524 product page](https://www.nxp.com/products/interfaces/ic-spi-i3c-interface-devices/general-purpose-i-o-gpio/ultra-low-voltage-translating-24-bit-fm-plus-ic-bus-smbus-i-o-expander:PCAL6524) and [PCAL6524DS Rev. 2.1 datasheet](https://www.nxp.com/docs/en/data-sheet/PCAL6524DS.pdf) (2025-07-03) — p. 4 Table 1 explicitly maps photographed topside `L6524` to `PCAL6524HE`, HUQFN32 / SOT1426-1; Table 2 lists `HEHP` and `HEAZ` packing options. Pages 2–3 specify 24 GPIOs and independent I²C-interface / GPIO-port supply ranges. A versioned PDF, selected-page extract and source record are retained in the Desktop integration tree under `docs/assets/hardware/z62-user-board-20261025/manufacturer/`.
   - [Renesas RX651 product page](https://www.renesas.com/en/products/rx651) — MCU family identification; series specifications are not automatically exact `R5F56519AD` specifications.

---

## 6. Consequences for the Native Machine

The present native machine runs **five emulated CPUs**: two in the Master E6 domain, two in the Slave E6 domain and one Cortex-M4 controller. These domains retain their modeled address spaces and interrupt/reset behavior while events share `QEMU_CLOCK_VIRTUAL`. The photographed RX651 is an additional physical controller and is **not** part of that five-CPU model. Its instruction set or oscillator rate would not by itself require a separate QEMU process; original firmware and board-interface evidence are needed to specify its domain.

The manufacturer-confirmed `L6524` / PCAL6524HE identification gives a concrete 24-GPIO I²C/SMBus device to investigate, while `D65490` suggests an actuator-driver investigation. The marking does not determine which controller owns the GPIO expander's bus, how its address pin or GPIOs are wired, or whether it participates in the current power, display, battery or shutter paths. The current QEMU I²C attachment remains a model choice; physical bus assignment requires board-level evidence. The Spansion Flash's owner and mapping are likewise unresolved. These photographs therefore do not establish a missing QEMU device transaction or explain the observed battery `0x89` timeout by themselves.
