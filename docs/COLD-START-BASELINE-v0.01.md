# Native Cold-Start Guide v0.01

Historical menu/OSD comparison guide. The current native method is [v0.0.2 / V44](NATIVE-v0.0.2.md). The frozen v0.01 manifest and original run evidence retain their original acceptance scope.

This guide describes how to start the native QEMU model, run the menu input scenario, and inspect the saved display evidence. It assumes a prepared runtime installation with compatible firmware and peripheral inputs.

The source distribution requires user-supplied firmware. Firmware images and device captures are outside the source-only distribution.

## 1. Scope

The native model runs the master E6, slave E6, and modeled system-control MCU in one QEMU instance. The implemented topology has five emulated CPUs, with separate chip domains and one shared `QEMU_CLOCK_VIRTUAL` time base.

A fresh run creates its own RAM/transport state, MCU bus state, and virtual storage. The E6 domains start from the original application entries; the MCU starts from its reset vector. Runtime RAM snapshots are not restored by this workflow.

This is an **application-entry cold start**. Full Boot ROM/physical Flash power-on behavior remains a separate validation target. The emulated CPU topology and external input mappings describe the current model; they do not certify the complete physical board architecture.

## 2. Prerequisites

Prepare the following before launching:

- A supported runtime environment. The current packaged runtime targets macOS on Apple Silicon.
- A verified QEMU build and the project's runtime tools.
- Compatible master E6, slave E6, and MCU firmware images supplied by the user.
- Peripheral input configuration and an observation plan matching that firmware.
- A menu input schedule using the common virtual clock.

Run commands from the project root. To build and check a prepared installation:

```sh
./z62 build --jobs 2
./z62 doctor
```

A verified prebuilt installation can begin with `./z62 doctor`. Resolve reported dependency, firmware, or configuration errors before starting.

The expected firmware input paths are:

```text
inputs/firmware/master-original-with-crc.bin
inputs/firmware/slave-original-with-crc.bin
inputs/firmware/ex1850_012000.bi.bin
```

These names identify input locations. They do not imply that firmware is distributed with the source.

## 3. Launch the menu scenario

The command below assumes that the prepared UI observation plan and input schedule are stored at the shown project-relative paths:

```sh
./z62 run --profile native --binary rebuilt --seconds 1200 \
  --virtual-seconds 34 --display-observation \
  --ui-plan profiles/baselines/native-menu-v0.01/ui-observation-plan.json \
  --pad-schedule profiles/baselines/native-menu-v0.01/external-pad-schedule.json
```

Use configuration files validated against your firmware and input models. The launcher records the selected build, firmware identities, effective configuration, observation plan, and input schedule for each run.

The entry resolves configuration relative to the project root. It can also be called through its full path from another working directory.

### Host and virtual time

`--seconds 1200` sets the host execution budget. `--virtual-seconds 34` sets the observation deadline in the shared virtual clock.

Host execution can take considerably longer than the emulated interval. Follow the launcher's actual virtual-time progress and allow the complete observation window. A short host budget can end the run before the display or scheduled inputs have progressed far enough.

The generic `native` defaults use a shorter host budget and another input scenario. Use the explicit arguments above when comparing this menu scenario.

Run one scenario at a time and keep its execution sources and inputs unchanged until final evidence has been saved.

## 4. Menu input schedule

All times are virtual seconds from the common clock origin. PCAL press drives the masked bit low; release restores it high.

The action names are simulator mappings. Physical wiring and exact hardware press durations still require independent verification. The table describes planned actions; input delivery alone does not prove successful navigation.

| Planned action | Model input | Press / low | Release / high |
| --- | --- | ---: | ---: |
| PC5 close-low | GPIO C bit 5 | 2.00 | No release scheduled |
| MENU enter | PCAL9 | 10.00 | 10.25 |
| Left to tabs | PCAL7 | 12.00 | 12.25 |
| Down next tab | PCAL4 | 13.50 | 13.75 |
| Up previous tab | PCAL5 | 15.00 | 15.25 |
| Right to list | PCAL6 | 16.50 | 16.75 |
| Down next row | PCAL4 | 18.00 | 18.25 |
| Up previous row | PCAL5 | 19.50 | 19.75 |
| Confirm | PCAL8 | 21.00 | 21.25 |
| MENU dismiss dialog | PCAL9 | 23.00 | 23.25 |
| MENU focus tabs | PCAL9 | 24.50 | 24.75 |
| MENU exit | PCAL9 | 26.00 | 26.25 |
| MENU reentry | PCAL9 | 29.00 | 29.25 |

The schedule contains 25 input events. Preserve both the press and release edges when reproducing the scenario.

## 5. Inspect a completed run

The launcher prints a new directory under `results/`. Record that directory name and use it explicitly for auditing:

```sh
./z62 ui-verify RUN_DIRECTORY_NAME --require evidence
```

Replace `RUN_DIRECTORY_NAME` with the name from your own run. The audit writes a fresh report directory and prints its location.

| Run-relative location | Contents |
| --- | --- |
| `prepare/` | Selected command, configuration, input identities, and execution-source snapshots |
| `logs/` | Coordinator and external input logs |
| `run/native-unified-result.json` | Architecture, virtual progress, original-code observations, and final sampling |
| `run/native-console-*.ppm` | Captured display console images |
| `debugger-writes.json` | Audit of debugger guest RAM/register write packets |
| `acceptance.json`, `acceptance.md` | Saved run and capability checks |

Check evidence and visible behavior separately:

1. Confirm one QEMU instance, the expected CPU domains, the common virtual clock, and complete final sampling.
2. Confirm delivery of all 25 scheduled events.
3. Check the debugger write audit. This native workflow requires zero debugger writes to guest RAM or registers.
4. Inspect the actual menu, dialog, and shooting OSD images. A nonblack frame alone does not establish menu behavior.
5. Read navigation, exit/reentry, and exposure checks independently.

`--require evidence` checks evidence completeness. It can pass while a functional check remains pending. To request the stronger stable-menu check:

```sh
./z62 ui-verify RUN_DIRECTORY_NAME --require stable-menu
```

The UI auditor returns `0` when the requested check passes and `2` when it does not. Keep the original run evidence and write subsequent audits to new directories.

## 6. Current capability boundary

| Capability | Current scope |
| --- | --- |
| Menu and shooting OSD output | Available with prepared inputs and the configured scenario |
| Confirmation dialog and dismissal | Visible behavior can be checked through original event responses and display frames |
| Complete directional navigation and stable exit/reentry | Pending functional acceptance |
| Shutter, aperture, and ISO display | Pending integration acceptance |
| Full Boot ROM/physical Flash power-on | Pending validation |
| Real-time imaging, capture, movie display, and HDMI | Separate validation targets |

Without a lens, `F---` is a valid aperture indication. This does not by itself establish completion of the exposure display pipeline.

## 7. Reproducible comparisons

Keep the QEMU build, firmware, input models, observation plan, schedule, and virtual deadline consistent when comparing runs. Read each run's saved identities instead of assuming that the latest build or result is the same.

If a development change alters one of those inputs, record the new identity and validate the resulting behavior. Observer changes can affect execution timing even when they perform no guest writes.

For black output or an incomplete menu check, first inspect actual virtual progress, input delivery, saved console frames, and original event responses. Preserve unresolved checks until the required behavior has been observed and accepted.
