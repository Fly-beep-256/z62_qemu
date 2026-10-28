# Running the native method — v0.0.2

The current development method is **v0.0.2 / V44**. Follow [the native guide](NATIVE-v0.0.2.md) for its source identities, firmware and retained-input requirements, exact launch recipe, observed exposure result and remaining gates.

## Source checkout

```sh
./z62 --version
./z62 native --check-only
./z62 native --print-command
```

These commands inspect the public source distribution. The entry uses local runtime Python when available and otherwise host `python3`. A source-only check creates no QEMU or camera session and reports `runtime_verified=false`.

A fresh clone omits runtime tools, firmware, private peripheral inputs, build artifacts and raw results. Prepare those locally before execution. The source check and a successful QEMU exit do not establish functional-camera acceptance.

## Prepared native installation

```sh
./z62 doctor
./z62 native --preflight-only
./z62 native
```

The last two commands use explicitly supplied manifests or the ignored selection file `inputs/local/native-v0.0.2/inputs.json`. See [the selection example](examples/native-v0.0.2-inputs.example.json). The method checks the source-bound rebuild, original ROM identities, retained composite Flash and the complete RTC bank with original producer evidence. It prints all experimental model selections and actual input paths before launch.

The native observation deadline is **34 virtual seconds**; the default host safety budget is **1800 seconds**. Allow the complete virtual window and final sampling to finish. Run scenarios sequentially and freeze their execution sources and inputs until cleanup completes.

`./z62 run --profile native` remains the low-level method with existing generic defaults. Use the named `native` entry for the v0.0.2 exposure scenario. `imaging`, `shooting-modes`, `specs`, `still-disp` and `movie-disp` retain their separately labeled assisted scope.

## Retained evidence

Each execution creates a new `results/<run-id>/` envelope:

| Location | Evidence |
| --- | --- |
| `prepare/` | Effective command, runtime models, input identities, frozen plans and execution sources |
| `prepare/native-milestone.json` | Published milestone manifest frozen by the named entry |
| `run/native-unified-result.json` | Actual original-code observations, virtual progress, architecture and final sampling |
| `run/RSP-io.jsonl`, `run/QMP-io.jsonl` | Both actual debugger streams; CPU/stop-epoch binding and write audit |
| `run/native-console-*.ppm` | Actual QMP display captures |
| `debugger-writes.json` | Guest RAM/register write packet audit |
| `acceptance.json`, `acceptance.md` | Run-local acceptance and pending capability gates |

```sh
./z62 ui-verify RUN_DIRECTORY_NAME --require evidence
./z62 exposure-verify RUN_DIRECTORY_NAME \
  --visual-reviews results/YOUR_EXACT_RGB_REVIEWS.json \
  --out results/YOUR_NEW_EXPOSURE_AUDIT
```

Use explicit run names and exact RGB reviews belonging to those runs. Write new audit outputs. Keep original acceptance, the global UI index and historical v0.01 comparison unchanged. The source-bound exposure verifier accepts numerical publication and observed LCD text independently of changing-light metering and image-processing completion.

## Current observed boundary

The V44 reference shows `30" / F-- / ISO AUTO 51200` and verifies zero debugger guest RAM/register writes. Continuous label visibility and sensor live view remain unverified. Four menu responses verify, but the first MENU delay is **8.846305488 virtual seconds**, exceeding the unchanged **3-second** criterion; strict stable MENU/reentry remain false.

RAW/ISP completion, measured AE feedback, physical Flash/Boot-ROM startup, complete shutdown/calendar continuity, capture/storage, movie and HDMI remain separate pending gates. See [the sanitized milestone evidence](evidence/native-v0.0.2.json) and [acceptance rules](ACCEPTANCE.md).

Earlier prepared-package and relocation observations are retained in [historical workspace notes](WORKSPACE-README.md) and local `results/` / `provenance/`. They are not bundled into a Git clone and do not replace this version's source or run identities.
