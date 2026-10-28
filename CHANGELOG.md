# Changelog

## v0.0.2 — 2026-10-28

Publish the V44 native exposure milestone. Original firmware now initializes and publishes the numerical shutter/aperture/ISO triple, and reviewed LCD pixels show `30" / F-- / ISO AUTO 51200` under explicit device-model hypotheses.

- Add the current `./z62 native` method with source-only checks, printed recipe and prepared-runtime preflight. Freeze the milestone, version and launcher in new run envelopes.
- Publish the 64-site original-code observation plan, 25 external input edges, 181 source/input fingerprints including 119 native model sources, and a sanitized result/LCD evidence summary.
- Include backed image configuration SRAM, exact configuration coverage, conservative unit request histories, owned IRQ status/masks, input geometry/address upload validation and passive input-byte observation. Actual RAW/ISP processing completion remains pending.
- Include the source-bound `exposure-verify` audit and its wire-bound negative regression. Preserve unknown request history and explicit `next-frame-ae-v4` / `pending-v1` selections.
- Preserve the historical v0.01 menu comparison and unchanged strict MENU criteria. Current first MENU delay is 8.846305488 virtual seconds; strict stable MENU/reentry remain false.
- Publish the ARM native source without upstream ROM projects or prebuilt boot blobs, include its offline DTC/keycode/SoftFloat source dependencies, and correct blob-disabled configuration and root firmware-ignore scope.

Validation: local prepared-runtime/input preflight; source-only export from another working directory; 12 native-entry boundary tests; retained original-exposure wire replay and 16 damaged-evidence checks; two image-device C tests; fresh offline ARM compilation and native-machine introspection from the exported source. Source-export compilation uses separately prepared host libraries and the standard host-binary relocation step.

Full changing-light metering, RAW/ISP completion, real sensor live view, physical Flash/Boot-ROM startup, complete shutdown/calendar continuity, capture/storage, movie and HDMI remain separate pending gates. The publication work starts no new firmware run or camera session. Reference results remain bound to `20261028-051606-native-display-observation-7a9393` and the immutable V44 QEMU build.

See [Native method v0.0.2](docs/NATIVE-v0.0.2.md) and [published evidence](docs/evidence/native-v0.0.2.json).

## Historical v0.01 menu baseline

The retained earlier menu/OSD profile and original comparison records remain unchanged. They have their own build/input identities and acceptance scope; see [the historical guide](docs/COLD-START-BASELINE-v0.01.md).
