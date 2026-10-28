# Attribution, Licensing, and Safety Notice

## Independent Research Statement

`z62_qemu` is an independent, non-commercial hobbyist research and educational project dedicated to studying the dual-processor system architecture of the Nikon Z 6II (Dual EXPEED 6 + Cortex-M MCU) inside a host-side QEMU emulation environment.

This project is not affiliated with, sponsored by, or endorsed by Nikon Corporation. "Nikon", "NIKKOR", "EXPEED", and "Z 6II" are trademarks or registered trademarks of Nikon Corporation, used here strictly for nominative technical identification of the target hardware architecture.

## Non-Infringing Distribution ("Bring Your Own Firmware")

To remain strictly non-infringing and respect intellectual property rights, this repository operates on a **source-and-documentation-only** basis regarding proprietary camera payloads:

- **No Firmware Redistributed**: No Nikon firmware binaries, extracted `MAIN` / `EG` / `EX` modules, Boot ROMs, flash dumps, or verbatim proprietary machine-code excerpts are included in or downloaded by this repository.
- **No Cryptographic Keys or Unpackers**: No proprietary encryption/integrity keys, decrypted update intermediates, or firmware package decoding/repacking utilities are distributed here.
- **User-Supplied Inputs**: Executing the emulator beyond synthetic firmware-free board tests requires the user to independently and legally obtain compatible, unmodified firmware images. Firmware copyright remains exclusively with its respective rights holders; no license in this repository grants any rights in Nikon firmware or proprietary assets.

## Hardware and Operational Safety

- **Host-Side Emulation Only**: This software runs entirely on a host computer inside an isolated QEMU virtual machine. It is **not** a camera-installable firmware modification, custom ROM, or on-camera patch.
- **No Physical Flash / Write Operations**: The emulator and its accompanying harness do not contain camera flashing tools, firmware updaters, or destructive USB/PTP write routines. Any optional physical-camera diagnostic documentation or comparison scripts remain strictly read-only and separate from QEMU execution.
- **Evidence-Bounded Separation**: Native cold-boot progression (zero host RAM/register write packets) and assisted feature-preview profiles (which use explicitly logged host staging or synthetic inputs to preview higher-level UI/display pipelines) are audited and reported separately so that synthetic or assisted states are never misrepresented as unassisted hardware behavior.

## Open-Source Licensing and Attribution

- **Project Code and Documentation**: Unless an individual file states otherwise, original board models, harness scripts, synthetic tests, and documentation in this repository are licensed under the **GNU General Public License v2.0 or later ([GPL-2.0-or-later](COPYING))**.
- **Upstream QEMU**: QEMU source code retains its upstream per-file licenses and GPL-2.0-or-later terms; see [LICENSES/QEMU-LICENSE.txt](LICENSES/QEMU-LICENSE.txt).
- **Community Acknowledgements**: Special thanks to [z72 (`JKWTCN/z72-qemu`)](https://github.com/JKWTCN/z72-qemu) for the moral inspiration and encouragement in confronting the complex second-generation Dual-EXPEED 6 (`Z 6II` / `Z 7II`) hardware and firmware topology, as well as [WonderLantern Z6 QEMU](https://github.com/WonderLantern/z6-qemu), [WonderLantern Z7 QEMU](https://github.com/WonderLantern/z7-qemu), and [WonderLantern Z9 QEMU](https://github.com/WonderLantern/z9-qemu) for pioneering QEMU-based Nikon system emulation and source-only publication standards. Upstream notices and attributions are preserved where applicable.
