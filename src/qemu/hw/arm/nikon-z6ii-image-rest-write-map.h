/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Source-bound write-only parameter map; original Master SHA
 * bb83613121f843d65101da936d942acdc513d86dbd3abc26259d0d870d03f5d4.
 * Generated from explicit scalar stores and exact table byte extents.
 * This predicate grants neither MMIO reads nor control/ready values.
 * Retain opaque words only: no pixel transform, program execution,
 * request retirement, IRQ, or functional-camera completion is implied. */
#ifndef NIKON_Z6II_IMAGE_REST_WRITE_MAP_H
#define NIKON_Z6II_IMAGE_REST_WRITE_MAP_H
#include <stdbool.h>
#include <stdint.h>

static inline bool z6ii_image_rest_configuration_write_word(uint32_t off)
{
    if (off & 3) { return false; }
    if (off >= 0x584u && off <= 0x65cu) { return true; }
    if (off >= 0x700u && off <= 0x778u) { return true; }
    if (off >= 0x900u && off <= 0x9d8u) { return true; }
    if (off >= 0xb00u && off <= 0xbbcu) { return true; }
    if (off >= 0xd00u && off <= 0xe18u) { return true; }
    if (off >= 0xf00u && off <= 0xf2cu) { return true; }
    if (off >= 0x1300u && off <= 0x1320u) { return true; }
    if (off >= 0x1328u && off <= 0x1348u) { return true; }
    if (off >= 0x1350u && off <= 0x1370u) { return true; }
    if (off >= 0x1378u && off <= 0x1398u) { return true; }
    if (off >= 0x1400u && off <= 0x1e34u) { return true; }
    if (off >= 0x1f00u && off <= 0x1f40u) { return true; }
    if (off >= 0x1f48u && off <= 0x1f88u) { return true; }
    if (off >= 0x1f90u && off <= 0x1fb0u) { return true; }
    if (off >= 0x1fb8u && off <= 0x1fd8u) { return true; }
    if (off >= 0x1fe0u && off <= 0x2000u) { return true; }
    if (off >= 0x2008u && off <= 0x2028u) { return true; }
    if (off >= 0x2030u && off <= 0x2050u) { return true; }
    if (off >= 0x2058u && off <= 0x2078u) { return true; }
    if (off >= 0x2080u && off <= 0x20a0u) { return true; }
    if (off >= 0x20a8u && off <= 0x20c8u) { return true; }
    if (off >= 0x20d0u && off <= 0x20dcu) { return true; }
    if (off >= 0x2400u && off <= 0x2c94u) { return true; }
    if (off >= 0x3900u && off <= 0x3a98u) { return true; }
    if (off >= 0x3aa0u && off <= 0x3c38u) { return true; }
    if (off >= 0x3c40u && off <= 0x3dd8u) { return true; }
    if (off >= 0x3de0u && off <= 0x3f78u) { return true; }
    if (off >= 0x3f80u && off <= 0x4118u) { return true; }
    if (off >= 0x4120u && off <= 0x42b8u) { return true; }
    if (off >= 0x42c0u && off <= 0x44c0u) { return true; }
    if (off >= 0x44c8u && off <= 0x45c8u) { return true; }
    if (off >= 0x45d0u && off <= 0x46d0u) { return true; }
    if (off >= 0x46d8u && off <= 0x47d8u) { return true; }
    if (off >= 0x47e0u && off <= 0x48e0u) { return true; }
    if (off >= 0x48e8u && off <= 0x49e8u) { return true; }
    if (off >= 0x49f0u && off <= 0x4af4u) { return true; }
    if (off >= 0x4afcu && off <= 0x4c00u) { return true; }
    if (off >= 0x4c08u && off <= 0x4d0cu) { return true; }
    if (off >= 0x4d14u && off <= 0x5024u) { return true; }
    if (off >= 0x502cu && off <= 0x512cu) { return true; }
    if (off >= 0x5134u && off <= 0x5334u) { return true; }
    if (off >= 0x533cu && off <= 0x553cu) { return true; }
    if (off >= 0x5544u && off <= 0x5744u) { return true; }
    if (off >= 0x574cu && off <= 0x594cu) { return true; }
    if (off >= 0x5954u && off <= 0x5a54u) { return true; }
    if (off >= 0x5a5cu && off <= 0x5adcu) { return true; }
    if (off >= 0x5ae4u && off <= 0x5b64u) { return true; }
    if (off >= 0x5c00u && off <= 0x5dfcu) { return true; }
    return false;
}

static inline bool z6ii_image_rest_configuration_write(uint32_t addr, unsigned size)
{
    uint32_t off;
    if (size != 4) { return false; }
    if (addr >= 0x20380000u && addr < 0x20390000u) {
        off = addr - 0x20380000u;
    } else if (addr >= 0x203c0000u && addr < 0x203d0000u) {
        off = addr - 0x203c0000u;
    } else { return false; }
    return z6ii_image_rest_configuration_write_word(off);
}

#endif
