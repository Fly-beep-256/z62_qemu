/* SPDX-License-Identifier: GPL-2.0-or-later */
/* C1.70 table1078ed60 rows34..75, unchanged source ROM SHA256
 * bb83613121f843d65101da936d942acdc513d86dbd3abc26259d0d870d03f5d4.
 * 103bf7b0 writes1 to the selected unit base. This map does not
 * assign an algorithm, pixel format, completion cause or timing. */
#ifndef NIKON_Z6II_IMAGE_UNIT_MAP_H
#define NIKON_Z6II_IMAGE_UNIT_MAP_H
#include <stdint.h>

#define Z6II_IMAGE_UNIT_COUNT 42
static const uint32_t z6ii_image_unit_bases[Z6II_IMAGE_UNIT_COUNT] = {
    0x20100920, 0x20100e60, 0x20100e80, 0x20100800, 0x20100820, 0x20100840,
    0x20100880, 0x201008a0, 0x201008c0, 0x201008e0, 0x20100c80, 0x20100900,
    0x20100ac0, 0x20100cc0, 0x20100ce0, 0x20100940, 0x20100960, 0x20100980,
    0x201009a0, 0x201009c0, 0x201009e0, 0x20100ba0, 0x20100bc0, 0x20100d40,
    0x20100d60, 0x20100d80, 0x20100da0, 0x20100dc0, 0x20100de0, 0x20100e00,
    0x20100e20, 0x20100a40, 0x20100a80, 0x20100aa0, 0x20100a60, 0x20100d00,
    0x20100d20, 0x20100e40, 0x20100a00, 0x20100a20, 0x20100b60, 0x20100b80,
};

static inline int z6ii_image_unit_index(uint32_t address)
{
    for (unsigned i = 0; i < Z6II_IMAGE_UNIT_COUNT; ++i) {
        if (address == z6ii_image_unit_bases[i]) { return i; }
    }
    return -1;
}

#endif
