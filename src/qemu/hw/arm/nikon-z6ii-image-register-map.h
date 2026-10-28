/* SPDX-License-Identifier: GPL-2.0-or-later */
/* C1.70 configuration stores only. Generated from original-byte
 * contract SHA256 c6b1e3a495bb40554c851f4829fea6956a248cdf076d3cf2deb66a9cfd40ac13.
 * Raw result/status groups are deliberately absent. */
#ifndef NIKON_Z6II_IMAGE_REGISTER_MAP_H
#define NIKON_Z6II_IMAGE_REGISTER_MAP_H
#include <stdbool.h>
#include <stdint.h>
#include "nikon-z6ii-image-auxiliary-map.h"
#include "nikon-z6ii-image-table-map.h"
#include "nikon-z6ii-image-rest-write-map.h"

static inline bool z6ii_image_configuration_word(unsigned bank, uint32_t off)
{
    static const uint16_t offsets[] = {
        0x040, 0x044, 0x048, 0x04c, 0x050, 0x084, 0x088, 0x08c,
        0x094, 0x098, 0x09c, 0x0a0, 0x0a8, 0x0ac, 0x0b0, 0x0b8,
        0x0bc, 0x0c0, 0x0c4, 0x0c8, 0x0cc, 0x0d4, 0x0d8, 0x0dc,
        0x0e0, 0x0e4, 0x0f8, 0x0fc, 0x100, 0x104, 0x108, 0x10c,
        0x11c, 0x120, 0x124, 0x128, 0x12c, 0x130, 0x134, 0x138,
        0x13c, 0x140, 0x144, 0x200, 0x204, 0x208, 0x20c, 0x210,
        0x218, 0x21c, 0x220, 0x224, 0x228, 0x22c, 0x230, 0x234,
        0x300, 0x304, 0x308, 0x30c, 0x310, 0x314, 0x318, 0x31c,
        0x320, 0x324, 0x328, 0x32c, 0x330, 0x334, 0x338, 0x33c,
        0x340, 0x344, 0x348, 0x34c, 0x364, 0x368, 0x36c, 0x370,
        0x374, 0x378, 0x37c, 0x380, 0x384, 0x394, 0x398, 0x39c,
        0x3a0, 0x3a4, 0x3a8, 0x3ac, 0x3b0, 0x3b4, 0x3c4, 0x3c8,
        0x3d8, 0x3dc, 0x3e0, 0x3e8, 0x3ec, 0x3f0,
    };
    if (bank > 1 || (off & 3) ||
        (bank == 1 && (off == 0xac || off == 0xb0))) { return false; }
    if (z6ii_image_auxiliary_configuration_word(off)) { return true; }
    if (z6ii_image_table_configuration_word(off)) { return true; }
    if (z6ii_image_rest_configuration_write_word(off)) { return true; }
    for (unsigned i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
        if (off == offsets[i]) { return true; }
    }
    return off >= 0x2100 && off <= 0x22fc;
}

static inline bool z6ii_image_control_word(uint32_t off)
{
    switch (off) {
    case 0: case 4: case 8: case 0x0c: case 0x10:
    case 0x20: case 0x24:
    /* Current 1036bf42 writes the complemented control mask at+e8;
     * 1036bf48 writes+f0. Both are latches here, with no retirement. */
    case 0x54: case 0x60: case 0x6c: case 0x78: case 0xd0: case 0xe8: case 0xf0:
        return true;
    default: return false;
    }
}

static inline bool z6ii_image_control_value(unsigned bank, uint32_t off,
                                            uint32_t word)
{
    /* 1036be9e writes0 to the unbanked203800d0 literal. No readback,
     * bank1 alias, nonzero write or retirement semantics is established. */
    return bank < 2 && z6ii_image_control_word(off) &&
           (off != 0xd0 || (!bank && !word));
}

#endif
