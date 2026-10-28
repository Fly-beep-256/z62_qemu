/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Original C1.70 auxiliary parameter stores from1036cc0a..d010.
 * Read/result groups418,474..484 and4cc..4dc stay unsupported.
 * These85 offsets retain parameters; no algorithm or job completion. */
#ifndef NIKON_Z6II_IMAGE_AUXILIARY_MAP_H
#define NIKON_Z6II_IMAGE_AUXILIARY_MAP_H
#include <stdbool.h>
#include <stdint.h>

static inline bool z6ii_image_auxiliary_configuration_word(uint32_t off)
{
    if (off & 3) { return false; }
    switch (off) {
    case 0x400: case 0x404: case 0x408: case 0x40c: case 0x410:
    case 0x414: case 0x420: case 0x424: case 0x428: case 0x42c:
        return true;
    default: break;
    }
    return (off >= 0x430 && off <= 0x470) ||
           (off >= 0x488 && off <= 0x4c8) ||
           (off >= 0x660 && off <= 0x67c) ||
           (off >= 0x500 && off <= 0x580);
}

#endif
