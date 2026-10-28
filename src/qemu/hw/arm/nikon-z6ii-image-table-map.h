/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Original1036cfaa/d5be ->1036ebbc uploads u32 tables, bounded by
 * the original byte extents. Their interpretation/execution is unknown. */
#ifndef NIKON_Z6II_IMAGE_TABLE_MAP_H
#define NIKON_Z6II_IMAGE_TABLE_MAP_H
#include <stdbool.h>
#include <stdint.h>
static inline bool z6ii_image_table_configuration_word(uint32_t off)
{
    return !(off & 3) && ((off >= 0x1100 && off <= 0x113c) ||
                         (off >= 0x1200 && off <= 0x1244));
}
#endif
