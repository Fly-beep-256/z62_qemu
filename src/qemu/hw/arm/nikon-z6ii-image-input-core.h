/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Original C1.70 input transport: 1036C3B0 transports direct width/height
 * to +48; 1036C774/78A transport the three header words; 1036C7BA
 * transports sixteen addresses and the byte stride. This view describes
 * byte spans only, without assigning pixel packing or frame ownership. */
#ifndef NIKON_Z6II_IMAGE_INPUT_CORE_H
#define NIKON_Z6II_IMAGE_INPUT_CORE_H

#include <stdbool.h>
#include <stdint.h>

#define Z6II_IMAGE_INPUT_GEOMETRY_FIELD 23
#define Z6II_IMAGE_INPUT_REQUIRED_FIELDS (UINT32_C(0xfffff) | (UINT32_C(1) << Z6II_IMAGE_INPUT_GEOMETRY_FIELD))

typedef struct Z6IIImageInputView {
    uint32_t header[3];
    uint32_t sources[16];
    uint32_t width, height, stride;
    uint64_t extent_bytes;
    unsigned source_count;
} Z6IIImageInputView;

static inline bool z6ii_image_input_view(const uint32_t *registers,
                                         uint32_t written,
                                         Z6IIImageInputView *output)
{
    if (!registers || !output ||
        (written & Z6II_IMAGE_INPUT_REQUIRED_FIELDS) != Z6II_IMAGE_INPUT_REQUIRED_FIELDS) {
        return false;
    }
    Z6IIImageInputView view = {0};
    view.width = registers[0x48 / 4] >> 16;
    view.height = registers[0x48 / 4] & 0xffff;
    view.stride = registers[0x30c / 4];
    if (!view.width || !view.height || !view.stride) { return false; }
    view.extent_bytes = (uint64_t)view.stride * view.height;
    if (view.extent_bytes > UINT64_C(0x100000000)) { return false; }
    for (unsigned i = 0; i < 3; ++i) {
        view.header[i] = registers[(0x300 + 4 * i) / 4];
    }
    for (unsigned i = 0; i < 16; ++i) {
        uint32_t source = registers[(0x310 + 4 * i) / 4];
        if (source && (uint64_t)source + view.extent_bytes > UINT64_C(0x100000000)) {
            return false;
        }
        view.sources[i] = source;
        view.source_count += source != 0;
    }
    if (!view.source_count) { return false; }
    /* Header mode0 does not uniquely determine RAW12. Duplicate slots
     * remain permitted here: their temporal ownership is not established.
     * RAM backing, payload production, execution and retirement are
     * independent checks. Nothing in this view admits an image job. */
    *output = view;
    return true;
}

#endif
