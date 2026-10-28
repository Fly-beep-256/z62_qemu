/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Deterministic, generated-on-demand sensor input. This is a documented
 * functional RAW assumption, not a measured Z6II sensor packing contract. */
#ifndef NIKON_Z6II_BAYER_SOURCE_H
#define NIKON_Z6II_BAYER_SOURCE_H

static const NikonRawGeometry z6ii_bayer_geometry = {2034, 1434, 4080, 64, 4095};

static void z6ii_bayer_generate(uint8_t *raw, uint64_t frame_id)
{
    static const uint8_t bars[8][3] = {
        {1,1,1}, {1,1,0}, {0,1,1}, {0,1,0},
        {1,0,1}, {1,0,0}, {0,0,1}, {0,0,0}
    };
    const unsigned cw = 1017, ch = 717, stride = 4080;
    unsigned left = (frame_id * 37) % (cw - 128);
    unsigned top = (frame_id * 19) % (ch - 96);
    unsigned bright = 768 + (frame_id % 32) * 96;
    for (unsigned y = 0; y < ch; ++y) {
        uint8_t *even = raw + 2 * y * stride;
        uint8_t *odd = even + stride;
        for (unsigned x = 0; x < cw; ++x) {
            unsigned bar = x * 8 / cw;
            uint16_t rgb[3];
            bool box = x >= left && x < left + 128 &&
                       y >= top && y < top + 96;
            for (unsigned c = 0; c < 3; ++c) {
                unsigned level = bars[bar][c] ? bright : 96;
                if (box) { level = c == frame_id % 3 ? 3900 : 256; }
                rgb[c] = 64 + level;
            }
            stw_le_p(even + 4*x, rgb[0]);
            stw_le_p(even + 4*x + 2, rgb[1]);
            stw_le_p(odd + 4*x, rgb[1]);
            stw_le_p(odd + 4*x + 2, rgb[2]);
        }
        for (unsigned x = cw * 4; x < stride; x += 2) {
            stw_le_p(even + x, 64);
            stw_le_p(odd + x, 64);
        }
    }
}

#endif
