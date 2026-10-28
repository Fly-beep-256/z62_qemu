/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "hw/arm/nikon-z6ii-image-input-core.h"

int main(void)
{
    uint32_t registers[0x350 / 4] = {0};
    Z6IIImageInputView output = {.width = 77};
    uint32_t fields = Z6II_IMAGE_INPUT_REQUIRED_FIELDS;
    registers[0x48 / 4] = 0x05ea03ee;
    registers[0x30c / 4] = 2272;
    registers[0x310 / 4] = 0x82c00000;
    registers[0x314 / 4] = 0x8448dc00;
    registers[0x318 / 4] = 0x85d1b800;
    registers[0x31c / 4] = 0x875a9400;
    /* Valid old geometry bytes do not prove the guest uploaded them. */
    assert(!z6ii_image_input_view(registers, 0xfffff, &output));
    assert(output.width == 77);
    assert(z6ii_image_input_view(registers, fields, &output));
    assert(output.width == 1514 && output.height == 1006);
    assert(output.stride == 2272 && output.extent_bytes == UINT64_C(2285632));
    assert(output.source_count == 4 && output.sources[3] == 0x875a9400);
    /* Every input word is required, including zero-valued unused slots. */
    assert(!z6ii_image_input_view(registers, fields & ~(1u << 19), &output));
    registers[0x310 / 4] = UINT32_MAX - 63;
    assert(!z6ii_image_input_view(registers, fields, &output));
    registers[0x310 / 4] = 0x82c00000;
    registers[0x30c / 4] = UINT32_MAX;
    assert(!z6ii_image_input_view(registers, fields, &output));
    registers[0x30c / 4] = 0;
    assert(!z6ii_image_input_view(registers, fields, &output));
    registers[0x30c / 4] = 2272;
    registers[0x48 / 4] = 0x05ea0000;
    assert(!z6ii_image_input_view(registers, fields, &output));
    registers[0x48 / 4] = 0x0014000e;
    registers[0x30c / 4] = 32;
    registers[0x300 / 4] = 2;
    assert(z6ii_image_input_view(registers, fields, &output));
    assert(output.width == 20 && output.height == 14 && output.extent_bytes == 448);
    assert(output.header[0] == 2); /* No pixel format or operation assigned. */
    registers[0x314 / 4] = registers[0x310 / 4];
    assert(z6ii_image_input_view(registers, fields, &output));
    memset(registers + 0x310 / 4, 0, 16 * sizeof(*registers));
    assert(!z6ii_image_input_view(registers, fields, &output));
    puts("PASS: original input fields, direct counts, byte spans, wrap rejection and unknown slot ownership");
    return 0;
}
