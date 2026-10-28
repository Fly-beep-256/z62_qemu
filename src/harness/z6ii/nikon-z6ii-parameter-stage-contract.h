/* Generated from original ROM move table; regenerate with parameter-contract/generate.py. */
#ifndef NIKON_Z6II_PARAMETER_STAGE_CONTRACT_H
#define NIKON_Z6II_PARAMETER_STAGE_CONTRACT_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#define Z6II_PARAMETER_CONTRACT_ROM_SHA256 "bb83613121f843d65101da936d942acdc513d86dbd3abc26259d0d870d03f5d4"
#define Z6II_PARAMETER_CONTRACT_TABLE_SHA256 "0240fb9d0a52cbe0b2ea03675a63ef1b6ad756ec3932019a45ec18f443ebdec0"
#define Z6II_PARAMETER_CONTRACT_TABLE_ADDRESS UINT32_C(0x118d7194)
#define Z6II_PARAMETER_CONTRACT_REGION47_TABLE_SHA256 "cb2c3e5b6314130e64933190d375c1cce13f619ad6a4128c9a05f40947ad2fa0"
#define Z6II_PARAMETER_CONTRACT_REGION47_TABLE_ADDRESS UINT32_C(0x118d7244)

/* Only opcode0 COPY entries at the selected original stages. Every other
 * byte must remain the new cold pool's zero initialization. Opcode1 stage9
 * is zero fill; opcode0 stage9 is a COPY and is deliberately unselected.
 * This compares provenance, not cross-process timing or physical Flash. */
typedef struct { uint32_t offset, bytes; } Z6IIParameterStageRange;

static bool z6ii_parameter_stage_ranges_match(const uint8_t *source,
                                              const uint8_t *reference,
                                              size_t bytes, size_t expected,
                                              const Z6IIParameterStageRange *ranges,
                                              size_t count)
{
    if (!source || !reference || bytes != expected) { return false; }
    size_t cursor = 0;
    for (size_t i = 0; i < count; i++) {
        size_t start = ranges[i].offset;
        size_t length = ranges[i].bytes;
        for (; cursor < start; cursor++) {
            if (source[cursor] != 0) { return false; }
        }
        if (memcmp(source + start, reference + start, length)) { return false; }
        cursor = start + length;
    }
    for (; cursor < bytes; cursor++) {
        if (source[cursor] != 0) { return false; }
    }
    return true;
}

static const Z6IIParameterStageRange z6ii_parameter_region50_stage8_ranges[] = {
    { UINT32_C(0x0), UINT32_C(0xca100) },
    { UINT32_C(0xce000), UINT32_C(0x6200) },
    { UINT32_C(0xe0780), UINT32_C(0xb890) },
    { UINT32_C(0xec010), UINT32_C(0x4a280) },
    { UINT32_C(0x142850), UINT32_C(0x1bf0) },
    { UINT32_C(0x167ffc), UINT32_C(0x4) },
};

static bool z6ii_parameter_region50_stage8_matches(const uint8_t *source,
                                                       const uint8_t *reference,
                                                       size_t bytes)
{
    return z6ii_parameter_stage_ranges_match(source, reference, bytes,
        UINT32_C(0x168000), z6ii_parameter_region50_stage8_ranges,
        sizeof(z6ii_parameter_region50_stage8_ranges) / sizeof(z6ii_parameter_region50_stage8_ranges[0]));
}

static const Z6IIParameterStageRange z6ii_parameter_region47_stage4_stage8_ranges[] = {
    { UINT32_C(0xa6860), UINT32_C(0xc500) },
    { UINT32_C(0xb2d60), UINT32_C(0x19aa0) },
    { UINT32_C(0xd7ff0), UINT32_C(0x10) },
};

static bool z6ii_parameter_region47_stage4_stage8_matches(const uint8_t *source,
                                                       const uint8_t *reference,
                                                       size_t bytes)
{
    return z6ii_parameter_stage_ranges_match(source, reference, bytes,
        UINT32_C(0xd8000), z6ii_parameter_region47_stage4_stage8_ranges,
        sizeof(z6ii_parameter_region47_stage4_stage8_ranges) / sizeof(z6ii_parameter_region47_stage4_stage8_ranges[0]));
}
#endif
