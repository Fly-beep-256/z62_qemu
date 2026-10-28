#ifndef NIKON_Z6II_PEER_PARAMETER_H
#define NIKON_Z6II_PEER_PARAMETER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "nikon-z6ii-parameter-stage-contract.h"

/* Original 103C8164/103C819A delimit the complete application allocation
 * pool C7F00000..CC200000. Share that pool instead of growing a small
 * window for each new allocation. The original DMA source C8300000 is
 * a view of the same backing, at +400000; it must not shadow this pool
 * with an unrelated file. Original domain0 and both ROM L1 tables also
 * establish the ordinary peer CPU aperture 47F00000..4C200000. Physical
 * DDR routing and cache timing are not established by those tables. */
#define Z6II_PARAMETER_LOCAL_BASE UINT32_C(0xc7f00000)
#define Z6II_PARAMETER_BUS_BASE UINT32_C(0x47f00000)
#define Z6II_PARAMETER_SECTION_BYTES UINT32_C(0x4300000)
#define Z6II_PARAMETER_DMA_VIEW_OFFSET UINT32_C(0x400000)

typedef struct Z6IIParameterCopy {
    uint32_t source, destination, source_stride, width, destination_stride, rows;
    uint64_t source_extent, destination_extent, payload_bytes;
} Z6IIParameterCopy;

static bool z6ii_parameter_decode(const uint32_t regs[13], Z6IIParameterCopy *out)
{
    Z6IIParameterCopy p = {
        .source = regs[11], .destination = regs[12],
        .source_stride = regs[7], .width = regs[8],
        .destination_stride = regs[9], .rows = regs[10],
    };
    if (regs[4] != 1 || regs[5] != 0x10 || regs[6] != 0 ||
        !p.width || p.width > 0xffff || !p.rows || p.rows > 0xffff ||
        p.source_stride > 0xffff || p.destination_stride > 0xffff ||
        p.source_stride < p.width || p.destination_stride < p.width) {
        return false;
    }
    p.source_extent = (uint64_t)p.source_stride * (p.rows - 1) + p.width;
    p.destination_extent = (uint64_t)p.destination_stride * (p.rows - 1) + p.width;
    p.payload_bytes = (uint64_t)p.width * p.rows;
    if (p.source < Z6II_PARAMETER_BUS_BASE ||
        (uint64_t)p.source + p.source_extent >
            (uint64_t)Z6II_PARAMETER_BUS_BASE + Z6II_PARAMETER_SECTION_BYTES ||
        p.destination_extent > UINT64_C(0x1000000) ||
        (uint64_t)p.destination + p.destination_extent > UINT64_C(0x100000000)) {
        return false;
    }
    *out = p;
    return true;
}

/* Optional research provenance guard, separate from the hardware contract.
 * Pinned complete recorded RAM bodies also anchor the ROM-derived stage8
 * byte comparison. They are not recovered physical Flash images.
 * Other source ranges/strided views have no certified byte coverage here. */
static const char *z6ii_parameter_recorded_body_sha256(const Z6IIParameterCopy *p)
{
    if (p->source_stride != p->width) { return NULL; }
    if (p->source == UINT32_C(0x47f00000) && p->payload_bytes == UINT32_C(0x168000)) {
        return "3131474120fa6a149b14709932bce810f9d801c2aabca01eda75e26bcc62fb93";
    }
    if (p->source == UINT32_C(0x48068000) && p->payload_bytes == UINT32_C(0xd8000)) {
        return "996d4ae717a00eb76d9b6ee42e92736bdf74069cc44a95af709ab228e0f6b76b";
    }
    return NULL;
}

#endif
