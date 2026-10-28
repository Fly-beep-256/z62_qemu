/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef Z6II_BA2_WINDOW98_H
#define Z6II_BA2_WINDOW98_H
#include "ba2-bus77.h"

#define Z6II_BA2_WINDOW98_POLICY "committed-additive-ordinary-ram-v1"

typedef struct {
    uint32_t base, master_address;
    size_t size;
    unsigned index;
} Z6IIBA2Window98Range;

/* Original Master 10242B40/10242B4C subtract 40000000/60000000 before
 * committing the window offsets. This opt-in candidate adds that offset
 * to a BA2 address. It defines neither a generic payload-pointer conversion
 * nor silicon cache coherence. Existing local payload/private RAM retain
 * precedence; only the remainder of each committed aperture is exported. */
static inline Z6IIBA2BusResult z6ii_ba2_window98_plan(
    const Z6IIIPU2402 *master, size_t payload_bytes, size_t private_bytes,
    Z6IIBA2Window98Range ranges[2], unsigned *count)
{
    Z6IIBA2Window98Range pending[2];
    unsigned used = 0;
    const uint32_t bases[2] = { UINT32_C(0x40000000), UINT32_C(0x60000000) };
    const size_t local[2] = { payload_bytes, private_bytes };
    if (!master || !ranges || !count || payload_bytes != Z6II_BA2_PAYLOAD_BYTES ||
        !private_bytes || private_bytes > UINT32_C(0x20000000)) {
        return Z6II_BA2_BUS_BAD_CONFIG;
    }
    if (!master->window_valid || !master->window_commits) {
        *count = 0;
        return Z6II_BA2_BUS_OK;
    }
    for (unsigned i = 0; i < 2; ++i) {
        uint64_t length = master->window_active[i * 2 + 1];
        uint64_t offset = master->window_active[i * 2];
        uint64_t translated = (uint64_t)bases[i] + offset;
        if (length > UINT32_C(0x20000000) ||
            translated + length > UINT64_C(0x100000000)) {
            return Z6II_BA2_BUS_UNMAPPED;
        }
        if (length <= local[i]) {
            continue;
        }
        pending[used++] = (Z6IIBA2Window98Range) {
            .base = bases[i] + (uint32_t)local[i],
            .master_address = (uint32_t)(translated + local[i]),
            .size = (size_t)(length - local[i]), .index = i,
        };
    }
    for (unsigned i = 0; i < used; ++i) {
        ranges[i] = pending[i];
    }
    *count = used;
    return Z6II_BA2_BUS_OK;
}

/* The caller owns and verifies an ordinary writable Master RAM allocation
 * for the entire call. No new allocation, zero-fill or guest write occurs.
 * All output state is preserved on a failed extent/permission check. */
static inline Z6IIBA2BusResult z6ii_ba2_window98_bind(
    const Z6IIBA2Window98Range *range, const Z6IIBA2MemoryMap *backing,
    Z6IIBA2MemoryMap *out)
{
    if (!range || !backing || !out || !range->size || !backing->bytes ||
        !backing->mapping_basis || !*backing->mapping_basis ||
        (uint64_t)range->base + range->size > UINT64_C(0x100000000) ||
        (uint64_t)backing->base + backing->size > UINT64_C(0x100000000)) {
        return Z6II_BA2_BUS_BAD_CONFIG;
    }
    if (!(backing->permissions & Z6II_BA2_MEM_READ) ||
        !(backing->permissions & Z6II_BA2_MEM_WRITE) ||
        backing->writable_bytes != backing->bytes) {
        return Z6II_BA2_BUS_PERMISSION;
    }
    if (range->master_address < backing->base ||
        (uint64_t)range->master_address - backing->base > backing->size ||
        range->size > backing->size - ((uint64_t)range->master_address - backing->base)) {
        return Z6II_BA2_BUS_UNMAPPED;
    }
    size_t offset = range->master_address - backing->base;
    *out = (Z6IIBA2MemoryMap) {
        .base = range->base, .size = range->size,
        .bytes = backing->bytes + offset,
        .writable_bytes = backing->writable_bytes + offset,
        .permissions = Z6II_BA2_MEM_READ | Z6II_BA2_MEM_WRITE,
        .mapping_basis = "committed additive window; same ordinary Master RAM; silicon-unverified",
    };
    return Z6II_BA2_BUS_OK;
}
#endif
