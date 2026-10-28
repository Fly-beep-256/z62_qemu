/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "ba2-bus79.h"
#include <string.h>

static bool contains(uint32_t base, size_t length, uint32_t a)
{
    return a >= base && (uint64_t)a - base <= length &&
           4 <= length - ((uint64_t)a - base);
}
static Z6IIBA2BusResult fail(Z6IIBA2Bus *b, Z6IIBA2BusResult result, uint32_t a)
{
    if (b) {
        b->fault = (Z6IIBA2BusFault) { result, a, 4, true, false };
    }
    return result;
}
Z6IIBA2BusResult z6ii_ba2_bus_write_ram_batch(void *opaque,
    const uint32_t *addresses, const uint32_t *values, unsigned count)
{
    Z6IIBA2Bus *b = opaque;
    uint32_t a[Z6II_BA2_RAM_BATCH_MAX], v[Z6II_BA2_RAM_BATCH_MAX];
    uint8_t *target[Z6II_BA2_RAM_BATCH_MAX];
    if (!b || !b->initialized || !addresses || !values || !count ||
        count > Z6II_BA2_RAM_BATCH_MAX) {
        return fail(b, Z6II_BA2_BUS_BAD_CONFIG, 0);
    }
    memcpy(a, addresses, count * sizeof(a[0]));
    memcpy(v, values, count * sizeof(v[0]));
    for (unsigned i = 0; i < count; i++) {
        if ((uint64_t)a[i] + 4 > UINT64_C(0x100000000)) {
            return fail(b, Z6II_BA2_BUS_UNMAPPED, a[i]);
        }
        if (!b->config.allow_unaligned_data && (a[i] & 3)) {
            return fail(b, Z6II_BA2_BUS_BAD_ALIGNMENT, a[i]);
        }
        const Z6IIBA2MemoryMap *m = NULL;
        for (unsigned j = 0; j < b->config.ram_count; j++) {
            if (contains(b->config.ram[j].base, b->config.ram[j].size, a[i])) {
                m = &b->config.ram[j];
                break;
            }
        }
        if (!m) {
            Z6IIBA2BusResult result = Z6II_BA2_BUS_UNMAPPED;
            if (contains(b->config.payload.base, b->config.payload.size, a[i]) ||
                (b->config.mmio.size && contains(b->config.mmio.base,
                                                b->config.mmio.size, a[i]))) {
                result = Z6II_BA2_BUS_PERMISSION;
            }
            return fail(b, result, a[i]);
        }
        if (!(m->permissions & Z6II_BA2_MEM_WRITE) || !m->writable_bytes) {
            return fail(b, Z6II_BA2_BUS_PERMISSION, a[i]);
        }
        target[i] = m->writable_bytes + (a[i] - m->base);
        for (unsigned j = 0; j < i; j++) {
            uintptr_t x = (uintptr_t)target[i], y = (uintptr_t)target[j];
            if ((uint64_t)a[i] < (uint64_t)a[j] + 4 &&
                (uint64_t)a[j] < (uint64_t)a[i] + 4) {
                return fail(b, Z6II_BA2_BUS_BAD_CONFIG, a[i]);
            }
            /* Reject aliased backing even when guest views do not overlap. */
            if (x <= UINTPTR_MAX - 4 && y <= UINTPTR_MAX - 4 &&
                x < y + 4 && y < x + 4) {
                return fail(b, Z6II_BA2_BUS_BAD_CONFIG, a[i]);
            }
        }
    }
    for (unsigned i = 0; i < count; i++) {
        for (unsigned j = 0; j < 4; j++) {
            unsigned shift = b->config.data_endian == Z6II_BA2_DATA_LE ?
                             j * 8 : (3 - j) * 8;
            target[i][j] = v[i] >> shift;
        }
    }
    return Z6II_BA2_BUS_OK;
}
