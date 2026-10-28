/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "ba2-bus77.h"
#include <string.h>

static bool basis(const char *s) { return s && *s; }
static bool extent(uint32_t base, size_t size)
{
    return size && size <= UINT64_C(0x100000000) - base;
}
static bool overlap(uint32_t a, size_t an, uint32_t b, size_t bn)
{
    return (uint64_t)a < (uint64_t)b + bn && (uint64_t)b < (uint64_t)a + an;
}
static bool valid_map(const Z6IIBA2MemoryMap *m)
{
    return extent(m->base, m->size) && m->bytes && basis(m->mapping_basis) &&
           m->permissions && !(m->permissions & ~7u) &&
           ((m->permissions & Z6II_BA2_MEM_WRITE) ?
            m->writable_bytes == m->bytes : !m->writable_bytes);
}

Z6IIBA2BusResult z6ii_ba2_bus_init(Z6IIBA2Bus *b, const Z6IIBA2BusConfig *c)
{
    unsigned i, j;
    if (!b) { return Z6II_BA2_BUS_BAD_CONFIG; }
    memset(b, 0, sizeof(*b));
    if (!c || !valid_map(&c->payload) || c->payload.size != Z6II_BA2_PAYLOAD_BYTES ||
        c->payload.permissions != (Z6II_BA2_MEM_READ | Z6II_BA2_MEM_EXEC) ||
        c->ram_count > Z6II_BA2_MAX_RAM_MAPS || (c->ram_count && !c->ram) ||
        (c->data_endian != Z6II_BA2_DATA_LE && c->data_endian != Z6II_BA2_DATA_BE) ||
        (c->master_fifo && !basis(c->fifo_binding_basis))) {
        return Z6II_BA2_BUS_BAD_CONFIG;
    }
    for (i = 0; i < c->ram_count; ++i) {
        const Z6IIBA2MemoryMap *m = &c->ram[i];
        if (!valid_map(m) || overlap(m->base, m->size, c->payload.base, c->payload.size)) {
            return Z6II_BA2_BUS_BAD_CONFIG;
        }
        for (j = 0; j < i; ++j) {
            if (overlap(m->base, m->size, c->ram[j].base, c->ram[j].size)) {
                return Z6II_BA2_BUS_BAD_CONFIG;
            }
        }
    }
    if (c->mmio.size) {
        if (!extent(c->mmio.base, c->mmio.size) || !basis(c->mmio.mapping_basis) ||
            (!c->mmio.read && !c->mmio.write) ||
            overlap(c->mmio.base, c->mmio.size, c->payload.base, c->payload.size)) {
            return Z6II_BA2_BUS_BAD_CONFIG;
        }
        for (i = 0; i < c->ram_count; ++i) {
            if (overlap(c->mmio.base, c->mmio.size, c->ram[i].base, c->ram[i].size)) {
                return Z6II_BA2_BUS_BAD_CONFIG;
            }
        }
    }
    b->config = *c;
    b->initialized = true;
    return Z6II_BA2_BUS_OK;
}

static Z6IIBA2BusResult fail(Z6IIBA2Bus *b, Z6IIBA2BusResult r,
                           uint32_t a, unsigned n, bool write, bool fetch)
{
    if (b) { b->fault = (Z6IIBA2BusFault){ r, a, n, write, fetch }; }
    return r;
}
static bool contains(uint32_t base, size_t bytes, uint32_t a, unsigned n)
{
    return a >= base && (uint64_t)a - base <= bytes &&
           n <= bytes - ((uint64_t)a - base);
}
static const Z6IIBA2MemoryMap *map(const Z6IIBA2Bus *b, uint32_t a, unsigned n)
{
    unsigned i;
    if (contains(b->config.payload.base, b->config.payload.size, a, n)) {
        return &b->config.payload;
    }
    for (i = 0; i < b->config.ram_count; ++i) {
        if (contains(b->config.ram[i].base, b->config.ram[i].size, a, n)) {
            return &b->config.ram[i];
        }
    }
    return NULL;
}
static Z6IIBA2BusResult guard(Z6IIBA2Bus *b, uint32_t a, unsigned n,
                            bool write, bool fetch)
{
    if (!b || !b->initialized) {
        return fail(b, Z6II_BA2_BUS_BAD_CONFIG, a, n, write, fetch);
    }
    if (fetch ? (!n || n > 6) : (n != 1 && n != 2 && n != 4)) {
        return fail(b, Z6II_BA2_BUS_BAD_WIDTH, a, n, write, fetch);
    }
    if ((uint64_t)a + n > UINT64_C(0x100000000)) {
        return fail(b, Z6II_BA2_BUS_UNMAPPED, a, n, write, fetch);
    }
    if (!fetch && !b->config.allow_unaligned_data && (a & (n - 1))) {
        return fail(b, Z6II_BA2_BUS_BAD_ALIGNMENT, a, n, write, fetch);
    }
    return Z6II_BA2_BUS_OK;
}

Z6IIBA2BusResult z6ii_ba2_bus_fetch(void *opaque, uint32_t a, uint8_t *out, unsigned n)
{
    Z6IIBA2Bus *b = opaque;
    Z6IIBA2BusResult r = guard(b, a, n, false, true);
    const Z6IIBA2MemoryMap *m;
    if (r != Z6II_BA2_BUS_OK) { return r; }
    if (!out) { return fail(b, Z6II_BA2_BUS_BAD_CONFIG, a, n, false, true); }
    m = map(b, a, n);
    if (!m) { return fail(b, Z6II_BA2_BUS_UNMAPPED, a, n, false, true); }
    if (!(m->permissions & Z6II_BA2_MEM_EXEC)) {
        return fail(b, Z6II_BA2_BUS_PERMISSION, a, n, false, true);
    }
    memcpy(out, m->bytes + (a - m->base), n);
    return Z6II_BA2_BUS_OK;
}

Z6IIBA2BusResult z6ii_ba2_bus_read(void *opaque, uint32_t a, unsigned n, uint32_t *out)
{
    Z6IIBA2Bus *b = opaque;
    Z6IIBA2BusResult r = guard(b, a, n, false, false);
    const Z6IIBA2MemoryMap *m;
    uint32_t value = 0;
    unsigned i;
    if (r != Z6II_BA2_BUS_OK) { return r; }
    if (!out) { return fail(b, Z6II_BA2_BUS_BAD_CONFIG, a, n, false, false); }
    m = map(b, a, n);
    if (m) {
        if (!(m->permissions & Z6II_BA2_MEM_READ)) {
            return fail(b, Z6II_BA2_BUS_PERMISSION, a, n, false, false);
        }
        for (i = 0; i < n; ++i) {
            unsigned shift = b->config.data_endian == Z6II_BA2_DATA_LE ? i * 8 : (n - i - 1) * 8;
            value |= (uint32_t)m->bytes[a - m->base + i] << shift;
        }
    } else if (b->config.mmio.size && contains(b->config.mmio.base, b->config.mmio.size, a, n)) {
        if (!b->config.mmio.read) { return fail(b, Z6II_BA2_BUS_PERMISSION, a, n, false, false); }
        r = b->config.mmio.read(b->config.mmio.opaque, a, n, &value);
        if (r != Z6II_BA2_BUS_OK) { return fail(b, r, a, n, false, false); }
    } else { return fail(b, Z6II_BA2_BUS_UNMAPPED, a, n, false, false); }
    *out = value;
    return Z6II_BA2_BUS_OK;
}

Z6IIBA2BusResult z6ii_ba2_bus_write(void *opaque, uint32_t a, unsigned n, uint32_t value)
{
    Z6IIBA2Bus *b = opaque;
    Z6IIBA2BusResult r = guard(b, a, n, true, false);
    const Z6IIBA2MemoryMap *m;
    unsigned i;
    if (r != Z6II_BA2_BUS_OK) { return r; }
    m = map(b, a, n);
    if (m) {
        if (!(m->permissions & Z6II_BA2_MEM_WRITE)) {
            return fail(b, Z6II_BA2_BUS_PERMISSION, a, n, true, false);
        }
        for (i = 0; i < n; ++i) {
            unsigned shift = b->config.data_endian == Z6II_BA2_DATA_LE ? i * 8 : (n - i - 1) * 8;
            m->writable_bytes[a - m->base + i] = value >> shift;
        }
    } else if (b->config.mmio.size && contains(b->config.mmio.base, b->config.mmio.size, a, n)) {
        if (!b->config.mmio.write) { return fail(b, Z6II_BA2_BUS_PERMISSION, a, n, true, false); }
        r = b->config.mmio.write(b->config.mmio.opaque, a, n, value);
        if (r != Z6II_BA2_BUS_OK) { return fail(b, r, a, n, true, false); }
    } else { return fail(b, Z6II_BA2_BUS_UNMAPPED, a, n, true, false); }
    return Z6II_BA2_BUS_OK;
}

bool z6ii_ba2_bus_irq(void *opaque)
{
    const Z6IIBA2Bus *b = opaque;
    return b && b->initialized && b->config.mmio.size && b->config.mmio.peer_irq &&
           b->config.mmio.peer_irq(b->config.mmio.opaque);
}
Z6IIIPU2402Result z6ii_ba2_bus_take_tx(Z6IIBA2Bus *b, uint32_t frame[3])
{
    Z6IIIPU2402Result r;
    if (!b || !b->initialized || !b->config.master_fifo) { return Z6II_IPU2402_BAD_ACCESS; }
    r = z6ii_ipu2402_peer_take_tx(b->config.master_fifo, frame);
    if (r == Z6II_IPU2402_OK && b->config.master_irq_update) {
        b->config.master_irq_update(b->config.master_irq_opaque);
    }
    return r;
}
Z6IIIPU2402Result z6ii_ba2_bus_push_rx(Z6IIBA2Bus *b, const uint32_t frame[3])
{
    Z6IIIPU2402Result r;
    if (!b || !b->initialized || !b->config.master_fifo) { return Z6II_IPU2402_BAD_ACCESS; }
    r = z6ii_ipu2402_peer_push_rx(b->config.master_fifo, frame, 3);
    if (r == Z6II_IPU2402_OK && b->config.master_irq_update) {
        b->config.master_irq_update(b->config.master_irq_opaque);
    }
    return r;
}
