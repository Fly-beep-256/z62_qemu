/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "ba2-engine140.h"
#include "ba2-startup-bridge137.h"
#include "ba2-window98.h"
#include <string.h>

bool z6ii_ba2_engine140_invariant(const Z6IIBA2Engine140 *s)
{
    /* Do not recurse through bridge137_invariant: that also checks this state. */
    return s && s->initialized && s->bus && s->bus->initialized &&
        s->bridge && s->bridge->initialized && s->bridge->engine == s &&
        s->basis && *s->basis && !(s->raw & ~Z6II_BA2_ENGINE140_DONE) &&
        s->last_reject <= Z6II_BA2_ENGINE140_REJECT_ALIAS &&
        (s->opaque_policy ?
         (!strcmp(s->opaque_policy, Z6II_BA2_ENGINE140_OPAQUE_POLICY) &&
          s->opaque_basis && *s->opaque_basis &&
          s->opaque_bytes == Z6II_BA2_ENGINE140_OPAQUE_BYTES) :
         (!s->opaque_basis && !s->opaque_bytes)) &&
        s->completions <= s->submissions && s->rejected <= s->submissions;
}

Z6IIBA2BusResult z6ii_ba2_engine140_init(Z6IIBA2Engine140 *s,
    Z6IIBA2Bus *bus, Z6IIBA2StartupBridge137 *bridge, const char *basis)
{
    if (!s || !bus || !bus->initialized ||
        !z6ii_ba2_startup_bridge137_invariant(bridge) || bridge->engine ||
        !bridge->transaction_config_basis || !basis || !*basis) {
        return Z6II_BA2_BUS_BAD_CONFIG;
    }
    *s = (Z6IIBA2Engine140) {
        .bus = bus, .bridge = bridge, .basis = basis, .initialized = true
    };
    bridge->engine = s;
    return Z6II_BA2_BUS_OK;
}

Z6IIBA2BusResult z6ii_ba2_engine140_enable_opaque_synthetic(
    Z6IIBA2Engine140 *s, const char *policy, uint32_t bytes, const char *basis)
{
    if (!z6ii_ba2_engine140_invariant(s) || !policy ||
        strcmp(policy, Z6II_BA2_ENGINE140_OPAQUE_POLICY) ||
        bytes != Z6II_BA2_ENGINE140_OPAQUE_BYTES || !basis || !*basis ||
        s->opaque_policy || s->raw) {
        return Z6II_BA2_BUS_BAD_CONFIG;
    }
    s->opaque_policy = policy;
    s->opaque_basis = basis;
    s->opaque_bytes = bytes;
    return Z6II_BA2_BUS_OK;
}

void z6ii_ba2_engine140_reset(Z6IIBA2Engine140 *s)
{
    if (!s || !s->initialized) {
        return;
    }
    s->raw = 0;
    s->last_reject = Z6II_BA2_ENGINE140_REJECT_NONE;
    s->source_cpu = s->destination_cpu = 0;
    ++s->resets;
}

static Z6IIBA2BusResult reject(Z6IIBA2Engine140 *s,
    Z6IIBA2Engine140Reject reason, Z6IIBA2BusResult result)
{
    s->last_reject = reason;
    ++s->rejected;
    return result;
}

/* Resolve only the immutable local ROM source and the complete committed
 * shared-RAM map. No MMIO fallback, private TCB/flag target or persisted span.
 * This is called while the production run_slice binding is held by BQL. */
static Z6IIBA2BusResult opaque_spans(const Z6IIBA2Engine140 *s,
    const uint8_t **source, uint8_t **destination)
{
    const Z6IIBA2BusConfig *b = &s->bus->config;
    const Z6IIBA2MemoryMap *rom = &b->payload;
    const size_t bytes = s->opaque_bytes;
    if (rom->base != UINT32_C(0x40000000) ||
        rom->size != Z6II_BA2_PAYLOAD_BYTES || !rom->bytes ||
        rom->writable_bytes || !rom->mapping_basis || !*rom->mapping_basis ||
        rom->permissions != (Z6II_BA2_MEM_READ | Z6II_BA2_MEM_EXEC) ||
        !b->ram || !b->ram_count || b->ram_count > Z6II_BA2_MAX_RAM_MAPS) {
        return Z6II_BA2_BUS_BAD_CONFIG;
    }
    if (s->source_cpu < rom->base ||
        (uint64_t)s->source_cpu - rom->base > rom->size ||
        bytes > rom->size - ((uint64_t)s->source_cpu - rom->base)) {
        return Z6II_BA2_BUS_UNMAPPED;
    }
    Z6IIBA2Window98Range ranges[2];
    unsigned count = 0;
    Z6IIBA2BusResult r = z6ii_ba2_window98_plan(s->bridge->master,
        Z6II_BA2_PAYLOAD_BYTES, UINT32_C(0x44000), ranges, &count);
    if (r != Z6II_BA2_BUS_OK) {
        return r;
    }
    const Z6IIBA2Window98Range *shared = NULL;
    for (unsigned i = 0; i < count; ++i) {
        if (ranges[i].index == 1) {
            shared = &ranges[i];
        }
    }
    if (!shared || s->destination_cpu < shared->base ||
        (uint64_t)s->destination_cpu - shared->base > shared->size ||
        bytes > shared->size - ((uint64_t)s->destination_cpu - shared->base)) {
        return Z6II_BA2_BUS_UNMAPPED;
    }
    const Z6IIBA2MemoryMap *map = NULL;
    for (unsigned i = 0; i < b->ram_count; ++i) {
        const Z6IIBA2MemoryMap *candidate = &b->ram[i];
        if (candidate->base == shared->base && candidate->size == shared->size) {
            if (map) {
                return Z6II_BA2_BUS_BAD_CONFIG;
            }
            map = candidate;
        }
    }
    if (!map) {
        return Z6II_BA2_BUS_UNMAPPED;
    }
    if ((map->permissions & (Z6II_BA2_MEM_READ | Z6II_BA2_MEM_WRITE)) !=
        (Z6II_BA2_MEM_READ | Z6II_BA2_MEM_WRITE)) {
        return Z6II_BA2_BUS_PERMISSION;
    }
    if (!map->bytes || map->writable_bytes != map->bytes ||
        !map->mapping_basis || !*map->mapping_basis ||
        (map->permissions & ~UINT32_C(7)) ||
        (uint64_t)map->base + map->size > UINT64_C(0x100000000)) {
        return Z6II_BA2_BUS_BAD_CONFIG;
    }
    *source = rom->bytes + (s->source_cpu - rom->base);
    *destination = map->writable_bytes + (s->destination_cpu - map->base);
    return Z6II_BA2_BUS_OK;
}

Z6IIBA2BusResult z6ii_ba2_engine140_submit(Z6IIBA2Engine140 *s, uint32_t value)
{
    if (!z6ii_ba2_engine140_invariant(s)) {
        return Z6II_BA2_BUS_BAD_CONFIG;
    }
    ++s->submissions;
    const Z6IIBA2StartupBridge137 *b = s->bridge;
    if (!z6ii_ba2_startup_bridge137_invariant(b) || b->control != 1 || s->raw) {
        return reject(s, Z6II_BA2_ENGINE140_REJECT_STATE,
                      Z6II_BA2_BUS_DEVICE_FAULT);
    }
    /* Original mode9 uses 25 of the 29 transaction write latches; the four
     * registers 8001000C..18 were not part of this submitted descriptor. */
    const uint32_t required = UINT32_C(0x1fffffe1);
    if ((b->transaction_config_written & required) != required) {
        return reject(s, Z6II_BA2_ENGINE140_REJECT_INCOMPLETE,
                      Z6II_BA2_BUS_DEVICE_FAULT);
    }
    const uint32_t *c = b->transaction_config;
    if (value != UINT32_C(0x19) || c[13] != 9) {
        return reject(s, Z6II_BA2_ENGINE140_REJECT_MODE,
                      Z6II_BA2_BUS_DEVICE_FAULT);
    }
    const uint32_t expected[29] = {
        1, 0, 0, 0, 0, 1, 1, 6, UINT32_C(0x00400040),
        UINT32_C(0x40004000), UINT32_C(0x000c0400), 1, 0, 9,
        UINT32_C(0x03ff0000), UINT32_C(0x000b0000),
        UINT32_C(0xc0c28d60), 0, 0, UINT32_C(0x400), 0, 0,
        UINT32_C(0xc0802000), 0, 0, 0, 0, 0, 1
    };
    for (unsigned i = 0; i < 29; ++i) {
        if ((required & (UINT32_C(1) << i)) && c[i] != expected[i]) {
            return reject(s, Z6II_BA2_ENGINE140_REJECT_DESCRIPTOR,
                          Z6II_BA2_BUS_DEVICE_FAULT);
        }
    }
    /* These two actual address translations are evidenced at 40009908..2F
     * and 40009C39. No generic folding of C0xxxxxxxx addresses is permitted. */
    const Z6IIIPU2402 *master = b->master;
    if (!master->window_valid || !master->window_commits ||
        master->window_active[0] != UINT32_C(0x80c00000) ||
        master->window_active[1] != UINT32_C(0x00400000) ||
        master->window_active[2] != UINT32_C(0x5ef00000) ||
        master->window_active[3] != UINT32_C(0x01d00000)) {
        return reject(s, Z6II_BA2_ENGINE140_REJECT_WINDOW,
                      Z6II_BA2_BUS_UNMAPPED);
    }
    /* Only values are kept; payload/RAM pointers must be resolved within
     * this call after byte extents are established by a supported format. */
    s->source_cpu = UINT32_C(0x40028d60);
    s->destination_cpu = UINT32_C(0x61902000);
    if (!s->opaque_policy) {
        return reject(s, Z6II_BA2_ENGINE140_REJECT_FORMAT,
                      Z6II_BA2_BUS_DEVICE_FAULT);
    }
    const uint8_t *source = NULL;
    uint8_t *destination = NULL;
    Z6IIBA2BusResult r = opaque_spans(s, &source, &destination);
    if (r != Z6II_BA2_BUS_OK) {
        return reject(s, Z6II_BA2_ENGINE140_REJECT_SPAN, r);
    }
    const uintptr_t a = (uintptr_t)source, z = (uintptr_t)destination;
    const size_t bytes = s->opaque_bytes;
    if (a > UINTPTR_MAX - bytes || z > UINTPTR_MAX - bytes ||
        (a < z + bytes && z < a + bytes)) {
        return reject(s, Z6II_BA2_ENGINE140_REJECT_ALIAS,
                      Z6II_BA2_BUS_BAD_CONFIG);
    }
    /* The explicitly declared synthetic policy is a real opaque byte copy.
     * All checks precede the first write; there is no fallible post-copy step.
     * Completion follows the data commit, never merely start or elapsed time. */
    memcpy(destination, source, bytes);
    s->transferred_bytes += bytes;
    ++s->completions;
    s->last_reject = Z6II_BA2_ENGINE140_REJECT_NONE;
    s->raw |= Z6II_BA2_ENGINE140_DONE;
    return Z6II_BA2_BUS_OK;
}

Z6IIBA2BusResult z6ii_ba2_engine140_read_raw(Z6IIBA2Engine140 *s, uint32_t *out)
{
    if (!out || !z6ii_ba2_engine140_invariant(s)) {
        return Z6II_BA2_BUS_BAD_CONFIG;
    }
    *out = s->raw;
    ++s->raw_reads;
    return Z6II_BA2_BUS_OK;
}

Z6IIBA2BusResult z6ii_ba2_engine140_ack(Z6IIBA2Engine140 *s, uint32_t value)
{
    if (!z6ii_ba2_engine140_invariant(s)) {
        return Z6II_BA2_BUS_BAD_CONFIG;
    }
    ++s->w1c_writes;
    if (value & s->raw & Z6II_BA2_ENGINE140_DONE) {
        s->raw &= ~Z6II_BA2_ENGINE140_DONE;
        ++s->completed_acks;
    }
    return Z6II_BA2_BUS_OK;
}

bool z6ii_ba2_engine140_level(const Z6IIBA2Engine140 *s)
{
    return z6ii_ba2_engine140_invariant(s) &&
        (s->bridge->config_written & (UINT32_C(1) << 3)) &&
        (s->raw & s->bridge->config[3] & Z6II_BA2_ENGINE140_DONE);
}
