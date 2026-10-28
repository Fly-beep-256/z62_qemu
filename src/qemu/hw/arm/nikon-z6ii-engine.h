/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef NIKON_Z6II_ENGINE_H
#define NIKON_Z6II_ENGINE_H

#include "hw/core/cpu.h"
#include "system/memory.h"

/* One EXPEED owns its CPU cluster, memory and configuration. All engines
 * use QEMU_CLOCK_VIRTUAL; their local peripheral frequencies stay separate. */
typedef struct Z6IIEngineContext {
    const char *role;
    bool unified;
    unsigned cpu_base, cpu_count;
    Object *cpu_parent;
    MemoryRegion *memory, *rom;
    AddressSpace as;
    GHashTable *options;
    /* Unified machine-owned backing objects. Guest apertures alias the same
     * RAMBlock, so writes and TCG invalidation have one owner. */
    GHashTable *shared_backings;
    GPtrArray *shared_apertures;
    struct MCUWireBus *wire_bus;
    char *wire_path;
    void *board;
    bool capseq_gpio_trace_initialized;
    uint64_t capseq_gpio_trace_attempts, capseq_gpio_trace_written;
    uint64_t capseq_gpio_trace_incomplete;
} Z6IIEngineContext;

Z6IIEngineContext *z6ii_engine_for_cpu(CPUState *cpu);
Z6IIEngineContext *z6ii_engine_new(const char *role, bool unified,
                                  unsigned cpu_base, unsigned cpu_count,
                                  MemoryRegion *memory);
const char *z6ii_engine_getenv(Z6IIEngineContext *engine, const char *name);
void z6ii_engine_shared_ram(Z6IIEngineContext *engine, MemoryRegion *region,
                            const char *name, uint64_t bytes, int owned_fd,
                            uint64_t offset);
QList *z6ii_engine_shared_aperture_state(Z6IIEngineContext *engine);

static inline MemTxResult z6ii_engine_read(Z6IIEngineContext *engine, hwaddr addr,
                                    void *buffer, hwaddr bytes)
{
    return address_space_read(&engine->as, addr, MEMTXATTRS_UNSPECIFIED, buffer, bytes);
}

static inline MemTxResult z6ii_engine_write(Z6IIEngineContext *engine, hwaddr addr,
                                     const void *buffer, hwaddr bytes)
{
    return address_space_write(&engine->as, addr, MEMTXATTRS_UNSPECIFIED, buffer, bytes);
}

#endif
