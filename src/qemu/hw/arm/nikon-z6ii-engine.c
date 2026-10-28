/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qobject/qdict.h"
#include "qobject/qlist.h"
#include "nikon-z6ii-engine.h"

/* Machine-lifetime contexts; configuration is immutable after construction. */
static GSList *z6ii_engines;

Z6IIEngineContext *z6ii_engine_new(const char *role, bool unified,
                                  unsigned cpu_base, unsigned cpu_count,
                                  MemoryRegion *memory)
{
    Z6IIEngineContext *engine = g_new0(Z6IIEngineContext, 1);
    engine->role = role;
    engine->unified = unified;
    engine->cpu_base = cpu_base;
    engine->cpu_count = cpu_count;
    engine->memory = memory;
    engine->options = g_hash_table_new_full(g_str_hash, g_str_equal,
                                           g_free, g_free);
    engine->shared_apertures = g_ptr_array_new();
    g_autofree char *upper = g_ascii_strup(role, -1);
    g_autofree char *prefix = g_strdup_printf("Z62_%s_", upper);
    size_t prefix_length = strlen(prefix);
    g_auto(GStrv) names = g_listenv();
    for (unsigned i = 0; names[i]; i++) {
        const char *key = names[i];
        if (unified) {
            if (!g_str_has_prefix(key, prefix)) { continue; }
            key += prefix_length;
        }
        g_hash_table_insert(engine->options, g_strdup(key),
                             g_strdup(g_getenv(names[i])));
    }
    g_autofree char *name = g_strdup_printf("z6ii-%s-address-space", role);
    address_space_init(&engine->as, memory, name);
    z6ii_engines = g_slist_append(z6ii_engines, engine);
    return engine;
}

Z6IIEngineContext *z6ii_engine_for_cpu(CPUState *cpu)
{
    if (!cpu) { return NULL; }
    for (GSList *item = z6ii_engines; item; item = item->next) {
        Z6IIEngineContext *engine = item->data;
        if (cpu->cpu_index >= engine->cpu_base &&
            cpu->cpu_index < engine->cpu_base + engine->cpu_count) {
            return engine;
        }
    }
    /* In particular, the Cortex-M4 has no EXPEED observer/configuration. */
    return NULL;
}

const char *z6ii_engine_getenv(Z6IIEngineContext *engine, const char *name)
{
    return engine ? g_hash_table_lookup(engine->options, name) : NULL;
}

typedef struct Z6IISharedBacking {
    MemoryRegion ram;
    uint64_t bytes;
} Z6IISharedBacking;

typedef struct Z6IISharedAperture {
    MemoryRegion *region;
    Z6IISharedBacking *backing;
    char *backing_id;
    uint64_t offset, bytes;
} Z6IISharedAperture;

void z6ii_engine_shared_ram(Z6IIEngineContext *engine, MemoryRegion *region,
                            const char *name, uint64_t bytes, int owned_fd,
                            uint64_t offset)
{
    if (!engine->unified) {
        memory_region_init_ram_from_fd(region, NULL, name, bytes, RAM_SHARED,
                                        owned_fd, offset, &error_fatal);
        return;
    }
    struct stat info;
    if (!engine->shared_backings || fstat(owned_fd, &info) ||
        !S_ISREG(info.st_mode) || info.st_size <= 0 ||
        offset > (uint64_t)info.st_size ||
        bytes > (uint64_t)info.st_size - offset) {
        error_report("Unified shared RAM has an invalid backing or aperture");
        exit(1);
    }
    g_autofree char *key = g_strdup_printf("%" PRIu64 ":%" PRIu64,
        (uint64_t)info.st_dev, (uint64_t)info.st_ino);
    Z6IISharedBacking *backing = g_hash_table_lookup(engine->shared_backings, key);
    if (!backing) {
        backing = g_new0(Z6IISharedBacking, 1);
        backing->bytes = info.st_size;
        /* One full-file RAMBlock also covers overlapping DMA/CPU views.
         * The file exports run-local observations; it is not a clock or peer. */
        memory_region_init_ram_from_fd(&backing->ram, NULL, name,
            backing->bytes, RAM_SHARED, owned_fd, 0, &error_fatal);
        g_hash_table_insert(engine->shared_backings, g_strdup(key), backing);
    } else {
        close(owned_fd);
        if (backing->bytes != (uint64_t)info.st_size) {
            error_report("Unified backing extent changed during construction");
            exit(1);
        }
    }
    memory_region_init_alias(region, NULL, name, &backing->ram, offset, bytes);
    Z6IISharedAperture *aperture = g_new0(Z6IISharedAperture, 1);
    aperture->region = region;
    aperture->backing = backing;
    aperture->backing_id = g_strdup(key);
    aperture->offset = offset;
    aperture->bytes = bytes;
    g_ptr_array_add(engine->shared_apertures, aperture);
    fprintf(stderr, "Z62_UNIFIED_RAM_APERTURE role=%s name=%s backing=%s "
            "offset=%" PRIx64 " bytes=%" PRIx64 " single_RAMBlock=1 "
            "host_payload_copy=0 physical_cache_coherence_verified=0\n",
            engine->role, name, key, offset, bytes);
}

QList *z6ii_engine_shared_aperture_state(Z6IIEngineContext *engine)
{
    QList *list = qlist_new();
    for (unsigned i = 0; i < engine->shared_apertures->len; i++) {
        Z6IISharedAperture *a = g_ptr_array_index(engine->shared_apertures, i);
        QDict *item = qdict_new();
        qdict_put_str(item, "name", memory_region_name(a->region));
        qdict_put_str(item, "ram_backing_id", a->backing_id);
        qdict_put_int(item, "offset", a->offset);
        qdict_put_int(item, "bytes", a->bytes);
        qdict_put_int(item, "backing_bytes", a->backing->bytes);
        qdict_put_int(item, "mapped_address", a->region->addr);
        qdict_put_bool(item, "same_RAMBlock", a->region->alias == &a->backing->ram &&
            memory_region_get_ram_ptr(a->region) ==
                (uint8_t *)memory_region_get_ram_ptr(&a->backing->ram) + a->offset);
        qlist_append(list, item);
    }
    return list;
}
