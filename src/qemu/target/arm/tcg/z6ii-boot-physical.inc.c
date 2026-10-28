/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Physical observations of the original DMA job. Never issue a bus/CPU load,
 * alter a job, expand a RAM whitelist, or manufacture peer readiness. */
#define Z6II_BOOT_COPY_CAPACITY 64
#define Z6II_BOOT_ORIGINAL_ROM_BYTES UINT32_C(38750138)
#define Z6II_BOOT_ORIGINAL_ROM_BASE UINT32_C(0x10020000)
#define Z6II_BOOT_ORIGINAL_ROM_SHA \
    "bb83613121f843d65101da936d942acdc513d86dbd3abc26259d0d870d03f5d4"


struct Z6IIBootCopyRecord {
    uint64_t index;
    int64_t now_ns, deadline_ns, buffer_ns, post_ns;
    uint32_t src, dst, length, prefix, channel;
    uint32_t source_valid, before_valid, buffer_valid, after_valid, ready;
    const char *source_reason, *before_reason, *buffer_reason, *after_reason;
    char source_sha[65], before_sha[65], buffer_sha[65], after_sha[65];
};


void z6ii_boot_bind_original_rom(Z6IIEngineContext *engine, struct MemoryRegion *region,
                                  uint32_t loaded_bytes, const char *sha)
{
    Z6IIBootState *state = z6ii_boot_state(engine);
    if (!state || !state->enabled) { return; }

    if (!state->enabled || state->error_only || state->startup_focus || state->saiso_focus || !region || !sha ||
        loaded_bytes != (!strcmp(engine->role, "master") ? Z6II_BOOT_ORIGINAL_ROM_BYTES : UINT32_C(8832194)) ||
        strcmp(sha, !strcmp(engine->role, "master") ? Z6II_BOOT_ORIGINAL_ROM_SHA :
            "3fd8c2cbdf57fadb03f6d69b596b58a8703efdd61ae82572d5afeea0241a9ed5") ||
        !memory_region_is_ram(region) || !memory_region_is_rom(region) ||
        memory_region_is_ram_device(region) ||
        memory_region_size(region) < loaded_bytes) {
        return;
    }
    /* rom_add_blob_fixed populates the region during the loader/reset phase.
     * Bind its actual MR now and hash its populated bytes on the first read. */
    assert(!state->original_rom || state->original_rom == region);
    state->original_rom = region;
    state->original_rom_bytes = loaded_bytes;
    state->original_rom_sha = !strcmp(engine->role, "master") ? Z6II_BOOT_ORIGINAL_ROM_SHA :
        "3fd8c2cbdf57fadb03f6d69b596b58a8703efdd61ae82572d5afeea0241a9ed5";
}

static bool z6ii_boot_rom_identity(Z6IIBootState *state)
{
    if (!state->original_rom) { return false; }
    if (g_once_init_enter(&state->original_rom_checked)) {
        const guchar *bytes = memory_region_get_ram_ptr(state->original_rom);
        g_autofree char *sha = g_compute_checksum_for_data(G_CHECKSUM_SHA256,
            bytes, state->original_rom_bytes);
        state->original_rom_verified = sha &&
            !strcmp(sha, state->original_rom_sha);
        g_once_init_leave(&state->original_rom_checked, 1);
    }
    return state->original_rom_verified;
}

/* One full FlatView section is required, with exact offset/extent checks and
 * balanced section references. ROM is accepted only for the bound original
 * input; it is never enabled for a generic payload or page-table read. */
typedef enum Z6IIBootPhysicalPolicy {
    Z6II_BOOT_ORDINARY_RAM,
    Z6II_BOOT_BOUND_ORIGINAL_ROM,
} Z6IIBootPhysicalPolicy;

static const uint8_t *z6ii_boot_section_pointer(Z6IIBootState *state, uint32_t address, unsigned size,
    Z6IIBootPhysicalPolicy policy, MemoryRegionSection *section,
    const char **reason)
{
    *reason = "unexamined";
    if (!size) { *reason = "zero_length"; return NULL; }
    if (address > UINT32_MAX - (size - 1)) {
        *reason = "address_overflow"; return NULL;
    }
    *section = memory_region_find(state->engine->memory, address, size);
    if (!section->mr) { *reason = "missing_MemoryRegion"; return NULL; }
    if (section->offset_within_address_space != address ||
        !int128_ge(section->size, int128_make64(size))) {
        *reason = "FlatView_span_crossing"; return NULL;
    }
    uint64_t extent = memory_region_size(section->mr);
    if (extent < size || section->offset_within_region > extent - size) {
        *reason = "MemoryRegion_bounds"; return NULL;
    }
    if (!memory_region_is_ram(section->mr)) {
        *reason = "not_RAM_backed"; return NULL;
    }
    if (memory_region_is_ram_device(section->mr)) {
        *reason = "RAM_device_rejected"; return NULL;
    }
    if (policy == Z6II_BOOT_BOUND_ORIGINAL_ROM) {
        if (section->mr != state->original_rom) {
            *reason = "not_bound_original_ROM"; return NULL;
        }
        if (!memory_region_is_rom(section->mr)) {
            *reason = "bound_region_not_ROM"; return NULL;
        }
        if (address < Z6II_BOOT_ORIGINAL_ROM_BASE ||
            (uint64_t)address + size > (uint64_t)Z6II_BOOT_ORIGINAL_ROM_BASE +
                                      state->original_rom_bytes ||
            section->offset_within_region != address - Z6II_BOOT_ORIGINAL_ROM_BASE) {
            *reason = "outside_original_ROM_payload"; return NULL;
        }
        if (!z6ii_boot_rom_identity(state)) {
            *reason = "original_ROM_identity_failed"; return NULL;
        }
    } else {
        if (memory_region_is_rom(section->mr)) {
            *reason = "ROM_rejected_for_ordinary_payload"; return NULL;
        }
        if (section->readonly) {
            *reason = "readonly_RAM_rejected"; return NULL;
        }
    }
    *reason = "accepted";
    return (const uint8_t *)memory_region_get_ram_ptr(section->mr) +
           section->offset_within_region;
}

static bool z6ii_boot_original_rom_bytes(Z6IIBootState *state, uint32_t address, void *out, unsigned size,
                                         const char **reason)
{
    MemoryRegionSection section = {0};
    const uint8_t *bytes = z6ii_boot_section_pointer(state, address, size,
        Z6II_BOOT_BOUND_ORIGINAL_ROM, &section, reason);
    bool valid = bytes != NULL;
    if (valid) { memcpy(out, bytes, size); }
    if (section.mr) { memory_region_unref(section.mr); }
    return valid;
}

static bool z6ii_boot_physical_sha(Z6IIBootState *state, uint32_t address, unsigned size,
    Z6IIBootPhysicalPolicy policy, char out[65], const char **reason)
{
    MemoryRegionSection section = {0};
    const uint8_t *bytes = z6ii_boot_section_pointer(state, address, size,
                                                   policy, &section, reason);
    if (bytes) {
        g_autofree char *sha = g_compute_checksum_for_data(G_CHECKSUM_SHA256,
                                                           bytes, size);
        memcpy(out, sha, 65);
    }
    if (section.mr) { memory_region_unref(section.mr); }
    return bytes != NULL;
}

uint32_t z6ii_boot_copy_pre_observe(Z6IIEngineContext *engine, bool recovery, unsigned channel,
    bool pending, int64_t deadline, int64_t now, uint32_t source,
    uint32_t destination, uint32_t length, unsigned prefix)
{
    Z6IIBootState *state = z6ii_boot_state(engine);
    if (!state || !state->enabled) { return 0; }

    if (!state->enabled || state->error_only || state->startup_focus || state->saiso_focus || !recovery || channel != 0 || !pending ||
        deadline > now || source != UINT32_C(0x107a99f4) ||
        destination != UINT32_C(0xc0c00000) || length != UINT32_C(0x3b1c0) ||
        prefix != 0) {
        return 0;
    }
    uint64_t index = qatomic_fetch_inc(&state->copy_attempts);
    if (index >= Z6II_BOOT_COPY_CAPACITY) { return 0; }
    Z6IIBootCopyRecord *r = &state->copy[index];
    r->index = index;
    r->src = source; r->dst = destination; r->length = length;
    r->channel = channel; r->prefix = prefix;
    r->now_ns = now; r->deadline_ns = deadline;
    r->source_reason = r->before_reason = r->buffer_reason = r->after_reason =
        "not_observed";
    r->source_valid = z6ii_boot_physical_sha(state, source, length,
        Z6II_BOOT_BOUND_ORIGINAL_ROM, r->source_sha, &r->source_reason);
    r->before_valid = z6ii_boot_physical_sha(state, destination, length,
        Z6II_BOOT_ORDINARY_RAM, r->before_sha, &r->before_reason);
    return index + 1;
}

void z6ii_boot_copy_buffer_observe(Z6IIEngineContext *engine, uint32_t token, const uint8_t *buffer,
                                    uint32_t length, int64_t now)
{
    Z6IIBootState *state = z6ii_boot_state(engine);
    if (!state || !state->enabled) { return; }

    if (!token || token > Z6II_BOOT_COPY_CAPACITY) { return; }
    Z6IIBootCopyRecord *r = &state->copy[token - 1];
    if (qatomic_read(&r->ready) || r->buffer_valid) { return; }
    if (!buffer || length != r->length) {
        r->buffer_reason = buffer ? "buffer_length_mismatch" : "missing_buffer";
        return;
    }
    g_autofree char *sha = g_compute_checksum_for_data(G_CHECKSUM_SHA256,
                                                       buffer, length);
    memcpy(r->buffer_sha, sha, 65);
    r->buffer_valid = 1;
    r->buffer_reason = "accepted_before_destination_write";
    r->buffer_ns = now;
}

void z6ii_boot_copy_destination_post_observe(Z6IIEngineContext *engine, uint32_t token, uint32_t length,
                                               int64_t now)
{
    Z6IIBootState *state = z6ii_boot_state(engine);
    if (!state || !state->enabled) { return; }

    if (!token || token > Z6II_BOOT_COPY_CAPACITY) { return; }
    Z6IIBootCopyRecord *r = &state->copy[token - 1];
    if (qatomic_read(&r->ready)) { return; }
    if (length != r->length) {
        r->after_reason = "destination_length_mismatch";
    } else {
        r->after_valid = z6ii_boot_physical_sha(state, r->dst, length,
            Z6II_BOOT_ORDINARY_RAM, r->after_sha, &r->after_reason);
    }
    r->post_ns = now;
    qatomic_store_release(&r->ready, 1);
}

static void z6ii_boot_copy_flush(Z6IIBootState *state, FILE *out)
{
    uint64_t attempts = qatomic_read(&state->copy_attempts);
    uint64_t limit = MIN(attempts, Z6II_BOOT_COPY_CAPACITY);
    unsigned written = 0, incomplete = 0;
    for (uint64_t i = 0; i < limit; ++i) {
        Z6IIBootCopyRecord *r = &state->copy[i];
        if (!qatomic_load_acquire(&r->ready)) { ++incomplete; continue; }
        fprintf(out, "Z6II_COPY_PROOF role=%s index=%" PRIu64
            " core=4294967295 global_core=4294967295 clock=QEMU_CLOCK_VIRTUAL channel=%u src=%08x dst=%08x length=%u prefix=%u"
            " pre_ns=%" PRId64 " deadline_ns=%" PRId64
            " buffer_ns=%" PRId64 " post_ns=%" PRId64
            " source_valid=%u destination_pre_valid=%u buffer_valid=%u"
            " destination_post_valid=%u source_reason=%s"
            " destination_pre_reason=%s buffer_reason=%s"
            " destination_post_reason=%s source_sha256=%s"
            " destination_pre_sha256=%s buffer_sha256=%s"
            " destination_post_sha256=%s original_ROM_verified=%u"
            " source_requires_bound_ROM=1 buffer_before_destination_write=1"
            " guest_writes=0 no_MMIO_reads=1 same_job_token=1\n",
            state->role, r->index, r->channel, r->src, r->dst, r->length,
            r->prefix, r->now_ns, r->deadline_ns, r->buffer_ns, r->post_ns,
            r->source_valid, r->before_valid, r->buffer_valid, r->after_valid,
            r->source_reason, r->before_reason, r->buffer_reason, r->after_reason,
            r->source_valid ? r->source_sha : "-",
            r->before_valid ? r->before_sha : "-",
            r->buffer_valid ? r->buffer_sha : "-",
            r->after_valid ? r->after_sha : "-", state->original_rom_verified);
        ++written;
    }
    fprintf(out, "Z6II_COPY_TRACE_END capacity=%u attempts=%" PRIu64
        " written=%u overflow=%" PRIu64 " incomplete=%u guest_writes=0\n",
        Z6II_BOOT_COPY_CAPACITY, attempts, written, attempts - limit, incomplete);
}
