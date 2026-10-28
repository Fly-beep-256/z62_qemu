/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Fixed-PC source50 observer; host trace storage only, no guest interventions. */
#ifndef Z6II_S50_STANDALONE_TEST
#include "z6ii-source50-observer.h"
#ifndef CONFIG_USER_ONLY
#include "exec/icount.h"
#include "exec/translation-block.h"
#include "qemu/atomic.h"
#include "qemu/bswap.h"
#include "system/address-spaces.h"
#include "system/memory.h"
#include "hw/arm/nikon-z6ii-engine.h"
#endif
#endif

#ifndef CONFIG_USER_ONLY
#define Z6II_S50_TRACE_CAPACITY 4096

typedef struct Z6IIS50TraceRecord {
    uint64_t index;
    uint32_t core, global_core, pc, opcode, site;
    uint32_t regs[15];
    uint64_t tb_pc;
    uint32_t tb_icount, tb_cflags, insn_index;
    ICountInstructionTime clock;
    uint32_t clock_valid;
    uint32_t ram_words[6], ram_valid_mask;
    uint32_t ready;
} Z6IIS50TraceRecord;

typedef struct Z6IIS50State {
    Z6IIEngineContext *engine;
    Z6IIS50TraceRecord *records;
    uint64_t attempts;
    gsize initialized;
    bool enabled;
    char *output;
    const char *role;
} Z6IIS50State;

static Z6IIS50State z6ii_s50_states[2];

static const uint32_t z6ii_s50_ram_addresses[6] = {
    0xc1864ce8, /* upper callback slot: PHYSICAL ordinary RAM view only */
    0xc20a4248, /* source50 callback[0] */
    0xc20a4270, /* source50 completion mask, +0x28 */
    0xc20a4274, /* low u16: source50 callback count, +0x2c */
    0xc237a788, 0xc237a78c, /* pending getter fields */
};

/* memory_region_find does a flatview lookup and takes an ownership reference.
 * It does NOT follow an IOMMU, call a MemoryRegionOps handler, or load CPU VAs.
 * Those host refs are balanced; no CPU, RAM, timer, or MMIO state is written. */
static bool z6ii_s50_peek_physical_ram_u32(Z6IIS50State *state, uint32_t address, uint32_t *word)
{
    MemoryRegionSection section = memory_region_find(state->engine->memory,
                                                     address, 4);
    bool valid = false;
    if (section.mr) {
        if (section.offset_within_address_space == address &&
            int128_ge(section.size, int128_make64(4)) &&
            memory_region_is_ram(section.mr) &&
            !memory_region_is_ram_device(section.mr) &&
            !memory_region_is_rom(section.mr) && !section.readonly &&
            memory_region_size(section.mr) >= 4 &&
            section.offset_within_region <= memory_region_size(section.mr) - 4) {
            const uint8_t *bytes = memory_region_get_ram_ptr(section.mr);
            *word = ldl_le_p(bytes + section.offset_within_region);
            valid = true;
        }
        memory_region_unref(section.mr);
    }
    return valid;
}

/* File I/O only on normal process exit; the per-instruction helper buffers. */
static void z6ii_s50_flush(Z6IIS50State *state)
{
    if (!state->enabled) {
        return;
    }
    FILE *out = stderr;
    if (state->output && *state->output) {
        out = fopen(state->output, "wx");
        if (!out) {
            fprintf(stderr, "Z6II_S50_TRACE_OUTPUT_ERROR errno=%d retained=0\n",
                    errno);
            return;
        }
    }
    uint64_t attempts = qatomic_read(&state->attempts);
    uint64_t limit = MIN(attempts, Z6II_S50_TRACE_CAPACITY);
    unsigned written = 0, incomplete = 0;
    fprintf(out, "Z6II_S50_TRACE schema=1 role=%s capacity=%u "
            "physical_RAM_peek=1 guest_VA_translation=0 "
            "instruction_bytes_changed=0 peer_clocks_synchronized=%u\n",
            state->role, Z6II_S50_TRACE_CAPACITY, state->engine->unified);
    for (uint64_t index = 0; index < limit; index++) {
        const Z6IIS50TraceRecord *r = &state->records[index];
        if (!qatomic_load_acquire(&r->ready)) {
            incomplete++;
            continue;
        }
        fprintf(out, "Z6II_S50_OBS role=%s index=%" PRIu64
                " core=%u global_core=%u pc=%08x opcode=%08x site=%s "
                "tb_pc=%" PRIx64 " tb_icount=%u tb_cflags=%08x "
                "insn_index=%u clock_valid=%u virtual_ns_before=%" PRId64
                " virtual_ns=%" PRId64 " raw_global=%" PRId64
                " raw_uncommitted=%" PRId64 " raw_before=%" PRId64
                " raw_inclusive=%" PRId64 " bias=%" PRId64 " shift=%d "
                "ram_valid_mask=%02x slot_physical=c1864ce8 slot_word=%08x "
                "source50_callback0=%08x source50_mask=%08x "
                "source50_count_word=%08x pending788=%08x pending78c=%08x",
                state->role, r->index, r->core, r->global_core, r->pc, r->opcode,
                z6ii_s50_site_name(r->site), r->tb_pc, r->tb_icount,
                r->tb_cflags, r->insn_index, r->clock_valid,
                r->clock.virtual_ns_before, r->clock.virtual_ns_inclusive,
                r->clock.raw_global, r->clock.raw_uncommitted,
                r->clock.raw_before, r->clock.raw_inclusive,
                r->clock.bias, r->clock.shift,
                r->ram_valid_mask, r->ram_words[0], r->ram_words[1],
                r->ram_words[2], r->ram_words[3],
                r->ram_words[4], r->ram_words[5]);
        for (unsigned reg = 0; reg < 15; reg++) {
            fprintf(out, " r%u=%08x", reg, r->regs[reg]);
        }
        fputc('\n', out);
        written++;
    }
    fprintf(out, "Z6II_S50_TRACE_END attempts=%" PRIu64
            " written=%u overflow=%" PRIu64 " incomplete=%u "
            "index_is_observer_reservation_order=1 global_causality_verified=0\n",
            attempts, written, attempts - limit, incomplete);
    if (out != stderr) {
        fclose(out);
    }
}

static void z6ii_s50_flush_all(void)
{
    for (unsigned i = 0; i < ARRAY_SIZE(z6ii_s50_states); i++) {
        if (z6ii_s50_states[i].engine) { z6ii_s50_flush(&z6ii_s50_states[i]); }
    }
}

static Z6IIS50State *z6ii_s50_state(Z6IIEngineContext *engine)
{
    if (!engine) { return NULL; }
    unsigned slot;
    if (!strcmp(engine->role, "master")) { slot = 0; }
    else if (!strcmp(engine->role, "slave")) { slot = 1; }
    else { return NULL; }
    Z6IIS50State *state = &z6ii_s50_states[slot];
    assert(!state->engine || state->engine == engine);
    state->engine = engine;
    state->role = engine->role;
    if (g_once_init_enter(&state->initialized)) {
        const char *enabled = z6ii_engine_getenv(engine, "Z6II_SOURCE50_TCG_TRACE");
        const char *path = z6ii_engine_getenv(engine, "Z6II_SOURCE50_TCG_TRACE_OUT");
        state->enabled = enabled && !strcmp(enabled, "1");
        if (state->enabled) {
            state->output = path ? g_strdup(path) : NULL;
            state->records = g_new0(Z6IIS50TraceRecord, Z6II_S50_TRACE_CAPACITY);
        }
        g_once_init_leave(&state->initialized, 1);
    }
    static gsize exit_registered;
    if (g_once_init_enter(&exit_registered)) {
        int result = atexit(z6ii_s50_flush_all);
        g_once_init_leave(&exit_registered, result ? 2 : 1);
    }
    if (exit_registered != 1) { state->enabled = false; }
    return state;
}

/* Translation instruments the union; execution filters by the CPU owner. */
bool z6ii_s50_observer_enabled(void)
{
    CPUState *cpu;
    CPU_FOREACH(cpu) {
        Z6IIS50State *state = z6ii_s50_state(z6ii_engine_for_cpu(cpu));
        if (state && state->enabled) { return true; }
    }
    return false;
}

void HELPER(z6ii_s50_observe)(CPUARMState *env, uint32_t pc, uint32_t opcode,
                            void *tb_opaque, uint32_t index_one_based)
{
    CPUState *cpu = env_cpu(env);
    Z6IIS50State *state = z6ii_s50_state(z6ii_engine_for_cpu(cpu));
    unsigned site = z6ii_s50_site_id(pc, opcode);
    if (!site || !state || !state->enabled || arm_feature(env, ARM_FEATURE_M)) {
        return;
    }
    uint64_t index = qatomic_fetch_inc(&state->attempts);
    if (index >= Z6II_S50_TRACE_CAPACITY) {
        return;
    }
    const TranslationBlock *tb = tb_opaque;
    Z6IIS50TraceRecord *r = &state->records[index];
    r->index = index;
    r->global_core = cpu->cpu_index;
    r->core = cpu->cpu_index - state->engine->cpu_base;
    r->pc = pc;
    r->opcode = opcode;
    r->site = site;
    /* TCG_CALL_NO_WG saves globals before this call; current regs0..14 are
     * read in their canonical env fields, and never written back by us. */
    for (unsigned reg = 0; reg < 15; reg++) {
        r->regs[reg] = env->regs[reg];
    }
    r->tb_pc = tb ? tb->pc : 0;
    r->tb_icount = tb ? tb->icount : 0;
    r->tb_cflags = tb ? tb_cflags(tb) : 0;
    r->insn_index = index_one_based;
    r->clock.virtual_ns_before = -1;
    r->clock.virtual_ns_inclusive = -1;
    r->clock.shift = -1;
    if (tb && (r->tb_cflags & CF_USE_ICOUNT)) {
        r->clock_valid = icount_read_only_instruction_time(cpu, tb->icount,
                                                          index_one_based,
                                                          &r->clock);
    }
    for (unsigned word = 0; word < ARRAY_SIZE(z6ii_s50_ram_addresses); word++) {
        if (z6ii_s50_peek_physical_ram_u32(state, z6ii_s50_ram_addresses[word],
                                         &r->ram_words[word])) {
            r->ram_valid_mask |= 1u << word;
        }
    }
    qatomic_store_release(&r->ready, 1);
}
#else
bool z6ii_s50_observer_enabled(void)
{
    return false;
}

void HELPER(z6ii_s50_observe)(CPUARMState *env, uint32_t pc, uint32_t opcode,
                            void *tb_opaque, uint32_t index_one_based)
{
    /* User-mode builds carry an inert helper; no system RAM or clock API. */
    (void)env;
    (void)pc;
    (void)opcode;
    (void)tb_opaque;
    (void)index_one_based;
}
#endif
