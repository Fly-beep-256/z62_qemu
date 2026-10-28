/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Bounded, default-off original-code and MMIO evidence. No guest writes. */
#ifndef Z6II_BOOT_STANDALONE_TEST
#include "z6ii-boot-observer.h"
#ifndef CONFIG_USER_ONLY
#include "exec/icount.h"
#include "exec/translation-block.h"
#include "qemu/atomic.h"
#include "qemu/thread.h"
#include "qemu/bswap.h"
#include "qemu/timer.h"
#include "system/address-spaces.h"
#include "system/memory.h"
#include "hw/arm/nikon-z6ii-engine.h"
#endif
#endif

#ifndef CONFIG_USER_ONLY
#define Z6II_BOOT_CODE_CAPACITY 4096
#define Z6II_BOOT_IPU_CAPACITY 4096
#define Z6II_BOOT_HDMI_CAPACITY 32768
#define Z6II_BOOT_I2C_CAPACITY 8192
#define Z6II_BOOT_ERROR_CAPACITY 192
#define Z6II_BOOT_ERROR_SITE_CAPACITY 8
#define Z6II_BOOT_ERROR_SITE_COUNT 77
#define Z6II_BOOT_BLOB_MAX 0x3e4

typedef struct Z6IIBootBlob {
    uint32_t va, first_pa, length, valid, requested, retained, guard;
    const char *reason;
    uint8_t bytes[Z6II_BOOT_BLOB_MAX];
} Z6IIBootBlob;

typedef struct Z6IIBootRecord {
    uint64_t index;
    uint32_t kind, lane, core, global_core, pc, opcode, site, cpsr, secure;
    uint32_t regs[15], fixed_words[12], fixed_valid;
    uint64_t sctlr, tcr, ttbr0, ttbr1, tb_pc;
    uint32_t tb_icount, tb_cflags, insn_index;
    ICountInstructionTime clock;
    uint32_t clock_valid;
    int64_t mmio_virtual_ns;
    uint32_t addr, size, write, result, tx[3];
    uint64_t value;
    uint64_t i2c_generation;
    int64_t i2c_deadline;
    uint32_t i2c_channel, i2c_pending, i2c_event, i2c_snapshot;
    uint32_t i2c_direction, i2c_address, i2c_length, rx_result_confirmed;
    const char *plane0_name, *plane1_name;
    Z6IIBootBlob payload, stack, business_state, plane0, plane1;
    uint32_t ready;
} Z6IIBootRecord;

typedef struct Z6IIBootCopyRecord Z6IIBootCopyRecord;
typedef struct SAISOCell SAISOCell;
typedef struct Z6IIBootState {
    Z6IIEngineContext *engine;
    gsize initialized, original_rom_checked;
    bool enabled, error_only, captg_only, capseq_only, startup_focus, saiso_focus;
    bool original_rom_verified;
    char *output;
    const char *role;
    MemoryRegion *original_rom;
    uint32_t original_rom_bytes;
    const char *original_rom_sha;
    Z6IIBootRecord *code, *ipu, *hdmi, *i2c, *errors;
    Z6IIBootCopyRecord *copy;
    uint64_t code_attempts, ipu_attempts, hdmi_attempts, i2c_attempts;
    uint64_t error_attempts, copy_attempts;
    uint64_t error_site_attempts[Z6II_BOOT_ERROR_SITE_COUNT];
    uint64_t startup_site_attempts[230];
    QemuMutex saiso_mutex;
    SAISOCell *saiso_cells[Z6II_SAISO_SITE_COUNT][8];
    uint64_t saiso_sequence, saiso_bad_core;
} Z6IIBootState;

static Z6IIBootState z6ii_boot_states[2];
static Z6IIBootState *z6ii_boot_state(Z6IIEngineContext *engine);
static const char *z6ii_boot_lane_names[] = {"code", "ipu2402", "hdmi", "i2c", "first_error"};
#define Z6II_BOOT_STARTUP_SITE_COUNT 230
#define Z6II_BOOT_STARTUP_SITE_LIMIT 12
static unsigned z6ii_boot_startup_site_limit(unsigned site)
{
    return site == 224 ? 64 : site == 225 ? 32 : Z6II_BOOT_STARTUP_SITE_LIMIT;
}

static bool z6ii_boot_error_site_active(Z6IIBootState *state, unsigned site)
{
    if (state->capseq_only) {
        return (site >= 114 && site <= 119) || (site >= 179 && site <= 190);
    }
    if (!state->captg_only) { return site <= 145; }
    return (site >= 114 && site <= 119) || site == 132 ||
           site == 143 || (site >= 146 && site <= 178);
}

/* Scheduler roots are observations, not independently verified task IDs. */
static const uint32_t z6ii_boot_fixed_addresses[] = {
    0xc18680ec, 0xc18680f0, 0xc18694f4, 0xc23e2e28,
    0xc23c8b60, 0xc1808c84, 0xc1861458, 0xc1d047e8,
    0xc2b2a934, 0xc2b2a938, 0xc2b2a944, 0xc2b2a948,
};

#include "z6ii-boot-physical.inc.c"

/* Direct FlatView ordinary RAM only: never invoke MMIO, IOMMU or a CPU load.
 * Exclude ROM and RAM devices, reject span crossings and balance the ref. */
static bool z6ii_boot_physical_bytes(Z6IIBootState *state, uint32_t address, void *destination,
                                     unsigned size)
{
    if (!size || address > UINT32_MAX - (size - 1)) {
        return false;
    }
    MemoryRegionSection section = memory_region_find(state->engine->memory, address, size);
    bool valid = false;
    if (section.mr) {
        uint64_t region_size = memory_region_size(section.mr);
        if (section.offset_within_address_space == address &&
            int128_ge(section.size, int128_make64(size)) &&
            memory_region_is_ram(section.mr) &&
            !memory_region_is_ram_device(section.mr) &&
            !memory_region_is_rom(section.mr) && !section.readonly &&
            region_size >= size && section.offset_within_region <= region_size - size) {
            memcpy(destination, (const uint8_t *)memory_region_get_ram_ptr(section.mr) +
                   section.offset_within_region, size);
            valid = true;
        }
        memory_region_unref(section.mr);
    }
    return valid;
}

static bool z6ii_boot_physical_word(Z6IIBootState *state, uint32_t address, uint32_t *word)
{
    uint8_t bytes[4];
    if (!z6ii_boot_physical_bytes(state, address, bytes, sizeof(bytes))) {
        return false;
    }
    *word = ldl_le_p(bytes);
    return true;
}

/* Read-only ARMv7 short-descriptor address walk. This is address evidence,
 * not a CPU permission/TLB translation. Unsupported regimes are rejected.
 * Table bytes must also be ordinary RAM, so an invalid TTBR cannot call MMIO.
 * Domain/AP/XN checks are deliberately not claimed by the trace. */
static bool z6ii_boot_address(Z6IIBootState *state, const Z6IIBootRecord *r, uint32_t va, uint32_t *pa)
{
    if (!(r->sctlr & 1)) {
        *pa = va;
        return true;
    }
    if ((r->tcr & (UINT64_C(1) << 31)) ||
        (r->sctlr & (UINT64_C(1) << 25))) {
        return false;
    }
    unsigned n = r->tcr & 7;
    bool use_ttbr1 = n && (va >> (32 - n));
    if (r->tcr & (1u << (use_ttbr1 ? 5 : 4))) {
        return false;
    }
    uint64_t base = use_ttbr1 ? r->ttbr1 : r->ttbr0;
    unsigned align = use_ttbr1 ? 14 : 14 - n;
    if (base >> 32) {
        return false;
    }
    uint32_t table = base & ~((1u << align) - 1u);
    uint32_t index = (va >> 20) & ((1u << (use_ttbr1 ? 12 : 12 - n)) - 1u);
    uint32_t first;
    if (!z6ii_boot_physical_word(state, table + index * 4, &first)) {
        return false;
    }
    if ((first & 3) >= 2) {
        if (first & (1u << 18)) { /* supersections not implemented */
            return false;
        }
        *pa = (first & 0xfff00000u) | (va & 0x000fffffu);
        return true;
    }
    if ((first & 3) != 1) {
        return false;
    }
    uint32_t second;
    table = (first & 0xfffffc00u) + ((va >> 12) & 0xffu) * 4;
    if (!z6ii_boot_physical_word(state, table, &second)) {
        return false;
    }
    switch (second & 3) {
    case 1:
        *pa = (second & 0xffff0000u) | (va & 0x0000ffffu);
        return true;
    case 2:
    case 3:
        *pa = (second & 0xfffff000u) | (va & 0x00000fffu);
        return true;
    default:
        return false;
    }
}

static void z6ii_boot_blob_policy(Z6IIBootState *state, const Z6IIBootRecord *r, Z6IIBootBlob *blob,
    uint32_t address, unsigned size, unsigned maximum, bool allow_original_rom)
{
    blob->va = address;
    blob->length = blob->requested = size;
    blob->reason = "not_observed";
    blob->guard = 2;
    if (!size) { blob->reason = "zero_length"; return; }
    if (!address) { blob->reason = "zero_pointer"; return; }
    if (size > maximum || size > sizeof(blob->bytes)) {
        blob->reason = "requested_length_exceeds_capture_contract"; return;
    }
    if (address > UINT32_MAX - (size - 1)) {
        blob->reason = "address_overflow"; return;
    }
    for (unsigned done = 0; done < size;) {
        uint32_t va = address + done, pa;
        unsigned take = MIN(size - done, 0x1000u - (va & 0xfffu));
        if (!z6ii_boot_address(state, r, va, &pa)) {
            blob->reason = "address_walk_rejected"; return;
        }
        if (!z6ii_boot_physical_bytes(state, pa, blob->bytes + done, take)) {
            const char *reason = "ordinary_RAM_capture_rejected";
            if (!allow_original_rom || !z6ii_boot_original_rom_bytes(state, 
                    pa, blob->bytes + done, take, &reason)) {
                blob->reason = reason; return;
            }
        }
        if (!done) { blob->first_pa = pa; }
        done += take;
    }
    blob->valid = blob->guard = 1;
    blob->retained = size;
    blob->reason = allow_original_rom ? "accepted_profile_RAM_or_bound_original_ROM" :
                                       "accepted_ordinary_RAM";
}

static void z6ii_boot_blob(Z6IIBootState *state, const Z6IIBootRecord *r, Z6IIBootBlob *blob,
                            uint32_t address, unsigned size)
{
    z6ii_boot_blob_policy(state, r, blob, address, size, sizeof(blob->bytes), false);
}

static void z6ii_boot_context(Z6IIBootState *state, Z6IIBootRecord *r, CPUARMState *env)
{
    CPUState *cpu = env ? env_cpu(env) : NULL;
    r->global_core = cpu ? cpu->cpu_index : UINT32_MAX;
    r->core = cpu ? cpu->cpu_index - state->engine->cpu_base : UINT32_MAX;
    if (!env) {
        return;
    }
    r->cpsr = cpsr_read(env);
    r->secure = arm_is_secure(env);
    unsigned bank = r->secure ? 3 : 1; /* selected Cortex-A15 AArch32 bank */
    r->sctlr = env->cp15.sctlr_el[bank];
    r->tcr = env->cp15.tcr_el[bank];
    r->ttbr0 = env->cp15.ttbr0_el[bank];
    r->ttbr1 = env->cp15.ttbr1_el[bank];
    for (unsigned i = 0; i < 15; i++) {
        r->regs[i] = env->regs[i];
    }
    for (unsigned i = 0; i < ARRAY_SIZE(z6ii_boot_fixed_addresses); i++) {
        if (z6ii_boot_physical_word(state, z6ii_boot_fixed_addresses[i], &r->fixed_words[i])) {
            r->fixed_valid |= 1u << i;
        }
    }
}

static void z6ii_boot_print_blob(FILE *out, const char *name, const Z6IIBootBlob *blob)
{
    fprintf(out, " %s_va=%08x %s_first_pa=%08x %s_length=%u %s_valid=%u",
            name, blob->va, name, blob->first_pa, name, blob->length,
            name, blob->valid);
    fprintf(out, " %s_requested=%u %s_retained=%u %s_guard=%u %s_reason=%s",
            name, blob->requested, name, blob->retained, name, blob->guard,
            name, blob->reason ? blob->reason : "unused");
    fprintf(out, " %s_hex=", name);
    if (!blob->valid) {
        fputc('-', out);
        return;
    }
    for (unsigned i = 0; i < blob->length; i++) {
        fprintf(out, "%02x", blob->bytes[i]);
    }
}

static void z6ii_boot_print_record(Z6IIBootState *state, FILE *out, const Z6IIBootRecord *r)
{
    fprintf(out, "Z6II_BOOT_OBS role=%s kind=%s lane=%s index=%" PRIu64
            " core=%u global_core=%u pc=%08x opcode=%08x site=%s cpsr=%08x secure=%u "
            "sctlr=%016" PRIx64 " tcr=%016" PRIx64 " ttbr0=%016" PRIx64
            " ttbr1=%016" PRIx64 " tb_pc=%" PRIx64 " tb_icount=%u tb_cflags=%08x "
            "insn_index=%u clock_valid=%u virtual_ns_before=%" PRId64
            " virtual_ns=%" PRId64 " mmio_virtual_ns=%" PRId64
            " fixed_valid=%03x",
            state->role, r->kind == 1 ? "code" : r->kind == 2 ? "mmio" : "timer",
            z6ii_boot_lane_names[r->lane], r->index,
            r->core, r->global_core, r->pc, r->opcode, z6ii_boot_site_name(r->site),
            r->cpsr, r->secure, r->sctlr, r->tcr, r->ttbr0, r->ttbr1,
            r->tb_pc, r->tb_icount, r->tb_cflags, r->insn_index,
            r->clock_valid, r->clock.virtual_ns_before, r->clock.virtual_ns_inclusive,
            r->mmio_virtual_ns, r->fixed_valid);
    for (unsigned i = 0; i < ARRAY_SIZE(z6ii_boot_fixed_addresses); i++) {
        fprintf(out, " m%08x=%08x", z6ii_boot_fixed_addresses[i], r->fixed_words[i]);
    }
    for (unsigned i = 0; i < 15; i++) {
        fprintf(out, " r%u=%08x", i, r->regs[i]);
    }
    if (r->kind == 2) {
        fprintf(out, " addr=%08x size=%u write=%u value=%016" PRIx64
                " result=%u logged_pc_is_TB_start=1 tx0=%08x tx1=%08x tx2=%08x",
                r->addr, r->size, r->write, r->value, r->result,
                r->tx[0], r->tx[1], r->tx[2]);
    }
    if (r->lane == 3) {
        fprintf(out, " i2c_generation=%" PRIu64 " i2c_deadline_ns=%" PRId64
            " i2c_channel=%u i2c_pending=%u i2c_event=%u i2c_snapshot=%u"
            " direction_byte=%u address_halfword=%04x transfer_requested=%u"
            " rx_result_confirmed=%u raw_direction_mapping_inferred=0",
            r->i2c_generation, r->i2c_deadline, r->i2c_channel, r->i2c_pending,
            r->i2c_event, r->i2c_snapshot, r->i2c_direction, r->i2c_address,
            r->i2c_length, r->rx_result_confirmed);
    }
    z6ii_boot_print_blob(out, "payload", &r->payload);
    z6ii_boot_print_blob(out, "stack", &r->stack);
    z6ii_boot_print_blob(out, "business_state", &r->business_state);
    z6ii_boot_print_blob(out, r->plane0_name ? r->plane0_name : "plane0_sample", &r->plane0);
    z6ii_boot_print_blob(out, r->plane1_name ? r->plane1_name : "plane1_sample", &r->plane1);
    fputc('\n', out);
}

#include "z6ii-saiso-observer.inc.c"

static void z6ii_boot_flush(Z6IIBootState *state)
{
    if (!state->enabled) {
        return;
    }
    FILE *out = state->output ? fopen(state->output, "wx") : stderr;
    if (!out) {
        fprintf(stderr, "Z6II_BOOT_TRACE_OUTPUT_ERROR errno=%d\n", errno);
        return;
    }
    fprintf(out, "Z6II_BOOT_TRACE schema=3 role=%s code_capacity=%u ipu_capacity=%u hdmi_capacity=%u i2c_capacity=%u "
            "guest_writes=0 payload_RAM_only=1 profile_original_ROM_exception=1 address_walk=ARMv7_short "
            "permission_translation_verified=0 peer_clocks_synchronized=%u clock=QEMU_CLOCK_VIRTUAL "
            "scheduler_root_identity_verified=0\n", state->role,
            Z6II_BOOT_CODE_CAPACITY, Z6II_BOOT_IPU_CAPACITY, Z6II_BOOT_HDMI_CAPACITY, Z6II_BOOT_I2C_CAPACITY, state->engine->unified);
    if (state->saiso_focus) {
        z6ii_saiso_flush(state, out);
        if (out != stderr) { fclose(out); }
        return;
    }
    uint64_t attempts[4] = {qatomic_read(&state->code_attempts),
                            qatomic_read(&state->ipu_attempts),
                            qatomic_read(&state->hdmi_attempts), qatomic_read(&state->i2c_attempts)};
    Z6IIBootRecord *arrays[4] = {state->code, state->ipu, state->hdmi, state->i2c};
    unsigned capacity[4] = {Z6II_BOOT_CODE_CAPACITY, Z6II_BOOT_IPU_CAPACITY,
                            Z6II_BOOT_HDMI_CAPACITY, Z6II_BOOT_I2C_CAPACITY};
    for (unsigned a = 0; a < 4; a++) {
        uint64_t limit = MIN(attempts[a], capacity[a]);
        unsigned written = 0, incomplete = 0;
        for (uint64_t i = 0; i < limit; i++) {
            if (qatomic_load_acquire(&arrays[a][i].ready)) {
                z6ii_boot_print_record(state, out, &arrays[a][i]);
                written++;
            } else {
                incomplete++;
            }
        }
        fprintf(out, "Z6II_BOOT_TRACE_END kind=%s lane=%s attempts=%" PRIu64
                " written=%u overflow=%" PRIu64 " incomplete=%u "
                "index_is_reservation_order=1 global_causality_verified=0\n",
                a == 3 ? "mixed" : a ? "mmio" : "code", z6ii_boot_lane_names[a], attempts[a], written,
                attempts[a] - limit, incomplete);
    }
    uint64_t error_count = qatomic_read(&state->error_attempts);
    unsigned error_written = 0;
    for (uint64_t i = 0; i < MIN(error_count, Z6II_BOOT_ERROR_CAPACITY); i++) {
        if (qatomic_load_acquire(&state->errors[i].ready)) {
            z6ii_boot_print_record(state, out, &state->errors[i]);
            error_written++;
        }
    }
    fprintf(out, "Z6II_BOOT_FIRST_ERROR_SUMMARY capacity=%u per_site_capacity=%u written=%u error_only=%u captg_only=%u capseq_only=%u guest_writes=0\n",
        Z6II_BOOT_ERROR_CAPACITY, Z6II_BOOT_ERROR_SITE_CAPACITY, error_written, state->error_only, state->captg_only, state->capseq_only);
    for (unsigned s = 0; s < Z6II_BOOT_ERROR_SITE_COUNT; s++) {
        if (!z6ii_boot_error_site_active(state, 114 + s)) { continue; }
        uint64_t count = qatomic_read(&state->error_site_attempts[s]);
        fprintf(out, "Z6II_BOOT_FIRST_ERROR_SITE site=%s attempts=%" PRIu64 " limit=%u\n",
            z6ii_boot_site_name(114 + s), count, z6ii_boot_error_site_limit(114 + s));
    }
    if (state->startup_focus) {
        fprintf(out, "Z6II_BOOT_STARTUP_FOCUS_SUMMARY active_site_count=43 default_per_site_capacity=%u written=%" PRIu64 " guest_writes=0\n",
                Z6II_BOOT_STARTUP_SITE_LIMIT, qatomic_read(&state->code_attempts));
        for (unsigned s = 0; s < Z6II_BOOT_STARTUP_SITE_COUNT; s++) {
            if (!z6ii_boot_startup_site(s)) { continue; }
            fprintf(out, "Z6II_BOOT_STARTUP_FOCUS_SITE site=%s attempts=%" PRIu64 " limit=%u\n",
                    z6ii_boot_site_name(s), qatomic_read(&state->startup_site_attempts[s]),
                    z6ii_boot_startup_site_limit(s));
        }
    }
    z6ii_boot_copy_flush(state, out);
    if (out != stderr) {
        fclose(out);
    }
}

static void z6ii_boot_flush_all(void)
{
    for (unsigned i = 0; i < ARRAY_SIZE(z6ii_boot_states); i++) {
        if (z6ii_boot_states[i].engine) { z6ii_boot_flush(&z6ii_boot_states[i]); }
    }
}

static void z6ii_boot_state_init(Z6IIBootState *state)
{
    if (g_once_init_enter(&state->initialized)) {
        const char *enabled = z6ii_engine_getenv(state->engine, "Z6II_BOOT_TCG_TRACE");
        const char *path = z6ii_engine_getenv(state->engine, "Z6II_BOOT_TCG_TRACE_OUT");
        const char *error_only = z6ii_engine_getenv(state->engine, "Z6II_BOOT_ERROR_ONLY");
        state->error_only = error_only && !strcmp(error_only, "1");
        const char *startup = z6ii_engine_getenv(state->engine, "Z6II_BOOT_STARTUP_FOCUS");
        state->startup_focus = startup && !strcmp(startup, "1");
        /* Explicit modes are mutually exclusive; no hidden override. */
        if (state->error_only && state->startup_focus) {
            fprintf(stderr, "Z6II_BOOT_MODE_ERROR mutually_exclusive=1\n");
            state->startup_focus = false;
        }
        const char *captg_only = z6ii_engine_getenv(state->engine, "Z6II_BOOT_CAPTG_ONLY");
        state->captg_only = captg_only && !strcmp(captg_only, "1");
        const char *capseq_only = z6ii_engine_getenv(state->engine, "Z6II_BOOT_CAPSEQ_ONLY");
        state->capseq_only = capseq_only && !strcmp(capseq_only, "1");
        state->enabled = enabled && !strcmp(enabled, "1");
        const char *saiso = z6ii_engine_getenv(state->engine, "Z6II_BOOT_SAISO_FOCUS");
        state->saiso_focus = saiso && !strcmp(saiso, "1");
        if (state->saiso_focus && (state->startup_focus || state->error_only ||
            state->captg_only || state->capseq_only)) {
            fprintf(stderr, "Z6II_BOOT_SAISO_MODE_ERROR mutually_exclusive=1\n");
            state->enabled = false;
        }
        if (state->saiso_focus) { qemu_mutex_init(&state->saiso_mutex); }
        if (state->enabled) {
            state->output = path && *path ? g_strdup(path) : NULL;
            if (!state->saiso_focus) {
                state->code = g_new0(Z6IIBootRecord, Z6II_BOOT_CODE_CAPACITY);
                state->ipu = g_new0(Z6IIBootRecord, Z6II_BOOT_IPU_CAPACITY);
                state->hdmi = g_new0(Z6IIBootRecord, Z6II_BOOT_HDMI_CAPACITY);
                state->i2c = g_new0(Z6IIBootRecord, Z6II_BOOT_I2C_CAPACITY);
                state->errors = g_new0(Z6IIBootRecord, Z6II_BOOT_ERROR_CAPACITY);
                state->copy = g_new0(Z6IIBootCopyRecord, Z6II_BOOT_COPY_CAPACITY);
            }
        }
        g_once_init_leave(&state->initialized, 1);
    }

}

static Z6IIBootState *z6ii_boot_state(Z6IIEngineContext *engine)
{
    if (!engine || !engine->role || !engine->memory) { return NULL; }
    unsigned slot;
    if (!strcmp(engine->role, "master")) { slot = 0; }
    else if (!strcmp(engine->role, "slave")) { slot = 1; }
    else { return NULL; }
    Z6IIBootState *state = &z6ii_boot_states[slot];
    assert(!state->engine || state->engine == engine);
    state->engine = engine;
    state->role = engine->role;
    z6ii_boot_state_init(state);
    static gsize exit_registered;
    if (g_once_init_enter(&exit_registered)) {
        int result = atexit(z6ii_boot_flush_all);
        g_once_init_leave(&exit_registered, result ? 2 : 1);
    }
    if (exit_registered != 1) { state->enabled = false; }
    return state;
}

/* Translation has no CPU argument. Instrument the union, then filter in the
 * helper by its actual E6 owner. MCU helpers never access E6 state or CP15. */
bool z6ii_boot_trace_enabled(void)
{
    CPUState *cpu;
    CPU_FOREACH(cpu) {
        Z6IIBootState *state = z6ii_boot_state(z6ii_engine_for_cpu(cpu));
        if (state && state->enabled) { return true; }
    }
    return false;
}

void HELPER(z6ii_boot_observe)(CPUARMState *env, uint32_t pc, uint32_t opcode,
                              void *tb_opaque, uint32_t index_one_based)
{
    Z6IIEngineContext *engine = env ? z6ii_engine_for_cpu(env_cpu(env)) : NULL;
    Z6IIBootState *state = z6ii_boot_state(engine);
    if (!state || !state->enabled || !env || arm_feature(env, ARM_FEATURE_M)) { return; }

    unsigned site = z6ii_boot_site_id(pc, opcode);
    if (!site || !state->enabled) {
        return;
    }
    if (state->saiso_focus) {
        z6ii_saiso_observe(state, env, pc, opcode, tb_opaque, index_one_based);
        return;
    }
    if (site >= 230) { return; }
    /* Observe only messages actually submitted to the original APPCTL owner.
     * This guard neither reads MMIO nor changes guest state. */
    if (site == 112 && env->regs[0] != 0xc1818be0u) {
        return;
    }
    /* 0x10433ac4 accepts exactly the 106-byte MCU startup block. */
    if (site == 113 && env->regs[1] != 0x6au) {
        return;
    }
    bool error = z6ii_boot_error_site(site);
    if (error && !z6ii_boot_error_site_active(state, site)) { return; }
    if (state->error_only && !error) { return; }
    if (state->startup_focus && !error && !z6ii_boot_startup_site(site)) { return; }
    /* Unfocused date sites must stay absent from legacy broad runs. */
    if (!state->startup_focus && site >= 191) { return; }
    if (state->startup_focus && site == 39 &&
        env->regs[0] != 0x430c0003u) { return; }
    if (state->startup_focus && site == 45 &&
        env->regs[0] != 0x103efb85u) { return; }
    /* Exact loader arguments, before their original instructions. r5 is the
     * region ID preserved by this inspected call chain; other resources cannot
     * consume this quota. Runtime guard coverage remains explicit in the log. */
    if (site == 213 && env->regs[0] != 0x0bu) { return; }
    if (((site >= 214 && site <= 217) || (site >= 221 && site <= 223)) &&
        env->regs[5] != 0x0bu) { return; }
    if (site == 218 && env->regs[0] != 0xc185ecdcu) { return; }
    if (site == 219 && env->regs[1] != 0xc18a7798u) { return; }
    if (site == 220 && env->regs[1] != 0xc185e7e0u) { return; }
    /* APPLV's exact native instance. At dispatch r0 already includes
     * state*4, r1 is the loaded state, r3 the original callback and r4 event.
     * Periodic housekeeping events 9/B do not consume this finite quota. */
    if (site == 224 && (env->regs[1] > 31u ||
        env->regs[0] != 0xc181d9e4u + env->regs[1] * 4u ||
        env->regs[4] == 9u || env->regs[4] == 0xbu)) { return; }
    if (site == 225 && env->regs[0] != 0xc181d9e4u) { return; }
    /* The generic object callback is observed only for the original APPLV
     * start caller. Other objects do not consume its finite quota. */
    if (site == 229 && (env->regs[14] < 0x10542b48u ||
                       env->regs[14] >= 0x10543560u)) { return; }
    /* Clear-all calls do not consume the first nonzero error quota. */
    if (site == 115 && env->regs[0] == 0) { return; }
    /* r0 is the message ID at this exact original entry. */
    if (site == 120 && env->regs[0] != 0x041000b0u &&
        env->regs[0] != 0x041000b1u) { return; }
    if (site == 128 && env->regs[0] != 0x03030011u) { return; }
    if (site == 132 && env->regs[0] !=
        (state->captg_only ? 0x04200181u : 0x03030001u)) { return; }
    /* Event bit 0x400 is the exact native Error check dispatch. */
    if (site == 143 && !(env->regs[4] & 0x400u)) { return; }
    if (site == 144 && env->regs[1] != 5u) { return; }
    if (site == 145 && (env->regs[0] != 9u || env->regs[2] != 5u)) { return; }
    if (site == 164 && env->regs[1] != 0x30000u) { return; }
    if ((site == 165 || site == 166) && env->regs[1] != 0x800u) { return; }
    if (site == 167 && !env->regs[0]) { return; }
    /* These exact original table checks belong to the observed mode1 input.
     * Other table consumers do not consume its bounded observation quota. */
    if ((site == 170 || site == 171) &&
        env->regs[7] != 0xc18a7694u) { return; }
    if (site == 185 && env->regs[0] != 0x03030024u) { return; }
    if (site == 187 && env->regs[0] != 0x03030004u) { return; }
    if (site == 188 && (env->regs[0] != 0xc18682acu || env->regs[1] != 8u)) { return; }
    bool i2c = !error && z6ii_boot_i2c_site(site);
    uint64_t index;
    Z6IIBootRecord *r;
    if (error) {
        unsigned slot = site - 114;
        uint64_t hit = qatomic_fetch_inc(&state->error_site_attempts[slot]);
        /* Independent per-site quota protects the first mutation from traffic
         * at descriptor/message entries. No guest read occurs after the cap. */
        if (hit >= z6ii_boot_error_site_limit(site)) { return; }
        index = qatomic_fetch_inc(&state->error_attempts);
        if (index >= Z6II_BOOT_ERROR_CAPACITY) { return; }
        r = &state->errors[index];
        r->lane = 4;
    } else {
        if (state->startup_focus) {
            uint64_t hit = qatomic_fetch_inc(&state->startup_site_attempts[site]);
            if (hit >= z6ii_boot_startup_site_limit(site)) { return; }
        }
        index = i2c ? qatomic_fetch_inc(&state->i2c_attempts) :
                      qatomic_fetch_inc(&state->code_attempts);
        if (index >= (i2c ? Z6II_BOOT_I2C_CAPACITY : Z6II_BOOT_CODE_CAPACITY)) { return; }
        r = i2c ? &state->i2c[index] : &state->code[index];
        r->lane = i2c ? 3 : 0;
    }
    r->index = index;
    r->kind = 1;
    r->pc = pc;
    r->opcode = opcode;
    r->site = site;
    z6ii_boot_context(state, r, env);
    const TranslationBlock *tb = tb_opaque;
    r->tb_pc = tb ? tb->pc : 0;
    r->tb_icount = tb ? tb->icount : 0;
    r->tb_cflags = tb ? tb_cflags(tb) : 0;
    r->insn_index = index_one_based;
    r->clock.virtual_ns_before = r->clock.virtual_ns_inclusive = -1;
    r->mmio_virtual_ns = -1;
    if (tb && (r->tb_cflags & CF_USE_ICOUNT)) {
        r->clock_valid = icount_read_only_instruction_time(env_cpu(env), tb->icount,
                                                          index_one_based, &r->clock);
    }
    uint32_t pointer = r->regs[z6ii_boot_payload_register(site)];
    unsigned requested = z6ii_boot_payload_size(site), maximum = Z6II_BOOT_BLOB_MAX;
    if (pc == 0x103d6fa4) { requested = r->regs[2]; maximum = 255; }
    bool permitted = pc != 0x102440ca || r->regs[0] == 0x900e;
    if (permitted) {
        z6ii_boot_blob_policy(state, r, &r->payload, pointer, requested, maximum,
                              pc == 0x103d71ea);
    } else {
        r->payload.va = pointer;
        r->payload.length = r->payload.requested = requested;
        r->payload.guard = 2;
        r->payload.reason = "IPUS_header_guard_rejected";
    }
    if (error) {
        /* Every blob is bounded ordinary RAM, with the original MMU walk.
         * These are raw error-domain roots, not an assumed device diagnosis. */
        z6ii_boot_blob(state, r, &r->stack, r->regs[13], 0x200);
        z6ii_boot_blob(state, r, &r->business_state, 0xc1868290, 0x1b0);
        if (site < 128) {
            r->plane0_name = "lower_error_registry";
            r->plane1_name = "pending_failure_descriptor";
            z6ii_boot_blob(state, r, &r->plane0, 0xc1866cd4, 0x60);
            z6ii_boot_blob(state, r, &r->plane1, 0xc23d96ec, 0x10);
        } else if (site <= 143 || site >= 179) {
            r->plane0_name = "native_gpio_driver_and_vtable";
            r->plane1_name = "native_gpio_input_object";
            z6ii_boot_blob(state, r, &r->plane0, 0xc18a790c, 0xa0);
            if (r->plane0.valid) {
                /* c18a7920[+0xc] is the native input GPIO object, produced
                 * by the original board table and driver initializer. */
                z6ii_boot_blob(state, r, &r->plane1,
                              ldl_le_p(r->plane0.bytes + 0x20), 0x40);
            }
        } else if (site == 170 || site == 171) {
            r->plane0_name = "native_CAPTG_default_table_registry";
            r->plane1_name = "native_CAPTG_default_table_mode";
            z6ii_boot_blob(state, r, &r->plane0, 0xc18a7798, 0x30);
            z6ii_boot_blob(state, r, &r->plane1, 0xc2b1fca0, 0x20);
        } else if (site >= 146) {
            r->plane0_name = "native_CAPTG_state_and_flag_wrapper";
            r->plane1_name = "native_sequence_peripheral_handles";
            z6ii_boot_blob(state, r, &r->plane0, 0xc18a75d8, 0x180);
            z6ii_boot_blob(state, r, &r->plane1, 0xc1809700, 0x40);
        } else {
            r->plane0_name = "provider9_parsed_records";
            r->plane1_name = "provider9_transport_fragment";
            z6ii_boot_blob(state, r, &r->plane0, 0xc1887930, 0x50);
            if (site == 145 && r->payload.valid && r->payload.length >= 12) {
                z6ii_boot_blob(state, r, &r->plane1,
                              ldl_le_p(r->payload.bytes + 8), 5);
            }
        }
        qatomic_store_release(&r->ready, 1);
        return;
    }
    if (state->startup_focus && site >= 226) {
        z6ii_boot_blob(state, r, &r->stack, r->regs[13], 192);
        z6ii_boot_blob(state, r, &r->business_state, 0xc202bf40u, 0x180);
        r->plane0_name = "APPLV_original_current_business_mode";
        r->plane1_name = "APPLV_original_capture_object_table";
        z6ii_boot_blob(state, r, &r->plane0, 0xc1821b4cu, 4);
        z6ii_boot_blob(state, r, &r->plane1, 0xc202f7e4u, 0x100);
        qatomic_store_release(&r->ready, 1);
        return;
    }
    if (state->startup_focus && (site == 224 || site == 225)) {
        z6ii_boot_blob(state, r, &r->stack, r->regs[13], 128);
        z6ii_boot_blob(state, r, &r->business_state, 0xc181d9e4u, 0x180);
        r->plane0_name = "APPLV_original_command_shared_state";
        r->plane1_name = "native_CAPTG_resource_registry";
        z6ii_boot_blob(state, r, &r->plane0, 0xc181d330u, 0x40);
        z6ii_boot_blob(state, r, &r->plane1, 0xc18a7798u, 0x30);
        qatomic_store_release(&r->ready, 1);
        return;
    }
    if (state->startup_focus && site >= 213) {
        z6ii_boot_blob(state, r, &r->stack, r->regs[13], 192);
        z6ii_boot_blob(state, r, &r->business_state, 0xc18a7798, 0x30);
        r->plane0_name = "region0B_original_runtime_record";
        r->plane1_name = "region0B_original_parent_source_record";
        z6ii_boot_blob(state, r, &r->plane0, 0xc185ecdc, 0x1c);
        z6ii_boot_blob(state, r, &r->plane1, 0xc185e7e0, 0x2c);
        qatomic_store_release(&r->ready, 1);
        return;
    }
    if (state->startup_focus && site >= 191) {
        z6ii_boot_blob(state, r, &r->stack, r->regs[13], 192);
        z6ii_boot_blob(state, r, &r->business_state, 0xc23e2d20, 0x130);
        r->plane0_name = "DtTm_original_global_state";
        r->plane1_name = "DtTm_original_callback_table";
        z6ii_boot_blob(state, r, &r->plane0, 0xc1810604, 0x60);
        z6ii_boot_blob(state, r, &r->plane1, 0xc1d60874, 0x20);
        qatomic_store_release(&r->ready, 1);
        return;
    }
    if (i2c) {
        r->i2c_channel = UINT32_MAX;
        r->i2c_deadline = -1;
        r->plane0_name = "TX_buffer";
        r->plane1_name = "RX_buffer_before_result";
        r->rx_result_confirmed = pc == 0x103d6f14 && r->regs[0] == 0;
        if (pc == 0x1036f55c || pc == 0x1036f5da) {
            z6ii_boot_blob(state, r, &r->business_state,
                           r->regs[pc == 0x1036f55c ? 0 : 4], 48);
        }
        if (r->payload.valid && r->payload.length == 20) {
            bool upper = pc == 0x103d6f10 || pc == 0x103d7002 ||
                         pc == 0x1038ab24 || pc == 0x103730d0;
            bool lower = pc == 0x10373040 || pc == 0x1036f55c || pc == 0x1036f5da;
            if (upper) {
                z6ii_boot_blob_policy(state, r, &r->plane0, ldl_le_p(r->payload.bytes + 4),
                    ldl_le_p(r->payload.bytes + 12), 256, false);
                z6ii_boot_blob_policy(state, r, &r->plane1, ldl_le_p(r->payload.bytes + 8),
                    ldl_le_p(r->payload.bytes + 16), 256, false);
            } else if (lower) {
                r->i2c_direction = r->payload.bytes[0];
                r->i2c_address = lduw_le_p(r->payload.bytes + 2);
                r->i2c_length = ldl_le_p(r->payload.bytes + 8);
                r->plane0_name = "direction_buffer_before_result";
                z6ii_boot_blob_policy(state, r, &r->plane0, ldl_le_p(r->payload.bytes + 4),
                    r->i2c_length, 256, false);
            }
        }
    }
    /* APPCTL submission includes the saved caller frame beyond its 0x44-byte message. */
    z6ii_boot_blob(state, r, &r->stack, r->regs[13], site == 112 ? 192 : 64);
    if (site >= 106 && site <= 110) {
        uint32_t service = r->regs[site == 108 ? 4 : 0];
        z6ii_boot_blob(state, r, &r->business_state, service, 0x3e4);
        r->plane0_name = "SWSRV_current_state_object";
        r->plane1_name = "SWSRV_state_object_table";
        if (r->business_state.valid) {
            z6ii_boot_blob(state, r, &r->plane0,
                          ldl_le_p(r->business_state.bytes + 0x154), 0x154);
        }
        z6ii_boot_blob(state, r, &r->plane1, 0xc1818fc4, 64);
    } else if (site >= 102 && site <= 105) {
        /* Stopped ordinary RAM only: inspect the actual dispatch owner. */
        z6ii_boot_blob(state, r, &r->business_state,
                       site == 104 ? 0xc1818be0 : 0xc209fa58,
                       site == 104 ? 0x3e4 : 0x40);
        if (site == 104 && r->business_state.valid) {
            r->plane0_name = "APPCTL_current_state_object";
            z6ii_boot_blob(state, r, &r->plane0,
                          ldl_le_p(r->business_state.bytes + 0x154), 0x154);
        }
    } else {
        z6ii_boot_blob(state, r, &r->business_state, 0xc20985a0, 0x44);
    }
    if (z6ii_boot_descriptor_site(site) && r->payload.valid &&
        r->payload.length >= 0x330) {
        /* Two independently observed pointer fields. Format and dimensions
         * are not inferred by the observer; these are ordinary-RAM samples. */
        z6ii_boot_blob(state, r, &r->plane0, ldl_le_p(r->payload.bytes + 0x328), 64);
        z6ii_boot_blob(state, r, &r->plane1, ldl_le_p(r->payload.bytes + 0x32c), 64);
    }
    qatomic_store_release(&r->ready, 1);
}

void z6ii_boot_mmio_observe(CPUARMState *env, uint32_t addr, unsigned size,
                           bool write, uint64_t value, uint32_t result,
                           const uint32_t tx[3])
{
    Z6IIEngineContext *engine = env ? z6ii_engine_for_cpu(env_cpu(env)) : NULL;
    Z6IIBootState *state = z6ii_boot_state(engine);
    if (!state || !state->enabled || !env || arm_feature(env, ARM_FEATURE_M)) { return; }

    if (!state->enabled || state->error_only || state->startup_focus || state->saiso_focus ||
        !((addr >= 0x24020000u && addr < 0x24020100u) ||
          (addr >= 0x20160000u && addr < 0x20180000u))) {
        return;
    }
    bool ipu = addr >= 0x24020000u && addr < 0x24020100u;
    uint64_t index = ipu ? qatomic_fetch_inc(&state->ipu_attempts) :
                           qatomic_fetch_inc(&state->hdmi_attempts);
    unsigned capacity = ipu ? Z6II_BOOT_IPU_CAPACITY : Z6II_BOOT_HDMI_CAPACITY;
    if (index >= capacity) {
        return;
    }
    Z6IIBootRecord *r = ipu ? &state->ipu[index] : &state->hdmi[index];
    r->lane = ipu ? 1 : 2;
    r->index = index;
    r->kind = 2;
    r->pc = env ? env->regs[15] : 0;
    r->addr = addr;
    r->size = size;
    r->write = write;
    r->value = value;
    r->result = result;
    r->mmio_virtual_ns = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    r->clock.virtual_ns_before = r->clock.virtual_ns_inclusive = -1;
    z6ii_boot_context(state, r, env);
    if (tx) {
        memcpy(r->tx, tx, sizeof(r->tx));
    }
    if (write && addr == 0x24020008u && value == 2 && tx) {
        z6ii_boot_blob(state, r, &r->payload, tx[1], 0x1c);
    }
    qatomic_store_release(&r->ready, 1);
}
/* Device snapshots follow the actual access/completion. They do not perform
 * any additional MMIO read, acknowledge IRQs, or change an existing timer. */
static void z6ii_boot_i2c_snapshot(Z6IIBootRecord *r, const uint32_t regs[11],
    const uint8_t tx[16], unsigned count, bool pending, int64_t deadline,
    uint64_t generation)
{
    r->i2c_generation = generation;
    r->i2c_deadline = deadline;
    r->i2c_pending = pending;
    r->plane0_name = "TX_FIFO";
    if (regs) {
        r->business_state.length = r->business_state.requested = 44;
        r->business_state.retained = 44;
        r->business_state.valid = r->business_state.guard = 1;
        r->business_state.reason = "actual_model_register_snapshot";
        for (unsigned i = 0; i < 11; ++i) {
            stl_le_p(r->business_state.bytes + i * 4, regs[i]);
        }
        r->i2c_snapshot = 1;
    }
    r->plane0.length = r->plane0.requested = count;
    r->plane0.guard = 2;
    r->plane0.reason = !count ? "zero_length" : "FIFO_snapshot_rejected";
    if (tx && count && count <= 16) {
        memcpy(r->plane0.bytes, tx, count);
        r->plane0.retained = count;
        r->plane0.valid = r->plane0.guard = 1;
        r->plane0.reason = "actual_model_TX_FIFO_snapshot";
    }
}

void z6ii_boot_i2c_mmio_observe(CPUARMState *env, uint32_t addr, unsigned size,
    bool write, uint64_t value, uint32_t result, const uint32_t regs[11],
    const uint8_t tx[16], unsigned tx_count, bool pending, int64_t deadline,
    uint64_t generation)
{
    Z6IIEngineContext *engine = env ? z6ii_engine_for_cpu(env_cpu(env)) : NULL;
    Z6IIBootState *state = z6ii_boot_state(engine);
    if (!state || !state->enabled || !env || arm_feature(env, ARM_FEATURE_M)) { return; }

    if (!state->enabled || state->error_only || state->startup_focus || state->saiso_focus || addr < 0x2c018000 || addr >= 0x2c01c000) { return; }
    uint64_t index = qatomic_fetch_inc(&state->i2c_attempts);
    if (index >= Z6II_BOOT_I2C_CAPACITY) { return; }
    Z6IIBootRecord *r = &state->i2c[index];
    r->index = index; r->kind = 2; r->lane = 3;
    r->pc = env ? env->regs[15] : 0;
    r->addr = addr; r->size = size; r->write = write; r->value = value; r->result = result;
    r->i2c_channel = (addr - 0x2c018000) / 0x1000;
    r->mmio_virtual_ns = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    r->clock.virtual_ns_before = r->clock.virtual_ns_inclusive = -1;
    z6ii_boot_context(state, r, env);
    z6ii_boot_i2c_snapshot(r, regs, tx, tx_count, pending, deadline, generation);
    qatomic_store_release(&r->ready, 1);
}

void z6ii_boot_i2c_timer_observe(Z6IIEngineContext *engine, unsigned channel, unsigned event, int64_t now,
    const uint32_t regs[11], const uint8_t tx[16], unsigned tx_count,
    bool pending, int64_t deadline, uint64_t generation)
{
    Z6IIBootState *state = z6ii_boot_state(engine);
    if (!state || !state->enabled) { return; }

    if (!state->enabled || state->error_only || state->startup_focus || state->saiso_focus || channel >= 4) { return; }
    uint64_t index = qatomic_fetch_inc(&state->i2c_attempts);
    if (index >= Z6II_BOOT_I2C_CAPACITY) { return; }
    Z6IIBootRecord *r = &state->i2c[index];
    r->index = index; r->kind = 3; r->lane = 3; r->core = r->global_core = UINT32_MAX;
    r->i2c_channel = channel; r->i2c_event = event;
    r->mmio_virtual_ns = now;
    r->clock.virtual_ns_before = r->clock.virtual_ns_inclusive = -1;
    z6ii_boot_i2c_snapshot(r, regs, tx, tx_count, pending, deadline, generation);
    qatomic_store_release(&r->ready, 1);
}

#else
bool z6ii_boot_trace_enabled(void) { return false; }
bool z6ii_boot_site_enabled(unsigned site) { return false; }
void HELPER(z6ii_boot_observe)(CPUARMState *env, uint32_t pc, uint32_t opcode,
                              void *tb, uint32_t index) { }
void z6ii_boot_mmio_observe(CPUARMState *env, uint32_t addr, unsigned size,
                           bool write, uint64_t value, uint32_t result,
                           const uint32_t tx[3]) { }
#endif

#ifdef CONFIG_USER_ONLY
void z6ii_boot_bind_original_rom(Z6IIEngineContext *engine, struct MemoryRegion *r, uint32_t n, const char *s) { }
uint32_t z6ii_boot_copy_pre_observe(Z6IIEngineContext *engine, bool a, unsigned b, bool c, int64_t d,
    int64_t e, uint32_t f, uint32_t g, uint32_t h, unsigned i) { return 0; }
void z6ii_boot_copy_buffer_observe(Z6IIEngineContext *engine, uint32_t a, const uint8_t *b, uint32_t c, int64_t d) { }
void z6ii_boot_copy_destination_post_observe(Z6IIEngineContext *engine, uint32_t a, uint32_t b, int64_t c) { }
void z6ii_boot_i2c_mmio_observe(CPUARMState *a, uint32_t b, unsigned c,
    bool d, uint64_t e, uint32_t f, const uint32_t g[11], const uint8_t h[16],
    unsigned i, bool j, int64_t k, uint64_t l) { }
void z6ii_boot_i2c_timer_observe(Z6IIEngineContext *engine, unsigned a, unsigned b, int64_t c,
    const uint32_t d[11], const uint8_t e[16], unsigned f, bool g,
    int64_t h, uint64_t i) { }
#endif
