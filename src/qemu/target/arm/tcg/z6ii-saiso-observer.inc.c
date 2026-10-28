/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Default-off, original-instruction observations. Only ordinary RAM is read. */
#define SAISO_HEAD 8
#define SAISO_CHANGE 96
#define SAISO_PERIODIC 192
#define SAISO_PRIORITY 64
#define SAISO_TAIL 8
#define SAISO_KEEP (SAISO_HEAD + SAISO_CHANGE + SAISO_PERIODIC + SAISO_PRIORITY)
#define SAISO_CORES 8
#define SAISO_PERIOD_NS INT64_C(2000000000)
#define SAISO_BLOBS 11

typedef struct SAISOBlob {
    uint32_t va, pa, length, valid;
    uint8_t bytes[0x200];
} SAISOBlob;

typedef struct SAISORecord {
    uint64_t sequence, hit;
    uint32_t site, pc, opcode, core, global_core, regs[16], cpsr, secure, m_profile;
    uint64_t sctlr, tcr, ttbr0, ttbr1, tb_pc;
    uint32_t tb_icount, tb_cflags, insn_index, clock_valid;
    int64_t virtual_ns_before, virtual_ns;
    uint32_t control, basepri, primask, faultmask, exception, mpu_ctrl, mpu_rnr;
    uint32_t mpu_count, mpu_base[16], mpu_size[16], mpu_access[16];
    uint32_t effective_address, source_value, width, retention;
    uint32_t signature_valid;
    uint8_t signature[64];
    SAISOBlob blobs[SAISO_BLOBS];
} SAISORecord;

struct SAISOCell {
    uint64_t attempts, filtered, eligible, changes, change_overflow;
    uint64_t priority_attempts, priority_overflow, periodic_overflow, tail_overwritten;
    unsigned head_count, change_count, periodic_count, priority_count, tail_count;
    unsigned keep_count;
    bool have_signature;
    uint32_t signature_valid;
    uint8_t signature[64];
    int64_t last_period_ns;
    SAISORecord *keep, *tail;
};


static bool z6ii_boot_engine_site_enabled(Z6IIBootState *state, unsigned site)
{
    if (state->saiso_focus) {
        return site < Z6II_SAISO_SITE_COUNT && z6ii_saiso_sites[site].valid &&
               !z6ii_saiso_sites[site].m_profile;
    }
    return site && site < 230;
}

bool z6ii_boot_site_enabled(unsigned site)
{
    CPUState *cpu;
    CPU_FOREACH(cpu) {
        Z6IIBootState *state = z6ii_boot_state(z6ii_engine_for_cpu(cpu));
        if (state && state->enabled && z6ii_boot_engine_site_enabled(state, site)) { return true; }
    }
    return false;
}

static bool saiso_read(Z6IIBootState *state, const Z6IIBootRecord *walk, bool m_profile,
    uint32_t va, void *out, unsigned size, uint32_t *first_pa)
{
    if (!size || !va || va > UINT32_MAX - (size - 1)) { return false; }
    for (unsigned done = 0; done < size;) {
        uint32_t pa, address = va + done;
        unsigned take = MIN(size - done, 0x1000u - (address & 0xfffu));
        if (m_profile) {
            /* Physical Cortex-M SRAM evidence; this is not an MPU permission check. */
            pa = address;
            if (address < 0x20000000u || address > 0x2003ffffu - (take - 1)) {
                return false;
            }
        } else if (!z6ii_boot_address(state, walk, address, &pa)) { return false; }
        if (!z6ii_boot_physical_bytes(state, pa, (uint8_t *)out + done, take)) { return false; }
        if (!done && first_pa) { *first_pa = pa; }
        done += take;
    }
    return true;
}

static void saiso_blob(Z6IIBootState *state, const Z6IIBootRecord *walk, SAISORecord *r,
    unsigned index, uint32_t va, unsigned size)
{
    SAISOBlob *b = &r->blobs[index];
    b->va = va;
    b->length = size;
    if (size <= sizeof(b->bytes)) {
        b->valid = saiso_read(state, walk, r->m_profile, va, b->bytes, size, &b->pa);
    }
}

static bool saiso_overlap(uint32_t address, unsigned width, uint32_t target, unsigned size)
{
    return width && address <= UINT32_MAX - (width - 1) &&
        address < target + size && address + width > target;
}

static bool saiso_property_id(uint32_t id)
{
    return id == 0 || id == 1 || id == 4 || id == 0x1800 || id == 0x1801 ||
        id == 0x1802 || id == 0x1810;
}

static bool saiso_guard(CPUARMState *env, const Z6IISAISOSite *s, SAISORecord *r)
{
    if (arm_feature(env, ARM_FEATURE_M) || s->m_profile) { return false; }
    if (s->width) {
        uint32_t address = env->regs[s->base] + (uint32_t)s->displacement;
        if (s->index >= 0) { address += env->regs[s->index] << s->shift; }
        r->effective_address = address;
        r->source_value = env->regs[s->source];
        r->width = s->width;
        if (s->m_profile) {
            const uint32_t fields[] = {0x2001f692, 0x2001f695, 0x2001f698,
                0x2001f69a, 0x2001f6a2, 0x2001f740, 0x2001f748};
            for (unsigned i = 0; i < ARRAY_SIZE(fields); i++) {
                if (saiso_overlap(address, s->width, fields[i], i >= 5 ? 4 : 1)) { return true; }
            }
            return false;
        }
        return saiso_overlap(address, s->width, 0xc181dabdu, 1) ||
            saiso_overlap(address, s->width, 0xc181da50u, 1) ||
            saiso_overlap(address, s->width, 0xc181d348u, 4) ||
            saiso_overlap(address, s->width, 0xc18694b1u, 1) ||
            saiso_overlap(address, s->width, 0xc253dc28u, 12) ||
            saiso_overlap(address, s->width, 0xc253dc68u, 4) ||
            saiso_overlap(address, s->width, 0xc253d7f4u, 12) ||
            saiso_overlap(address, s->width, 0xc253d804u, 4) ||
            saiso_overlap(address, s->width, 0xc202c0acu, 8);
    }
    switch (s->guard) {
    case 1: return saiso_property_id(env->regs[0]);
    case 2: return env->regs[1] <= 31u && env->regs[0] == 0xc181d9e4u + env->regs[1] * 4u;
    case 3: return env->regs[0] == 0x430c0003u;
    case 4: return env->regs[0] == 0x103efb85u;
    case 5: return env->regs[0] == 0xc181d9e4u;
    case 6: return env->regs[1] == 0x800u;
    default: return true;
    }
}

static void saiso_context(Z6IIBootState *state, CPUARMState *env, SAISORecord *r, Z6IIBootRecord *walk,
    void *tb_opaque, uint32_t instruction_index)
{
    CPUState *cpu = env_cpu(env);
    r->core = cpu->cpu_index - state->engine->cpu_base;
    r->global_core = cpu->cpu_index;
    r->m_profile = arm_feature(env, ARM_FEATURE_M);
    for (unsigned i = 0; i < 16; i++) { r->regs[i] = env->regs[i]; }
    if (r->m_profile) {
        /* Cortex-M context has no A15 CP15 bank or short-descriptor page tables. */
        unsigned bank = M_REG_NS;
        r->cpsr = xpsr_read(env);
        r->control = env->v7m.control[bank];
        r->basepri = env->v7m.basepri[bank];
        r->primask = env->v7m.primask[bank];
        r->faultmask = env->v7m.faultmask[bank];
        r->exception = env->v7m.exception;
        r->mpu_ctrl = env->v7m.mpu_ctrl[bank];
        r->mpu_rnr = env->pmsav7.rnr[bank];
        r->mpu_count = MIN(ARM_CPU(cpu)->pmsav7_dregion, 16);
        for (unsigned i = 0; i < r->mpu_count; i++) {
            r->mpu_base[i] = env->pmsav7.drbar[i];
            r->mpu_size[i] = env->pmsav7.drsr[i];
            r->mpu_access[i] = env->pmsav7.dracr[i];
        }
    } else {
        r->cpsr = cpsr_read(env);
        r->secure = arm_is_secure(env);
        unsigned bank = r->secure ? 3 : 1;
        r->sctlr = walk->sctlr = env->cp15.sctlr_el[bank];
        r->tcr = walk->tcr = env->cp15.tcr_el[bank];
        r->ttbr0 = walk->ttbr0 = env->cp15.ttbr0_el[bank];
        r->ttbr1 = walk->ttbr1 = env->cp15.ttbr1_el[bank];
    }
    const TranslationBlock *tb = tb_opaque;
    r->tb_pc = tb ? tb->pc : 0;
    r->tb_icount = tb ? tb->icount : 0;
    r->tb_cflags = tb ? tb_cflags(tb) : 0;
    r->insn_index = instruction_index;
    r->virtual_ns_before = r->virtual_ns = -1;
    if (tb && (r->tb_cflags & CF_USE_ICOUNT)) {
        ICountInstructionTime clock;
        r->clock_valid = icount_read_only_instruction_time(cpu, tb->icount, instruction_index, &clock);
        if (r->clock_valid) {
            r->virtual_ns_before = clock.virtual_ns_before;
            r->virtual_ns = clock.virtual_ns_inclusive;
        }
    }
}

static void saiso_signature(Z6IIBootState *state, const Z6IIBootRecord *walk, SAISORecord *r,
    const Z6IISAISOSite *site)
{
    const uint32_t master_va[] = {0xc253dc28, 0xc253dc68, 0xc18694b0,
        0xc181da50, 0xc181dabd, 0xc181d348, 0xc202c0ac, 0xc202bf48, 0xc253d7f4};
    const unsigned master_len[] = {12, 4, 4, 1, 1, 4, 8, 1, 12};
    const uint32_t mcu_va[] = {0x2001f692, 0x2001f695, 0x2001f698,
        0x2001f69a, 0x2001f6a2, 0x2001f740, 0x2001f748};
    unsigned offset = 0;
    for (unsigned i = 0; i < (r->m_profile ? ARRAY_SIZE(mcu_va) : ARRAY_SIZE(master_va)); i++) {
        unsigned size = r->m_profile ? (i >= 5 ? 4 : 1) : master_len[i];
        uint32_t va = r->m_profile ? mcu_va[i] : master_va[i];
        if (saiso_read(state, walk, r->m_profile, va, r->signature + offset, size, NULL)) {
            r->signature_valid |= 1u << i;
        }
        offset += size;
    }
    if (site->width) {
        stl_le_p(r->signature + 48, r->effective_address);
        stl_le_p(r->signature + 52, r->source_value);
    } else if (site->guard == 1 || site->guard == 3 || site->guard == 4 || site->guard == 6) {
        stl_le_p(r->signature + 48, r->regs[0]);
        stl_le_p(r->signature + 52, r->regs[1]);
    }
}

static void saiso_capture(Z6IIBootState *state, const Z6IIBootRecord *walk, SAISORecord *r)
{
    if (r->m_profile) {
        saiso_blob(state, walk, r, 0, 0x2001f688u, 0xe0);
    } else {
        saiso_blob(state, walk, r, 0, 0xc253dc28u, 12);
        saiso_blob(state, walk, r, 1, 0xc253dc68u, 4);
        saiso_blob(state, walk, r, 2, 0xc18694b0u, 0xc0);
        saiso_blob(state, walk, r, 3, 0xc181d9e4u, 0xe4);
        saiso_blob(state, walk, r, 4, 0xc181d330u, 0x40);
        saiso_blob(state, walk, r, 5, 0xc202bf40u, 0x200);
        saiso_blob(state, walk, r, 6, 0xc253d7f4u, 20);
    }
    saiso_blob(state, walk, r, 7, r->regs[13], 128);
    saiso_blob(state, walk, r, 8, r->regs[0], 64);
    saiso_blob(state, walk, r, 9, r->regs[1], 64);
    saiso_blob(state, walk, r, 10, r->effective_address, r->width);
}

static void z6ii_saiso_observe(Z6IIBootState *state, CPUARMState *env, uint32_t pc, uint32_t opcode,
    void *tb_opaque, uint32_t instruction_index)
{
    unsigned site = z6ii_boot_site_id(pc, opcode);
    if (!site || !z6ii_boot_engine_site_enabled(state, site)) { return; }
    unsigned core = env_cpu(env)->cpu_index - state->engine->cpu_base;
    qemu_mutex_lock(&state->saiso_mutex);
    if (core >= SAISO_CORES) { state->saiso_bad_core++; qemu_mutex_unlock(&state->saiso_mutex); return; }
    SAISOCell *cell = state->saiso_cells[site][core];
    if (!cell) {
        cell = state->saiso_cells[site][core] = g_new0(SAISOCell, 1);
        cell->last_period_ns = -1;
    }
    uint64_t hit = ++cell->attempts;
    SAISORecord r = { .site = site, .pc = pc, .opcode = opcode, .core = core, .hit = hit };
    const Z6IISAISOSite *info = &z6ii_saiso_sites[site];
    if (!saiso_guard(env, info, &r)) {
        cell->filtered++;
        qemu_mutex_unlock(&state->saiso_mutex);
        return;
    }
    cell->eligible++;
    if (!cell->keep) {
        cell->keep = g_new0(SAISORecord, SAISO_KEEP);
        cell->tail = g_new0(SAISORecord, SAISO_TAIL);
    }
    r.sequence = ++state->saiso_sequence;
    Z6IIBootRecord walk = {0};
    saiso_context(state, env, &r, &walk, tb_opaque, instruction_index);
    saiso_signature(state, &walk, &r, info);
    bool changed = !cell->have_signature || cell->signature_valid != r.signature_valid ||
        memcmp(cell->signature, r.signature, sizeof(r.signature));
    if (changed) {
        cell->changes++;
        cell->have_signature = true;
        cell->signature_valid = r.signature_valid;
        memcpy(cell->signature, r.signature, sizeof(r.signature));
    }
    bool priority = !r.m_profile && ((info->guard == 2 && r.regs[4] == 0x0410000du) ||
        (r.effective_address == 0xc18694b1u && changed));
    bool periodic = r.clock_valid && (cell->last_period_ns < 0 ||
        r.virtual_ns - cell->last_period_ns >= SAISO_PERIOD_NS);
    if (periodic) { cell->last_period_ns = r.virtual_ns; }
    if (cell->head_count < SAISO_HEAD) { cell->head_count++; r.retention |= 1; }
    if (changed) {
        if (cell->change_count < SAISO_CHANGE) { cell->change_count++; r.retention |= 2; }
        else { cell->change_overflow++; }
    }
    if (periodic) {
        if (cell->periodic_count < SAISO_PERIODIC) { cell->periodic_count++; r.retention |= 4; }
        else { cell->periodic_overflow++; }
    }
    if (priority) {
        cell->priority_attempts++;
        if (cell->priority_count < SAISO_PRIORITY) { cell->priority_count++; r.retention |= 8; }
        else { cell->priority_overflow++; }
    }
    saiso_capture(state, &walk, &r);
    if (r.retention) { cell->keep[cell->keep_count++] = r; }
    unsigned tail = (cell->eligible - 1) % SAISO_TAIL;
    if (cell->tail_count < SAISO_TAIL) { cell->tail_count++; }
    else { cell->tail_overwritten++; }
    r.retention = 16;
    cell->tail[tail] = r;
    qemu_mutex_unlock(&state->saiso_mutex);
}

static void saiso_print(Z6IIBootState *state, FILE *out, const SAISORecord *r)
{
    const Z6IISAISOSite *s = &z6ii_saiso_sites[r->site];
    fprintf(out, "Z6II_SAISO_OBS role=%s sequence=%" PRIu64 " site_id=%u site=%s"
        " hit=%" PRIu64 " core=%u global_core=%u pc=%08x opcode=%08x phase=%s retention=%u"
        " m_profile=%u cpsr_xpsr=%08x secure=%u sctlr=%016" PRIx64
        " tcr=%016" PRIx64 " ttbr0=%016" PRIx64 " ttbr1=%016" PRIx64
        " tb_pc=%" PRIx64 " tb_icount=%u tb_cflags=%08x insn_index=%u clock_valid=%u"
        " virtual_ns_before=%" PRId64 " virtual_ns=%" PRId64
        " effective_address=%08x source_value=%08x width=%u signature_valid=%08x",
        state->role, r->sequence, r->site, s->name, r->hit, r->core, r->global_core, r->pc, r->opcode,
        s->phase ? "adjacent_following_instruction" : "before_original_instruction",
        r->retention, r->m_profile, r->cpsr, r->secure, r->sctlr, r->tcr, r->ttbr0, r->ttbr1,
        r->tb_pc, r->tb_icount, r->tb_cflags, r->insn_index, r->clock_valid,
        r->virtual_ns_before, r->virtual_ns, r->effective_address, r->source_value,
        r->width, r->signature_valid);
    for (unsigned i = 0; i < 16; i++) { fprintf(out, " r%u=%08x", i, r->regs[i]); }
    if (r->m_profile) {
        fprintf(out, " control=%08x basepri=%08x primask=%08x faultmask=%08x exception=%u"
            " mpu_ctrl=%08x mpu_rnr=%u mpu_count=%u", r->control, r->basepri, r->primask,
            r->faultmask, r->exception, r->mpu_ctrl, r->mpu_rnr, r->mpu_count);
        for (unsigned i = 0; i < r->mpu_count; i++) {
            fprintf(out, " mpu%u_base=%08x mpu%u_size=%08x mpu%u_access=%08x",
                i, r->mpu_base[i], i, r->mpu_size[i], i, r->mpu_access[i]);
        }
    }
    const char *names[] = {r->m_profile ? "mcu_power" : "properties180x", "property1810",
        "sysctl", "applv", "flags", "shared", "properties014", "stack", "input_r0", "input_r1", "destination"};
    for (unsigned i = 0; i < SAISO_BLOBS; i++) {
        const SAISOBlob *b = &r->blobs[i];
        fprintf(out, " %s_va=%08x %s_pa=%08x %s_length=%u %s_valid=%u %s_hex=",
            names[i], b->va, names[i], b->pa, names[i], b->length, names[i], b->valid, names[i]);
        if (!b->valid) { fputc('-', out); }
        else { for (unsigned j = 0; j < b->length; j++) { fprintf(out, "%02x", b->bytes[j]); } }
    }
    fputc('\n', out);
}

static void z6ii_saiso_flush(Z6IIBootState *state, FILE *out)
{
    qemu_mutex_lock(&state->saiso_mutex);
    uint64_t attempts = 0, eligible = 0, filtered = 0, written = 0, overwritten = 0;
    for (unsigned site = 0; site < Z6II_SAISO_SITE_COUNT; site++) {
        if (!z6ii_saiso_sites[site].valid) { continue; }
        for (unsigned core = 0; core < SAISO_CORES; core++) {
            const SAISOCell *c = state->saiso_cells[site][core];
            if (!c) { continue; }
            for (unsigned i = 0; i < c->keep_count; i++) { saiso_print(state, out, &c->keep[i]); }
            for (unsigned i = 0; i < c->tail_count; i++) { saiso_print(state, out, &c->tail[i]); }
            fprintf(out, "Z6II_SAISO_SITE site_id=%u site=%s core=%u attempts=%" PRIu64
                " filtered=%" PRIu64 " eligible=%" PRIu64 " kept=%u tail=%u changes=%" PRIu64
                " change_overflow=%" PRIu64 " priority_attempts=%" PRIu64 " priority_overflow=%" PRIu64
                " periodic_overflow=%" PRIu64 " tail_overwritten=%" PRIu64 "\n",
                site, z6ii_saiso_sites[site].name, core, c->attempts, c->filtered, c->eligible,
                c->keep_count, c->tail_count, c->changes, c->change_overflow,
                c->priority_attempts, c->priority_overflow, c->periodic_overflow, c->tail_overwritten);
            attempts += c->attempts; filtered += c->filtered; eligible += c->eligible;
            written += c->keep_count + c->tail_count; overwritten += c->tail_overwritten;
        }
    }
    fprintf(out, "Z6II_SAISO_SUMMARY schema=1 attempts=%" PRIu64 " filtered=%" PRIu64
        " eligible=%" PRIu64 " written=%" PRIu64 " tail_overwritten=%" PRIu64
        " bad_core=%" PRIu64 " guest_writes=0 ordinary_RAM_only=1 MMIO_and_copy_lanes=0"
        " retention=head8_changes96_period2s192_priority64_tail8 per_site_per_core=1"
        " pre_instruction=1 tail_may_duplicate_keep=1 permission_translation_verified=0"
        " global_causality_verified=0 peer_clocks_synchronized=%u clock=QEMU_CLOCK_VIRTUAL\n",
        attempts, filtered, eligible, written, overwritten, state->saiso_bad_core, state->engine->unified);
    qemu_mutex_unlock(&state->saiso_mutex);
}
