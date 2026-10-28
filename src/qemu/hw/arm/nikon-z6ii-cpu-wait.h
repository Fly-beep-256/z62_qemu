/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef NIKON_Z6II_CPU_WAIT_H
#define NIKON_Z6II_CPU_WAIT_H

#define TYPE_Z6II_A15 ARM_CPU_TYPE_NAME("nikon-z6ii-a15")

typedef struct Z6IIWireReadWait {
    bool active;
    Z6IIEngineContext *engine;
    hwaddr physical_address;
    vaddr address;
    uint32_t needed, regs[16], cpsr, pending_seen;
    uint8_t instruction[4];
    unsigned instruction_bytes;
    int64_t begin, deadline;
} Z6IIWireReadWait;

typedef struct Z6IIA15CPU {
    ARMCPU parent;
    Z6IIWireReadWait wait;
    QEMUTimer *wait_timer;
    uint64_t system_reset_count;
    int64_t last_system_reset_ns;
} Z6IIA15CPU;

static const SysemuCPUOps *z6ii_a15_parent_sysemu_ops;
static const TCGCPUOps *z6ii_a15_parent_tcg_ops;
static SysemuCPUOps z6ii_a15_sysemu_ops;
static TCGCPUOps z6ii_a15_tcg_ops;

/* Retrying a multi-transfer instruction could repeat an earlier side effect.
 * Only a single scalar LDR without base writeback is allowed to stall. The
 * original instruction is read from this CPU's virtual code address, never
 * guessed from the MMIO dispatch width. */
static bool z6ii_wire_wait_instruction(CPUState *cs, Z6IIWireReadWait *wait)
{
    CPUARMState *env = &ARM_CPU(cs)->env;
    if (cpu_memory_rw_debug(cs, env->regs[15], wait->instruction, 4, false)) {
        return false;
    }
    uint16_t first = lduw_le_p(wait->instruction);
    uint16_t second = lduw_le_p(wait->instruction + 2);
    if (env->thumb) {
        wait->instruction_bytes = 2;
        if ((first & 0xf800) == 0x6800 ||
            (first & 0xfe00) == 0x5800 ||
            (first & 0xf800) == 0x9800 ||
            (first & 0xf800) == 0x4800) {
            return true;
        }
        wait->instruction_bytes = 4;
        if ((second >> 12) == 15) { return false; }
        return (first & 0xfff0) == 0xf8d0 ||
               ((first & 0xfff0) == 0xf850 &&
                ((second & 0x0fc0) == 0 ||
                 (second & 0x0d00) == 0x0c00));
    }
    uint32_t insn = ldl_le_p(wait->instruction);
    wait->instruction_bytes = 4;
    return (insn & 0x0d700000) == 0x05100000 &&
           ((insn >> 12) & 15) != 15;
}

static bool z6ii_a15_has_work(CPUState *cs)
{
    Z6IIA15CPU *cpu = (Z6IIA15CPU *)cs;
    if (cpu->wait.active) {
        cpu->wait.pending_seen |= cs->interrupt_request;
        return false;
    }
    return z6ii_a15_parent_sysemu_ops->has_work(cs);
}

static bool z6ii_a15_exec_halt(CPUState *cs)
{
    Z6IIA15CPU *cpu = (Z6IIA15CPU *)cs;
    if (cpu->wait.active) {
        cpu->wait.pending_seen |= cs->interrupt_request;
        return false;
    }
    return z6ii_a15_parent_tcg_ops->cpu_exec_halt(cs);
}

static void z6ii_a15_wait_poll(void *opaque)
{
    Z6IIA15CPU *cpu = opaque;
    CPUState *cs = CPU(&cpu->parent);
    Z6IIWireReadWait *wait = &cpu->wait;
    if (!wait->active) { return; }
    Z6IIState *board = wait->engine->board;
    Z6IIFunctionalDevices *devices = board->devices;
    CPUARMState *env = &cpu->parent.env;
    MCUWireCore snapshot;
    int have_snapshot = mcu_wire_try_snapshot(devices->mcu_wire.bus, &snapshot);
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    wait->pending_seen |= cs->interrupt_request;
    if (!have_snapshot || (snapshot.mcu_known & wait->needed) != wait->needed) {
        if (now < wait->deadline) {
            timer_mod(cpu->wait_timer,
                       MIN(now + devices->mcu_wire_poll_ns, wait->deadline));
            return;
        }
        error_report("Z62_WIRE_VIRTUAL_WAIT_TIMEOUT role=%s cpu=%d pc=%08x "
                     "addr=%08" HWADDR_PRIx " needed=%08x known=%08x "
                     "begin_ns=%" PRId64 " virtual_ns=%" PRId64 " "
                     "GPIO_level_supplied=0 guest_state_injected=0",
                     wait->engine->role, cs->cpu_index, wait->regs[15],
                     wait->physical_address, wait->needed,
                     have_snapshot ? snapshot.mcu_known : 0, wait->begin, now);
        z6ii_wire_stop("virtual GPIO wait expired before actual MCU output");
    }
    uint8_t instruction[4];
    if (!cs->halted || memcmp(wait->regs, env->regs, sizeof(wait->regs)) ||
        wait->cpsr != cpsr_read(env) ||
        cpu_memory_rw_debug(cs, wait->regs[15], instruction,
                             wait->instruction_bytes, false) ||
        memcmp(instruction, wait->instruction, wait->instruction_bytes)) {
        z6ii_wire_stop("suspended original E6 load context changed");
    }
    wait->active = false;
    /* This wake comes from an actual MCU output, independent of IRQ level. */
    cs->halted = 0;
    /* Only the original load executes before pending IRQ entry. Its normal
     * MMIO callback supplies the actual MCU line value on the retry. */
    cs->cflags_next_tb = (curr_cflags(cs) & ~CF_COUNT_MASK) |
                        CF_MEMI_ONLY | CF_NOIRQ | 1;
    cpu_interrupt(cs, CPU_INTERRUPT_EXITTB);
    fprintf(stderr, "Z62_WIRE_VIRTUAL_WAIT_RESUME role=%s cpu=%d pc=%08x "
            "addr=%08" HWADDR_PRIx " needed=%08x known=%08x level=%08x "
            "begin_ns=%" PRId64 " virtual_ns=%" PRId64 " "
            "pending_IRQ_mask=%08x original_load_retry=1 "
            "wait_arch_context_unchanged=1 MCU_actual_store_required=1 "
            "host_sleep=0 guest_state_injected=0\n",
            wait->engine->role, cs->cpu_index, wait->regs[15],
            wait->physical_address, wait->needed, snapshot.mcu_known,
            snapshot.mcu_level, wait->begin, now, wait->pending_seen);
}

static void z6ii_a15_before_mmio(CPUState *cs, MMUAccessType type,
    vaddr address, MemoryRegion *mr, hwaddr offset, unsigned size,
    uint64_t value, uintptr_t ra)
{
    Z6IIEngineContext *engine = z6ii_engine_for_cpu(cs);
    if (!engine || !engine->unified) { return; }
    Z6IIState *board = engine->board;
    Z6IIFunctionalDevices *devices = board->devices;
    if (!devices || !devices->mcu_wire.bus ||
        !devices->mcu_wire_known_wait_ms || mr != &board->unknown ||
        type != MMU_DATA_LOAD || size != 4 ||
        (offset != 0x04282014 && offset != 0x04282018)) {
        return;
    }
    uint32_t needed = offset == 0x04282014 ? 5 : 2;
    MCUWireCore snapshot;
    if (mcu_wire_try_snapshot(devices->mcu_wire.bus, &snapshot) &&
        (snapshot.mcu_known & needed) == needed) {
        return;
    }
    Z6IIA15CPU *cpu = (Z6IIA15CPU *)cs;
    Z6IIWireReadWait *wait = &cpu->wait;
    if (wait->active || !ra || !cpu_restore_state(cs, ra) ||
        !z6ii_wire_wait_instruction(cs, wait)) {
        z6ii_wire_stop("unresolved GPIO read is not a restorable scalar E6 load");
    }
    CPUARMState *env = &cpu->parent.env;
    wait->engine = engine;
    wait->address = address;
    wait->physical_address = offset;
    wait->needed = needed;
    memcpy(wait->regs, env->regs, sizeof(wait->regs));
    wait->cpsr = cpsr_read(env);
    wait->pending_seen = cs->interrupt_request;
    wait->begin = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    wait->deadline = wait->begin +
                     devices->mcu_wire_known_wait_ms * INT64_C(1000000);
    wait->active = true;
    if (!cpu->wait_timer) {
        cpu->wait_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                        z6ii_a15_wait_poll, cpu);
    }
    timer_mod(cpu->wait_timer,
               MIN(wait->begin + devices->mcu_wire_poll_ns, wait->deadline));
    cs->halted = 1;
    cs->exception_index = EXCP_HLT;
    fprintf(stderr, "Z62_WIRE_VIRTUAL_WAIT_BEGIN role=%s cpu=%d pc=%08x "
            "addr=%08" HWADDR_PRIx " vaddr=%08" VADDR_PRIx " needed=%08x "
            "begin_ns=%" PRId64 " deadline_ns=%" PRId64 " "
            "state_restored_once=1 load_committed=0 other_CPUs_continue=1 "
            "IRQ_delivery_deferred=1 virtual_bus_wait_hypothesis=1 "
            "physical_reset_gating_verified=0\n",
            engine->role, cs->cpu_index, env->regs[15], offset, address,
            needed, wait->begin, wait->deadline);
    /* cpu_restore_state already repaired icount; do not restore twice. */
    cpu_loop_exit(cs);
}

static void z6ii_a15_wait_reset(void *opaque)
{
    Z6IIA15CPU *cpu = opaque;
    if (cpu->wait_timer) { timer_del(cpu->wait_timer); }
    cpu->wait.active = false;
    cpu->system_reset_count++;
    cpu->last_system_reset_ns = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
}

static void z6ii_a15_instance_init(Object *obj)
{
    qemu_register_reset(z6ii_a15_wait_reset, obj);
}

static void z6ii_a15_instance_finalize(Object *obj)
{
    Z6IIA15CPU *cpu = (Z6IIA15CPU *)obj;
    qemu_unregister_reset(z6ii_a15_wait_reset, obj);
    if (cpu->wait_timer) { timer_free(cpu->wait_timer); }
}

static void z6ii_a15_class_init(ObjectClass *klass, const void *data)
{
    CPUClass *cc = CPU_CLASS(klass);
    z6ii_a15_parent_sysemu_ops = cc->sysemu_ops;
    z6ii_a15_parent_tcg_ops = cc->tcg_ops;
    g_assert(z6ii_a15_parent_sysemu_ops && z6ii_a15_parent_tcg_ops);
    z6ii_a15_sysemu_ops = *z6ii_a15_parent_sysemu_ops;
    z6ii_a15_tcg_ops = *z6ii_a15_parent_tcg_ops;
    g_assert(!z6ii_a15_tcg_ops.before_mmio);
    z6ii_a15_sysemu_ops.has_work = z6ii_a15_has_work;
    z6ii_a15_tcg_ops.cpu_exec_halt = z6ii_a15_exec_halt;
    z6ii_a15_tcg_ops.before_mmio = z6ii_a15_before_mmio;
    cc->sysemu_ops = &z6ii_a15_sysemu_ops;
    cc->tcg_ops = &z6ii_a15_tcg_ops;
}

static void z6ii_a15_register_type(void)
{
    static const TypeInfo info = {
        .name = TYPE_Z6II_A15,
        .parent = ARM_CPU_TYPE_NAME("cortex-a15"),
        .instance_size = sizeof(Z6IIA15CPU),
        .instance_init = z6ii_a15_instance_init,
        .instance_finalize = z6ii_a15_instance_finalize,
        .class_init = z6ii_a15_class_init,
    };
    type_register_static(&info);
}
type_init(z6ii_a15_register_type)

#endif
