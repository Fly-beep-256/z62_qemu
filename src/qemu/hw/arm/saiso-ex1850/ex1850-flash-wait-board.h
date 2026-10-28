/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef EX1850_FLASH_WAIT_BOARD_H
#define EX1850_FLASH_WAIT_BOARD_H

static bool ex1850_flash_wait_has_work(CPUState *cs)
{
    EX1850M4R0P1 *mcu = (EX1850M4R0P1 *)cs;
    if (mcu->wait.active) {
        /* IRQ delivery cannot interrupt an unfinished single bus transfer.
         * Timers and NVIC pending state still advance in the main loop. */
        mcu->wait.pending_seen |= cs->interrupt_request;
        return false;
    }
    return ex1850_power_has_work(cs);
}

static bool ex1850_flash_wait_exec_halt(CPUState *cs)
{
    EX1850M4R0P1 *mcu = (EX1850M4R0P1 *)cs;
    if (mcu->wait.active) {
        mcu->wait.pending_seen |= cs->interrupt_request;
        return false;
    }
    bool leave = ex1850_parent_tcg_ops->cpu_exec_halt(cs);
    if (leave) { ex1850_power_resume(cs); }
    return leave;
}

static void ex1850_flash_wait_release(EX1850ResetState *s)
{
    if (!s->armv7m) { return; }
    EX1850M4R0P1 *mcu = (EX1850M4R0P1 *)s->armv7m->cpu;
    EX1850FlashWait *wait = &mcu->wait;
    if (!wait->active) { return; }
    CPUState *cs = CPU(&mcu->parent);
    CPUARMState *env = &mcu->parent.env;
    uint16_t insn = lduw_le_p((uint8_t *)memory_region_get_ram_ptr(&s->ram) +
                             wait->decoded.pc - EX1850_RAM_BASE);
    if ((s->flash.sr & EX1850_FLASH_BSY) ||
        s->flash.completed != wait->completed_before + 1 ||
        s->flash.last_commit.due != wait->due ||
        qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) < wait->due ||
        !cs->halted || memcmp(wait->regs, env->regs, sizeof(wait->regs)) ||
        wait->xpsr != xpsr_read(env) || insn != wait->decoded.insn) {
        ex1850_flash_boundary(&s->flash, "wait-context-or-completion-contract-changed");
        ex1850_flash_stop(s, wait->decoded.address, 4, wait->decoded.write,
                          wait->decoded.word);
    }
    uint32_t pending = cs->interrupt_request;
    uint32_t seen = wait->pending_seen | pending;
    wait->active = false;
    /* Preserve normal icount accounting. This single restart executes before
     * pending IRQ entry; no guest register or callback is manufactured. The
     * next ordinary TB restores normal interrupt and WFI behavior. */
    cs->cflags_next_tb = (curr_cflags(cs) & ~CF_COUNT_MASK) |
                        CF_MEMI_ONLY | CF_NOIRQ | 1;
    cpu_interrupt(cs, CPU_INTERRUPT_EXITTB);
    fprintf(stderr, "EX1850_FLASH_RESUME addr=%08x pc=%08x insn=%04x "
            "write=%u due_ns=%" PRId64 " virtual_ns=%" PRId64
            " completed=%" PRIu64 " pending_IRQ_mask=%08x "
            "pending_seen_mask=%08x wait_arch_context_unchanged=1 "
            "original_instruction_retry_requested=1 retry_before_IRQ=1 "
            "guest_register_or_callback_injected=0\n",
            wait->decoded.address, wait->decoded.pc, wait->decoded.insn,
            wait->decoded.write, wait->due, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
            s->flash.completed, pending, seen);
}

static void ex1850_flash_before_mmio(CPUState *cs, MMUAccessType type,
    vaddr address, MemoryRegion *mr, hwaddr offset, unsigned size,
    uint64_t value, uintptr_t ra)
{
    EX1850M4R0P1 *mcu = (EX1850M4R0P1 *)cs;
    EX1850ResetState *s = mcu->board;
    if (!s || !(s->flash.sr & EX1850_FLASH_BSY)) { return; }
    bool array = mr == &s->rom;
    bool cr_write = mr == &s->flash_registers &&
                    type == MMU_DATA_STORE && (offset & ~3ULL) == 0x10;
    if (!array && !cr_write) { return; }
    if (qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) >= s->flash.pending.due) {
        ex1850_flash_sync(s);
        return;
    }
    const char *reason = NULL;
    if (mcu->wait.active) {
        reason = "wait-reentrant-CPU-access";
    } else if ((type != MMU_DATA_LOAD && type != MMU_DATA_STORE) || !ra) {
        reason = "wait-access-without-data-TCG-return-address";
    } else if (!cpu_restore_state(cs, ra)) {
        reason = "wait-TCG-return-address-not-restorable";
    }
    CPUARMState *env = &mcu->parent.env;
    uint32_t pc = env->regs[15];
    EX1850FlashWaitInsn decoded;
    if (!reason && (pc < EX1850_RAM_BASE ||
                    pc > EX1850_RAM_BASE + EX1850_RAM_BYTES - 2 || (pc & 1))) {
        reason = "wait-instruction-outside-aligned-SRAM";
    }
    if (!reason) {
        uint16_t insn = lduw_le_p((uint8_t *)memory_region_get_ram_ptr(&s->ram) +
                                 pc - EX1850_RAM_BASE);
        reason = ex1850_flash_wait_decode(&decoded, pc, env->thumb,
            env->condexec_bits, insn, env->regs, address, size,
            type == MMU_DATA_STORE, value);
    }
    if (!reason && array &&
        !((address < EX1850_BYTES && offset == address) ||
          (address >= EX1850_BASE && address < EX1850_BASE + EX1850_BYTES &&
           offset == address - EX1850_BASE))) {
        reason = "wait-array-alias-offset-mismatch";
    }
    if (!reason && cr_write && (address != 0x40023c10 || offset != 0x10)) {
        reason = "wait-CR-offset-mismatch";
    }
    if (reason) {
        ex1850_flash_boundary(&s->flash, reason);
        ex1850_flash_stop(s, array ? EX1850_BASE + offset : 0x40023c00 + offset,
                          size, type == MMU_DATA_STORE, value);
    }
    EX1850FlashWait *wait = &mcu->wait;
    wait->decoded = decoded;
    memcpy(wait->regs, env->regs, sizeof(wait->regs));
    wait->xpsr = xpsr_read(env);
    wait->completed_before = s->flash.completed;
    wait->due = s->flash.pending.due;
    wait->pending_seen = cs->interrupt_request;
    wait->active = true;
    cs->halted = 1;
    cs->exception_index = EXCP_HLT;
    fprintf(stderr, "EX1850_FLASH_STALL addr=%08x device_offset=%08" HWADDR_PRIx
            " pc=%08x insn=%04x size=%u write=%u Rn=%u Rt=%u "
            "word=%08x due_ns=%" PRId64 " virtual_ns=%" PRId64
            " SR=%08x CR=%08x pending_IRQ_mask=%08x "
            "state_restored_once=1 array_or_CR_access_committed=0 "
            "peripheral_time_continues=1 IRQ_delivery_deferred=1\n",
            decoded.address, offset, decoded.pc, decoded.insn, size, decoded.write,
            decoded.rn, decoded.rt, decoded.word, wait->due,
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), s->flash.sr, s->flash.cr,
            wait->pending_seen);
    /* cpu_restore_state above already repaired icount. Do not restore twice. */
    cpu_loop_exit(cs);
}

#endif
