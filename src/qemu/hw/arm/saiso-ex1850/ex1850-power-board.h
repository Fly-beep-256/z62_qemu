/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef EX1850_POWER_BOARD_H
#define EX1850_POWER_BOARD_H

static bool ex1850_sleep_control_write(void *opaque, uint32_t value)
{
    EX1850ResetState *s = opaque;
    if (!ex1850_power_scr(&s->power, value)) {
        fprintf(stderr, "EX1850_POWER_BOUNDARY reason=unsupported-SCR requested=%08x\n", value);
        ex1850_unknown_access(s, 0xe000ed10, 4, true, value);
    }
    fprintf(stderr, "EX1850_SCR requested=%08x PWR_CR=%08x pc=%08x "
            "virtual_ns=%" PRId64 " STOP_entered=%u entries=%" PRIu64
            " wakes=%" PRIu64 " source=original_SCR_write\n",
            value, s->pwr_cr, ex1850_pc(), qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
            s->power.stopped, s->power.entries, s->power.wakes);
    return true; /* NVIC stores the original SCR bits without stock RAZ/WI. */
}

static bool ex1850_power_has_work(CPUState *cs)
{
    EX1850M4R0P1 *mcu = (EX1850M4R0P1 *)cs;
    EX1850ResetState *s = mcu->board;
    if (!s || !s->power.stopped) {
        return ex1850_parent_sysemu_ops->has_work(cs);
    }
    /* EXITTB is host scheduling, not an electrical wake source. NVIC
     * chooses enabled pending exceptions; exception entry remains QEMU's. */
    return s->armv7m->nvic.vectpending != 0 &&
           ex1850_parent_sysemu_ops->has_work(cs) &&
           (cs->interrupt_request & (CPU_INTERRUPT_HARD | CPU_INTERRUPT_NMI));
}

static void ex1850_power_exec_exit(CPUState *cs)
{
    if (ex1850_parent_tcg_ops->cpu_exec_exit) {
        ex1850_parent_tcg_ops->cpu_exec_exit(cs);
    }
    EX1850M4R0P1 *mcu = (EX1850M4R0P1 *)cs;
    EX1850ResetState *s = mcu->board;
    if (!s || mcu->wait.active || s->power.stopped ||
        !(s->power.scr & 4)) { return; }
    BQL_LOCK_GUARD();
    uint32_t next_pc = mcu->parent.env.regs[15];
    uint16_t insn = 0;
    if (next_pc >= EX1850_BASE + 2 && next_pc <= EX1850_BASE + EX1850_BYTES) {
        insn = lduw_le_p((uint8_t *)memory_region_get_ram_ptr(&s->rom) +
                         next_pc - EX1850_BASE - 2);
    } else if (next_pc >= EX1850_RAM_BASE + 2 &&
               next_pc <= EX1850_RAM_BASE + EX1850_RAM_BYTES) {
        insn = lduw_le_p((uint8_t *)memory_region_get_ram_ptr(&s->ram) +
                         next_pc - EX1850_RAM_BASE - 2);
    }
    if (mcu->parent.env.thumb && insn == 0xbf20) {
        /* Stock QEMU implements WFE as yield. It must not silently skip
         * an unimplemented deep event sleep on this isolated board. */
        fprintf(stderr, "EX1850_POWER_BOUNDARY reason=deep-WFE-not-modeled "
                "next_pc=%08x\n", next_pc);
        ex1850_unknown_access(s, 0xe000ed10, 4, true, s->power.scr);
    }
    if (!cs->halted) { return; }
    /* Finish elapsed work under the old clocks before gating. */
    ex1850_sync_timer_clocks(s, "STOP_WFI_entry");
    ex1850_flash_sync(s);
    const char *reason = NULL;
    if (s->adc_busy || (s->flash.sr & EX1850_FLASH_BSY) ||
        s->i2c_pending_phase || s->i2c_rx_in_flight || s->i2c_tx_count ||
        (s->i2c1.sr2 & 2) || (s->i2c2.sr2 & 2)) {
        reason = "STOP-with-active-unmodeled-ADC-Flash-I2C";
    } else {
        reason = ex1850_power_enter(&s->power, s->pwr_cr, insn,
            mcu->parent.env.thumb, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    }
    if (reason) {
        fprintf(stderr, "EX1850_POWER_BOUNDARY reason=%s next_pc=%08x insn=%04x\n",
                reason, next_pc, insn);
        ex1850_unknown_access(s, 0xe000ed10, 4, true, s->power.scr);
    }
    timer_del(s->hse_timer);
    timer_del(s->pll_timer);
    timer_del(s->switch_timer);
    s->rcc_cr &= ~(RCC_HSION | RCC_HSIRDY | RCC_HSEON | RCC_HSERDY |
                   RCC_PLLON | RCC_PLLRDY);
    /* A zero clock period disables QEMU's ptimer. Explicitly stop first
     * and resume after restoring the clock, retaining the countdown and
     * guest CTRL bits instead of permanently losing SysTick after STOP. */
    SysTickState *systick = &s->armv7m->systick[0];
    s->systick_resume_enabled = !!(systick->control & 1);
    ptimer_transaction_begin(systick->ptimer);
    ptimer_stop(systick->ptimer);
    ptimer_transaction_commit(systick->ptimer);
    ex1850_update_clock(s);
    if (s->wire.bus) { mcu_wire_gates(s->wire.bus, 0, 0); }
    fprintf(stderr, "EX1850_STOP_ENTER next_pc=%08x PWR_CR=%08x SCR=%08x "
            "HCLK_hz=%u RCC_CR=%08x CFGR=%08x virtual_ns=%" PRId64
            " entries=%" PRIu64 " LSE_continues=1 wire_edges_continue=1 "
            "SRAM_and_GPIO_retained=1 SysTick_count=%" PRIu64
            " SysTick_enabled=%u wake_injected=0\n", next_pc, s->pwr_cr,
            s->power.scr, s->cpu_hz, s->rcc_cr, s->cfgr,
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), s->power.entries,
            ptimer_get_count(systick->ptimer), s->systick_resume_enabled);
}

static void ex1850_power_resume(CPUState *cs)
{
    EX1850M4R0P1 *mcu = (EX1850M4R0P1 *)cs;
    EX1850ResetState *s = mcu->board;
    if (!s || !s->power.stopped) { return; }
    BQL_LOCK_GUARD();
    unsigned exception = s->armv7m->nvic.vectpending;
    g_assert(ex1850_power_has_work(cs));
    /* Move epochs across stopped time at zero frequency before restoring
     * HSI. Do not advance timers by the duration spent in STOP. */
    ex1850_sync_timer_clocks(s, "STOP_real_IRQ_wake");
    g_assert(ex1850_power_wake(&s->power, exception != 0));
    s->rcc_cr |= RCC_HSION | RCC_HSIRDY;
    s->cfgr &= ~UINT32_C(0xf); /* Hardware selects HSI on STOP exit. */
    ex1850_update_clock(s);
    SysTickState *systick = &s->armv7m->systick[0];
    if (s->systick_resume_enabled && (systick->control & 1)) {
        ptimer_transaction_begin(systick->ptimer);
        ptimer_run(systick->ptimer, 0);
        ptimer_transaction_commit(systick->ptimer);
    }
    s->systick_resume_enabled = false;
    if (s->wire.bus) { mcu_wire_gates(s->wire.bus, s->ahb1enr, s->apb2enr); }
    fprintf(stderr, "EX1850_STOP_WAKE exception=%u external_IRQ=%d next_pc=%08x "
            "HCLK_hz=%u RCC_CR=%08x CFGR=%08x virtual_ns=%" PRId64
            " duration_ns=%" PRId64 " wakes=%" PRIu64
            " source=enabled_pending_NVIC original_WFI_returns=1 guest_flags_written=0\n",
            exception, (int)exception - 16, mcu->parent.env.regs[15], s->cpu_hz,
            s->rcc_cr, s->cfgr, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) - s->power.entered_ns, s->power.wakes);
}

static void ex1850_power_reset(void *opaque)
{
    EX1850ResetState *s = opaque;
    ex1850_sync_timer_clocks(s, "power_reset");
    bool was_stopped = s->power.stopped;
    s->power.scr = 0;
    s->power.stopped = false;
    s->systick_resume_enabled = false;
    s->pwr_cr = EX1850_PWR_CR_RESET;
    timer_del(s->hse_timer);
    timer_del(s->pll_timer);
    timer_del(s->switch_timer);
    s->rcc_cr = RCC_HSION | RCC_HSIRDY | 0x80;
    s->pllcfgr = 0x24003010;
    s->cfgr = 0;
    ex1850_update_clock(s);
    if (s->wire.bus) { mcu_wire_gates(s->wire.bus, s->ahb1enr, s->apb2enr); }
    fprintf(stderr, "EX1850_POWER_RESET stopped_before=%u HCLK_hz=%u "
            "SCR=%08x reset_is_not_IRQ_wake=1 peripheral_reset_scope=power_clocks\n",
            was_stopped, s->cpu_hz, s->power.scr);
}
#endif
