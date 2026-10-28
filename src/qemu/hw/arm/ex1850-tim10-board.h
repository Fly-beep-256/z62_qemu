/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef EX1850_TIM10_BOARD_H
#define EX1850_TIM10_BOARD_H

static unsigned ex1850_tim10_kernel_hz(EX1850ResetState *s)
{
    if (s->rcc_apb2rstr & EX1850_TIM10_APB2_BIT) { return 0; }
    return ex1850_tim10_apb2_kernel_hz(s->cpu_hz, s->cfgr, s->apb2enr);
}

static void ex1850_tim10_sync(EX1850ResetState *s)
{
    uint64_t updates = s->tim10.updates, compares = s->tim10.compares;
    if (!ex1850_tim10_core_sync(&s->tim10,
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), ex1850_tim10_kernel_hz(s))) {
        fprintf(stderr, "EX1850_TIM10_TIME_BOUNDARY pc=%08x "
                "source=unsupported_counter_or_time_contract completion_supplied=0\n",
                ex1850_pc());
        ex1850_unknown_access(s, 0x40014424, 4, false, 0);
    }
    if (updates != s->tim10.updates || compares != s->tim10.compares) {
        ex1850_sampled_log("EX1850_TIM10_EVENT update_delta=%" PRIu64
                " CC1_delta=%" PRIu64 " CNT=%04x SR=%08x DIER=%08x "
                "CCER=%08x CCR1=%04x active_PSC=%u active_ARR=%04x "
                "virtual_ns=%" PRId64 " source=elapsed_virtual_clock "
                "CCR_gt_ARR_overflow_contract=explicit_family_condition "
                "external_AF_pad_or_completion_supplied=0\n",
                s->tim10.updates - updates, s->tim10.compares - compares,
                s->tim10.cnt, s->tim10.sr, s->tim10.dier, s->tim10.ccer,
                s->tim10.ccr1, s->tim10.active_psc, s->tim10.active_arr,
                s->tim10.epoch);
    }
}

static void ex1850_tim10_schedule(EX1850ResetState *s)
{
    timer_del(s->tim10_event);
    int64_t deadline = ex1850_tim10_core_deadline(&s->tim10,
                                                 ex1850_tim10_kernel_hz(s));
    if (deadline >= 0) { timer_mod(s->tim10_event, deadline); }
    /* The existing TIM1 function owns every write to shared IRQ25.
     * It aggregates TIM1 update and both TIM10 sources, retaining IRQ26/27. */
    ex1850_tim1_irq_update(s);
}

static void ex1850_tim10_event(void *opaque)
{
    EX1850ResetState *s = opaque;
    ex1850_tim10_sync(s);
    ex1850_tim10_schedule(s);
}

static bool ex1850_tim10_access(EX1850ResetState *s, hwaddr addr,
                                unsigned size, bool write, uint64_t *value)
{
    if (addr < 0x40014400 || addr > 0x40014434 || (addr & 3) || size != 4 ||
        !(s->apb2enr & EX1850_TIM10_APB2_BIT) ||
        (s->rcc_apb2rstr & EX1850_TIM10_APB2_BIT)) { return false; }
    unsigned offset = addr - 0x40014400;
    uint32_t ignored;
    if ((write && (*value > UINT32_MAX ||
         !ex1850_tim10_core_valid_write(&s->tim10, offset, *value))) ||
        (!write && !ex1850_tim10_core_read(&s->tim10, offset, &ignored))) {
        return false;
    }
    EX1850TIM10 candidate = s->tim10;
    if (!ex1850_tim10_core_sync(&candidate,
        qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), ex1850_tim10_kernel_hz(s))) {
        return false;
    }
    uint32_t result = 0;
    if (write) {
        if (!ex1850_tim10_core_write(&candidate, offset, *value)) { return false; }
    } else {
        g_assert(ex1850_tim10_core_read(&candidate, offset, &result));
    }
    s->tim10 = candidate;
    if (!write) { *value = result; }
    ex1850_tim10_schedule(s);
    uint64_t count = ++s->tim10_access_counts[offset / 4];
    /* The original 24-access init includes the ninth CCER access. Keep
     * every early request, then sample long-running reads exponentially. */
    if (write || count <= 16 || !(count & (count - 1))) {
        ex1850_sampled_log("EX1850_TIM10_%c addr=%08" HWADDR_PRIx
                " size=%u value=%08" PRIx64 " pc=%08x kernel_hz=%u "
                "ARR_known=%u active_PSC=%u active_ARR=%04x CNT=%04x "
                "SR=%08x DIER=%08x CCER=%08x CCR1=%04x IRQ25_shared=%u "
                "virtual_ns=%" PRId64 " sampled_access_index=%" PRIu64
                " source=original_guest_control_only "
                "reserved_CR2_zero_family_hypothesis=%u "
                "external_AF_pad_level_known=0 completion_supplied=0\n",
                write ? 'W' : 'R', addr, size, *value, ex1850_pc(),
                ex1850_tim10_kernel_hz(s), s->tim10.arr_known,
                s->tim10.active_psc, s->tim10.active_arr, s->tim10.cnt,
                s->tim10.sr, s->tim10.dier, s->tim10.ccer, s->tim10.ccr1,
                ex1850_tim10_shared25(&s->tim10,
                    !!ex1850_tim10_kernel_hz(s),
                    !!ex1850_tim1_kernel_hz(s), s->tim1.sr, s->tim1.dier),
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), count, offset == 4);
    }
    return true;
}
#endif
