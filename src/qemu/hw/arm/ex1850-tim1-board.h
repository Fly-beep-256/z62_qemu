/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Include at the old TIM1 idle-helper location, after TIM11/TIM12 helpers.
 * State fields/prototypes/include are added by the exact candidate generator.
 * Unsupported TIM1 modes never fall back to the old SR/DIER-zero helper.
 */
#ifndef EX1850_TIM1_BOARD_H
#define EX1850_TIM1_BOARD_H

static unsigned ex1850_tim1_kernel_hz(EX1850ResetState *s)
{
    return ex1850_tim1_apb2_kernel_hz(s->cpu_hz, s->cfgr, s->apb2enr);
}

static void ex1850_tim1_irq_update(EX1850ResetState *s)
{
    if (!s->armv7m) { return; }
    bool gate = !!ex1850_tim1_kernel_hz(s);
    /* One authoritative IRQ25 source aggregates TIM1 update and TIM10
     * UIF/CC1IF. TIM9/break/trigger/COM retain their strict boundaries. */
    qemu_set_irq(qdev_get_gpio_in(DEVICE(s->armv7m), 25),
                 ex1850_tim10_shared25(&s->tim10,
                     !(s->rcc_apb2rstr & EX1850_TIM10_APB2_BIT) &&
                     !!ex1850_tim10_apb2_kernel_hz(s->cpu_hz, s->cfgr, s->apb2enr),
                     gate, s->tim1.sr, s->tim1.dier));
    qemu_set_irq(qdev_get_gpio_in(DEVICE(s->armv7m), 26),
                 ex1850_tim1_shared26(&s->tim1, gate,
                    !!(s->apb2enr & (1U << 18)), s->tim11_sr, s->tim11_dier));
    qemu_set_irq(qdev_get_gpio_in(DEVICE(s->armv7m), 27),
                 gate && ex1850_tim1_core_irq(&s->tim1, 27));
}

static void ex1850_tim1_sync(EX1850ResetState *s)
{
    uint64_t updates = s->tim1.updates;
    uint64_t compares[4];
    memcpy(compares, s->tim1.compares, sizeof(compares));
    if (!ex1850_tim1_core_sync(&s->tim1,
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), ex1850_tim1_kernel_hz(s))) {
        fprintf(stderr, "EX1850_TIM1_TIME_BOUNDARY pc=%08x "
                "source=unsupported_counter_or_time_contract completion_supplied=0\n",
                ex1850_pc());
        ex1850_unknown_access(s, 0x40010024, 4, false, 0);
    }
    if (updates != s->tim1.updates ||
        memcmp(compares, s->tim1.compares, sizeof(compares))) {
        fprintf(stderr, "EX1850_TIM1_EVENT update_delta=%" PRIu64
                " CC1_delta=%" PRIu64 " CC2_delta=%" PRIu64
                " CC3_delta=%" PRIu64 " CC4_delta=%" PRIu64
                " CNT=%04x SR=%08x DIER=%08x CCER=%08x BDTR=%08x active_PSC=%u active_ARR=%04x "
                "virtual_ns=%" PRId64 " source=elapsed_virtual_clock "
                "PWM_external_pad_DMA_or_completion_supplied=0\n",
                s->tim1.updates - updates,
                s->tim1.compares[0] - compares[0],
                s->tim1.compares[1] - compares[1],
                s->tim1.compares[2] - compares[2],
                s->tim1.compares[3] - compares[3],
                s->tim1.cnt, s->tim1.sr, s->tim1.dier, s->tim1.ccer, s->tim1.bdtr,
                s->tim1.active_psc, s->tim1.active_arr, s->tim1.epoch);
    }
}

static void ex1850_tim1_schedule(EX1850ResetState *s)
{
    timer_del(s->tim1_event);
    int64_t deadline = ex1850_tim1_core_deadline(&s->tim1,
                                                ex1850_tim1_kernel_hz(s));
    if (deadline >= 0) { timer_mod(s->tim1_event, deadline); }
    ex1850_tim1_irq_update(s);
}

static void ex1850_tim1_event(void *opaque)
{
    EX1850ResetState *s = opaque;
    ex1850_tim1_sync(s);
    ex1850_tim1_schedule(s);
}

static bool ex1850_tim1_access(EX1850ResetState *s, hwaddr addr,
                               unsigned size, bool write, uint64_t *value)
{
    if (addr < 0x40010000 || addr > 0x4001004c || (addr & 3) || size != 4 ||
        !(s->apb2enr & EX1850_TIM1_APB2_BIT) ||
        (s->rcc_apb2rstr & EX1850_TIM1_APB2_BIT)) { return false; }
    unsigned offset = addr - 0x40010000;
    uint32_t ignored;
    if ((write && (*value > UINT32_MAX ||
                    !ex1850_tim1_core_valid_write(&s->tim1, offset, *value))) ||
        (!write && !ex1850_tim1_core_read(&s->tim1, offset, &ignored))) {
        return false; /* Caller retains strict MMIO boundary; no mutation. */
    }
    EX1850TIM1 candidate = s->tim1;
    if (!ex1850_tim1_core_sync(&candidate,
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), ex1850_tim1_kernel_hz(s))) {
        return false;
    }
    uint32_t result = 0;
    if (write) {
        if (!ex1850_tim1_core_write(&candidate, offset, *value)) { return false; }
    } else {
        g_assert(ex1850_tim1_core_read(&candidate, offset, &result));
    }
    /* Failed requests leave both authoritative state and caller value intact,
     * including failures discovered after an elapsed-time counter preview. */
    s->tim1 = candidate;
    if (!write) { *value = result; }
    ex1850_tim1_schedule(s);
    uint64_t count = ++s->tim1_access_counts[offset / 4];
    if (write || count <= 8 || !(count & (count - 1))) {
        fprintf(stderr, "EX1850_TIM1_%c addr=%08" HWADDR_PRIx
                " size=%u value=%08" PRIx64 " pc=%08x kernel_hz=%u "
                "ARR_known=%u active_PSC=%u active_ARR=%04x CNT=%04x "
                "SR=%08x DIER=%08x CCER=%08x BDTR=%08x IRQ25=%u IRQ26_shared=%u IRQ27=%u "
                "virtual_ns=%" PRId64 " sampled_access_index=%" PRIu64
                " source=original_guest_control_only internal_frozen_OC2_controls=1 "
                "external_AF_pad_level_known=0 waveform_or_completion_supplied=0\n",
                write ? 'W' : 'R', addr, size, *value, ex1850_pc(),
                ex1850_tim1_kernel_hz(s), s->tim1.arr_known,
                s->tim1.active_psc, s->tim1.active_arr, s->tim1.cnt,
                s->tim1.sr, s->tim1.dier, s->tim1.ccer, s->tim1.bdtr,
                ex1850_tim1_core_irq(&s->tim1, 25),
                ex1850_tim1_shared26(&s->tim1, true,
                    !!(s->apb2enr & (1U << 18)), s->tim11_sr, s->tim11_dier),
                ex1850_tim1_core_irq(&s->tim1, 27),
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), count);
    }
    return true;
}

static bool ex1850_tim1_apb2_reset(EX1850ResetState *s, uint64_t value)
{
    /* USART1RST bit4 is applied by its independent board clock/reset adapter. */
    if (value & ~UINT64_C(0x23011)) { return false; }
    uint32_t before = s->rcc_apb2rstr;
    uint32_t rising = (uint32_t)value & ~before;
    uint32_t spi = rising & EX1850_TIM1_APB2_SPI_MASK;
    /* Validate/reset only the actual SPI rising bits. A TIM1-only pulse is
     * independent of wire attachment and must never reach the SPI helper. */
    if (spi && (!s->wire.bus ||
        mcu_wire_spi_reset(s->wire.bus, spi) != MCU_WIRE_OK)) { return false; }
    s->rcc_apb2rstr = (uint32_t)value;
    if (rising & EX1850_TIM1_APB2_BIT) {
        ex1850_tim1_core_reset(&s->tim1, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
        ex1850_tim1_schedule(s);
        fprintf(stderr, "EX1850_TIM1_RESET source=APB2RSTR_bit0 "
                "pc=%08x virtual_ns=%" PRId64 " ARR_reset_known=0 "
                "TIM11_SPI_DMA_GPIO_ACK_or_completion_changed=0\n",
                ex1850_pc(), qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    }
    if (rising & EX1850_TIM10_APB2_BIT) {
        ex1850_tim10_core_reset(&s->tim10, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
        ex1850_tim10_schedule(s);
        fprintf(stderr, "EX1850_TIM10_RESET source=APB2RSTR_bit17 "
                "pc=%08x virtual_ns=%" PRId64 " ARR_reset_known=0 "
                "TIM11_unchanged=1 external_pad_or_completion_supplied=0\n",
                ex1850_pc(), qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    }
    fprintf(stderr, "EX1850_RCC_APB2RSTR W before=%08x after=%08" PRIx64
            " pc=%08x virtual_ns=%" PRId64 " TIM1_rising=%u SPI_rising=%08x "
            "reset_controls_only=1 DMA_GPIO_ACK_unchanged=1\n",
            before, value, ex1850_pc(), qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
            !!(rising & EX1850_TIM1_APB2_BIT), spi);
    return true;
}
#endif
