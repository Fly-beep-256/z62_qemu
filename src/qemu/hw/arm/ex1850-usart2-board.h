/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef EX1850_USART2_BOARD_H
#define EX1850_USART2_BOARD_H

static void ex1850_usart2_schedule(EX1850ResetState *s)
{
    if (s->usart2_event) {
        timer_del(s->usart2_event);
        int64_t due = ex1850_usart2_deadline(&s->usart2);
        if (due >= 0) { timer_mod(s->usart2_event, due); }
    }
    bool level = ex1850_usart2_irq(&s->usart2);
    if (s->armv7m) {
        qemu_set_irq(qdev_get_gpio_in(DEVICE(s->armv7m), 38), level);
    }
    if (level != s->usart2_irq38_level) {
        fprintf(stderr, "EX1850_USART2_IRQ IRQ38=%u SR=%08x CR1=%08x CR2=%08x "
                "CR3=%08x virtual_ns=%" PRId64 " source=status_and_interrupt_enables\n",
                level, s->usart2.sr, s->usart2.cr1, s->usart2.cr2,
                s->usart2.cr3, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    }
    s->usart2_irq38_level = level;
}

static void ex1850_usart2_transmitted(void *opaque, int64_t now, uint16_t word)
{
    EX1850ResetState *s = opaque;
    fprintf(stderr, "EX1850_USART2_TX_COMPLETE word=%03x BRR=%04x PCLK_hz=%u "
            "accepted=%" PRIu64 " completed=%" PRIu64 " virtual_ns=%" PRId64
            " RX_response_supplied=0\n", word, s->usart2.brr,
            s->usart2.pclk_hz, s->usart2.tx_accepted, s->usart2.tx_completed, now);
}

static void ex1850_usart2_sync(EX1850ResetState *s)
{
    g_assert(ex1850_usart2_advance(&s->usart2, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
                                  ex1850_usart2_transmitted, s));
    ex1850_usart2_schedule(s);
}

static void ex1850_usart2_clocks_changed(EX1850ResetState *s)
{
    unsigned ppre = (s->cfgr >> 10) & 7;
    unsigned pclk = ppre < 4 ? s->cpu_hz : s->cpu_hz >> (ppre - 3);
    ex1850_usart2_clocks(&s->usart2, pclk, !!(s->apb1enr & (1U << 17)),
                         !!(s->rcc_apb1rstr & (1U << 17)),
                         qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    ex1850_usart2_schedule(s);
}

static void ex1850_usart2_event(void *opaque)
{
    ex1850_usart2_sync(opaque);
}

static bool ex1850_usart2_board_access(EX1850ResetState *s, hwaddr addr,
                                       unsigned size, bool write, uint64_t *value)
{
    if (addr < 0x40004400 || addr >= 0x4000441c) { return false; }
    uint32_t requested = *value, v = *value;
    if (*value > UINT32_MAX || !ex1850_usart2_access(&s->usart2,
            addr - 0x40004400, size, write, &v)) {
        fprintf(stderr, "EX1850_USART2_BOUNDARY SR=%08x BRR=%04x CR1=%08x "
                "CR2=%08x CR3=%08x buffer_full=%u shifting=%u\n",
                s->usart2.sr, s->usart2.brr, s->usart2.cr1, s->usart2.cr2,
                s->usart2.cr3, s->usart2.buffer_full, s->usart2.shifting);
        ex1850_unknown_access(s, addr, size, write, *value);
    }
    *value = v;
    ex1850_usart2_schedule(s);
    if (s->usart2_access_count++ < 4096 || (write && addr == 0x40004404)) {
        fprintf(stderr, "EX1850_USART2_%c addr=%08" HWADDR_PRIx
                " size=%u value=%08x SR=%08x BRR=%04x CR1=%08x CR2=%08x "
                "CR3=%08x pc=%08x virtual_ns=%" PRId64 " RX_supplied=%" PRIu64 "\n",
                write ? 'W' : 'R', addr, size, write ? requested : v,
                s->usart2.sr, s->usart2.brr, s->usart2.cr1, s->usart2.cr2,
                s->usart2.cr3, ex1850_pc(), qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
                s->usart2.rx_supplied);
    }
    return true;
}
#endif
