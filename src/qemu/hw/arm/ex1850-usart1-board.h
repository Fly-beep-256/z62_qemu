/* SPDX-License-Identifier: GPL-2.0-or-later */
/* STM32F412 USART1: independent APB2 state and IRQ37. TX and an explicit
 * external clean byte stream share registers, not data or deadlines. */
#ifndef EX1850_USART1_BOARD_H
#define EX1850_USART1_BOARD_H
#define EX1850_USART1_BASE UINT32_C(0x40011000)
#define EX1850_USART1_APB2_BIT (UINT32_C(1) << 4)
#define EX1850_USART1_IRQ 37

static void ex1850_usart1_line_write(EX1850ResetState *s, uint16_t word);
static void ex1850_usart1_line_accept(EX1850ResetState *s);

static int64_t ex1850_usart1_deadline(EX1850ResetState *s)
{
    int64_t tx = ex1850_usart2_deadline(&s->usart1);
    int64_t rx = ex1850_usart1_rx_deadline(&s->usart1_rx);
    return tx < 0 ? rx : rx < 0 ? tx : MIN(tx, rx);
}

static void ex1850_usart1_schedule(EX1850ResetState *s)
{
    if (s->usart1_event) {
        timer_del(s->usart1_event);
        int64_t due = ex1850_usart1_deadline(s);
        if (due >= 0) { timer_mod(s->usart1_event, due); }
    }
    bool level = ex1850_usart2_irq(&s->usart1);
    if (s->armv7m) {
        qemu_set_irq(qdev_get_gpio_in(DEVICE(s->armv7m), EX1850_USART1_IRQ), level);
    }
    if (level != s->usart1_irq37_level && s->usart1_irq_count++ < 128) {
        fprintf(stderr, "EX1850_USART1_IRQ IRQ37=%u SR=%08x CR1=%08x CR2=%08x "
                "CR3=%08x virtual_ns=%" PRId64 " source=status_and_interrupt_enables\n",
                level, s->usart1.sr, s->usart1.cr1, s->usart1.cr2,
                s->usart1.cr3, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    }
    s->usart1_irq37_level = level;
}

static void ex1850_usart1_transmitted(void *opaque, int64_t now, uint16_t word)
{
    EX1850ResetState *s = opaque;
    ex1850_usart1_line_write(s, word);
    if (s->usart1.tx_completed <= 64) {
        fprintf(stderr, "EX1850_USART1_TX_COMPLETE word=%03x BRR=%04x PCLK2_hz=%u "
                "accepted=%" PRIu64 " completed=%" PRIu64 " virtual_ns=%" PRId64
                " RX_response_generated=0 TDR_move_policy_one_PCLK=1\n", word,
                s->usart1.brr, s->usart1.pclk_hz, s->usart1.tx_accepted,
                s->usart1.tx_completed, now);
    }
}

static void ex1850_usart1_sync(EX1850ResetState *s)
{
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), due;
    bool freed = ex1850_usart1_rx_reconcile(&s->usart1_rx, &s->usart1) != 0;
    while ((due = ex1850_usart1_deadline(s)) >= 0 && due <= now) {
        g_assert(ex1850_usart2_advance(&s->usart1, due,
                                     ex1850_usart1_transmitted, s));
        if (ex1850_usart1_rx_deadline(&s->usart1_rx) == due) {
            uint16_t word;
            g_assert(ex1850_usart1_rx_complete(&s->usart1_rx, &s->usart1,
                                             due, &word));
            freed = true;
            if (s->usart1_rx.completed <= 64) {
                fprintf(stderr, "EX1850_USART1_RX_COMPLETE word=%03x SR=%08x "
                        "completed=%" PRIu64 " overruns=%" PRIu64
                        " virtual_ns=%" PRId64 " source=external_clean_serial_frame\n",
                        word, s->usart1.sr, s->usart1_rx.completed,
                        s->usart1.rx_overruns, due);
            }
        }
    }
    g_assert(ex1850_usart2_advance(&s->usart1, now,
                                 ex1850_usart1_transmitted, s));
    ex1850_usart1_schedule(s);
    if (freed) { ex1850_usart1_line_accept(s); }
}

static void ex1850_usart1_clocks_changed(EX1850ResetState *s)
{
    unsigned ppre = (s->cfgr >> 13) & 7;
    unsigned pclk = ppre < 4 ? s->cpu_hz : s->cpu_hz >> (ppre - 3);
    ex1850_usart2_clocks(&s->usart1, pclk,
                         !!(s->apb2enr & EX1850_USART1_APB2_BIT),
                         !!(s->rcc_apb2rstr & EX1850_USART1_APB2_BIT),
                         qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    unsigned lost = ex1850_usart1_rx_reconcile(&s->usart1_rx, &s->usart1);
    ex1850_usart1_schedule(s);
    if (lost) { ex1850_usart1_line_accept(s); }
}

static void ex1850_usart1_reset(void *opaque)
{
    EX1850ResetState *s = opaque;
    ex1850_usart1_rx_cancel(&s->usart1_rx);
    ex1850_usart2_reset(&s->usart1, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    ex1850_usart1_clocks_changed(s);
    ex1850_usart1_line_accept(s);
}

static void ex1850_usart1_external_bytes(EX1850ResetState *s,
                                        const uint8_t *bytes, unsigned length)
{
    ex1850_usart1_sync(s);
    if (!ex1850_usart1_rx_push(&s->usart1_rx, &s->usart1, bytes, length,
                              qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL))) {
        fprintf(stderr, "EX1850_USART1_LINE_BOUNDARY bytes=%u queue=%u "
                "SR=%08x BRR=%04x CR1=%08x CR2=%08x CR3=%08x\n",
                length, s->usart1_rx.count, s->usart1.sr, s->usart1.brr,
                s->usart1.cr1, s->usart1.cr2, s->usart1.cr3);
        ex1850_unknown_access(s, EX1850_USART1_BASE + 4, 4, false, 0);
    }
    ex1850_usart1_schedule(s);
}

static void ex1850_usart1_event(void *opaque)
{
    ex1850_usart1_sync(opaque);
}

static bool ex1850_usart1_board_access(EX1850ResetState *s, hwaddr addr,
                                      unsigned size, bool write, uint64_t *value)
{
    if (addr < EX1850_USART1_BASE || addr >= EX1850_USART1_BASE + 0x1c) { return false; }
    ex1850_usart1_sync(s);
    uint32_t requested = *value, v = *value;
    /* RM0402 specifies word register accesses; the observed HAL path uses 32 bits. */
    if (size != 4 || *value > UINT32_MAX || !ex1850_usart2_access(&s->usart1,
            addr - EX1850_USART1_BASE, size, write, &v)) {
        fprintf(stderr, "EX1850_USART1_BOUNDARY SR=%08x BRR=%04x CR1=%08x "
                "CR2=%08x CR3=%08x buffer_full=%u shifting=%u\n",
                s->usart1.sr, s->usart1.brr, s->usart1.cr1, s->usart1.cr2,
                s->usart1.cr3, s->usart1.buffer_full, s->usart1.shifting);
        ex1850_unknown_access(s, addr, size, write, *value);
    }
    *value = v;
    unsigned lost = ex1850_usart1_rx_reconcile(&s->usart1_rx, &s->usart1);
    ex1850_usart1_schedule(s);
    if (lost) { ex1850_usart1_line_accept(s); }
    if (s->usart1_access_count++ < 64) {
        fprintf(stderr, "EX1850_USART1_%c addr=%08" HWADDR_PRIx
                " size=%u value=%08x SR=%08x BRR=%04x CR1=%08x CR2=%08x "
                "CR3=%08x pc=%08x virtual_ns=%" PRId64 " RX_supplied=%" PRIu64 "\n",
                write ? 'W' : 'R', addr, size, write ? requested : v,
                s->usart1.sr, s->usart1.brr, s->usart1.cr1, s->usart1.cr2,
                s->usart1.cr3, ex1850_pc(), qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
                s->usart1.rx_supplied);
    }
    return true;
}
#endif
