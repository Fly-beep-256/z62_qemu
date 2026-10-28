/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Opt-in chardev id ex1850-usart1. Only serial TX/RX is exposed: no RAM,
 * RNG, protocol parser, authentication reply or firmware result interface. */
#ifndef EX1850_USART1_CHARDEV_H
#define EX1850_USART1_CHARDEV_H

static void ex1850_usart1_line_write(EX1850ResetState *s, uint16_t word)
{
    if (!s->usart1_line_enabled || !qemu_chr_fe_backend_open(&s->usart1_chr)) {
        return;
    }
    if (word > 0xff) {
        ex1850_unknown_access(s, EX1850_USART1_BASE + 4, 4, true, word);
        return;
    }
    uint8_t byte = word;
    int used = qemu_chr_fe_write(&s->usart1_chr, &byte, 1);
    if (used != 1) {
        s->usart1_line_tx_failures++;
        error_report("USART1 external line short write: %d/1; byte not replayed", used);
        exit(67);
    }
    s->usart1_line_tx_bytes++;
}

static void ex1850_usart1_line_accept(EX1850ResetState *s)
{
    if (s->usart1_line_enabled && qemu_chr_fe_backend_open(&s->usart1_chr)) {
        qemu_chr_fe_accept_input(&s->usart1_chr);
    }
}

static int ex1850_usart1_line_can_read(void *opaque)
{
    EX1850ResetState *s = opaque;
    return EX1850_U1_RX_CAPACITY - s->usart1_rx.count;
}

static void ex1850_usart1_line_read(void *opaque, const uint8_t *bytes, int size)
{
    EX1850ResetState *s = opaque;
    g_assert(size >= 0);
    s->usart1_line_rx_bytes += size;
    ex1850_usart1_external_bytes(s, bytes, size);
}

static void ex1850_usart1_line_event(void *opaque, QEMUChrEvent event)
{
    EX1850ResetState *s = opaque;
    if (event == CHR_EVENT_OPENED || event == CHR_EVENT_CLOSED) {
        ex1850_usart1_sync(s);
        s->usart1_line_open = event == CHR_EVENT_OPENED;
        unsigned lost = s->usart1_line_open ? 0 :
                        ex1850_usart1_rx_cancel(&s->usart1_rx);
        ex1850_usart1_schedule(s);
        if (s->usart1_line_events++ < 16) {
            fprintf(stderr, "EX1850_USART1_LINE open=%u discarded=%u "
                    "TX_bytes=%" PRIu64 " RX_bytes=%" PRIu64
                    " virtual_ns=%" PRId64 " source=explicit_external_byte_stream\n",
                    s->usart1_line_open, lost, s->usart1_line_tx_bytes,
                    s->usart1_line_rx_bytes, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
        }
    } else if (event == CHR_EVENT_BREAK) {
        error_report("USART1 clean byte-stream contract has no break waveform");
        ex1850_unknown_access(s, EX1850_USART1_BASE, 4, false, 0);
    }
}

static void ex1850_usart1_line_init(EX1850ResetState *s)
{
    Chardev *backend = qemu_chr_find("ex1850-usart1");
    s->usart1_line_enabled = backend != NULL;
    if (backend) {
        if (!qemu_chr_fe_init(&s->usart1_chr, backend, &error_fatal)) { exit(1); }
        qemu_chr_fe_set_handlers(&s->usart1_chr, ex1850_usart1_line_can_read,
                                 ex1850_usart1_line_read, ex1850_usart1_line_event,
                                 NULL, s, NULL, true);
    }
    fprintf(stderr, "EX1850_USART1_LINE_PROFILE enabled=%u id=ex1850-usart1 "
            "input=synthetic_clean_async_byte_stream RX_capacity=%u "
            "timing=full_frame_at_guest_BRR_PCLK parity_errors=unprovided "
            "queued_input_on_disconnect_disable_reset_format_change=discard "
            "battery_reply_generated=0 MCU_private_RAM_exposed=0 physical_capture=0\n",
            s->usart1_line_enabled, EX1850_U1_RX_CAPACITY);
}
#endif
