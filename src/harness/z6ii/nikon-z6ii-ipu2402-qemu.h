/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Stage98 opt-in FIFO adapter. Include after Z6IIState.
 * Core nikon-z6ii-ipu2402.c must be compiled once. The board may connect BA2. */
#ifndef Z6II_IPU2402_QEMU_CANDIDATE_H
#define Z6II_IPU2402_QEMU_CANDIDATE_H

static const char *z6ii_ipu2402_qemu_peer(Z6IIState *s)
{
    return s->ba2_peer ? "ba2-connected" : "unconnected";
}

static void z6ii_ipu2402_qemu_update_irq(Z6IIState *s)
{
    bool level = z6ii_ipu2402_irq(&s->ipu2402);
    if (level == s->ipu2402_irq_level) {
        return;
    }
    s->ipu2402_irq_level = level;
    if (s->ipu2402_gic_input >= 0) {
        qemu_set_irq(qdev_get_gpio_in(DEVICE(s->priv), s->ipu2402_gic_input), level);
    }
    fprintf(stderr, "Z6II_IPU2402_IRQ now_ns=%" PRId64
            " level=%u gic_input=%d raw=%08x mask=%08x"
            " route_verified=0 guest_flag_written=0 peer=%s\n",
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), level,
            s->ipu2402_gic_input, z6ii_ipu2402_raw(&s->ipu2402),
            s->ipu2402.interrupt_mask, z6ii_ipu2402_qemu_peer(s));
}

static bool z6ii_ipu2402_qemu_owns(Z6IIState *s, hwaddr addr)
{
    return s->ipu2402_enabled && addr >= 0x24020000 && addr < 0x24020100;
}

static bool z6ii_ipu2402_qemu_access(Z6IIState *s, hwaddr addr, unsigned size,
                                   bool write, uint64_t *value)
{
    uint32_t word = (uint32_t)*value;
    Z6IIIPU2402Result result;
    uint64_t old_frames = s->ipu2402.tx_frames;
    CPUARMState *env = current_cpu ? &ARM_CPU(current_cpu)->env : NULL;
    if (write && *value > UINT32_MAX) {
        result = Z6II_IPU2402_BAD_ACCESS;
    } else if (write) {
        result = z6ii_ipu2402_write(&s->ipu2402, addr - 0x24020000, size, word);
    } else {
        result = z6ii_ipu2402_read(&s->ipu2402, addr - 0x24020000, size, &word);
        if (result == Z6II_IPU2402_OK) {
            *value = word;
        }
    }
    if (result == Z6II_IPU2402_OK && write && addr == 0x24020004) {
        /* Diagnostic shadow of the actual staged words, for the read-only
         * boot observer. This does not create a second transaction. */
        s->ipu_transmit_words[s->ipu2402.tx_staged - 1] = word;
        s->ipu_transmit_count = s->ipu2402.tx_staged;
    } else if (result == Z6II_IPU2402_OK && write &&
               addr == 0x24020008 && word == 2) {
        s->ipu_transmit_count = 0;
    }
    if (s->ipu2402_trace_count++ < s->ipu2402_trace_limit ||
        result != Z6II_IPU2402_OK) {
        fprintf(stderr, "Z6II_IPU2402_MMIO now_ns=%" PRId64
                " %c addr=%08" HWADDR_PRIx " size=%u value=%08" PRIx64
                " result=%u tx_words=%u rx_words=%u window_valid=%u"
                " cpu=%d pc=%08x\n",
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), write ? 'W' : 'R',
                addr, size, *value, result, s->ipu2402.tx.count,
                s->ipu2402.rx.count, s->ipu2402.window_valid,
                current_cpu ? current_cpu->cpu_index : -1,
                env ? env->regs[15] : 0);
    }
    if (s->ipu2402.tx_frames != old_frames) {
        unsigned tail = (s->ipu2402.tx.head + s->ipu2402.tx.count - 3) % 32;
        fprintf(stderr, "Z6II_IPU2402_TX frame=%" PRIu64
                " words=%08x,%08x,%08x peer=%s tx_words_at_commit=%u"
                " automatic_reply=0\n",
                s->ipu2402.tx_frames, s->ipu2402.tx.words[tail],
                s->ipu2402.tx.words[(tail + 1) % 32],
                s->ipu2402.tx.words[(tail + 2) % 32],
                z6ii_ipu2402_qemu_peer(s), s->ipu2402.tx.count);
    }
    if (result == Z6II_IPU2402_OK) {
        z6ii_ipu2402_qemu_update_irq(s);
    }
    return result == Z6II_IPU2402_OK;
}

static void z6ii_ipu2402_qemu_reset(void *opaque)
{
    Z6IIState *s = opaque;
    if (!s->ipu2402_enabled) {
        return;
    }
    z6ii_ipu2402_reset(&s->ipu2402);
    memset(s->ipu_transmit_words, 0, sizeof(s->ipu_transmit_words));
    s->ipu_transmit_count = 0;
    z6ii_ipu2402_qemu_update_irq(s);
    fprintf(stderr, "Z6II_IPU2402_RESET signature=%08x tx_words=0 rx_words=0"
            " raw=%08x mask=00000000 peer=%s guest_flag_written=0\n",
            s->ipu2402.signature, z6ii_ipu2402_raw(&s->ipu2402),
            z6ii_ipu2402_qemu_peer(s));
}

static void z6ii_ipu2402_qemu_init(Z6IIState *s, bool functional)
{
    const char *mode = getenv("Z6II_IPU2402_MODEL");
    uint64_t signature, route;
    if (!mode || strcmp(s->profile->role, "master")) {
        return;
    }
    if (!functional || strcmp(mode, "fifo-v1")) {
        error_report("IPU2402 fifo-v1 requires a functional Master board");
        exit(1);
    }
    if (!z6ii_hdmi_decimal(getenv("Z6II_IPU2402_SIGNATURE"), 256, &signature) ||
        (signature != 0 && signature != 256)) {
        error_report("IPU2402 requires explicit decimal signature 0 or 256");
        exit(1);
    }
    s->ipu2402_gic_input = -1;
    if (getenv("Z6II_IPU2402_EXPERIMENTAL_GIC_INPUT")) {
        if (!z6ii_hdmi_decimal(getenv("Z6II_IPU2402_EXPERIMENTAL_GIC_INPUT"),
                               223, &route)) {
            error_report("IPU2402 experimental GIC input requires decimal 0..223");
            exit(1);
        }
        s->ipu2402_gic_input = route;
    }
    z6ii_ipu2402_init(&s->ipu2402, (uint32_t)signature);
    s->ipu2402_trace_limit = z6ii_hdmi_number("Z6II_IPU2402_TRACE_LIMIT", 4096, 1, 65536);
    s->ipu2402_enabled = true;
    qemu_register_reset(z6ii_ipu2402_qemu_reset, s);
    fprintf(stderr, "Z6II_IPU2402_MODEL mode=fifo-v1 signature=%08x"
            " peer=%s gic_input=%d raw_RX_bit_hypothesis=1 read_pop_hypothesis=1"
            " W1C_hypothesis=1 silicon_route_verified=0"
            " command1_generated=0 command900F_generated=0\n", (unsigned)signature,
            z6ii_ipu2402_qemu_peer(s), s->ipu2402_gic_input);
}

#endif
