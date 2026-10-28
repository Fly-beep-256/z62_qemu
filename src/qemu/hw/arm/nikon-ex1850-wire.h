/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Included after the reset board's types and strict boundary handler.
 * All controls below remain guest-written. Separate QEMU virtual clocks,
 * the pin pairing, polling quantum and uncontented pads are hypotheses. */

static void ex1850_wire_stop(const char *reason)
{
    error_report("EX1850_MCU_WIRE_BOUNDARY reason=%s original_GPIO_ACK_only=1 "
                 "physical_pairing_verified=0 relative_clock_verified=0", reason);
    exit(66);
}

static uint32_t ex1850_wire_static_exti_sources(EX1850ResetState *s)
{
    uint32_t known = 0;
    for (unsigned pin = 0; pin < 16; pin++) {
        if (pin == 6) { continue; }
        unsigned port = (s->syscfg_exticr[pin / 4] >> (4 * (pin % 4))) & 15;
        if (port < 8 && (s->gpio_pin_known_mask[port] & (1U << pin)) &&
            ((s->gpio[port].moder >> (2 * pin)) & 3) == 0) {
            known |= 1U << pin;
        }
    }
    return known;
}

static bool ex1850_wire_exti_supported(EX1850ResetState *s)
{
    /* RTC17 is an independent internal source with its own IRQ41. Keep
     * the original PG6 source validation for all remaining armed lines. */
    const uint32_t rtc17 = UINT32_C(1) << 17;
    uint32_t rtsr = s->exti_rtsr & ~rtc17, ftsr = s->exti_ftsr & ~rtc17;
    if (s->exti_emr & rtc17) { return false; }
    if (!s->wire.bus) {
        return !((rtsr | ftsr) & ~ex1850_wire_static_exti_sources(s));
    }
    return mcu_wire_pg6_exti_supported(rtsr, ftsr, s->exti_emr,
        (s->syscfg_exticr[1] >> 8) & 15, ex1850_wire_static_exti_sources(s));
}

static void ex1850_wire_poll(EX1850ResetState *s)
{
    if (!s->wire.bus) { return; }
    MCUWireCore c;
    mcu_wire_snapshot(s->wire.bus, &c);
    uint32_t edges = c.master_ack_edge_count - s->wire_ack_edges;
    if (edges && ((s->syscfg_exticr[1] >> 8) & 15) == 6) {
        if (!ex1850_wire_exti_supported(s)) {
            ex1850_wire_stop("unmodeled EXTI source or event wake request");
        }
        uint32_t before = s->exti_pr;
        s->exti_pr = mcu_wire_pg6_pending(s->exti_pr, s->exti_rtsr,
            s->exti_ftsr, edges, c.master_ack_last_edge_rising);
        fprintf(stderr, "EX1850_MCU_WIRE_EXTI_EDGE rising=%u edge_count=%u "
                "observed_edges=%u coalesced_pending_bit=1 "
                "RTSR=%08x FTSR=%08x IMR=%08x EMR=%08x PR_before=%08x PR_after=%08x "
                "static_input_source_mask=%04x pc=%08x virtual_ns=%" PRId64
                " source=actual_master_GPIO_write PG6_pairing_hypothesis=1\n",
                c.master_ack_last_edge_rising, c.master_ack_edge_count, edges,
                s->exti_rtsr, s->exti_ftsr, s->exti_imr, s->exti_emr,
                before, s->exti_pr, ex1850_wire_static_exti_sources(s),
                ex1850_pc(), qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    }
    s->wire_ack_edges = c.master_ack_edge_count;
    if (c.shifted_bytes[0] != s->wire_rx_bytes) {
        /* The admitted buffers are SRAM data, not executable code. This
         * dirty mark is not proof of cross-process TCG coherency for code. */
        memory_region_set_dirty(&s->ram, 0, EX1850_RAM_BYTES);
        s->wire_rx_bytes = c.shifted_bytes[0];
    }
    if (s->armv7m) {
        qemu_set_irq(qdev_get_gpio_in(DEVICE(s->armv7m), 56),
                     mcu_wire_irq(s->wire.bus, 0));
        qemu_set_irq(qdev_get_gpio_in(DEVICE(s->armv7m), 57),
                     mcu_wire_irq(s->wire.bus, 1));
        qemu_set_irq(qdev_get_gpio_in(DEVICE(s->armv7m), 35),
                     mcu_wire_spi_irq(s->wire.bus, 0));
        qemu_set_irq(qdev_get_gpio_in(DEVICE(s->armv7m), 84),
                     mcu_wire_spi_irq(s->wire.bus, 1));
        qemu_set_irq(qdev_get_gpio_in(DEVICE(s->armv7m), 23),
                     !!(s->exti_pr & s->exti_imr & 0x40));
    }
}

static void ex1850_wire_timer(void *opaque)
{
    EX1850ResetState *s = opaque;
    ex1850_wire_poll(s);
    timer_mod(s->wire_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + s->wire_poll_ns);
}

static bool ex1850_wire_access(EX1850ResetState *s, hwaddr addr,
                                unsigned size, bool write, uint64_t *value)
{
    if (!s->wire.bus) { return false; }
    /* Reset pulses are modeled; an access while reset is held still stops
     * before a value is supplied. No sustained-reset transfer is admitted. */
    for (unsigned spi = 0; spi < 2; spi++) {
        uint32_t base = spi ? 0x40013400 : 0x40013000;
        if ((s->rcc_apb2rstr & (1U << (12 + spi))) &&
            addr >= base && addr < base + 32) { return false; }
    }
    mcu_wire_gates(s->wire.bus, s->ahb1enr, s->apb2enr);
    uint32_t word = *value;
    bool wire_addr = (addr >= 0x40026400 && addr < 0x40026440) ||
                     (addr >= 0x40013000 && addr < 0x40013020) ||
                     (addr >= 0x40013400 && addr < 0x40013420);
    MCUWireCore failure;
    int result = mcu_wire_mmio_observed(s->wire.bus, addr, size, write, &word,
                                      wire_addr ? &failure : NULL);
    if (result != MCU_WIRE_OK) {
        if (wire_addr) {
            uint64_t host_ns = 0;
            int clock_ok = !mcu_wire_host_monotonic_ns(&host_ns);
            unsigned stream = UINT32_MAX, index = UINT32_MAX;
            if (addr >= 0x40026410 && addr < 0x40026440) {
                stream = (addr - 0x40026410) / 24;
                index = ((addr - 0x40026410) % 24) / 4;
            }
            const MCUWireCore *c = &failure;
            error_report("EX1850_MCU_WIRE_REJECT_SNAPSHOT op=%c addr=%08" HWADDR_PRIx
                " size=%u requested=%08x result=%d stream=%u word=%u pc=%08x"
                " host_ns=%" PRIu64 " host_clock_valid=%u virtual_ns=%" PRId64
                " CR0=%08x CR1=%08x NDTR0=%u NDTR1=%u initial0=%u initial1=%u"
                " transferred0=%u transferred1=%u PAR0=%08x PAR1=%08x"
                " M0AR0=%08x M0AR1=%08x M1AR0=%08x M1AR1=%08x FCR0=%08x FCR1=%08x"
                " LISR=%08x AHB1ENR=%08x APB2ENR=%08x"
                " SPI_CR10=%08x SPI_CR11=%08x SPI_CR20=%08x SPI_CR21=%08x"
                " SPI_SR0=%08x SPI_SR1=%08x known=%08x level=%08x"
                " shifted0=%" PRIu64 " shifted1=%" PRIu64
                " same_wire_lock=1 virtual_clocks_synchronized=0 observation_guest_writes=0",
                write ? 'W' : 'R', addr, size, (uint32_t)*value, result, stream,
                index, ex1850_pc(), host_ns, clock_ok, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
                c->dma[0].reg[0], c->dma[1].reg[0], c->dma[0].reg[1], c->dma[1].reg[1],
                c->dma[0].initial_ndtr, c->dma[1].initial_ndtr,
                c->dma[0].transferred, c->dma[1].transferred,
                c->dma[0].reg[2], c->dma[1].reg[2], c->dma[0].reg[3], c->dma[1].reg[3],
                c->dma[0].reg[4], c->dma[1].reg[4], c->dma[0].reg[5], c->dma[1].reg[5],
                c->dma_lisr, c->ahb1enr, c->apb2enr, c->spi_cr1[0], c->spi_cr1[1],
                c->spi_cr2[0], c->spi_cr2[1], c->spi_sr[0], c->spi_sr[1],
                c->mcu_known, c->mcu_level, c->shifted_bytes[0], c->shifted_bytes[1]);
        }
        return false;
    }
    *value = word;
    ex1850_wire_poll(s);
    ex1850_sampled_log("EX1850_MCU_WIRE_MMIO %c addr=%08" HWADDR_PRIx
            " size=%u value=%08x pc=%08x ACK_source=original_GPIO_only\n",
            write ? 'W' : 'R', addr, size, word, ex1850_pc());
    return true;
}

static void ex1850_wire_gpio_changed(EX1850ResetState *s, unsigned bank,
                                     uint32_t written)
{
    if (!s->wire.bus) { return; }
    EX1850GPIOControl *g = &s->gpio[bank];
    uint32_t drive = 0;
    if (s->ahb1enr & (1U << bank)) {
        for (unsigned pin = 0; pin < 16; pin++) {
            if (((g->moder >> (2 * pin)) & 3) == 1 && !(g->otyper & (1U << pin))) {
                drive |= 1U << pin;
            }
        }
    }
    mcu_wire_invalidate_output(s->wire.bus, bank, ~drive & 0xffff);
    s->wire_gpio_known[bank] &= drive;
    if (written & drive) {
        uint16_t selected = written & drive;
        uint64_t count = ++s->wire_gpio_access_counts[bank];
        bool changed = (selected & ~s->wire_gpio_known[bank]) ||
            ((s->wire_gpio_levels[bank] ^ g->odr) & selected);
        s->wire_gpio_known[bank] |= selected;
        s->wire_gpio_levels[bank] =
            (s->wire_gpio_levels[bank] & ~selected) | (g->odr & selected);
        /* Publish every original write, including unchanged outputs. The
         * cache controls logging only; it never supplies a wire level. */
        mcu_wire_mcu_output(s->wire.bus, bank, written & drive, g->odr);
        if (changed || count <= 8 || !(count & (count - 1))) {
            fprintf(stderr, "EX1850_MCU_WIRE_GPIO port=%c written=%04x ODR=%04x "
                    "pc=%08x access_count=%" PRIu64 " original_writer=1 "
                    "pairing_hypothesis=1 repeated_writes_sampled=1\n",
                    'A' + bank, selected, g->odr, ex1850_pc(), count);
        }
    }
}

static bool ex1850_wire_pg6_profile(EX1850ResetState *s, unsigned bank,
                                    uint16_t *levels)
{
    if (!s->wire.bus || bank != 6) { return true; }
    MCUWireCore c;
    mcu_wire_snapshot(s->wire.bus, &c);
    if (!c.master_ack_known) { return false; }
    *levels = (*levels & ~0x40U) | (c.master_ack_level ? 0x40 : 0);
    return true;
}

static void ex1850_wire_attach(EX1850ResetState *s)
{
    const char *path = g_getenv("Z6II_MCU_WIRE_PATH");
    if (!path) { return; }
    const char *pairing = g_getenv("Z6II_MCU_WIRE_PAIRING");
    const char *quantum = g_getenv("Z6II_MCU_WIRE_POLL_NS");
    if (!pairing || strcmp(pairing, "pb14_pd12_pe3_pg6") || !quantum ||
        qemu_strtou64(quantum, NULL, 10, &s->wire_poll_ns) ||
        !s->wire_poll_ns || s->wire_poll_ns > 1000000) {
        ex1850_wire_stop("explicit pin pairing and poll quantum 1..1000000ns required");
    }
    if (mcu_wire_attach(path, 1, &s->wire)) {
        error_report("Cannot attach MCU wire endpoint: %s", strerror(errno)); exit(1);
    }
    MCUWireCore c;
    mcu_wire_snapshot(s->wire.bus, &c);
    /* Fresh cold creator, no old session, RAM snapshot, completion or key. */
    MCUWireCore expected;
    mcu_wire_core_init(&expected);
    if (memcmp(&c, &expected, sizeof(c))) {
        ex1850_wire_stop("MCU endpoint requires fresh unstarted bus");
    }
    for (size_t i = 0; i < sizeof(s->wire.bus->sram); i++) {
        if (s->wire.bus->sram[i]) {
            ex1850_wire_stop("non-cold SRAM in supplied bus; historical snapshot prohibited");
        }
    }
    s->wire_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, ex1850_wire_timer, s);
    fprintf(stderr, "EX1850_MCU_WIRE_ATTACHED path=%s SPI_RX=1 DMA_RX=2S0_CH3 "
            "SPI_TX=4 DMA_TX=2S1_CH4 poll_ns=%" PRIu64
            " relative_virtual_clocks_synchronized=0 physical_pairing_verified=0 "
            "full_native_MCU_boot_verified=0 application_flags_supplied=0\n",
            path, s->wire_poll_ns);
}
