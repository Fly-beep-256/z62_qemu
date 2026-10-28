/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Included after functional devices and z6ii_fd_exmcu_irq. Default off.
 * Native MCU GPIO stores are the sole ready/ACK producers. No old packet
 * decoder, diagnostic replay or donor-response path is used in live mode. */

static void z6ii_wire_stop(const char *reason)
{
    error_report("Z6II_MCU_WIRE_BOUNDARY reason=%s GPIO_pairing_hypothesis=1 "
                 "physical_relative_clock_verified=0 donor_or_replay_response=0", reason);
    exit(66);
}

static void z6ii_wire_apply_snapshot(Z6IIFunctionalDevices *s,
                                     const MCUWireCore *c)
{
    for (unsigned i = 0; i < 2; i++) {
        if (c->master_event_generation[i] != s->mcu_wire_events[i]) {
            s->exmcu_gpio_pending |= 1U << (2 + i);
            s->mcu_wire_events[i] = c->master_event_generation[i];
        }
    }
    /* GPIO IRQ67/68 routing and ready rising-edge latch preserve the old
     * functional controller contract; their physical timing is unmeasured. */
    z6ii_fd_exmcu_irq(s);
    timer_mod(s->mcu_wire_timer,
              qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + s->mcu_wire_poll_ns);
}

static void z6ii_wire_poll(void *opaque)
{
    Z6IIFunctionalDevices *s = opaque;
    MCUWireCore c;
    mcu_wire_snapshot(s->mcu_wire.bus, &c);
    z6ii_wire_apply_snapshot(s, &c);
}

static void z6ii_wire_gpio_input_boundary(hwaddr addr, uint32_t known,
                                          uint32_t needed, uint32_t level,
                                          int snapshot_valid, const char *reason)
{
    const uint32_t *regs = current_cpu ? ARM_CPU(current_cpu)->env.regs : NULL;
    error_report("Z6II_MCU_WIRE_GPIO_INPUT_BOUNDARY addr=%08" HWADDR_PRIx
                 " known=%08x needed=%08x level=%08x pc=%08x "
                 "r0=%08x r1=%08x r2=%08x r3=%08x snapshot_valid=%u "
                 "source=actual_guest_DATA_read unknown_guard_preserved=1",
                 addr, known, needed, level, regs ? regs[15] : 0,
                 regs ? regs[0] : 0, regs ? regs[1] : 0,
                 regs ? regs[2] : 0, regs ? regs[3] : 0, snapshot_valid);
    z6ii_wire_stop(reason);
}

/* Suspend this host MMIO call until the separate MCU actually publishes all
 * required GPIO known bits. This is not EXPEED/MCU virtual-clock synchronization
 * or measured hardware latency, and cannot synthesize a level or completion. */
static void z6ii_wire_wait_gpio_inputs(Z6IIFunctionalDevices *s, hwaddr addr,
                                       uint32_t needed, uint32_t *known,
                                       uint32_t *level)
{
    MCUWireCore c;
    int have_snapshot = mcu_wire_try_snapshot(s->mcu_wire.bus, &c);
    if (s->engine->unified) {
        /* The CPU-specific pre-dispatch hook pauses only the original load.
         * Never block the single TCG/BQL thread that must run the MCU. */
        if (!have_snapshot || (c.mcu_known & needed) != needed) {
            z6ii_wire_gpio_input_boundary(addr, have_snapshot ? c.mcu_known : 0,
                needed, have_snapshot ? c.mcu_level : 0, have_snapshot,
                "unresolved unified GPIO read reached device callback; no DATA supplied");
        }
        *known = c.mcu_known;
        *level = c.mcu_level;
        z6ii_wire_apply_snapshot(s, &c);
        return;
    }
    if (!have_snapshot || (c.mcu_known & needed) != needed) {
        uint64_t begin_ns, deadline_ns, observed_ns;
        if (mcu_wire_host_monotonic_ns(&begin_ns)) {
            z6ii_wire_gpio_input_boundary(addr, have_snapshot ? c.mcu_known : 0,
                needed, have_snapshot ? c.mcu_level : 0, have_snapshot,
                "host causal wait clock unavailable; no DATA value supplied");
        }
        deadline_ns = begin_ns + s->mcu_wire_known_wait_ms * UINT64_C(1000000);
        observed_ns = begin_ns;
        fprintf(stderr, "Z6II_MCU_WIRE_KNOWN_WAIT_BEGIN addr=%08" HWADDR_PRIx
                " needed=%08x initial_known=%08x snapshot_valid=%u "
                "limit_ms=%" PRIu64 " begin_host_ns=%" PRIu64
                " deadline_host_ns=%" PRIu64 " pc=%08x host_causality_experiment=1 "
                "virtual_clocks_synchronized=0 physical_latency_verified=0\n",
                addr, needed, have_snapshot ? c.mcu_known : 0, have_snapshot,
                s->mcu_wire_known_wait_ms, begin_ns, deadline_ns,
                current_cpu ? ARM_CPU(current_cpu)->env.regs[15] : 0);
        int result = mcu_wire_host_wait_known(s->mcu_wire.bus, needed,
                         deadline_ns, &c, &have_snapshot, &observed_ns);
        fprintf(stderr, "Z6II_MCU_WIRE_KNOWN_WAIT_END addr=%08" HWADDR_PRIx
                " outcome=%s known=%08x needed=%08x level=%08x snapshot_valid=%u "
                "elapsed_host_ns=%" PRIu64 " deadline_host_ns=%" PRIu64
                " observed_host_ns=%" PRIu64 " host_causality_experiment=1 "
                "virtual_clocks_synchronized=0 GPIO_or_DMA_completion_supplied=0\n",
                addr, result == MCU_WIRE_HOST_WAIT_READY ? "actual_known_ready" :
                      result == MCU_WIRE_HOST_WAIT_TIMEOUT ? "timeout" : "host_error",
                have_snapshot ? c.mcu_known : 0, needed,
                have_snapshot ? c.mcu_level : 0, have_snapshot,
                observed_ns - begin_ns, deadline_ns, observed_ns);
        if (result != MCU_WIRE_HOST_WAIT_READY) {
            z6ii_wire_gpio_input_boundary(addr, have_snapshot ? c.mcu_known : 0,
                needed, have_snapshot ? c.mcu_level : 0, have_snapshot,
                result == MCU_WIRE_HOST_WAIT_TIMEOUT ?
                "host causal wait deadline expired; no DATA value supplied" :
                "host causal wait failed; no DATA value supplied");
        }
    }
    *known = c.mcu_known;
    *level = c.mcu_level;
    z6ii_wire_apply_snapshot(s, &c);
}

/* Overlay only MCU inputs on the caller's DATA latch. The coupled EXPEED
 * GPIO path has its own peer input (master pin3), which must be retained. */
static bool z6ii_wire_gpio_inputs(Z6IIFunctionalDevices *s, hwaddr addr,
                                  uint64_t *value)
{
    if (!s->mcu_wire.bus || (addr != 0x04282014 && addr != 0x04282018)) {
        return false;
    }
    uint32_t known, level;
    uint32_t needed = addr == 0x04282014 ? 5 : 2;
    if (s->mcu_wire_known_wait_ms) {
        z6ii_wire_wait_gpio_inputs(s, addr, needed, &known, &level);
    } else {
        z6ii_wire_poll(s);
        mcu_wire_master_lines(s->mcu_wire.bus, &known, &level);
    }
    if ((known & needed) != needed) {
        z6ii_wire_gpio_input_boundary(addr, known, needed, level, 1,
            "DATA read precedes actual MCU output; external pad baseline unavailable");
    }
    if (addr == 0x04282014) {
        *value = (*value & ~0x600ULL) | ((level & 1) ? 0x200 : 0) |
                 ((level & 4) ? 0x400 : 0);
    } else {
        *value = (*value & ~0x8000ULL) | ((level & 2) ? 0x8000 : 0);
    }
    z6ii_capseq_actuator_input(s, addr, value);
    return true;
}

/* Both DATA paths call this only after their actual upper16 masked write.
 * A same-level first write establishes the baseline; an unmasked bit cannot. */
static bool z6ii_wire_gpio_output(Z6IIFunctionalDevices *s, hwaddr addr,
                                  uint32_t before, uint32_t after,
                                  uint32_t enable)
{
    if (!s->mcu_wire.bus || addr != 0x04282018) { return false; }
    s->setup_regs[0x2018 / 4] = after;
    z6ii_capseq_actuator_output(s, addr, before, after, enable);
    if (enable & 0x1000) {
        mcu_wire_master_ack(s->mcu_wire.bus, !!(after & 0x1000));
        fprintf(stderr, "Z6II_MCU_WIRE_MASTER_ACK DATA_bit12=%u enable=%04x pc=%08x "
                "source=actual_guest_masked_DATA_write MCU_PG6_pairing_hypothesis=1\n",
                !!(after & 0x1000), enable,
                current_cpu ? ARM_CPU(current_cpu)->env.regs[15] : 0);
    }
    return true;
}

static bool z6ii_wire_access(Z6IIFunctionalDevices *s, hwaddr addr,
                              unsigned size, bool write, uint64_t *value)
{
    if (!s->mcu_wire.bus || size != 4) { return false; }
    bool gpio_read = !write && (addr == 0x04282014 || addr == 0x04282018);
    if (!gpio_read) { z6ii_wire_poll(s); }
    if (gpio_read) {
        *value = s->setup_regs[(addr - 0x04280000) / 4];
        z6ii_wire_gpio_inputs(s, addr, value);
    } else if (write && addr == 0x04282018) {
        uint32_t mask = *value >> 16;
        uint32_t *port = &s->setup_regs[0x2018 / 4];
        uint32_t before = *port;
        *port = (*port & ~mask) | (*value & mask);
        z6ii_wire_gpio_output(s, addr, before, *port, mask);
    } else if (addr == 0x0426f000) {
        if (write) { s->exmcu_gpio_mask = *value; }
        else { *value = s->exmcu_gpio_mask; }
    } else if (addr == 0x0426f008 && !write) { *value = s->exmcu_gpio_pending; }
    else if (addr == 0x0426f010) {
        if (write) { s->exmcu_gpio_pending &= ~*value; }
        else { *value = s->exmcu_gpio_pending; }
    } else if (addr == 0x0426f014) {
        if (write) { s->exmcu_gpio_polarity = *value; }
        else { *value = s->exmcu_gpio_polarity; }
    } else if (addr == 0x0426f018) {
        if (write) { s->exmcu_gpio_mode = *value; }
        else { *value = s->exmcu_gpio_mode; }
    } else { return false; }
    z6ii_fd_exmcu_irq(s);
    z6ii_fd_mmio_trace(s, addr, size, write, *value);
    return true;
}

/* The serial timer owns a pending word. A temporarily unarmed original MCU
 * leaves that word in the FIFO, so the Master CPU and its timeout/ACK handlers
 * keep running. No host sleep, guessed MISO or completion on NOT_READY. */
static bool z6ii_wire_shift(Z6IIFunctionalDevices *s, unsigned channel,
                            uint16_t tx, uint16_t *rx)
{
    MCUWireCore failure;
    int result = mcu_wire_clock16_observed(s->mcu_wire.bus, channel, tx, rx,
                                          &failure);
    if (result == MCU_WIRE_NOT_READY) { return false; }
    if (result != MCU_WIRE_OK) {
        const MCUWireCore *c = &failure;
        unsigned stream = channel < 2 ? channel : 0;
        const MCUWireDMA *d = &c->dma[stream];
        uint64_t host_ns = 0;
        int clock_ok = !mcu_wire_host_monotonic_ns(&host_ns);
        error_report("Z6II_MCU_WIRE_CLOCK_REJECT_SNAPSHOT channel=%u tx=%04x result=%d"
            " pc=%08x host_ns=%" PRIu64 " host_clock_valid=%u virtual_ns=%" PRId64
            " CR=%08x NDTR=%u initial=%u transferred=%u frame_word_index=%u"
            " shifted_word_index=%" PRIu64 " PAR=%08x M0AR=%08x M1AR=%08x FCR=%08x"
            " LISR=%08x AHB1ENR=%08x APB2ENR=%08x SPI_CR1=%08x SPI_CR2=%08x SPI_SR=%08x"
            " known=%08x level=%08x shifted0=%" PRIu64 " shifted1=%" PRIu64
            " same_wire_lock=1 virtual_clocks_synchronized=%u completion_supplied=0",
            channel, tx, result, current_cpu ? ARM_CPU(current_cpu)->env.regs[15] : 0,
            host_ns, clock_ok, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
            d->reg[0], d->reg[1], d->initial_ndtr, d->transferred, d->transferred / 2,
            c->shifted_bytes[stream] / 2, d->reg[2], d->reg[3], d->reg[4], d->reg[5],
            c->dma_lisr, c->ahb1enr, c->apb2enr, c->spi_cr1[stream],
            c->spi_cr2[stream], c->spi_sr[stream], c->mcu_known, c->mcu_level,
            c->shifted_bytes[0], c->shifted_bytes[1], s->engine->unified);
        z6ii_wire_stop("clock without native-ready SPI DMA contract; no completion supplied");
    }
    /* Channel0's unused MISO retains the explicit disconnected-high
     * functional hypothesis. Channel1 returns only original MCU SRAM. */
    return true;
}

static bool z6ii_wire_init(Z6IIFunctionalDevices *s, const char *role)
{
    const char *path = z6ii_engine_getenv(s->engine, "Z6II_MCU_WIRE_PATH");
    if (!path) { return false; }
    if (strcmp(role, "master")) { return true; } /* shared launch environment */
    const char *pairing = z6ii_engine_getenv(s->engine, "Z6II_MCU_WIRE_PAIRING");
    const char *quantum = z6ii_engine_getenv(s->engine, "Z6II_MCU_WIRE_POLL_NS");
    if (!s || !pairing || strcmp(pairing, "pb14_pd12_pe3_pg6") || !quantum ||
        qemu_strtou64(quantum, NULL, 10, &s->mcu_wire_poll_ns) ||
        !s->mcu_wire_poll_ns || s->mcu_wire_poll_ns > 1000000) {
        z6ii_wire_stop("explicit master devices, pairing and poll quantum required");
    }
    const char *known_wait = z6ii_engine_getenv(s->engine, "Z6II_MCU_WIRE_KNOWN_WAIT_MS");
    s->mcu_wire_known_wait_ms = 0;
    if (known_wait && (qemu_strtou64(known_wait, NULL, 10,
                                   &s->mcu_wire_known_wait_ms) ||
                       s->mcu_wire_known_wait_ms > 5000)) {
        z6ii_wire_stop("causal GPIO known-bit wait requires explicit integer0..5000ms");
    }
    /* Any former EXMCU replay/donor option is incompatible. Passive capture
     * has a separate future wire trace path, not the old packet callback. */
    GHashTableIter option_iter;
    gpointer option_key;
    g_hash_table_iter_init(&option_iter, s->engine->options);
    while (g_hash_table_iter_next(&option_iter, &option_key, NULL)) {
        if (g_str_has_prefix(option_key, "Z6II_EXMCU_")) {
            z6ii_wire_stop("legacy EXMCU option conflicts with live native endpoint");
        }
    }
    if (mcu_wire_attach(path, 2, &s->mcu_wire)) {
        error_report("Cannot attach master wire endpoint: %s", strerror(errno)); exit(1);
    }
    if (s->engine->unified) {
        s->engine->wire_bus = s->mcu_wire.bus;
        s->engine->wire_path = g_strdup(path);
    }
    s->exmcu_test_device = false;
    s->exmcu_protocol_opaque = NULL;
    s->exmcu_protocol_tx = NULL;
    s->exmcu_protocol_queued = NULL;
    s->exmcu_protocol_consumed = NULL;
    s->exmcu_capture_sync_test = false;
    s->exmcu_no_lens = false;
    s->mcu_wire_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, z6ii_wire_poll, s);
    timer_mod(s->mcu_wire_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + s->mcu_wire_poll_ns);
    fprintf(stderr, "Z6II_MCU_WIRE_KNOWN_WAIT_CONFIG enabled=%u limit_ms=%" PRIu64
            " wait_clock=%s virtual_clocks_synchronized=%u "
            "physical_latency_verified=0\n",
            !!s->mcu_wire_known_wait_ms, s->mcu_wire_known_wait_ms,
            s->engine->unified ? "QEMU_CLOCK_VIRTUAL" : "host_monotonic",
            s->engine->unified);
    fprintf(stderr, "Z6II_MCU_WIRE_ATTACHED path=%s poll_ns=%" PRIu64
            " native_peer=EX1850 SPI1_SPI4_DMA2S0S1 pin_pairing_hypothesis=1 "
            "relative_virtual_clocks_synchronized=%u IRQ_edge_semantics_hypothesis=1 "
            "replay_packets=0 donor_responses=0 full_native_boot_verified=0\n",
            path, s->mcu_wire_poll_ns, s->engine->unified);
    return true;
}
