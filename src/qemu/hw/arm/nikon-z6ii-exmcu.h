/* SPDX-License-Identifier: GPL-2.0-or-later */
/* EX1850 transport hypothesis, opt-in and master-only. The replay packet is
 * produced by original EX1850 serializer instructions, not by a full MCU
 * boot. Device FIFO/GPIO input never writes an application flag or pointer.
 * Zero MAKE/MODE/INDI versions are evidence of absent configuration. */
static void z6ii_exmcu_gpio_inputs(Z6IIState *s, hwaddr addr, uint64_t *value)
{
    Z6IIFunctionalDevices *d = s->devices;
    if (!d) { return; }
    if (d->mcu_wire.bus) {
        z6ii_wire_gpio_inputs(d, addr, value);
        return;
    }
    if (!d->exmcu_test_device) { return; }
    if (addr == 0x04282014) {
        *value = (*value & ~UINT64_C(0x600)) | (d->exmcu_tx_ready ? 0x200 : 0) |
                 (d->exmcu_rx_ready ? 0x400 : 0);
    } else if (addr == 0x04282018) {
        *value = (*value & ~UINT64_C(0x8000)) | (d->exmcu_tx_ack ? 0x8000 : 0);
    }
    /* All other GPIO bits, including the observed two-ended candidate
     * slave pin10 -> master pin3, retain their independently modeled value. */
}

static void z6ii_exmcu_rx_queued(void *opaque)
{
    Z6IIState *s = opaque;
    Z6IIFunctionalDevices *d = s->devices;
    if (d->exmcu_rx_count && !d->exmcu_rx_ready && !s->exmcu_rx_awaiting_ack) {
        d->exmcu_rx_ready = true;
        d->exmcu_gpio_pending |= 8;
        z6ii_fd_exmcu_irq(d);
    }
}

static void z6ii_exmcu_rx_consumed(void *opaque)
{
    Z6IIState *s = opaque;
    s->devices->exmcu_rx_ready = false;
    s->exmcu_rx_awaiting_ack = true;
    fprintf(stderr, "Z6II_EXMCU_SPI_PACKET_CONSUMED remaining=%u awaiting_native_RX_ACK=1\n",
            s->devices->exmcu_rx_count);
}

static void z6ii_exmcu_gpio_output(Z6IIState *s, hwaddr addr,
                                 uint32_t before, uint32_t after, uint32_t enable)
{
    if (s->devices && s->devices->mcu_wire.bus) {
        z6ii_wire_gpio_output(s->devices, addr, before, after, enable);
        return;
    }
    /* Original serial GPIO object C1803B94: pin69, DATA04282018 bit12.
     * Original1020B69A lowers RX ACK;1020B720 raises it after checksum.
     * This is the emulated wire handshake, not an application-ready flag. */
    if (s->devices && s->devices->exmcu_test_device && addr == 0x04282018 &&
        s->exmcu_rx_awaiting_ack && !(before & 0x1000) && (after & 0x1000)) {
        s->exmcu_rx_awaiting_ack = false;
        fprintf(stderr, "Z6II_EXMCU_NATIVE_RX_ACK remaining=%u wire_hypothesis=1\n",
                s->devices->exmcu_rx_count);
        z6ii_exmcu_rx_queued(s);
    }
}

static void z6ii_exmcu_enqueue(Z6IIState *s, const uint8_t *packet, const char *label)
{
    Z6IIFunctionalDevices *d = s->devices;
    /* Arrival is a device input timing hypothesis, never an instruction
     * callback or an application-ready test. GPIO initialization can clear
     * an earlier edge; retain that failure in the zero-delay control. */
    if (d->exmcu_rx_count == ARRAY_SIZE(d->exmcu_rx)) {
        error_report("EX MCU replay cannot overwrite a full device receive queue");
        s->faulted = true;
        vm_stop(RUN_STATE_PAUSED);
        return;
    }
    unsigned index = (d->exmcu_rx_head + d->exmcu_rx_count) % ARRAY_SIZE(d->exmcu_rx);
    memcpy(d->exmcu_rx[index], packet, 256);
    d->exmcu_rx_count++;
    z6ii_exmcu_rx_queued(s);
    fprintf(stderr, "Z6II_EXMCU_ORIGINAL_PACKET_ARRIVED kind=%s virtual_ns=%" PRId64
            " pending=%08x mask=%08x mode=%08x polarity=%08x "
            "original_MCU_boot=0 arrival_time_physically_verified=0\n",
            label, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), d->exmcu_gpio_pending,
            d->exmcu_gpio_mask, d->exmcu_gpio_mode, d->exmcu_gpio_polarity);
}

static void z6ii_exmcu_original_report_arrived(void *opaque)
{
    Z6IIState *s = opaque;
    z6ii_exmcu_enqueue(s, s->exmcu_original_packet, "configuration-startup");
}

static void z6ii_exmcu_key_arrived(void *opaque)
{
    Z6IIState *s = opaque;
    z6ii_exmcu_enqueue(s, s->exmcu_key_packet, "GPIO-sampled-diagnostic-KEY");
}

static void z6ii_exmcu_power_arrived(void *opaque)
{
    Z6IIState *s = opaque;
    z6ii_exmcu_enqueue(s, s->exmcu_power_packet, "power-C-initialized-diagnostic-state");
}

static void z6ii_exmcu_service0d_arrived(void *opaque)
{
    Z6IIState *s = opaque;
    z6ii_exmcu_enqueue(s, s->exmcu_service0d_packet, "service0D-native-GPIO-wire82-diagnostic");
}

static void z6ii_exmcu_service0d_command01_arrived(void *opaque)
{
    Z6IIState *s = opaque;
    z6ii_exmcu_enqueue(s, s->exmcu_service0d_command01_packet,
                      "service0D-native-init-phase1-wire81-diagnostic");
}

static void z6ii_exmcu_sys_arrived(void *opaque)
{
    Z6IIState *s = opaque;
    if (s->exmcu_sys_stage == 1) {
        z6ii_exmcu_enqueue(s, s->exmcu_sys_version_packet, "SYS-version");
        s->exmcu_sys_stage = 2;
        if (s->exmcu_sys_state_enabled) {
            /* Explicit C-initialized diagnostic state input,100ms later.
             * No physical control sampling or MCU startup task is presumed. */
            timer_mod(s->exmcu_sys_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 100000000);
        }
    } else if (s->exmcu_sys_stage == 2 && s->exmcu_sys_state_enabled) {
        z6ii_exmcu_enqueue(s, s->exmcu_sys_state_packet, "SYS-C-initialized-state");
        s->exmcu_sys_stage = 3;
    }
}

static void z6ii_exmcu_original_tx(void *opaque, const uint8_t *packet)
{
    Z6IIState *s = opaque;
    /* Exact original initial SYS request, not later wire0D version notice. */
    static const uint8_t request_payload[28] = {
        1, 2, 0, 0, '0','1','.','7','0','.','0','2',0,0,0,0,
        'Z',' ','6','_','2',0,0,0,0x69,0,0,0
    };
    if (s->exmcu_sys_version_enabled && !s->exmcu_sys_request_seen &&
        packet[0] == 1 && packet[1] == 1 && lduw_le_p(packet + 2) == 28 &&
        !memcmp(packet + 8, request_payload, sizeof(request_payload))) {
        s->exmcu_sys_request_seen = true;
        s->exmcu_sys_stage = 1;
        timer_mod(s->exmcu_sys_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                                    (int64_t)s->exmcu_sys_delay_ms * 1000000);
        fprintf(stderr, "Z6II_EXMCU_SYS_REQUEST original_service01_command01=1 "
                "version_response_delay_ms=%u physical_timing_verified=0 state_C_init_input=%u\n",
                s->exmcu_sys_delay_ms, s->exmcu_sys_state_enabled);
    }
    if (s->exmcu_service0d_enabled && !s->exmcu_service0d_request_seen) {
        /* Only the captured original command02, sequence1 request. The
         * response is the unchanged packet produced by original MCU GPIO,
         * completion callback and serializer instructions. No host selects
         * a result or constructs response bytes; other requests stay pending.
         * Original RTOS mutex API failure was retained in that diagnostic. */
        g_autofree char *sha = g_compute_checksum_for_data(G_CHECKSUM_SHA256, packet, 256);
        if (!strcmp(sha, "01ee6699bdde0435350399d545d95d957181a88ca1cd8dbe2f29a6388b79004d")) {
            s->exmcu_service0d_request_seen = true;
            timer_mod(s->exmcu_service0d_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                      (int64_t)s->exmcu_service0d_delay_ms * 1000000);
            fprintf(stderr, "Z6II_EXMCU_SERVICE0D_REQUEST exact_original_sequence1=1 "
                    "native_GPIO_wire82_response_delay_ms=%u MCU_full_boot=0 "
                    "physical_GPIO_effect_verified=0 host_completion_result_supplied=0\n",
                    s->exmcu_service0d_delay_ms);
        }
    }
    if (s->exmcu_service0d_command01_enabled &&
        !s->exmcu_service0d_command01_request_seen) {
        /* The original MCU module initializer, using a declared diagnostic
         * phase1 CPU input, established state3 and produced this packet via
         * the original state3/input2 and completion/serializer path. This is
         * not a physical completion signal or full MCU power-on execution.
         * Replay only the captured command01/sequence2; never edit payloads. */
        g_autofree char *sha = g_compute_checksum_for_data(G_CHECKSUM_SHA256, packet, 256);
        if (!strcmp(sha, "e9ba210be8296467ef14030b2cd91f8c34cd4d71c3ca1aa3c3867e2af6d2a677")) {
            s->exmcu_service0d_command01_request_seen = true;
            timer_mod(s->exmcu_service0d_command01_timer,
                      qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                      (int64_t)s->exmcu_service0d_command01_delay_ms * 1000000);
            fprintf(stderr, "Z6II_EXMCU_SERVICE0D_COMMAND01_REQUEST exact_original_sequence2=1 "
                    "native_init_wire81_response_delay_ms=%u MCU_full_boot=0 "
                    "MCU_phase1_diagnostic=1 phase_natural_caller_verified=0 "
                    "host_completion_result_supplied=0 host_worker_state_supplied=0\n",
                    s->exmcu_service0d_command01_delay_ms);
        }
    }
}

static void z6ii_exmcu_load_packet(const char *path, const char *expected,
                                 uint8_t *destination, const char *label)
{
    g_autofree gchar *data = NULL;
    gsize length = 0;
    g_autoptr(GError) error = NULL;
    if (!g_file_get_contents(path, &data, &length, &error)) {
        error_report("Cannot load original EX1850 %s packet: %s", label, error->message);
        exit(1);
    }
    g_autofree char *sha = g_compute_checksum_for_data(G_CHECKSUM_SHA256, (guchar *)data, length);
    if (length != 256 || strcmp(sha, expected)) {
        error_report("Original EX1850 %s packet identity mismatch", label);
        exit(1);
    }
    memcpy(destination, data, 256);
    fprintf(stderr, "Z6II_EXMCU_ORIGINAL_INPUT kind=%s SHA256=%s MCU_full_boot=0 "
            "main_guest_state_fixtures=0\n", label, sha);
}

static void z6ii_exmcu_transport_init(Z6IIState *s)
{
    if (z6ii_wire_init(s->devices, s->profile->role)) { return; }
    const char *enabled = z6ii_engine_getenv(s->engine, "Z6II_EXMCU_TRANSPORT");
    const char *path = z6ii_engine_getenv(s->engine, "Z6II_EXMCU_PACKET");
    const char *version_path = z6ii_engine_getenv(s->engine, "Z6II_EXMCU_SYS_VERSION_PACKET");
    const char *state_path = z6ii_engine_getenv(s->engine, "Z6II_EXMCU_SYS_STATE_PACKET");
    const char *key_path = z6ii_engine_getenv(s->engine, "Z6II_EXMCU_KEY_PACKET");
    const char *power_path = z6ii_engine_getenv(s->engine, "Z6II_EXMCU_POWER_PACKET");
    const char *service0d_path = z6ii_engine_getenv(s->engine, "Z6II_EXMCU_SERVICE0D_PACKET");
    const char *command01_path = z6ii_engine_getenv(s->engine, "Z6II_EXMCU_SERVICE0D_COMMAND01_PACKET");
    if (!enabled && !path && !version_path && !state_path && !key_path &&
        !power_path && !service0d_path && !command01_path) { return; }
    if (!enabled || strcmp(enabled, "1") || !s->devices ||
        strcmp(s->profile->role, "master")) {
        error_report("EX MCU transport requires explicit master functional board and value1");
        exit(1);
    }
    Z6IIFunctionalDevices *d = s->devices;
    d->exmcu_test_device = true;
    d->exmcu_tx_ready = true;
    d->exmcu_gpio_mask = UINT32_MAX;
    d->exmcu_protocol_opaque = s;
    d->exmcu_protocol_tx = z6ii_exmcu_original_tx;
    d->exmcu_protocol_queued = z6ii_exmcu_rx_queued;
    d->exmcu_protocol_consumed = z6ii_exmcu_rx_consumed;
    fprintf(stderr, "Z6II_EXMCU_TRANSPORT master_only=1 original_MCU_full_boot=0 "
            "factory_configuration=absent register_or_RAM_fixtures=0 "
            "GPIO_SPI_hypothesis=1 DMA_transport=absent donor_CAPCOM_replies=1\n");
    if (state_path && !version_path) {
        error_report("SYS C-initialized diagnostic input requires original SYS version response");
        exit(1);
    }
    if (version_path) {
        z6ii_exmcu_load_packet(version_path,
                "cdfdfa0ff6c6d330cc0d6afca9c811998153c64abe2a961f52d4b69844f7d8a1",
                s->exmcu_sys_version_packet, "SYS-version");
        s->exmcu_sys_version_enabled = true;
        s->exmcu_sys_delay_ms = 1000;
        const char *sys_delay = z6ii_engine_getenv(s->engine, "Z6II_EXMCU_SYS_DELAY_MS");
        if (sys_delay && (qemu_strtoui(sys_delay, NULL, 10, &s->exmcu_sys_delay_ms) ||
                          s->exmcu_sys_delay_ms > 5000)) {
            error_report("SYS response delay hypothesis must be between0 and5000ms");
            exit(1);
        }
        s->exmcu_sys_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, z6ii_exmcu_sys_arrived, s);
    }
    if (state_path) {
        z6ii_exmcu_load_packet(state_path,
                "10aaf044134c791bd486afbb4ed7973e4a9c67f2adc1f016372477a96055dd25",
                s->exmcu_sys_state_packet, "SYS-C-initialized-state");
        s->exmcu_sys_state_enabled = true;
    }
    if (key_path) {
        const char *level = z6ii_engine_getenv(s->engine, "Z6II_EXMCU_KEY_LEVEL");
        const char *sha = NULL;
        if (level && !strcmp(level, "high")) {
            sha = "e719378f4a32e6a7bf5b59f47f85a03cf669c8dfecab2a5e312119930ad670ac";
        } else if (level && !strcmp(level, "low")) {
            sha = "625c01b8135dc9d714e6b231c1ad5ff758c7156d92ded21d7e4de46a51bf8458";
        } else {
            error_report("GPIO-sampled KEY input requires explicit high/low source identity");
            exit(1);
        }
        z6ii_exmcu_load_packet(key_path, sha, s->exmcu_key_packet, "GPIO-sampled-KEY");
        s->exmcu_key_delay_ms = 2000;
        const char *key_delay = z6ii_engine_getenv(s->engine, "Z6II_EXMCU_KEY_DELAY_MS");
        if (key_delay && (qemu_strtoui(key_delay, NULL, 10, &s->exmcu_key_delay_ms) ||
                          s->exmcu_key_delay_ms > 5000)) {
            error_report("GPIO-sampled KEY input delay hypothesis must be0..5000ms");
            exit(1);
        }
        s->exmcu_key_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, z6ii_exmcu_key_arrived, s);
        timer_mod(s->exmcu_key_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                                    (int64_t)s->exmcu_key_delay_ms * 1000000);
        fprintf(stderr, "Z6II_EXMCU_KEY_PIN_INPUT level=%s delay_ms=%u "
                "original_GPIO_sampler_and_serializer=1 MCU_full_boot=0 "
                "physical_pin_levels_measured=0 guest_RAM_fixture=0\n",
                level, s->exmcu_key_delay_ms);
    }
    if (power_path) {
        /* Original serializer output from untouched C-initialized state.
         * Battery/ADC/controller sampling is absent. This never supplies
         * application-ready flags, completion events, or configuration. */
        z6ii_exmcu_load_packet(power_path,
                "15601ea6879781609e45e607b2f055315836506e33d3a2b2889c9fbe34cd55f2",
                s->exmcu_power_packet, "power-C-initialized-diagnostic-state");
        s->exmcu_power_delay_ms = 3000;
        const char *power_delay = z6ii_engine_getenv(s->engine, "Z6II_EXMCU_POWER_DELAY_MS");
        if (power_delay && (qemu_strtoui(power_delay, NULL, 10, &s->exmcu_power_delay_ms) ||
                            s->exmcu_power_delay_ms > 5000)) {
            error_report("C-initialized power arrival hypothesis must be0..5000ms");
            exit(1);
        }
        s->exmcu_power_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, z6ii_exmcu_power_arrived, s);
        timer_mod(s->exmcu_power_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                                      (int64_t)s->exmcu_power_delay_ms * 1000000);
        fprintf(stderr, "Z6II_EXMCU_POWER_C_INIT_INPUT delay_ms=%u "
                "source_state_supplied=0 physical_power_sampling=0 "
                "original_serializer=1 MCU_full_boot=0 guest_RAM_fixture=0\n",
                s->exmcu_power_delay_ms);
    }
    if (service0d_path) {
        z6ii_exmcu_load_packet(service0d_path,
                "a1b460698e1895650d541220dea57ef01e701fd653deb0499748d407eb73ec83",
                s->exmcu_service0d_packet, "service0D-native-GPIO-wire82-diagnostic");
        s->exmcu_service0d_enabled = true;
        s->exmcu_service0d_delay_ms = 10;
        const char *delay = z6ii_engine_getenv(s->engine, "Z6II_EXMCU_SERVICE0D_DELAY_MS");
        if (delay && (qemu_strtoui(delay, NULL, 10, &s->exmcu_service0d_delay_ms) ||
                      s->exmcu_service0d_delay_ms > 5000)) {
            error_report("Native GPIO wire82 response delay hypothesis must be0..5000ms");
            exit(1);
        }
        s->exmcu_service0d_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, z6ii_exmcu_service0d_arrived, s);
    }
    if (command01_path) {
        if (!service0d_path) {
            error_report("Original command01 diagnostic replay requires the preceding wire82 input");
            exit(1);
        }
        z6ii_exmcu_load_packet(command01_path,
                "e26040542afb1efe1d3871c5135e365d1fdc60a1d440c3fc80a94d7a0f02995c",
                s->exmcu_service0d_command01_packet, "service0D-native-init-phase1-wire81-diagnostic");
        s->exmcu_service0d_command01_enabled = true;
        s->exmcu_service0d_command01_delay_ms = 10;
        const char *delay = z6ii_engine_getenv(s->engine, "Z6II_EXMCU_SERVICE0D_COMMAND01_DELAY_MS");
        if (delay && (qemu_strtoui(delay, NULL, 10, &s->exmcu_service0d_command01_delay_ms) ||
                      s->exmcu_service0d_command01_delay_ms > 5000)) {
            error_report("Original wire81 response delay hypothesis must be0..5000ms");
            exit(1);
        }
        s->exmcu_service0d_command01_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                z6ii_exmcu_service0d_command01_arrived, s);
    }
    if (path) {
        g_autofree gchar *data = NULL;
        gsize length = 0;
        g_autoptr(GError) error = NULL;
        if (!g_file_get_contents(path, &data, &length, &error)) {
            error_report("Cannot load original EX1850 startup packet: %s", error->message);
            exit(1);
        }
        g_autofree char *sha = g_compute_checksum_for_data(G_CHECKSUM_SHA256,
                                                          (guchar *)data, length);
        if (length != 256 || strcmp(sha,
                "77b609bb95f21cbf40666862ee1c7e94120d24362192860528812aeae2081a42")) {
            error_report("Original EX1850 startup replay packet identity mismatch");
            exit(1);
        }
        memcpy(s->exmcu_original_packet, data, length);
        const char *delay = z6ii_engine_getenv(s->engine, "Z6II_EXMCU_PACKET_DELAY_MS");
        unsigned milliseconds = 0;
        if (delay && (qemu_strtoui(delay, NULL, 10, &milliseconds) || milliseconds > 5000)) {
            error_report("EX MCU packet arrival hypothesis must be between0 and5000ms");
            exit(1);
        }
        s->exmcu_report_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                            z6ii_exmcu_original_report_arrived, s);
        timer_mod(s->exmcu_report_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                                        (int64_t)milliseconds * 1000000);
        fprintf(stderr, "Z6II_EXMCU_ORIGINAL_PACKET prepared=1 arrival_delay_ms=%u service=0F route=02 "
                "payload=13000000000000000000000000000000 SHA256=%s "
                "serializer_diagnostic_source=1 ready_success_assumed=0\n", milliseconds, sha);
    }
}
