/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Optional original BA2 reset execution. All model inputs are explicit. */
#ifndef Z6II_BA2_BOARD_QEMU_H
#define Z6II_BA2_BOARD_QEMU_H

static uint64_t z6ii_ba2_required_number(const char *key, uint64_t maximum)
{
    uint64_t value;
    if (!z6ii_hdmi_decimal(getenv(key), maximum, &value)) {
        error_report("BA2 requires explicit decimal %s in 0..%" PRIu64, key, maximum);
        exit(1);
    }
    return value;
}

static void z6ii_ba2_master_irq_update(void *opaque)
{
    z6ii_ipu2402_qemu_update_irq(opaque);
}

static Z6IIBA2SPRResult z6ii_ba2_board_spr_read(void *opaque, uint32_t selector,
                                             uint32_t *value)
{
    Z6IIState *s = opaque;
    if (selector == UINT32_C(0x5000) && s->ba2_spr5000_enabled) {
        Z6IIBA2SPRResult result = z6ii_ba2_spr5000_storage_read(
            &s->ba2_spr5000, selector, value);
        if (result == Z6II_BA2_SPR_OK) {
            fprintf(stderr, "Z6II_BA2_SPR5000_ACCESS access=R value=%08x"
                " reads=%" PRIu64 " writes=%" PRIu64 " timer_events=0 IRQ_events=0\n",
                *value, s->ba2_spr5000.reads, s->ba2_spr5000.writes);
        }
        return result;
    }
    if (selector == UINT32_C(0x5001) && s->ba2_spr5001_enabled) {
        Z6IIBA2SPRResult result = z6ii_ba2_spr5001_storage_read(
            &s->ba2_spr5001, selector, value);
        if (result == Z6II_BA2_SPR_OK) {
            fprintf(stderr, "Z6II_BA2_SPR5001_ACCESS access=R value=%08x"
                " reads=%" PRIu64 " writes=%" PRIu64 " timer_events=0 IRQ_events=0\n",
                *value, s->ba2_spr5001.reads, s->ba2_spr5001.writes);
        }
        return result;
    }
    if (selector == UINT32_C(0x4000) && s->ba2_spr4000_enabled) {
        Z6IIBA2SPRResult result = z6ii_ba2_spr4000_storage_read(
            &s->ba2_spr4000, selector, value);
        if (result == Z6II_BA2_SPR_OK) {
            fprintf(stderr, "Z6II_BA2_SPR4000_ACCESS access=R value=%08x"
                " reads=%" PRIu64 " writes=%" PRIu64 " timer_events=0 IRQ_events=0\n",
                *value, s->ba2_spr4000.reads, s->ba2_spr4000.writes);
        }
        return result;
    }
    if (selector == UINT32_C(0x5004) && s->ba2_spr5004_enabled) {
        Z6IIBA2SPRResult result = z6ii_ba2_spr5004_snapshot_read(
            &s->ba2_spr5004, selector, value);
        if (result == Z6II_BA2_SPR_OK) {
            fprintf(stderr, "Z6II_BA2_SPR5004_ACCESS access=R value=%08x"
                " reads=%" PRIu64 " writes=0 timer_events=0 IRQ_events=0\n",
                *value, s->ba2_spr5004.reads);
        }
        return result;
    }
    if (selector == UINT32_C(0x5005) && s->ba2_spr5005_enabled) {
        Z6IIBA2SPRResult result = z6ii_ba2_spr5005_snapshot_read(
            &s->ba2_spr5005, selector, value);
        if (result == Z6II_BA2_SPR_OK) {
            fprintf(stderr, "Z6II_BA2_SPR5005_ACCESS access=R value=%08x"
                " reads=%" PRIu64 " writes=0 timer_events=0 IRQ_events=0\n",
                *value, s->ba2_spr5005.reads);
        }
        return result;
    }
    return z6ii_ba2_reset_bank98_read(&s->ba2_spr_bank, selector, value);
}

static Z6IIBA2SPRResult z6ii_ba2_board_spr_write(void *opaque, uint32_t selector,
                                              uint32_t value)
{
    Z6IIState *s = opaque;
    if (selector == UINT32_C(0x5000) && s->ba2_spr5000_enabled) {
        Z6IIBA2SPRResult result = z6ii_ba2_spr5000_storage_write(
            &s->ba2_spr5000, selector, value);
        if (result == Z6II_BA2_SPR_OK) {
            fprintf(stderr, "Z6II_BA2_SPR5000_ACCESS access=W value=%08x"
                " reads=%" PRIu64 " writes=%" PRIu64 " timer_events=0 IRQ_events=0\n",
                value, s->ba2_spr5000.reads, s->ba2_spr5000.writes);
        }
        return result;
    }
    if (selector == UINT32_C(0x5001) && s->ba2_spr5001_enabled) {
        Z6IIBA2SPRResult result = z6ii_ba2_spr5001_storage_write(
            &s->ba2_spr5001, selector, value);
        if (result == Z6II_BA2_SPR_OK) {
            fprintf(stderr, "Z6II_BA2_SPR5001_ACCESS access=W value=%08x"
                " reads=%" PRIu64 " writes=%" PRIu64 " timer_events=0 IRQ_events=0\n",
                value, s->ba2_spr5001.reads, s->ba2_spr5001.writes);
        }
        return result;
    }
    if (selector == UINT32_C(0x4000) && s->ba2_spr4000_enabled) {
        Z6IIBA2SPRResult result = z6ii_ba2_spr4000_storage_write(
            &s->ba2_spr4000, selector, value);
        if (result == Z6II_BA2_SPR_OK) {
            fprintf(stderr, "Z6II_BA2_SPR4000_ACCESS access=W value=%08x"
                " reads=%" PRIu64 " writes=%" PRIu64 " timer_events=0 IRQ_events=0\n",
                value, s->ba2_spr4000.reads, s->ba2_spr4000.writes);
        }
        return result;
    }
    if (selector == UINT32_C(0x5004) && s->ba2_spr5004_enabled) {
        return z6ii_ba2_spr5004_snapshot_write(&s->ba2_spr5004, selector, value);
    }
    if (selector == UINT32_C(0x5005) && s->ba2_spr5005_enabled) {
        return z6ii_ba2_spr5005_snapshot_write(&s->ba2_spr5005, selector, value);
    }
    return z6ii_ba2_reset_bank98_write(&s->ba2_spr_bank, selector, value);
}

static void z6ii_ba2_board_spr_reset(void *opaque)
{
    Z6IIState *s = opaque;
    memset(&s->ba2_spr_bank, 0, sizeof(s->ba2_spr_bank));
    memcpy(s->ba2_spr_bank.value, s->ba2_spr_initial, sizeof(s->ba2_spr_initial));
    if (s->ba2_spr5000_enabled) {
        if (z6ii_ba2_spr5000_storage_init(&s->ba2_spr5000,
                s->ba2_spr5000_initial, "caller-explicit-initial; silicon reset unverified")
                != Z6II_BA2_SPR_OK ||
            z6ii_ba2_spr5000_storage_enable(&s->ba2_spr5000,
                "explicit-raw32-storage-candidate-v1; no timer/IRQ/Ready effects")
                != Z6II_BA2_SPR_OK) {
            error_report("BA2 SPR5000 explicit storage initialization failed");
            exit(1);
        }
    }
    if (s->ba2_spr5001_enabled) {
        if (z6ii_ba2_spr5001_storage_init(&s->ba2_spr5001,
                s->ba2_spr5001_initial, "caller-explicit-initial; silicon reset unverified")
                != Z6II_BA2_SPR_OK ||
            z6ii_ba2_spr5001_storage_enable(&s->ba2_spr5001,
                "explicit-raw32-storage-candidate-v1; no timer/IRQ/Ready effects")
                != Z6II_BA2_SPR_OK) {
            error_report("BA2 SPR5001 explicit storage initialization failed");
            exit(1);
        }
    }
    if (s->ba2_spr4000_enabled) {
        if (z6ii_ba2_spr4000_storage_init(&s->ba2_spr4000,
                s->ba2_spr4000_initial, "caller-explicit-initial; silicon reset unverified")
                != Z6II_BA2_SPR_OK ||
            z6ii_ba2_spr4000_storage_enable(&s->ba2_spr4000,
                "explicit-raw32-storage-candidate-v1; no timer/IRQ/Ready effects")
                != Z6II_BA2_SPR_OK) {
            error_report("BA2 SPR4000 explicit storage initialization failed");
            exit(1);
        }
    }
    if (s->ba2_spr5004_enabled) {
        if (z6ii_ba2_spr5004_snapshot_init(&s->ba2_spr5004,
                s->ba2_spr5004_initial, "caller-explicit raw32 snapshot; silicon meaning unproved")
                != Z6II_BA2_SPR_OK ||
            z6ii_ba2_spr5004_snapshot_enable(&s->ba2_spr5004,
                "SPR5004-explicit-raw32-read-v1; no timer/IRQ/Ready effects")
                != Z6II_BA2_SPR_OK) {
            error_report("BA2 SPR5004 explicit snapshot initialization failed");
            exit(1);
        }
    }
    if (s->ba2_spr5005_enabled) {
        if (z6ii_ba2_spr5005_snapshot_init(&s->ba2_spr5005,
                s->ba2_spr5005_initial, "caller-explicit raw32 snapshot; silicon meaning unproved")
                != Z6II_BA2_SPR_OK ||
            z6ii_ba2_spr5005_snapshot_enable(&s->ba2_spr5005,
                "SPR5005-explicit-raw32-read-v1; no timer/IRQ/Ready effects")
                != Z6II_BA2_SPR_OK) {
            error_report("BA2 SPR5005 explicit snapshot initialization failed");
            exit(1);
        }
    }
}

static void z6ii_ba2_board_init(Z6IIState *s)
{
    const char *mode = getenv("Z6II_BA2_MODEL");
    if (!mode || strcmp(s->profile->role, "master")) {
        return;
    }
    if (!s->devices || !s->ipu2402_enabled) {
        error_report("BA2 reset execution requires functional Master and IPU2402 fifo-v1");
        exit(1);
    }
    const char *endian = getenv("Z6II_BA2_DATA_ENDIAN");
    if (!endian || (strcmp(endian, "le") && strcmp(endian, "be"))) {
        error_report("BA2 requires explicit Z6II_BA2_DATA_ENDIAN=le or be");
        exit(1);
    }
    const char *spr = getenv("Z6II_BA2_SPR_POLICY");
    if (!spr || strcmp(spr, "observed-reset-storage-v1")) {
        error_report("BA2 requires explicit observed-reset-storage-v1 SPR policy");
        exit(1);
    }
    s->ba2_spr_initial[0] = z6ii_ba2_required_number("Z6II_BA2_SPR11_INITIAL", UINT32_MAX);
    s->ba2_spr_initial[1] = z6ii_ba2_required_number("Z6II_BA2_SPR14_INITIAL", UINT32_MAX);
    s->ba2_spr_initial[2] = z6ii_ba2_required_number("Z6II_BA2_SPR15_INITIAL", UINT32_MAX);
    const char *spr5000 = getenv("Z6II_BA2_SPR5000_POLICY");
    const char *tick139 = getenv("Z6II_BA2_TICK139_POLICY");
    if (tick139 && (spr5000 || getenv("Z6II_BA2_SPR5000_INITIAL") ||
        getenv("Z6II_BA2_SPR5001_POLICY") || getenv("Z6II_BA2_SPR5001_INITIAL") ||
        getenv("Z6II_BA2_SPR5004_POLICY") || getenv("Z6II_BA2_SPR5004_INITIAL") ||
        getenv("Z6II_BA2_SPR5005_POLICY") || getenv("Z6II_BA2_SPR5005_INITIAL"))) {
        error_report("BA2 periodic clock conflicts with raw timer SPR storage policies");
        exit(1);
    }
    if (!tick139 && (getenv("Z6II_BA2_TICK139_SOURCE_HZ") ||
                     getenv("Z6II_BA2_TICK139_INITIAL_SOURCE_CYCLES"))) {
        error_report("BA2 clock inputs require an explicit periodic clock policy");
        exit(1);
    }
    if (spr5000) {
        if (strcmp(spr5000, "explicit-raw32-storage-candidate-v1")) {
            error_report("BA2 SPR5000 requires explicit-raw32-storage-candidate-v1");
            exit(1);
        }
        s->ba2_spr5000_initial = z6ii_ba2_required_number(
            "Z6II_BA2_SPR5000_INITIAL", UINT32_MAX);
        s->ba2_spr5000_enabled = true;
    } else if (getenv("Z6II_BA2_SPR5000_INITIAL")) {
        error_report("BA2 SPR5000 initial value requires an explicit policy");
        exit(1);
    }
    const char *spr5001 = getenv("Z6II_BA2_SPR5001_POLICY");
    if (spr5001) {
        if (strcmp(spr5001, "explicit-raw32-storage-candidate-v1")) {
            error_report("BA2 SPR5001 requires explicit-raw32-storage-candidate-v1");
            exit(1);
        }
        s->ba2_spr5001_initial = z6ii_ba2_required_number(
            "Z6II_BA2_SPR5001_INITIAL", UINT32_MAX);
        s->ba2_spr5001_enabled = true;
    } else if (getenv("Z6II_BA2_SPR5001_INITIAL")) {
        error_report("BA2 SPR5001 initial value requires an explicit policy");
        exit(1);
    }
    const char *spr4000 = getenv("Z6II_BA2_SPR4000_POLICY");
    if (spr4000) {
        if (strcmp(spr4000, "explicit-raw32-storage-candidate-v1")) {
            error_report("BA2 SPR4000 requires explicit-raw32-storage-candidate-v1");
            exit(1);
        }
        s->ba2_spr4000_initial = z6ii_ba2_required_number(
            "Z6II_BA2_SPR4000_INITIAL", UINT32_MAX);
        s->ba2_spr4000_enabled = true;
    } else if (getenv("Z6II_BA2_SPR4000_INITIAL")) {
        error_report("BA2 SPR4000 initial value requires an explicit policy");
        exit(1);
    }
    const char *spr5004 = getenv("Z6II_BA2_SPR5004_POLICY");
    if (spr5004) {
        if (strcmp(spr5004, "SPR5004-explicit-raw32-read-v1")) {
            error_report("BA2 SPR5004 requires SPR5004-explicit-raw32-read-v1");
            exit(1);
        }
        s->ba2_spr5004_initial = z6ii_ba2_required_number(
            "Z6II_BA2_SPR5004_INITIAL", UINT32_MAX);
        s->ba2_spr5004_enabled = true;
    } else if (getenv("Z6II_BA2_SPR5004_INITIAL")) {
        error_report("BA2 SPR5004 initial value requires an explicit policy");
        exit(1);
    }
    const char *spr5005 = getenv("Z6II_BA2_SPR5005_POLICY");
    if (spr5005) {
        if (strcmp(spr5005, "SPR5005-explicit-raw32-read-v1")) {
            error_report("BA2 SPR5005 requires SPR5005-explicit-raw32-read-v1");
            exit(1);
        }
        s->ba2_spr5005_initial = z6ii_ba2_required_number(
            "Z6II_BA2_SPR5005_INITIAL", UINT32_MAX);
        s->ba2_spr5005_enabled = true;
    } else if (getenv("Z6II_BA2_SPR5005_INITIAL")) {
        error_report("BA2 SPR5005 initial value requires an explicit policy");
        exit(1);
    }
    const char *engine140 = getenv("Z6II_BA2_ENGINE140_POLICY");
    const char *engine140_backend = getenv("Z6II_BA2_ENGINE140_BACKEND_POLICY");
    if ((!engine140 && engine140_backend) ||
        (!engine140_backend && getenv("Z6II_BA2_ENGINE140_BACKEND_BYTES"))) {
        error_report("BA2 engine/backend inputs require explicit matching policies");
        exit(1);
    }
    Z6IIBA2QEMU78Config config = {
        .mode = mode,
        .program_base = z6ii_ba2_required_number("Z6II_BA2_PROGRAM_BASE", UINT32_MAX),
        .reset_pc = z6ii_ba2_required_number("Z6II_BA2_RESET_PC", UINT32_MAX),
        .ram_base = z6ii_ba2_required_number("Z6II_BA2_RAM_BASE", UINT32_MAX),
        .ram_bytes = z6ii_ba2_required_number("Z6II_BA2_RAM_BYTES", UINT32_MAX),
        .copy_channel = z6ii_ba2_required_number("Z6II_BA2_COPY_CHANNEL", 3),
        .slice_steps = z6ii_ba2_required_number("Z6II_BA2_SLICE_STEPS", 65536),
        .total_steps = z6ii_ba2_required_number("Z6II_BA2_TOTAL_STEPS", 10000000),
        .timer_period_ns = z6ii_ba2_required_number("Z6II_BA2_TIMER_PERIOD_NS", 1000000000),
        .data_endian = !strcmp(endian, "le") ? Z6II_BA2_DATA_LE : Z6II_BA2_DATA_BE,
        .allow_unaligned_data = z6ii_ba2_required_number("Z6II_BA2_ALLOW_UNALIGNED", 1),
        .ram_policy = getenv("Z6II_BA2_RAM_POLICY"),
        .register_policy = getenv("Z6II_BA2_REGISTER_POLICY"),
        .controller_policy = getenv("Z6II_BA2_CONTROLLER_POLICY"),
        .irq_policy = getenv("Z6II_BA2_IRQ_POLICY"),
        .tick139_policy = tick139,
        .tick139_source_hz = tick139 ?
            z6ii_ba2_required_number("Z6II_BA2_TICK139_SOURCE_HZ", UINT64_MAX) : 0,
        .tick139_initial_source_cycles = tick139 ?
            z6ii_ba2_required_number("Z6II_BA2_TICK139_INITIAL_SOURCE_CYCLES", UINT64_MAX) : 0,
        .tick139_basis = tick139 ?
            "original-72EE-400MHz-BE97-period-BD86-ACK-D476;"
            " explicit-qemu-virtual-ns-delta; same-source-64bit-counter-candidate" : NULL,
        .irq_sr11_initial = getenv("Z6II_BA2_IRQ_POLICY") &&
            !strcmp(getenv("Z6II_BA2_IRQ_POLICY"), "fifo-level-vector38-candidate-v1") ?
            s->ba2_spr_initial[0] : 0,
        .irq_basis = getenv("Z6II_BA2_IRQ_POLICY") &&
            !strcmp(getenv("Z6II_BA2_IRQ_POLICY"), "fifo-level-vector38-candidate-v1") ?
            "original-vector38-to-BD63-ISR7383-RFE0400; actual-FIFO-level-and-EI;"
            " caller-raw-SR11; nonnested-software-candidate; silicon-unverified" : NULL,
        .entri4_policy = getenv("Z6II_BA2_ENTRI4_POLICY"),
        .entri1n1_policy = getenv("Z6II_BA2_ENTRI1N1_POLICY"),
        .entri1n_policy = getenv("Z6II_BA2_ENTRI1N_POLICY"),
        .jr9_policy = getenv("Z6II_BA2_JR9_POLICY"),
        .reti1n1_policy = getenv("Z6II_BA2_RETI1N1_POLICY"),
        .divu337_policy = getenv("Z6II_BA2_DIVU337_POLICY"),
        .movi_d7g3_policy = getenv("Z6II_BA2_MOVI_D7G3_POLICY"),
        .movi_nontrap_policy = getenv("Z6II_BA2_MOVI_NONTRAP_POLICY"),
        .mov_gpr_policy = getenv("Z6II_BA2_MOV_GPR_POLICY"),
        .bt_add_gpr_policy = getenv("Z6II_BA2_BT_ADD_GPR_POLICY"),
        .bt_add_bn_addc_pair_policy = getenv("Z6II_BA2_BT_ADD_BN_ADDC_PAIR_POLICY"),
        .bg_beq_gpr_policy = getenv("Z6II_BA2_BG_BEQ_GPR_POLICY"),
        .bg_bgeu_gpr_policy = getenv("Z6II_BA2_BG_BGEU_GPR_POLICY"),
        .startup_isa_policy = getenv("Z6II_BA2_STARTUP_ISA_POLICY"),
        .startup_irq_initial_enabled = getenv("Z6II_BA2_STARTUP_ISA_POLICY") ?
            z6ii_ba2_required_number("Z6II_BA2_STARTUP_IRQ_INITIAL_ENABLED", 1) : false,
        .startup_irq_reset_basis = getenv("Z6II_BA2_STARTUP_ISA_POLICY") ?
            "caller-explicit-reset-mask; silicon-reset-unverified" : NULL,
        .startup_bridge_policy = getenv("Z6II_BA2_STARTUP_BRIDGE_POLICY"),
        .window_policy = getenv("Z6II_BA2_WINDOW_POLICY"),
        .transaction_config_policy = getenv("Z6II_BA2_TRANSACTION_CONFIG_POLICY"),
        .engine140_policy = engine140,
        .engine140_basis = engine140 ? "original-mode9-descriptor-source-window-raw40-ISR-ACK;packing-unverified" : NULL,
        .engine140_backend_policy = engine140_backend,
        .engine140_backend_bytes = engine140_backend ?
            z6ii_ba2_required_number("Z6II_BA2_ENGINE140_BACKEND_BYTES", UINT32_MAX) : 0,
        .engine140_backend_basis = engine140_backend ?
            "explicit-artificial-byte-transfer;caller-declared-extent;not-mode9-transform-or-golden-output" : NULL,
        .startup_spr4800_initial = getenv("Z6II_BA2_STARTUP_BRIDGE_POLICY") ?
            z6ii_ba2_required_number("Z6II_BA2_SPR4800_INITIAL", UINT32_MAX) : 0,
        .startup_bridge_basis = getenv("Z6II_BA2_STARTUP_BRIDGE_POLICY") ?
            "original-startup-mmio-candidate-v1; actual-Master-committed-window;"
            " active0-3-to-7C-80-84-88; explicit-one-poll-local-reset;"
            " caller-raw32-SPR4800; silicon-unverified" : NULL,
        .msw_c0_policy = getenv("Z6II_BA2_MSW_C0_POLICY"),
        .mlwz_c0_policy = getenv("Z6II_BA2_MLWZ_C0_POLICY"),
        .sub_subb_pair_policy = getenv("Z6II_BA2_SUB_SUBB_PAIR_POLICY"),
        .sub_subb_pair2_policy = getenv("Z6II_BA2_SUB_SUBB_PAIR2_POLICY"),
        .spr_read = z6ii_ba2_board_spr_read,
        .spr_write = z6ii_ba2_board_spr_write,
        .spr_reset = z6ii_ba2_board_spr_reset,
        .spr_opaque = s,
        .spr_basis = "observed-reset-storage-v1; selectors11/14/15; optional_exact_SPR5000_SPR5001_SPR4000_raw32; explicit_board_policies_logged; silicon semantics unproved",
    };
    s->ba2_peer = z6ii_ba2_qemu78_create(&config, true, &s->ipu2402,
        z6ii_ba2_master_irq_update, s, &error_fatal);
    fprintf(stderr, "Z6II_BA2_SPR5000_INPUT policy=%s initial=%08x"
        " enabled=%u storage_only=1 silicon_reset_verified=0 timer_events=0 IRQ_events=0\n",
        spr5000 ? spr5000 : "disabled", s->ba2_spr5000_initial,
        s->ba2_spr5000_enabled);
    fprintf(stderr, "Z6II_BA2_SPR5001_INPUT policy=%s initial=%08x"
        " enabled=%u storage_only=1 silicon_reset_verified=0 timer_events=0 IRQ_events=0\n",
        spr5001 ? spr5001 : "disabled", s->ba2_spr5001_initial,
        s->ba2_spr5001_enabled);
    fprintf(stderr, "Z6II_BA2_SPR4000_INPUT policy=%s initial=%08x"
        " enabled=%u storage_only=1 silicon_reset_verified=0 timer_events=0 IRQ_events=0\n",
        spr4000 ? spr4000 : "disabled", s->ba2_spr4000_initial,
        s->ba2_spr4000_enabled);
    fprintf(stderr, "Z6II_BA2_SPR5004_INPUT policy=%s initial=%08x"
        " enabled=%u read_only=1 silicon_reset_verified=0 timer_events=0 IRQ_events=0\n",
        spr5004 ? spr5004 : "disabled", s->ba2_spr5004_initial,
        s->ba2_spr5004_enabled);
    fprintf(stderr, "Z6II_BA2_SPR5005_INPUT policy=%s initial=%08x"
        " enabled=%u read_only=1 silicon_reset_verified=0 timer_events=0 IRQ_events=0\n",
        spr5005 ? spr5005 : "disabled", s->ba2_spr5005_initial,
        s->ba2_spr5005_enabled);
    s->devices->ba2_payload_opaque = s->ba2_peer;
    s->devices->ba2_payload_pre = z6ii_ba2_qemu78_copy_pre;
    s->devices->ba2_payload_post = z6ii_ba2_qemu78_copy_post;
    fprintf(stderr, "Z6II_BA2_SPR_INPUT policy=%s initial11=%08x initial14=%08x"
        " initial15=%08x storage_only=1 silicon_reset_verified=0 IRQ_generation=0\n",
        spr, s->ba2_spr_initial[0], s->ba2_spr_initial[1], s->ba2_spr_initial[2]);
}
#endif
