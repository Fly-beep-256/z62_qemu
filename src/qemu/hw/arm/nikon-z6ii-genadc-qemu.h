/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Opt-in adapter for an explicit GENADC scan contract. It routes only the
 * model's peripheral IRQ level; original firmware owns ISR/callback/flags.
 * No hardware route, sample voltage, or conversion timing is inferred. */
#ifndef NIKON_Z6II_GENADC_QEMU_H
#define NIKON_Z6II_GENADC_QEMU_H

#define GENADC_FRAME_LIMIT 256u

static uint64_t z6ii_genadc_required_number(Z6IIState *s, const char *name,
                                          uint64_t min, uint64_t max)
{
    uint64_t result;
    if (!z6ii_hdmi_decimal(z6ii_engine_getenv(s->engine, name), max, &result) || result < min) {
        error_report("%s requires explicit decimal [%" PRIu64 ", %" PRIu64 "]",
                     name, min, max);
        exit(1);
    }
    return result;
}

static void z6ii_genadc_update_irq(Z6IIState *s)
{
    bool pending = z6ii_genadc_irq_pending(&s->genadc);
    if (pending == s->genadc_irq_level) {
        return;
    }
    s->genadc_irq_level = pending;
    if (s->genadc_gic_input >= 0) {
        qemu_set_irq(qdev_get_gpio_in(DEVICE(s->priv), s->genadc_gic_input),
                     pending);
    }
    fprintf(stderr, "Z6II_GENADC_IRQ now_ns=%" PRId64
            " gpio_input=%d source_pending=%u routed=%u"
            " status=%08x scan=%08x silicon_route_verified=0"
            " guest_GIC_configuration_required=1 guest_flag_written=0\n",
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), s->genadc_gic_input,
            pending, s->genadc_gic_input >= 0, s->genadc.status, s->genadc.scan);
}

static void z6ii_genadc_schedule(Z6IIState *s)
{
    uint64_t deadline, generation;
    if (z6ii_genadc_next_due(&s->genadc, &deadline, &generation)) {
        if (deadline > INT64_MAX) {
            error_report("GENADC deadline exceeds virtual-clock range");
            exit(1);
        }
        s->genadc_timer_generation = generation;
        timer_mod(s->genadc_timer, deadline);
    } else {
        s->genadc_timer_generation = 0;
        timer_del(s->genadc_timer);
    }
    z6ii_genadc_update_irq(s);
}

static void z6ii_genadc_timer(void *opaque)
{
    Z6IIState *s = opaque;
    uint64_t ticket = s->genadc_timer_generation;
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    bool completed = z6ii_genadc_complete(&s->genadc, ticket, now);
    fprintf(stderr, "Z6II_GENADC_COMPLETE now_ns=%" PRId64
            " generation=%" PRIu64 " accepted=%u status=%08x valid=%03x"
            " submitted=%" PRIu64 " completed=%" PRIu64
            " cancelled=%" PRIu64 " source_kind=%s source_label=%s"
            " timer_context=1 guest_callback_invoked_by_host=0\n",
            now, ticket, completed, s->genadc.status, s->genadc.valid_results,
            s->genadc.submitted, s->genadc.completed, s->genadc.cancelled,
            s->genadc.config.source == Z6II_GENADC_SOURCE_RECORDED ?
                "recorded" : "synthetic-test", s->genadc.config.source_label);
    z6ii_genadc_schedule(s);
}

static bool z6ii_genadc_qemu_access(Z6IIState *s, hwaddr addr, unsigned size,
                                  bool write, uint64_t *value)
{
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    Z6IIGenADCResult result = z6ii_genadc_access(&s->genadc, addr, size,
                                               write, value, now);
    if (s->genadc_trace_count++ < s->genadc_trace_limit ||
        result != Z6II_GENADC_OK) {
        CPUARMState *env = current_cpu ? &ARM_CPU(current_cpu)->env : NULL;
        fprintf(stderr, "Z6II_GENADC_MMIO now_ns=%" PRId64
                " %c addr=%08" HWADDR_PRIx " size=%u value=%08" PRIx64
                " result=%s control=%08x scan=%08x status=%08x"
                " active=%u input_index=%zu submitted=%" PRIu64
                " completed=%" PRIu64 " cpu=%d pc=%08x\n",
                now, write ? 'W' : 'R', addr, size, *value,
                z6ii_genadc_result_name(result), s->genadc.control,
                s->genadc.scan, s->genadc.status, s->genadc.active,
                s->genadc.frame_index, s->genadc.submitted, s->genadc.completed,
                current_cpu ? current_cpu->cpu_index : -1,
                env ? env->regs[15] : 0);
    }
    if (result == Z6II_GENADC_OK) {
        z6ii_genadc_schedule(s);
    }
    return result == Z6II_GENADC_OK;
}

static size_t z6ii_genadc_load_frames(Z6IIState *s)
{
    gsize bytes;
    gchar *data = z6ii_hdmi_input_file(s, "Z6II_GENADC_INPUT_FILE", &bytes);
    gchar **lines;
    size_t count = 0;
    gchar *sha;
    if (!bytes || bytes > 65536 || memchr(data, 0, bytes)) {
        error_report("GENADC input requires 1..65536 bytes, no embedded NUL");
        exit(1);
    }
    s->genadc_frames = g_new0(Z6IIGenADCFrame, GENADC_FRAME_LIMIT);
    lines = g_strsplit(data, "\n", -1);
    for (unsigned line = 0; lines[line]; line++) {
        gchar *trimmed = g_strstrip(lines[line]);
        gchar **tokens;
        unsigned column = 0;
        if (!*trimmed && !lines[line+1]) {
            continue; /* Permit one final newline. */
        }
        if (!*trimmed || count == GENADC_FRAME_LIMIT) {
            error_report("GENADC input has an empty row or exceeds 256 frames");
            exit(1);
        }
        tokens = g_strsplit_set(trimmed, " \t\r", -1);
        for (unsigned n = 0; tokens[n]; n++) {
            uint64_t value;
            if (!*tokens[n]) {
                continue;
            }
            if (column >= 10 ||
                !z6ii_hdmi_decimal(tokens[n], column ? 1023 : 511, &value)) {
                error_report("GENADC row %u requires valid-mask plus nine decimal raw10 samples", line+1);
                exit(1);
            }
            if (!column) {
                s->genadc_frames[count].valid_channels = (uint16_t)value;
            } else {
                s->genadc_frames[count].raw[column-1] = (uint16_t)value;
            }
            column++;
        }
        g_strfreev(tokens);
        if (column != 10) {
            error_report("GENADC row %u must have exactly ten fields", line+1);
            exit(1);
        }
        count++;
    }
    g_strfreev(lines);
    sha = g_compute_checksum_for_data(G_CHECKSUM_SHA256, (guchar *)data, bytes);
    fprintf(stderr, "Z6II_GENADC_INPUT file=%s bytes=%zu sha256=%s frames=%zu"
            " repeating=0 immutable_after_init=1\n",
            z6ii_engine_getenv(s->engine, "Z6II_GENADC_INPUT_FILE"), (size_t)bytes, sha, count);
    g_free(sha);
    g_free(data);
    return count;
}

static void z6ii_genadc_qemu_init(Z6IIState *s, bool functional)
{
    const char *mode = z6ii_engine_getenv(s->engine, "Z6II_GENADC_MODEL");
    const char *kind, *label;
    Z6IIGenADCConfig config = {0};
    if (!mode || strcmp(s->profile->role, "master")) {
        return;
    }
    if (!functional || strcmp(mode, "scan-v1")) {
        error_report("GENADC scan-v1 requires a functional Master board");
        exit(1);
    }
    kind = z6ii_engine_getenv(s->engine, "Z6II_GENADC_SOURCE_KIND");
    label = z6ii_engine_getenv(s->engine, "Z6II_GENADC_SOURCE_LABEL");
    if (!kind || (strcmp(kind, "recorded") && strcmp(kind, "synthetic-test")) ||
        !label || !*label || strlen(label) > 128) {
        error_report("GENADC requires explicit recorded/synthetic-test source kind and nonempty label <=128 bytes");
        exit(1);
    }
    for (const char *p = label; *p; p++) {
        if ((unsigned char)*p < 32 || (unsigned char)*p > 126) {
            error_report("GENADC label requires printable ASCII");
            exit(1);
        }
    }
    config.experimental_scan_contract = true;
    config.conversion_latency_ns = z6ii_genadc_required_number(s, "Z6II_GENADC_DELAY_NS", 1, 1000000000);
    config.completion_status_mask = (uint32_t)z6ii_genadc_required_number(s, "Z6II_GENADC_COMPLETION_MASK", 2, 8);
    config.interrupt_enable_mask = (uint32_t)z6ii_genadc_required_number(s, "Z6II_GENADC_ENABLE_MASK", 1024, 4096);
    config.source = !strcmp(kind, "recorded") ? Z6II_GENADC_SOURCE_RECORDED : Z6II_GENADC_SOURCE_SYNTHETIC_TEST;
    config.source_label = g_strdup(label);
    config.frame_count = z6ii_genadc_load_frames(s);
    config.frames = s->genadc_frames;
    s->genadc_gic_input = -1;
    if (z6ii_engine_getenv(s->engine, "Z6II_GENADC_EXPERIMENTAL_GIC_INPUT")) {
        s->genadc_gic_input = (int)z6ii_genadc_required_number(s, "Z6II_GENADC_EXPERIMENTAL_GIC_INPUT", 0, 223);
    }
    s->genadc_trace_limit = z6ii_hdmi_number(s, "Z6II_GENADC_TRACE_LIMIT", 4096, 1, 65536);
    if (z6ii_genadc_init(&s->genadc, &config) != Z6II_GENADC_OK) {
        error_report("GENADC config needs status 2/4/8, enable 1024/2048/4096 and valid raw10 input frames");
        exit(1);
    }
    s->genadc_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, z6ii_genadc_timer, s);
    s->genadc_enabled = true;
    fprintf(stderr, "Z6II_GENADC_MODEL mode=scan-v1 role=master source_kind=%s"
            " source_label=%s frames=%zu delay_ns=%" PRIu64
            " completion_mask=%x enable_mask=%x gpio_input=%d"
            " timing_verified=0 W0C_hypothesis=1 self_clear_start_hypothesis=1"
            " silicon_route_verified=0 guest_callbacks_and_flags_owned_by_firmware=1\n",
            kind, label, config.frame_count, config.conversion_latency_ns,
            config.completion_status_mask, config.interrupt_enable_mask,
            s->genadc_gic_input);
}

#endif
