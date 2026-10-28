/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Explicit POSTSERV type0/RX6 transport experiment, not an identified sensor.
 * Included after Z6IIFunctionalDevices and z6ii_fd_i2c_irq. One selected lane
 * owns its entire register window; all other lanes retain the empty bus.
 * Rows/identity strings are immutable and retained for the machine lifetime.
 * The original firmware owns its callbacks, event flags and Ready reports. */
#ifndef NIKON_Z6II_POST68_QEMU_H
#define NIKON_Z6II_POST68_QEMU_H

#define Z6II_POST68_INPUT_LIMIT (6u * 65536u)

static uint64_t z6ii_post68_number(Z6IIFunctionalDevices *s, const char *name, uint64_t min, uint64_t max)
{
    const char *text = z6ii_engine_getenv(s->engine, name);
    uint64_t value = 0;
    if (!text || !*text) {
        error_report("%s requires explicit decimal [%" PRIu64 ",%" PRIu64 "]", name, min, max);
        exit(1);
    }
    for (const char *p = text; *p; p++) {
        if (*p < '0' || *p > '9' || value > max / 10 ||
            (value == max / 10 && (unsigned)(*p-'0') > max % 10)) {
            error_report("%s requires decimal [%" PRIu64 ",%" PRIu64 "]", name, min, max);
            exit(1);
        }
        value = value * 10 + (unsigned)(*p-'0');
    }
    if (value < min) {
        error_report("%s is below %" PRIu64, name, min);
        exit(1);
    }
    return value;
}

static bool z6ii_post68_qemu_owns(const Z6IIFunctionalDevices *s, unsigned ch)
{
    return s->post68_enabled && ch == s->post68.config.controller;
}

static void z6ii_post68_qemu_sync(Z6IIFunctionalDevices *s)
{
    unsigned ch = s->post68.config.controller;
    uint64_t due, ticket;
    memcpy(s->i2c_regs[ch], s->post68.regs, sizeof(s->post68.regs));
    memcpy(s->i2c_tx[ch], s->post68.tx, sizeof(s->post68.tx));
    s->i2c_tx_count[ch] = s->post68.tx_count;
    s->i2c_pending[ch] = s->post68.pending;
    s->i2c_generation[ch] = s->post68.generation;
    if (z6ii_post68_next_due(&s->post68, &due, &ticket)) {
        if (due > INT64_MAX) {
            error_report("POST68 deadline exceeds QEMU virtual clock range"); exit(1);
        }
        s->i2c_deadline[ch] = (int64_t)due;
        s->post68_timer_generation = ticket;
    } else {
        s->i2c_deadline[ch] = -1;
        s->post68_timer_generation = 0;
    }
}

/* Shared scheduling has one owner for each lane. A disabled POST68 adapter
 * leaves the existing four generic lanes in the same completion path. */
static void z6ii_fd_i2c_reschedule(Z6IIFunctionalDevices *s)
{
    int64_t next = INT64_MAX;
    for (unsigned ch = 0; ch < 4; ch++) {
        if (s->i2c_pending[ch]) {
            if (s->i2c_deadline[ch] < 0) {
                error_report("I2C pending lane has a negative deadline"); exit(1);
            }
            next = MIN(next, s->i2c_deadline[ch]);
        }
    }
    if (next == INT64_MAX) { timer_del(s->i2c_timer); }
    else { timer_mod(s->i2c_timer, next); }
}

static const char *z6ii_post68_result_name(Z6IIPost68Result result)
{
    switch (result) {
    case Z6II_POST68_OK: return "ok";
    case Z6II_POST68_BAD_CONFIG: return "bad-config";
    case Z6II_POST68_UNSUPPORTED_ACCESS: return "unsupported-access";
    case Z6II_POST68_BUSY: return "busy";
    case Z6II_POST68_TIME_OR_GENERATION_RANGE: return "range";
    case Z6II_POST68_EMPTY_FIFO: return "empty-fifo";
    default: return "invalid-result";
    }
}

static bool z6ii_post68_qemu_access(Z6IIFunctionalDevices *s, hwaddr addr,
                                  unsigned size, bool write, uint64_t *value)
{
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    if (now < 0) { error_report("POST68 requires nonnegative virtual time"); exit(1); }
    Z6IIPost68Result result = z6ii_post68_access(&s->post68, addr & 0xfff,
                                               size, write, value, now);
    z6ii_post68_qemu_sync(s);
    z6ii_fd_i2c_irq(s, s->post68.config.controller);
    z6ii_fd_i2c_reschedule(s);
    if (s->post68_trace_count++ < s->post68_trace_limit || result != Z6II_POST68_OK) {
        fprintf(stderr, "Z6II_POST68_MMIO now_ns=%" PRId64
                " ch=%u %c addr=%08" HWADDR_PRIx " size=%u value=%08" PRIx64
                " result=%s generation=%" PRIu64 " pending=%u deadline_ns=%" PRId64
                " control=%08x raw=%08x mask=%08x tx_count=%u rx_count=%u"
                " row_index=%zu config_valid=%u command_valid=%u reason=%s\n",
                now, s->post68.config.controller, write ? 'W' : 'R', addr, size, *value,
                z6ii_post68_result_name(result), s->post68.generation, s->post68.pending,
                s->i2c_deadline[s->post68.config.controller], s->post68.regs[0],
                s->post68.regs[4], s->post68.regs[8], s->post68.tx_count, s->post68.rx_count,
                s->post68.row_index, s->post68.config_valid, s->post68.command_valid,
                z6ii_post68_reason_name(s->post68.last_reason));
    }
    if (result == Z6II_POST68_OK) { z6ii_fd_mmio_trace(s, addr, size, write, *value); }
    return result == Z6II_POST68_OK;
}

static void z6ii_post68_qemu_complete_lane(Z6IIFunctionalDevices *s,
                                         unsigned ch, int64_t now)
{
    if (!z6ii_post68_qemu_owns(s, ch) || !s->post68.pending ||
        now < 0 || s->i2c_deadline[ch] > now) { return; }
    uint64_t ticket = s->post68_timer_generation;
    Z6IIPost68Job job = s->post68.job;
    bool accepted = z6ii_post68_complete(&s->post68, ch, ticket, now);
    z6ii_post68_qemu_sync(s);
    z6ii_fd_i2c_irq(s, ch);
    z6ii_boot_i2c_timer_observe(s->engine, ch, 1, now, s->i2c_regs[ch], s->i2c_tx[ch],
        s->i2c_tx_count[ch], s->i2c_pending[ch], s->i2c_deadline[ch], s->i2c_generation[ch]);
    fprintf(stderr, "Z6II_POST68_COMPLETE now_ns=%" PRId64
            " ch=%u ticket=%" PRIu64 " accepted=%u address=%04x receive=%u"
            " job_tx_count=%u tx0=%02x tx1=%02x requested=%u raw=%08x mask=%08x"
            " rx_count=%u row_index=%zu job_row=%zu config_byte=%02x"
            " reason=%s source_kind=%s silicon_device_identified=0"
            " guest_callback_invoked_by_host=0 guest_flag_written=0\n",
            now, ch, ticket, accepted, job.address, job.receive, job.tx_count,
            job.tx[0], job.tx[1], job.receive_count, s->post68.regs[4], s->post68.regs[8],
            s->post68.rx_count, s->post68.row_index, job.row_index, s->post68.config_byte,
            z6ii_post68_reason_name(job.reason),
            s->post68.config.source == Z6II_POST68_ACQUIRED ? "recorded" :
            s->post68.config.source == Z6II_POST68_SYNTHETIC ? "synthetic-test" : "unconfigured");
}

static void z6ii_post68_qemu_reset(void *opaque)
{
    Z6IIFunctionalDevices *s = opaque;
    if (!s->post68_enabled) { return; }
    if (z6ii_post68_board_reset(&s->post68) != Z6II_POST68_OK) {
        error_report("POST68 reset generation exceeded range"); exit(1);
    }
    z6ii_post68_qemu_sync(s);
    z6ii_fd_i2c_irq(s, s->post68.config.controller);
    z6ii_fd_i2c_reschedule(s);
    fprintf(stderr, "Z6II_POST68_RESET ch=%u generation=%" PRIu64
            " row_index=%zu reset_policy=%s guest_flags_written=0\n",
            s->post68.config.controller, s->post68.generation, s->post68.row_index,
            s->post68.config.reset_policy == Z6II_POST68_RESET_REWIND_ROWS ? "rewind" : "preserve");
}

static void z6ii_post68_qemu_init(Z6IIFunctionalDevices *s, bool master)
{
    const char *mode = z6ii_engine_getenv(s->engine, "Z6II_POST68_MODEL");
    Z6IIPost68Config c = {0};
    if (!mode || !master) { return; }
    if (!s->recovery_profile || (strcmp(mode, "type0-rx6-v1") &&
                                strcmp(mode, "type0-startup-rx6-v2"))) {
        error_report("POST68 type0-rx6-v1/type0-startup-rx6-v2 requires functional Master"); exit(1);
    }
    c.experimental_contract = true;
    c.startup_register_writes = !strcmp(mode, "type0-startup-rx6-v2");
    c.controller = (unsigned)z6ii_post68_number(s, "Z6II_POST68_CONTROLLER", 0, 3);
    c.delay_ns = z6ii_post68_number(s, "Z6II_POST68_DELAY_NS", 1, 1000000000);
    const char *kind = z6ii_engine_getenv(s->engine, "Z6II_POST68_SOURCE_KIND");
    const char *advance = z6ii_engine_getenv(s->engine, "Z6II_POST68_ADVANCE");
    const char *reset = z6ii_engine_getenv(s->engine, "Z6II_POST68_RESET");
    if (!advance || (strcmp(advance, "exhaust") && strcmp(advance, "hold-last")) ||
        !reset || (strcmp(reset, "rewind") && strcmp(reset, "preserve"))) {
        error_report("POST68 requires explicit ADVANCE=exhaust/hold-last and RESET=rewind/preserve"); exit(1);
    }
    c.advance = !strcmp(advance, "exhaust") ? Z6II_POST68_ADVANCE_ON_DRAIN_EXHAUST : Z6II_POST68_ADVANCE_ON_DRAIN_HOLD_LAST;
    c.reset_policy = !strcmp(reset, "rewind") ? Z6II_POST68_RESET_REWIND_ROWS : Z6II_POST68_RESET_PRESERVE_ROW_INDEX;
    if (!kind || (strcmp(kind, "recorded") && strcmp(kind, "synthetic-test") && strcmp(kind, "unconfigured"))) {
        error_report("POST68 requires SOURCE_KIND=recorded/synthetic-test/unconfigured"); exit(1);
    }
    if (!strcmp(kind, "unconfigured")) {
        if (z6ii_engine_getenv(s->engine, "Z6II_POST68_INPUT_FILE") || z6ii_engine_getenv(s->engine, "Z6II_POST68_INPUT_SHA256") ||
            z6ii_engine_getenv(s->engine, "Z6II_POST68_SOURCE_LABEL")) {
            error_report("POST68 unconfigured source cannot have input/identity metadata"); exit(1);
        }
        c.source = Z6II_POST68_UNCONFIGURED;
    } else {
        const char *path = z6ii_engine_getenv(s->engine, "Z6II_POST68_INPUT_FILE");
        const char *expected = z6ii_engine_getenv(s->engine, "Z6II_POST68_INPUT_SHA256");
        const char *label = z6ii_engine_getenv(s->engine, "Z6II_POST68_SOURCE_LABEL");
        gchar *data = NULL;
        gsize bytes = 0;
        GError *error = NULL;
        if (!path || path[0] != '/' || !z6ii_post68_digest_valid(expected) ||
            !label || !*label || strlen(label) > 128) {
            error_report("POST68 needs absolute INPUT_FILE, lowercase SHA256 and label 1..128 bytes"); exit(1);
        }
        for (const char *p = label; *p; p++) {
            if ((unsigned char)*p < 32 || (unsigned char)*p > 126) {
                error_report("POST68 source label requires printable ASCII"); exit(1);
            }
        }
        if (!g_file_get_contents(path, &data, &bytes, &error)) {
            error_report("POST68 input read failed: %s", error ? error->message : "unknown");
            g_clear_error(&error); exit(1);
        }
        if (!bytes || bytes > Z6II_POST68_INPUT_LIMIT || bytes % Z6II_POST68_RX_BYTES) {
            error_report("POST68 input needs 1..65536 immutable rows of exactly 6 bytes");
            g_free(data); exit(1);
        }
        gchar *actual = g_compute_checksum_for_data(G_CHECKSUM_SHA256, (const guchar *)data, bytes);
        if (strcmp(actual, expected)) {
            error_report("POST68 input SHA256 mismatch"); g_free(actual); g_free(data); exit(1);
        }
        c.source = !strcmp(kind, "recorded") ? Z6II_POST68_ACQUIRED : Z6II_POST68_SYNTHETIC;
        c.rows = (const uint8_t *)data; c.row_count = bytes / Z6II_POST68_RX_BYTES;
        c.source_bytes = bytes; c.source_path = g_strdup(path);
        c.source_sha256 = actual; c.source_label = g_strdup(label);
        fprintf(stderr, "Z6II_POST68_INPUT file=%s bytes=%zu rows=%zu sha256=%s"
                " source_kind=%s source_label=%s immutable_after_init=1"
                " layout=three_little_endian_signed16 units_and_axes_unknown=1\n",
                path, (size_t)bytes, c.row_count, actual, kind, label);
    }
    if (z6ii_post68_init(&s->post68, &c) != Z6II_POST68_OK) {
        error_report("POST68 core configuration rejected"); exit(1);
    }
    s->post68_trace_limit = z6ii_engine_getenv(s->engine, "Z6II_POST68_TRACE_LIMIT") ?
        z6ii_post68_number(s, "Z6II_POST68_TRACE_LIMIT", 1, 65536) : 4096;
    s->post68_enabled = true;
    z6ii_post68_qemu_sync(s);
    z6ii_fd_i2c_irq(s, c.controller);
    qemu_register_reset(z6ii_post68_qemu_reset, s);
    fprintf(stderr, "Z6II_POST68_MODEL mode=%s role=master ch=%u"
            " address=0068 delay_ns=%" PRIu64 " source_kind=%s rows=%zu"
            " advance=%s reset=%s IRQ=%u whole_lane_window_owned=1"
            " generic_NACK_completion_suppressed_on_lane=1 timing_verified=0"
            " control_OR40_hardware_meaning_unknown=1 guest_flags_owned_by_firmware=1\n",
            mode, c.controller, c.delay_ns, kind, c.row_count, advance, reset, 214+c.controller);
}

#endif
