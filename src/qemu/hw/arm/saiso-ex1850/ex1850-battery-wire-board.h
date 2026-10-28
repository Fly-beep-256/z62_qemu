/* SPDX-License-Identifier: GPL-2.0-or-later */
/* An explicitly configured battery wire, scheduled by the same virtual clock
 * as all three processors. Contract selection consumes completed TX only.
 * UART receive enable, reset, format, IRQ and original timeout behavior remain
 * in the USART model. The endpoint never waits for the guest receiver to open. */
#ifndef EX1850_BATTERY_WIRE_BOARD_H
#define EX1850_BATTERY_WIRE_BOARD_H

#define EX1850_BATTERY_EVENT_LIMIT 96
static EX1850ResetState *ex1850_battery_exit_state;

static char *ex1850_battery_hex(const uint8_t *bytes, unsigned length)
{
    char *hex = g_malloc(length * 2 + 1);
    for (unsigned n = 0; n < length; n++) {
        snprintf(hex + n * 2, 3, "%02x", bytes[n]);
    }
    hex[length * 2] = 0;
    return hex;
}

static FILE *ex1850_battery_file(EX1850ResetState *s, const char *name)
{
    g_autofree char *path = g_build_filename(s->battery_wire_output, name, NULL);
    int fd = g_open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    FILE *file = fd < 0 ? NULL : fdopen(fd, "w");
    if (!file) {
        if (fd >= 0) { close(fd); }
        error_report("Cannot exclusively create battery evidence %s: %s", path,
                     strerror(errno));
        exit(67);
    }
    return file;
}

static void ex1850_battery_json(FILE *file, const QDict *value)
{
    GString *json = qobject_to_json(QOBJECT(value));
    bool ok = fwrite(json->str, 1, json->len, file) == json->len &&
              fputc('\n', file) != EOF && fflush(file) == 0;
    g_string_free(json, true);
    if (!ok) {
        error_report("Battery evidence write failed");
        exit(67);
    }
}

static QDict *ex1850_usart1_statistics(EX1850ResetState *s)
{
    QDict *q = qdict_new();
    qdict_put_str(q, "clock", "QEMU_CLOCK_VIRTUAL");
    qdict_put_int(q, "virtual_ns", qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    qdict_put_int(q, "TX_accepted", s->usart1.tx_accepted);
    qdict_put_int(q, "TX_completed", s->usart1.tx_completed);
    qdict_put_int(q, "wire_TX_bytes", s->usart1_line_tx_bytes);
    qdict_put_int(q, "wire_RX_bytes", s->usart1_line_rx_bytes);
    qdict_put_int(q, "RX_admitted", s->usart1_rx.admitted);
    qdict_put_int(q, "RX_completed", s->usart1_rx.completed);
    qdict_put_int(q, "RX_discarded", s->usart1_rx.discarded);
    qdict_put_int(q, "RX_queued", s->usart1_rx.count);
    qdict_put_int(q, "RX_overruns", s->usart1.rx_overruns);
    qdict_put_int(q, "RX_DR_supplied", s->usart1.rx_supplied);
    qdict_put_int(q, "SR", s->usart1.sr);
    qdict_put_int(q, "BRR", s->usart1.brr);
    qdict_put_int(q, "PCLK2_hz", s->usart1.pclk_hz);
    qdict_put_int(q, "CR1", s->usart1.cr1);
    qdict_put_bool(q, "receiver_enabled", ex1850_usart1_rx_enabled(&s->usart1));
    qdict_put_bool(q, "virtual_battery_enabled", s->battery_wire_enabled);
    qdict_put_int(q, "battery_pending_replies", s->battery_wire.count);
    qdict_put_int(q, "peripheral_reset_generation", s->usart1_reset_trace_count);
    qdict_put_bool(q, "guest_state_written", false);
    return q;
}

static int64_t ex1850_battery_wire_deadline(EX1850ResetState *s)
{
    return s->battery_wire_enabled ? ex1850_battery_deadline(&s->battery_wire) : -1;
}

static QDict *ex1850_battery_event(EX1850ResetState *s,
                                  const EX1850BatteryReply *r, const char *phase)
{
    const EX1850BatteryContract *c = &s->battery_wire.contracts[r->contract];
    QDict *event = qdict_clone_shallow(s->battery_wire_fields[r->contract]);
    g_autofree char *tx = ex1850_battery_hex(c->tx, c->tx_size);
    g_autofree char *rx = ex1850_battery_hex(c->rx, c->rx_size);
    qdict_put_str(event, "phase", phase);
    qdict_put_int(event, "sequence", r->sequence);
    qdict_put_int(event, "contract_index", r->contract);
    qdict_put_str(event, "public_TX", tx);
    qdict_put_str(event, "synthetic_RX", rx);
    qdict_put_int(event, "TX_byte_offset", r->tx_offset);
    qdict_put_int(event, "TX_complete_virtual_ns", r->tx_complete_ns);
    qdict_put_int(event, "reply_due_virtual_ns", r->due);
    qdict_put_str(event, "clock", "QEMU_CLOCK_VIRTUAL");
    qdict_put_int(event, "turnaround_ns", s->battery_wire.turnaround_ns);
    qdict_put_bool(event, "private_RAM_RNG_or_register_access", false);
    qdict_put_bool(event, "guest_state_written", false);
    return event;
}

static void ex1850_battery_wire_transmitted(EX1850ResetState *s,
                                           uint16_t word, int64_t now)
{
    if (word > 0xff) {
        ex1850_unknown_access(s, EX1850_USART1_BASE + 4, 4, true, word);
        return;
    }
    if (fputc(word, s->battery_wire_tx_file) == EOF ||
        fflush(s->battery_wire_tx_file)) { exit(67); }
    s->usart1_line_tx_bytes++;
    uint64_t frames = s->battery_wire.valid_frames;
    if (!ex1850_battery_tx(&s->battery_wire, word, now)) {
        error_report("EX1850_BATTERY_WIRE_BOUNDARY %s virtual_ns=%" PRId64,
                     s->battery_wire.error, now);
        exit(66);
    }
    if (frames != s->battery_wire.valid_frames) {
        unsigned tail = (s->battery_wire.head + s->battery_wire.count - 1) %
                        EX1850_BATTERY_PENDING;
        QDict *event = ex1850_battery_event(s, &s->battery_wire.pending[tail], "request");
        qdict_put_int(event, "virtual_ns", now);
        qdict_put_str(event, "source", "completed_guest_UART_TX_frame");
        ex1850_battery_json(s->battery_wire_event_file, event);
        qobject_unref(event);
    }
}

static void ex1850_battery_wire_dispatch(EX1850ResetState *s, int64_t due)
{
    EX1850BatteryReply reply;
    if (!ex1850_battery_reply(&s->battery_wire, due, &reply)) {
        error_report("EX1850_BATTERY_WIRE_BOUNDARY reply deadline or retention limit");
        exit(66);
    }
    const EX1850BatteryContract *c = &s->battery_wire.contracts[reply.contract];
    uint64_t admitted = s->usart1_rx.admitted, discarded = s->usart1_rx.discarded;
    QDict *event = ex1850_battery_event(s, &reply, "reply");
    qdict_put_int(event, "RX_byte_offset", s->usart1_line_rx_bytes);
    qdict_put_int(event, "virtual_ns", due);
    qdict_put_int(event, "dispatch_observed_virtual_ns", qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    qdict_put_bool(event, "receiver_enabled_at_offer", ex1850_usart1_rx_enabled(&s->usart1));
    if (fwrite(c->rx, 1, c->rx_size, s->battery_wire_rx_file) != c->rx_size ||
        fflush(s->battery_wire_rx_file)) { exit(67); }
    s->usart1_line_rx_bytes += c->rx_size;
    if (c->authentication) { s->battery_wire_auth_replies++; }
    else { s->battery_wire_ordinary_replies++; }
    /* Direct queue admission at the external wire deadline avoids recursively
     * synchronizing USART1. Disabled receivers still lose this input. */
    if (!ex1850_usart1_rx_push(&s->usart1_rx, &s->usart1, c->rx, c->rx_size, due)) {
        ex1850_battery_fail(&s->battery_wire, "UART cannot accept declared battery wire format");
        qdict_put_str(event, "error", s->battery_wire.error);
        ex1850_battery_json(s->battery_wire_event_file, event);
        qobject_unref(event);
        ex1850_unknown_access(s, EX1850_USART1_BASE + 4, 4, false, 0);
        return;
    }
    qdict_put_int(event, "RX_admitted_delta", s->usart1_rx.admitted - admitted);
    qdict_put_int(event, "RX_discarded_delta", s->usart1_rx.discarded - discarded);
    qdict_put_str(event, "source", "immutable_TX_match_and_virtual_external_turnaround");
    ex1850_battery_json(s->battery_wire_event_file, event);
    if (qlist_size(s->battery_wire_events) < EX1850_BATTERY_EVENT_LIMIT) {
        qlist_append(s->battery_wire_events, event);
    } else { qobject_unref(event); }
}

static void ex1850_battery_wire_close(EX1850ResetState *s, bool normal_exit)
{
    if (!s || s->battery_wire_closed) { return; }
    s->battery_wire_closed = true;
    ex1850_battery_exit_state = NULL;
    fclose(s->battery_wire_tx_file);
    fclose(s->battery_wire_rx_file);
    fclose(s->battery_wire_event_file);
    EX1850BatteryWire *w = &s->battery_wire;
    QDict *q = qdict_new(), *parser = qdict_new(), *protocol = qdict_new();
    QList *unknown = qlist_new();
    qdict_put_str(q, "schema", "ex1850.virtual-battery-wire-closure/1");
    qdict_put_bool(q, "enabled", true);
    qdict_put_bool(q, "connected", true);
    qdict_put_bool(q, "endpoint_closed", true);
    qdict_put_bool(q, "normal_QEMU_exit", normal_exit);
    qdict_put_str(q, "clock", "QEMU_CLOCK_VIRTUAL");
    qdict_put_str(q, "mode", "public-entropy-battery");
    qdict_put_str(q, "contract_sha256", s->battery_wire_sha256);
    qdict_put_int(q, "turnaround_ns", w->turnaround_ns);
    qdict_put_bool(q, "physical_turnaround_verified", false);
    qdict_put_bool(q, "authentication_success_supplied", s->battery_wire_auth_replies != 0);
    qdict_put_int(q, "max_replies", w->max_replies);
    qdict_put_int(q, "replies", w->replies);
    qdict_put_int(q, "pending_replies", w->count);
    qdict_put_int(q, "public_TX_bytes", w->tx_bytes);
    qdict_put_int(q, "synthetic_RX_bytes", w->rx_bytes);
    qdict_put_int(q, "raw_limit_per_direction", EX1850_BATTERY_RAW_LIMIT);
    qdict_put_int(q, "event_limit", EX1850_BATTERY_EVENT_LIMIT);
    g_autofree char *partial = ex1850_battery_hex(w->partial, w->partial_size);
    qdict_put_str(q, "partial_TX_tail", partial);
    qdict_put_int(parser, "valid_frames", w->valid_frames);
    qdict_put_int(parser, "unframed_bytes", w->unframed_bytes);
    qdict_put_int(parser, "invalid_lengths", w->invalid_lengths);
    qdict_put_int(parser, "checksum_failures", w->checksum_failures);
    qdict_put_int(protocol, "authentication_replies", s->battery_wire_auth_replies);
    qdict_put_int(protocol, "ordinary_replies", s->battery_wire_ordinary_replies);
    qdict_put_int(protocol, "unmodeled_requests", w->unmodeled_requests);
    qdict_put_int(protocol, "authentication_challenge_mismatches", w->auth_mismatches);
    for (unsigned n = 0; n < 256; n++) {
        if (!w->commands[n]) { continue; }
        char key[32];
        snprintf(key, sizeof(key), "command_%02x", n);
        qdict_put_int(parser, key, w->commands[n]);
        snprintf(key, sizeof(key), "TX_command_%02x", n);
        qdict_put_int(protocol, key, w->commands[n]);
    }
    if (w->unknown_tx_size) {
        g_autofree char *hex = ex1850_battery_hex(w->unknown_tx, w->unknown_tx_size);
        qlist_append_str(unknown, hex);
    }
    qdict_put(q, "parser_counts", parser);
    qdict_put(q, "protocol_counts", protocol);
    qdict_put(q, "unmodeled_public_TX", unknown);
    qdict_put_obj(q, "events", qobject_ref(QOBJECT(s->battery_wire_events)));
    qdict_put_obj(q, "public_entropy", qobject_ref(qdict_get(s->battery_wire_table, "public_entropy")));
    qdict_put_obj(q, "input_kind", qobject_ref(qdict_get(s->battery_wire_table, "input_kind")));
    qdict_put(q, "final_USART1", ex1850_usart1_statistics(s));
    if (w->error) { qdict_put_str(q, "error", w->error); }
    else { qdict_put_null(q, "error"); }
    FILE *file = ex1850_battery_file(s, "wire-closed.json");
    ex1850_battery_json(file, q);
    fclose(file);
    qobject_unref(q);
}

static void ex1850_battery_wire_exit(Notifier *notifier, void *data)
{
    EX1850ResetState *s = container_of(notifier, EX1850ResetState, battery_wire_exit_notifier);
    ex1850_battery_wire_close(s, true);
}

static void ex1850_battery_wire_exit_fallback(void)
{
    ex1850_battery_wire_close(ex1850_battery_exit_state, false);
}

static unsigned ex1850_battery_unhex(const char *hex, uint8_t *bytes)
{
    size_t length = hex ? strlen(hex) : 0;
    if (length < 8 || length > EX1850_BATTERY_FRAME * 2 || (length & 1)) {
        error_report("Invalid immutable battery contract frame length"); exit(1);
    }
    for (unsigned n = 0; n < length / 2; n++) {
        int hi = g_ascii_xdigit_value(hex[n * 2]), lo = g_ascii_xdigit_value(hex[n * 2 + 1]);
        if (hi < 0 || lo < 0) { error_report("Invalid battery contract hex"); exit(1); }
        bytes[n] = hi * 16 + lo;
    }
    if (bytes[0] != 2 || ex1850_battery_xor(bytes, length / 2)) {
        error_report("Invalid immutable battery contract checksum"); exit(1);
    }
    return length / 2;
}

static void ex1850_battery_wire_init(EX1850ResetState *s)
{
    const char *path = g_getenv("EX1850_BATTERY_WIRE_SPEC");
    if (!path) { return; }
    const char *output = g_getenv("EX1850_BATTERY_WIRE_OUTPUT");
    const char *expected = g_getenv("EX1850_BATTERY_WIRE_SHA256");
    if (!output || !expected || qemu_chr_find("ex1850-usart1")) {
        error_report("Virtual battery requires a locked output and exclusive USART1 endpoint"); exit(1);
    }
    g_autofree char *raw = NULL;
    gsize length;
    if (!g_file_get_contents(path, &raw, &length, NULL) || length > 256 * 1024) {
        error_report("Cannot load bounded immutable battery contracts"); exit(1);
    }
    g_autofree char *sha = g_compute_checksum_for_data(G_CHECKSUM_SHA256, (guchar *)raw, length);
    if (strcmp(sha, expected)) { error_report("Immutable battery contract hash changed"); exit(1); }
    s->battery_wire_table = qobject_to(QDict, qobject_from_json(raw, &error_fatal));
    if (!s->battery_wire_table ||
        g_strcmp0(qdict_get_try_str(s->battery_wire_table, "schema"), "ex1850.virtual-battery-contracts/1") ||
        g_strcmp0(qdict_get_try_str(s->battery_wire_table, "clock"), "QEMU_CLOCK_VIRTUAL") ||
        !qdict_get_try_bool(s->battery_wire_table, "immutable_inputs_compiled_before_guest_start", false)) {
        error_report("Invalid virtual battery contract schema"); exit(1);
    }
    EX1850BatteryWire *w = &s->battery_wire;
    w->turnaround_ns = qdict_get_try_int(s->battery_wire_table, "turnaround_ns", -1);
    int64_t max_replies = qdict_get_try_int(s->battery_wire_table, "max_replies", 0);
    QList *contracts = qdict_get_qlist(s->battery_wire_table, "contracts");
    if (!contracts || !qlist_size(contracts) || qlist_size(contracts) > EX1850_BATTERY_CONTRACTS ||
        w->turnaround_ns < 0 || max_replies < 1 || max_replies > 8192) {
        error_report("Invalid virtual battery contract limits"); exit(1);
    }
    w->max_replies = max_replies;
    const QListEntry *entry;
    QLIST_FOREACH_ENTRY(contracts, entry) {
        QDict *item = qobject_to(QDict, qlist_entry_obj(entry));
        if (!item) { error_report("Invalid virtual battery contract object"); exit(1); }
        unsigned n = w->contract_count++;
        EX1850BatteryContract *c = &w->contracts[n];
        c->tx_size = ex1850_battery_unhex(qdict_get_try_str(item, "TX"), c->tx);
        c->rx_size = ex1850_battery_unhex(qdict_get_try_str(item, "RX"), c->rx);
        c->authentication = qdict_get_bool(item, "authentication");
        c->allowed_before_authentication = qdict_get_bool(item, "allowed_before_authentication");
        s->battery_wire_fields[n] = qdict_get_qdict(item, "fields");
        if (c->tx_size != c->tx[2] + 4 || !s->battery_wire_fields[n] ||
            c->rx[1] != 6 || (c->authentication && (c->tx_size != 21 || c->tx[1] != 1 || c->rx_size != 29))) {
            error_report("Invalid virtual battery contract frame structure"); exit(1);
        }
        for (unsigned i = 0; i < n; i++) {
            if (w->contracts[i].tx_size == c->tx_size &&
                !memcmp(w->contracts[i].tx, c->tx, c->tx_size)) {
                error_report("Duplicate immutable battery TX contract"); exit(1);
            }
        }
    }
    s->battery_wire_output = g_strdup(output);
    s->battery_wire_sha256 = g_strdup(sha);
    s->battery_wire_events = qlist_new();
    s->battery_wire_tx_file = ex1850_battery_file(s, "UART1-TX.bin");
    s->battery_wire_rx_file = ex1850_battery_file(s, "UART1-RX.bin");
    s->battery_wire_event_file = ex1850_battery_file(s, "wire-events.jsonl");
    s->battery_wire_enabled = true;
    ex1850_battery_exit_state = s;
    s->battery_wire_exit_notifier.notify = ex1850_battery_wire_exit;
    qemu_add_exit_notifier(&s->battery_wire_exit_notifier);
    atexit(ex1850_battery_wire_exit_fallback);
    QDict *opened = qdict_new();
    qdict_put_bool(opened, "enabled", true);
    qdict_put_str(opened, "clock", "QEMU_CLOCK_VIRTUAL");
    qdict_put_str(opened, "contract_sha256", sha);
    qdict_put_int(opened, "contracts", w->contract_count);
    qdict_put_int(opened, "turnaround_ns", w->turnaround_ns);
    FILE *file = ex1850_battery_file(s, "wire-opened.json");
    ex1850_battery_json(file, opened);
    fclose(file);
    qobject_unref(opened);
    fprintf(stderr, "EX1850_BATTERY_WIRE_PROFILE enabled=1 clock=QEMU_CLOCK_VIRTUAL "
            "contracts=%u turnaround_ns=%" PRId64 " physical_latency_verified=0 "
            "runtime_input=completed_UART_TX_only MCU_private_RAM_exposed=0\n",
            w->contract_count, w->turnaround_ns);
}
#endif
