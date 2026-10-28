/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Opt-in QEMU adapter for the Z6II C1.70 HPD/DDC proposal. The EDID file
 * and HPD events are immutable host inputs, loaded before guest startup.
 * Timing, W1C and unplug-error policies remain explicit hypotheses.
 * GIC input selection is experimental and has no inferred default. */
#ifndef NIKON_Z6II_HDMI_H
#define NIKON_Z6II_HDMI_H

#define Z6II_HDMI_HPD_EVENT_LIMIT 64u
#define Z6II_HDMI_GIC_INPUT_MAX 223u

static bool z6ii_hdmi_decimal(const char *text, uint64_t maximum,
                             uint64_t *value)
{
    uint64_t result = 0;
    if (!text || !*text) {
        return false;
    }
    for (const char *p = text; *p; p++) {
        unsigned digit;
        if (*p < '0' || *p > '9') {
            return false;
        }
        digit = *p - '0';
        if (digit > maximum || result > (maximum - digit) / 10) {
            return false;
        }
        result = result * 10 + digit;
    }
    *value = result;
    return true;
}

static uint64_t z6ii_hdmi_number(Z6IIState *s, const char *name, uint64_t fallback,
                                uint64_t minimum, uint64_t maximum)
{
    const char *text = z6ii_engine_getenv(s->engine, name);
    uint64_t value;
    if (!text) {
        return fallback;
    }
    if (!z6ii_hdmi_decimal(text, maximum, &value) || value < minimum) {
        error_report("%s requires a decimal integer in [%" PRIu64
                     ", %" PRIu64 "]", name, minimum, maximum);
        exit(1);
    }
    return value;
}

static gchar *z6ii_hdmi_input_file(Z6IIState *s, const char *name, gsize *bytes)
{
    const char *path = z6ii_engine_getenv(s->engine, name);
    gchar *data = NULL;
    GError *error = NULL;
    if (!path || !g_path_is_absolute(path)) {
        error_report("%s requires an explicit absolute input path", name);
        exit(1);
    }
    if (!g_file_get_contents(path, &data, bytes, &error)) {
        error_report("%s could not read input %s: %s", name, path,
                     error ? error->message : "unknown read error");
        g_clear_error(&error);
        exit(1);
    }
    return data;
}

static bool z6ii_hdmi_trace_allowed(Z6IIState *s)
{
    if (s->hdmi_trace_count >= s->hdmi_trace_limit) {
        return false;
    }
    ++s->hdmi_trace_count;
    return true;
}

static void z6ii_hdmi_trace_state(Z6IIState *s, const char *action,
                                 hwaddr addr, unsigned size, bool write,
                                 uint64_t value, Z6IIHDMIAccess result,
                                 bool guest_mmio)
{
    /* Timers explicitly pass false: current_cpu in a timer callback
     * would identify the interrupted CPU, not a guest MMIO access. */
    CPUState *access_cpu = guest_mmio ? current_cpu : NULL;
    CPUARMState *access_env = access_cpu ? &ARM_CPU(access_cpu)->env : NULL;
    const char *context = !guest_mmio ? "timer-no-guest-mmio" :
                          access_cpu ? "guest-mmio" : "noncpu-mmio";
    if (result == Z6II_HDMI_ACCESS_OK && !z6ii_hdmi_trace_allowed(s)) {
        return;
    }
    fprintf(stderr, "Z6II_HDMI_STATE action=%s now_ns=%" PRId64
            " %c addr=%08" HWADDR_PRIx " size=%u value=%02" PRIx64
            " result=%s hpd=%u status=%02x source_pending=%u fifo_valid=%u"
            " job=%u generation=%" PRIu64 " job_generation=%" PRIu64
            " due_ns=%" PRIu64 " index=%zu submitted=%" PRIu64
            " completed=%" PRIu64 " errors=%" PRIu64 " cancelled=%" PRIu64
            " fifo=%02x%02x%02x%02x%02x%02x%02x%02x"
            " access_context=%s access_cpu=%d access_pc_valid=%u"
            " access_pc=0x%08x access_lr=0x%08x access_sp=0x%08x"
            " access_cpsr=0x%08x\n",
            action, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), write ? 'W' : 'R',
            addr, size, value, z6ii_hdmi_core_access_name(result),
            s->hdmi.connected, s->hdmi.status,
            z6ii_hdmi_core_irq_pending(&s->hdmi), s->hdmi.fifo_valid,
            s->hdmi.job, s->hdmi.generation, s->hdmi.job_generation,
            s->hdmi.due_ns, s->hdmi.request_index, s->hdmi.submitted_reads,
            s->hdmi.completed_reads, s->hdmi.errors, s->hdmi.cancelled_jobs,
            s->hdmi.fifo[0], s->hdmi.fifo[1], s->hdmi.fifo[2], s->hdmi.fifo[3],
            s->hdmi.fifo[4], s->hdmi.fifo[5], s->hdmi.fifo[6], s->hdmi.fifo[7],
            context, access_cpu ? access_cpu->cpu_index : -1, access_env != NULL,
            access_env ? access_env->regs[15] : 0,
            access_env ? access_env->regs[14] : 0,
            access_env ? access_env->regs[13] : 0,
            access_env ? cpsr_read(access_env) : 0);
}

static void z6ii_hdmi_update_irq(Z6IIState *s)
{
    uint8_t phy = s->hdmi_phy_i2c_enabled ? s->hdmi_phy_i2c.status : 0;
    uint8_t pll = s->hdmi_phy_pll_enabled ? s->hdmi_phy_pll.raw : 0;
    uint8_t summary = s->hdmi_ih_enabled ?
        z6ii_hdmi_ih_summary(&s->hdmi_ih, s->hdmi.status, phy, pll) :
        (z6ii_hdmi_core_irq_pending(&s->hdmi) ? 4 : 0);
    bool pending = s->hdmi_ih_enabled ?
        z6ii_hdmi_ih_irq(&s->hdmi_ih, s->hdmi.status, phy, pll) :
        z6ii_hdmi_core_irq_pending(&s->hdmi);
    if (pending == s->hdmi_irq_level) {
        return;
    }
    s->hdmi_irq_level = pending;
    if (s->hdmi_gic_input >= 0) {
        /* The parameter is the raw QEMU external input index. No conversion
         * from the observed firmware registration selectors is applied.
         * Distributor enable, group, targets and EOI remain guest-owned. */
        qemu_set_irq(qdev_get_gpio_in(DEVICE(s->priv), s->hdmi_gic_input),
                     pending);
        fprintf(stderr, "Z6II_HDMI_EXPERIMENTAL_IRQ now_ns=%" PRId64
                " gpio_input=%d level=%u policy=%s"
                " summary=%02x ddc_status=%02x phy_status=%02x pll_status=%02x"
                " ddc_mute=%02x phy_mute=%02x pll_mute=%02x global_mute=%02x"
                " silicon_route_verified=0 peripheral_mask_verified=0"
                " guest_GIC_configuration_required=1\n",
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), s->hdmi_gic_input,
                pending, s->hdmi_ih_enabled ? "ih-groups-level" :
                "ddc-pending-level", summary, s->hdmi.status, phy, pll,
                s->hdmi_ih.ddc_mute, s->hdmi_ih.phy_mute,
                s->hdmi_ih.pll_mute, s->hdmi_ih.global_mute);
    } else {
        fprintf(stderr, "Z6II_HDMI_ROUTE_BOUNDARY now_ns=%" PRId64
                " source=ddc source_pending=%u gpio_input=unresolved"
                " IRQ_driven=0 registration_selectors_are_not_routes=1\n",
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), pending);
    }
}

static void z6ii_hdmi_schedule(Z6IIState *s)
{
    uint64_t due;
    if (z6ii_hdmi_core_next_due(&s->hdmi, &due)) {
        if (due > INT64_MAX) {
            error_report("HDMI DDC deadline exceeds QEMU virtual clock range");
            exit(1);
        }
        s->hdmi_timer_generation = s->hdmi.job_generation;
        timer_mod(s->hdmi_timer, due);
    } else {
        timer_del(s->hdmi_timer);
        s->hdmi_timer_generation = 0;
    }
    z6ii_hdmi_update_irq(s);
}

static void z6ii_hdmi_complete(void *opaque)
{
    Z6IIState *s = opaque;
    uint64_t generation = s->hdmi_timer_generation;
    uint64_t deadline = s->hdmi.due_ns;
    bool completed = z6ii_hdmi_core_complete(&s->hdmi, generation,
                        qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    if (z6ii_hdmi_trace_allowed(s)) {
        fprintf(stderr, "Z6II_HDMI_DEADLINE now_ns=%" PRId64
                " captured_generation=%" PRIu64 " deadline_ns=%" PRIu64
                " accepted=%u\n", qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
                generation, deadline, completed);
    }
    z6ii_hdmi_trace_state(s, completed ? "complete" : "stale-or-early",
                          Z6II_HDMI_STATUS_ADDR, 1, false, s->hdmi.status,
                          Z6II_HDMI_ACCESS_OK, false);
    z6ii_hdmi_schedule(s);
}

static void z6ii_hdmi_schedule_hpd(Z6IIState *s)
{
    if (s->hdmi_hpd_index < s->hdmi_hpd_count) {
        timer_mod(s->hdmi_hpd_timer, s->hdmi_hpd_epoch +
                  s->hdmi_hpd_events[s->hdmi_hpd_index].offset_ns);
    } else {
        timer_del(s->hdmi_hpd_timer);
    }
}

static void z6ii_hdmi_hpd_event(void *opaque)
{
    Z6IIState *s = opaque;
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    if (now < s->hdmi_hpd_epoch) {
        z6ii_hdmi_schedule_hpd(s);
        return;
    }
    while (s->hdmi_hpd_index < s->hdmi_hpd_count &&
           s->hdmi_hpd_events[s->hdmi_hpd_index].offset_ns <=
           (uint64_t)(now - s->hdmi_hpd_epoch)) {
        const Z6IIHDMIHPDEvent *event =
            &s->hdmi_hpd_events[s->hdmi_hpd_index++];
        z6ii_hdmi_core_set_hpd(&s->hdmi, event->connected);
        z6ii_hdmi_trace_state(s, "hpd-event", Z6II_HDMI_HPD_ADDR, 1,
                              false, event->connected ? 2 : 0,
                              Z6II_HDMI_ACCESS_OK, false);
    }
    z6ii_hdmi_schedule(s);
    z6ii_hdmi_schedule_hpd(s);
}

static void z6ii_hdmi_load_hpd_events(Z6IIState *s)
{
    gsize bytes;
    gchar *data = z6ii_hdmi_input_file(s, "Z6II_HDMI_HPD_EVENTS_FILE", &bytes);
    gchar **lines;
    if (memchr(data, 0, bytes)) {
        error_report("HDMI HPD event input contains an embedded NUL");
        exit(1);
    }
    lines = g_strsplit(data, "\n", -1);
    for (unsigned i = 0; lines[i]; i++) {
        char *row = g_strstrip(lines[i]);
        char *end = row;
        char *state;
        uint64_t offset;
        if (!*row || *row == '#') {
            continue;
        }
        while (*end >= '0' && *end <= '9') {
            ++end;
        }
        if (end == row || (*end != ' ' && *end != '\t')) {
            goto malformed;
        }
        state = end + 1;
        *end = 0;
        while (*state == ' ' || *state == '\t') {
            ++state;
        }
        if (!z6ii_hdmi_decimal(row, INT64_MAX - s->hdmi_hpd_epoch,
                               &offset) ||
            (strcmp(state, "0") && strcmp(state, "1")) ||
            (s->hdmi_hpd_count && offset <=
             s->hdmi_hpd_events[s->hdmi_hpd_count - 1].offset_ns) ||
            s->hdmi_hpd_count == Z6II_HDMI_HPD_EVENT_LIMIT) {
            goto malformed;
        }
        s->hdmi_hpd_events[s->hdmi_hpd_count++] =
            (Z6IIHDMIHPDEvent) { offset, *state == '1' };
        continue;
malformed:
        error_report("HDMI HPD event line %u requires strictly increasing "
                     "relative_virtual_ns and state 0/1; maximum %u events",
                     i + 1, Z6II_HDMI_HPD_EVENT_LIMIT);
        exit(1);
    }
    gchar *sha = g_compute_checksum_for_data(G_CHECKSUM_SHA256,
                                             (const guchar *)data, bytes);
    fprintf(stderr, "Z6II_HDMI_HPD_INPUT file=%s bytes=%zu sha256=%s"
            " events=%u epoch_ns=%" PRId64 " clock=virtual"
            " host_polling=0 HPD_IRQ_invented=0\n",
            z6ii_engine_getenv(s->engine, "Z6II_HDMI_HPD_EVENTS_FILE"), (size_t)bytes, sha,
            s->hdmi_hpd_count, s->hdmi_hpd_epoch);
    g_free(sha);
    g_strfreev(lines);
    g_free(data);
}

static bool z6ii_hdmi_owns(Z6IIState *s, hwaddr addr)
{
    return s->hdmi_enabled && addr <= UINT32_MAX &&
           (z6ii_hdmi_core_owns(addr) ||
            (s->hdmi_ih_enabled && z6ii_hdmi_ih_owns(addr)));
}

static bool z6ii_hdmi_access(Z6IIState *s, hwaddr addr, unsigned size,
                            bool write, uint64_t *value)
{
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    if (now < 0) { return false; }
    if (s->hdmi_ih_enabled && z6ii_hdmi_ih_owns(addr)) {
        uint8_t phy = s->hdmi_phy_i2c_enabled ? s->hdmi_phy_i2c.status : 0;
        uint8_t pll = s->hdmi_phy_pll_enabled ? s->hdmi_phy_pll.raw : 0;
        bool accepted = z6ii_hdmi_ih_access(&s->hdmi_ih, addr, size,
            write, value, s->hdmi.status, phy, pll);
        if (!accepted || z6ii_hdmi_trace_allowed(s)) {
            fprintf(stderr, "Z6II_HDMI_IH_MMIO %c addr=%08" HWADDR_PRIx
                    " size=%u value=%02" PRIx64 " accepted=%u"
                    " summary=%02x ddc_status=%02x phy_status=%02x pll_status=%02x"
                    " ddc_mute=%02x phy_mute=%02x pll_mute=%02x global_mute=%02x"
                    " summary_precedes_global_mute=policy"
                    " wakeup_bit1_readback=1 wakeup_lifecycle=absent\n",
                    write ? 'W' : 'R', addr, size, *value, accepted,
                    z6ii_hdmi_ih_summary(&s->hdmi_ih, s->hdmi.status, phy, pll),
                    s->hdmi.status, phy, pll, s->hdmi_ih.ddc_mute,
                    s->hdmi_ih.phy_mute, s->hdmi_ih.pll_mute,
                    s->hdmi_ih.global_mute);
        }
        if (write && accepted) { z6ii_hdmi_update_irq(s); }
        z6ii_trace(s, addr, size, write, *value);
        return accepted;
    }
    /* Reject signed-clock overflow before the portable DDC core commits
     * a command or cancels an existing job. Unsupported commands remain
     * rejected without changing any transaction state. */
    if (write && size == 1 && addr == Z6II_HDMI_COMMAND_ADDR && *value &&
        (uint64_t)now > (uint64_t)INT64_MAX - s->hdmi.delay_ns) {
        fprintf(stderr, "Z6II_HDMI_DEADLINE_REJECT now_ns=%" PRId64
                " delay_ns=%" PRIu64 " state_mutated=0\n",
                now, s->hdmi.delay_ns);
        return false;
    }
    Z6IIHDMIAccess result = z6ii_hdmi_core_access(&s->hdmi, addr, size,
                            write, value, now);
    z6ii_hdmi_trace_state(s, "mmio", addr, size, write, *value, result, true);
    if (write) {
        /* QEMU virtual timer mutation and callbacks are serialized. Removing
         * a timer invalidates its captured generation; the portable core also
         * rejects stale generation tokens independently of QEMU scheduling. */
        z6ii_hdmi_schedule(s);
    }
    z6ii_trace(s, addr, size, write, *value);
    return result == Z6II_HDMI_ACCESS_OK;
}

static void z6ii_hdmi_board_reset(void *opaque)
{
    Z6IIState *s = opaque;
    /* Cancel the old deadlines first. A reset may replay the immutable HPD
     * schedule relative to a new epoch; it never retains an old DDC job. */
    timer_del(s->hdmi_timer);
    timer_del(s->hdmi_hpd_timer);
    s->hdmi_timer_generation = 0;
    if (s->hdmi_ih_enabled) { z6ii_hdmi_ih_reset(&s->hdmi_ih); }
    z6ii_hdmi_core_cancel(&s->hdmi, false);
    z6ii_hdmi_video_reset(&s->hdmi_video, s->hdmi.generation);
    s->hdmi.device = s->hdmi.offset = s->hdmi.segment_device = 0;
    s->hdmi.segment = s->hdmi.command = s->hdmi.status = 0;
    s->hdmi.power_mask = s->hdmi.tx_control = 0;
    z6ii_hdmi_config_reset(&s->hdmi);
    s->hdmi.fifo_valid = false;
    memset(s->hdmi.fifo, 0, sizeof(s->hdmi.fifo));
    s->hdmi.connected = s->hdmi_initial_hpd;
    if (s->hdmi_phy_pll_enabled) { z6ii_hdmi_phy_pll_board_reset_state(s); }
    if (s->hdmi_phy_i2c_enabled) { z6ii_hdmi_phy_i2c_reset_state(s); }
    z6ii_hdmi_update_irq(s);
    s->hdmi_hpd_index = 0;
    s->hdmi_hpd_epoch = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    for (unsigned i = 0; i < s->hdmi_hpd_count; ++i) {
        if (s->hdmi_hpd_events[i].offset_ns >
            (uint64_t)INT64_MAX - s->hdmi_hpd_epoch) {
            error_report("HDMI reset HPD schedule exceeds virtual clock range");
            exit(1);
        }
    }
    z6ii_hdmi_schedule_hpd(s);
    fprintf(stderr, "Z6II_HDMI_BOARD_RESET DDC_timer_cancelled=1"
            " source_status_cleared=1 PHY_cancelled=%u"
            " PLL_cancelled=%u PLL_board_reset_once=1"
            " IH_reset=%u HPD_schedule=replay-immutable-input"
            " guest_ready_write=0 video_completion=0\n",
            s->hdmi_phy_i2c_enabled, s->hdmi_phy_pll_enabled, s->hdmi_ih_enabled);
}

static void z6ii_hdmi_init(Z6IIState *s, bool functional_devices)
{
    static const char *const names[] = {
        "Z6II_HDMI_MODEL", "Z6II_HDMI_EDID_FILE", "Z6II_HDMI_HPD",
        "Z6II_HDMI_HPD_EVENTS_FILE", "Z6II_HDMI_DDC_DELAY_NS",
        "Z6II_HDMI_DDC_FAULT_REQUEST", "Z6II_HDMI_DDC_FAULT_KIND",
        "Z6II_HDMI_TRACE_LIMIT", "Z6II_HDMI_EXPERIMENTAL_GIC_INPUT",
        "Z6II_HDMI_EXPERIMENTAL_IRQ_POLICY",
        "Z6II_HDMI_IRQ_MODEL",
    };
    const char *model = z6ii_engine_getenv(s->engine, names[0]);
    const char *hpd = z6ii_engine_getenv(s->engine, "Z6II_HDMI_HPD");
    const char *fault_request = z6ii_engine_getenv(s->engine, "Z6II_HDMI_DDC_FAULT_REQUEST");
    const char *fault_kind = z6ii_engine_getenv(s->engine, "Z6II_HDMI_DDC_FAULT_KIND");
    const char *gic_input = z6ii_engine_getenv(s->engine, "Z6II_HDMI_EXPERIMENTAL_GIC_INPUT");
    const char *irq_policy = z6ii_engine_getenv(s->engine, "Z6II_HDMI_EXPERIMENTAL_IRQ_POLICY");
    const char *ih_model = z6ii_engine_getenv(s->engine, "Z6II_HDMI_IRQ_MODEL");
    bool any = false;
    bool ih_policy = irq_policy &&
        (!strcmp(irq_policy, "ih-groups-level") || !strcmp(irq_policy, "ih-phy"));
    gsize bytes;
    uint64_t delay;
    s->hdmi_gic_input = -1;
    for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        any |= z6ii_engine_getenv(s->engine, names[i]) != NULL;
    }
    if (!any) {
        return;
    }
    if (strcmp(s->profile->role, "master")) {
        fprintf(stderr, "Z6II_HDMI_INPUT_IGNORED role=%s scope=master"
                " shared_process_environment=1 transport_created=0\n",
                s->profile->role);
        return;
    }
    if (!model || strcmp(model, "ddc-v1") || !functional_devices) {
        error_report("HDMI inputs require Z6II_HDMI_MODEL=ddc-v1 on a "
                     "functional Master board");
        exit(1);
    }
    if (!hpd || (strcmp(hpd, "0") && strcmp(hpd, "1"))) {
        error_report("HDMI ddc-v1 requires explicit Z6II_HDMI_HPD=0 or 1");
        exit(1);
    }
    if (!!fault_request != !!fault_kind ||
        (fault_kind && strcmp(fault_kind, "error") &&
         strcmp(fault_kind, "timeout"))) {
        error_report("HDMI fault injection requires both FAULT_REQUEST=N "
                     "and FAULT_KIND=error or timeout");
        exit(1);
    }
    if (!!gic_input != !!irq_policy ||
        (irq_policy && strcmp(irq_policy, "ddc-pending-level") && !ih_policy) ||
        (ih_model && strcmp(ih_model, "ih-groups-v1")) ||
        (!!ih_model != ih_policy)) {
        error_report("HDMI experimental IRQ requires explicit GIC_INPUT "
                     "and either IRQ_POLICY=ddc-pending-level or"
                     " IRQ_MODEL=ih-groups-v1 with IRQ_POLICY=ih-groups-level or ih-phy");
        exit(1);
    }
    delay = z6ii_hdmi_number(s, "Z6II_HDMI_DDC_DELAY_NS", 1000000, 1,
                             INT64_MAX);
    s->hdmi_trace_limit = z6ii_hdmi_number(s, "Z6II_HDMI_TRACE_LIMIT", 4096,
                                          0, UINT_MAX);
    s->hdmi_edid = (uint8_t *)z6ii_hdmi_input_file(s, "Z6II_HDMI_EDID_FILE",
                                                 &bytes);
    if (!z6ii_hdmi_core_init(&s->hdmi, s->hdmi_edid, bytes,
                             *hpd == '1', delay)) {
        error_report("HDMI EDID requires a valid header, 128B blocks, "
                     "matching extension count and per-block checksums");
        exit(1);
    }
    if (fault_kind) {
        s->hdmi.fault_request = z6ii_hdmi_number(s, 
            "Z6II_HDMI_DDC_FAULT_REQUEST", 0, 1, UINT64_MAX);
        s->hdmi.fault = !strcmp(fault_kind, "error") ?
                        Z6II_HDMI_FAULT_ERROR : Z6II_HDMI_FAULT_TIMEOUT;
    }
    if (gic_input) {
        s->hdmi_gic_input = z6ii_hdmi_number(s, 
            "Z6II_HDMI_EXPERIMENTAL_GIC_INPUT", 0, 0,
            Z6II_HDMI_GIC_INPUT_MAX);
    }
    if (ih_model) {
        if (s->hdmi_gic_input != 100) {
            error_report("HDMI IH groups require original IRQ84/GIC ID132/"
                         "QEMU input100; independent IRQ85 is not modeled");
            exit(1);
        }
        z6ii_hdmi_ih_reset(&s->hdmi_ih);
        s->hdmi_ih_enabled = true;
        fprintf(stderr, "Z6II_HDMI_IH_MODEL model=ih-groups-v1"
                " DDC_summary_bit=2 PHY_I2C_summary_bit=3 PLL_summary_bit=3"
                " separate_DDC_PLL_PHY_I2C_mutes=1"
                " source_mute=active-high global_bit0=normal-IRQ-mute"
                " global_bit1=latched-wakeup-mute wakeup_lifecycle=absent"
                " reset_mutes=policy summary_precedes_global_mute=policy"
                " source_status_preserved_under_mute=1"
                " IRQ_owner=single-aggregator GPIO_input=100"
                " native_ISR=10481968 silicon_mask_verified=0\n");
    }
    s->hdmi_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, z6ii_hdmi_complete, s);
    s->hdmi_hpd_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                     z6ii_hdmi_hpd_event, s);
    s->hdmi_hpd_epoch = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    if (z6ii_engine_getenv(s->engine, "Z6II_HDMI_HPD_EVENTS_FILE")) {
        z6ii_hdmi_load_hpd_events(s);
    }
    s->hdmi_enabled = true;
    s->hdmi_initial_hpd = *hpd == '1';
    z6ii_hdmi_schedule_hpd(s);
    qemu_register_reset(z6ii_hdmi_board_reset, s);
    gchar *sha = g_compute_checksum_for_data(G_CHECKSUM_SHA256,
                                             s->hdmi_edid, bytes);
    fprintf(stderr, "Z6II_HDMI_MODEL role=master model=ddc-v1 EDID_file=%s"
            " EDID_bytes=%zu EDID_sha256=%s HPD=%u delay_ns=%" PRIu64
            " delay_measured=0 ack=W1C-hypothesis unplug_error=hypothesis"
            " experimental_gpio_input=%d fault_request=%" PRIu64
            " fault_kind=%s HPD_nibble_unknown=1 video_transport=absent"
            " guest_readiness_writes=0\n",
            z6ii_engine_getenv(s->engine, "Z6II_HDMI_EDID_FILE"), (size_t)bytes, sha,
            s->hdmi.connected, delay, s->hdmi_gic_input, s->hdmi.fault_request,
            fault_kind ? fault_kind : "none");
    g_free(sha);
}

#endif
