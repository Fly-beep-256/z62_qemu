/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Default-off synthetic actuator for the independent CAPSEQ GPIO pair.
 * Original ROM proves request DATA04282018 bit8, input DATA04282014 bit7,
 * pending bit0/IRQ65, and the original callback/message consumers. The actual
 * mechanism, polarity/mode meaning and latency are not recovered. This v1
 * candidate latches one rising completion per rising request, holds done high
 * until request falls, and leaves pending to the original mask/W1C controller.
 * It never supplies an MCU packet or changes guest RAM/RTOS/application state.
 * Included after Z6IIFunctionalDevices and z6ii_fd_exmcu_irq, before wire.h. */

static void z6ii_capseq_actuator_trace(Z6IIFunctionalDevices *s,
                                      const char *action)
{
    uint64_t index = s->capseq_trace_attempts++;
    if (index >= s->capseq_trace_limit) { return; }
    fprintf(stderr, "Z6II_CAPSEQ_ACTUATOR index=%" PRIu64 " action=%s"
            " virtual_ns=%" PRId64 " generation=%" PRIu64
            " due_ns=%" PRId64 " request=%u armed=%u done=%u"
            " pending=%08x mask=%08x polarity_raw=%08x mode_raw=%08x"
            " irq=%u source=synthetic-actuator physical_timing_verified=0\n",
            index, action, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
            s->capseq_generation, s->capseq_due_ns,
            s->capseq_request, s->capseq_armed, s->capseq_done,
            s->exmcu_gpio_pending, s->exmcu_gpio_mask,
            s->exmcu_gpio_polarity, s->exmcu_gpio_mode, s->capseq_irq_level);
}

static void z6ii_capseq_actuator_irq_observe(Z6IIFunctionalDevices *s,
                                            bool level)
{
    if (s->capseq_irq_level == level) { return; }
    s->capseq_irq_level = level;
    z6ii_capseq_actuator_trace(s, level ? "irq-assert" : "irq-deassert");
}

static void z6ii_capseq_actuator_complete(void *opaque)
{
    Z6IIFunctionalDevices *s = opaque;
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    if (!s->capseq_armed || !s->capseq_request ||
        s->capseq_armed_generation != s->capseq_generation) { return; }
    if (now < s->capseq_due_ns) {
        timer_mod(s->capseq_timer, s->capseq_due_ns);
        return;
    }
    s->capseq_armed = false;
    s->capseq_done = true;
    s->exmcu_gpio_pending |= 1;
    z6ii_capseq_actuator_trace(s, "complete");
    z6ii_fd_exmcu_irq(s);
}

static void z6ii_capseq_actuator_output(Z6IIFunctionalDevices *s,
                                        hwaddr addr, uint32_t before,
                                        uint32_t after, uint32_t enable)
{
    if (!s->capseq_actuator_enabled || addr != 0x04282018 ||
        !(enable & 0x100) || !((before ^ after) & 0x100)) { return; }
    s->capseq_request = (after & 0x100) != 0;
    ++s->capseq_generation;
    timer_del(s->capseq_timer);
    s->capseq_armed = false;
    if (!s->capseq_request) {
        s->capseq_done = false;
        /* An already latched pending event survives the input falling. */
        z6ii_capseq_actuator_trace(s, "request-fall-cancel");
        z6ii_fd_exmcu_irq(s);
        return;
    }
    s->capseq_done = false;
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    if (now > INT64_MAX - s->capseq_delay_ns) {
        z6ii_capseq_actuator_trace(s, "deadline-overflow-no-completion");
        return;
    }
    s->capseq_due_ns = now + s->capseq_delay_ns;
    s->capseq_armed_generation = s->capseq_generation;
    if (!s->capseq_fault_timeout) {
        s->capseq_armed = true;
        timer_mod(s->capseq_timer, s->capseq_due_ns);
    }
    z6ii_capseq_actuator_trace(s, s->capseq_fault_timeout ?
        "request-timeout-injected" : "request-rise-arm");
}

static void z6ii_capseq_actuator_input(Z6IIFunctionalDevices *s,
                                       hwaddr addr, uint64_t *value)
{
    if (s->capseq_actuator_enabled && addr == 0x04282014) {
        *value = (*value & ~UINT64_C(0x80)) | (s->capseq_done ? 0x80 : 0);
    }
}

static void z6ii_capseq_actuator_reset(Z6IIFunctionalDevices *s)
{
    if (!s || !s->capseq_actuator_enabled) { return; }
    timer_del(s->capseq_timer);
    ++s->capseq_generation;
    s->capseq_armed = s->capseq_request = s->capseq_done = false;
    s->capseq_due_ns = 0;
    s->setup_regs[0x2018 / 4] &= ~0x100U;
    s->exmcu_gpio_pending &= ~1U;
    z6ii_fd_exmcu_irq(s);
    z6ii_capseq_actuator_trace(s, "board-reset-cancel-clear");
}

static bool z6ii_capseq_actuator_init(Z6IIFunctionalDevices *s,
                                     const char *role)
{
    const char *model = z6ii_engine_getenv(s->engine, "Z6II_CAPSEQ_ACTUATOR_MODEL");
    if (!model || strcmp(role, "master")) { return false; }
    const char *delay = z6ii_engine_getenv(s->engine, "Z6II_CAPSEQ_ACTUATOR_DELAY_NS");
    const char *fault = z6ii_engine_getenv(s->engine, "Z6II_CAPSEQ_ACTUATOR_FAULT");
    uint64_t parsed = 0;
    const char *end = NULL;
    if (!s || !s->mcu_wire.bus || strcmp(model, "request-done-edge-v1") ||
        !delay || !g_ascii_isdigit(delay[0]) ||
        qemu_strtou64(delay, &end, 10, &parsed) || !end || *end ||
        !parsed || parsed > 1000000000 ||
        (fault && strcmp(fault, "timeout"))) {
        error_report("CAPSEQ actuator requires native master wire, explicit "
                     "request-done-edge-v1, delay1..1000000000ns and optional timeout fault");
        exit(1);
    }
    s->capseq_actuator_enabled = true;
    s->capseq_delay_ns = parsed;
    s->capseq_fault_timeout = fault != NULL;
    s->capseq_trace_limit = 64;
    s->capseq_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                  z6ii_capseq_actuator_complete, s);
    fprintf(stderr, "Z6II_CAPSEQ_ACTUATOR_CONFIG model=%s delay_ns=%" PRIu64
            " fault=%s trace_limit=64 request_DATA=04282018 request_bit=8"
            " done_DATA=04282014 done_bit=7 pending_bit=0 IRQ=65 GIC_input=33"
            " source=synthetic-actuator polarity_mode_semantics_verified=0"
            " physical_wiring_verified=0 guest_RAM_writes=0 MCU_packets=0\n",
            model, parsed, fault ? fault : "none");
    return true;
}

/* Passive, bounded adapter evidence after actual board MMIO dispatch.
 * This does not issue another device access. Enabled separately so both the
 * default-off control and candidate can verify real MemTxResult values. */
/* The registry is only for exit reporting; observation budgets belong to
 * the engine and cannot suppress the other EXPEED's evidence. */
static GSList *z6ii_capseq_gpio_trace_engines;

static void z6ii_capseq_gpio_trace_end(void)
{
    for (GSList *entry = z6ii_capseq_gpio_trace_engines; entry; entry = entry->next) {
        Z6IIEngineContext *engine = entry->data;
        fprintf(stderr, "Z6II_CAPSEQ_GPIO_TRACE_END role=%s attempts=%" PRIu64
            " written=%" PRIu64 " overflow=%" PRIu64 " incomplete=%" PRIu64
            " guest_writes=0\n", engine->role, engine->capseq_gpio_trace_attempts,
            engine->capseq_gpio_trace_written,
            engine->capseq_gpio_trace_attempts > 1024 ?
                engine->capseq_gpio_trace_attempts - 1024 : 0,
            engine->capseq_gpio_trace_incomplete);
    }
}

static void z6ii_capseq_gpio_mmio_trace(Z6IIEngineContext *engine, hwaddr addr, unsigned size, bool write,
                                       uint64_t value, MemTxResult result)
{
    if (!((addr >= 0x04282000 && addr < 0x04282030) ||
          (addr >= 0x0426f000 && addr < 0x0426f020))) { return; }
    const char *enable = z6ii_engine_getenv(engine, "Z6II_CAPSEQ_GPIO_TRACE");
    if (!enable || strcmp(enable, "1")) { return; }
    if (!engine->capseq_gpio_trace_initialized) {
        engine->capseq_gpio_trace_initialized = true;
        if (!z6ii_capseq_gpio_trace_engines && atexit(z6ii_capseq_gpio_trace_end)) {
            error_report("CAPSEQ GPIO trace cannot register final record");
            exit(1);
        }
        z6ii_capseq_gpio_trace_engines = g_slist_append(z6ii_capseq_gpio_trace_engines, engine);
    }
    uint64_t index = engine->capseq_gpio_trace_attempts++;
    if (index >= 1024) { return; }
    if (fprintf(stderr, "Z6II_CAPSEQ_GPIO_MMIO role=%s index=%" PRIu64
            " addr=%08" HWADDR_PRIx " size=%u write=%u value=%" PRIx64
            " result=%u\n", engine->role, index, addr, size, write, value,
            (unsigned)result) < 0) {
        ++engine->capseq_gpio_trace_incomplete;
    } else { ++engine->capseq_gpio_trace_written; }
}
