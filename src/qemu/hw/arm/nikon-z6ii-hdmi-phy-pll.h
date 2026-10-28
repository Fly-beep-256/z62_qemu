/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Opt-in, independent PHY PLL completion adapter. Six accepted immutable
 * PHY-I2C configuration jobs precede the guest's powered CONF write. The
 * latency, reset and rising-lock policies are functional model inputs. */
#ifndef NIKON_Z6II_HDMI_PHY_PLL_H
#define NIKON_Z6II_HDMI_PHY_PLL_H

static void z6ii_hdmi_phy_pll_trace(Z6IIState *s, const char *action,
    hwaddr addr, unsigned size, bool write, uint64_t value,
    Z6IIPhyPLLAccess result, bool guest_mmio)
{
    if (result == Z6II_PLL_OK && !z6ii_hdmi_trace_allowed(s)) { return; }
    CPUState *cpu = guest_mmio ? current_cpu : NULL;
    CPUARMState *env = cpu ? &ARM_CPU(cpu)->env : NULL;
    Z6IIPhyPLLCore *p = &s->hdmi_phy_pll;
    fprintf(stderr, "Z6II_HDMI_PHY_PLL action=%s now_ns=%" PRId64
            " %c addr=%08" HWADDR_PRIx " size=%u value=%02" PRIx64
            " result=%u pending=%u generation=%" PRIu64
            " captured_generation=%" PRIu64 " job_generation=%" PRIu64
            " due_ns=%" PRIu64 " sequence=%u conf=%02x reset=%02x"
            " locked=%u hpd=%u internal_int=%02x internal_mask=%02x"
            " polarity=%02x raw=%02x announced=%u fault=%u"
            " words=%04x,%04x,%04x,%04x,%04x,%04x"
            " submitted=%" PRIu64 " completed=%" PRIu64
            " cancelled=%" PRIu64 " access_context=%s access_cpu=%d"
            " access_pc_valid=%u access_pc=%08x"
            " guest_ready_write=0 video_completion=0\n",
            action, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), write ? 'W' : 'R',
            addr, size, value, result, p->pending, p->generation,
            s->hdmi_phy_pll_timer_generation, p->job.generation, p->job.due_ns,
            p->sequence, p->conf, p->reset, p->locked, s->hdmi.connected,
            p->internal_int, p->mask, p->polarity, p->raw, p->announced,
            p->fault, p->words[0], p->words[1], p->words[2], p->words[3],
            p->words[4], p->words[5], p->submitted, p->completed, p->cancelled,
            guest_mmio ? (cpu ? "guest-mmio" : "noncpu-mmio") :
            "adapter-no-guest-mmio", cpu ? cpu->cpu_index : -1,
            env != NULL, env ? env->regs[15] : 0);
}

static void z6ii_hdmi_phy_pll_schedule(Z6IIState *s)
{
    if (!s->hdmi_phy_pll_enabled) { return; }
    uint64_t due;
    if (z6ii_pll_next_due(&s->hdmi_phy_pll, &due)) {
        assert(due <= INT64_MAX);
        s->hdmi_phy_pll_timer_generation = s->hdmi_phy_pll.job.generation;
        timer_mod(s->hdmi_phy_pll_timer, due);
    } else {
        timer_del(s->hdmi_phy_pll_timer);
        s->hdmi_phy_pll_timer_generation = 0;
    }
    z6ii_hdmi_update_irq(s);
}

static void z6ii_hdmi_phy_pll_complete(void *opaque)
{
    Z6IIState *s = opaque;
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    uint64_t token = s->hdmi_phy_pll_timer_generation;
    bool accepted = now >= 0 &&
        z6ii_pll_complete(&s->hdmi_phy_pll, token, now);
    z6ii_hdmi_phy_pll_trace(s, accepted ? "complete" : "stale-or-early",
        Z6II_PLL_IH_STAT, 1, false, s->hdmi_phy_pll.raw,
        Z6II_PLL_OK, false);
    z6ii_hdmi_phy_pll_schedule(s);
}

static void z6ii_hdmi_phy_pll_i2c_completed(Z6IIState *s,
    const Z6IIPhyI2CJob *job)
{
    if (!s->hdmi_phy_pll_enabled || job->slave != 0x69) { return; }
    bool success = job->fault == Z6II_PHY_I2C_FAULT_NONE;
    bool accepted = z6ii_pll_i2c_completion(&s->hdmi_phy_pll,
        job->slave, job->address, job->word, success);
    /* The caller captured this job before accepting the I2C completion;
     * mutable programming registers and sticky status are never evidence. */
    fprintf(stderr, "Z6II_HDMI_PHY_PLL_CONFIG now_ns=%" PRId64
            " i2c_job_generation=%" PRIu64 " i2c_due_ns=%" PRIu64
            " slave=%02x address=%02x word=%04x i2c_fault=%u"
            " accepted_i2c_completion=1 success=%u accepted=%u sequence=%u"
            " PLL_submitted=%" PRIu64 " PLL_raw=%02x"
            " immutable_job=1 guest_ready_write=0 video_completion=0\n",
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), job->generation,
            job->due_ns, job->slave, job->address, job->word, job->fault,
            success, accepted, s->hdmi_phy_pll.sequence,
            s->hdmi_phy_pll.submitted, s->hdmi_phy_pll.raw);
    if (!accepted) {
        error_report("HDMI PLL configuration identity exhausted");
        exit(1);
    }
    z6ii_hdmi_phy_pll_schedule(s);
}

static bool z6ii_hdmi_phy_pll_owns(Z6IIState *s, hwaddr addr)
{
    return s->hdmi_phy_pll_enabled && addr <= UINT32_MAX &&
           z6ii_pll_owns(addr);
}

static bool z6ii_hdmi_phy_pll_access(Z6IIState *s, hwaddr addr,
    unsigned size, bool write, uint64_t *value)
{
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    Z6IIPhyPLLCore trial = s->hdmi_phy_pll;
    Z6IIPhyPLLAccess result = now < 0 ? Z6II_PLL_OVERFLOW :
        z6ii_pll_access(&trial, addr, size, write, value, now,
                       s->hdmi.connected);
    /* Even TIMEOUT jobs have a signed-clock submission contract. Reject
     * before assigning the trial, including before a CONF byte changes. */
    if (result == Z6II_PLL_OK && trial.pending &&
        trial.job.due_ns > INT64_MAX) {
        result = Z6II_PLL_OVERFLOW;
    }
    if (result == Z6II_PLL_OK) { s->hdmi_phy_pll = trial; }
    z6ii_hdmi_phy_pll_trace(s, "mmio", addr, size, write, *value, result, true);
    if (write) { z6ii_hdmi_phy_pll_schedule(s); }
    z6ii_trace(s, addr, size, write, *value);
    return result == Z6II_PLL_OK;
}

static void z6ii_hdmi_phy_pll_commit_configuration_cancel(Z6IIState *s,
    const Z6IIPhyPLLCore *preflight)
{
    timer_del(s->hdmi_phy_pll_timer);
    s->hdmi_phy_pll_timer_generation = 0;
    s->hdmi_phy_pll = *preflight;
    z6ii_hdmi_phy_pll_trace(s, "controller-reset-cancel",
        Z6II_PLL_IH_STAT, 1, false, s->hdmi_phy_pll.raw,
        Z6II_PLL_OK, false);
    /* The lane0 caller next cancels PHY-I2C and updates the shared IRQ.
     * No intermediate source-level notification is published here. */
}

static void z6ii_hdmi_phy_pll_board_reset_state(Z6IIState *s)
{
    timer_del(s->hdmi_phy_pll_timer);
    s->hdmi_phy_pll_timer_generation = 0;
    if (!z6ii_pll_board_reset(&s->hdmi_phy_pll)) {
        error_report("HDMI PLL board-reset identity exhausted");
        exit(1);
    }
    z6ii_hdmi_phy_pll_trace(s, "board-reset-cancel-clear",
        Z6II_PLL_IH_STAT, 1, false, 0, Z6II_PLL_OK, false);
}

static void z6ii_hdmi_phy_pll_init(Z6IIState *s, bool functional)
{
    const char *model = z6ii_engine_getenv(s->engine, "Z6II_HDMI_PHY_PLL_MODEL");
    const char *delay = z6ii_engine_getenv(s->engine, "Z6II_HDMI_PHY_PLL_DELAY_NS");
    const char *fault = z6ii_engine_getenv(s->engine, "Z6II_HDMI_PHY_PLL_FAULT");
    uint64_t ns;
    Z6IIPhyPLLFault kind = Z6II_PLL_LOCK;
    if (!model && !delay && !fault) { return; }
    if (strcmp(s->profile->role, "master")) { return; }
    if (!functional || !s->hdmi_enabled || !s->hdmi_ih_enabled ||
        !s->hdmi_i2c_reset_enabled || !s->hdmi_phy_i2c_enabled ||
        s->hdmi_gic_input != 100 || !model ||
        strcmp(model, "completion-v1") ||
        !z6ii_hdmi_decimal(delay, INT64_MAX, &ns) || !ns) {
        error_report("HDMI PLL requires functional Master, DDC, IH groups,"
                     " SOFTRSTZ and PHY-I2C, PHY_PLL_MODEL=completion-v1"
                     " and explicit positive PHY_PLL_DELAY_NS");
        exit(1);
    }
    if (fault) {
        if (!strcmp(fault, "timeout")) { kind = Z6II_PLL_TIMEOUT; }
        else if (strcmp(fault, "lock")) {
            error_report("HDMI PHY_PLL_FAULT requires lock or timeout");
            exit(1);
        }
    }
    if (!z6ii_pll_init(&s->hdmi_phy_pll, true, ns, kind)) { abort(); }
    s->hdmi_phy_pll_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                       z6ii_hdmi_phy_pll_complete, s);
    s->hdmi_phy_pll_enabled = true;
    fprintf(stderr, "Z6II_HDMI_PHY_PLL_MODEL model=completion-v1"
            " delay_ns=%" PRIu64 " delay_measured=0 fault=%s"
            " six_accepted_configuration_jobs=1 powered_CONF_submission=1"
            " independent_timer=1 signed_deadline_preflight=1"
            " live_status=2016c010 internal_INT=2016c014 internal_mask=2016c018"
            " raw_status=20160410 source_mute=20160610 summary_bit=3"
            " IRQ_owner=single-HDMI-IH-aggregator GPIO_input=100"
            " controller_reset=narrow-cancel-clear board_reset=distinct"
            " rising_lock_only=1 polarity=storage-policy HPD_IRQ=absent"
            " guest_ready_write=0 video_transport=absent\n",
            ns, fault ? fault : "lock");
}
#endif
