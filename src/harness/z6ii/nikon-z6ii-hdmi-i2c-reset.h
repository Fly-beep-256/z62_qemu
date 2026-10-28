/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Private QEMU adapter candidate. Include after Z6IIState. The release delay
 * is an explicit policy, not measured Nikon timing. No interrupt is emitted.
 * PHY reset explicitly cancels its job and clears its audit bank. Concurrent
 * DDC reset retains the previously verified rejection policy. */
#ifndef NIKON_Z6II_HDMI_I2C_RESET_H
#define NIKON_Z6II_HDMI_I2C_RESET_H

static bool z6ii_hdmi_i2c_reset_owns(Z6IIState *s, hwaddr addr)
{
    return s->hdmi_i2c_reset_enabled && addr <= UINT32_MAX &&
           z6ii_hdmi_i2c_reset_lane(addr) >= 0;
}

static void z6ii_hdmi_i2c_reset_timer_complete(Z6IIState *s, unsigned lane)
{
    uint64_t generation = s->hdmi_i2c_reset_timer_generation[lane];
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    bool accepted = now >= 0 && z6ii_hdmi_i2c_reset_complete(
        &s->hdmi_i2c_reset, lane, generation, now);
    Z6IIHDMIResetLane *r = &s->hdmi_i2c_reset.lane[lane];
    fprintf(stderr, "Z6II_HDMI_I2C_RESET_EVENT lane=%u now_ns=%" PRId64
            " captured_generation=%" PRIu64 " generation=%" PRIu64
            " accepted=%u value=%u pending=%u context=virtual-timer"
            " guest_mmio=0 IRQ=0 guest_ready_write=0 video_completion=0\n",
            lane, now, generation, r->generation, accepted, r->value,
            r->pending);
}

static void z6ii_hdmi_i2c_reset_phy_complete(void *opaque)
{
    z6ii_hdmi_i2c_reset_timer_complete(opaque, 0);
}

static void z6ii_hdmi_i2c_reset_ddc_complete(void *opaque)
{
    z6ii_hdmi_i2c_reset_timer_complete(opaque, 1);
}

static bool z6ii_hdmi_i2c_reset_qemu_access(Z6IIState *s, hwaddr addr,
    unsigned size, bool write, uint64_t *value)
{
    int lane = z6ii_hdmi_i2c_reset_lane(addr);
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    Z6IIHDMIResetAccess result;
    if (lane < 0 || now < 0) { return false; }
    /* Startup reset is proved, resetting an in-flight DDC job is not. Reject
     * that boundary instead of releasing a reset over stale FIFO/status. */
    if (write && lane == 1 && s->hdmi_enabled &&
        (s->hdmi.job != Z6II_HDMI_JOB_NONE || s->hdmi.fifo_valid ||
         z6ii_hdmi_core_irq_pending(&s->hdmi))) {
        fprintf(stderr, "Z6II_HDMI_I2C_RESET_REJECT lane=1 reason=active-DDC"
                " IRQ=0 guest_ready_write=0\n");
        return false;
    }
    if (write && ((uint64_t)now > INT64_MAX - s->hdmi_i2c_reset.delay_ns)) {
        return false;
    }
    if (write && lane == 0 && s->hdmi_phy_i2c_enabled &&
        (s->hdmi_phy_i2c.generation == UINT64_MAX ||
         (s->hdmi_phy_i2c.pending &&
          s->hdmi_phy_i2c.cancelled == UINT64_MAX))) {
        return false;
    }
    Z6IIPhyPLLCore pll_trial = s->hdmi_phy_pll;
    bool pll_cancel = write && lane == 0 && s->hdmi_phy_pll_enabled;
    if (pll_cancel && !z6ii_pll_configuration_cancel(&pll_trial, true)) {
        return false;
    }
    result = z6ii_hdmi_i2c_reset_access(&s->hdmi_i2c_reset,
                                      addr, size, write, value, now);
    if (result != Z6II_HDMI_I2C_RESET_OK) { return false; }
    Z6IIHDMIResetLane *r = &s->hdmi_i2c_reset.lane[lane];
    if (write) {
        if (pll_cancel) {
            z6ii_hdmi_phy_pll_commit_configuration_cancel(s, &pll_trial);
        }
        if (lane == 0 && s->hdmi_phy_i2c_enabled) {
            z6ii_hdmi_phy_i2c_reset_state(s);
        }
        if (pll_cancel) { z6ii_hdmi_phy_pll_schedule(s); }
        s->hdmi_i2c_reset_timer_generation[lane] = r->generation;
        timer_mod(s->hdmi_i2c_reset_timer[lane], r->due_ns);
        CPUState *cpu = current_cpu;
        CPUARMState *env = cpu ? &ARM_CPU(cpu)->env : NULL;
        fprintf(stderr, "Z6II_HDMI_I2C_RESET_SUBMIT lane=%d now_ns=%" PRId64
                " generation=%" PRIu64 " deadline_ns=%" PRIu64
                " size=%u value=%" PRIu64 " guest_pc_valid=%u pc=%08x"
                " context=%s latency_measured=0 IRQ=0 guest_ready_write=0\n",
                lane, now, r->generation, r->due_ns, size, *value,
                env != NULL, env ? env->regs[15] : 0,
                env ? "guest-mmio" : "noncpu-mmio");
    }
    z6ii_trace(s, addr, size, write, *value);
    return true;
}

static void z6ii_hdmi_i2c_reset_board(void *opaque)
{
    Z6IIState *s = opaque;
    for (unsigned i = 0; i < Z6II_HDMI_I2C_RESET_LANES; ++i) {
        timer_del(s->hdmi_i2c_reset_timer[i]);
        s->hdmi_i2c_reset_timer_generation[i] = 0;
    }
    if (!z6ii_hdmi_i2c_reset_cancel_all(&s->hdmi_i2c_reset)) {
        error_report("HDMI I2C reset generation identity exhausted");
        exit(1);
    }
}

static void z6ii_hdmi_i2c_reset_qemu_init(Z6IIState *s, bool functional)
{
    const char *model = getenv("Z6II_HDMI_I2C_RESET_MODEL");
    const char *delay = getenv("Z6II_HDMI_I2C_RESET_DELAY_NS");
    uint64_t ns = 0;
    if (!model && !delay) { return; }
    if (strcmp(s->profile->role, "master")) { return; }
    if (!functional || !model || strcmp(model, "softrstz-v1") ||
        !z6ii_hdmi_decimal(delay, INT64_MAX, &ns) || !ns) {
        error_report("HDMI I2C reset requires a functional Master, "
                     "Z6II_HDMI_I2C_RESET_MODEL=softrstz-v1 and explicit "
                     "positive decimal Z6II_HDMI_I2C_RESET_DELAY_NS");
        exit(1);
    }
    if (!z6ii_hdmi_i2c_reset_init(&s->hdmi_i2c_reset, ns)) { abort(); }
    s->hdmi_i2c_reset_timer[0] = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                           z6ii_hdmi_i2c_reset_phy_complete, s);
    s->hdmi_i2c_reset_timer[1] = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                           z6ii_hdmi_i2c_reset_ddc_complete, s);
    s->hdmi_i2c_reset_enabled = true;
    qemu_register_reset(z6ii_hdmi_i2c_reset_board, s);
    fprintf(stderr, "Z6II_HDMI_I2C_RESET_MODEL model=softrstz-v1"
            " PHY_addr=2016c0a8 DDC_addr=2017f824 byte_only=1"
            " write0_reset=1 release_value=1 delay_ns=%" PRIu64
            " delay_measured=0 initial_value_hypothesis=0"
            " concurrent_DDC_reset_supported=0 IRQ=0 video_transport=0\n", ns);
}
#endif
