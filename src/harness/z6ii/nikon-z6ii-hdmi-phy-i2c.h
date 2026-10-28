/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Original-ROM PHY-I2C transaction adapter. Its only completion is a
 * latched IH source; the shared HDMI aggregator owns the GIC line.
 * Accepted immutable jobs can configure the separately enabled PLL;
 * I2C DONE is never itself a PLL or video completion. */
#ifndef NIKON_Z6II_HDMI_PHY_I2C_H
#define NIKON_Z6II_HDMI_PHY_I2C_H

static void z6ii_hdmi_phy_i2c_trace(Z6IIState *s, const char *action,
    hwaddr addr, unsigned size, bool write, uint64_t value,
    Z6IIPhyI2CAccess result, bool guest_mmio)
{
    if (result == Z6II_PHY_I2C_OK && !z6ii_hdmi_trace_allowed(s)) { return; }
    CPUState *cpu = guest_mmio ? current_cpu : NULL;
    CPUARMState *env = cpu ? &ARM_CPU(cpu)->env : NULL;
    Z6IIPhyI2CCore *p = &s->hdmi_phy_i2c;
    fprintf(stderr, "Z6II_HDMI_PHY_I2C action=%s now_ns=%" PRId64
            " %c addr=%08" HWADDR_PRIx " size=%u value=%02" PRIx64
            " result=%u pending=%u generation=%" PRIu64
            " job_generation=%" PRIu64 " due_ns=%" PRIu64
            " slave=%02x address=%02x word=%04x status=%02x"
            " submitted=%" PRIu64 " completed=%" PRIu64
            " errors=%" PRIu64 " cancelled=%" PRIu64
            " access_context=%s access_cpu=%d access_pc_valid=%u"
            " access_pc=%08x guest_ready_write=0 PLL_completion=0"
            " video_completion=0\n",
            action, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), write ? 'W' : 'R',
            addr, size, value, result, p->pending, p->generation,
            p->job.generation, p->job.due_ns, p->job.slave, p->job.address,
            p->job.word, p->status, p->submitted, p->completed, p->errors,
            p->cancelled, guest_mmio ? (cpu ? "guest-mmio" : "noncpu-mmio") :
            "timer-no-guest-mmio", cpu ? cpu->cpu_index : -1,
            env != NULL, env ? env->regs[15] : 0);
}

static void z6ii_hdmi_phy_i2c_schedule(Z6IIState *s)
{
    uint64_t due;
    if (z6ii_phy_i2c_next_due(&s->hdmi_phy_i2c, &due)) {
        /* Submission preflight already validated the signed QEMU deadline. */
        assert(due <= INT64_MAX);
        s->hdmi_phy_i2c_timer_generation = s->hdmi_phy_i2c.job.generation;
        timer_mod(s->hdmi_phy_i2c_timer, due);
    } else {
        timer_del(s->hdmi_phy_i2c_timer);
        s->hdmi_phy_i2c_timer_generation = 0;
    }
    z6ii_hdmi_update_irq(s);
}

static void z6ii_hdmi_phy_i2c_complete(void *opaque)
{
    Z6IIState *s = opaque;
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    uint64_t token = s->hdmi_phy_i2c_timer_generation;
    const Z6IIPhyI2CJob job = s->hdmi_phy_i2c.job;
    bool accepted = now >= 0 &&
        z6ii_phy_i2c_complete(&s->hdmi_phy_i2c, token, now);
    if (accepted) { z6ii_hdmi_phy_pll_i2c_completed(s, &job); }
    z6ii_hdmi_phy_i2c_trace(s, accepted ? "complete" : "stale-or-early",
        Z6II_PHY_I2C_STATUS, 1, false, s->hdmi_phy_i2c.status,
        Z6II_PHY_I2C_OK, false);
    z6ii_hdmi_phy_i2c_schedule(s);
}

static bool z6ii_hdmi_phy_i2c_owns(Z6IIState *s, hwaddr addr)
{
    return s->hdmi_phy_i2c_enabled && addr <= UINT32_MAX &&
           z6ii_phy_i2c_owns(addr);
}

static bool z6ii_hdmi_phy_i2c_access(Z6IIState *s, hwaddr addr,
    unsigned size, bool write, uint64_t *value)
{
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    Z6IIPhyI2CAccess result;
    if (now < 0) { return false; }
    /* Reject before committing a job; QEMU timers use a signed clock. */
    if (write && size == 1 && addr == Z6II_PHY_I2C_OPERATION &&
        ((uint64_t)now > (uint64_t)INT64_MAX -
         s->hdmi_phy_i2c.delay_ns)) {
        result = Z6II_PHY_I2C_OVERFLOW;
    } else if (write && size == 1 && addr == Z6II_PHY_I2C_OPERATION &&
               s->hdmi_i2c_reset_enabled &&
               s->hdmi_i2c_reset.lane[0].pending) {
        result = Z6II_PHY_I2C_BUSY;
    } else {
        result = z6ii_phy_i2c_access(&s->hdmi_phy_i2c, addr, size,
                                     write, value, now);
    }
    z6ii_hdmi_phy_i2c_trace(s, "mmio", addr, size, write, *value, result, true);
    if (write) { z6ii_hdmi_phy_i2c_schedule(s); }
    z6ii_trace(s, addr, size, write, *value);
    return result == Z6II_PHY_I2C_OK;
}

static void z6ii_hdmi_phy_i2c_reset_state(Z6IIState *s)
{
    timer_del(s->hdmi_phy_i2c_timer);
    s->hdmi_phy_i2c_timer_generation = 0;
    if (!z6ii_phy_i2c_board_reset(&s->hdmi_phy_i2c)) {
        error_report("HDMI PHY-I2C reset identity exhausted");
        exit(1);
    }
    z6ii_hdmi_phy_i2c_trace(s, "reset-cancel-clear",
        Z6II_PHY_I2C_STATUS, 1, false, 0, Z6II_PHY_I2C_OK, false);
    z6ii_hdmi_update_irq(s);
}

static void z6ii_hdmi_phy_i2c_init(Z6IIState *s, bool functional)
{
    const char *model = getenv("Z6II_HDMI_PHY_I2C_MODEL");
    const char *delay = getenv("Z6II_HDMI_PHY_I2C_DELAY_NS");
    const char *fault = getenv("Z6II_HDMI_PHY_I2C_FAULT");
    uint64_t ns;
    Z6IIPhyI2CFault kind = Z6II_PHY_I2C_FAULT_NONE;
    if (!model && !delay && !fault) { return; }
    if (strcmp(s->profile->role, "master")) { return; }
    if (!functional || !s->hdmi_enabled || !s->hdmi_ih_enabled ||
        !s->hdmi_i2c_reset_enabled || !model ||
        strcmp(model, "transactions-v1") ||
        !z6ii_hdmi_decimal(delay, INT64_MAX, &ns) || !ns) {
        error_report("HDMI PHY-I2C requires a functional Master with DDC,"
                     " IH groups and SOFTRSTZ, PHY_I2C_MODEL=transactions-v1"
                     " and an explicit positive PHY_I2C_DELAY_NS");
        exit(1);
    }
    if (fault) {
        if (!strcmp(fault, "error")) { kind = Z6II_PHY_I2C_FAULT_ERROR; }
        else if (!strcmp(fault, "timeout")) { kind = Z6II_PHY_I2C_FAULT_TIMEOUT; }
        else if (strcmp(fault, "none")) {
            error_report("HDMI PHY_I2C_FAULT requires none, error or timeout");
            exit(1);
        }
    }
    if (!z6ii_phy_i2c_init(&s->hdmi_phy_i2c, ns, kind)) { abort(); }
    s->hdmi_phy_i2c_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                       z6ii_hdmi_phy_i2c_complete, s);
    s->hdmi_phy_i2c_enabled = true;
    fprintf(stderr, "Z6II_HDMI_PHY_I2C_MODEL model=transactions-v1"
            " delay_ns=%" PRIu64 " delay_measured=0 fault=%s"
            " immutable_job=1 source_status=20160420 W1C=1"
            " shared_summary_bit=3 IRQ_owner=HDMI-IH-aggregator"
            " reset_policy=cancel-clear guest_ready_write=0"
            " PLL_completion=0 video_transport=0\n", ns,
            fault ? fault : "none");
}
#endif
