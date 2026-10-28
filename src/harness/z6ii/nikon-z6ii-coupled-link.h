/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Explicit V3 interconnect hypotheses. Original code proves the GPIO data
 * command format and IRQ/RTOS consumers. Slave pin10 -> master pin3 and the
 * two-ended PHY startup below are functional hypotheses, not measured wires,
 * recovered PHY microcode or cycle-accurate EXPEED hardware. No scripted
 * single-ended success, guest RTOS writes, persistent data or image samples. */
enum {
    Z6II_LINK_GPIO_DATA = 4,       /* local writers only, master/slave */
    Z6II_LINK_GPIO_KNOWN = 8,
    Z6II_LINK_CONFIGURED = 12,     /* original C128 command F00F */
    Z6II_LINK_START_COMMAND = 16,  /* original master 6 / slave 4 */
    Z6II_LINK_STATUS = 18,        /* each guest produces/acks its own status */
    Z6II_LINK_READY = 20,
    Z6II_LINK_STOP_GENERATION = 22, /* master writes only; peer observes */
    Z6II_LINK_STOP_ACK = 24,        /* original ISR writes hardware ack */
};

static unsigned z6ii_link_slot(Z6IIState *s)
{
    return !strcmp(s->profile->role, "slave");
}

static bool z6ii_candidate_gpio_high(Z6IIState *s)
{
    return s->gpio_connection &&
        (qatomic_load_acquire(&s->shared_event_words[Z6II_LINK_GPIO_KNOWN + 1]) & 0x400) &&
        (qatomic_read(&s->shared_event_words[Z6II_LINK_GPIO_DATA + 1]) & 0x400);
}

static bool z6ii_coupled_gpio_access(Z6IIState *s, hwaddr addr, unsigned size,
                                    bool write, uint64_t *value)
{
    /* Only the DATA ports are proven to use upper16 write-enable. Direction,
     * pull/configuration ports are separate and retain their previous model. */
    if (!s->coupled_gpio || size != 4 || (addr & 3) ||
        addr < 0x04282000 || addr > 0x0428202c) { return false; }
    unsigned index = (addr - 0x04280000) / 4;
    unsigned pinbank = (addr - 0x04282000) / 4;
    unsigned local = z6ii_link_slot(s);
    if (write) {
        uint32_t enable = (*value >> 16) & 0xffff;
        uint32_t before = s->config[index] & 0xffff;
        s->config[index] = (before & ~enable) | ((uint32_t)*value & enable);
        z6ii_exmcu_gpio_output(s, addr, before, s->config[index], enable);
        s->coupled_gpio_known[pinbank] |= enable;
        s->config_written[index] = true;
        hwaddr signal_port = local ? 0x04282020 : 0x04282018;
        if (addr == signal_port) {
            qatomic_set(&s->shared_event_words[Z6II_LINK_GPIO_DATA + local], s->config[index]);
            qatomic_store_release(&s->shared_event_words[Z6II_LINK_GPIO_KNOWN + local],
                                  s->coupled_gpio_known[pinbank]);
        }
        fprintf(stderr, "Z6II_GPIO_MASKED_WRITE role=%s addr=%08" HWADDR_PRIx
                " command=%08" PRIx64 " enable=%04x before=%04x after=%04x "
                "physical_pin_state_measured=0\n", s->profile->role, addr, *value,
                enable, before, s->config[index]);
    } else {
        if (!s->config_written[index]) { return false; }
        *value = s->config[index] & 0xffff;
        if (s->gpio_connection && !local && addr == 0x04282018) {
            uint32_t known = qatomic_load_acquire(&s->shared_event_words[Z6II_LINK_GPIO_KNOWN + 1]);
            uint32_t peer = qatomic_read(&s->shared_event_words[Z6II_LINK_GPIO_DATA + 1]);
            if (known & 0x400) {
                *value = (*value & ~UINT64_C(8)) | ((peer & 0x400) ? 8 : 0);
            }
            if (!s->coupled_gpio_read_seen || *value != s->coupled_gpio_last_read) {
                fprintf(stderr, "Z6II_GPIO_CANDIDATE_INPUT role=master addr=04282018 "
                        "value=%08" PRIx64 " source=slave:04282020:10 target_pin=3 "
                        "source_known=%u connection_hypothesis=1 physical_connection_verified=0\n",
                        *value, !!(known & 0x400));
                s->coupled_gpio_read_seen = true;
                s->coupled_gpio_last_read = *value;
            }
        }
    }
    if (!write) { z6ii_exmcu_gpio_inputs(s, addr, value); }
    z6ii_trace(s, addr, size, write, *value);
    return true;
}

static void z6ii_coupled_phy_emit(Z6IIState *s, uint32_t status, const char *reason)
{
    unsigned local = z6ii_link_slot(s);
    qatomic_fetch_or(&s->shared_event_words[Z6II_LINK_STATUS + local], status);
    fprintf(stderr, "Z6II_COUPLED_PHY_EVENT role=%s status=%08x reason=%s "
            "master_command=%u slave_command=%u candidate_gpio_high=%u "
            "functional_two_ended_hypothesis=1 physical_protocol_verified=0 "
            "virtual_ns=%" PRId64 "\n", s->profile->role, status, reason,
            qatomic_read(&s->shared_event_words[Z6II_LINK_START_COMMAND]),
            qatomic_read(&s->shared_event_words[Z6II_LINK_START_COMMAND + 1]),
            z6ii_candidate_gpio_high(s), qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
}

static void z6ii_coupled_phy_step(Z6IIState *s)
{
    if (!s->coupled_phy) { return; }
    unsigned local = z6ii_link_slot(s);
    bool configured = qatomic_read(&s->shared_event_words[Z6II_LINK_CONFIGURED]) &&
                      qatomic_read(&s->shared_event_words[Z6II_LINK_CONFIGURED + 1]);
    uint32_t stop = qatomic_load_acquire(&s->shared_event_words[Z6II_LINK_STOP_GENERATION]);
    if (s->coupled_stop && configured && stop != s->coupled_stop_seen &&
        qatomic_load_acquire(&s->shared_event_words[Z6II_LINK_READY]) &&
        qatomic_load_acquire(&s->shared_event_words[Z6II_LINK_READY + 1])) {
        s->coupled_stop_seen = stop;
        z6ii_coupled_phy_emit(s, 0x20, "native_master_bank1_stop_command_after_both_ready");
    }
    uint32_t master = qatomic_read(&s->shared_event_words[Z6II_LINK_START_COMMAND]);
    uint32_t slave = qatomic_read(&s->shared_event_words[Z6II_LINK_START_COMMAND + 1]);
    if (!configured || !z6ii_candidate_gpio_high(s) || master != 6) { return; }
    /* The slave's original wait(flag1) must be satisfied before its native
     * command4. No event is produced merely by local configuration. */
    if (local && !s->coupled_phy_request_seen) {
        s->coupled_phy_request_seen = true;
        z6ii_coupled_phy_emit(s, 1, "peer_master_request_after_both_configured");
    }
    if (slave == 4 && !s->coupled_phy_complete_seen) {
        s->coupled_phy_complete_seen = true;
        qatomic_store_release(&s->shared_event_words[Z6II_LINK_READY + local], 1);
        z6ii_coupled_phy_emit(s, 2, "both_original_start_commands");
    }
}

static void z6ii_coupled_phy_command(Z6IIState *s, hwaddr addr, uint64_t value)
{
    if (!s->coupled_phy) { return; }
    unsigned local = z6ii_link_slot(s);
    if (addr == 0x2013c128 && value == 0xf00f) {
        qatomic_set(&s->shared_event_words[Z6II_LINK_CONFIGURED + local], 1);
    } else if (addr == 0x2013c90c && (value == 4 || value == 6)) {
        qatomic_set(&s->shared_event_words[Z6II_LINK_START_COMMAND + local], (uint32_t)value);
    } else if (s->coupled_stop && !local && addr == 0x2013c13c && value == 2) {
        /* Original102e112a calls bank writer(mode2): base2013413c +8000.
         * Each original command is a new diagnostic stop generation. Lane
         * idle/status, stopped PHY and recovery are deliberately unmodeled. */
        qatomic_fetch_add(&s->shared_event_words[Z6II_LINK_STOP_GENERATION], 1);
        fprintf(stderr, "Z6II_COUPLED_STOP_COMMAND role=master addr=2013c13c value=2 "
                "native_bank_writer=102e11a0 notification_hypothesis=1 unconditional_lane_idle=0\n");
    }
    if (s->coupled_lanes && (addr == 0x20134128 || addr == 0x2013c128)) {
        unsigned bank = addr == 0x2013c128;
        s->coupled_lane_generation[bank] = qatomic_load_acquire(&s->shared_event_words[Z6II_LINK_STOP_GENERATION]);
    }
    z6ii_coupled_phy_step(s);
}

static bool z6ii_coupled_lane_status(Z6IIState *s, hwaddr addr, uint64_t *value)
{
    if (!s->coupled_lanes || addr < 0x20138104 || addr > 0x20138f04) { return false; }
    uint32_t offset = addr - 0x20138104;
    unsigned lane = offset / 0x400, channel = (offset & 0x3ff) / 0x200;
    if ((offset & 0x3ff) != 0 && (offset & 0x3ff) != 0x200) { return false; }
    /* Original102e108c packs inbound lanes in low4, outbound in bits12..15,
     * then waits for the selected bank1 lane to equal3. Report no idle before
     * a lane-select command issued in an actual stop generation. */
    unsigned reg = 0xc128 / 4;
    uint32_t generation = s->coupled_lane_generation[1];
    if (!generation || !s->link_written[reg] ||
        !(s->link_regs[reg] & (1U << (lane + 12 * channel)))) { return false; }
    bool acknowledged = qatomic_load_acquire(&s->shared_event_words[Z6II_LINK_STOP_ACK]) == generation &&
                        qatomic_load_acquire(&s->shared_event_words[Z6II_LINK_STOP_ACK + 1]) == generation;
    uint32_t known = qatomic_load_acquire(&s->shared_event_words[Z6II_LINK_GPIO_KNOWN + 1]);
    uint32_t pins = qatomic_read(&s->shared_event_words[Z6II_LINK_GPIO_DATA + 1]);
    *value = acknowledged && (known & 0x400) && !(pins & 0x400) ? 3 : 0;
    unsigned record = 2 * lane + channel;
    if (s->coupled_lane_reported[record] != *value + 1) {
        fprintf(stderr, "Z6II_COUPLED_LANE_STATUS role=%s addr=%08" HWADDR_PRIx
                " lane=%u channel=%u value=%" PRIu64 " generation=%u both_native_ISR_acked=%u "
                "slave_pin10_low=%u functional_idle_hypothesis=1 physical_idle_verified=0\n",
                s->profile->role, addr, lane, channel, *value, generation, acknowledged,
                !!(known & 0x400) && !(pins & 0x400));
        s->coupled_lane_reported[record] = *value + 1;
    }
    return true;
}

static uint32_t z6ii_coupled_status(Z6IIState *s)
{
    unsigned local = z6ii_link_slot(s);
    uint32_t queue = qatomic_read(&s->shared_event_words[local ^ 1]) ? 0x8000 : 0;
    return queue | (s->coupled_phy ? qatomic_read(&s->shared_event_words[Z6II_LINK_STATUS + local]) : 0);
}
