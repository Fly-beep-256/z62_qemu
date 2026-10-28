/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Functional Z6II link register model, established from original mas
 * 102df730, 102df7e8, 102e0a72..102e11c8. Configuration is restricted to
 * observed addresses. Z6II_LINK_TEST_PEER enables a SCRIPTED peer handshake,
 * not execution of the other EXPEED's firmware or a physical link model.
 * No queue data, service replies, calibration or image samples are invented. */

static void z6ii_link_irq(Z6IIState *s)
{
    qemu_set_irq(qdev_get_gpio_in(DEVICE(s->priv), 127 - 32),
                 (s->link_pending & s->link_mask) != 0);
}

static void z6ii_link_complete(void *opaque)
{
    Z6IIState *s = opaque;
    s->link_pending |= s->link_scheduled;
    if (s->link_scheduled & 2) { s->link_ready = true; }
    if (s->link_scheduled & 0x20) { s->link_gpio = false; }
    fprintf(stderr, "Z6II_LINK_TEST_COMPLETION role=%s status=%08x "
            "latency_ns=1000 scripted_peer=1 other_firmware_executed=0\n",
            s->profile->role, s->link_scheduled);
    s->link_scheduled = 0;
    z6ii_link_irq(s);
}

static void z6ii_link_schedule(Z6IIState *s, uint32_t status)
{
    if (!s->link_test_peer) { return; }
    s->link_scheduled |= status;
    timer_mod(s->link_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 1000);
}

static bool z6ii_link_register(hwaddr addr)
{
    if (addr < 0x20130000 || addr >= 0x20140000 || (addr & 3)) {
        return false;
    }
    uint32_t off = (addr - 0x20130000) & 0x7fff;
    /* 102df7e8: four lanes at+400, then second bank at+8000. */
    static const uint16_t lane[] = {
        0x84, 0x88, 0x8c, 0x90, 0x98, 0x9c, 0xa0, 0xa4, 0xa8, 0xac,
        0xb0, 0xb4, 0xbc, 0xcc, 0xdc, 0xe0, 0xe4,
        0x284, 0x288, 0x28c, 0x290, 0x29c,
    };
    if (off < 0x1000) {
        uint32_t reg = off & 0x3ff;
        for (unsigned n = 0; n < ARRAY_SIZE(lane); n++) {
            if (reg == lane[n]) { return true; }
        }
    }
    switch (off) {
    case 0x1c8: case 0x1cc: case 0x1ec:
    case 0x4104: case 0x4120: case 0x4124: case 0x4128:
    case 0x412c: case 0x4130: case 0x4134: case 0x413c: case 0x4140:
    case 0x4400: case 0x4504: case 0x450c: case 0x4520:
    case 0x45f0: case 0x45fc: case 0x4904: case 0x490c: case 0x4910:
    case 0x5004: case 0x504c:
        return true;
    default: return false;
    }
}

static bool z6ii_link_access(Z6IIState *s, hwaddr addr, unsigned size,
                             bool write, uint64_t *value)
{
    if ((!s->devices && !s->coupled_link_configuration) || size != 4 || (addr & 3)) { return false; }
    if (s->coupled_notifications && addr >= 0x2013d020 && addr <= 0x2013d028) {
        /* Coupled event status/mask/ack belongs to the shared-bank model,
         * rather than this older local/scripted status implementation. */
        return false;
    }
    if (!write && z6ii_coupled_lane_status(s, addr, value)) {
        z6ii_trace(s, addr, size, write, *value);
        return true;
    }
    if (addr == 0x04282018 && !write && s->link_test_peer) {
        /* Runtime-confirmed GPIO object C180399C: ID60, bit3, port04282018.
         * Preserve the other original pin configuration bits. */
        *value = (s->config[0x2018 / 4] & ~8U) | (s->link_gpio ? 8 : 0);
    } else if (addr == 0x2013d020 && !write) {
        *value = s->link_pending;
    } else if (addr == 0x2013d024) {
        if (write) {
            if (*value & ~UINT64_C(0xffff)) { return false; }
            s->link_mask = *value;
            z6ii_link_irq(s);
        } else { *value = s->link_mask; }
    } else if (addr == 0x2013d028 && write) {
        /* Original102df736..73a acknowledges the complete status word. */
        s->link_pending &= ~*value;
        z6ii_link_irq(s);
    } else if (addr == 0x20134908 && !write && s->coupled_phy) {
        /* Only the original startup consumer's bit0 is modeled. Other PHY
         * status, stopping/recovery and physical lane behavior remain absent. */
        *value = qatomic_load_acquire(&s->shared_event_words[Z6II_LINK_READY + z6ii_link_slot(s)]) ? 1 : 0;
    } else if (addr == 0x20134908 && !write && s->link_test_peer) {
        *value = s->link_ready ? 1 : 0;
    } else if (addr == 0x2013c908 && !write && s->link_test_peer) {
        *value = s->link_ready ? 4 : 0;
    } else if (addr == 0x2013c90c && write && (*value == 4 || *value == 6)) {
        /* Completion trigger is an explicit functional peer hypothesis.
         * The original ISR, not the model, sets the native RTOS event. */
        s->link_regs[(addr - 0x20130000) / 4] = *value;
        z6ii_link_schedule(s, 2);
    } else if (addr == 0x2013c5e0 && write && (*value == 0 || *value == 0xf000f)) {
        s->link_regs[(addr - 0x20130000) / 4] = *value;
    } else if ((addr == 0x2013c5f4 || addr == 0x2013c5f8) && write &&
               (*value == 0x1b || *value == 0xe4)) {
        s->link_regs[(addr - 0x20130000) / 4] = *value;
    } else if (s->link_test_peer && !write && addr >= 0x20138104 &&
               addr <= 0x20138f04 &&
               (((addr - 0x20138104) & 0x3ff) == 0 ||
                ((addr - 0x20138304) & 0x3ff) == 0)) {
        if (!s->link_stop_command) { return false; }
        *value = 3;
    } else if (z6ii_link_register(addr)) {
        unsigned index = (addr - 0x20130000) / 4;
        uint32_t off = (addr - 0x20130000) & 0x7fff;
        if (write) {
            s->link_regs[index] = *value;
            s->link_written[index] = true;
            if (addr == 0x2013c128 && *value == 0xf00f) {
                s->link_gpio = true;
                if (!strcmp(s->profile->role, "slave")) { z6ii_link_schedule(s, 1); }
            } else if (off == 0x4128) {
                s->link_stop_command = true;
            } else if (off == 0x413c && *value == 2) {
                z6ii_link_schedule(s, 0x20);
            }
        } else {
            if (!s->link_written[index]) { return false; }
            *value = s->link_regs[index];
        }
    } else { return false; }
    if (write) { z6ii_coupled_phy_command(s, addr, *value); }
    z6ii_trace(s, addr, size, write, *value);
    return true;
}
