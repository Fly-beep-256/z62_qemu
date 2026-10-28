/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Narrow, opt-in functional hypothesis for original slave1008B0F0's
 * configuration transaction. Register fields come from original RMW/BFI
 * instructions; reset values, commit timing and status semantics are not
 * physically measured. There is no sensor, pixel result, IRQ or RAM fixture.
 * config mode retains the original initializer's timeout as a control. */

static void z6ii_slave_pipeline_complete(void *opaque)
{
    Z6IIState *s = opaque;
    if (!s->slave_pipeline_committed || s->slave_pipeline_held) { return; }
    /*1008A42A extracts bits16..21;1008B336 checks decoded byte8==0x11.
     * This is configuration-complete only, never a frame-ready indication. */
    s->slave_pipeline_status58 = 0x00110000;
    fprintf(stderr, "Z6II_SLAVE_PIPELINE_COMPLETE generation=%u status58=%08x "
            "virtual_ns=%" PRId64 " original_status_consumer=1008b336 "
            "physical_semantics_verified=0 frames_generated=0\n",
            s->slave_pipeline_generation, s->slave_pipeline_status58,
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
}

static void z6ii_slave_pipeline_commit(Z6IIState *s, uint32_t control)
{
    if (!s->slave_pipeline_configuration || !(control & 0x10) || s->slave_pipeline_held ||
        !s->slave_pipeline_released || s->slave_pipeline_committed) { return; }
    /* Require native hold/release plus programmed address windows, rather
     * than answering success merely because the driver polled status. */
    /* Original1008B8CE's descriptor[0]==0 branch returns after010/014;
     *020/024 belong to its alternate branch, not this native initializer. */
    const unsigned needed[] = {0x010, 0x014, 0x900, 0x90c,
                               0x910, 0x914, 0x918, 0x91c, 0x8a8};
    for (unsigned i = 0; i < ARRAY_SIZE(needed); i++) {
        if (!s->slave_pipeline_written[needed[i] / 4]) { return; }
    }
    s->slave_pipeline_committed = true;
    s->slave_pipeline_generation++;
    fprintf(stderr, "Z6II_SLAVE_PIPELINE_COMMIT generation=%u completion_enabled=%u "
            "virtual_ns=%" PRId64 " configuration_from_guest=1\n",
            s->slave_pipeline_generation, s->slave_pipeline_completion,
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    if (s->slave_pipeline_completion) {
        timer_mod(s->slave_pipeline_timer,
                  qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 1000000);
    }
}

static bool z6ii_slave_pipeline_access(Z6IIState *s, hwaddr addr,
                                      unsigned size, bool write, uint64_t *value)
{
    if (!s->slave_pipeline_configuration || size != 4) { return false; }
    if (s->slave_pipeline_access_ready_line &&
        ((addr >= 0x2a800000 && addr < 0x2a802000) ||
         (addr >= 0x2a808000 && addr < 0x2a80a000)) && !(addr & 3)) {
        /* Original1008AD3C:2A7F8000+(descriptor[1]<<15)+
         * (descriptor[2]<<12)+offset. Groups1/2, channels0/1. */
        unsigned group = addr >= 0x2a808000;
        unsigned relative = addr - (group ? 0x2a808000 : 0x2a800000);
        unsigned ch = group * 2 + relative / 0x1000;
        unsigned off = relative % 0x1000;
        uint32_t mask;
        switch (off) {
        case 0x004: mask = 0x00000147; break;
        case 0x010: case 0x014: mask = 0xfffffff0; break;
        case 0x03c: mask = 3; break;
        /* Original100C664C configures the remaining host bridge words;
         *100C813C clears70/248. Permit only the native RMW field masks. */
        case 0x070: mask = 3; break;
        case 0x090: mask = 0x00000103; break;
        case 0x0fc: mask = 0x000f0000; break;
        case 0x248: mask = 0xf; break;
        /*100C64C6 packs timing fields1..3/4..6/8..10/12..14;
         *100C6906 stores the clock divider in the upper halfword. */
        case 0x304: case 0x384: mask = 0xffff777e; break;
        /*100C6242 clears the matching descriptor-control word after
         * a native SDHCI software reset. Other operations stay unknown. */
        case 0x354: case 0x3d4:
            if (!write || *value != 0) { return false; }
            mask = 0; break;
        case 0x3e4: case 0x42c: mask = 0x80000000; break;
        case 0x428: mask = 0x8e000000; break;
        case 0x434: mask = 4; break;
        case 0x034: case 0x038: case 0x0d0: case 0x0f0:
        case 0x150: case 0x154: case 0x158: case 0x15c: case 0x300:
            mask = UINT32_MAX; break;
        case 0x064:
            if (write) { return false; }
            /*100C8C12 checks idle bits2/3. An enabled channel with no
             * modeled transaction has empty FIFOs; this never completes
             * data transfer or supplies card/sensor content. */
            *value = (s->slave_bridge_channel_regs[ch][0x004 / 4] & 0x106) == 0x106 ? 0xc : 0;
            fprintf(stderr, "Z6II_SLAVE_BRIDGE_CHANNEL_IDLE ch=%u value=%08" PRIx64
                    " FIFO_idle_hypothesis=1 data_transferred=0\n", ch, *value);
            return true;
        default: return false;
        }
        if (write) {
            if (*value & ~(uint64_t)mask) { return false; }
            s->slave_bridge_channel_regs[ch][off / 4] = *value;
        } else { *value = s->slave_bridge_channel_regs[ch][off / 4]; }
        fprintf(stderr, "Z6II_SLAVE_BRIDGE_CHANNEL_CONFIG %c addr=%08" HWADDR_PRIx
                " value=%08" PRIx64 " original_descriptor_mapping=1 "
                "reset_zero_hypothesis=1 data_transferred=0\n",
                write ? 'W' : 'R', addr, *value);
        return true;
    }
    if (addr == 0x2b000010 && !write && s->slave_pipeline_access_ready_line) {
        /* Original1008BA26 ->10089A16(3) selects input pair2; raw bit10
         * becomes decoded bit8 and enables native bridge accesses. The old
         * disconnected-low donor input makes all those accesses return2.
         * Tying this single line to completed bridge configuration is an
         * explicit, unmeasured connectivity hypothesis, not a RAM ready flag. */
        *value = s->slave_pipeline_status58 == 0x00110000 ? 0x00000400 : 0;
        fprintf(stderr, "Z6II_SLAVE_ACCESS_READY_INPUT value=%08" PRIx64
                " bridge_generation=%u raw_bit=10 connectivity_hypothesis=1 "
                "physical_wiring_verified=0\n", *value, s->slave_pipeline_generation);
        return true;
    }
    if (addr == 0x2b200058 || addr == 0x2b20005c) {
        if (write) { return false; }
        *value = addr == 0x2b200058 ? s->slave_pipeline_status58 : 0;
        fprintf(stderr, "Z6II_SLAVE_PIPELINE_STATUS R addr=%08" HWADDR_PRIx
                " value=%08" PRIx64 " generation=%u committed=%u\n",
                addr, *value, s->slave_pipeline_generation, s->slave_pipeline_committed);
        return true;
    }
    if (addr < 0x2a900000 || addr >= 0x2a901000 || (addr & 3)) { return false; }
    unsigned off = addr - 0x2a900000;
    uint32_t mask;
    switch (off) {
    case 0x004: mask = 0x00000147; break;
    case 0x034: case 0x038: mask = UINT32_MAX; break;
    case 0x03c: mask = 3; break;
    case 0x010: case 0x014: case 0x018: case 0x01c:
    case 0x020: case 0x024: mask = 0xfffffff0; break;
    case 0x050: mask = 0x007f0000; break;
    case 0x078: mask = 0x000ff4ff; break;
    case 0x07c: mask = 0x0003f000; break;
    case 0x080: mask = 0xc0000ff3; break;
    case 0x088: mask = 0x011f1fff; break;
    case 0x08c: mask = 0x0000000f; break;
    case 0x090: mask = 0x00010000; break;
    case 0x098: mask = 0x0000041f; break;
    case 0x0a0: mask = 0x0020ffbf; break;
    case 0x104:
        if (write || !s->slave_pipeline_access_ready_line) { return false; }
        /*1008BA16 queries transaction-error bit14 after supported config
         * accesses. Unknown device transactions still stop at their address. */
        *value = 0;
        return true;
    /* Original100C664C/100C5DBC/100C5D92 configure these bridge words
     * via1008B64A/1008B6D4. Latching is not a transfer completion. */
    case 0x0d0: case 0x0f0: case 0x150: case 0x154: case 0x158: case 0x15c:
    case 0x300: mask = UINT32_MAX; break;
    case 0x168: mask = 0xfffffff0; break;
    case 0x80c: mask = 0x00020000; break;
    case 0x8a8: mask = 0x00ffff00; break;
    case 0x8bc: mask = 1; break;
    case 0x900: mask = 1; break;
    case 0x904: mask = 0x007307ff; break;
    case 0x908: mask = 0xb8d9ffff; break;
    case 0x90c: case 0x910: case 0x914: case 0x918: case 0x91c:
        mask = UINT32_MAX; break;
    default: return false;
    }
    if (write) {
        if (*value & ~(uint64_t)mask) { return false; }
        s->slave_pipeline_regs[off / 4] = *value;
        s->slave_pipeline_written[off / 4] = true;
        if (off == 0x8bc && *value == 1) {
            timer_del(s->slave_pipeline_timer);
            s->slave_pipeline_held = true;
            s->slave_pipeline_released = s->slave_pipeline_committed = false;
            s->slave_pipeline_status58 = 0;
        } else if (off == 0x8bc && s->slave_pipeline_held && *value == 0) {
            s->slave_pipeline_held = false;
            s->slave_pipeline_released = true;
        }
    } else { *value = s->slave_pipeline_regs[off / 4]; }
    fprintf(stderr, "Z6II_SLAVE_PIPELINE_CONFIG %c addr=%08" HWADDR_PRIx
            " value=%08" PRIx64 " guest_config_latched=1 reset_zero_hypothesis=1\n",
            write ? 'W' : 'R', addr, *value);
    return true;
}
