/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Original slave100C5DE8/100C5E0E accesses SDHCI-like host registers at
 * the bases in10169FF4:2A810000/2A811000. Reuse QEMU's real SDHCI state
 * machine, with no card or an explicit fresh, run-local empty card.
 * Vendor reset values and bridge IRQ
 * connectivity are explicit hypotheses, not measured Nikon silicon. */

static void z6ii_slave_storage_update_irq(Z6IIState *s)
{
    /*1008A256 decodes status24 bits28/29 into fields5/6.1008ACBE
     * registers the original bridge ISR on GIC243. The source SDHCI
     * IRQ is already gated by native status/signal enable words34/38;
     * GIC enable is also programmed by the original guest.
     * Experiment16 showed30 is never written before the first CMD0.
     *1008A2C8's packed30/34 fields therefore cannot be assumed to be
     * an additional interrupt enable. Their wider effects are unknown. */
    bool level = (s->slave_storage_irq_pending & 0x30000000) != 0;
    if (s->priv) { qemu_set_irq(qdev_get_gpio_in(DEVICE(s->priv), 243 - 32), level); }
}

static void z6ii_slave_storage_irq(void *opaque, int ch, int level)
{
    Z6IIState *s = opaque;
    if (level && !s->slave_sdhci_irq_level[ch]) {
        s->slave_storage_irq_pending |= 1U << (28 + ch);
    }
    s->slave_sdhci_irq_level[ch] = level;
    z6ii_slave_storage_update_irq(s);
    fprintf(stderr, "Z6II_SLAVE_SDHCI_IRQ host=%d level=%d pending=%08x "
            "native_SDHCI_signal_mask_required=1 gic=243 connectivity_hypothesis=1\n",
            ch, level, s->slave_storage_irq_pending);
}

static bool z6ii_slave_storage_bridge_irq(Z6IIState *s, hwaddr addr,
                                        unsigned size, bool write, uint64_t *value)
{
    if (!s->slave_sdhci_enabled || size != 4) { return false; }
    if (addr == 0x2b200024) {
        if (write) {
            if (*value & ~UINT64_C(0x30010001)) { return false; }
            s->slave_storage_irq_pending &= ~((uint32_t)*value & 0x30000000);
            s->slave_2b20_config[2] = *value & 0x00010001;
        } else { *value = s->slave_2b20_config[2] | s->slave_storage_irq_pending; }
    } else if (addr == 0x2b200030) {
        /* Readback only; these fields are not an inferred IRQ mask. */
        if (write) {
            if (*value & ~UINT64_C(0x11111111)) { return false; }
            s->slave_storage_irq_enable = *value;
        } else { *value = s->slave_storage_irq_enable; }
    } else if (addr == 0x2b200034) {
        /* Native mask's ninth field is unrelated to the two SD hosts. */
        if (write && (*value & ~UINT64_C(0x10))) { return false; }
        if (write) { s->slave_storage_irq_enable9 = *value; }
        else { *value = s->slave_storage_irq_enable9; }
    } else { return false; }
    z6ii_slave_storage_update_irq(s);
    fprintf(stderr, "Z6II_SLAVE_SDHCI_BRIDGE_IRQ %c addr=%08" HWADDR_PRIx
            " value=%08" PRIx64 " pc=%08x native_ack_and_config=1 wiring_hypothesis=1\n",
            write ? 'W' : 'R', addr, *value,
            current_cpu ? ARM_CPU(current_cpu)->env.regs[15] : 0);
    return true;
}

static bool z6ii_slave_storage_access(Z6IIState *s, hwaddr addr, unsigned size,
                                    bool write, uint64_t *value)
{
    if (!s->slave_sdhci_enabled || addr < 0x2a810000 || addr >= 0x2a812000 ||
        (size != 1 && size != 2 && size != 4)) { return false; }
    unsigned ch = (addr - 0x2a810000) / 0x1000;
    unsigned off = (addr - 0x2a810000) % 0x1000;
    if (off == 0xc2 && size == 2) {
        /* Original100C801E..8040 clears low nibbles then writesEE.
         * A vendor configuration latch, without tuning or data effects. */
        if (write && (*value & ~UINT64_C(0xff))) { return false; }
        if (write) { s->slave_sdhci_vendor_c2[ch] = *value; }
        else { *value = s->slave_sdhci_vendor_c2[ch]; }
        fprintf(stderr, "Z6II_SLAVE_SDHCI_VENDOR_CONFIG %c host=%u off=c2 "
                "value=%04" PRIx64 " reset_zero_hypothesis=1 effects_emulated=0\n",
                write ? 'W' : 'R', ch, *value);
        return true;
    }
    if (off == 0xc8 && size == 4) {
        /* Original100C8044 acknowledges all vendor status bits before
         * submitting any command. No modeled vendor status source yet. */
        if (write) { s->slave_sdhci_vendor_status_c8[ch] &= ~(uint32_t)*value; }
        else { *value = s->slave_sdhci_vendor_status_c8[ch]; }
        fprintf(stderr, "Z6II_SLAVE_SDHCI_VENDOR_STATUS %c host=%u off=c8 "
                "value=%08" PRIx64 " ack_hypothesis=1 vendor_status_source=absent\n",
                write ? 'W' : 'R', ch, *value);
        return true;
    }
    if (off + size <= 0x70 || (off >= 0xfc && off + size <= 0x100)) {
        MemTxResult result = write ?
            memory_region_dispatch_write(&s->slave_sdhci[ch]->iomem, off, *value,
                                          size_memop(size), MEMTXATTRS_UNSPECIFIED) :
            memory_region_dispatch_read(&s->slave_sdhci[ch]->iomem, off, value,
                                         size_memop(size), MEMTXATTRS_UNSPECIFIED);
        if (result != MEMTX_OK) { return false; }
        fprintf(stderr, "Z6II_SLAVE_SDHCI %c host=%u off=%03x size=%u value=%08" PRIx64
                " pc=%08x original_driver=1 card=%s model=qemu_sdhci\n",
                write ? 'W' : 'R', ch, off, size, *value,
                current_cpu ? ARM_CPU(current_cpu)->env.regs[15] : 0,
                s->slave_sdhci_formatted_cards ? "run_local_FAT" :
                s->slave_sdhci_virtual_cards ? "run_local_empty" : "absent");
        return true;
    }
    if (!write && size == 4 && !(off & 3) && off >= 0x150 && off <= 0x15c) {
        /*100C66E6..6718 saves these four vendor reset words. Their physical
         * contents are unknown; no card bytes or processing result supplied. */
        *value = 0;
        fprintf(stderr, "Z6II_SLAVE_SDHCI_VENDOR_RESET host=%u off=%03x "
                "value=00000000 reset_zero_hypothesis=1 card_content_supplied=0\n", ch, off);
        return true;
    }
    return false;
}

static void z6ii_slave_storage_init(Z6IIState *s)
{
    if (!s->slave_sdhci_enabled) { return; }
    qemu_irq *irqs = qemu_allocate_irqs(z6ii_slave_storage_irq, s, 2);
    for (unsigned ch = 0; ch < 2; ch++) {
        DeviceState *dev = qdev_new(TYPE_SYSBUS_SDHCI);
        /* SDMA/ADMA descriptors and buffers belong to the slave E6 bus.
         * In the unified machine the global system-memory root is not an
         * E6 address space. Bind before realize, when SDHCI creates its DMA
         * AddressSpace; standalone slave machines use the same owner root. */
        object_property_set_link(OBJECT(dev), "dma", OBJECT(s->engine->memory),
                                 &error_fatal);
        s->slave_sdhci[ch] = SYSBUS_SDHCI(dev);
        sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
        sysbus_connect_irq(SYS_BUS_DEVICE(dev), 0, irqs[ch]);
        if (s->slave_sdhci_virtual_cards) {
            g_autofree char *id = g_strdup_printf("z6ii_slave_sd%u", ch);
            BlockBackend *blk = blk_by_name(id);
            if (!blk) {
                error_report("Virtual-card experiment requires its run-local block backend %s", id);
                exit(1);
            }
            DeviceState *card = qdev_new(TYPE_SD_CARD);
            qdev_prop_set_drive_err(card, "drive", blk, &error_fatal);
            qdev_realize_and_unref(card, BUS(&s->slave_sdhci[ch]->sdbus), &error_fatal);
        }
    }
    fprintf(stderr, "Z6II_SLAVE_SDHCI_PROFILE hosts=2 mode=%s "
            "standard_registers=qemu_sdhci vendor_reset_zero_hypothesis=1 "
            "bridge_irq_wiring_hypothesis=1 physical_semantics_verified=0 "
            "physical_slot_mapping_verified=0 factory_content=absent\n",
            s->slave_sdhci_formatted_cards ? "fat-card" :
            s->slave_sdhci_virtual_cards ? "empty-card" : "no-card");
}
