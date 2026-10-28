/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef EX1850_SPI2_DMA_BOARD_H
#define EX1850_SPI2_DMA_BOARD_H

static void ex1850_spi2_schedule(EX1850ResetState *s)
{
    if (s->spi2_event) {
        timer_del(s->spi2_event);
        int64_t due = ex1850_spi2_deadline(&s->spi2_dma);
        if (due >= 0) { timer_mod(s->spi2_event, due); }
    }
    bool irq15 = ex1850_spi2_irq15(&s->spi2_dma);
    bool irq36 = ex1850_spi2_irq36(&s->spi2_dma);
    bool irq16 = ex1850_dma1_irq16(&s->spi2_dma);
    if (s->armv7m) {
        qemu_set_irq(qdev_get_gpio_in(DEVICE(s->armv7m), 15), irq15);
        qemu_set_irq(qdev_get_gpio_in(DEVICE(s->armv7m), 36), irq36);
        qemu_set_irq(qdev_get_gpio_in(DEVICE(s->armv7m), 16), irq16);
    }
    if (irq15 != s->spi2_irq15_level || irq36 != s->spi2_irq36_level) {
        fprintf(stderr, "EX1850_SPI2_IRQ IRQ15=%u IRQ36=%u HISR=%08x SR=%08x "
                "DMA_CR=%08x CR2=%08x virtual_ns=%" PRId64
                " source=device_flags_and_original_interrupt_enables\n",
                irq15, irq36, s->spi2_dma.hisr, s->spi2_dma.sr,
                s->spi2_dma.dma1[4].cr, s->spi2_dma.cr2,
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    }
    s->spi2_irq15_level = irq15;
    s->spi2_irq36_level = irq36;
    if (irq16 != s->dma1_irq16_level) {
        fprintf(stderr, "EX1850_DMA1_IRQ IRQ16=%u HISR=%08x S5_CR=%08x "
                "S5_NDTR=%u virtual_ns=%" PRId64
                " source=stream5_flags_and_interrupt_enables RX_supplied=0\n",
                irq16, s->spi2_dma.hisr, s->spi2_dma.dma1[5].cr,
                s->spi2_dma.dma1[5].ndtr, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    }
    s->dma1_irq16_level = irq16;
}

static bool ex1850_spi2_read_byte(void *opaque, uint32_t address, uint8_t *byte)
{
    EX1850ResetState *s = opaque;
    if (address < EX1850_RAM_BASE ||
        address >= (uint64_t)EX1850_RAM_BASE + EX1850_RAM_BYTES) { return false; }
    const uint8_t *ram = memory_region_get_ram_ptr(&s->ram);
    *byte = ram[address - EX1850_RAM_BASE];
    return true;
}

static void ex1850_spi2_observe(void *opaque, EX1850SPI2Event event,
                              int64_t now, uint32_t address, uint8_t byte)
{
    EX1850ResetState *s = opaque;
    static const char *names[] = {"DMA_ACCEPT", "BUFFER_TO_SHIFT", "SHIFT_COMPLETE"};
    ex1850_sampled_log("EX1850_SPI2_EVENT event=%s source_address=%08x MOSI=%02x "
            "NDTR=%u DMA_EN=%u TXE=%u BSY=%u RXNE=%u OVR=%u HISR=%08x "
            "accepted_total=%" PRIu64 " shifted_total=%" PRIu64
            " virtual_ns=%" PRId64
            " MISO_payload_known=0 receive_token=unknown guest_memory_written=0\n",
            names[event], address, byte, s->spi2_dma.dma1[4].ndtr,
            s->spi2_dma.dma1[4].cr & 1, !!(s->spi2_dma.sr & EX1850_SPI2_TXE),
            !!(s->spi2_dma.sr & EX1850_SPI2_BSY),
            !!(s->spi2_dma.sr & EX1850_SPI2_RXNE),
            !!(s->spi2_dma.sr & EX1850_SPI2_OVR), s->spi2_dma.hisr,
            s->spi2_dma.accepted_total, s->spi2_dma.shifted_total, now);
}

static void ex1850_spi2_sync(EX1850ResetState *s)
{
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    if (s->spi2_dma.epoch < 0 || now < s->spi2_dma.epoch) {
        fprintf(stderr, "EX1850_VIRTUAL_TIME_BOUNDARY previous_ns=%" PRId64
                " virtual_ns=%" PRId64 " pc=%08x "
                "DMA_memory_access_attempted=0 time_clamped=0\n",
                s->spi2_dma.epoch, now, ex1850_pc());
        ex1850_capture_boundary(s);
        exit(66);
    }
    if (!ex1850_spi2_advance(&s->spi2_dma,
            now, ex1850_spi2_read_byte,
            ex1850_spi2_observe, s)) {
        fprintf(stderr, "EX1850_SPI2_DMA_MEMORY_BOUNDARY address=%08x NDTR=%u "
                "byte_not_accepted=1 pc=%08x\n", s->spi2_dma.dma_address,
                s->spi2_dma.dma1[4].ndtr, ex1850_pc());
        ex1850_unknown_access(s, s->spi2_dma.dma_address, 1, false, 0);
    }
    ex1850_spi2_schedule(s);
}

/* Invoke after syncing with the old clock and then changing RCC state. */
static void ex1850_spi2_clocks_changed(EX1850ResetState *s)
{
    unsigned ppre = (s->cfgr >> 10) & 7;
    unsigned pclk = ppre < 4 ? s->cpu_hz : s->cpu_hz >> (ppre - 3);
    g_assert(ex1850_spi2_set_clocks(&s->spi2_dma, s->cpu_hz, pclk,
        (s->ahb1enr & (1U << 21)) && !(s->rcc_ahb1rstr & (1U << 21)),
        !!(s->apb1enr & (1U << 14)), !!(s->rcc_apb1rstr & (1U << 14))));
    ex1850_spi2_schedule(s);
}

static void ex1850_spi2_event(void *opaque)
{
    ex1850_spi2_sync(opaque);
}

static bool ex1850_spi2_instruction_pc(uint32_t *pc)
{
    uint64_t data[1 + TARGET_INSN_START_EXTRA_WORDS];

    /* io_prepare records the host return address for this MMIO instruction.
     * env.regs[15] alone can still identify the first instruction of the TB.
     * Match arm_restore_state_to_opc's PC reconstruction, but only read the
     * unwind data: restoring CPU state here would also disturb icount/state.
     */
    if (!current_cpu ||
        !cpu_unwind_state_data(current_cpu, current_cpu->mem_io_pc, data)) {
        return false;
    }
    *pc = (curr_cflags(current_cpu) & CF_PCREL)
        ? (ex1850_pc() & TARGET_PAGE_MASK) | (uint32_t)data[0]
        : (uint32_t)data[0];
    return true;
}

static bool ex1850_spi2_discard_proven(EX1850ResetState *s, unsigned size)
{
    /* Original 08049646: LDR r2,[r0,#12]; LDR r0,[r0,#8]; STR r0,[sp].
     * The full original TX-complete body establishes that r2's read value
     * is discarded. Verify both the pinned instruction bytes and runtime
     * base register; this is not a generic SPI payload/ready-value fixture.
     */
    static const uint8_t instructions[] = {0xc2, 0x68, 0x80, 0x68, 0x00, 0x90};
    uint32_t instruction_pc;
    return size == 4 && ex1850_spi2_instruction_pc(&instruction_pc) &&
        instruction_pc == 0x08049646 &&
        ARM_CPU(current_cpu)->env.regs[0] == 0x40003800 &&
        !memcmp((uint8_t *)memory_region_get_ram_ptr(&s->rom) + 0x49646,
                instructions, sizeof(instructions));
}

static bool ex1850_spi2_board_access(EX1850ResetState *s, hwaddr addr,
                                    unsigned size, bool write, uint64_t *value)
{
    if (addr < 0x40003800 || addr >= 0x40003824) { return false; }
    if (size != 4 || (addr & 3) || *value > UINT32_MAX) {
        ex1850_unknown_access(s, addr, size, write, *value);
    }
    uint32_t v = *value;
    bool discard = !write && addr == 0x4000380c && ex1850_spi2_discard_proven(s, size);
    if (discard && ex1850_pc() != 0x08049646) {
        ex1850_sampled_log("EX1850_SPI2_DISCARD_SITE cached_pc=%08x "
                "instruction_pc=08049646 source=read_only_TCG_unwind "
                "ROM_and_runtime_base_verified=1 CPU_state_modified=0 "
                "MISO_payload_supplied=0\n", ex1850_pc());
    }
    if (!ex1850_spi2_access(&s->spi2_dma, addr - 0x40003800, write, discard, &v)) {
        fprintf(stderr, "EX1850_SPI2_BOUNDARY addr=%08" HWADDR_PRIx
                " write=%u CR1=%08x CR2=%08x SR=%08x receive_token_unknown=%u "
                "discard_proven=%u pc=%08x\n", addr, write, s->spi2_dma.cr1,
                s->spi2_dma.cr2, s->spi2_dma.sr, s->spi2_dma.rx_unknown,
                discard, ex1850_pc());
        ex1850_unknown_access(s, addr, size, write, *value);
    }
    *value = v;
    ex1850_spi2_schedule(s);
    ex1850_sampled_log("EX1850_SPI2_CONTROL_%c addr=%08" HWADDR_PRIx
            " value=%08x CR1=%08x CR2=%08x SR=%08x pc=%08x "
            "virtual_ns=%" PRId64
            " DR_discard_representative=%u MISO_payload_supplied=0\n",
            write ? 'W' : 'R', addr, v, s->spi2_dma.cr1, s->spi2_dma.cr2,
            s->spi2_dma.sr, ex1850_pc(), qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
            discard && s->spi2_dma.rx_unknown);
    return true;
}

static bool ex1850_dma1_access(EX1850ResetState *s, hwaddr addr,
                              unsigned size, bool write, uint64_t *value)
{
    if (addr < 0x40026000 || addr >= 0x400260d0) { return false; }
    if (size != 4 || (addr & 3) || *value > UINT32_MAX) {
        ex1850_unknown_access(s, addr, size, write, *value);
    }
    uint32_t requested = *value, v = *value, offset = addr - 0x40026000;
    if (!ex1850_spi2_dma_access(&s->spi2_dma, offset, write, &v)) {
        fprintf(stderr, "EX1850_DMA1_BOUNDARY addr=%08" HWADDR_PRIx
                " value=%08x stream4_CR=%08x NDTR=%u PAR=%08x M0AR=%08x "
                "supported_active_streams=4_channel0_SPI2_TX,5_channel4_USART2_RX_idle pc=%08x\n", addr,
                requested, s->spi2_dma.dma1[4].cr, s->spi2_dma.dma1[4].ndtr,
                s->spi2_dma.dma1[4].par, s->spi2_dma.dma1[4].m0ar, ex1850_pc());
        ex1850_unknown_access(s, addr, size, write, *value);
    }
    *value = v;
    ex1850_spi2_schedule(s);
    if (offset < 0x10) {
        ex1850_sampled_log("EX1850_DMA1_STATUS_%c bank=%s requested=%08x "
                "state=%08x pc=%08x virtual_ns=%" PRId64 " W1C=%u\n",
                write ? 'W' : 'R', offset & 4 ? "high" : "low", requested,
                offset & 4 ? s->spi2_dma.hisr : s->spi2_dma.lisr, ex1850_pc(),
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), write);
    } else {
        static const char *names[] = {"CR", "NDTR", "PAR", "M0AR", "M1AR", "FCR"};
        unsigned stream = (offset - 0x10) / 0x18, word = ((offset - 0x10) % 0x18) / 4;
        uint32_t state = 0;
        g_assert(ex1850_spi2_dma_access(&s->spi2_dma, offset, false, &state));
        ex1850_sampled_log("EX1850_DMA1_CONTROL %c stream=%u reg=%s requested=%08x "
                "state=%08x pc=%08x virtual_ns=%" PRId64
                " source=original_control_or_real_DMA_state accepted_total=%" PRIu64 "\n",
                write ? 'W' : 'R', stream, names[word], write ? requested : state,
                state, ex1850_pc(), qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
                s->spi2_dma.accepted_total);
    }
    return true;
}
#endif
