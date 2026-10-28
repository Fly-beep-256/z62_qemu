/* SPDX-License-Identifier: GPL-2.0-or-later */
/* STM32F412 USART1: independent APB2 state and IRQ37. TX and an explicit
 * external clean byte stream share registers, not data or deadlines. */
#ifndef EX1850_USART1_BOARD_H
#define EX1850_USART1_BOARD_H
#define EX1850_USART1_BASE UINT32_C(0x40011000)
#define EX1850_USART1_APB2_BIT (UINT32_C(1) << 4)
#define EX1850_USART1_IRQ 37

static void ex1850_usart1_line_write(EX1850ResetState *s, uint16_t word,
                                    int64_t now);
static void ex1850_usart1_line_accept(EX1850ResetState *s);
static int64_t ex1850_battery_wire_deadline(EX1850ResetState *s);
static void ex1850_battery_wire_dispatch(EX1850ResetState *s, int64_t due);

static int64_t ex1850_usart1_deadline(EX1850ResetState *s)
{
    int64_t tx = ex1850_usart2_deadline(&s->usart1);
    int64_t rx = ex1850_usart1_rx_deadline(&s->usart1_rx);
    int64_t due = tx < 0 ? rx : rx < 0 ? tx : MIN(tx, rx);
    int64_t battery = ex1850_battery_wire_deadline(s);
    return due < 0 ? battery : battery < 0 ? due : MIN(due, battery);
}

static void ex1850_usart1_schedule(EX1850ResetState *s)
{
    if (s->usart1_event) {
        timer_del(s->usart1_event);
        int64_t due = ex1850_usart1_deadline(s);
        if (due >= 0) { timer_mod(s->usart1_event, due); }
    }
    bool level = ex1850_usart2_irq(&s->usart1);
    if (s->armv7m) {
        qemu_set_irq(qdev_get_gpio_in(DEVICE(s->armv7m), EX1850_USART1_IRQ), level);
    }
    if (level != s->usart1_irq37_level && s->usart1_irq_count++ < 128) {
        fprintf(stderr, "EX1850_USART1_IRQ IRQ37=%u SR=%08x CR1=%08x CR2=%08x "
                "CR3=%08x virtual_ns=%" PRId64 " source=status_and_interrupt_enables\n",
                level, s->usart1.sr, s->usart1.cr1, s->usart1.cr2,
                s->usart1.cr3, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    }
    s->usart1_irq37_level = level;
}

static void ex1850_usart1_transmitted(void *opaque, int64_t now, uint16_t word)
{
    EX1850ResetState *s = opaque;
    uint64_t offset = s->usart1_line_tx_bytes;
    ex1850_usart1_line_write(s, word, now);
    if (!word && s->usart1_line_tx_bytes == offset + 1 &&
        s->usart1_zero_tx_trace_count++ < 128) {
        fprintf(stderr, "EX1850_USART1_ZERO_TX wire_offset=%" PRIu64
                " word=000 accepted=%" PRIu64 " completed=%" PRIu64
                " reset_generation=%" PRIu64 " virtual_ns=%" PRId64
                " source=completed_guest_DR_data_frame\n", offset,
                s->usart1.tx_accepted, s->usart1.tx_completed,
                s->usart1_reset_trace_count, now);
    }
    if (s->usart1.tx_completed <= 64) {
        fprintf(stderr, "EX1850_USART1_TX_COMPLETE word=%03x BRR=%04x PCLK2_hz=%u "
                "accepted=%" PRIu64 " completed=%" PRIu64 " virtual_ns=%" PRId64
                " RX_response_generated=0 TDR_move_policy_one_PCLK=1\n", word,
                s->usart1.brr, s->usart1.pclk_hz, s->usart1.tx_accepted,
                s->usart1.tx_completed, now);
    }
}

/* Passive state inspection only: no MMIO read, IRQ acknowledgement or
 * guest-memory update. Use the board's MCU, not the CPU currently running
 * in another cluster. The NVIC fields precede this sync's IRQ update. */
static void ex1850_usart1_rx_timing(EX1850ResetState *s, uint16_t word,
                                   int64_t due, int64_t now,
                                   uint64_t previous_overruns)
{
    if (s->usart1_rx_timing_trace_count++ >= 512 || !s->armv7m) {
        return;
    }
    ARMCPU *mcu = s->armv7m->cpu;
    EX1850FlashWait *wait = &((EX1850M4R0P1 *)mcu)->wait;
    CPUState *cpu = CPU(mcu);
    CPUARMState *env = &mcu->env;
    NVICState *nvic = &s->armv7m->nvic;
    VecInfo *uart = &nvic->vectors[EX1850_USART1_IRQ + 16];
    VecInfo *tick = &nvic->vectors[15];
    uint8_t *ram = memory_region_get_ram_ptr(&s->ram);
    fprintf(stderr, "EX1850_USART1_RX_TIMING word=%03x completed=%" PRIu64
            " overruns=%" PRIu64 " new_overrun=%u SR=%08x"
            " deadline_ns=%" PRId64 " actual_ns=%" PRId64
            " lateness_ns=%" PRId64 " MCU_cpu=%d MCU_pc=%08x"
            " MCU_HAL_tick=%u MCU_exception=%d MCU_primask=%u MCU_basepri=%u"
            " MCU_halted=%d MCU_stop=%u MCU_stopped=%u MCU_singlestep=%u"
            " MCU_interrupt_request=%08x executing_cpu=%d"
            " IRQ37_enabled=%u IRQ37_pending=%u IRQ37_active=%u IRQ37_prio=%d"
            " SysTick_pending=%u SysTick_active=%u vectpending=%u"
            " MCU_flash_wait_active=%u MCU_flash_wait_due_ns=%" PRId64
            " MCU_flash_wait_PC=%08x MCU_flash_BSY=%u"
            " MCU_flash_operation=%u MCU_flash_operation_due_ns=%" PRId64
            " source=passive_state_before_IRQ_update\n",
            word, s->usart1_rx.completed, s->usart1.rx_overruns,
            s->usart1.rx_overruns != previous_overruns, s->usart1.sr,
            due, now, now - due, cpu->cpu_index, env->regs[15],
            ldl_le_p(ram + 0x20020400 - EX1850_RAM_BASE), env->v7m.exception,
            env->v7m.primask[0], env->v7m.basepri[0], cpu->halted,
            cpu->stop, cpu->stopped, cpu->singlestep_enabled,
            cpu->interrupt_request, current_cpu ? current_cpu->cpu_index : -1,
            uart->enabled, uart->pending, uart->active, uart->prio,
            tick->pending, tick->active, nvic->vectpending,
            wait->active, wait->due, wait->decoded.pc,
            !!(s->flash.sr & EX1850_FLASH_BSY), (unsigned)s->flash.pending.kind,
            s->flash.pending.due);
}

static void ex1850_usart1_sync(EX1850ResetState *s)
{
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), due;
    bool freed = ex1850_usart1_rx_reconcile(&s->usart1_rx, &s->usart1) != 0;
    while ((due = ex1850_usart1_deadline(s)) >= 0 && due <= now) {
        g_assert(ex1850_usart2_advance(&s->usart1, due,
                                     ex1850_usart1_transmitted, s));
        if (ex1850_battery_wire_deadline(s) == due) {
            ex1850_battery_wire_dispatch(s, due);
        }
        if (ex1850_usart1_rx_deadline(&s->usart1_rx) == due) {
            uint16_t word;
            uint64_t previous_overruns = s->usart1.rx_overruns;
            g_assert(ex1850_usart1_rx_complete(&s->usart1_rx, &s->usart1,
                                             due, &word));
            ex1850_usart1_rx_timing(s, word, due, now, previous_overruns);
            freed = true;
            if (s->usart1_rx.completed <= 64) {
                fprintf(stderr, "EX1850_USART1_RX_COMPLETE word=%03x SR=%08x "
                        "completed=%" PRIu64 " overruns=%" PRIu64
                        " virtual_ns=%" PRId64 " source=external_clean_serial_frame\n",
                        word, s->usart1.sr, s->usart1_rx.completed,
                        s->usart1.rx_overruns, due);
            }
        }
    }
    g_assert(ex1850_usart2_advance(&s->usart1, now,
                                 ex1850_usart1_transmitted, s));
    ex1850_usart1_schedule(s);
    if (freed) { ex1850_usart1_line_accept(s); }
}

static void ex1850_usart1_clocks_changed(EX1850ResetState *s)
{
    unsigned ppre = (s->cfgr >> 13) & 7;
    unsigned pclk = ppre < 4 ? s->cpu_hz : s->cpu_hz >> (ppre - 3);
    ex1850_usart2_clocks(&s->usart1, pclk,
                         !!(s->apb2enr & EX1850_USART1_APB2_BIT),
                         !!(s->rcc_apb2rstr & EX1850_USART1_APB2_BIT),
                         qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    unsigned lost = ex1850_usart1_rx_reconcile(&s->usart1_rx, &s->usart1);
    ex1850_usart1_schedule(s);
    if (lost) { ex1850_usart1_line_accept(s); }
}

static void ex1850_usart1_reset(void *opaque)
{
    EX1850ResetState *s = opaque;
    if (s->usart1_reset_trace_count++ < 128) {
        fprintf(stderr, "EX1850_USART1_RESET generation=%" PRIu64
                " wire_TX_bytes=%" PRIu64 " virtual_ns=%" PRId64
                " source=MCU_peripheral_reset\n", s->usart1_reset_trace_count,
                s->usart1_line_tx_bytes, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    }
    ex1850_usart1_rx_cancel(&s->usart1_rx);
    ex1850_usart2_reset(&s->usart1, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    ex1850_usart1_clocks_changed(s);
    ex1850_usart1_line_accept(s);
}

static void ex1850_usart1_external_bytes(EX1850ResetState *s,
                                        const uint8_t *bytes, unsigned length)
{
    ex1850_usart1_sync(s);
    if (!ex1850_usart1_rx_push(&s->usart1_rx, &s->usart1, bytes, length,
                              qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL))) {
        fprintf(stderr, "EX1850_USART1_LINE_BOUNDARY bytes=%u queue=%u "
                "SR=%08x BRR=%04x CR1=%08x CR2=%08x CR3=%08x\n",
                length, s->usart1_rx.count, s->usart1.sr, s->usart1.brr,
                s->usart1.cr1, s->usart1.cr2, s->usart1.cr3);
        ex1850_unknown_access(s, EX1850_USART1_BASE + 4, 4, false, 0);
    }
    ex1850_usart1_schedule(s);
}

static void ex1850_usart1_event(void *opaque)
{
    ex1850_usart1_sync(opaque);
}

static bool ex1850_usart1_board_access(EX1850ResetState *s, hwaddr addr,
                                      unsigned size, bool write, uint64_t *value)
{
    if (addr < EX1850_USART1_BASE || addr >= EX1850_USART1_BASE + 0x1c) { return false; }
    ex1850_usart1_sync(s);
    uint32_t requested = *value, v = *value;
    uint32_t previous_sr = s->usart1.sr;
    uint64_t accepted_before = s->usart1.tx_accepted;
    /* RM0402 specifies word register accesses; the observed HAL path uses 32 bits. */
    if (size != 4 || *value > UINT32_MAX || !ex1850_usart2_access(&s->usart1,
            addr - EX1850_USART1_BASE, size, write, &v)) {
        fprintf(stderr, "EX1850_USART1_BOUNDARY SR=%08x BRR=%04x CR1=%08x "
                "CR2=%08x CR3=%08x buffer_full=%u shifting=%u\n",
                s->usart1.sr, s->usart1.brr, s->usart1.cr1, s->usart1.cr2,
                s->usart1.cr3, s->usart1.buffer_full, s->usart1.shifting);
        ex1850_unknown_access(s, addr, size, write, *value);
    }
    *value = v;
    if (!write && addr == EX1850_USART1_BASE + 4 &&
        (previous_sr & 0x20) && s->usart1_rx_read_trace_count++ < 512) {
        uint8_t *ram = memory_region_get_ram_ptr(&s->ram);
        fprintf(stderr, "EX1850_USART1_RX_READ word=%03x previous_SR=%08x"
                " SR=%08x pc=%08x virtual_ns=%" PRId64
                " MCU_HAL_tick=%u source=guest_DR_read\n", v, previous_sr,
                s->usart1.sr, ex1850_pc(), qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
                ldl_le_p(ram + 0x20020400 - EX1850_RAM_BASE));
    }
    unsigned lost = ex1850_usart1_rx_reconcile(&s->usart1_rx, &s->usart1);
    ex1850_usart1_schedule(s);
    if (lost) { ex1850_usart1_line_accept(s); }
    if (write && addr == EX1850_USART1_BASE + 0x0c &&
        (requested & 0x80) && ex1850_pc() == 0x0804677c &&
        s->usart1_send_setup_trace_count++ < 1024) {
        CPUARMState *env = current_cpu ? &ARM_CPU(current_cpu)->env : NULL;
        /* The unchanged V1.70 HAL send routine writes TXEIE here without
         * changing LR or SP. Retain its caller and the existing SRAM bytes,
         * including the transaction's saved caller. These are observations,
         * not register reads through MMIO or writes to guest state. */
        uint8_t *ram = memory_region_get_ram_ptr(&s->ram);
        const uint32_t handle = 0x2001f518, control = 0x2001f4e8;
        uint8_t *bytes = ram + handle - EX1850_RAM_BASE;
        uint32_t tx_pointer = ldl_le_p(bytes + 0x20);
        uint32_t sp = env ? env->regs[13] : 0;
        char handle_hex[64 * 2 + 1] = "", tx_hex[24 * 2 + 1] = "";
        char control_hex[6 * 2 + 1] = "", stack_hex[64 * 2 + 1] = "";
        for (unsigned i = 0; i < 64; ++i) {
            snprintf(handle_hex + i * 2, 3, "%02x", bytes[i]);
        }
        for (unsigned i = 0; i < 6; ++i) {
            snprintf(control_hex + i * 2, 3, "%02x",
                     ram[control - EX1850_RAM_BASE + i]);
        }
        if (tx_pointer >= EX1850_RAM_BASE &&
            (uint64_t)tx_pointer + 24 <= EX1850_RAM_BASE + EX1850_RAM_BYTES) {
            bytes = ram + tx_pointer - EX1850_RAM_BASE;
            for (unsigned i = 0; i < 24; ++i) {
                snprintf(tx_hex + i * 2, 3, "%02x", bytes[i]);
            }
        }
        if (sp >= EX1850_RAM_BASE &&
            (uint64_t)sp + 64 <= EX1850_RAM_BASE + EX1850_RAM_BYTES) {
            bytes = ram + sp - EX1850_RAM_BASE;
            for (unsigned i = 0; i < 64; ++i) {
                snprintf(stack_hex + i * 2, 3, "%02x", bytes[i]);
            }
        }
        fprintf(stderr, "EX1850_USART1_SEND_SETUP addr=4001100c value=%08x "
                "pc=%08x lr=%08x sp=%08x r0=%08x r1=%08x r2=%08x r4=%08x "
                "accepted=%" PRIu64 " completed=%" PRIu64
                " wire_TX_bytes=%" PRIu64 " reset_generation=%" PRIu64
                " virtual_ns=%" PRId64 " handle=%08x handle_hex=%s "
                "tx_pointer=%08x tx24_hex=%s control6_hex=%s stack64_hex=%s "
                "source=original_HAL_TXEIE_store\n",
                requested, ex1850_pc(), env ? env->regs[14] : 0, sp,
                env ? env->regs[0] : 0, env ? env->regs[1] : 0,
                env ? env->regs[2] : 0, env ? env->regs[4] : 0,
                s->usart1.tx_accepted, s->usart1.tx_completed,
                s->usart1_line_tx_bytes, s->usart1_reset_trace_count,
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), handle, handle_hex,
                tx_pointer, tx_hex, control_hex, stack_hex);
    }
    if (write && addr == EX1850_USART1_BASE + 4 && !requested &&
        s->usart1_zero_dr_trace_count++ < 128) {
        CPUARMState *env = current_cpu ? &ARM_CPU(current_cpu)->env : NULL;
        /* Observe the original HAL handle and TX pointer directly in SRAM.
         * This does not access MMIO, acknowledge an IRQ or change guest data.
         * A NUL inside a packet and a separate initialization byte must remain
         * distinguishable by their actual buffer and wire positions. */
        uint32_t handle = env ? env->regs[0] : 0, tx_pointer = 0;
        uint8_t *ram = memory_region_get_ram_ptr(&s->ram);
        char handle_hex[64 * 2 + 1] = "", tx_hex[8 * 2 + 1] = "";
        if (handle >= EX1850_RAM_BASE &&
            (uint64_t)handle + 64 <= EX1850_RAM_BASE + EX1850_RAM_BYTES) {
            uint8_t *bytes = ram + handle - EX1850_RAM_BASE;
            for (unsigned i = 0; i < 64; ++i) {
                snprintf(handle_hex + i * 2, 3, "%02x", bytes[i]);
            }
            tx_pointer = ldl_le_p(bytes + 0x20);
            if (tx_pointer >= EX1850_RAM_BASE &&
                (uint64_t)tx_pointer + 8 <= EX1850_RAM_BASE + EX1850_RAM_BYTES) {
                bytes = ram + tx_pointer - EX1850_RAM_BASE;
                for (unsigned i = 0; i < 8; ++i) {
                    snprintf(tx_hex + i * 2, 3, "%02x", bytes[i]);
                }
            }
        }
        fprintf(stderr, "EX1850_USART1_ZERO_DR addr=40011004 value=00000000 "
                "pc=%08x lr=%08x r0=%08x r1=%08x r2=%08x r3=%08x sp=%08x "
                "accepted_before=%" PRIu64 " accepted_after=%" PRIu64
                " wire_TX_bytes=%" PRIu64 " reset_generation=%" PRIu64
                " virtual_ns=%" PRId64 " handle_hex=%s tx_pointer=%08x "
                "tx8_hex=%s source=guest_MMIO_write\n",
                ex1850_pc(), env ? env->regs[14] : 0, env ? env->regs[0] : 0,
                env ? env->regs[1] : 0, env ? env->regs[2] : 0,
                env ? env->regs[3] : 0, env ? env->regs[13] : 0,
                accepted_before, s->usart1.tx_accepted, s->usart1_line_tx_bytes,
                s->usart1_reset_trace_count, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
                handle_hex, tx_pointer, tx_hex);
    }
    if (write && addr != EX1850_USART1_BASE + 4 &&
        s->usart1_control_trace_count++ < 128) {
        fprintf(stderr, "EX1850_USART1_CONTROL addr=%08" HWADDR_PRIx
                " value=%08x pc=%08x wire_TX_bytes=%" PRIu64
                " BRR=%04x CR1=%08x CR2=%08x CR3=%08x virtual_ns=%" PRId64 "\n",
                addr, requested, ex1850_pc(), s->usart1_line_tx_bytes,
                s->usart1.brr, s->usart1.cr1, s->usart1.cr2, s->usart1.cr3,
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    }
    if (s->usart1_access_count++ < 64) {
        fprintf(stderr, "EX1850_USART1_%c addr=%08" HWADDR_PRIx
                " size=%u value=%08x SR=%08x BRR=%04x CR1=%08x CR2=%08x "
                "CR3=%08x pc=%08x virtual_ns=%" PRId64 " RX_supplied=%" PRIu64 "\n",
                write ? 'W' : 'R', addr, size, write ? requested : v,
                s->usart1.sr, s->usart1.brr, s->usart1.cr1, s->usart1.cr2,
                s->usart1.cr3, ex1850_pc(), qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
                s->usart1.rx_supplied);
    }
    return true;
}
#endif
