/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef EX1850_FLASH_BOARD_H
#define EX1850_FLASH_BOARD_H

/* Only this adapter owns FLASH registers and the supplied main array.
 * ROMD permits ordinary direct reads/executes, but every guest write still
 * reaches the device. While busy, ROMD is disabled. The MCU subtype's
 * bounded TCG hook waits for restartable SRAM word LDR/STR; direct accesses
 * and all unsupported instructions still stop before supplying old bytes.
 * No guest callback or software completion flag is written by this adapter.
 */
static void ex1850_flash_schedule(EX1850ResetState *s)
{
    bool busy = !!(s->flash.sr & EX1850_FLASH_BSY);
    memory_region_rom_device_set_romd(&s->rom, !busy);
    if (s->flash_event) {
        timer_del(s->flash_event);
        if (busy) { timer_mod(s->flash_event, s->flash.pending.due); }
    }
    bool level = ex1850_flash_irq4(&s->flash);
    if (s->armv7m) {
        qemu_set_irq(qdev_get_gpio_in(DEVICE(s->armv7m), 4), level);
    }
    if (level != s->flash_irq4_level) {
        fprintf(stderr, "EX1850_FLASH_IRQ IRQ4=%u SR=%08x CR=%08x "
                "virtual_ns=%" PRId64 " source=device_flags_and_guest_enables\n",
                level, s->flash.sr, s->flash.cr,
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    }
    s->flash_irq4_level = level;
}

static const char *ex1850_flash_operation_name(EX1850FlashOperation kind)
{
    return kind == EX1850_FLASH_ERASE ? "ERASE" :
           kind == EX1850_FLASH_PROGRAM ? "PROGRAM" : "IDLE";
}

static void ex1850_flash_sync(EX1850ResetState *s)
{
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    if (ex1850_flash_advance(&s->flash, now)) {
        EX1850FlashPending *op = &s->flash.last_commit;
        /* This dedicated ROM-device API marks dirty pages and invalidates
         * TCG TBs. It requires ROMD=true, restored before the flush. */
        memory_region_rom_device_set_romd(&s->rom, true);
        memory_region_flush_rom_device(&s->rom, op->offset, op->bytes);
        uint32_t word = 0;
        for (unsigned i = 0; i < 4; i++) {
            word |= (uint32_t)s->flash.array[op->offset + i] << (8 * i);
        }
        fprintf(stderr, "EX1850_FLASH_COMPLETE operation=%s sector=%u "
                "offset=%08x bytes=%u latched_word=%08x committed_prefix=%08x "
                "SR=%08x CR=%08x accepted=%" PRIu64 " completed=%" PRIu64
                " erases=%" PRIu64 " programs=%" PRIu64 " due_ns=%" PRId64
                " virtual_ns=%" PRId64 " TB_range_invalidated=1 "
                "completion_source=virtual_time guest_callback_injected=0\n",
                ex1850_flash_operation_name(op->kind), op->sector, op->offset,
                op->bytes, op->word, word, s->flash.sr, s->flash.cr,
                s->flash.accepted, s->flash.completed, s->flash.erases,
                s->flash.programs, op->due, now);
    }
    ex1850_flash_schedule(s);
    ex1850_flash_wait_release(s);
}

static void ex1850_flash_event(void *opaque)
{
    ex1850_flash_sync(opaque);
}

static G_NORETURN void ex1850_flash_stop(EX1850ResetState *s, hwaddr addr,
    unsigned size, bool write, uint64_t value)
{
    fprintf(stderr, "EX1850_FLASH_BOUNDARY reason=%s addr=%08" HWADDR_PRIx
            " size=%u write=%u value=%08" PRIx64 " pc=%08x "
            "SR=%08x CR=%08x operation=%s due_ns=%" PRId64
            " virtual_ns=%" PRId64 " unknown_result_supplied=0\n",
            s->flash.boundary ? s->flash.boundary : "unclassified",
            addr, size, write, value, ex1850_pc(), s->flash.sr, s->flash.cr,
            ex1850_flash_operation_name(s->flash.pending.kind),
            s->flash.pending.due, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    ex1850_unknown_access(s, addr, size, write, value);
}

static MemTxResult ex1850_flash_result(EX1850ResetState *s,
    EX1850FlashResult result, hwaddr addr, unsigned size, bool write,
    uint64_t value, uint64_t accepted_before)
{
    if (result == EX1850_FLASH_BOUNDARY) {
        ex1850_flash_stop(s, addr, size, write, value);
    }
    if (result == EX1850_FLASH_BUS_ERROR) {
        fprintf(stderr, "EX1850_FLASH_BUS_ERROR addr=%08" HWADDR_PRIx
                " size=%u write=%u pc=%08x CR=%08x key_failed=%u "
                "virtual_ns=%" PRId64 " architecture_result=MEMTX_ERROR\n",
                addr, size, write, ex1850_pc(), s->flash.cr,
                s->flash.key_failed, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
        ex1850_flash_schedule(s);
        return MEMTX_ERROR;
    }
    if (s->flash.accepted != accepted_before) {
        EX1850FlashPending *op = &s->flash.pending;
        fprintf(stderr, "EX1850_FLASH_ACCEPT operation=%s sector=%u "
                "offset=%08x bytes=%u word=%08x pc=%08x SR=%08x CR=%08x "
                "accepted=%" PRIu64 " completed=%" PRIu64 " due_ns=%" PRId64
                " virtual_ns=%" PRId64 " HCLK_hz=%u "
                "array_committed=0 source=original_guest_register_or_store\n",
                ex1850_flash_operation_name(op->kind), op->sector, op->offset,
                op->bytes, op->word, ex1850_pc(), s->flash.sr, s->flash.cr,
                s->flash.accepted, s->flash.completed, op->due,
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), s->cpu_hz);
    }
    ex1850_flash_schedule(s);
    return MEMTX_OK;
}

static MemTxResult ex1850_flash_register_access(EX1850ResetState *s,
    hwaddr offset, uint64_t *value, unsigned size, bool write)
{
    ex1850_flash_sync(s);
    uint64_t accepted = s->flash.accepted, requested = *value;
    EX1850FlashResult result = ex1850_flash_reg_access(&s->flash, offset,
        size, write, value, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), s->cpu_hz);
    MemTxResult tx = ex1850_flash_result(s, result, 0x40023c00 + offset,
                                       size, write, requested, accepted);
    if (tx != MEMTX_OK) { return tx; }
    unsigned index = offset / 4;
    uint32_t state = index == 0 ? s->flash.acr : index == 3 ? s->flash.sr :
                     index == 4 ? s->flash.cr : 0;
    bool sample = write;
    if (!write && index < 6) {
        uint64_t count = ++s->flash_read_counts[index];
        sample = count <= 8 || s->flash_last_reads[index] != state ||
                 !(count & (count - 1));
        s->flash_last_reads[index] = state;
    }
    if (sample) {
        ex1850_sampled_log("EX1850_FLASH_REG_%c offset=%02" HWADDR_PRIx
                " size=%u value=%08" PRIx64 " state=%08x "
                "ACR=%08x SR=%08x CR=%08x pc=%08x virtual_ns=%" PRId64
                " read_log_sampled=1 SR_write_semantics=W1C_BSY_readonly\n",
                write ? 'W' : 'R', offset, size, write ? requested : *value,
                state, s->flash.acr, s->flash.sr, s->flash.cr, ex1850_pc(),
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    }
    return MEMTX_OK;
}

static MemTxResult ex1850_flash_register_read(void *opaque, hwaddr offset,
    uint64_t *value, unsigned size, MemTxAttrs attrs)
{
    (void)attrs;
    *value = 0;
    return ex1850_flash_register_access(opaque, offset, value, size, false);
}

static MemTxResult ex1850_flash_register_write(void *opaque, hwaddr offset,
    uint64_t value, unsigned size, MemTxAttrs attrs)
{
    (void)attrs;
    return ex1850_flash_register_access(opaque, offset, &value, size, true);
}

static MemTxResult ex1850_flash_array_access_board(EX1850ResetState *s,
    hwaddr offset, uint64_t *value, unsigned size, bool write)
{
    ex1850_flash_sync(s);
    uint64_t accepted = s->flash.accepted, requested = *value;
    EX1850FlashResult result = ex1850_flash_array_access(&s->flash, offset,
        size, write, value, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), s->cpu_hz);
    MemTxResult tx = ex1850_flash_result(s, result, EX1850_BASE + offset,
                                       size, write, requested, accepted);
    if (tx == MEMTX_OK && write) {
        fprintf(stderr, "EX1850_FLASH_ARRAY_W offset=%08" HWADDR_PRIx
                " size=%u word=%08" PRIx64 " pc=%08x SR=%08x CR=%08x "
                "accepted=%" PRIu64 " errors=%" PRIu64
                " virtual_ns=%" PRId64 " guest_store_supplied_bytes=1\n",
                offset, size, requested, ex1850_pc(), s->flash.sr, s->flash.cr,
                s->flash.accepted, s->flash.errors,
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    }
    return tx;
}

static MemTxResult ex1850_flash_array_read(void *opaque, hwaddr offset,
    uint64_t *value, unsigned size, MemTxAttrs attrs)
{
    (void)attrs;
    *value = 0;
    return ex1850_flash_array_access_board(opaque, offset, value, size, false);
}

static MemTxResult ex1850_flash_array_write(void *opaque, hwaddr offset,
    uint64_t value, unsigned size, MemTxAttrs attrs)
{
    (void)attrs;
    return ex1850_flash_array_access_board(opaque, offset, &value, size, true);
}

static const MemoryRegionOps ex1850_flash_register_ops = {
    .read_with_attrs = ex1850_flash_register_read,
    .write_with_attrs = ex1850_flash_register_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 4, .unaligned = true },
    .impl = { .min_access_size = 1, .max_access_size = 4, .unaligned = true },
};

static const MemoryRegionOps ex1850_flash_array_ops = {
    .read_with_attrs = ex1850_flash_array_read,
    .write_with_attrs = ex1850_flash_array_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 4, .unaligned = true },
    .impl = { .min_access_size = 1, .max_access_size = 4, .unaligned = true },
};

static void ex1850_flash_reset(void *opaque)
{
    EX1850ResetState *s = opaque;
    /* A reset during an accepted operation has unspecified array contents
     * in RM0402. Do not silently complete, abort, or restore the input ROM. */
    if (s->flash.sr & EX1850_FLASH_BSY) {
        ex1850_flash_boundary(&s->flash, "reset-during-operation-contents-unknown");
        ex1850_flash_stop(s, 0x40023c10, 4, true, EX1850_FLASH_LOCK);
    }
    EX1850FlashConfig config = s->flash.config;
    g_assert(ex1850_flash_init(&s->flash, memory_region_get_ram_ptr(&s->rom),
                              EX1850_BYTES, config));
    memset(s->flash_read_counts, 0, sizeof(s->flash_read_counts));
    memset(s->flash_last_reads, 0, sizeof(s->flash_last_reads));
    s->flash_resets++;
    ex1850_flash_schedule(s);
    fprintf(stderr, "EX1850_FLASH_RESET reset_epoch=%u ACR=%08x SR=%08x "
            "CR=%08x array_retained=1 input_image_reloaded=0 virtual_ns=%" PRId64 "\n",
            s->flash_resets, s->flash.acr, s->flash.sr, s->flash.cr,
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
}

#endif
