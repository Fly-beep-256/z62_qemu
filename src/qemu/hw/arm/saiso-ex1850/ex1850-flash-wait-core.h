/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef EX1850_FLASH_WAIT_CORE_H
#define EX1850_FLASH_WAIT_CORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Deliberately bounded, restartable Thumb16 immediate word LDR/STR only.
 * A halfword encoding check alone is insufficient: match the actual access,
 * its direction, full width, alignment and (for stores) dispatch bytes.
 * No destination/base register has changed before these single accesses.
 */
typedef struct EX1850FlashWaitInsn {
    uint32_t pc, address, word;
    uint16_t insn;
    unsigned rn, rt;
    bool write;
} EX1850FlashWaitInsn;

static inline const char *ex1850_flash_wait_decode(
    EX1850FlashWaitInsn *decoded, uint32_t pc, bool thumb, unsigned it,
    uint16_t insn, const uint32_t regs[16], uint64_t address,
    unsigned size, bool write, uint64_t value)
{
    if (!thumb || it) { return "wait-requires-Thumb-without-IT"; }
    if (pc < UINT32_C(0x20000000) || pc > UINT32_C(0x2003fffe) || (pc & 1)) {
        return "wait-instruction-outside-aligned-SRAM";
    }
    if ((insn & 0xf000) != 0x6000 || !!(insn & 0x0800) == write) {
        return "wait-instruction-not-matching-single-word-LDR-STR";
    }
    if (size != 4 || address > UINT32_MAX || (address & 3)) {
        return "wait-access-not-one-aligned-word";
    }
    unsigned rn = (insn >> 3) & 7, rt = insn & 7;
    uint32_t effective = regs[rn] + ((insn >> 6) & 31) * 4;
    if (address != effective) { return "wait-effective-address-mismatch"; }
    if (write && (uint32_t)value != regs[rt]) {
        return "wait-store-dispatch-bytes-mismatch";
    }
    *decoded = (EX1850FlashWaitInsn){pc, effective, regs[rt], insn, rn, rt, write};
    return NULL;
}

#endif
