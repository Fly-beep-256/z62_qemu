/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef EX1850_FLASH_CORE_H
#define EX1850_FLASH_CORE_H

#include <stdbool.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>

/* STM32F412 RM0402 Rev7, sections3.5/3.8. This first contract covers
 * sector erase and x32 programming in the supplied main-array extent.
 * Voltage/protection/latency are explicit experiment inputs, not camera
 * measurements. This portable core cannot stall a CPU: busy array/CR
 * access returns a boundary unless the board's bounded TCG wait hook
 * intercepts it before dispatch. Option/OTP/mass erase, x8/x16/x64
 * programming and attempted0->1 remain strict boundaries.
 */
#define EX1850_FLASH_EOP       UINT32_C(0x00000001)
#define EX1850_FLASH_OPERR     UINT32_C(0x00000002)
#define EX1850_FLASH_WRPERR    UINT32_C(0x00000010)
#define EX1850_FLASH_PGAERR    UINT32_C(0x00000020)
#define EX1850_FLASH_PGPERR    UINT32_C(0x00000040)
#define EX1850_FLASH_PGSERR    UINT32_C(0x00000080)
#define EX1850_FLASH_RDERR     UINT32_C(0x00000100)
#define EX1850_FLASH_BSY       UINT32_C(0x00010000)
#define EX1850_FLASH_W1C       UINT32_C(0x000001f3)
#define EX1850_FLASH_PG        UINT32_C(0x00000001)
#define EX1850_FLASH_SER       UINT32_C(0x00000002)
#define EX1850_FLASH_MER       UINT32_C(0x00000004)
#define EX1850_FLASH_SNB       UINT32_C(0x00000078)
#define EX1850_FLASH_PSIZE     UINT32_C(0x00000300)
#define EX1850_FLASH_STRT      UINT32_C(0x00010000)
#define EX1850_FLASH_EOPIE     UINT32_C(0x01000000)
#define EX1850_FLASH_ERRIE     UINT32_C(0x02000000)
#define EX1850_FLASH_LOCK      UINT32_C(0x80000000)
#define EX1850_FLASH_CR_MASK   UINT32_C(0x8301037f)
#define EX1850_FLASH_ACR_MASK  UINT32_C(0x00001f0f)

typedef enum EX1850FlashResult {
    EX1850_FLASH_OK,
    EX1850_FLASH_BUS_ERROR,
    EX1850_FLASH_BOUNDARY,
} EX1850FlashResult;

typedef enum EX1850FlashOperation {
    EX1850_FLASH_IDLE,
    EX1850_FLASH_ERASE,
    EX1850_FLASH_PROGRAM,
} EX1850FlashOperation;

typedef struct EX1850FlashConfig {
    bool functional;
    unsigned vdd_mv;
    uint16_t nwrp;
    int64_t erase_ns, program_ns;
} EX1850FlashConfig;

typedef struct EX1850FlashPending {
    EX1850FlashOperation kind;
    uint32_t offset, bytes, word;
    unsigned sector;
    int64_t due;
} EX1850FlashPending;

typedef struct EX1850Flash {
    uint8_t *array;
    uint32_t array_bytes, acr, sr, cr;
    EX1850FlashConfig config;
    EX1850FlashPending pending;
    unsigned key_stage;
    bool key_failed;
    const char *boundary;
    uint64_t accepted, completed, erases, programs, errors;
    EX1850FlashPending last_commit;
} EX1850Flash;

static inline EX1850FlashResult ex1850_flash_boundary(EX1850Flash *f,
                                                    const char *reason)
{
    f->boundary = reason;
    return EX1850_FLASH_BOUNDARY;
}

static inline bool ex1850_flash_init(EX1850Flash *f, uint8_t *array,
                                    uint32_t bytes, EX1850FlashConfig config)
{
    if (!array || !bytes || bytes > UINT32_C(0x100000) ||
        (config.functional && (config.vdd_mv < 2700 || config.vdd_mv > 3600 ||
         config.nwrp > 0xfff || config.erase_ns <= 0 || config.program_ns <= 0))) {
        return false;
    }
    memset(f, 0, sizeof(*f));
    f->array = array;
    f->array_bytes = bytes;
    f->config = config;
    f->cr = EX1850_FLASH_LOCK;
    f->pending.due = -1;
    f->last_commit.due = -1;
    return true;
}

static inline bool ex1850_flash_irq4(const EX1850Flash *f)
{
    return ((f->sr & EX1850_FLASH_EOP) && (f->cr & EX1850_FLASH_EOPIE)) ||
           ((f->sr & EX1850_FLASH_OPERR) && (f->cr & EX1850_FLASH_ERRIE));
}

static inline bool ex1850_flash_sector(unsigned sector, uint32_t *offset,
                                     uint32_t *bytes)
{
    if (sector < 4) {
        *offset = sector * UINT32_C(0x4000);
        *bytes = 0x4000;
    } else if (sector == 4) {
        *offset = 0x10000;
        *bytes = 0x10000;
    } else if (sector < 12) {
        *offset = UINT32_C(0x20000) + (sector - 5) * UINT32_C(0x20000);
        *bytes = 0x20000;
    } else {
        return false;
    }
    return true;
}

static inline unsigned ex1850_flash_sector_for_offset(uint32_t offset)
{
    return offset < 0x10000 ? offset / 0x4000 :
           offset < 0x20000 ? 4 : 5 + (offset - 0x20000) / 0x20000;
}

static inline EX1850FlashResult ex1850_flash_error(EX1850Flash *f,
                                                 uint32_t flag)
{
    f->sr |= flag;
    if (f->cr & EX1850_FLASH_ERRIE) { f->sr |= EX1850_FLASH_OPERR; }
    f->cr &= ~EX1850_FLASH_STRT;
    f->errors++;
    return EX1850_FLASH_OK; /* Accepted hardware request, rejected operation. */
}

static inline EX1850FlashResult ex1850_flash_operation_allowed(EX1850Flash *f,
                                                              unsigned hclk)
{
    if (!f->config.functional) { return ex1850_flash_boundary(f, "unprovided-VDD-protection-latency"); }
    if (hclk < 1000000) { return ex1850_flash_boundary(f, "HCLK-below-one-MHz"); }
    if ((f->cr & EX1850_FLASH_PSIZE) != 0x200) {
        return ex1850_flash_boundary(f, "parallelism-other-than-x32");
    }
    return EX1850_FLASH_OK;
}

static inline EX1850FlashResult ex1850_flash_begin(EX1850Flash *f,
    EX1850FlashOperation kind, uint32_t offset, uint32_t bytes, uint32_t word,
    unsigned sector, int64_t now)
{
    int64_t delay = kind == EX1850_FLASH_ERASE ? f->config.erase_ns : f->config.program_ns;
    if (now < 0 || delay > INT64_MAX - now) {
        return ex1850_flash_boundary(f, "operation-deadline-overflow");
    }
    f->pending = (EX1850FlashPending){kind, offset, bytes, word, sector, now + delay};
    f->sr |= EX1850_FLASH_BSY;
    f->accepted++;
    return EX1850_FLASH_OK;
}

/* Only time advancement commits bytes. Poll count and read values have no
 * effect. The adapter must invalidate QEMU TBs for last_commit's range.
 */
static inline bool ex1850_flash_advance(EX1850Flash *f, int64_t now)
{
    EX1850FlashPending op = f->pending;
    if (op.kind == EX1850_FLASH_IDLE || now < op.due) { return false; }
    if (op.kind == EX1850_FLASH_ERASE) {
        memset(f->array + op.offset, 0xff, op.bytes);
        f->erases++;
    } else {
        for (unsigned i = 0; i < 4; i++) {
            f->array[op.offset + i] &= op.word >> (i * 8);
        }
        f->programs++;
    }
    f->last_commit = op;
    f->completed++;
    f->pending.kind = EX1850_FLASH_IDLE;
    f->pending.due = -1;
    f->sr &= ~EX1850_FLASH_BSY;
    f->cr &= ~EX1850_FLASH_STRT;
    /* RM0402 Rev7 section3.8.4: EOP is gated by EOPIE. */
    if (f->cr & EX1850_FLASH_EOPIE) { f->sr |= EX1850_FLASH_EOP; }
    return true;
}

static inline EX1850FlashResult ex1850_flash_reg_access(EX1850Flash *f,
    uint32_t offset, unsigned size, bool write, uint64_t *value,
    int64_t now, unsigned hclk)
{
    f->boundary = NULL;
    if ((size != 1 && size != 2 && size != 4) || (offset & 3) + size > 4) {
        return ex1850_flash_boundary(f, "register-width-or-crossing");
    }
    uint32_t base = offset & ~UINT32_C(3), shift = (offset & 3) * 8;
    uint32_t mask = size == 4 ? UINT32_MAX : (UINT32_C(1) << (size * 8)) - 1;
    uint32_t input = (uint32_t)(*value & mask) << shift;
    if (base == 4) {
        if (!write || size != 4) { return ex1850_flash_boundary(f, "KEYR-word-write-only"); }
        if (f->key_failed) { return EX1850_FLASH_BUS_ERROR; }
        if (!(f->cr & EX1850_FLASH_LOCK)) { return EX1850_FLASH_OK; }
        if (f->key_stage == 0 && input == UINT32_C(0x45670123)) {
            f->key_stage = 1;
        } else if (f->key_stage == 1 && input == UINT32_C(0xcdef89ab)) {
            f->key_stage = 0;
            f->cr &= ~EX1850_FLASH_LOCK;
        } else {
            f->key_stage = 0;
            f->key_failed = true;
            f->cr |= EX1850_FLASH_LOCK;
            return EX1850_FLASH_BUS_ERROR;
        }
        return EX1850_FLASH_OK;
    }
    uint32_t *reg = base == 0 ? &f->acr : base == 0x0c ? &f->sr :
                    base == 0x10 ? &f->cr : NULL;
    if (!reg) { return ex1850_flash_boundary(f, "option-or-undefined-register"); }
    if (!write) { *value = (*reg >> shift) & mask; return EX1850_FLASH_OK; }
    if (base == 0x0c) {
        if (input & ~(EX1850_FLASH_W1C | EX1850_FLASH_BSY)) {
            return ex1850_flash_boundary(f, "SR-reserved-write");
        }
        f->sr &= ~(input & EX1850_FLASH_W1C); /* BSY is read-only. */
        return EX1850_FLASH_OK;
    }
    uint32_t merged = (*reg & ~(mask << shift)) | input;
    if (base == 0) {
        if ((merged & ~EX1850_FLASH_ACR_MASK) ||
            ((merged & 0x800) && (merged & 0x200)) ||
            ((merged & 0x1000) && (merged & 0x400))) {
            return ex1850_flash_boundary(f, "ACR-reserved-or-reset-while-cache-enabled");
        }
        f->acr = merged; /* Digital latches only; no cache-performance model. */
        return EX1850_FLASH_OK;
    }
    if (f->sr & EX1850_FLASH_BSY) {
        return ex1850_flash_boundary(f, "CR-write-needs-busy-bus-stall");
    }
    if (f->cr & EX1850_FLASH_LOCK) { return EX1850_FLASH_OK; }
    if (merged & ~EX1850_FLASH_CR_MASK) {
        return ex1850_flash_boundary(f, "CR-reserved-write");
    }
    if (merged & EX1850_FLASH_STRT) {
        if (merged & EX1850_FLASH_MER) { return ex1850_flash_boundary(f, "mass-erase-unimplemented"); }
        if (!(merged & EX1850_FLASH_SER)) { return ex1850_flash_boundary(f, "STRT-without-erase-selection"); }
        if (merged & EX1850_FLASH_PG) {
            return ex1850_flash_boundary(f, "simultaneous-erase-program-unimplemented");
        }
        /* Validate supported scope before changing control latches. */
        uint32_t before = f->cr;
        f->cr = merged;
        EX1850FlashResult allowed = ex1850_flash_operation_allowed(f, hclk);
        if (allowed != EX1850_FLASH_OK) { f->cr = before; return allowed; }
        unsigned sector = (merged & EX1850_FLASH_SNB) >> 3;
        uint32_t start, length;
        if (sector == 12 || sector == 13) {
            f->cr = before;
            return ex1850_flash_boundary(f, "user-specific-or-option-sector");
        }
        if (!ex1850_flash_sector(sector, &start, &length)) {
            return ex1850_flash_error(f, EX1850_FLASH_WRPERR);
        }
        if ((uint64_t)start + length > f->array_bytes) {
            f->cr = before;
            return ex1850_flash_boundary(f, "sector-outside-supplied-array");
        }
        if (!(f->config.nwrp & (1U << sector))) {
            return ex1850_flash_error(f, EX1850_FLASH_WRPERR);
        }
        EX1850FlashResult result = ex1850_flash_begin(f, EX1850_FLASH_ERASE,
                                                   start, length, 0, sector, now);
        if (result != EX1850_FLASH_OK) { f->cr = before; }
        return result;
    }
    f->cr = merged;
    return EX1850_FLASH_OK;
}

static inline EX1850FlashResult ex1850_flash_array_access(EX1850Flash *f,
    uint32_t offset, unsigned size, bool write, uint64_t *value,
    int64_t now, unsigned hclk)
{
    f->boundary = NULL;
    if ((size != 1 && size != 2 && size != 4) ||
        (uint64_t)offset + size > f->array_bytes) {
        return ex1850_flash_boundary(f, "array-width-or-outside-supplied-extent");
    }
    if (f->sr & EX1850_FLASH_BSY) {
        return ex1850_flash_boundary(f, "array-access-needs-busy-bus-stall");
    }
    if (!write) {
        *value = 0;
        for (unsigned i = 0; i < size; i++) { *value |= (uint64_t)f->array[offset+i] << (8*i); }
        return EX1850_FLASH_OK;
    }
    if ((f->cr & EX1850_FLASH_PG) &&
        (f->cr & (EX1850_FLASH_SER | EX1850_FLASH_MER))) {
        return ex1850_flash_boundary(f, "simultaneous-erase-program-unimplemented");
    }
    if ((f->cr & EX1850_FLASH_LOCK) || !(f->cr & EX1850_FLASH_PG)) {
        return ex1850_flash_error(f, EX1850_FLASH_PGSERR);
    }
    EX1850FlashResult allowed = ex1850_flash_operation_allowed(f, hclk);
    if (allowed != EX1850_FLASH_OK) { return allowed; }
    if (size != 4) { return ex1850_flash_error(f, EX1850_FLASH_PGPERR); }
    if ((offset & 15) + size > 16) { return ex1850_flash_error(f, EX1850_FLASH_PGAERR); }
    unsigned sector = ex1850_flash_sector_for_offset(offset);
    if (!(f->config.nwrp & (1U << sector))) {
        return ex1850_flash_error(f, EX1850_FLASH_WRPERR);
    }
    for (unsigned i = 0; i < 4; i++) {
        uint8_t data = *value >> (8*i);
        if ((f->array[offset+i] & data) != data) {
            /* RM requires erase to write1; it does not establish the error
             * flags for this attempted transition. Do not invent them. */
            return ex1850_flash_boundary(f, "attempted-zero-to-one-needs-erase");
        }
    }
    return ex1850_flash_begin(f, EX1850_FLASH_PROGRAM, offset, 4,
                             *value, sector, now);
}

#endif
