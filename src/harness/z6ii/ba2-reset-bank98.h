/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef Z6II_BA2_RESET_BANK98_H
#define Z6II_BA2_RESET_BANK98_H
#include "ba2-core7494.h"

/* Explicit storage model for SPR selectors observed in original reset.
 * Initial values are caller input. Selector meanings, cache/exception side
 * effects and silicon reset values are unproved. There is no completion or
 * interrupt generation; every other selector is visibly unknown. */
typedef struct {
    uint32_t value[3]; /* selectors 11, 14, 15 (hex) */
    uint64_t reads, writes;
} Z6IIBA2ResetBank98;

static inline int z6ii_ba2_reset_bank98_index(uint32_t selector)
{
    switch (selector) {
    case 0x11: return 0;
    case 0x14: return 1;
    case 0x15: return 2;
    default: return -1;
    }
}

static inline Z6IIBA2SPRResult z6ii_ba2_reset_bank98_read(
    void *opaque, uint32_t selector, uint32_t *value)
{
    Z6IIBA2ResetBank98 *bank = opaque;
    int index = z6ii_ba2_reset_bank98_index(selector);
    if (index < 0) { return Z6II_BA2_SPR_UNKNOWN; }
    if (!bank || !value) { return Z6II_BA2_SPR_FAULT; }
    *value = bank->value[index];
    bank->reads++;
    return Z6II_BA2_SPR_OK;
}

static inline Z6IIBA2SPRResult z6ii_ba2_reset_bank98_write(
    void *opaque, uint32_t selector, uint32_t value)
{
    Z6IIBA2ResetBank98 *bank = opaque;
    int index = z6ii_ba2_reset_bank98_index(selector);
    if (index < 0) { return Z6II_BA2_SPR_UNKNOWN; }
    if (!bank) { return Z6II_BA2_SPR_FAULT; }
    bank->value[index] = value;
    bank->writes++;
    return Z6II_BA2_SPR_OK;
}
#endif
