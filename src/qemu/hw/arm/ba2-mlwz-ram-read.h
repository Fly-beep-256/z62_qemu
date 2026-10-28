/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef Z6II_BA2_MLWZ_RAM_READ_H
#define Z6II_BA2_MLWZ_RAM_READ_H
#include "ba2-bus77.h"
/* Exactly two ordinary RAM words: snapshot addresses, precheck both mappings,
 * permissions and alignment, stage both values, then commit caller output once.
 * No payload/MMIO fallback or callbacks, writes, IRQ/status effects.
 * BQL/exclusive RAM/config ownership required; output must be a separate caller
 * two-word array, not mapped backing RAM. Output may alias the address array.
 * Endian/alignment is existing explicit bus policy, not silicon certification. */
Z6IIBA2BusResult z6ii_ba2_mlwz_ram_read_pair(void *,const uint32_t *,
                                         uint32_t *,unsigned count);
#endif
