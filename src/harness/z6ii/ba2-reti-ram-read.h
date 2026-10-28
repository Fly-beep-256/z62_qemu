/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef Z6II_BA2_RETI_RAM_READ_H
#define Z6II_BA2_RETI_RAM_READ_H
#include "ba2-bus77.h"
/* RAM-only read32 callback for the explicit reti F1/N1 candidate.
 * Uses the caller's existing endian/alignment policy and RAM maps.
 * No payload/ROM/MMIO fallback, guest writes, IRQ or status side effects.
 * The caller must hold BQL or exclusively own the mapped RAM. */
Z6IIBA2BusResult z6ii_ba2_reti_ram_read32(void *,uint32_t,uint32_t *);
#endif
