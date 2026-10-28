/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef Z6II_BA2_TICK139_H
#define Z6II_BA2_TICK139_H
#include "ba2-core7494.h"
#define Z6II_BA2_TICK139_VECTOR UINT32_C(0x40000030)
#define Z6II_BA2_TICK139_POLICY "original-periodic-tick-external-cycles-v1"
typedef struct Z6IIBA2Tick139 {
    const char *basis;
    uint64_t source_hz, source_cycles, elapsed_cycles, events, acknowledgements;
    uint32_t control, count;
    unsigned ns_fraction_fifths; /* exact 400MHz: cycles = ns * 2 / 5 */
    bool initialized, pending;
} Z6IIBA2Tick139;
/* Candidate evidence: original 72EE returns 400MHz; BE97 writes period=(hz/1000)-1
 * with mode01 and IE; vector30->BD86 clears IP bit28 then calls original D476.
 * Time is supplied by the caller in source cycles, never inferred from retired
 * instructions. 5004/5005 use an explicitly selected same-source 64-bit counter
 * candidate; the original high/low/high reads prove its shape, not silicon rate.
 * No guest RAM, task, Ready flag, FIFO data or protocol reply is written here. */
Z6IIBA2SPRResult z6ii_ba2_tick139_init(Z6IIBA2Tick139 *,uint64_t source_hz,
                                    uint64_t initial_source_cycles,const char *basis);
Z6IIBA2SPRResult z6ii_ba2_tick139_advance(Z6IIBA2Tick139 *,uint64_t elapsed_cycles);
/* Exact virtual-time conversion, preserving sub-cycle fractions across slices. */
Z6IIBA2SPRResult z6ii_ba2_tick139_advance_ns(Z6IIBA2Tick139 *,uint64_t elapsed_ns);
bool z6ii_ba2_tick139_invariant(const Z6IIBA2Tick139 *);
Z6IIBA2SPRResult z6ii_ba2_tick139_spr(Z6IIBA2Tick139 *,uint32_t selector,bool write,
                                   uint32_t *value,bool *handled);
bool z6ii_ba2_tick139_level(const Z6IIBA2Tick139 *);
#endif
