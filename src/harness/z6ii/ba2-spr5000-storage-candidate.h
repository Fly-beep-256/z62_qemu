/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef Z6II_BA2_SPR5000_STORAGE_CANDIDATE_H
#define Z6II_BA2_SPR5000_STORAGE_CANDIDATE_H
#include "ba2-core7494.h"
/* Explicit software environment ONLY. SPR5000 device purpose, reset value,
 * reserved/mode/W1C bits, tick/IRQ effects and hardware readback are unknown.
 * No timer, IRQ, readiness or protocol event is generated.
 * Caller exclusively owns this state and keeps basis strings alive. */
typedef struct {
    uint32_t value;
    uint64_t reads,writes; /* Successful software accesses, not hardware ticks. */
    bool initialized,enabled;
    const char *initial_basis,*enable_basis;
} Z6IIBA2SPR5000StorageCandidate;
/* Initial value and nonempty basis are mandatory. Initialization stays disabled.
 * Invalid arguments preserve the entire object. No implicit silicon reset value. */
Z6IIBA2SPRResult z6ii_ba2_spr5000_storage_init(
    Z6IIBA2SPR5000StorageCandidate *,uint32_t initial_value,const char *initial_basis);
/* Independent explicit opt-in. Preserves value/counters and cannot clear CPU halt.
 * Invalid arguments/uninitialized object preserve the entire object. */
Z6IIBA2SPRResult z6ii_ba2_spr5000_storage_enable(
    Z6IIBA2SPR5000StorageCandidate *,const char *enable_basis);
/* Selector must equal the full uint32 value 0x5000. Every other selector returns
 * UNKNOWN without accessing the object or output. Enabled reads/writes save and
 * return the uint32 verbatim; no masking, W1C or incrementing value semantics.
 * Disabled valid state returns UNKNOWN. Invalid selected state returns FAULT.
 * Failures preserve every environment byte/read output; no fallback routing. */
Z6IIBA2SPRResult z6ii_ba2_spr5000_storage_read(void *,uint32_t selector,uint32_t *value);
Z6IIBA2SPRResult z6ii_ba2_spr5000_storage_write(void *,uint32_t selector,uint32_t value);
#endif
