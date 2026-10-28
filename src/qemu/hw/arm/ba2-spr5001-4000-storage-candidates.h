/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef Z6II_BA2_SPR5001_4000_STORAGE_CANDIDATES_H
#define Z6II_BA2_SPR5001_4000_STORAGE_CANDIDATES_H
#include "ba2-core7494.h"
/* Two independent caller-owned opt-in raw32 software states. Each initial value
 * and basis must be supplied explicitly; default disabled. Neither selector has
 * a source-certified silicon contract. No clock, IRQ, W1C, Ready or protocol
 * effects. Basis strings must remain alive; callers exclusively own each state.
 * No generic array, bank fallback, alias mask or implicit environment routing. */
typedef struct {
    uint32_t value;
    uint64_t reads,writes; /* Successful software accesses, not hardware ticks. */
    bool initialized,enabled;
    const char *initial_basis,*enable_basis;
} Z6IIBA2SPR5001StorageCandidate;
/* Initial value and nonempty basis are mandatory. Initialization stays disabled.
 * Invalid arguments preserve the entire object. No implicit silicon reset value. */
Z6IIBA2SPRResult z6ii_ba2_spr5001_storage_init(
    Z6IIBA2SPR5001StorageCandidate *,uint32_t initial_value,const char *initial_basis);
/* Independent explicit opt-in. Preserves value/counters and cannot clear CPU halt.
 * Invalid arguments/uninitialized object preserve the entire object. */
Z6IIBA2SPRResult z6ii_ba2_spr5001_storage_enable(
    Z6IIBA2SPR5001StorageCandidate *,const char *enable_basis);
/* Selector must equal the full uint32 value 0x5001. Every other selector returns
 * UNKNOWN without accessing the object or output. Enabled reads/writes save and
 * return the uint32 verbatim; no masking, W1C or incrementing value semantics.
 * Disabled valid state returns UNKNOWN. Invalid selected state returns FAULT.
 * Failures preserve every environment byte/read output; no fallback routing. */
Z6IIBA2SPRResult z6ii_ba2_spr5001_storage_read(void *,uint32_t selector,uint32_t *value);
Z6IIBA2SPRResult z6ii_ba2_spr5001_storage_write(void *,uint32_t selector,uint32_t value);

typedef struct {
    uint32_t value;
    uint64_t reads,writes; /* Successful software accesses, not hardware ticks. */
    bool initialized,enabled;
    const char *initial_basis,*enable_basis;
} Z6IIBA2SPR4000StorageCandidate;
/* Initial value and nonempty basis are mandatory. Initialization stays disabled.
 * Invalid arguments preserve the entire object. No implicit silicon reset value. */
Z6IIBA2SPRResult z6ii_ba2_spr4000_storage_init(
    Z6IIBA2SPR4000StorageCandidate *,uint32_t initial_value,const char *initial_basis);
/* Independent explicit opt-in. Preserves value/counters and cannot clear CPU halt.
 * Invalid arguments/uninitialized object preserve the entire object. */
Z6IIBA2SPRResult z6ii_ba2_spr4000_storage_enable(
    Z6IIBA2SPR4000StorageCandidate *,const char *enable_basis);
/* Selector must equal the full uint32 value 0x4000. Every other selector returns
 * UNKNOWN without accessing the object or output. Enabled reads/writes save and
 * return the uint32 verbatim; no masking, W1C or incrementing value semantics.
 * Disabled valid state returns UNKNOWN. Invalid selected state returns FAULT.
 * Failures preserve every environment byte/read output; no fallback routing. */
Z6IIBA2SPRResult z6ii_ba2_spr4000_storage_read(void *,uint32_t selector,uint32_t *value);
Z6IIBA2SPRResult z6ii_ba2_spr4000_storage_write(void *,uint32_t selector,uint32_t value);

#endif
