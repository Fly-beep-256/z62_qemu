/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef Z6II_BA2_SPR5004_5005_SNAPSHOT_CANDIDATES_H
#define Z6II_BA2_SPR5004_5005_SNAPSHOT_CANDIDATES_H
#include "ba2-core7494.h"
/* Original D895 reads 5005, D89B reads 5004, D8A1 rereads 5005, then compares
 * the two 5005 observations. This proves local paired sampling only, not clock,
 * device purpose, silicon reset values, latch, tick, IRQ or write semantics.
 * Two separate caller-owned, default-disabled raw32 read-only snapshots follow.
 * Explicit initial value+basis and separate enable+basis are required for each.
 * Basis strings stay alive; caller exclusively owns each state.
 * All writes are UNKNOWN, including the named selector; no fallback routing. */
typedef struct {
    uint32_t value;
    uint64_t reads; /* Diagnostic successful reads only; no clock/tick meaning. */
    bool initialized,enabled;
    const char *initial_basis,*enable_basis;
} Z6IIBA2SPR5004SnapshotCandidate;
/* Init preserves all bytes on invalid args and stays disabled on success. */
Z6IIBA2SPRResult z6ii_ba2_spr5004_snapshot_init(
    Z6IIBA2SPR5004SnapshotCandidate *,uint32_t initial_value,const char *initial_basis);
/* Separate opt-in; preserves value/read count and cannot clear CPU halt. */
Z6IIBA2SPRResult z6ii_ba2_spr5004_snapshot_enable(
    Z6IIBA2SPR5004SnapshotCandidate *,const char *enable_basis);
/* Only full uint32 selector 0x5004 is admitted; others UNKNOWN before state/output
 * access. Selected invalid state FAULT; initialized disabled state UNKNOWN.
 * Enabled reads return the exact caller value unchanged across repeated reads.
 * Failures preserve state/output. Mapping to hardware remains unverified. */
Z6IIBA2SPRResult z6ii_ba2_spr5004_snapshot_read(void *,uint32_t selector,uint32_t *value);
/* Every selector/write is UNKNOWN without state access or any side effect. */
Z6IIBA2SPRResult z6ii_ba2_spr5004_snapshot_write(void *,uint32_t selector,uint32_t value);

typedef struct {
    uint32_t value;
    uint64_t reads; /* Diagnostic successful reads only; no clock/tick meaning. */
    bool initialized,enabled;
    const char *initial_basis,*enable_basis;
} Z6IIBA2SPR5005SnapshotCandidate;
/* Init preserves all bytes on invalid args and stays disabled on success. */
Z6IIBA2SPRResult z6ii_ba2_spr5005_snapshot_init(
    Z6IIBA2SPR5005SnapshotCandidate *,uint32_t initial_value,const char *initial_basis);
/* Separate opt-in; preserves value/read count and cannot clear CPU halt. */
Z6IIBA2SPRResult z6ii_ba2_spr5005_snapshot_enable(
    Z6IIBA2SPR5005SnapshotCandidate *,const char *enable_basis);
/* Only full uint32 selector 0x5005 is admitted; others UNKNOWN before state/output
 * access. Selected invalid state FAULT; initialized disabled state UNKNOWN.
 * Enabled reads return the exact caller value unchanged across repeated reads.
 * Failures preserve state/output. Mapping to hardware remains unverified. */
Z6IIBA2SPRResult z6ii_ba2_spr5005_snapshot_read(void *,uint32_t selector,uint32_t *value);
/* Every selector/write is UNKNOWN without state access or any side effect. */
Z6IIBA2SPRResult z6ii_ba2_spr5005_snapshot_write(void *,uint32_t selector,uint32_t value);

#endif
