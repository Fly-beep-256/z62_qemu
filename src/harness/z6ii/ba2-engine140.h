/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef Z6II_BA2_ENGINE140_H
#define Z6II_BA2_ENGINE140_H
#include "ba2-bus77.h"

#define Z6II_BA2_ENGINE140_POLICY "startup-mode9-descriptor-candidate-v1"
#define Z6II_BA2_ENGINE140_DONE UINT32_C(0x40)
#define Z6II_BA2_ENGINE140_OPAQUE_POLICY "opaque-buffer-copy-synthetic-v1"
#define Z6II_BA2_ENGINE140_OPAQUE_BYTES UINT32_C(0x2800)
struct Z6IIBA2StartupBridge137;

typedef enum {
    Z6II_BA2_ENGINE140_REJECT_NONE = 0,
    Z6II_BA2_ENGINE140_REJECT_STATE,
    Z6II_BA2_ENGINE140_REJECT_INCOMPLETE,
    Z6II_BA2_ENGINE140_REJECT_MODE,
    Z6II_BA2_ENGINE140_REJECT_DESCRIPTOR,
    Z6II_BA2_ENGINE140_REJECT_WINDOW,
    Z6II_BA2_ENGINE140_REJECT_FORMAT,
    Z6II_BA2_ENGINE140_REJECT_SPAN,
    Z6II_BA2_ENGINE140_REJECT_ALIAS
} Z6IIBA2Engine140Reject;

/* State holds no borrowed payload/RAM spans. Submission is synchronous inside
 * the caller's exclusive/BQL window binding. It must validate every input and
 * output byte before a transform and commit phase; only a successful data
 * commit may set DONE. Unsupported packing is a hard rejection, never a
 * timer/start-triggered completion or fabricated protocol result.
 *
 * This candidate currently knows the original mode9 descriptor and additive
 * addresses, but its packing/byte extents remain unverified. Consequently it
 * rejects that submission with REJECT_FORMAT and does not write RAM or DONE.
 * An explicitly enabled opaque-buffer-copy-synthetic-v1 diagnostic backend
 * may copy exactly the caller-declared 0x2800 bytes for this descriptor. That
 * is an artificial byte-transfer policy, not a mode9 packing or DMA extent
 * assertion. It writes actual bounded data before raw DONE, and routes the
 * original ISR/ACK/callback without host writes to guest business flags.
 */
typedef struct Z6IIBA2Engine140 {
    Z6IIBA2Bus *bus;
    struct Z6IIBA2StartupBridge137 *bridge;
    const char *basis;
    bool initialized;
    const char *opaque_policy, *opaque_basis;
    uint32_t opaque_bytes;
    uint32_t raw;
    Z6IIBA2Engine140Reject last_reject;
    uint32_t source_cpu, destination_cpu;
    uint64_t submissions, completions, rejected;
    uint64_t raw_reads, w1c_writes, completed_acks, resets;
    uint64_t transferred_bytes;
} Z6IIBA2Engine140;

Z6IIBA2BusResult z6ii_ba2_engine140_init(Z6IIBA2Engine140 *,
    Z6IIBA2Bus *, struct Z6IIBA2StartupBridge137 *, const char *basis);
bool z6ii_ba2_engine140_invariant(const Z6IIBA2Engine140 *);
/* No implicit enable: default init rejects unknown packing. Exact policy,
 * byte count and nonempty declaration are mandatory for artificial transfer. */
Z6IIBA2BusResult z6ii_ba2_engine140_enable_opaque_synthetic(
    Z6IIBA2Engine140 *,const char *policy,uint32_t caller_bytes,
    const char *nonempty_basis);
void z6ii_ba2_engine140_reset(Z6IIBA2Engine140 *);
Z6IIBA2BusResult z6ii_ba2_engine140_submit(Z6IIBA2Engine140 *, uint32_t);
Z6IIBA2BusResult z6ii_ba2_engine140_read_raw(Z6IIBA2Engine140 *, uint32_t *);
Z6IIBA2BusResult z6ii_ba2_engine140_ack(Z6IIBA2Engine140 *, uint32_t);
bool z6ii_ba2_engine140_level(const Z6IIBA2Engine140 *);
#endif
