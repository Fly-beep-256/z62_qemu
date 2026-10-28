/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef Z6II_BA2_STARTUP_BRIDGE137_H
#define Z6II_BA2_STARTUP_BRIDGE137_H
#include "ba2-controller136.h"
#include "ba2-core7494.h"

#define Z6II_BA2_STARTUP_BRIDGE137_BASE UINT32_C(0x80010000)
#define Z6II_BA2_STARTUP_BRIDGE137_BYTES UINT32_C(0x524)
#define Z6II_BA2_STARTUP_BRIDGE137_CONFIG_BASE UINT32_C(0x80010400)
#define Z6II_BA2_STARTUP_BRIDGE137_POLICY "original-startup-mmio-candidate-v1"
#define Z6II_BA2_STARTUP_BRIDGE137_SPR UINT32_C(0x4800)
#define Z6II_BA2_STARTUP_BRIDGE137_CONFIG_COUNT 9u
#define Z6II_BA2_STARTUP_BRIDGE137_TRANSACTION_CONFIG_COUNT 29u

struct Z6IIBA2Engine140;

/* Explicit startup-device candidate, not a silicon contract. The only FIFO
 * owner is the existing Master. Window reads map active[0..3] to +7C/80/84/88
 * as two pointer/length pairs; original BA2 reads +84,+88,+7C,+80. The +88
 * value is read then overwritten in this prefix, so its use is not verified.
 * Never expose staging or synthesize a valid zero window. A later open Master
 * transaction leaves the previous committed active window visible.
 *
 * +90=2 starts a local reset: one read sees busy=2, the next sees busy=0.
 * Busy timing is an explicit polling candidate. Reset affects only these nine
 * local configuration latches, never a FIFO, window, guest RAM or IRQ event.
 * +78 accepts only original idle write=1 after enable. It records a local
 * request without advancing time, sleeping the host, changing FIFO, or raising
 * IRQ. Readback and other values remain unsupported.
 * Original configuration values are latched verbatim. +90=1 is enable storage;
 * it performs no DMA, reply or completion. SPR4800 is independent caller-
 * initialized raw32 storage, with no inferred local IRQ-mask semantics.
 *
 * The separate transaction-config opt-in covers 29 exact write addresses: original
 * 4000BAB4..4000BC94 and the same transaction event task's 8001005C. It stores raw32 values without a
 * hardware effect. Only 80010050 and 8001041C have readback, after an actual modeled write,
 * for original 4000BBA2 / 4000962C read/modify/write. Other reads remain
 * unmapped; in particular completion status 800104BC has no fallback.
 * Global model reset clears this storage; +90 reset affects only the original
 * nine startup latches. No reset, DMA, IRQ, Ready or reply is inferred for the
 * added hardware block. An unset opt-in never accepts transaction writes.
 *
 * Caller holds the same exclusive/BQL ownership as controller136 and keeps
 * pointer bindings stable. IRQ query delegates the controller level unchanged.
 */
typedef struct Z6IIBA2StartupBridge137 {
    Z6IIBA2Controller136 *controller;
    Z6IIIPU2402 *master;
    struct Z6IIBA2Engine140 *engine; /* Optional, no borrowed RAM pointers. */
    const char *policy;
    const char *basis;
    uint32_t config[Z6II_BA2_STARTUP_BRIDGE137_CONFIG_COUNT];
    uint32_t config_written;
    const char *transaction_config_basis;
    uint32_t transaction_config[Z6II_BA2_STARTUP_BRIDGE137_TRANSACTION_CONFIG_COUNT];
    uint32_t transaction_config_written;
    uint64_t transaction_config_writes;
    uint64_t transaction_config_reads;
    uint32_t control;
    uint32_t idle_request;
    uint64_t idle_requests;
    unsigned reset_busy_reads;
    uint32_t spr4800_initial;
    uint32_t spr4800;
    bool reset_completed;
    bool initialized;
    uint64_t reset_transactions;
    uint64_t reset_busy_observations;
    uint64_t reset_completions;
    uint64_t enable_writes;
    uint64_t window_reads;
    uint64_t spr_reads;
    uint64_t spr_writes;
} Z6IIBA2StartupBridge137;

Z6IIBA2BusResult z6ii_ba2_startup_bridge137_init(Z6IIBA2StartupBridge137 *,
    Z6IIBA2Controller136 *, Z6IIIPU2402 *, const char *policy,
    uint32_t caller_spr4800_initial, const char *nonempty_basis);
void z6ii_ba2_startup_bridge137_reset(Z6IIBA2StartupBridge137 *);
Z6IIBA2BusResult z6ii_ba2_startup_bridge137_enable_transaction_config_candidate(
    Z6IIBA2StartupBridge137 *, const char *nonempty_basis);
bool z6ii_ba2_startup_bridge137_invariant(const Z6IIBA2StartupBridge137 *);
Z6IIBA2BusResult z6ii_ba2_startup_bridge137_read(void *, uint32_t, unsigned,
                                             uint32_t *);
Z6IIBA2BusResult z6ii_ba2_startup_bridge137_write(void *, uint32_t, unsigned,
                                              uint32_t);
Z6IIBA2SPRResult z6ii_ba2_startup_bridge137_spr_read(void *, uint32_t,
                                                uint32_t *);
Z6IIBA2SPRResult z6ii_ba2_startup_bridge137_spr_write(void *, uint32_t,
                                                 uint32_t);
bool z6ii_ba2_startup_bridge137_irq(void *);
/* Original SPR4802 source bits: bit1=FIFO, bit0=104xx engine. */
uint32_t z6ii_ba2_startup_bridge137_irq_sources(void *);
#endif
