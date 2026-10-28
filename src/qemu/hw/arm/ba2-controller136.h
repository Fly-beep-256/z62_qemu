/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef Z6II_BA2_CONTROLLER136_H
#define Z6II_BA2_CONTROLLER136_H
#include "ba2-bus77.h"

#define Z6II_BA2_CONTROLLER136_BASE UINT32_C(0x80010500)
#define Z6II_BA2_CONTROLLER136_BYTES UINT32_C(0x24)
#define Z6II_BA2_CONTROLLER136_POLICY "original-triplet-fifo-candidate-v1"

/* Opt-in transport model. Original BA2 accesses establish the register shape,
 * init values and three-word commit. External wiring, word-pop timing and
 * silicon IRQ behavior remain explicit candidates. No command interpretation,
 * guest-address dereference, protocol reply or processing completion occurs.
 *
 * Master owns both directional FIFOs. +00 takes one committed Master TX frame
 * through the existing bus API on the first read, returning one word and
 * retaining two words locally. +04 only stages BA2 output; +08=2 or the original response value3 atomically
 * pushes all three unchanged words to Master RX through the existing bus API.
 * Configuration, reset, IRQ query and ACK never take or push a frame.
 *
 * Caller holds BQL/exclusive access, keeps the named bus/FIFO configuration
 * stable, and does not reenter this model from master_irq_update. The existing
 * callback must update only the Master IRQ line, after an actual FIFO action.
 */
typedef struct {
    Z6IIBA2Bus *bus;
    Z6IIIPU2402 *master;
    const char *policy;
    const char *basis;
    uint32_t threshold_config;
    uint32_t interrupt_mask;
    uint32_t control;
    uint32_t event_latch;
    uint32_t rx_frame[3];
    uint32_t tx_stage[3];
    unsigned rx_next; /* 3 means no retained input words. */
    unsigned tx_staged;
    bool threshold_configured;
    bool initialized;
    uint64_t rx_frames_taken;
    uint64_t rx_read_words;
    uint64_t rx_acknowledgements;
    uint64_t tx_word_writes;
    uint64_t tx_frames_committed;
    uint64_t reset_discarded_rx_words;
    uint64_t reset_discarded_tx_words;
} Z6IIBA2Controller136;

/* Call after bus_init on fresh storage (or after an explicit lifecycle reset).
 * Requires policy above, nonempty provenance, present fifo-v1 signature100,
 * an invariant-valid Master FIFO and its IRQ update callback. Does not modify
 * the bus or Master FIFO; missing policy keeps this model uninitialized. */
Z6IIBA2BusResult z6ii_ba2_controller136_init(Z6IIBA2Controller136 *,
    Z6IIBA2Bus *, const char *policy, const char *nonempty_basis);

/* Explicit local lifecycle reset. Clears only local controls/staging/cache;
 * cumulative counters record any abandoned local words. Master FIFO reset is
 * exclusively its owner's job. Does not inject an IRQ event or message. */
void z6ii_ba2_controller136_reset(Z6IIBA2Controller136 *);

/* Absolute addresses, aligned 32-bit accesses only. Invalid accesses and
 * empty/full/incomplete transactions fail without changing output or logical
 * FIFO/staging state. Unknown control/threshold values fail visibly.
 * +20 accepts only original BA2 value0 and remains a plain readback latch. */
Z6IIBA2BusResult z6ii_ba2_controller136_read(void *, uint32_t, unsigned,
                                          uint32_t *);
Z6IIBA2BusResult z6ii_ba2_controller136_write(void *, uint32_t, unsigned,
                                           uint32_t);
uint32_t z6ii_ba2_controller136_raw(const Z6IIBA2Controller136 *);
bool z6ii_ba2_controller136_irq(void *);
bool z6ii_ba2_controller136_invariant(const Z6IIBA2Controller136 *);
#endif
