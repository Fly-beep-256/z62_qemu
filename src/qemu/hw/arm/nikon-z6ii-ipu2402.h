#ifndef Z6II_IPU2402_H
#define Z6II_IPU2402_H

#include <stdbool.h>
#include <stdint.h>

/* Original Master 102427D0/10242CBE uses three opaque message words.
 * 32 FIFO words, RX-ready bit0, TX-space bit2 and read-pop/W1C semantics
 * are explicit fifo-v1 model choices, not hardware measurements.
 * This core never interprets a command or fabricates a peer reply. */
#define Z6II_IPU2402_WORDS 32u
#define Z6II_IPU2402_FRAME_WORDS 3u
#define Z6II_IPU2402_RX_READY UINT32_C(1)
#define Z6II_IPU2402_TX_SPACE UINT32_C(4)

typedef enum {
    Z6II_IPU2402_OK = 0,
    Z6II_IPU2402_BAD_ACCESS,
    Z6II_IPU2402_FULL,
    Z6II_IPU2402_EMPTY,
    Z6II_IPU2402_INCOMPLETE,
    Z6II_IPU2402_BAD_SEQUENCE
} Z6IIIPU2402Result;

typedef struct {
    uint32_t words[Z6II_IPU2402_WORDS];
    unsigned head;
    unsigned count;
} Z6IIIPU2402FIFO;

typedef struct {
    Z6IIIPU2402FIFO tx;
    Z6IIIPU2402FIFO rx;
    unsigned tx_committed;
    unsigned tx_staged;
    uint32_t signature;
    uint32_t threshold_config;
    uint32_t event_latch;
    uint32_t interrupt_mask;
    uint32_t control;
    uint32_t window_stage[4];
    uint32_t window_active[4];
    unsigned window_written;
    bool window_open;
    bool window_valid;
    bool threshold_configured;
    uint64_t tx_frames;
    uint64_t tx_peer_frames;
    uint64_t rx_words;
    uint64_t rx_read_words;
    uint64_t rx_acknowledgements;
    uint64_t window_commits;
} Z6IIIPU2402;

/* signature=0 keeps the endpoint absent; 0x100 declares a present FIFO
 * interface only. No processing engine or completion is implied. */
void z6ii_ipu2402_init(Z6IIIPU2402 *s, uint32_t signature);
void z6ii_ipu2402_reset(Z6IIIPU2402 *s);
uint32_t z6ii_ipu2402_raw(const Z6IIIPU2402 *s);
bool z6ii_ipu2402_irq(const Z6IIIPU2402 *s);
Z6IIIPU2402Result z6ii_ipu2402_read(Z6IIIPU2402 *s, uint32_t offset,
                                  unsigned size, uint32_t *value);
Z6IIIPU2402Result z6ii_ipu2402_write(Z6IIIPU2402 *s, uint32_t offset,
                                   unsigned size, uint32_t value);

/* Called only by a separately identified peer/fixture. Arguments remain
 * opaque guest addresses; this core has no access to guest RAM. */
Z6IIIPU2402Result z6ii_ipu2402_peer_take_tx(Z6IIIPU2402 *s, uint32_t frame[3]);
Z6IIIPU2402Result z6ii_ipu2402_peer_push_rx(Z6IIIPU2402 *s,
                                         const uint32_t *words, unsigned count);
void z6ii_ipu2402_peer_raise(Z6IIIPU2402 *s, uint32_t events);
bool z6ii_ipu2402_invariant(const Z6IIIPU2402 *s);

#endif
