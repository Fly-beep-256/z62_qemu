#include "nikon-z6ii-ipu2402.h"
#include <stddef.h>
#include <string.h>

static void fifo_push(Z6IIIPU2402FIFO *f, uint32_t word)
{
    f->words[(f->head + f->count) % Z6II_IPU2402_WORDS] = word;
    ++f->count;
}

static uint32_t fifo_pop(Z6IIIPU2402FIFO *f)
{
    uint32_t value = f->words[f->head];
    f->head = (f->head + 1u) % Z6II_IPU2402_WORDS;
    --f->count;
    return value;
}

void z6ii_ipu2402_init(Z6IIIPU2402 *s, uint32_t signature)
{
    memset(s, 0, sizeof(*s));
    s->signature = signature;
}

void z6ii_ipu2402_reset(Z6IIIPU2402 *s)
{
    uint32_t signature = s->signature;
    z6ii_ipu2402_init(s, signature);
}

uint32_t z6ii_ipu2402_raw(const Z6IIIPU2402 *s)
{
    uint32_t raw = s->event_latch;
    if (s->rx.count >= Z6II_IPU2402_FRAME_WORDS) {
        raw |= Z6II_IPU2402_RX_READY;
    }
    if (s->threshold_configured &&
        s->tx.count <= (s->threshold_config >> 8)) {
        raw |= Z6II_IPU2402_TX_SPACE;
    }
    return raw;
}

bool z6ii_ipu2402_irq(const Z6IIIPU2402 *s)
{
    return (z6ii_ipu2402_raw(s) & s->interrupt_mask) != 0;
}

Z6IIIPU2402Result z6ii_ipu2402_read(Z6IIIPU2402 *s, uint32_t offset,
                                  unsigned size, uint32_t *value)
{
    if (size != 4 || (offset & 3) != 0 || value == NULL) {
        return Z6II_IPU2402_BAD_ACCESS;
    }
    switch (offset) {
    case 0x00:
        if (s->rx.count == 0) {
            return Z6II_IPU2402_EMPTY;
        }
        *value = fifo_pop(&s->rx);
        ++s->rx_read_words;
        return Z6II_IPU2402_OK;
    case 0x0c:
        *value = (s->tx.count << 8) | s->rx.count;
        return Z6II_IPU2402_OK;
    case 0x10: *value = s->threshold_config; return Z6II_IPU2402_OK;
    case 0x14: *value = z6ii_ipu2402_raw(s); return Z6II_IPU2402_OK;
    case 0x1c: *value = s->interrupt_mask; return Z6II_IPU2402_OK;
    case 0x20: *value = s->control; return Z6II_IPU2402_OK;
    case 0x80: *value = s->signature; return Z6II_IPU2402_OK;
    case 0x84: *value = s->window_open ? 1u : 0u; return Z6II_IPU2402_OK;
    case 0x88: case 0x8c: case 0x90: case 0x94:
        *value = (s->window_open ? s->window_stage : s->window_active)[(offset - 0x88) / 4];
        return Z6II_IPU2402_OK;
    default:
        return Z6II_IPU2402_BAD_ACCESS;
    }
}

Z6IIIPU2402Result z6ii_ipu2402_write(Z6IIIPU2402 *s, uint32_t offset,
                                   unsigned size, uint32_t value)
{
    if (size != 4 || (offset & 3) != 0) {
        return Z6II_IPU2402_BAD_ACCESS;
    }
    switch (offset) {
    case 0x04:
        if (s->tx_staged == Z6II_IPU2402_FRAME_WORDS) {
            return Z6II_IPU2402_BAD_SEQUENCE;
        }
        if (s->tx.count == Z6II_IPU2402_WORDS) {
            return Z6II_IPU2402_FULL;
        }
        fifo_push(&s->tx, value);
        ++s->tx_staged;
        return Z6II_IPU2402_OK;
    case 0x08:
        if (value == 2) {
            if (s->tx_staged != Z6II_IPU2402_FRAME_WORDS) {
                return Z6II_IPU2402_INCOMPLETE;
            }
            s->tx_committed += Z6II_IPU2402_FRAME_WORDS;
            s->tx_staged = 0;
            ++s->tx_frames;
            return Z6II_IPU2402_OK;
        }
        if (value == 4) {
            /* read-pop is a declared choice; original init ACKs each word,
             * whereas the original RX worker ACKs each three-word frame. */
            ++s->rx_acknowledgements;
            return Z6II_IPU2402_OK;
        }
        return Z6II_IPU2402_BAD_ACCESS;
    case 0x10:
        if (value != 0x1d00) {
            return Z6II_IPU2402_BAD_ACCESS;
        }
        s->threshold_config = value;
        s->threshold_configured = true;
        return Z6II_IPU2402_OK;
    case 0x18:
        s->event_latch &= ~value; /* W1C: inferred from original ISR. */
        return Z6II_IPU2402_OK;
    case 0x1c:
        s->interrupt_mask = value;
        return Z6II_IPU2402_OK;
    case 0x20:
        if (value != 0x7ffff) {
            return Z6II_IPU2402_BAD_ACCESS;
        }
        s->control = value;
        return Z6II_IPU2402_OK;
    case 0x84:
        if (value == 1 && !s->window_open) {
            memcpy(s->window_stage, s->window_active, sizeof(s->window_stage));
            s->window_written = 0;
            s->window_open = true;
            return Z6II_IPU2402_OK;
        }
        if (value == 0 && s->window_open && s->window_written == 0xf) {
            memcpy(s->window_active, s->window_stage, sizeof(s->window_active));
            s->window_open = false;
            s->window_valid = true;
            ++s->window_commits;
            /* Original 10242B74 then waits for command1. A real peer must
             * provide it; a window commit never injects a completion. */
            return Z6II_IPU2402_OK;
        }
        return Z6II_IPU2402_BAD_SEQUENCE;
    case 0x88: case 0x8c: case 0x90: case 0x94:
        if (!s->window_open) {
            return Z6II_IPU2402_BAD_SEQUENCE;
        }
        s->window_stage[(offset - 0x88) / 4] = value;
        s->window_written |= 1u << ((offset - 0x88) / 4);
        return Z6II_IPU2402_OK;
    default:
        return Z6II_IPU2402_BAD_ACCESS;
    }
}

Z6IIIPU2402Result z6ii_ipu2402_peer_take_tx(Z6IIIPU2402 *s, uint32_t frame[3])
{
    unsigned i;
    if (frame == NULL) {
        return Z6II_IPU2402_BAD_ACCESS;
    }
    if (s->tx_committed < Z6II_IPU2402_FRAME_WORDS) {
        return Z6II_IPU2402_EMPTY;
    }
    for (i = 0; i < Z6II_IPU2402_FRAME_WORDS; ++i) {
        frame[i] = fifo_pop(&s->tx);
    }
    s->tx_committed -= Z6II_IPU2402_FRAME_WORDS;
    ++s->tx_peer_frames;
    return Z6II_IPU2402_OK;
}

Z6IIIPU2402Result z6ii_ipu2402_peer_push_rx(Z6IIIPU2402 *s,
                                         const uint32_t *words, unsigned count)
{
    unsigned i;
    if (words == NULL || count == 0) {
        return Z6II_IPU2402_BAD_ACCESS;
    }
    if (count > Z6II_IPU2402_WORDS - s->rx.count) {
        return Z6II_IPU2402_FULL;
    }
    for (i = 0; i < count; ++i) {
        fifo_push(&s->rx, words[i]);
    }
    s->rx_words += count;
    return Z6II_IPU2402_OK;
}

void z6ii_ipu2402_peer_raise(Z6IIIPU2402 *s, uint32_t events)
{
    s->event_latch |= events;
}

bool z6ii_ipu2402_invariant(const Z6IIIPU2402 *s)
{
    return s->tx.head < Z6II_IPU2402_WORDS && s->rx.head < Z6II_IPU2402_WORDS &&
           s->tx.count <= Z6II_IPU2402_WORDS && s->rx.count <= Z6II_IPU2402_WORDS &&
           s->tx_staged <= Z6II_IPU2402_FRAME_WORDS &&
           s->tx_committed % Z6II_IPU2402_FRAME_WORDS == 0 &&
           s->tx_committed + s->tx_staged == s->tx.count &&
           s->window_written <= 0xf &&
           s->tx_frames >= s->tx_peer_frames &&
           s->rx_words >= s->rx_read_words &&
           s->rx_words - s->rx_read_words == s->rx.count;
}
