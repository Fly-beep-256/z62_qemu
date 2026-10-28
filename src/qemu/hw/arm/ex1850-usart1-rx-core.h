/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Explicit clean async byte stream, serialized at the guest's BRR/PCLK.
 * This is a functional line hypothesis, not sampled battery data. Host
 * bytes contain no parity/error metadata. Queued/in-flight input is lost
 * on disconnect, reset, receiver/clock disable or format/clock change.
 * TX has an independent shifter and never calls the receive interface. */
#ifndef EX1850_USART1_RX_CORE_H
#define EX1850_USART1_RX_CORE_H
#include "ex1850-usart2-core.h"
#define EX1850_U1_RX_CAPACITY 256

typedef struct EX1850USART1Rx {
    uint8_t bytes[EX1850_U1_RX_CAPACITY];
    unsigned head, count;
    int64_t due;
    uint32_t pclk, brr, cr1_format, cr2_format, cr3_format;
    uint64_t admitted, completed, discarded;
} EX1850USART1Rx;

static inline void ex1850_usart1_rx_reset(EX1850USART1Rx *r)
{
    memset(r, 0, sizeof(*r));
    r->due = -1;
}

static inline unsigned ex1850_usart1_rx_cancel(EX1850USART1Rx *r)
{
    unsigned lost = r->count;
    r->discarded += lost;
    r->head = r->count = 0;
    r->due = -1;
    return lost;
}

static inline bool ex1850_usart1_rx_enabled(const EX1850USART2 *u)
{
    return ex1850_usart2_running(u) && (u->cr1 & EX1850_U2_RE);
}

static inline bool ex1850_usart1_rx_supported(const EX1850USART2 *u)
{
    unsigned data = ((u->cr1 & 0x1000) ? 9 : 8) - !!(u->cr1 & 0x400);
    return data <= 8 && ex1850_usart2_divider(u) &&
           !((u->cr1 & 0x8000) && (u->brr & 8)) &&
           !(u->cr1 & 0x12) && !(u->cr2 & 0x4800) && !(u->cr3 & 0x26a);
}

static inline bool ex1850_usart1_rx_config_matches(const EX1850USART1Rx *r,
                                                  const EX1850USART2 *u)
{
    return ex1850_usart1_rx_enabled(u) && ex1850_usart1_rx_supported(u) &&
           u->pclk_hz == r->pclk &&
           u->brr == r->brr && (u->cr1 & 0xb604) == r->cr1_format &&
           (u->cr2 & 0x7800) == r->cr2_format &&
           (u->cr3 & 0x26a) == r->cr3_format;
}

static inline unsigned ex1850_usart1_rx_reconcile(EX1850USART1Rx *r,
                                                const EX1850USART2 *u)
{
    return r->count && !ex1850_usart1_rx_config_matches(r, u) ?
           ex1850_usart1_rx_cancel(r) : 0;
}

static inline bool ex1850_usart1_rx_arm(EX1850USART1Rx *r,
                                       const EX1850USART2 *u, int64_t now)
{
    uint64_t ns = (ex1850_usart2_frame(u) + u->pclk_hz - 1) / u->pclk_hz;
    if (!ns || now < 0 || ns > (uint64_t)(INT64_MAX - now)) { return false; }
    r->pclk = u->pclk_hz;
    r->brr = u->brr;
    r->cr1_format = u->cr1 & 0xb604;
    r->cr2_format = u->cr2 & 0x7800;
    r->cr3_format = u->cr3 & 0x26a;
    r->due = now + ns;
    return true;
}

static inline bool ex1850_usart1_rx_push(EX1850USART1Rx *r,
                                        const EX1850USART2 *u,
                                        const uint8_t *bytes, unsigned length,
                                        int64_t now)
{
    if ((!bytes && length) || length > EX1850_U1_RX_CAPACITY - r->count) {
        return false;
    }
    if (!ex1850_usart1_rx_enabled(u)) { r->discarded += length; return true; }
    if (!ex1850_usart1_rx_supported(u)) { return false; }
    if (!length) { return true; }
    if (!r->count && !ex1850_usart1_rx_arm(r, u, now)) { return false; }
    for (unsigned n = 0; n < length; n++) {
        r->bytes[(r->head + r->count++) % EX1850_U1_RX_CAPACITY] = bytes[n];
    }
    r->admitted += length;
    return true;
}

static inline int64_t ex1850_usart1_rx_deadline(const EX1850USART1Rx *r)
{
    return r->count ? r->due : -1;
}

/* Call at this exact frame deadline after advancing the TX register core. */
static inline bool ex1850_usart1_rx_complete(EX1850USART1Rx *r,
                                            EX1850USART2 *u, int64_t now,
                                            uint16_t *word)
{
    if (!word || !r->count || r->due != now ||
        !ex1850_usart1_rx_config_matches(r, u)) { return false; }
    unsigned bits = ((u->cr1 & 0x1000) ? 9 : 8) - !!(u->cr1 & 0x400);
    *word = r->bytes[r->head] & ((1U << bits) - 1);
    r->head = (r->head + 1) % EX1850_U1_RX_CAPACITY;
    r->count--;
    r->completed++;
    if (!ex1850_usart2_receive(u, *word, 0)) { return false; }
    if (!r->count) { r->due = -1; return true; }
    return ex1850_usart1_rx_arm(r, u, now);
}
#endif
