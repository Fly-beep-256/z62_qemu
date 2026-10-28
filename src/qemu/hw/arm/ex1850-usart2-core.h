/* SPDX-License-Identifier: GPL-2.0-or-later */
/* STM32F412 USART2 asynchronous register and frame model (RM0402 USART).
 * One PCLK for TDR->shift is a declared functional timing policy. Frame
 * duration follows BRR/OVER8, M and STOP, not a host sleep or HAL callback.
 * Received words must be explicitly supplied; TX never invents RX data.
 * Synchronous/IrDA/LIN/smartcard/CTS-gated transmission remains bounded.
 */
#ifndef EX1850_USART2_CORE_H
#define EX1850_USART2_CORE_H
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>

#define EX1850_U2_RXNE UINT32_C(0x20)
#define EX1850_U2_TC UINT32_C(0x40)
#define EX1850_U2_TXE UINT32_C(0x80)
#define EX1850_U2_UE UINT32_C(0x2000)
#define EX1850_U2_TE UINT32_C(8)
#define EX1850_U2_RE UINT32_C(4)
#define EX1850_U2_Q UINT64_C(1000000000)

typedef struct EX1850USART2 {
    uint32_t sr, brr, cr1, cr2, cr3, gtpr;
    uint16_t rx_word, buffer_word, shift_word;
    bool clock_enabled, reset_held, sr_read, buffer_full, shifting;
    bool preamble_pending;
    uint32_t pclk_hz;
    uint64_t move_remaining, shift_remaining, preamble_remaining;
    uint64_t tx_accepted, tx_completed, rx_supplied, rx_overruns;
    int64_t epoch;
} EX1850USART2;

typedef void (*EX1850USART2Transmit)(void *opaque, int64_t now, uint16_t word);

static inline void ex1850_usart2_reset(EX1850USART2 *u, int64_t now)
{
    bool enabled = u->clock_enabled, held = u->reset_held;
    uint32_t pclk = u->pclk_hz;
    memset(u, 0, sizeof(*u));
    u->sr = EX1850_U2_TC | EX1850_U2_TXE;
    u->clock_enabled = enabled;
    u->reset_held = held;
    u->pclk_hz = pclk;
    u->epoch = now;
}

static inline bool ex1850_usart2_running(const EX1850USART2 *u)
{
    return u->clock_enabled && !u->reset_held && u->pclk_hz &&
           (u->cr1 & EX1850_U2_UE);
}

static inline bool ex1850_usart2_irq(const EX1850USART2 *u)
{
    if (!ex1850_usart2_running(u)) { return false; }
    return (u->sr & u->cr1 & (EX1850_U2_TXE | EX1850_U2_TC |
                             EX1850_U2_RXNE | UINT32_C(0x10))) ||
           ((u->sr & 1) && (u->cr1 & 0x100)) ||
           ((u->sr & 8) && (u->cr1 & 0x20)) ||
           ((u->sr & 0x0e) && (u->cr3 & 1)) ||
           ((u->sr & 0x100) && (u->cr2 & 0x40)) ||
           ((u->sr & 0x200) && (u->cr3 & 0x400));
}

static inline uint32_t ex1850_usart2_divider(const EX1850USART2 *u)
{
    return (u->cr1 & 0x8000) ? ((u->brr >> 4) * 8 + (u->brr & 7)) : u->brr;
}

static inline uint64_t ex1850_usart2_frame(const EX1850USART2 *u)
{
    static const unsigned stop_halfbits[] = {2, 1, 4, 3};
    /* M counts the parity position when PCE is enabled: it does not add
     * a tenth data/parity bit to an M=1 frame. */
    unsigned bits = (u->cr1 & 0x1000) ? 9 : 8;
    unsigned halfbits = 2 * (1 + bits) + stop_halfbits[(u->cr2 >> 12) & 3];
    return (uint64_t)halfbits * ex1850_usart2_divider(u) * (EX1850_U2_Q / 2);
}

/* RM0402 pp753-755,794: idle frame after TE enable, including STOP,
 * preceded by the one bit-time enable delay. Neither interval is a data
 * byte: do not invoke tx(), increment data counters or manufacture TC/RX.
 * TE configured with UE=0 is armed only once UE and a valid baud are live.
 * Re-enabling UE with TE retained starts a fresh preamble (model policy).
 */
static inline bool ex1850_usart2_tx_format(const EX1850USART2 *u)
{
    return ex1850_usart2_divider(u) &&
           !((u->cr1 & 0x8000) && (u->brr & 8)) &&
           !(u->cr2 & 0x4800) && !(u->cr3 & 0x22a);
}

static inline void ex1850_usart2_preamble_arm(EX1850USART2 *u)
{
    if (u->preamble_pending && !u->preamble_remaining &&
        ex1850_usart2_running(u) && (u->cr1 & EX1850_U2_TE) &&
        ex1850_usart2_tx_format(u)) {
        u->preamble_remaining = ex1850_usart2_frame(u) +
                               (uint64_t)ex1850_usart2_divider(u) * EX1850_U2_Q;
    }
}

static inline int64_t ex1850_usart2_deadline(const EX1850USART2 *u)
{
    if (!ex1850_usart2_running(u)) { return -1; }
    uint64_t remaining = u->move_remaining;
    if (u->shift_remaining && (!remaining || u->shift_remaining < remaining)) {
        remaining = u->shift_remaining;
    }
    if (u->preamble_remaining && (!remaining || u->preamble_remaining < remaining)) {
        remaining = u->preamble_remaining;
    }
    if (!remaining) { return -1; }
    uint64_t delta = (remaining + u->pclk_hz - 1) / u->pclk_hz;
    return delta > (uint64_t)(INT64_MAX - u->epoch) ? -1 : u->epoch + delta;
}

static inline bool ex1850_usart2_advance(EX1850USART2 *u, int64_t now,
                                        EX1850USART2Transmit tx, void *opaque)
{
    if (now < u->epoch) { return false; }
    int64_t due;
    while ((due = ex1850_usart2_deadline(u)) >= 0 && due <= now) {
        uint64_t cycles = (uint64_t)(due - u->epoch) * u->pclk_hz;
        if (u->move_remaining) {
            u->move_remaining = cycles >= u->move_remaining ? 0 : u->move_remaining - cycles;
        }
        if (u->shift_remaining) {
            u->shift_remaining = cycles >= u->shift_remaining ? 0 : u->shift_remaining - cycles;
        }
        if (u->preamble_remaining) {
            u->preamble_remaining = cycles >= u->preamble_remaining ?
                                    0 : u->preamble_remaining - cycles;
        }
        u->epoch = due;
        if (u->preamble_pending && !u->preamble_remaining) {
            u->preamble_pending = false;
            if (u->buffer_full) { u->move_remaining = EX1850_U2_Q; }
        } else if (u->shifting && !u->shift_remaining) {
            u->shifting = false;
            u->tx_completed++;
            if (tx) { tx(opaque, due, u->shift_word); }
            if (u->buffer_full) { u->move_remaining = EX1850_U2_Q; }
            else { u->sr |= EX1850_U2_TC; }
        } else if (!u->preamble_pending && !u->shifting &&
                   u->buffer_full && !u->move_remaining) {
            u->shift_word = u->buffer_word;
            u->buffer_full = false;
            u->shifting = true;
            u->sr |= EX1850_U2_TXE;
            u->shift_remaining = ex1850_usart2_frame(u);
        }
    }
    if (ex1850_usart2_running(u)) {
        uint64_t elapsed = now - u->epoch;
        /* A live deadline is greater than now, so this multiplication is
         * bounded by the remaining frame/buffer cycles. No idle overflow. */
        if (u->move_remaining || u->shift_remaining || u->preamble_remaining) {
            uint64_t cycles = elapsed * u->pclk_hz;
            if (u->move_remaining) { u->move_remaining -= cycles; }
            if (u->shift_remaining) { u->shift_remaining -= cycles; }
            if (u->preamble_remaining) { u->preamble_remaining -= cycles; }
        }
    }
    u->epoch = now;
    return true;
}

/* Caller advances the old clock before changing RCC. Remaining cycle
 * fractions survive gate-off and resume; peripheral reset cancels frames. */
static inline void ex1850_usart2_clocks(EX1850USART2 *u, uint32_t pclk,
                                       bool enabled, bool held, int64_t now)
{
    if (held && !u->reset_held) { ex1850_usart2_reset(u, now); }
    u->pclk_hz = pclk;
    u->clock_enabled = enabled;
    u->reset_held = held;
    u->epoch = now;
    ex1850_usart2_preamble_arm(u);
}

static inline bool ex1850_usart2_receive(EX1850USART2 *u, uint16_t word,
                                        uint32_t error_flags)
{
    if (word > 0x1ff || (error_flags & ~UINT32_C(0xf))) { return false; }
    if (!ex1850_usart2_running(u) || !(u->cr1 & EX1850_U2_RE)) { return true; }
    u->rx_supplied++;
    if (u->sr & EX1850_U2_RXNE) {
        u->sr |= 8;
        u->rx_overruns++;
    } else {
        u->rx_word = word & ((u->cr1 & 0x1000) ? 0x1ff : 0xff);
        u->sr |= EX1850_U2_RXNE | error_flags;
    }
    return true;
}

static inline bool ex1850_usart2_access(EX1850USART2 *u, uint32_t offset,
                                       unsigned size, bool write, uint32_t *value)
{
    if (!value || (offset & 3) || offset > 0x18 ||
        (size != 1 && size != 2 && size != 4)) { return false; }
    uint32_t access_mask = size == 4 ? UINT32_MAX : (UINT32_C(1) << (8 * size)) - 1;
    if (write && (*value & ~access_mask)) { return false; }
    if (!u->clock_enabled || u->reset_held) {
        if (!write) { *value = 0; }
        return true;
    }
    if (offset == 0) {
        if (!write) { *value = u->sr & access_mask; u->sr_read = true; }
        else { u->sr &= ~((~*value) & access_mask & UINT32_C(0x360)); }
        return true;
    }
    if (offset == 4) {
        if (!write) {
            *value = u->rx_word & access_mask;
            u->sr &= ~EX1850_U2_RXNE;
            if (u->sr_read) { u->sr &= ~UINT32_C(0x1f); }
        } else {
            if (*value > 0x1ff || !ex1850_usart2_running(u) ||
                !(u->cr1 & EX1850_U2_TE) || u->buffer_full ||
                !ex1850_usart2_tx_format(u)) { return false; }
            unsigned bits = ((u->cr1 & 0x1000) ? 9 : 8) - !!(u->cr1 & 0x400);
            u->buffer_word = *value & ((1U << bits) - 1);
            u->buffer_full = true;
            u->sr &= ~EX1850_U2_TXE;
            if (u->sr_read) { u->sr &= ~EX1850_U2_TC; }
            if (!u->shifting && !u->preamble_pending) {
                u->move_remaining = EX1850_U2_Q;
            }
            u->tx_accepted++;
        }
        u->sr_read = false;
        return true;
    }
    uint32_t *reg, mask;
    switch (offset) {
    case 0x08: reg = &u->brr; mask = 0xffff; break;
    case 0x0c: reg = &u->cr1; mask = 0xbfff; break;
    case 0x10: reg = &u->cr2; mask = 0x7f6f; break;
    case 0x14: reg = &u->cr3; mask = 0xfff; break;
    case 0x18: reg = &u->gtpr; mask = 0xffff; break;
    default: return false;
    }
    if (!write) { *value = *reg & access_mask; return true; }
    uint32_t merged = (*reg & ~access_mask) | *value;
    if (merged & ~mask) { return false; }
    if ((u->buffer_full || u->shifting) &&
        ((offset == 8 && merged != *reg) ||
         (offset == 0x0c && ((merged ^ *reg) & 0xb60b)) ||
         (offset == 0x10 && ((merged ^ *reg) & 0x7800)) ||
         (offset == 0x14 && ((merged ^ *reg) & 0x22a)))) { return false; }
    /* This byte-level model still rejects TE/UE/format mutations while
     * real data is buffered or shifting. It does not model a mid-data TE
     * pulse or claim to recover the data loss warned of in RM0402 p753.
     * Keep the active idle interval's baud/format fixed; disabling an idle
     * transmitter with no buffered data cancels that interval only.
     */
    if (u->preamble_remaining &&
        ((offset == 8 && merged != *reg) ||
         (offset == 0x0c && ((merged ^ *reg) & 0x9603)) ||
         (offset == 0x10 && ((merged ^ *reg) & 0x7800)) ||
         (offset == 0x14 && ((merged ^ *reg) & 0x22a)))) { return false; }
    uint32_t previous = *reg;
    *reg = merged;
    if (offset == 0x0c && ((merged ^ previous) & (EX1850_U2_UE | EX1850_U2_TE))) {
        if (!(merged & EX1850_U2_TE) || !(merged & EX1850_U2_UE)) {
            u->preamble_remaining = 0;
            u->preamble_pending = !!(merged & EX1850_U2_TE);
        } else {
            u->preamble_pending = true;
        }
    }
    ex1850_usart2_preamble_arm(u);
    return true;
}
#endif
