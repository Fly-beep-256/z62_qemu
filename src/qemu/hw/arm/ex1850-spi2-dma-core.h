/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Bounded STM32F412 DMA1 Stream4/Channel0 -> SPI2 functional model,
 * plus Stream5/Channel4 USART2 RX waiting with no external receive source.
 * RM0402 pp200,213,216-224,813,819,843-845 establish mapping, gates, status
 * and W1C semantics. The one-HCLK request and one-PCLK buffer handoff are
 * explicit functional timing hypotheses, not measured silicon latency.
 * Odd-count HT occurs at ceil(initial_count/2) accepted items here; the
 * public text does not establish that rounding rule for this board.
 * MOSI comes only from the caller's real SRAM read. MISO is an unknown
 * receive token: DR may return a representative only to a proven discard
 * instruction. This core never writes guest callbacks, RTOS flags or RAM.
 */
#ifndef EX1850_SPI2_DMA_CORE_H
#define EX1850_SPI2_DMA_CORE_H
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>

#define EX1850_SPI2_TXE UINT32_C(2)
#define EX1850_SPI2_RXNE UINT32_C(1)
#define EX1850_SPI2_OVR UINT32_C(0x40)
#define EX1850_SPI2_BSY UINT32_C(0x80)
#define EX1850_DMA4_HT UINT32_C(0x10)
#define EX1850_DMA4_TC UINT32_C(0x20)
#define EX1850_DMA4_FLAGS UINT32_C(0x3d)
#define EX1850_SPI2_SPE UINT32_C(0x40)
#define EX1850_SPI2_TXDMAEN UINT32_C(2)
#define EX1850_SPI2_ERRIE UINT32_C(0x20)
#define EX1850_SPI2_RAM_BASE UINT32_C(0x20000000)
#define EX1850_SPI2_RAM_BYTES UINT32_C(0x40000)
#define EX1850_SPI2_Q UINT64_C(1000000000)

typedef struct EX1850DMAStreamControl {
    uint32_t cr, ndtr, par, m0ar, m1ar, fcr;
} EX1850DMAStreamControl;

typedef enum EX1850SPI2Event {
    EX1850_SPI2_DMA_ACCEPT,
    EX1850_SPI2_BUFFER_TO_SHIFT,
    EX1850_SPI2_SHIFT_COMPLETE,
} EX1850SPI2Event;

typedef bool (*EX1850SPI2ReadByte)(void *opaque, uint32_t address, uint8_t *byte);
typedef void (*EX1850SPI2Observe)(void *opaque, EX1850SPI2Event event,
                                int64_t now, uint32_t address, uint8_t byte);

typedef struct EX1850SPI2DMA {
    EX1850DMAStreamControl dma1[8];
    uint32_t lisr, hisr, cr1, cr2, i2scfgr, sr;
    uint32_t dma_initial, dma_accepted, dma_address;
    uint32_t hclk_hz, pclk_hz;
    bool dma_gate, spi_gate, reset_held;
    bool buffer_full, shifting, rx_unknown, ovr_dr_read;
    uint8_t buffer_byte, shift_byte;
    uint32_t buffer_address, shift_address;
    uint64_t dma_remaining, move_remaining, shift_remaining;
    uint64_t accepted_total, shifted_total, overrun_total;
    int64_t epoch;
} EX1850SPI2DMA;

static inline void ex1850_spi2_dma_reset(EX1850SPI2DMA *t)
{
    memset(t->dma1, 0, sizeof(t->dma1));
    for (unsigned n = 0; n < 8; n++) { t->dma1[n].fcr = 0x21; }
    t->lisr = t->hisr = 0;
    t->dma_initial = t->dma_accepted = t->dma_address = 0;
    t->dma_remaining = 0;
    /* Already accepted SPI data belongs to SPI, not the DMA reset domain. */
}

static inline void ex1850_spi2_peripheral_reset(EX1850SPI2DMA *t)
{
    t->cr1 = t->cr2 = t->i2scfgr = 0;
    t->sr = EX1850_SPI2_TXE;
    t->buffer_full = t->shifting = t->rx_unknown = t->ovr_dr_read = false;
    t->buffer_byte = t->shift_byte = 0;
    t->buffer_address = t->shift_address = 0;
    t->move_remaining = t->shift_remaining = t->dma_remaining = 0;
    /* SPI2 reset does not clear DMA EN, NDTR, addresses or sticky flags. */
}

static inline void ex1850_spi2_core_reset(EX1850SPI2DMA *t, int64_t now)
{
    memset(t, 0, sizeof(*t));
    t->epoch = now;
    ex1850_spi2_dma_reset(t);
    ex1850_spi2_peripheral_reset(t);
}

static inline bool ex1850_spi2_irq15(const EX1850SPI2DMA *t)
{
    uint32_t cr = t->dma1[4].cr, flags = t->hisr;
    return t->dma_gate &&
        (((flags & EX1850_DMA4_HT) && (cr & 8)) ||
         ((flags & EX1850_DMA4_TC) && (cr & 0x10)) ||
         ((flags & 8) && (cr & 4)) || ((flags & 4) && (cr & 2)) ||
         ((flags & 1) && (t->dma1[4].fcr & 0x80)));
}

static inline bool ex1850_spi2_irq36(const EX1850SPI2DMA *t)
{
    return t->spi_gate && !t->reset_held &&
        (t->cr2 & EX1850_SPI2_ERRIE) && (t->sr & EX1850_SPI2_OVR);
}

static inline bool ex1850_dma1_irq16(const EX1850SPI2DMA *t)
{
    const EX1850DMAStreamControl *d = &t->dma1[5];
    uint32_t flags = t->hisr >> 6;
    return t->dma_gate &&
        (((flags & 0x10) && (d->cr & 8)) ||
         ((flags & 0x20) && (d->cr & 0x10)) ||
         ((flags & 8) && (d->cr & 4)) || ((flags & 4) && (d->cr & 2)) ||
         ((flags & 1) && (d->fcr & 0x80)));
}

static inline bool ex1850_spi2_request(const EX1850SPI2DMA *t)
{
    return (t->dma1[4].cr & 1) && t->dma1[4].ndtr &&
           (t->cr1 & EX1850_SPI2_SPE) &&
           (t->cr2 & EX1850_SPI2_TXDMAEN) &&
           (t->sr & EX1850_SPI2_TXE);
}

static inline void ex1850_spi2_refresh(EX1850SPI2DMA *t)
{
    if (!ex1850_spi2_request(t)) { t->dma_remaining = 0; }
    else if (!t->dma_remaining) { t->dma_remaining = EX1850_SPI2_Q; }
    if (t->buffer_full && !t->shifting && (t->cr1 & EX1850_SPI2_SPE)) {
        if (!t->move_remaining) { t->move_remaining = EX1850_SPI2_Q; }
    } else { t->move_remaining = 0; }
}

static inline uint32_t ex1850_spi2_dma_hz(const EX1850SPI2DMA *t)
{
    return t->dma_gate && t->spi_gate && !t->reset_held ? t->hclk_hz : 0;
}

static inline uint32_t ex1850_spi2_serial_hz(const EX1850SPI2DMA *t)
{
    return t->spi_gate && !t->reset_held && (t->cr1 & EX1850_SPI2_SPE)
           ? t->pclk_hz : 0;
}

static inline uint64_t ex1850_spi2_delay(uint64_t remaining, uint32_t hz)
{
    return remaining && hz ? (remaining + hz - 1) / hz : UINT64_MAX;
}

static inline int64_t ex1850_spi2_deadline(const EX1850SPI2DMA *t)
{
    uint32_t dma_hz = ex1850_spi2_dma_hz(t), spi_hz = ex1850_spi2_serial_hz(t);
    uint64_t delay = ex1850_spi2_delay(t->dma_remaining, dma_hz);
    uint64_t move = ex1850_spi2_delay(t->move_remaining, spi_hz);
    uint64_t shift = ex1850_spi2_delay(t->shift_remaining, spi_hz);
    if (move < delay) { delay = move; }
    if (shift < delay) { delay = shift; }
    if (t->epoch < 0 || delay == UINT64_MAX ||
        delay > (uint64_t)(INT64_MAX - t->epoch)) { return -1; }
    return t->epoch + (int64_t)delay;
}

static inline void ex1850_spi2_consume(uint64_t *remaining, uint64_t ns,
                                     uint32_t hz)
{
    if (!*remaining || !hz) { return; }
    __uint128_t consumed = (__uint128_t)ns * hz;
    *remaining = consumed >= *remaining ? 0 : *remaining - (uint64_t)consumed;
}

/* Caller invokes at timer deadlines and before changes of clock/gate state.
 * Sub-nanosecond event times round up independently. A stopped clock retains
 * the remaining source cycles; polling never advances hardware by itself.
 * A false memory read is a boundary before accepting that byte or reducing
 * NDTR. Earlier real hardware events are retained, never rolled back.
 */
static inline bool ex1850_spi2_advance(EX1850SPI2DMA *t, int64_t now,
    EX1850SPI2ReadByte read_byte, EX1850SPI2Observe observe, void *opaque)
{
    if (t->epoch < 0 || now < t->epoch) { return false; }
    ex1850_spi2_refresh(t);
    for (;;) {
        int64_t due = ex1850_spi2_deadline(t);
        int64_t until = due >= 0 && due <= now ? due : now;
        uint64_t elapsed = (uint64_t)(until - t->epoch);
        uint32_t dhz = ex1850_spi2_dma_hz(t), shz = ex1850_spi2_serial_hz(t);
        bool dma_event = t->dma_remaining && dhz &&
            ex1850_spi2_delay(t->dma_remaining, dhz) <= elapsed;
        bool move_event = t->move_remaining && shz &&
            ex1850_spi2_delay(t->move_remaining, shz) <= elapsed;
        bool shift_event = t->shift_remaining && shz &&
            ex1850_spi2_delay(t->shift_remaining, shz) <= elapsed;
        ex1850_spi2_consume(&t->dma_remaining, elapsed, dhz);
        ex1850_spi2_consume(&t->move_remaining, elapsed, shz);
        ex1850_spi2_consume(&t->shift_remaining, elapsed, shz);
        t->epoch = until;
        if (shift_event) {
            t->shifting = false;
            /* RM0402 p844: busy while communicating OR Tx buffer nonempty. */
            if (!t->buffer_full) { t->sr &= ~EX1850_SPI2_BSY; }
            if (t->sr & (EX1850_SPI2_RXNE | EX1850_SPI2_OVR)) {
                t->sr |= EX1850_SPI2_OVR;
                t->overrun_total++;
                /* RM0402 p819: preserve the prior token; subsequent receive
                 * frames remain lost until DR->SR clears the latched OVR.
                 * A DR read alone may clear RXNE, but does not resume Rx.
                 */
            } else {
                t->sr |= EX1850_SPI2_RXNE;
                t->rx_unknown = true;
            }
            t->shifted_total++;
            if (observe) { observe(opaque, EX1850_SPI2_SHIFT_COMPLETE, until,
                                  t->shift_address, t->shift_byte); }
        }
        if (move_event) {
            t->buffer_full = false;
            t->shifting = true;
            t->shift_byte = t->buffer_byte;
            t->shift_address = t->buffer_address;
            t->sr |= EX1850_SPI2_TXE | EX1850_SPI2_BSY;
            unsigned prescaler = 2U << ((t->cr1 >> 3) & 7);
            t->shift_remaining = UINT64_C(8) * prescaler * EX1850_SPI2_Q;
            if (observe) { observe(opaque, EX1850_SPI2_BUFFER_TO_SHIFT, until,
                                  t->shift_address, t->shift_byte); }
        }
        if (dma_event) {
            uint8_t byte;
            if (!ex1850_spi2_request(t) || !read_byte ||
                !read_byte(opaque, t->dma_address, &byte)) { return false; }
            EX1850DMAStreamControl *d = &t->dma1[4];
            t->buffer_full = true;
            t->buffer_byte = byte;
            t->buffer_address = t->dma_address;
            t->sr &= ~EX1850_SPI2_TXE;
            t->sr |= EX1850_SPI2_BSY;
            d->ndtr--;
            t->dma_accepted++;
            t->accepted_total++;
            if (t->dma_accepted == (t->dma_initial + 1) / 2) {
                t->hisr |= EX1850_DMA4_HT;
            }
            if (!d->ndtr) {
                t->hisr |= EX1850_DMA4_TC;
                d->cr &= ~UINT32_C(1);
            }
            if (d->cr & 0x400) { t->dma_address++; }
            if (observe) { observe(opaque, EX1850_SPI2_DMA_ACCEPT, until,
                                  t->buffer_address, byte); }
        }
        ex1850_spi2_refresh(t);
        if (until == now) { return true; }
    }
}

static inline bool ex1850_spi2_set_clocks(EX1850SPI2DMA *t, uint32_t hclk,
    uint32_t pclk, bool dma_gate, bool spi_gate, bool reset_held)
{
    if (hclk > 1000000000U || pclk > 1000000000U) { return false; }
    t->hclk_hz = hclk; t->pclk_hz = pclk;
    t->dma_gate = dma_gate; t->spi_gate = spi_gate; t->reset_held = reset_held;
    ex1850_spi2_refresh(t);
    return true;
}

static inline bool ex1850_spi2_dma_configuration(const EX1850SPI2DMA *t,
                                                uint32_t cr)
{
    const EX1850DMAStreamControl *d = &t->dma1[4];
    /* Normal/direct, Channel0, 8-bit memory->peripheral, optional MINC.
     * No FIFO/burst, circular, DBM, peripheral increment or flow controller.
     */
    if ((cr & ~UINT32_C(0x0003045f)) || (cr & 0xc0) != 0x40 ||
        (d->fcr & 4) || d->par != 0x4000380c) { return false; }
    if (!d->ndtr) { return true; } /* RM0402 p224: no request for NDTR=0. */
    uint64_t last = (uint64_t)d->m0ar + ((cr & 0x400) ? d->ndtr - 1 : 0);
    return d->m0ar >= EX1850_SPI2_RAM_BASE &&
           last < (uint64_t)EX1850_SPI2_RAM_BASE + EX1850_SPI2_RAM_BYTES;
}

static inline bool ex1850_spi2_dma_access(EX1850SPI2DMA *t, uint32_t offset,
                                        bool write, uint32_t *value)
{
    if (!value || (offset & 3) || offset >= 0xd0 || !t->dma_gate) { return false; }
    if (offset < 0x10) {
        uint32_t *status = (offset & 4) ? &t->hisr : &t->lisr;
        if (offset < 8 && !write) { *value = *status; return true; }
        if (offset >= 8 && write) {
            *status &= ~(*value & UINT32_C(0x0f7d0f7d));
            return true;
        }
        return false;
    }
    unsigned stream = (offset - 0x10) / 0x18;
    unsigned word = ((offset - 0x10) % 0x18) / 4;
    EX1850DMAStreamControl *d = &t->dma1[stream];
    uint32_t *reg, mask, readonly = 0;
    switch (word) {
    case 0: reg = &d->cr; mask = 0x0fefffff; readonly = 0x00100000; break;
    case 1: reg = &d->ndtr; mask = 0xffff; break;
    case 2: reg = &d->par; mask = UINT32_MAX; break;
    case 3: reg = &d->m0ar; mask = UINT32_MAX; break;
    case 4: reg = &d->m1ar; mask = UINT32_MAX; break;
    case 5: reg = &d->fcr; mask = 0x87; readonly = 0x38; break;
    default: return false;
    }
    if (!write) { *value = *reg; return true; }
    if (*value & ~(mask | readonly)) { return false; }
    uint32_t requested = (*reg & ~mask) | (*value & mask);
    if (d->cr & 1) {
        /* RM0402 pp226-227: FEIE is software controlled even with EN=1;
         * only DMDIS/FTH are protected. FS is read-only and already retained
         * above. The original 080433CC abort clears FEIE before clearing EN.
         */
        uint32_t live_mask = word == 0 ? 0x1f : word == 5 ? 0x80 : 0;
        if (!live_mask || ((*reg ^ requested) & ~live_mask)) { return false; }
    }
    if (word == 0 && (requested & 1)) {
        if (stream == 4) {
            if (!ex1850_spi2_dma_configuration(t, requested)) { return false; }
        } else if (stream == 5) {
            /* RM0402 DMA1 CH4: USART2_RX on Stream5. Normal/direct byte
             * transfer, optional MINC. The UART has no external RX source
             * in this board profile, so EN alone cannot accept a byte,
             * decrement NDTR, publish completion or write SRAM.
             */
            uint64_t last = (uint64_t)d->m0ar +
                ((requested & 0x400) && d->ndtr ? d->ndtr - 1 : 0);
            if ((requested & ~UINT32_C(0x0803041f)) ||
                (requested & 0x0e0000c0) != 0x08000000 ||
                (d->fcr & 4) || d->par != 0x40004404 ||
                (d->ndtr && (d->m0ar < EX1850_SPI2_RAM_BASE ||
                 last >= (uint64_t)EX1850_SPI2_RAM_BASE + EX1850_SPI2_RAM_BYTES))) {
                return false;
            }
        } else {
            return false;
        }
        if (stream == 4 && !(d->cr & 1)) {
            t->dma_initial = d->ndtr;
            t->dma_accepted = 0;
            t->dma_address = d->m0ar;
        }
    }
    if (word == 0 && (d->cr & 1) && !(requested & 1)) {
        /* RM0402 p213: software stream interruption also raises TCIF.
         * This direct-mode model has no partially accepted DMA bus beat:
         * cancel the unaccepted request, retain NDTR and any data already
         * owned by SPI. Do not confuse this with final SPI shift completion.
         */
        t->hisr |= EX1850_DMA4_TC << (stream == 5 ? 6 : 0);
    }
    *reg = requested;
    ex1850_spi2_refresh(t);
    return true;
}

static inline bool ex1850_spi2_access(EX1850SPI2DMA *t, uint32_t offset,
    bool write, bool discard_proven, uint32_t *value)
{
    if (!value || (offset & 3) || !t->spi_gate || t->reset_held) { return false; }
    switch (offset) {
    case 0x00:
        if (!write) { *value = t->cr1; return true; }
        if (*value & ~UINT32_C(0x3ff)) { return false; }
        if ((*value & EX1850_SPI2_SPE) && (*value & 0x304) != 0x304) { return false; }
        if ((t->buffer_full || t->shifting) && *value != t->cr1) { return false; }
        t->cr1 = *value;
        ex1850_spi2_refresh(t);
        return true;
    case 0x04:
        if (!write) { *value = t->cr2; return true; }
        if (*value & ~UINT32_C(0x26)) { return false; }
        t->cr2 = *value;
        ex1850_spi2_refresh(t);
        return true;
    case 0x08:
        if (write) { return false; }
        *value = t->sr;
        if (t->ovr_dr_read) { t->sr &= ~EX1850_SPI2_OVR; t->ovr_dr_read = false; }
        return true;
    case 0x0c:
        if (write || (t->rx_unknown && !discard_proven)) { return false; }
        /* 0 is a discarded representative of an unknown token, never MISO=0. */
        *value = 0;
        t->ovr_dr_read = !!(t->sr & EX1850_SPI2_OVR);
        t->sr &= ~EX1850_SPI2_RXNE;
        return true;
    case 0x1c:
        if (!write) { *value = t->i2scfgr; return true; }
        if (*value) { return false; }
        t->i2scfgr = 0;
        return true;
    default: return false;
    }
}
#endif
