/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Isolated, opt-in MCU SPI/DMA rendezvous core, ABI2.
 *
 * The original MCU selects RX SPI1/DMA2S0 CH3 and TX SPI4/DMA2S1 CH4.
 * GPIO writer provenance is preserved: neither checksum nor DMA completion
 * writes an ACK or manufactures a software packet. The EXPEED-to-MCU wire
 * pairing and the scheduling quantum remain explicit functional hypotheses.
 * No native boot, rail, key, calibration or complete peripheral claim.
 */
#ifndef Z6II_MCU_WIRE_BUS_H
#define Z6II_MCU_WIRE_BUS_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdatomic.h>

#define MCU_WIRE_MAGIC UINT32_C(0x3157434d)
#define MCU_WIRE_ABI 2
#define MCU_WIRE_RAM_BASE UINT32_C(0x20000000)
#define MCU_WIRE_RAM_BYTES UINT32_C(0x40000)
#define MCU_WIRE_HEADER_BYTES 0x1000
#define MCU_WIRE_RX_READY (1U << 0) /* MCU PB14 -> master pin55(bit9), hypothesis */
#define MCU_WIRE_RX_ACK   (1U << 1) /* MCU PD12 -> master pin72(bit15), hypothesis */
#define MCU_WIRE_TX_READY (1U << 2) /* MCU PE3 -> master pin56(bit10), hypothesis */
#define MCU_WIRE_SPI_SPE (1U << 6)
#define MCU_WIRE_SPI_ERRIE (1U << 5)
#define MCU_WIRE_SPI_RXNE (1U << 0)
#define MCU_WIRE_SPI_TXE (1U << 1)
#define MCU_WIRE_SPI_OVR (1U << 6)
#define MCU_WIRE_DMA_EN (1U << 0)

enum MCUWireResult {
    MCU_WIRE_OK,
    MCU_WIRE_UNSUPPORTED,
    MCU_WIRE_NOT_READY,
    MCU_WIRE_BAD_ABI,
    MCU_WIRE_RANGE,
};

typedef struct MCUWireDMA {
    uint32_t reg[6]; /* CR,NDTR,PAR,M0AR,M1AR,FCR */
    uint32_t initial_ndtr, transferred;
} MCUWireDMA;

typedef struct MCUWireCore {
    uint32_t ahb1enr, apb2enr;
    uint32_t spi_cr1[2], spi_cr2[2]; /* [0] SPI1; [1] SPI4 */
    uint32_t spi_dr[2], spi_sr[2], spi_ovr_dr_read[2];
    MCUWireDMA dma[2];             /* DMA2 stream0, stream1 */
    uint32_t dma_lisr;
    uint32_t mcu_known, mcu_level;
    uint32_t master_ack_known, master_ack_level;
    uint32_t master_ack_edge_count, master_ack_last_edge_rising;
    uint32_t master_event_generation[3];
    uint64_t shifted_bytes[2];
    /* Cumulative observations, not readiness or protocol inputs. */
    uint64_t spi_received_bytes[2], spi_overrun_bytes[2], spi_ovr_clears[2];
} MCUWireCore;

typedef struct MCUWireHeader {
    uint32_t magic, abi, bytes;
    _Atomic uint32_t lock;
    MCUWireCore core;
} MCUWireHeader;

typedef struct MCUWireBus {
    union { MCUWireHeader h; uint8_t header[MCU_WIRE_HEADER_BYTES]; };
    uint8_t sram[MCU_WIRE_RAM_BYTES];
} MCUWireBus;

_Static_assert(sizeof(MCUWireHeader) <= MCU_WIRE_HEADER_BYTES, "header size");
_Static_assert(offsetof(MCUWireBus, sram) == MCU_WIRE_HEADER_BYTES, "RAM offset");
_Static_assert(sizeof(MCUWireBus) == 0x41000, "wire file bytes");

static inline void mcu_wire_lock(MCUWireBus *b)
{
    while (atomic_exchange_explicit(&b->h.lock, 1, memory_order_acquire)) { }
}

static inline void mcu_wire_unlock(MCUWireBus *b)
{
    atomic_store_explicit(&b->h.lock, 0, memory_order_release);
}

static inline void mcu_wire_core_init(MCUWireCore *c)
{
    memset(c, 0, sizeof(*c));
    c->spi_sr[0] = c->spi_sr[1] = MCU_WIRE_SPI_TXE;
    c->dma[0].reg[5] = c->dma[1].reg[5] = 0x21;
}

/* Creator only, before either emulator starts. Never apply to a live bus. */
static inline void mcu_wire_init(MCUWireBus *b)
{
    memset(b, 0, sizeof(*b));
    b->h.magic = MCU_WIRE_MAGIC;
    b->h.abi = MCU_WIRE_ABI;
    b->h.bytes = sizeof(*b);
    atomic_init(&b->h.lock, 0);
    mcu_wire_core_init(&b->h.core);
}

static inline int mcu_wire_validate(MCUWireBus *b)
{
    return b->h.magic == MCU_WIRE_MAGIC && b->h.abi == MCU_WIRE_ABI &&
           b->h.bytes == sizeof(*b) && atomic_is_lock_free(&b->h.lock) ?
           MCU_WIRE_OK : MCU_WIRE_BAD_ABI;
}

/* Feed actual guest-written RCC state; this does not turn any gate on. */
static inline void mcu_wire_gates(MCUWireBus *b, uint32_t ahb1, uint32_t apb2)
{
    mcu_wire_lock(b);
    b->h.core.ahb1enr = ahb1;
    b->h.core.apb2enr = apb2;
    mcu_wire_unlock(b);
}

static inline uint32_t mcu_wire_irq(MCUWireBus *b, unsigned stream)
{
    if (stream > 1) { return 0; }
    uint32_t active;
    mcu_wire_lock(b);
    MCUWireCore *c = &b->h.core;
    uint32_t flags = (c->dma_lisr >> (stream * 6)) & 0x3f;
    uint32_t cr = c->dma[stream].reg[0];
    active = !!((c->ahb1enr & (1U << 22)) &&
               (((flags & 0x20) && (cr & 0x10)) ||
                ((flags & 0x10) && (cr & 0x08))));
    mcu_wire_unlock(b);
    return active;
}

/* ERRIE is admitted by CR2. NVIC enable/priority remain original guest state.
 * SPI1 IRQ35 and SPI4 IRQ84 come from the STM32F412 device description. */
static inline uint32_t mcu_wire_spi_irq(MCUWireBus *b, unsigned spi)
{
    if (spi > 1) { return 0; }
    mcu_wire_lock(b);
    MCUWireCore *c = &b->h.core;
    uint32_t active = !!((c->apb2enr & (1U << (12 + spi))) &&
                         (c->spi_cr2[spi] & MCU_WIRE_SPI_ERRIE) &&
                         (c->spi_sr[spi] & MCU_WIRE_SPI_OVR));
    mcu_wire_unlock(b);
    return active;
}

/* Other armed lines may have explicit, constant external input profiles.
 * Their edge selectors do not invalidate an actual edge on the independent
 * PG6 line. Unknown sources and event-wakeup delivery remain unsupported. */
static inline int mcu_wire_pg6_exti_supported(uint32_t rtsr, uint32_t ftsr,
                                             uint32_t emr, unsigned port6,
                                             uint32_t static_sources)
{
    uint32_t known = static_sources & UINT32_C(0xffbf);
    if (port6 == 6) { known |= UINT32_C(0x40); }
    return !((rtsr | ftsr) & ~known) && !(emr & UINT32_C(0x40));
}

/* RM0402 10.3.6: PR6 is a sticky pending bit, not an edge counter. The
 * original master GPIO writer counts only changes of its binary level, so
 * two or more unobserved changes contain both edge polarities. Coalesce
 * them into the one hardware pending bit; do not replay interrupt calls.
 * The board consumes observations before changing edge/routing controls
 * or applying PR W1C. This does not reconstruct physical edge timing. */
static inline uint32_t mcu_wire_pg6_pending(uint32_t pending, uint32_t rtsr,
                                           uint32_t ftsr, uint32_t edges,
                                           int last_edge_rising)
{
    if (edges && (((edges > 1 || last_edge_rising) && (rtsr & 0x40)) ||
                  ((edges > 1 || !last_edge_rising) && (ftsr & 0x40)))) {
        pending |= UINT32_C(0x40);
    }
    return pending;
}

/* Caller holds the wire lock. DR is the receive buffer; writing the separate
 * transmit buffer through DMA must not replace an unread received byte.
 * The next complete byte overruns an occupied receive buffer. SPI keeps
 * shifting TX data, while the unread RX byte is retained. */
static inline void mcu_wire_spi_receive(MCUWireCore *c, unsigned spi, uint8_t byte)
{
    c->spi_received_bytes[spi]++;
    if (c->spi_sr[spi] & MCU_WIRE_SPI_RXNE) {
        c->spi_sr[spi] |= MCU_WIRE_SPI_OVR;
        c->spi_overrun_bytes[spi]++;
    } else {
        c->spi_dr[spi] = byte;
        c->spi_sr[spi] |= MCU_WIRE_SPI_RXNE;
    }
}

/* Both CPU and DMA reads consume RXNE. A DR read made before a later overrun
 * cannot clear that later OVR with an unrelated SR read. */
static inline uint32_t mcu_wire_spi_read_dr(MCUWireCore *c, unsigned spi)
{
    uint32_t value = c->spi_dr[spi];
    c->spi_sr[spi] &= ~MCU_WIRE_SPI_RXNE;
    c->spi_ovr_dr_read[spi] = !!(c->spi_sr[spi] & MCU_WIRE_SPI_OVR);
    return value;
}

static inline int mcu_wire_dma_valid(const MCUWireDMA *d, unsigned stream)
{
    uint32_t cr = d->reg[0];
    uint32_t expected = stream ? 0x08000440 : 0x06000400;
    uint32_t allowed = 0x0e03045f; /* CHSEL,PL,MINC,DIR,normal IRQ bits,EN */
    uint32_t port = stream ? 0x4001340c : 0x4001300c;
    if ((cr & ~allowed) || (cr & 0x0e000440) != expected ||
        d->reg[1] != 256 || d->reg[2] != port || (d->reg[5] & 4)) {
        return MCU_WIRE_UNSUPPORTED;
    }
    if (d->reg[3] < MCU_WIRE_RAM_BASE ||
        (uint64_t)d->reg[3] + d->reg[1] > MCU_WIRE_RAM_BASE + MCU_WIRE_RAM_BYTES) {
        return MCU_WIRE_RANGE;
    }
    return MCU_WIRE_OK;
}

/* STM32F412 SPI1RST/SPI4RST reset peripheral control latches, independent of
 * their APB clock enables. A peripheral reset does not reset its DMA stream,
 * GPIO handshakes, RAM, or already latched DMA flags. Only whole-byte shifts
 * exist in this model; no partial SPI word is represented. */
static inline int mcu_wire_spi_reset(MCUWireBus *b, uint32_t asserted)
{
    if (asserted & ~UINT32_C(0x3000)) { return MCU_WIRE_UNSUPPORTED; }
    mcu_wire_lock(b);
    for (unsigned spi = 0; spi < 2; spi++) {
        if (asserted & (1U << (12 + spi))) {
            b->h.core.spi_cr1[spi] = 0;
            b->h.core.spi_cr2[spi] = 0;
            b->h.core.spi_dr[spi] = 0;
            b->h.core.spi_sr[spi] = MCU_WIRE_SPI_TXE;
            b->h.core.spi_ovr_dr_read[spi] = 0;
        }
    }
    mcu_wire_unlock(b);
    return MCU_WIRE_OK;
}

/* Only the source-backed normal 8-bit SPI1/SPI4 + DMA2S0/S1 subset.
 * All rejected writes leave registers and RAM unchanged. */
/* failure receives state at rejection while the operation still holds the
 * wire lock. It is observational storage outside the shared ABI. */
static inline int mcu_wire_mmio_observed(MCUWireBus *b, uint32_t addr,
                               unsigned size, int write, uint32_t *value,
                               MCUWireCore *failure)
{
    int result = MCU_WIRE_UNSUPPORTED;
    mcu_wire_lock(b);
    MCUWireCore *c = &b->h.core;
    if (addr >= 0x40026400 && addr < 0x40026440 && size == 4 && !(addr & 3) &&
        (c->ahb1enr & (1U << 22))) {
        uint32_t off = addr - 0x40026400;
        if (off < 16) {
            if (!write && off == 0) { *value = c->dma_lisr; result = MCU_WIRE_OK; }
            else if (!write && off == 4) { *value = 0; result = MCU_WIRE_OK; }
            else if (write && off == 8) {
                /* STM32F412 W1C fields; reserved bits have no flag latch.
                 * The original HAL clears a six-bit slot with 0x3f, which
                 * also writes reserved bit1. Ignore that bit instead of
                 * treating a documented initialization clear as a transfer. */
                c->dma_lisr &= ~(*value & UINT32_C(0x0f7d0f7d));
                result = MCU_WIRE_OK;
            } else if (write && off == 12) {
                result = MCU_WIRE_OK; /* no stream4..7 transfer is admitted */
            }
        } else {
            unsigned stream = (off - 16) / 24, word = ((off - 16) % 24) / 4;
            MCUWireDMA *d = &c->dma[stream];
            const uint32_t mask[6] = {0x0fefffff, 0xffff, UINT32_MAX,
                                     UINT32_MAX, UINT32_MAX, 0x87};
            if (!write) { *value = d->reg[word]; result = MCU_WIRE_OK; }
            else if (word == 0 && (d->reg[0] & MCU_WIRE_DMA_EN) &&
                     (*value & MCU_WIRE_DMA_EN) &&
                     !((*value ^ d->reg[0]) & ~UINT32_C(0x1e))) {
                /* An active normal stream may change its IRQ enable bits.
                 * EN and configuration stay identical: this is not an arm.
                 * Preserve NDTR, progress, pending flags and all RAM bytes.
                 * A completed EN=0 stream still uses the strict path below. */
                d->reg[0] = (d->reg[0] & ~UINT32_C(0x1e)) |
                            (*value & UINT32_C(0x1e));
                result = MCU_WIRE_OK;
            }
            else if (!(*value & ~(mask[word] | (word == 5 ? 0x38U : 0U))) &&
                     (!(d->reg[0] & 1) || (word == 0 && !(*value & 1)))) {
                MCUWireDMA next = *d;
                next.reg[word] = (next.reg[word] & ~mask[word]) | (*value & mask[word]);
                if (word == 0 && (*value & 1)) {
                    result = mcu_wire_dma_valid(&next, stream);
                    if (result == MCU_WIRE_OK) {
                        next.initial_ndtr = next.reg[1]; next.transferred = 0;
                    }
                } else { result = MCU_WIRE_OK; }
                if (result == MCU_WIRE_OK) { *d = next; }
            }
        }
    } else {
        unsigned spi = addr >= 0x40013400 ? 1 : 0;
        uint32_t base = spi ? 0x40013400 : 0x40013000;
        uint32_t gate = 1U << (spi ? 13 : 12);
        if (addr >= base && addr < base + 32 && size == 4 && !(addr & 3) &&
            (c->apb2enr & gate)) {
            uint32_t off = addr - base;
            if (off == 0) {
                if (!write) { *value = c->spi_cr1[spi]; result = MCU_WIRE_OK; }
                else if (*value == 0 || *value == 0x289 || *value == 0x2c9) {
                    c->spi_cr1[spi] = *value; result = MCU_WIRE_OK;
                }
            } else if (off == 4) {
                if (!write) { *value = c->spi_cr2[spi]; result = MCU_WIRE_OK; }
                else if (!(*value & ~0x23U)) {
                    c->spi_cr2[spi] = *value; result = MCU_WIRE_OK;
                }
            } else if (!write && off == 8) {
                /* OVR clears only on DR -> SR. Return the status sampled by
                 * this read before its clear side effect; later reads see it
                 * cleared. No BSY interval exists in whole-byte rendezvous. */
                *value = c->spi_sr[spi];
                if (c->spi_ovr_dr_read[spi]) {
                    c->spi_sr[spi] &= ~MCU_WIRE_SPI_OVR;
                    c->spi_ovr_dr_read[spi] = 0;
                    c->spi_ovr_clears[spi]++;
                }
                result = MCU_WIRE_OK;
            } else if (!write && off == 12) {
                *value = mcu_wire_spi_read_dr(c, spi); result = MCU_WIRE_OK;
            } else if (off == 0x1c && (!write || *value == 0)) {
                /* Reset I2SCFGR=0; original SPI initializer clears I2SMOD.
                 * I2S enabling or other nonzero configuration stays strict. */
                *value = 0; result = MCU_WIRE_OK;
            }
        }
    }
    if (result != MCU_WIRE_OK && failure) { *failure = *c; }
    mcu_wire_unlock(b);
    return result;
}

static inline int mcu_wire_mmio(MCUWireBus *b, uint32_t addr,
                               unsigned size, int write, uint32_t *value)
{
    return mcu_wire_mmio_observed(b, addr, size, write, value, NULL);
}

/* Caller must only publish GPIO bits an original guest actually writes,
 * after checking native MODER=output, push-pull, and its RCC gate. */
static inline void mcu_wire_mcu_output(MCUWireBus *b, unsigned port,
                                      uint32_t written, uint32_t levels)
{
    mcu_wire_lock(b);
    MCUWireCore *c = &b->h.core;
    const unsigned ports[3] = {1, 3, 4};
    const uint32_t bits[3] = {0x4000, 0x1000, 0x0008};
    for (unsigned i = 0; i < 3; i++) {
        if (port == ports[i] && (written & bits[i])) {
            uint32_t wire = 1U << i;
            int known = !!(c->mcu_known & wire), old = !!(c->mcu_level & wire);
            int now = !!(levels & bits[i]);
            c->mcu_known |= wire;
            c->mcu_level = (c->mcu_level & ~wire) | (now ? wire : 0);
            /* master GPIO event2=RX ready, event3=TX ready; only rising edges */
            if (known && !old && now && i != 1) {
                c->master_event_generation[i == 0 ? 0 : 1]++;
            }
        }
    }
    mcu_wire_unlock(b);
}

/* A disabled gate or native direction change releases that modeled driver;
 * an old high output must not remain an implied ready after reset/deinit. */
static inline void mcu_wire_invalidate_output(MCUWireBus *b, unsigned port,
                                             uint32_t no_longer_output)
{
    mcu_wire_lock(b);
    const unsigned ports[3] = {1, 3, 4};
    const uint32_t bits[3] = {0x4000, 0x1000, 0x0008};
    for (unsigned i = 0; i < 3; i++) {
        if (port == ports[i] && (no_longer_output & bits[i])) {
            b->h.core.mcu_known &= ~(1U << i);
        }
    }
    mcu_wire_unlock(b);
}

/* Original master DATA04282018 bit12 writer, never a receiver callback. */
static inline void mcu_wire_master_ack(MCUWireBus *b, int level)
{
    mcu_wire_lock(b);
    MCUWireCore *c = &b->h.core;
    if (c->master_ack_known && c->master_ack_level != !!level) {
        c->master_ack_edge_count++;
        c->master_ack_last_edge_rising = !!level;
    }
    c->master_ack_known = 1;
    c->master_ack_level = !!level;
    mcu_wire_unlock(b);
}

static inline void mcu_wire_master_lines(MCUWireBus *b,
                                        uint32_t *known, uint32_t *level)
{
    mcu_wire_lock(b);
    *known = b->h.core.mcu_known;
    *level = b->h.core.mcu_level;
    mcu_wire_unlock(b);
}

/* A master 16-bit LSB-first clock rendezvous = two native MCU8-bit bytes.
 * Core time is abstract. QEMU glue must retain explicit scheduling metadata.
 * The unused master TX MISO is not returned; the host board may keep its
 * separately declared disconnected-input hypothesis for that sink only. */
/* Wire lock must be held. Both immediate and bounded host rendezvous use this
 * single transaction, including every original readiness gate and side effect. */
static inline int mcu_wire_clock16_locked(MCUWireBus *b, unsigned channel,
                                   uint16_t tx, uint16_t *rx,
                                   MCUWireCore *failure)
{
    if (channel > 1) {
        if (failure) { *failure = b->h.core; }
        return MCU_WIRE_UNSUPPORTED;
    }
    MCUWireCore *c = &b->h.core;
    MCUWireDMA *d = &c->dma[channel];
    uint32_t ready = channel ? MCU_WIRE_TX_READY : MCU_WIRE_RX_READY;
    uint32_t spi_gate = 1U << (channel ? 13 : 12);
    uint32_t dma_gate = channel ? 2 : 1;
    int result = MCU_WIRE_NOT_READY;
    if ((c->ahb1enr & (1U << 22)) && (c->apb2enr & spi_gate) &&
        c->spi_cr1[channel] == 0x2c9 && (c->spi_cr2[channel] & dma_gate) &&
        (d->reg[0] & 1) && d->reg[1] >= 2 &&
        (c->mcu_known & ready) && (c->mcu_level & ready)) {
        uint32_t off = d->reg[3] - MCU_WIRE_RAM_BASE + d->transferred;
        if ((uint64_t)off + 2 > MCU_WIRE_RAM_BYTES) { result = MCU_WIRE_RANGE; }
        else {
            if (channel) { *rx = b->sram[off] | (uint16_t)b->sram[off + 1] << 8; }
            for (unsigned byte = 0; byte < 2; byte++) {
                mcu_wire_spi_receive(c, channel, tx >> (8 * byte));
                if (!channel) {
                    /* SPI1 RX DMA consumes each byte before the next shift. */
                    b->sram[off + byte] = mcu_wire_spi_read_dr(c, channel);
                }
            }
            d->reg[1] -= 2; d->transferred += 2; c->shifted_bytes[channel] += 2;
            if (d->transferred == d->initial_ndtr / 2) {
                c->dma_lisr |= 0x10U << (6 * channel);
            }
            if (!d->reg[1]) {
                d->reg[0] &= ~1U;
                c->dma_lisr |= 0x20U << (6 * channel);
            }
            result = MCU_WIRE_OK;
        }
    }
    if (result != MCU_WIRE_OK && failure) { *failure = *c; }
    return result;
}

static inline int mcu_wire_clock16_observed(MCUWireBus *b, unsigned channel,
                                   uint16_t tx, uint16_t *rx,
                                   MCUWireCore *failure)
{
    mcu_wire_lock(b);
    int result = mcu_wire_clock16_locked(b, channel, tx, rx, failure);
    mcu_wire_unlock(b);
    return result;
}

static inline int mcu_wire_clock16(MCUWireBus *b, unsigned channel,
                                   uint16_t tx, uint16_t *rx)
{
    return mcu_wire_clock16_observed(b, channel, tx, rx, NULL);
}
#endif
