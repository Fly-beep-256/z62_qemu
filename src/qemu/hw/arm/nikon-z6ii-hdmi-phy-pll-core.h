/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Private, opt-in Gen2 PHY lock proposal for Z6II C1.70. Original ROM
 * 10481D9E performs six successful PHY-I2C writes before PHY_CONF0=2e,
 * then waits separately for IH_PHY_STAT0 bit1 -> RTOS event2. This core
 * does not write RTOS memory, a GIC line, pixels or an HDMI video stream.
 * Register bit names are corroborated by DW HDMI, not Nikon measurements.
 * The six-write prerequisite, delay, fault, reset, edge/mask and polarity
 * rules below are explicit functional policies. Only a rising lock event
 * is modeled. POL0 is stored for the original ISR's XOR/ack sequence;
 * its physical edge selection and HPD/RXSENSE interrupts remain absent. */
#ifndef Z6II_HDMI_PHY_PLL_CORE_H
#define Z6II_HDMI_PHY_PLL_CORE_H
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define Z6II_PLL_CONF UINT32_C(0x2016c000)
#define Z6II_PLL_LIVE UINT32_C(0x2016c010)
#define Z6II_PLL_INT UINT32_C(0x2016c014)
#define Z6II_PLL_MASK UINT32_C(0x2016c018)
#define Z6II_PLL_POL UINT32_C(0x2016c01c)
#define Z6II_PLL_RESET UINT32_C(0x20170014)
#define Z6II_PLL_IH_STAT UINT32_C(0x20160410)

typedef enum Z6IIPhyPLLFault {
    Z6II_PLL_LOCK, Z6II_PLL_TIMEOUT,
} Z6IIPhyPLLFault;
typedef enum Z6IIPhyPLLAccess {
    Z6II_PLL_OK, Z6II_PLL_NOT_OWNED, Z6II_PLL_UNSUPPORTED,
    Z6II_PLL_OVERFLOW,
} Z6IIPhyPLLAccess;
typedef struct Z6IIPhyPLLJob {
    uint64_t generation, due_ns;
    uint16_t words[6];
    Z6IIPhyPLLFault fault;
} Z6IIPhyPLLJob;
typedef struct Z6IIPhyPLLCore {
    uint64_t delay_ns, generation, submitted, completed, cancelled;
    bool enabled, pending, locked, announced;
    uint8_t conf, reset, mask, polarity, internal_int, raw, sequence;
    uint16_t words[6];
    Z6IIPhyPLLFault fault;
    Z6IIPhyPLLJob job;
} Z6IIPhyPLLCore;

static inline bool z6ii_pll_fault_valid(Z6IIPhyPLLFault fault)
{
    return fault == Z6II_PLL_LOCK || fault == Z6II_PLL_TIMEOUT;
}
static inline bool z6ii_pll_init(Z6IIPhyPLLCore *s, bool enabled,
    uint64_t delay_ns, Z6IIPhyPLLFault fault)
{
    if (!s || !delay_ns || !z6ii_pll_fault_valid(fault)) { return false; }
    memset(s, 0, sizeof(*s));
    s->enabled = enabled;
    s->delay_ns = delay_ns;
    s->fault = fault;
    s->mask = UINT8_MAX; /* Conservative reset policy; guest writes f2. */
    return true;
}
static inline bool z6ii_pll_owns(uint32_t addr)
{
    switch (addr & ~UINT32_C(3)) {
    case Z6II_PLL_CONF: case Z6II_PLL_LIVE: case Z6II_PLL_INT:
    case Z6II_PLL_MASK: case Z6II_PLL_POL: case Z6II_PLL_RESET:
    case Z6II_PLL_IH_STAT: return true;
    default: return false;
    }
}
static inline bool z6ii_pll_powered(const Z6IIPhyPLLCore *s)
{
    /* Gen2 TXPWRON=bit3 and PDDQ=bit4; original writes 2e. */
    return (s->conf & UINT8_C(0x18)) == UINT8_C(0x08) && !(s->reset & 1);
}
static inline bool z6ii_pll_cancel_inner(Z6IIPhyPLLCore *s)
{
    if (s->generation == UINT64_MAX ||
        (s->pending && s->cancelled == UINT64_MAX)) { return false; }
    ++s->generation;
    if (s->pending) { ++s->cancelled; }
    s->pending = s->locked = s->announced = false;
    s->internal_int = 0;
    memset(&s->job, 0, sizeof(s->job));
    /* Power loss retains the IH latch until W1C. Reset clears it below. */
    return true;
}
static inline void z6ii_pll_publish_inner(Z6IIPhyPLLCore *s)
{
    /* Internal mask gates forwarding. Unmask forwards a previously
     * unannounced rising completion exactly once. Source mutes are
     * outside this core and cannot destroy the raw latch. */
    if (s->locked && (s->internal_int & 1) && !(s->mask & 1) &&
        !s->announced) {
        s->raw |= 2;
        s->announced = true;
    }
}
static inline bool z6ii_pll_start_inner(Z6IIPhyPLLCore *s, uint64_t now_ns)
{
    if (!s->enabled || !z6ii_pll_powered(s) || s->sequence != 6 ||
        s->pending || s->locked) { return true; }
    if (!s->delay_ns || now_ns > UINT64_MAX - s->delay_ns ||
        s->generation == UINT64_MAX || s->submitted == UINT64_MAX ||
        !z6ii_pll_fault_valid(s->fault)) { return false; }
    ++s->generation;
    ++s->submitted;
    s->pending = true;
    s->job = (Z6IIPhyPLLJob) { .generation = s->generation,
        .due_ns = now_ns + s->delay_ns, .fault = s->fault };
    memcpy(s->job.words, s->words, sizeof(s->words));
    return true;
}
static inline bool z6ii_pll_i2c_completion(Z6IIPhyPLLCore *s,
    uint8_t slave, uint8_t address, uint16_t word, bool success)
{
    /* Caller invokes only AFTER accepting the immutable I2C job's
     * completion. A stale callback or rejected submit cannot count.
     * Commits while PHY reset is asserted configure the PHY bank, as
     * the original ROM does. Deassertion preserves that bank. */
    static const uint8_t order[6] = { 6, 0x10, 0x15, 0x0e, 9, 0x19 };
    if (!s || slave != UINT8_C(0x69)) { return false; }
    Z6IIPhyPLLCore n = *s;
    if ((n.pending || n.locked) && !z6ii_pll_cancel_inner(&n)) { return false; }
    if (!success) {
        n.sequence = 0;
    } else if (address == order[0]) {
        n.sequence = 1;
        n.words[0] = word;
    } else if (n.sequence < 6 && n.sequence && address == order[n.sequence]) {
        n.words[n.sequence++] = word;
    } else {
        n.sequence = 0;
    }
    *s = n;
    return true;
}
static inline Z6IIPhyPLLAccess z6ii_pll_access(Z6IIPhyPLLCore *s,
    uint32_t addr, unsigned size, bool write, uint64_t *value,
    uint64_t now_ns, bool hpd_connected)
{
    if (!z6ii_pll_owns(addr)) { return Z6II_PLL_NOT_OWNED; }
    if (!s || !value || size != 1 || (addr & 3) ||
        (write && *value > UINT8_MAX)) { return Z6II_PLL_UNSUPPORTED; }
    if (!write) {
        switch (addr) {
        case Z6II_PLL_CONF: *value = s->conf; break;
        case Z6II_PLL_LIVE: *value = (s->locked ? 1 : 0) | (hpd_connected ? 2 : 0); break;
        case Z6II_PLL_INT: *value = s->internal_int; break;
        case Z6II_PLL_MASK: *value = s->mask; break;
        case Z6II_PLL_POL: *value = s->polarity; break;
        case Z6II_PLL_RESET: *value = s->reset; break;
        case Z6II_PLL_IH_STAT: *value = s->raw; break;
        default: return Z6II_PLL_UNSUPPORTED;
        }
        return Z6II_PLL_OK;
    }
    Z6IIPhyPLLCore n = *s;
    switch (addr) {
    case Z6II_PLL_CONF:
        n.conf = (uint8_t)*value;
        if (!z6ii_pll_powered(&n) && (n.pending || n.locked)) {
            if (!z6ii_pll_cancel_inner(&n)) { return Z6II_PLL_OVERFLOW; }
        }
        if (!z6ii_pll_start_inner(&n, now_ns)) { return Z6II_PLL_OVERFLOW; }
        break;
    case Z6II_PLL_MASK:
        n.mask = (uint8_t)*value;
        z6ii_pll_publish_inner(&n);
        break;
    case Z6II_PLL_POL: n.polarity = (uint8_t)*value; break;
    case Z6II_PLL_RESET:
        if ((*value & 1) && !(n.reset & 1)) {
            if (!z6ii_pll_cancel_inner(&n)) { return Z6II_PLL_OVERFLOW; }
            n.sequence = n.raw = 0;
            memset(n.words, 0, sizeof(n.words));
        }
        n.reset = (uint8_t)*value;
        /* Reset release alone never submits a PLL job. The guest's
         * subsequent powered CONF write is the submission boundary. */
        break;
    case Z6II_PLL_IH_STAT: n.raw &= (uint8_t)~*value; break;
    default: return Z6II_PLL_UNSUPPORTED;
    }
    *s = n;
    return Z6II_PLL_OK;
}
static inline bool z6ii_pll_next_due(const Z6IIPhyPLLCore *s, uint64_t *due_ns)
{
    if (!s || !due_ns || !s->pending || s->job.fault == Z6II_PLL_TIMEOUT) {
        return false;
    }
    *due_ns = s->job.due_ns;
    return true;
}
static inline bool z6ii_pll_complete(Z6IIPhyPLLCore *s,
    uint64_t captured_generation, uint64_t now_ns)
{
    if (!s || !s->enabled || !s->pending || !z6ii_pll_powered(s) ||
        captured_generation != s->job.generation || now_ns < s->job.due_ns ||
        s->job.fault == Z6II_PLL_TIMEOUT || s->completed == UINT64_MAX) {
        return false;
    }
    s->pending = false;
    s->locked = true;
    s->internal_int |= 1;
    ++s->completed;
    z6ii_pll_publish_inner(s);
    return true;
}
static inline bool z6ii_pll_board_reset(Z6IIPhyPLLCore *s)
{
    if (!s) { return false; }
    Z6IIPhyPLLCore n = *s;
    if (!z6ii_pll_cancel_inner(&n)) { return false; }
    n.conf = n.reset = n.polarity = n.raw = n.sequence = 0;
    n.mask = UINT8_MAX;
    memset(n.words, 0, sizeof(n.words));
    *s = n;
    return true;
}
static inline bool z6ii_pll_configuration_cancel(Z6IIPhyPLLCore *s,
    bool clear_raw)
{
    /* Narrow I2C-controller reset policy: accepted configuration and
     * pending lock cannot survive, but PHY CONF/MASK/POL/MC reset bytes
     * retain their separate owners and are not board-reset defaults. */
    if (!s) { return false; }
    Z6IIPhyPLLCore n = *s;
    if (!z6ii_pll_cancel_inner(&n)) { return false; }
    n.sequence = 0;
    if (clear_raw) { n.raw = 0; }
    memset(n.words, 0, sizeof(n.words));
    *s = n;
    return true;
}
#endif
