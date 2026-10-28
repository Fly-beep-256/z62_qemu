/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Narrow Z6II C1.70 I2C software-reset proposal. Two original byte-write-0
 * / poll-nonzero loops agree with DW-HDMI SOFTRSTZ register offsets.
 * Release latency and reset initial state are explicit functional policies.
 * No EDID, FIFO, IRQ, PLL, DMA, video or guest memory operation occurs here. */
#ifndef Z6II_HDMI_I2C_RESET_CORE_H
#define Z6II_HDMI_I2C_RESET_CORE_H
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define Z6II_HDMI_I2C_RESET_PHY_ADDR UINT32_C(0x2016c0a8)
#define Z6II_HDMI_I2C_RESET_DDC_ADDR UINT32_C(0x2017f824)
#define Z6II_HDMI_I2C_RESET_LANES 2u

typedef struct Z6IIHDMIResetLane {
    uint64_t generation, due_ns, submitted, completed, cancelled;
    uint8_t value;
    bool pending;
} Z6IIHDMIResetLane;

typedef struct Z6IIHDMIResetCore {
    uint64_t delay_ns;
    Z6IIHDMIResetLane lane[Z6II_HDMI_I2C_RESET_LANES];
} Z6IIHDMIResetCore;

typedef enum Z6IIHDMIResetAccess {
    Z6II_HDMI_I2C_RESET_OK,
    Z6II_HDMI_I2C_RESET_NOT_OWNED,
    Z6II_HDMI_I2C_RESET_UNSUPPORTED,
    Z6II_HDMI_I2C_RESET_OVERFLOW,
} Z6IIHDMIResetAccess;

static inline int z6ii_hdmi_i2c_reset_lane(uint32_t addr)
{
    uint32_t slot = addr & ~UINT32_C(3);
    if (slot == Z6II_HDMI_I2C_RESET_PHY_ADDR) { return 0; }
    if (slot == Z6II_HDMI_I2C_RESET_DDC_ADDR) { return 1; }
    return -1;
}

static inline bool z6ii_hdmi_i2c_reset_init(Z6IIHDMIResetCore *s,
                                         uint64_t delay_ns)
{
    if (!s || !delay_ns) { return false; }
    memset(s, 0, sizeof(*s));
    s->delay_ns = delay_ns;
    /* Unobserved power-on value is 0 in this narrow proposal. Neither lane
     * becomes nonzero until an accepted original-style reset write. */
    return true;
}

static inline Z6IIHDMIResetAccess z6ii_hdmi_i2c_reset_access(
    Z6IIHDMIResetCore *s, uint32_t addr, unsigned size, bool write,
    uint64_t *value, uint64_t now_ns)
{
    int lane = z6ii_hdmi_i2c_reset_lane(addr);
    if (lane < 0) { return Z6II_HDMI_I2C_RESET_NOT_OWNED; }
    if (size != 1 || (addr & 3) || !s || !value ||
        (write && *value != 0)) {
        return Z6II_HDMI_I2C_RESET_UNSUPPORTED;
    }
    Z6IIHDMIResetLane *r = &s->lane[lane];
    if (!write) {
        *value = r->value;
        return Z6II_HDMI_I2C_RESET_OK;
    }
    if (!s->delay_ns || now_ns > UINT64_MAX - s->delay_ns ||
        r->generation == UINT64_MAX || r->submitted == UINT64_MAX ||
        (r->pending && r->cancelled == UINT64_MAX)) {
        return Z6II_HDMI_I2C_RESET_OVERFLOW;
    }
    if (r->pending) { ++r->cancelled; }
    ++r->generation;
    ++r->submitted;
    r->value = 0;
    r->pending = true;
    r->due_ns = now_ns + s->delay_ns;
    return Z6II_HDMI_I2C_RESET_OK;
}

static inline bool z6ii_hdmi_i2c_reset_complete(Z6IIHDMIResetCore *s,
    unsigned lane, uint64_t captured_generation, uint64_t now_ns)
{
    if (!s || lane >= Z6II_HDMI_I2C_RESET_LANES) { return false; }
    Z6IIHDMIResetLane *r = &s->lane[lane];
    if (!r->pending || captured_generation != r->generation ||
        now_ns < r->due_ns || r->completed == UINT64_MAX) { return false; }
    r->pending = false;
    r->due_ns = 0;
    r->value = 1;
    ++r->completed;
    return true;
}

/* Board reset invalidates both lanes. If identity would wrap, fail before
 * touching either lane. Caller deletes timers before using this function. */
static inline bool z6ii_hdmi_i2c_reset_cancel_all(Z6IIHDMIResetCore *s)
{
    if (!s) { return false; }
    for (unsigned i = 0; i < Z6II_HDMI_I2C_RESET_LANES; ++i) {
        Z6IIHDMIResetLane *r = &s->lane[i];
        if (r->generation == UINT64_MAX ||
            (r->pending && r->cancelled == UINT64_MAX)) { return false; }
    }
    for (unsigned i = 0; i < Z6II_HDMI_I2C_RESET_LANES; ++i) {
        Z6IIHDMIResetLane *r = &s->lane[i];
        ++r->generation;
        if (r->pending) { ++r->cancelled; }
        r->pending = false;
        r->due_ns = 0;
        r->value = 0;
    }
    return true;
}
#endif
