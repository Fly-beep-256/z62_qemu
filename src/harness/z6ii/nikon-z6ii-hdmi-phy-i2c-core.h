/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Private Z6II C1.70 PHY-I2C transaction proposal. Original ROM 10481D54
 * writes slave 0x69, an 8-bit register, a 16-bit word, and operation 0x10.
 * Original ISR 10481968 translates IH_I2CMPHY status DONE/ERROR to RTOS
 * event bits 4/8. This core supplies only byte MMIO and a source status;
 * it does not drive a GIC line, summary bit, RTOS flag, PLL or video.
 * Completion latency, W1C, initial register values, busy rejection, retained
 * operation byte and reset semantics are explicit functional policies.
 * The committed word bank is audit state, not a claim about PHY internals. */
#ifndef Z6II_HDMI_PHY_I2C_CORE_H
#define Z6II_HDMI_PHY_I2C_CORE_H
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define Z6II_PHY_I2C_STATUS UINT32_C(0x20160420)
#define Z6II_PHY_I2C_SLAVE UINT32_C(0x2016c080)
#define Z6II_PHY_I2C_ADDRESS UINT32_C(0x2016c084)
#define Z6II_PHY_I2C_DATA_HIGH UINT32_C(0x2016c088)
#define Z6II_PHY_I2C_DATA_LOW UINT32_C(0x2016c08c)
#define Z6II_PHY_I2C_OPERATION UINT32_C(0x2016c098)
#define Z6II_PHY_I2C_DONE UINT8_C(2)
#define Z6II_PHY_I2C_ERROR UINT8_C(1)

typedef enum Z6IIPhyI2CFault {
    Z6II_PHY_I2C_FAULT_NONE,
    Z6II_PHY_I2C_FAULT_ERROR,
    Z6II_PHY_I2C_FAULT_TIMEOUT,
} Z6IIPhyI2CFault;

typedef enum Z6IIPhyI2CAccess {
    Z6II_PHY_I2C_OK,
    Z6II_PHY_I2C_NOT_OWNED,
    Z6II_PHY_I2C_UNSUPPORTED,
    Z6II_PHY_I2C_BUSY,
    Z6II_PHY_I2C_OVERFLOW,
} Z6IIPhyI2CAccess;

typedef struct Z6IIPhyI2CJob {
    uint64_t generation, due_ns;
    uint16_t word;
    uint8_t slave, address;
    Z6IIPhyI2CFault fault;
} Z6IIPhyI2CJob;

typedef struct Z6IIPhyI2CCore {
    uint64_t delay_ns, generation, submitted, completed, errors, cancelled;
    uint8_t slave, address, high, low, operation, status;
    bool pending;
    Z6IIPhyI2CFault fault;
    Z6IIPhyI2CJob job;
    uint16_t committed[256];
    bool committed_valid[256];
} Z6IIPhyI2CCore;

static inline bool z6ii_phy_i2c_owns(uint32_t addr)
{
    switch (addr & ~UINT32_C(3)) {
    case Z6II_PHY_I2C_STATUS:
    case Z6II_PHY_I2C_SLAVE:
    case Z6II_PHY_I2C_ADDRESS:
    case Z6II_PHY_I2C_DATA_HIGH:
    case Z6II_PHY_I2C_DATA_LOW:
    case Z6II_PHY_I2C_OPERATION: return true;
    default: return false;
    }
}

static inline bool z6ii_phy_i2c_fault_valid(Z6IIPhyI2CFault fault)
{
    return fault == Z6II_PHY_I2C_FAULT_NONE ||
           fault == Z6II_PHY_I2C_FAULT_ERROR ||
           fault == Z6II_PHY_I2C_FAULT_TIMEOUT;
}

static inline bool z6ii_phy_i2c_init(Z6IIPhyI2CCore *s,
    uint64_t delay_ns, Z6IIPhyI2CFault fault)
{
    if (!s || !delay_ns || !z6ii_phy_i2c_fault_valid(fault)) {
        return false;
    }
    memset(s, 0, sizeof(*s));
    s->delay_ns = delay_ns;
    s->fault = fault;
    return true;
}

static inline Z6IIPhyI2CAccess z6ii_phy_i2c_access(Z6IIPhyI2CCore *s,
    uint32_t addr, unsigned size, bool write, uint64_t *value,
    uint64_t now_ns)
{
    if (!z6ii_phy_i2c_owns(addr)) { return Z6II_PHY_I2C_NOT_OWNED; }
    if (!s || !value || size != 1 || (addr & 3) ||
        (write && *value > UINT8_MAX)) { return Z6II_PHY_I2C_UNSUPPORTED; }
    uint8_t *reg = NULL;
    switch (addr) {
    case Z6II_PHY_I2C_STATUS: reg = &s->status; break;
    case Z6II_PHY_I2C_SLAVE: reg = &s->slave; break;
    case Z6II_PHY_I2C_ADDRESS: reg = &s->address; break;
    case Z6II_PHY_I2C_DATA_HIGH: reg = &s->high; break;
    case Z6II_PHY_I2C_DATA_LOW: reg = &s->low; break;
    case Z6II_PHY_I2C_OPERATION: reg = &s->operation; break;
    default: return Z6II_PHY_I2C_UNSUPPORTED;
    }
    if (!write) { *value = *reg; return Z6II_PHY_I2C_OK; }
    if (addr == Z6II_PHY_I2C_STATUS) {
        /* Source W1C, including while a new transaction is pending. */
        s->status &= (uint8_t)~*value;
        return Z6II_PHY_I2C_OK;
    }
    if (addr != Z6II_PHY_I2C_OPERATION) {
        *reg = (uint8_t)*value;
        return Z6II_PHY_I2C_OK;
    }
    if (*value != UINT8_C(0x10) || s->slave != UINT8_C(0x69) ||
        !z6ii_phy_i2c_fault_valid(s->fault)) {
        return Z6II_PHY_I2C_UNSUPPORTED;
    }
    if (s->pending) { return Z6II_PHY_I2C_BUSY; }
    if (!s->delay_ns || now_ns > UINT64_MAX - s->delay_ns ||
        s->generation == UINT64_MAX || s->submitted == UINT64_MAX) {
        return Z6II_PHY_I2C_OVERFLOW;
    }
    ++s->generation;
    ++s->submitted;
    s->operation = (uint8_t)*value;
    s->pending = true;
    s->job = (Z6IIPhyI2CJob) {
        s->generation, now_ns + s->delay_ns,
        (uint16_t)(((uint16_t)s->high << 8) | s->low),
        s->slave, s->address, s->fault,
    };
    return Z6II_PHY_I2C_OK;
}

static inline bool z6ii_phy_i2c_next_due(const Z6IIPhyI2CCore *s,
    uint64_t *due_ns)
{
    if (!s || !due_ns || !s->pending ||
        s->job.fault == Z6II_PHY_I2C_FAULT_TIMEOUT) { return false; }
    *due_ns = s->job.due_ns;
    return true;
}

static inline bool z6ii_phy_i2c_complete(Z6IIPhyI2CCore *s,
    uint64_t captured_generation, uint64_t now_ns)
{
    if (!s || !s->pending || captured_generation != s->job.generation ||
        now_ns < s->job.due_ns ||
        s->job.fault == Z6II_PHY_I2C_FAULT_TIMEOUT ||
        s->completed == UINT64_MAX ||
        (s->job.fault == Z6II_PHY_I2C_FAULT_ERROR &&
         s->errors == UINT64_MAX)) { return false; }
    s->pending = false;
    ++s->completed;
    if (s->job.fault == Z6II_PHY_I2C_FAULT_ERROR) {
        ++s->errors;
        s->status |= Z6II_PHY_I2C_ERROR;
    } else {
        s->committed[s->job.address] = s->job.word;
        s->committed_valid[s->job.address] = true;
        s->status |= Z6II_PHY_I2C_DONE;
    }
    return true;
}

static inline bool z6ii_phy_i2c_source_pending(const Z6IIPhyI2CCore *s)
{
    /* No claim about physical peripheral masks or IRQ routing. */
    return s && (s->status & (Z6II_PHY_I2C_DONE | Z6II_PHY_I2C_ERROR));
}

static inline bool z6ii_phy_i2c_cancel(Z6IIPhyI2CCore *s)
{
    if (!s || s->generation == UINT64_MAX ||
        (s->pending && s->cancelled == UINT64_MAX)) { return false; }
    ++s->generation;
    if (s->pending) { ++s->cancelled; }
    s->pending = false;
    memset(&s->job, 0, sizeof(s->job));
    return true;
}

static inline bool z6ii_phy_i2c_board_reset(Z6IIPhyI2CCore *s)
{
    if (!z6ii_phy_i2c_cancel(s)) { return false; }
    /* Narrow board-reset policy, independent of the SOFTRSTZ core. The
     * integration must explicitly decide which reset invokes this hook. */
    s->slave = s->address = s->high = s->low = s->operation = s->status = 0;
    memset(s->committed, 0, sizeof(s->committed));
    memset(s->committed_valid, 0, sizeof(s->committed_valid));
    return true;
}
#endif
