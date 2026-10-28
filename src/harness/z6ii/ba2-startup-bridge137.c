/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "ba2-startup-bridge137.h"
#include "ba2-engine140.h"
#include <string.h>

static const uint32_t offsets[Z6II_BA2_STARTUP_BRIDGE137_CONFIG_COUNT] = {
    0x00, 0x04, 0x08, 0x0c, 0x3c, 0x40, 0x60, 0x64, 0x8c
};
/* Original 40007998..400079EE immediate/store sequence, GNU BA2 decode. */
static const uint32_t values[Z6II_BA2_STARTUP_BRIDGE137_CONFIG_COUNT] = {
    4112, 4112, 2, 198082, 65537, 0, 35686468, 146944034, 0
};
#define ALL_CONFIG ((UINT32_C(1) << Z6II_BA2_STARTUP_BRIDGE137_CONFIG_COUNT) - 1)
/* Exact original 4000BAB4..4000BC94 writes, then event-task 40009618/689. */
static const uint32_t transaction_addresses[Z6II_BA2_STARTUP_BRIDGE137_TRANSACTION_CONFIG_COUNT] = {
    0x80010008, 0x8001000c, 0x80010010, 0x80010014, 0x80010018,
    0x80010024, 0x80010030, 0x80010034, 0x80010038, 0x8001003c,
    0x80010040, 0x8001004c, 0x80010050, 0x8001041c, 0x80010420,
    0x80010424, 0x80010428, 0x8001042c, 0x80010430, 0x80010434,
    0x80010438, 0x80010444, 0x80010448, 0x8001044c, 0x80010450,
    0x80010454, 0x80010458, 0x8001045c, 0x8001005c
};
#define ALL_TRANSACTION_CONFIG ((UINT32_C(1) << Z6II_BA2_STARTUP_BRIDGE137_TRANSACTION_CONFIG_COUNT) - 1)

bool z6ii_ba2_startup_bridge137_invariant(const Z6IIBA2StartupBridge137 *s)
{
    if (!s || !s->initialized || !s->policy ||
        strcmp(s->policy, Z6II_BA2_STARTUP_BRIDGE137_POLICY) ||
        !s->basis || !*s->basis || !s->controller || !s->master ||
        s->controller->master != s->master ||
        !z6ii_ba2_controller136_invariant(s->controller) ||
        (s->engine && !z6ii_ba2_engine140_invariant(s->engine)) ||
        (s->config_written & ~ALL_CONFIG) || s->reset_busy_reads > 1 ||
        (s->transaction_config_written & ~ALL_TRANSACTION_CONFIG) ||
        (s->transaction_config_basis && !*s->transaction_config_basis) ||
        (!s->transaction_config_basis && s->transaction_config_written) ||
        s->idle_request > 1 ||
        (s->control != 0 && s->control != 1 && s->control != 2) ||
        (s->reset_busy_reads && s->control != 2) ||
        (s->control == 2 && s->reset_completed) ||
        (s->control == 1 && (!s->reset_completed || s->config_written != ALL_CONFIG))) {
        return false;
    }
    for (unsigned i = 0; i < Z6II_BA2_STARTUP_BRIDGE137_CONFIG_COUNT; ++i) {
        if (s->engine && i == 3 && (s->config_written & (UINT32_C(1) << i))) {
            continue; /* Runtime mask storage; only implemented raw bits assert. */
        }
        if (s->config[i] != ((s->config_written & (UINT32_C(1) << i)) ? values[i] : 0)) {
            return false;
        }
    }
    for (unsigned i = 0; i < Z6II_BA2_STARTUP_BRIDGE137_TRANSACTION_CONFIG_COUNT; ++i) {
        if (!(s->transaction_config_written & (UINT32_C(1) << i)) &&
            s->transaction_config[i] != 0) {
            return false;
        }
    }
    return true;
}

Z6IIBA2BusResult z6ii_ba2_startup_bridge137_init(Z6IIBA2StartupBridge137 *s,
    Z6IIBA2Controller136 *controller, Z6IIIPU2402 *master,
    const char *policy, uint32_t initial, const char *basis)
{
    if (!s) {
        return Z6II_BA2_BUS_BAD_CONFIG;
    }
    memset(s, 0, sizeof(*s));
    if (!controller || !master || controller->master != master ||
        !z6ii_ba2_controller136_invariant(controller) || !policy ||
        strcmp(policy, Z6II_BA2_STARTUP_BRIDGE137_POLICY) || !basis || !*basis) {
        return Z6II_BA2_BUS_BAD_CONFIG;
    }
    s->controller = controller;
    s->master = master;
    s->policy = policy;
    s->basis = basis;
    s->spr4800_initial = initial;
    s->spr4800 = initial;
    s->initialized = true;
    return Z6II_BA2_BUS_OK;
}

void z6ii_ba2_startup_bridge137_reset(Z6IIBA2StartupBridge137 *s)
{
    if (!s || !s->initialized) {
        return;
    }
    memset(s->config, 0, sizeof(s->config));
    s->config_written = 0;
    memset(s->transaction_config, 0, sizeof(s->transaction_config));
    s->transaction_config_written = 0;
    s->control = 0;
    s->idle_request = 0;
    s->reset_busy_reads = 0;
    s->reset_completed = false;
    s->spr4800 = s->spr4800_initial;
    if (s->engine) {
        z6ii_ba2_engine140_reset(s->engine);
    }
}

Z6IIBA2BusResult z6ii_ba2_startup_bridge137_enable_transaction_config_candidate(
    Z6IIBA2StartupBridge137 *s, const char *basis)
{
    if (!z6ii_ba2_startup_bridge137_invariant(s) || !basis || !*basis) {
        return Z6II_BA2_BUS_BAD_CONFIG;
    }
    s->transaction_config_basis = basis;
    return Z6II_BA2_BUS_OK;
}

static Z6IIBA2BusResult guard(const Z6IIBA2StartupBridge137 *s,
                             uint32_t addr, unsigned size)
{
    if (!z6ii_ba2_startup_bridge137_invariant(s)) {
        return Z6II_BA2_BUS_BAD_CONFIG;
    }
    if (size != 4) {
        return Z6II_BA2_BUS_BAD_WIDTH;
    }
    if (addr & 3) {
        return Z6II_BA2_BUS_BAD_ALIGNMENT;
    }
    if (addr < Z6II_BA2_STARTUP_BRIDGE137_BASE ||
        addr - Z6II_BA2_STARTUP_BRIDGE137_BASE >= Z6II_BA2_STARTUP_BRIDGE137_BYTES) {
        return Z6II_BA2_BUS_UNMAPPED;
    }
    return Z6II_BA2_BUS_OK;
}

Z6IIBA2BusResult z6ii_ba2_startup_bridge137_read(void *opaque, uint32_t addr,
                                             unsigned size, uint32_t *out)
{
    Z6IIBA2StartupBridge137 *s = opaque;
    Z6IIBA2BusResult r = guard(s, addr, size);
    if (r != Z6II_BA2_BUS_OK) {
        return r;
    }
    if (!out) {
        return Z6II_BA2_BUS_BAD_CONFIG;
    }
    if (addr >= Z6II_BA2_CONTROLLER136_BASE) {
        return z6ii_ba2_controller136_read(s->controller, addr, size, out);
    }
    if (s->engine && addr == UINT32_C(0x80010414)) {
        return z6ii_ba2_engine140_read_raw(s->engine, out);
    }
    /* Only original read/modify/write locations; never completion/status data. */
    if ((addr == UINT32_C(0x80010050) || addr == UINT32_C(0x8001041c)) &&
        s->transaction_config_basis) {
        const unsigned i = addr == UINT32_C(0x80010050) ? 12 : 13;
        if (!(s->transaction_config_written & (UINT32_C(1) << i))) {
            return Z6II_BA2_BUS_DEVICE_FAULT;
        }
        *out = s->transaction_config[i];
        ++s->transaction_config_reads;
        return Z6II_BA2_BUS_OK;
    }
    uint32_t offset = addr - Z6II_BA2_STARTUP_BRIDGE137_CONFIG_BASE;
    if (offset == 0x18) {
        *out = s->master->signature;
        return Z6II_BA2_BUS_OK;
    }
    if (offset >= 0x7c && offset <= 0x88) {
        if (!s->master->window_valid || !s->master->window_commits) {
            return Z6II_BA2_BUS_DEVICE_FAULT;
        }
        *out = s->master->window_active[(offset - 0x7c) / 4];
        ++s->window_reads;
        return Z6II_BA2_BUS_OK;
    }
    if (offset == 0x90) {
        if (s->control == 2) {
            if (s->reset_busy_reads) {
                --s->reset_busy_reads;
                ++s->reset_busy_observations;
                *out = 2;
                return Z6II_BA2_BUS_OK;
            }
            s->control = 0;
            s->reset_completed = true;
            ++s->reset_completions;
        }
        *out = s->control;
        return Z6II_BA2_BUS_OK;
    }
    for (unsigned i = 0; i < Z6II_BA2_STARTUP_BRIDGE137_CONFIG_COUNT; ++i) {
        if (offset == offsets[i]) {
            if (!(s->config_written & (UINT32_C(1) << i))) {
                return Z6II_BA2_BUS_DEVICE_FAULT;
            }
            *out = s->config[i];
            return Z6II_BA2_BUS_OK;
        }
    }
    return Z6II_BA2_BUS_UNMAPPED;
}

Z6IIBA2BusResult z6ii_ba2_startup_bridge137_write(void *opaque, uint32_t addr,
                                              unsigned size, uint32_t value)
{
    Z6IIBA2StartupBridge137 *s = opaque;
    Z6IIBA2BusResult r = guard(s, addr, size);
    if (r != Z6II_BA2_BUS_OK) {
        return r;
    }
    if (addr >= Z6II_BA2_CONTROLLER136_BASE) {
        return z6ii_ba2_controller136_write(s->controller, addr, size, value);
    }
    if (s->engine && addr == UINT32_C(0x80010410)) {
        return z6ii_ba2_engine140_ack(s->engine, value);
    }
    if (s->transaction_config_basis) {
        for (unsigned i = 0; i < Z6II_BA2_STARTUP_BRIDGE137_TRANSACTION_CONFIG_COUNT; ++i) {
            if (addr == transaction_addresses[i]) {
                if (s->engine && i == 13 && (value & UINT32_C(0x10))) {
                    /* Validate/transform/commit before latching the submission.
                     * A failure preserves all guest-visible RAM/raw/config. */
                    r = z6ii_ba2_engine140_submit(s->engine, value);
                    if (r != Z6II_BA2_BUS_OK) {
                        return r;
                    }
                }
                s->transaction_config[i] = value;
                s->transaction_config_written |= UINT32_C(1) << i;
                ++s->transaction_config_writes;
                return Z6II_BA2_BUS_OK;
            }
        }
    }
    uint32_t offset = addr - Z6II_BA2_STARTUP_BRIDGE137_CONFIG_BASE;
    if (offset == 0x78) {
        /* Original idle 4000BED1; explicit request-storage candidate only.
         * This never acknowledges, completes, advances a timer or raises IRQ. */
        if (value != 1 || s->control != 1) {
            return Z6II_BA2_BUS_DEVICE_FAULT;
        }
        s->idle_request = value;
        ++s->idle_requests;
        return Z6II_BA2_BUS_OK;
    }
    if (offset == 0x18 || (offset >= 0x7c && offset <= 0x88)) {
        return Z6II_BA2_BUS_PERMISSION;
    }
    if (offset == 0x90) {
        if (s->control == 2) {
            return Z6II_BA2_BUS_DEVICE_FAULT;
        }
        if (value == 2) {
            memset(s->config, 0, sizeof(s->config));
            s->config_written = 0;
            s->reset_completed = false;
            s->control = 2;
            s->reset_busy_reads = 1;
            ++s->reset_transactions;
            return Z6II_BA2_BUS_OK;
        }
        if (value == 1 && s->reset_completed && s->config_written == ALL_CONFIG) {
            s->control = 1;
            ++s->enable_writes;
            return Z6II_BA2_BUS_OK;
        }
        return Z6II_BA2_BUS_DEVICE_FAULT;
    }
    for (unsigned i = 0; i < Z6II_BA2_STARTUP_BRIDGE137_CONFIG_COUNT; ++i) {
        if (offset == offsets[i]) {
            if (s->engine && i == 3 && s->reset_completed &&
                (s->control == 0 || s->control == 1)) {
                s->config[i] = value;
                s->config_written |= UINT32_C(1) << i;
                return Z6II_BA2_BUS_OK;
            }
            if (!s->reset_completed || s->control != 0 || value != values[i]) {
                return Z6II_BA2_BUS_DEVICE_FAULT;
            }
            s->config[i] = value;
            s->config_written |= UINT32_C(1) << i;
            return Z6II_BA2_BUS_OK;
        }
    }
    return Z6II_BA2_BUS_UNMAPPED;
}

Z6IIBA2SPRResult z6ii_ba2_startup_bridge137_spr_read(void *opaque,
                                                uint32_t selector, uint32_t *out)
{
    Z6IIBA2StartupBridge137 *s = opaque;
    if (selector != Z6II_BA2_STARTUP_BRIDGE137_SPR) {
        return Z6II_BA2_SPR_UNKNOWN;
    }
    if (!out || !z6ii_ba2_startup_bridge137_invariant(s)) {
        return Z6II_BA2_SPR_FAULT;
    }
    *out = s->spr4800;
    ++s->spr_reads;
    return Z6II_BA2_SPR_OK;
}

Z6IIBA2SPRResult z6ii_ba2_startup_bridge137_spr_write(void *opaque,
                                                 uint32_t selector, uint32_t value)
{
    Z6IIBA2StartupBridge137 *s = opaque;
    if (selector != Z6II_BA2_STARTUP_BRIDGE137_SPR) {
        return Z6II_BA2_SPR_UNKNOWN;
    }
    if (!z6ii_ba2_startup_bridge137_invariant(s)) {
        return Z6II_BA2_SPR_FAULT;
    }
    s->spr4800 = value;
    ++s->spr_writes;
    return Z6II_BA2_SPR_OK;
}

bool z6ii_ba2_startup_bridge137_irq(void *opaque)
{
    return z6ii_ba2_startup_bridge137_irq_sources(opaque) != 0;
}

uint32_t z6ii_ba2_startup_bridge137_irq_sources(void *opaque)
{
    Z6IIBA2StartupBridge137 *s = opaque;
    if (!z6ii_ba2_startup_bridge137_invariant(s)) {
        return 0;
    }
    return (z6ii_ba2_controller136_irq(s->controller) ? UINT32_C(2) : 0) |
        (z6ii_ba2_engine140_level(s->engine) ? UINT32_C(1) : 0);
}
