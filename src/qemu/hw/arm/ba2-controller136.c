/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "ba2-controller136.h"
#include <string.h>

static bool live(const Z6IIBA2Controller136 *s)
{
    return s && s->initialized && s->bus && s->bus->initialized &&
        s->master && s->bus->config.master_fifo == s->master &&
        s->master->signature == 0x100 &&
        s->bus->config.master_irq_update &&
        z6ii_ipu2402_invariant(s->master);
}

bool z6ii_ba2_controller136_invariant(const Z6IIBA2Controller136 *s)
{
    return live(s) && s->policy &&
        !strcmp(s->policy, Z6II_BA2_CONTROLLER136_POLICY) &&
        s->basis && *s->basis && s->rx_next <= 3 && s->tx_staged <= 3 &&
        s->control == 0 &&
        s->threshold_config == (s->threshold_configured ? 0x1d00u : 0u) &&
        s->tx_word_writes == s->tx_frames_committed * 3 + s->tx_staged +
                             s->reset_discarded_tx_words &&
        s->rx_frames_taken * 3 == s->rx_read_words + (3u - s->rx_next) +
                                 s->reset_discarded_rx_words;
}

Z6IIBA2BusResult z6ii_ba2_controller136_init(Z6IIBA2Controller136 *s,
    Z6IIBA2Bus *bus, const char *policy, const char *basis)
{
    if (!s) {
        return Z6II_BA2_BUS_BAD_CONFIG;
    }
    memset(s, 0, sizeof(*s));
    s->rx_next = 3;
    if (!bus || !bus->initialized || !policy ||
        strcmp(policy, Z6II_BA2_CONTROLLER136_POLICY) || !basis || !*basis ||
        !bus->config.master_fifo ||
        bus->config.master_fifo->signature != 0x100 ||
        !bus->config.master_irq_update ||
        !z6ii_ipu2402_invariant(bus->config.master_fifo)) {
        return Z6II_BA2_BUS_BAD_CONFIG;
    }
    s->bus = bus;
    s->master = bus->config.master_fifo;
    s->policy = policy;
    s->basis = basis;
    s->initialized = true;
    return Z6II_BA2_BUS_OK;
}

void z6ii_ba2_controller136_reset(Z6IIBA2Controller136 *s)
{
    if (!s || !s->initialized || s->rx_next > 3 || s->tx_staged > 3) {
        return;
    }
    s->reset_discarded_rx_words += 3u - s->rx_next;
    s->reset_discarded_tx_words += s->tx_staged;
    memset(s->rx_frame, 0, sizeof(s->rx_frame));
    memset(s->tx_stage, 0, sizeof(s->tx_stage));
    s->rx_next = 3;
    s->tx_staged = 0;
    s->threshold_config = 0;
    s->threshold_configured = false;
    s->interrupt_mask = 0;
    s->event_latch = 0;
    s->control = 0;
}

static unsigned rx_available(const Z6IIBA2Controller136 *s)
{
    /* Uncommitted Master TX staging is never visible here. */
    return s->master->tx_committed + (3u - s->rx_next);
}

static unsigned tx_occupied(const Z6IIBA2Controller136 *s)
{
    return s->master->rx.count + s->tx_staged;
}

uint32_t z6ii_ba2_controller136_raw(const Z6IIBA2Controller136 *s)
{
    if (!z6ii_ba2_controller136_invariant(s)) {
        return 0;
    }
    uint32_t raw = s->event_latch;
    if (rx_available(s) >= Z6II_IPU2402_FRAME_WORDS) {
        raw |= Z6II_IPU2402_RX_READY;
    }
    if (s->threshold_configured &&
        tx_occupied(s) <= (s->threshold_config >> 8)) {
        raw |= Z6II_IPU2402_TX_SPACE;
    }
    return raw;
}

bool z6ii_ba2_controller136_irq(void *opaque)
{
    const Z6IIBA2Controller136 *s = opaque;
    return s && (z6ii_ba2_controller136_raw(s) & s->interrupt_mask) != 0;
}

static Z6IIBA2BusResult guard(const Z6IIBA2Controller136 *s,
                             uint32_t addr, unsigned size)
{
    if (!z6ii_ba2_controller136_invariant(s)) {
        return Z6II_BA2_BUS_BAD_CONFIG;
    }
    if (size != 4) {
        return Z6II_BA2_BUS_BAD_WIDTH;
    }
    if (addr & 3) {
        return Z6II_BA2_BUS_BAD_ALIGNMENT;
    }
    if (addr < Z6II_BA2_CONTROLLER136_BASE ||
        addr - Z6II_BA2_CONTROLLER136_BASE >= Z6II_BA2_CONTROLLER136_BYTES) {
        return Z6II_BA2_BUS_UNMAPPED;
    }
    return Z6II_BA2_BUS_OK;
}

Z6IIBA2BusResult z6ii_ba2_controller136_read(void *opaque, uint32_t addr,
                                          unsigned size, uint32_t *out)
{
    Z6IIBA2Controller136 *s = opaque;
    Z6IIBA2BusResult r = guard(s, addr, size);
    if (r != Z6II_BA2_BUS_OK) {
        return r;
    }
    if (!out) {
        return Z6II_BA2_BUS_BAD_CONFIG;
    }
    uint32_t value;
    switch (addr - Z6II_BA2_CONTROLLER136_BASE) {
    case 0x00:
        if (s->rx_next == 3) {
            uint32_t frame[3];
            if (z6ii_ba2_bus_take_tx(s->bus, frame) != Z6II_IPU2402_OK) {
                return Z6II_BA2_BUS_DEVICE_FAULT;
            }
            memcpy(s->rx_frame, frame, sizeof(frame));
            s->rx_next = 0;
            ++s->rx_frames_taken;
        }
        value = s->rx_frame[s->rx_next++];
        ++s->rx_read_words;
        break;
    case 0x0c:
        value = (tx_occupied(s) << 8) | rx_available(s);
        break;
    case 0x10: value = s->threshold_config; break;
    case 0x14: value = z6ii_ba2_controller136_raw(s); break;
    case 0x1c: value = s->interrupt_mask; break;
    case 0x20: value = s->control; break;
    default:
        return Z6II_BA2_BUS_PERMISSION;
    }
    *out = value;
    return Z6II_BA2_BUS_OK;
}

Z6IIBA2BusResult z6ii_ba2_controller136_write(void *opaque, uint32_t addr,
                                           unsigned size, uint32_t value)
{
    Z6IIBA2Controller136 *s = opaque;
    Z6IIBA2BusResult r = guard(s, addr, size);
    if (r != Z6II_BA2_BUS_OK) {
        return r;
    }
    switch (addr - Z6II_BA2_CONTROLLER136_BASE) {
    case 0x04:
        if (s->tx_staged == Z6II_IPU2402_FRAME_WORDS ||
            tx_occupied(s) >= Z6II_IPU2402_WORDS) {
            return Z6II_BA2_BUS_DEVICE_FAULT;
        }
        s->tx_stage[s->tx_staged++] = value;
        ++s->tx_word_writes;
        return Z6II_BA2_BUS_OK;
    case 0x08:
        if (value == 2 || value == 3) {
            /* Original reset uses 2; original 40009369 response uses 3.
             * Both require a complete staged triplet. Bit0's independent
             * silicon meaning remains unproved; no event/Ready is invented. */
            if (s->tx_staged != Z6II_IPU2402_FRAME_WORDS ||
                z6ii_ba2_bus_push_rx(s->bus, s->tx_stage) != Z6II_IPU2402_OK) {
                return Z6II_BA2_BUS_DEVICE_FAULT;
            }
            s->tx_staged = 0;
            ++s->tx_frames_committed;
            return Z6II_BA2_BUS_OK;
        }
        if (value == 4) {
            /* Transport ACK: candidate read-pop already consumed a word.
             * It neither fabricates a protocol response nor clears a level. */
            ++s->rx_acknowledgements;
            return Z6II_BA2_BUS_OK;
        }
        return Z6II_BA2_BUS_DEVICE_FAULT;
    case 0x10:
        if (value != 0x1d00) {
            return Z6II_BA2_BUS_DEVICE_FAULT;
        }
        s->threshold_config = value;
        s->threshold_configured = true;
        return Z6II_BA2_BUS_OK;
    case 0x18:
        s->event_latch &= ~value;
        return Z6II_BA2_BUS_OK;
    case 0x1c:
        s->interrupt_mask = value;
        return Z6II_BA2_BUS_OK;
    case 0x20:
        if (value != 0) {
            return Z6II_BA2_BUS_DEVICE_FAULT;
        }
        s->control = value;
        return Z6II_BA2_BUS_OK;
    default:
        return Z6II_BA2_BUS_PERMISSION;
    }
}
