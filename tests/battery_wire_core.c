/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <assert.h>
#include <stdio.h>
#include "ex1850-battery-wire-core.h"
#include "ex1850-usart1-rx-core.h"

static EX1850BatteryWire wire(void)
{
    EX1850BatteryWire w = { .contract_count = 1, .turnaround_ns = 2000000, .max_replies = 8 };
    EX1850BatteryContract *c = &w.contracts[0];
    const uint8_t tx[] = {2, 0x89, 0, 0x8b}, rx[] = {2, 6, 0, 4};
    memcpy(c->tx, tx, sizeof(tx)); memcpy(c->rx, rx, sizeof(rx));
    c->tx_size = sizeof(tx); c->rx_size = sizeof(rx);
    c->allowed_before_authentication = true;
    return w;
}

static void request(EX1850BatteryWire *w, int64_t first)
{
    for (unsigned i = 0; i < w->contracts[0].tx_size; i++) {
        assert(ex1850_battery_tx(w, w->contracts[0].tx[i], first + i * 1000));
    }
}

static EX1850USART2 uart(void)
{
    EX1850USART2 u = {0};
    ex1850_usart2_reset(&u, 0);
    ex1850_usart2_clocks(&u, 48000000, true, false, 0);
    u.brr = 416;
    u.cr1 = EX1850_U2_UE | EX1850_U2_TE | EX1850_U2_RE;
    return u;
}

int main(void)
{
    EX1850BatteryWire w = wire();
    for (unsigned i = 0; i < 3; i++) {
        assert(ex1850_battery_tx(&w, w.contracts[0].tx[i], 1000 + i * 1000));
        assert(ex1850_battery_deadline(&w) == -1);
    }
    assert(ex1850_battery_tx(&w, w.contracts[0].tx[3], 4000));
    assert(ex1850_battery_deadline(&w) == 2004000);
    EX1850BatteryReply reply;
    assert(!ex1850_battery_reply(&w, 2003999, &reply));
    assert(w.replies == 0);
    assert(ex1850_battery_reply(&w, 2004000, &reply));
    assert(reply.tx_complete_ns == 4000 && reply.tx_offset == 0);
    puts("PASS reply requires final TX completion and exact virtual deadline");

    EX1850USART2 u = uart();
    EX1850USART1Rx r;
    ex1850_usart1_rx_reset(&r);
    u.cr1 &= ~EX1850_U2_RE;
    assert(ex1850_usart1_rx_push(&r, &u, w.contracts[0].rx, 4, reply.due));
    assert(r.discarded == 4 && r.admitted == 0 && r.count == 0);
    u.cr1 |= EX1850_U2_RE;
    assert(ex1850_usart1_rx_deadline(&r) == -1);
    puts("PASS disabled receiver discards input without deferred replay");

    assert(ex1850_usart1_rx_push(&r, &u, w.contracts[0].rx, 4, reply.due));
    int64_t first_due = ex1850_usart1_rx_deadline(&r);
    uint16_t word;
    assert(first_due > reply.due);
    assert(!ex1850_usart1_rx_complete(&r, &u, first_due - 1, &word));
    assert(ex1850_usart1_rx_complete(&r, &u, first_due, &word) && word == 2);
    assert(r.completed == 1 && r.count == 3);
    puts("PASS received data reaches UART DR only at the serial frame deadline");

    w = wire(); request(&w, first_due);
    int64_t external_due = ex1850_battery_deadline(&w);
    assert(ex1850_usart1_rx_cancel(&r) == 3);
    ex1850_usart2_reset(&u, first_due);
    assert(ex1850_battery_deadline(&w) == external_due);
    assert(ex1850_battery_reply(&w, external_due, &reply));
    assert(ex1850_usart1_rx_push(&r, &u, w.contracts[0].rx, 4, external_due));
    assert(r.count == 0 && r.discarded == 11);
    puts("PASS MCU reset cancels UART input while the external battery deadline survives");

    u = uart(); ex1850_usart1_rx_reset(&r);
    assert(ex1850_usart1_rx_push(&r, &u, w.contracts[0].rx, 4, 1));
    u.brr++;
    assert(ex1850_usart1_rx_reconcile(&r, &u) == 4 && r.count == 0);
    puts("PASS UART format change cancels queued serial input");

    w = wire();
    const uint8_t unknown[] = {2, 0x88, 0, 0x8a};
    for (unsigned i = 0; i < 3; i++) { assert(ex1850_battery_tx(&w, unknown[i], i)); }
    assert(!ex1850_battery_tx(&w, unknown[3], 3));
    assert(w.unmodeled_requests == 1 && w.replies == 0 && w.count == 0);
    puts("PASS unknown completed TX stops without a guessed reply");

    w = wire(); w.contracts[0].allowed_before_authentication = false;
    for (unsigned i = 0; i < 3; i++) { assert(ex1850_battery_tx(&w, w.contracts[0].tx[i], i)); }
    assert(!ex1850_battery_tx(&w, w.contracts[0].tx[3], 3) && w.count == 0);
    puts("PASS ordinary request cannot bypass the declared authentication contract");

    w = wire(); assert(ex1850_battery_tx(&w, 0, 100));
    assert(!ex1850_battery_tx(&w, 0, 99));
    puts("PASS wire input rejects regressing virtual time");
    return 0;
}
