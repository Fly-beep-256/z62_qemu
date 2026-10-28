/* SPDX-License-Identifier: GPL-2.0-or-later */
/* An explicitly configured external battery endpoint. Its only runtime input
 * is a completed UART TX byte and its wire timestamp. Immutable TX/RX contracts
 * are compiled before guest start. No MCU RAM, RNG, registers or callbacks.
 * MCU resets do not reset the separately powered battery endpoint. */
#ifndef EX1850_BATTERY_WIRE_CORE_H
#define EX1850_BATTERY_WIRE_CORE_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

#define EX1850_BATTERY_CONTRACTS 128
#define EX1850_BATTERY_FRAME 68
#define EX1850_BATTERY_PENDING 8
#define EX1850_BATTERY_RAW_LIMIT (256 * 1024)

typedef struct EX1850BatteryContract {
    uint8_t tx[EX1850_BATTERY_FRAME], rx[EX1850_BATTERY_FRAME];
    unsigned tx_size, rx_size;
    bool authentication, allowed_before_authentication;
} EX1850BatteryContract;

typedef struct EX1850BatteryReply {
    unsigned contract;
    uint64_t sequence, tx_offset;
    int64_t tx_complete_ns, due;
} EX1850BatteryReply;

typedef struct EX1850BatteryWire {
    EX1850BatteryContract contracts[EX1850_BATTERY_CONTRACTS];
    unsigned contract_count;
    int64_t turnaround_ns;
    int64_t last_tx_ns;
    uint64_t max_replies;
    uint8_t partial[EX1850_BATTERY_FRAME];
    unsigned partial_size;
    EX1850BatteryReply pending[EX1850_BATTERY_PENDING];
    unsigned head, count;
    uint64_t tx_bytes, rx_bytes, valid_frames, replies;
    uint64_t unframed_bytes, invalid_lengths, checksum_failures;
    uint64_t commands[256], auth_requests, ordinary_requests;
    uint64_t unmodeled_requests, auth_mismatches;
    uint8_t unknown_tx[EX1850_BATTERY_FRAME];
    unsigned unknown_tx_size;
    bool authentication_request_seen;
    const char *error;
} EX1850BatteryWire;

static inline uint8_t ex1850_battery_xor(const uint8_t *bytes, unsigned length)
{
    uint8_t value = 0;
    for (unsigned i = 0; i < length; i++) { value ^= bytes[i]; }
    return value;
}

static inline void ex1850_battery_drop(EX1850BatteryWire *w, unsigned length)
{
    w->partial_size -= length;
    memmove(w->partial, w->partial + length, w->partial_size);
}

static inline bool ex1850_battery_fail(EX1850BatteryWire *w, const char *error)
{
    w->error = error;
    return false;
}

static inline bool ex1850_battery_tx(EX1850BatteryWire *w, uint8_t byte,
                                    int64_t now)
{
    if (w->error) { return false; }
    if (now < w->last_tx_ns || w->tx_bytes >= EX1850_BATTERY_RAW_LIMIT ||
        w->partial_size >= EX1850_BATTERY_FRAME) {
        return ex1850_battery_fail(w, "invalid timestamp or TX retention limit");
    }
    w->last_tx_ns = now;
    w->tx_bytes++;
    w->partial[w->partial_size++] = byte;
    while (w->partial_size) {
        if (w->partial[0] != 2) {
            w->unframed_bytes++;
            ex1850_battery_drop(w, 1);
            continue;
        }
        if (w->partial_size < 3) { break; }
        if (w->partial[2] > 64) {
            w->invalid_lengths++;
            ex1850_battery_drop(w, 1);
            continue;
        }
        unsigned length = w->partial[2] + 4;
        if (w->partial_size < length) { break; }
        if (ex1850_battery_xor(w->partial, length)) {
            w->checksum_failures++;
            ex1850_battery_drop(w, 1);
            continue;
        }
        w->valid_frames++;
        w->commands[w->partial[1]]++;
        unsigned i;
        for (i = 0; i < w->contract_count; i++) {
            const EX1850BatteryContract *c = &w->contracts[i];
            if (c->tx_size == length && !memcmp(c->tx, w->partial, length)) {
                break;
            }
        }
        if (i == w->contract_count) {
            memcpy(w->unknown_tx, w->partial, length);
            w->unknown_tx_size = length;
            w->unmodeled_requests++;
            if (length == 21 && w->partial[1] == 1) { w->auth_mismatches++; }
            return ex1850_battery_fail(w, "unmodeled completed battery TX; no reply guessed");
        }
        const EX1850BatteryContract *c = &w->contracts[i];
        if (!c->authentication && !c->allowed_before_authentication &&
            !w->authentication_request_seen) {
            return ex1850_battery_fail(w, "ordinary TX preceded matching authentication request");
        }
        if (w->count >= EX1850_BATTERY_PENDING ||
            w->valid_frames > w->max_replies ||
            w->turnaround_ns < 0 || w->turnaround_ns > INT64_MAX - now) {
            return ex1850_battery_fail(w, "reply budget, queue or virtual deadline overflow");
        }
        if (c->authentication) {
            w->authentication_request_seen = true;
            w->auth_requests++;
        } else {
            w->ordinary_requests++;
        }
        EX1850BatteryReply *r = &w->pending[
            (w->head + w->count++) % EX1850_BATTERY_PENDING];
        *r = (EX1850BatteryReply) {
            .contract = i, .sequence = w->valid_frames,
            .tx_offset = w->tx_bytes - w->partial_size,
            .tx_complete_ns = now, .due = now + w->turnaround_ns,
        };
        ex1850_battery_drop(w, length);
    }
    return true;
}

static inline int64_t ex1850_battery_deadline(const EX1850BatteryWire *w)
{
    return w->count && !w->error ? w->pending[w->head].due : -1;
}

static inline bool ex1850_battery_reply(EX1850BatteryWire *w, int64_t due,
                                       EX1850BatteryReply *reply)
{
    if (!reply || !w->count || w->error ||
        w->pending[w->head].due != due) { return false; }
    *reply = w->pending[w->head];
    unsigned length = w->contracts[reply->contract].rx_size;
    if (w->rx_bytes + length > EX1850_BATTERY_RAW_LIMIT) {
        return ex1850_battery_fail(w, "RX retention limit");
    }
    w->head = (w->head + 1) % EX1850_BATTERY_PENDING;
    w->count--;
    w->replies++;
    w->rx_bytes += length;
    return true;
}
#endif
