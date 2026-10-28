/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Private C1.70 POSTSERV type0 candidate, bound to original contracts100/101.
 * Address halfword0068 TX50+byte, TX1F and RX6 are implemented in v1.
 * Explicit v2 also latches the startup TX2 register set used by 103D7714.
 * This is an explicitly enabled transport experiment, not identified sensor
 * hardware. W1C, mask-set/clear, delay, cancellation, FIFO/reset and source-row
 * policies are model choices. Control OR40 is retained without reset effects.
 * No guest RAM, RTOS callback, Ready flag or GIC access occurs in this core. */
#ifndef NIKON_Z6II_POST68_CORE_H
#define NIKON_Z6II_POST68_CORE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define Z6II_POST68_ADDRESS UINT16_C(0x0068)
#define Z6II_POST68_IRQ_BITS UINT32_C(0x2ff)
#define Z6II_POST68_DONE UINT32_C(1)
#define Z6II_POST68_FIFO UINT32_C(2)
#define Z6II_POST68_NACK UINT32_C(4)
#define Z6II_POST68_OVERFLOW UINT32_C(0x40)
#define Z6II_POST68_RX_BYTES 6u

typedef enum Z6IIPost68Source {
    Z6II_POST68_UNCONFIGURED,
    Z6II_POST68_ACQUIRED,
    Z6II_POST68_SYNTHETIC,
} Z6IIPost68Source;
typedef enum Z6IIPost68Advance {
    Z6II_POST68_ADVANCE_UNSPECIFIED,
    Z6II_POST68_ADVANCE_ON_DRAIN_EXHAUST,
    Z6II_POST68_ADVANCE_ON_DRAIN_HOLD_LAST,
} Z6IIPost68Advance;
typedef enum Z6IIPost68ResetPolicy {
    Z6II_POST68_RESET_UNSPECIFIED,
    Z6II_POST68_RESET_REWIND_ROWS,
    Z6II_POST68_RESET_PRESERVE_ROW_INDEX,
} Z6IIPost68ResetPolicy;
typedef enum Z6IIPost68Result {
    Z6II_POST68_OK,
    Z6II_POST68_BAD_CONFIG,
    Z6II_POST68_UNSUPPORTED_ACCESS,
    Z6II_POST68_BUSY,
    Z6II_POST68_TIME_OR_GENERATION_RANGE,
    Z6II_POST68_EMPTY_FIFO,
} Z6IIPost68Result;
typedef enum Z6IIPost68Reason {
    Z6II_POST68_REASON_NONE,
    Z6II_POST68_REASON_NO_SOURCE,
    Z6II_POST68_REASON_ADDRESS,
    Z6II_POST68_REASON_TX_SHAPE,
    Z6II_POST68_REASON_CONFIG_REQUIRED,
    Z6II_POST68_REASON_COMMAND_REQUIRED,
    Z6II_POST68_REASON_RX_LENGTH,
    Z6II_POST68_REASON_EXHAUSTED,
} Z6IIPost68Reason;

typedef struct Z6IIPost68Config {
    bool experimental_contract;
    bool startup_register_writes; /* v2: observed ROM writes, unknown silicon. */
    unsigned controller; /* Explicit physical lane0..3, not logical bus ID. */
    uint64_t delay_ns;
    Z6IIPost68Source source;
    /* Caller retains immutable bytes and strings for the core lifetime.
     * The loader must hash/validate the exact file before passing rows here;
     * metadata presence alone does not authenticate captured provenance. */
    const uint8_t *rows;
    size_t row_count;
    uint64_t source_bytes;
    const char *source_path, *source_sha256, *source_label;
    Z6IIPost68Advance advance;
    Z6IIPost68ResetPolicy reset_policy;
} Z6IIPost68Config;
typedef struct Z6IIPost68Job {
    uint64_t generation, due_ns;
    uint16_t address;
    bool receive;
    unsigned tx_count, receive_count;
    uint8_t tx[16], row[Z6II_POST68_RX_BYTES];
    size_t row_index;
    Z6IIPost68Reason reason;
} Z6IIPost68Job;
typedef struct Z6IIPost68Core {
    Z6IIPost68Config config;
    bool initialized, pending, config_valid, command_valid, row_reserved;
    uint32_t regs[11];
    uint8_t tx[16], rx[Z6II_POST68_RX_BYTES], config_byte;
    uint8_t register_values[256];
    bool register_written[256];
    unsigned tx_count, rx_count, rx_offset;
    size_t row_index, reserved_row;
    uint64_t generation, submitted, completed, cancelled, nacks, drained_rows;
    Z6IIPost68Job job;
    Z6IIPost68Reason last_reason;
} Z6IIPost68Core;

static inline bool z6ii_post68_nonempty(const char *s)
{ return s && s[0]; }
static inline bool z6ii_post68_digest_valid(const char *s)
{
    if (!s || strlen(s) != 64) { return false; }
    for (unsigned i = 0; i < 64; i++) {
        if (!((s[i] >= '0' && s[i] <= '9') ||
              (s[i] >= 'a' && s[i] <= 'f'))) { return false; }
    }
    return true;
}
static inline bool z6ii_post68_config_valid(const Z6IIPost68Config *c)
{
    if (!c || !c->experimental_contract || c->controller >= 4 || !c->delay_ns ||
        (c->advance != Z6II_POST68_ADVANCE_ON_DRAIN_EXHAUST &&
         c->advance != Z6II_POST68_ADVANCE_ON_DRAIN_HOLD_LAST) ||
        (c->reset_policy != Z6II_POST68_RESET_REWIND_ROWS &&
         c->reset_policy != Z6II_POST68_RESET_PRESERVE_ROW_INDEX)) {
        return false;
    }
    if (c->source == Z6II_POST68_UNCONFIGURED) {
        return !c->rows && !c->row_count && !c->source_bytes &&
               !c->source_path && !c->source_sha256 && !c->source_label;
    }
    return (c->source == Z6II_POST68_ACQUIRED ||
            c->source == Z6II_POST68_SYNTHETIC) && c->rows && c->row_count &&
           c->row_count <= SIZE_MAX / Z6II_POST68_RX_BYTES &&
           c->row_count <= UINT64_MAX / Z6II_POST68_RX_BYTES &&
           c->source_bytes == c->row_count * Z6II_POST68_RX_BYTES &&
           z6ii_post68_nonempty(c->source_path) &&
           z6ii_post68_nonempty(c->source_label) &&
           z6ii_post68_digest_valid(c->source_sha256);
}
static inline Z6IIPost68Result z6ii_post68_init(Z6IIPost68Core *s,
    const Z6IIPost68Config *c)
{
    if (!s || !z6ii_post68_config_valid(c)) { return Z6II_POST68_BAD_CONFIG; }
    memset(s, 0, sizeof(*s));
    s->config = *c; s->initialized = true;
    s->regs[7] = 0xff; s->regs[8] = Z6II_POST68_IRQ_BITS;
    return Z6II_POST68_OK;
}
static inline void z6ii_post68_status(Z6IIPost68Core *s)
{
    s->regs[1] = (s->pending ? 0x100u : 0) |
                 (s->tx_count ? 0x40u : 0) | (s->rx_count ? 0x20u : 0);
}
static inline bool z6ii_post68_irq_pending(const Z6IIPost68Core *s)
{
    return s && s->initialized &&
        (s->regs[4] & ~s->regs[8] & Z6II_POST68_IRQ_BITS);
}
static inline bool z6ii_post68_startup_register(uint8_t reg)
{
    /* Original 103D7714 configuration, including repeated writes to 76.
     * Values are guest profile bytes; no physical meanings are inferred. */
    switch (reg) {
    case 0x11: case 0x13: case 0x4c: case 0x76: case 0x7a: case 0x7c:
    case 0x03: case 0x04: case 0x05: case 0x51: case 0x52: case 0x53:
    case 0x50: case 0x4e:
        return true;
    default:
        return false;
    }
}
static inline Z6IIPost68Reason z6ii_post68_job_reason(
    const Z6IIPost68Core *s, const Z6IIPost68Job *j)
{
    if (s->config.source == Z6II_POST68_UNCONFIGURED) {
        return Z6II_POST68_REASON_NO_SOURCE;
    }
    if (j->address != Z6II_POST68_ADDRESS) { return Z6II_POST68_REASON_ADDRESS; }
    if (!j->receive) {
        if ((j->tx_count == 2 && (j->tx[0] == 0x50 ||
             (s->config.startup_register_writes &&
              z6ii_post68_startup_register(j->tx[0])))) ||
            (j->tx_count == 1 && j->tx[0] == 0x1f)) {
            return (j->tx[0] == 0x1f && !s->config_valid) ?
                Z6II_POST68_REASON_CONFIG_REQUIRED : Z6II_POST68_REASON_NONE;
        }
        return Z6II_POST68_REASON_TX_SHAPE;
    }
    if (!s->config_valid) { return Z6II_POST68_REASON_CONFIG_REQUIRED; }
    if (!s->command_valid) { return Z6II_POST68_REASON_COMMAND_REQUIRED; }
    if (j->receive_count != Z6II_POST68_RX_BYTES) { return Z6II_POST68_REASON_RX_LENGTH; }
    if (s->row_index >= s->config.row_count) { return Z6II_POST68_REASON_EXHAUSTED; }
    return Z6II_POST68_REASON_NONE;
}
static inline Z6IIPost68Result z6ii_post68_launch(Z6IIPost68Core *s,
    uint16_t address, uint64_t now_ns)
{
    if (s->pending || s->rx_count || (s->regs[4] & Z6II_POST68_IRQ_BITS)) {
        /* Do not let an old raw DONE satisfy a new transaction. The original
         * ISR must W1C the old source and drain the old FIFO before reusing. */
        return Z6II_POST68_BUSY;
    }
    if (!(s->regs[0] & 2)) { return Z6II_POST68_UNSUPPORTED_ACCESS; }
    if (s->generation == UINT64_MAX || s->submitted == UINT64_MAX ||
        now_ns > UINT64_MAX - s->config.delay_ns) {
        return Z6II_POST68_TIME_OR_GENERATION_RANGE;
    }
    Z6IIPost68Job j = {0};
    j.generation = ++s->generation; j.due_ns = now_ns + s->config.delay_ns;
    j.address = address; j.receive = (s->regs[0] & 1) != 0;
    j.tx_count = s->tx_count; j.receive_count = s->regs[5];
    memcpy(j.tx, s->tx, s->tx_count);
    j.reason = z6ii_post68_job_reason(s, &j);
    if (j.receive && j.reason == Z6II_POST68_REASON_NONE) {
        j.row_index = s->row_index;
        memcpy(j.row, s->config.rows + j.row_index * Z6II_POST68_RX_BYTES,
               Z6II_POST68_RX_BYTES);
    }
    s->regs[2] = address; s->job = j; s->pending = true;
    ++s->submitted; s->last_reason = j.reason; z6ii_post68_status(s);
    /* TX prelaunch FIFO is intentionally intact until this job consumes it. */
    return Z6II_POST68_OK;
}
static inline bool z6ii_post68_next_due(const Z6IIPost68Core *s,
    uint64_t *due_ns, uint64_t *generation)
{
    if (!s || !due_ns || !generation || !s->initialized || !s->pending) {
        return false;
    }
    *due_ns = s->job.due_ns; *generation = s->job.generation; return true;
}
static inline bool z6ii_post68_complete(Z6IIPost68Core *s,
    unsigned captured_controller, uint64_t captured_generation, uint64_t now_ns)
{
    if (!s || !s->initialized || !s->pending ||
        captured_controller != s->config.controller ||
        captured_generation != s->job.generation ||
        captured_generation != s->generation || now_ns < s->job.due_ns ||
        s->completed == UINT64_MAX ||
        (s->job.reason != Z6II_POST68_REASON_NONE && s->nacks == UINT64_MAX)) {
        return false;
    }
    s->pending = false; ++s->completed;
    if (!s->job.receive) { s->tx_count = 0; memset(s->tx, 0, sizeof(s->tx)); }
    if (s->job.reason != Z6II_POST68_REASON_NONE) {
        ++s->nacks; s->regs[4] |= Z6II_POST68_NACK;
        if (!s->job.receive) { s->command_valid = false; }
    } else if (s->job.receive) {
        memcpy(s->rx, s->job.row, sizeof(s->rx)); s->rx_count = sizeof(s->rx);
        s->rx_offset = 0; s->regs[5] = sizeof(s->rx);
        s->row_reserved = true; s->reserved_row = s->job.row_index;
        /* All six bytes exist before DONE becomes observable. */
        s->regs[4] |= Z6II_POST68_DONE;
    } else {
        if (s->job.tx_count == 2) {
            uint8_t reg = s->job.tx[0];
            s->register_values[reg] = s->job.tx[1];
            s->register_written[reg] = true;
            if (reg == 0x50) {
                s->config_byte = s->job.tx[1]; s->config_valid = true;
            }
            s->command_valid = false;
        } else { s->command_valid = true; }
        s->regs[4] |= Z6II_POST68_DONE;
    }
    z6ii_post68_status(s); return true;
}
static inline Z6IIPost68Result z6ii_post68_cancel(Z6IIPost68Core *s)
{
    if (!s || !s->initialized) { return Z6II_POST68_BAD_CONFIG; }
    if (s->generation == UINT64_MAX || (s->pending && s->cancelled == UINT64_MAX)) {
        return Z6II_POST68_TIME_OR_GENERATION_RANGE;
    }
    ++s->generation;
    if (s->pending) {
        ++s->cancelled;
        /* Abort discards only the active TX. A prelaunch FIFO and already
         * arrived RX remain available. Cancelled RX does not consume a row. */
        if (!s->job.receive) { s->tx_count = 0; memset(s->tx, 0, sizeof(s->tx)); }
    }
    s->pending = false; memset(&s->job, 0, sizeof(s->job));
    z6ii_post68_status(s); return Z6II_POST68_OK;
}
static inline Z6IIPost68Result z6ii_post68_board_reset(Z6IIPost68Core *s)
{
    Z6IIPost68Result r = z6ii_post68_cancel(s);
    if (r != Z6II_POST68_OK) { return r; }
    memset(s->regs, 0, sizeof(s->regs)); s->regs[7] = 0xff;
    s->regs[8] = Z6II_POST68_IRQ_BITS;
    memset(s->tx, 0, sizeof(s->tx)); memset(s->rx, 0, sizeof(s->rx));
    memset(s->register_values, 0, sizeof(s->register_values));
    memset(s->register_written, 0, sizeof(s->register_written));
    s->tx_count = s->rx_count = s->rx_offset = 0;
    s->config_valid = s->command_valid = s->row_reserved = false;
    s->config_byte = 0; s->reserved_row = 0; s->last_reason = Z6II_POST68_REASON_NONE;
    if (s->config.reset_policy == Z6II_POST68_RESET_REWIND_ROWS) { s->row_index = 0; }
    /* Generation and audit counters never rewind, so old timers stay stale. */
    return Z6II_POST68_OK;
}
static inline Z6IIPost68Result z6ii_post68_access(Z6IIPost68Core *s,
    unsigned offset, unsigned size, bool write, uint64_t *value, uint64_t now_ns)
{
    if (!s || !s->initialized) { return Z6II_POST68_BAD_CONFIG; }
    if (!value || size != 4 || offset > 0x28 || (offset & 3)) {
        return Z6II_POST68_UNSUPPORTED_ACCESS;
    }
    unsigned i = offset / 4;
    uint32_t mask = i == 0 ? 0xffffu : i == 2 ? 0x3ffu :
                    i == 3 || i == 7 ? 0xffu : i == 5 ? 0x3fu :
                    i == 6 ? 0xfu : Z6II_POST68_IRQ_BITS;
    if (!write) {
        if (i == 3) {
            if (!s->rx_count) { return Z6II_POST68_EMPTY_FIFO; }
            if (s->rx_count == 1 && s->drained_rows == UINT64_MAX) {
                return Z6II_POST68_TIME_OR_GENERATION_RANGE;
            }
            *value = s->rx[s->rx_offset++]; --s->rx_count; s->regs[5] = s->rx_count;
            if (!s->rx_count && s->row_reserved) {
                ++s->drained_rows;
                s->row_index = s->reserved_row + 1;
                if (s->row_index == s->config.row_count &&
                    s->config.advance == Z6II_POST68_ADVANCE_ON_DRAIN_HOLD_LAST) {
                    --s->row_index;
                }
                s->row_reserved = false; s->command_valid = false;
            }
            z6ii_post68_status(s); return Z6II_POST68_OK;
        }
        *value = i == 5 && !(s->regs[0] & 1) ? s->tx_count :
                 i >= 9 ? 0 : s->regs[i];
        return Z6II_POST68_OK;
    }
    if (i == 1 || i == 8 || (*value & ~(uint64_t)mask)) {
        return Z6II_POST68_UNSUPPORTED_ACCESS;
    }
    if (i == 0) {
        /* Unknown OR40 semantics: no FIFO reset or automatic bit clearing. */
        s->regs[0] = (uint32_t)*value;
    } else if (i == 2) {
        return z6ii_post68_launch(s, (uint16_t)*value, now_ns);
    } else if (i == 3) {
        if (s->pending) { return Z6II_POST68_BUSY; }
        if (s->tx_count == sizeof(s->tx)) {
            s->regs[4] |= Z6II_POST68_OVERFLOW; return Z6II_POST68_UNSUPPORTED_ACCESS;
        }
        s->tx[s->tx_count++] = (uint8_t)*value;
    } else if (i == 4) { s->regs[4] &= ~(uint32_t)*value; }
    else if (i == 9) { s->regs[8] &= ~(uint32_t)*value; }
    else if (i == 10) {
        if ((*value & Z6II_POST68_IRQ_BITS) == Z6II_POST68_IRQ_BITS) {
            Z6IIPost68Result r = z6ii_post68_cancel(s);
            if (r != Z6II_POST68_OK) { return r; }
        }
        s->regs[8] |= (uint32_t)*value;
    } else {
        if (s->pending && i == 5) { return Z6II_POST68_BUSY; }
        s->regs[i] = (uint32_t)*value;
    }
    z6ii_post68_status(s); return Z6II_POST68_OK;
}
static inline const char *z6ii_post68_reason_name(Z6IIPost68Reason r)
{
    switch (r) {
    case Z6II_POST68_REASON_NONE: return "none";
    case Z6II_POST68_REASON_NO_SOURCE: return "unconfigured-source";
    case Z6II_POST68_REASON_ADDRESS: return "unsupported-address";
    case Z6II_POST68_REASON_TX_SHAPE: return "unsupported-tx-shape";
    case Z6II_POST68_REASON_CONFIG_REQUIRED: return "config50-required";
    case Z6II_POST68_REASON_COMMAND_REQUIRED: return "command1f-required";
    case Z6II_POST68_REASON_RX_LENGTH: return "rx-length-must-be6";
    case Z6II_POST68_REASON_EXHAUSTED: return "source-rows-exhausted";
    default: return "invalid-reason";
    }
}
#endif
