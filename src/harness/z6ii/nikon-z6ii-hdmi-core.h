/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Z6II C1.70 HPD/DDC and transmitter configuration model. This is a causal
 * implementation proposal based
 * on original Master byte accesses, not a measured HDMI silicon model.
 * No guest memory, GIC routing, video, audio or recorder control lives here. */
#ifndef NIKON_Z6II_HDMI_CORE_H
#define NIKON_Z6II_HDMI_CORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Original 10481C32/10481C62 read, clear/set the low five bits here.
 * 10481C72/10481D46 similarly read/modify/write TX control. Byte readback
 * is modeled; zero reset values and downstream physical effects are not
 * measured. These latches issue no completion, FIFO data or GIC event. */
#define Z6II_HDMI_POWER_MASK_ADDR UINT32_C(0x20170004)
#define Z6II_HDMI_TX_CONTROL_ADDR UINT32_C(0x2016c000)
#define Z6II_HDMI_HPD_ADDR UINT32_C(0x2016c010)
#define Z6II_HDMI_STATUS_ADDR UINT32_C(0x20160414)
#define Z6II_HDMI_SUMMARY_ADDR UINT32_C(0x201605c0)
#define Z6II_HDMI_DEVICE_ADDR UINT32_C(0x2017f800)
#define Z6II_HDMI_OFFSET_ADDR UINT32_C(0x2017f804)
#define Z6II_HDMI_SINGLE_ADDR UINT32_C(0x2017f80c)
#define Z6II_HDMI_COMMAND_ADDR UINT32_C(0x2017f810)
#define Z6II_HDMI_SEGMENT_DEVICE_ADDR UINT32_C(0x2017f820)
#define Z6II_HDMI_SEGMENT_ADDR UINT32_C(0x2017f828)
#define Z6II_HDMI_FIFO_ADDR UINT32_C(0x2017f880)
#define Z6II_HDMI_DONE UINT8_C(0x02)
#define Z6II_HDMI_ERROR UINT8_C(0x01)
#define Z6II_HDMI_EDID_MAX_BYTES (128u * 256u)
#define Z6II_HDMI_PACKET_BASE UINT32_C(0x20164000)
#define Z6II_HDMI_PACKET_LAST UINT32_C(0x20164610)
#define Z6II_HDMI_PACKET_SLOTS \
    ((Z6II_HDMI_PACKET_LAST - Z6II_HDMI_PACKET_BASE) / 4u + 1u)

/* The original 10481D9E and 104820D0..10482E28 setters use these byte registers with
 * four-byte spacing. Keep holes unowned: this does not implement an entire
 * Frame Composer address window. Values are retained for the transmitter;
 * packet enables/manual requests alone do not produce data or completion.
 * Zero reset/readback is a model policy, not a measured silicon reset. */
static inline bool z6ii_hdmi_packet_owns(uint32_t addr)
{
    uint32_t slot = addr & ~UINT32_C(3);
    if (slot < Z6II_HDMI_PACKET_BASE || slot > Z6II_HDMI_PACKET_LAST) {
        return false;
    }
    unsigned offset = slot - Z6II_HDMI_PACKET_BASE;
    return offset <= 0x0a8 || /* video timing, duration/preamble, AVI/audio */
           (offset >= 0x0c0 && offset <= 0x1bc) || /* payload, SPD, ISRC */
           offset == 0x1d4 ||                    /* ACP type */
           (offset >= 0x208 && offset <= 0x314) || /* ACP, ISRC, scheduling */
           offset == 0x348 || offset == 0x358 || offset == 0x368 || /* FC masks */
           (offset >= 0x380 && offset <= 0x38c) ||
           (offset >= 0x3a0 && offset <= 0x3a8) || /* active space */
           (offset >= 0x400 && offset <= 0x480) || /* additional packet */
           (offset >= 0x4a0 && offset <= 0x514) ||
           (offset >= 0x520 && offset <= 0x590) ||
           (offset >= 0x59c && offset <= 0x610);
}

/* Original input sampler / packetizer / output-control configuration and
 * 10482EE0 PHY-I2C mask registers. Only the documented byte locations are
 * retained. These settings do not create pixels, status or an IRQ. The PHY
 * transaction and PLL cores remain the owners of their live status. */
static inline bool z6ii_hdmi_video_config_owns(uint32_t addr)
{
    switch (addr & ~UINT32_C(3)) {
    case UINT32_C(0x20160800):
    case UINT32_C(0x20162004):
    case UINT32_C(0x20162008):
    case UINT32_C(0x2016200c):
    case UINT32_C(0x20162010):
    case UINT32_C(0x2016201c):
    case UINT32_C(0x2016c408):
    case UINT32_C(0x2016c410):
    case UINT32_C(0x20170010): return true;
    default: return false;
    }
}

static inline bool z6ii_hdmi_video_status_owns(uint32_t addr)
{
    switch (addr & ~UINT32_C(3)) {
    case UINT32_C(0x20160400):
    case UINT32_C(0x20160404):
    case UINT32_C(0x20160408):
    case UINT32_C(0x2016041c): return true;
    default: return false;
    }
}

typedef enum Z6IIHDMIJob {
    Z6II_HDMI_JOB_NONE,
    Z6II_HDMI_JOB_READ,
    Z6II_HDMI_JOB_ERROR,
    Z6II_HDMI_JOB_RESET,
    Z6II_HDMI_JOB_TIMEOUT,
} Z6IIHDMIJob;

typedef enum Z6IIHDMIFault {
    Z6II_HDMI_FAULT_NONE,
    Z6II_HDMI_FAULT_ERROR,
    Z6II_HDMI_FAULT_TIMEOUT,
} Z6IIHDMIFault;

typedef enum Z6IIHDMIAccess {
    Z6II_HDMI_ACCESS_OK,
    Z6II_HDMI_ACCESS_NOT_OWNED,
    Z6II_HDMI_ACCESS_BAD_WIDTH_OR_DIRECTION,
    Z6II_HDMI_ACCESS_UNSUPPORTED,
    Z6II_HDMI_ACCESS_BUSY,
    Z6II_HDMI_ACCESS_FIFO_NOT_READY,
    Z6II_HDMI_ACCESS_ACTIVE_RESET_BOUNDARY,
} Z6IIHDMIAccess;

typedef struct Z6IIHDMIHPDEvent {
    uint64_t offset_ns;
    bool connected;
} Z6IIHDMIHPDEvent;

typedef struct Z6IIHDMICore {
    const uint8_t *edid;
    size_t edid_bytes;
    bool connected, fifo_valid;
    uint8_t device, offset, segment_device, segment, command, status;
    uint8_t power_mask, tx_control;
    uint8_t packet[Z6II_HDMI_PACKET_SLOTS];
    uint8_t input_sampler, packetizer[8], output_control, phy_i2c_masks[2];
    uint8_t fc_status[3], vp_status;
    uint8_t fifo[8];
    uint8_t request_device, request_offset, request_segment_device;
    uint8_t request_segment, request_command;
    size_t request_index;
    Z6IIHDMIJob job;
    Z6IIHDMIFault fault;
    uint64_t delay_ns, due_ns, generation, job_generation, fault_request;
    uint64_t submitted_reads, completed_reads, errors, acknowledgements;
    uint64_t cancelled_jobs, rejected_submissions, stale_callbacks, fifo_reads;
} Z6IIHDMICore;

static inline void z6ii_hdmi_packet_reset(Z6IIHDMICore *s)
{
    memset(s->packet, 0, sizeof(s->packet));
}

static inline void z6ii_hdmi_config_reset(Z6IIHDMICore *s)
{
    z6ii_hdmi_packet_reset(s);
    s->input_sampler = s->output_control = s->vp_status = 0;
    memset(s->packetizer, 0, sizeof(s->packetizer));
    memset(s->phy_i2c_masks, 0, sizeof(s->phy_i2c_masks));
    memset(s->fc_status, 0, sizeof(s->fc_status));
}

static inline bool z6ii_hdmi_core_edid_valid(const uint8_t *data, size_t bytes)
{
    static const uint8_t header[8] = { 0, 255, 255, 255, 255, 255, 255, 0 };
    if (!data || bytes < 128 || bytes > Z6II_HDMI_EDID_MAX_BYTES ||
        bytes % 128 || memcmp(data, header, sizeof(header)) ||
        (size_t)data[126] + 1 != bytes / 128) {
        return false;
    }
    for (size_t block = 0; block < bytes; block += 128) {
        unsigned sum = 0;
        for (size_t i = 0; i < 128; i++) {
            sum += data[block + i];
        }
        if (sum & 255) {
            return false;
        }
    }
    return true;
}

static inline bool z6ii_hdmi_core_init(Z6IIHDMICore *s, const uint8_t *edid,
                                     size_t bytes, bool connected,
                                     uint64_t delay_ns)
{
    if (!delay_ns || !z6ii_hdmi_core_edid_valid(edid, bytes)) {
        return false;
    }
    memset(s, 0, sizeof(*s));
    s->edid = edid;
    s->edid_bytes = bytes;
    s->connected = connected;
    s->delay_ns = delay_ns;
    return true;
}

static inline uint64_t z6ii_hdmi_core_next_generation(Z6IIHDMICore *s)
{
    if (++s->generation == 0) {
        ++s->generation;
    }
    return s->generation;
}

static inline bool z6ii_hdmi_core_irq_pending(const Z6IIHDMICore *s)
{
    /* This is a source-pending predicate, not a silicon mask or GIC route. */
    return (s->status & (Z6II_HDMI_DONE | Z6II_HDMI_ERROR)) != 0;
}

static inline bool z6ii_hdmi_core_next_due(const Z6IIHDMICore *s,
                                         uint64_t *due_ns)
{
    if (s->job == Z6II_HDMI_JOB_NONE || s->job == Z6II_HDMI_JOB_TIMEOUT) {
        return false;
    }
    *due_ns = s->due_ns;
    return true;
}

static inline void z6ii_hdmi_core_cancel(Z6IIHDMICore *s, bool notify_error)
{
    bool unfinished = s->job != Z6II_HDMI_JOB_NONE;
    z6ii_hdmi_core_next_generation(s);
    s->job_generation = 0;
    s->job = Z6II_HDMI_JOB_NONE;
    s->due_ns = 0;
    if (unfinished) {
        ++s->cancelled_jobs;
        if (notify_error) {
            s->status = (s->status & ~Z6II_HDMI_DONE) | Z6II_HDMI_ERROR;
            s->fifo_valid = false;
            ++s->errors;
        }
    }
    /* A previously completed, latched chunk survives idle cancellation. */
}

static inline void z6ii_hdmi_core_set_hpd(Z6IIHDMICore *s, bool connected)
{
    if (s->connected == connected) {
        return;
    }
    s->connected = connected;
    if (!connected) {
        /* Failed-job notification on unplug is an explicit model policy. */
        z6ii_hdmi_core_cancel(s, true);
    }
}

static inline void z6ii_hdmi_core_start(Z6IIHDMICore *s, Z6IIHDMIJob job,
                                      uint64_t now_ns)
{
    s->job = job;
    s->job_generation = z6ii_hdmi_core_next_generation(s);
    s->due_ns = now_ns > UINT64_MAX - s->delay_ns ? UINT64_MAX :
                now_ns + s->delay_ns;
}

static inline Z6IIHDMIAccess z6ii_hdmi_core_submit(Z6IIHDMICore *s,
                                                uint8_t command,
                                                uint64_t now_ns)
{
    if (command & 0x20) {
        if (command != 0x20 && command != 0x24 && command != 0x28) {
            return Z6II_HDMI_ACCESS_UNSUPPORTED;
        }
        if (s->job != Z6II_HDMI_JOB_NONE) {
            s->command = command;
            z6ii_hdmi_core_cancel(s, false);
            /* Guest active/reset recovery is not established. No completion
             * is issued that the active ISR could misread as received data. */
            return Z6II_HDMI_ACCESS_ACTIVE_RESET_BOUNDARY;
        }
        if (z6ii_hdmi_core_irq_pending(s)) {
            ++s->rejected_submissions;
            return Z6II_HDMI_ACCESS_BUSY;
        }
        s->command = command;
        z6ii_hdmi_core_start(s, Z6II_HDMI_JOB_RESET, now_ns);
        return Z6II_HDMI_ACCESS_OK;
    }
    if (command != 0 && command != 4 && command != 8) {
        return Z6II_HDMI_ACCESS_UNSUPPORTED;
    }
    if (s->job != Z6II_HDMI_JOB_NONE || z6ii_hdmi_core_irq_pending(s)) {
        ++s->rejected_submissions;
        return Z6II_HDMI_ACCESS_BUSY;
    }
    s->command = command;
    if (command == 0) {
        return Z6II_HDMI_ACCESS_OK;
    }
    s->request_device = s->device;
    s->request_offset = s->offset;
    s->request_segment_device = s->segment_device;
    s->request_segment = s->segment;
    s->request_command = command;
    /* Segment arithmetic is derived from the six-byte firmware descriptor. */
    s->request_index = (command == 8 ? (size_t)s->segment * 256 : 0) +
                       s->offset;
    ++s->submitted_reads;
    s->fifo_valid = false;
    Z6IIHDMIJob job = Z6II_HDMI_JOB_READ;
    if (!s->connected || s->device != 0x50 ||
        (command == 8 && s->segment_device != 0x30) ||
        s->request_index > s->edid_bytes ||
        s->edid_bytes - s->request_index < sizeof(s->fifo)) {
        job = Z6II_HDMI_JOB_ERROR;
    } else if (s->fault_request == s->submitted_reads) {
        if (s->fault == Z6II_HDMI_FAULT_ERROR) {
            job = Z6II_HDMI_JOB_ERROR;
        } else if (s->fault == Z6II_HDMI_FAULT_TIMEOUT) {
            job = Z6II_HDMI_JOB_TIMEOUT;
        }
    }
    z6ii_hdmi_core_start(s, job, now_ns);
    return Z6II_HDMI_ACCESS_OK;
}

static inline bool z6ii_hdmi_core_complete(Z6IIHDMICore *s,
                                         uint64_t generation,
                                         uint64_t now_ns)
{
    if (!generation || generation != s->generation ||
        generation != s->job_generation || s->job == Z6II_HDMI_JOB_NONE) {
        ++s->stale_callbacks;
        return false;
    }
    if (s->job == Z6II_HDMI_JOB_TIMEOUT || now_ns < s->due_ns) {
        return false;
    }
    if (s->job == Z6II_HDMI_JOB_READ) {
        memcpy(s->fifo, s->edid + s->request_index, sizeof(s->fifo));
        s->fifo_valid = true;
        s->status = (s->status & ~Z6II_HDMI_ERROR) | Z6II_HDMI_DONE;
        ++s->completed_reads;
    } else if (s->job == Z6II_HDMI_JOB_RESET) {
        s->status = (s->status & ~Z6II_HDMI_ERROR) | Z6II_HDMI_DONE;
    } else {
        s->status = (s->status & ~Z6II_HDMI_DONE) | Z6II_HDMI_ERROR;
        s->fifo_valid = false;
        ++s->errors;
    }
    s->job = Z6II_HDMI_JOB_NONE;
    s->job_generation = 0;
    s->due_ns = 0;
    return true;
}

static inline bool z6ii_hdmi_core_owns(uint32_t addr)
{
    uint32_t slot = addr & ~UINT32_C(3);
    if (z6ii_hdmi_packet_owns(addr) || z6ii_hdmi_video_config_owns(addr) ||
        z6ii_hdmi_video_status_owns(addr)) {
        return true;
    }
    if (slot >= Z6II_HDMI_FIFO_ADDR && slot <= Z6II_HDMI_FIFO_ADDR + 28) {
        return true;
    }
    switch (slot) {
    case Z6II_HDMI_HPD_ADDR: case Z6II_HDMI_STATUS_ADDR:
    case Z6II_HDMI_SUMMARY_ADDR: case Z6II_HDMI_DEVICE_ADDR:
    case Z6II_HDMI_OFFSET_ADDR: case Z6II_HDMI_SINGLE_ADDR:
    case Z6II_HDMI_COMMAND_ADDR: case Z6II_HDMI_SEGMENT_DEVICE_ADDR:
    case Z6II_HDMI_SEGMENT_ADDR:
    case Z6II_HDMI_POWER_MASK_ADDR: case Z6II_HDMI_TX_CONTROL_ADDR:
        return true;
    default:
        return false;
    }
}

static inline Z6IIHDMIAccess z6ii_hdmi_core_access(Z6IIHDMICore *s,
                                                uint32_t addr, unsigned size,
                                                bool write, uint64_t *value,
                                                uint64_t now_ns)
{
    if (!z6ii_hdmi_core_owns(addr)) {
        return Z6II_HDMI_ACCESS_NOT_OWNED;
    }
    if (size != 1 || (addr & 3) || (write && *value > 255)) {
        return Z6II_HDMI_ACCESS_BAD_WIDTH_OR_DIRECTION;
    }
    if (z6ii_hdmi_packet_owns(addr)) {
        uint8_t *reg = &s->packet[(addr - Z6II_HDMI_PACKET_BASE) / 4u];
        if (write) {
            *reg = *value;
        } else {
            *value = *reg;
        }
        return Z6II_HDMI_ACCESS_OK;
    }
    if (z6ii_hdmi_video_config_owns(addr) || z6ii_hdmi_video_status_owns(addr)) {
        uint8_t *reg;
        switch (addr) {
        case UINT32_C(0x20160800): reg = &s->input_sampler; break;
        case UINT32_C(0x20162004):
        case UINT32_C(0x20162008):
        case UINT32_C(0x2016200c):
        case UINT32_C(0x20162010):
        case UINT32_C(0x2016201c):
            reg = &s->packetizer[(addr - UINT32_C(0x20162000)) / 4]; break;
        case UINT32_C(0x2016c408): reg = &s->phy_i2c_masks[0]; break;
        case UINT32_C(0x2016c410): reg = &s->phy_i2c_masks[1]; break;
        case UINT32_C(0x20170010): reg = &s->output_control; break;
        case UINT32_C(0x20160400):
        case UINT32_C(0x20160404):
        case UINT32_C(0x20160408):
            reg = &s->fc_status[(addr - UINT32_C(0x20160400)) / 4]; break;
        case UINT32_C(0x2016041c): reg = &s->vp_status; break;
        default: return Z6II_HDMI_ACCESS_UNSUPPORTED;
        }
        if (write) {
            if (z6ii_hdmi_video_status_owns(addr)) {
                /* Original 10483262/104832EE/10483358 reads then ACKs the
                 * same byte. No producer is active until a video pipeline
                 * supplies a real event; writing ones cannot create one. */
                *reg &= (uint8_t)~*value;
            } else {
                *reg = *value;
            }
        } else {
            *value = *reg;
        }
        return Z6II_HDMI_ACCESS_OK;
    }
    if (addr == Z6II_HDMI_HPD_ADDR || addr == Z6II_HDMI_SUMMARY_ADDR) {
        if (write) {
            return Z6II_HDMI_ACCESS_BAD_WIDTH_OR_DIRECTION;
        }
        *value = addr == Z6II_HDMI_HPD_ADDR ? (s->connected ? 2 : 0) :
                 (z6ii_hdmi_core_irq_pending(s) ? 4 : 0);
        return Z6II_HDMI_ACCESS_OK;
    }
    if (addr == Z6II_HDMI_STATUS_ADDR) {
        if (write) {
            /* W1C for the implemented bits is a model proposal. Crucially,
             * the original ISR acknowledges BEFORE its eight FIFO reads. */
            s->status &= ~((uint8_t)*value & (Z6II_HDMI_DONE | Z6II_HDMI_ERROR));
            ++s->acknowledgements;
        } else {
            *value = s->status;
        }
        return Z6II_HDMI_ACCESS_OK;
    }
    if (addr >= Z6II_HDMI_FIFO_ADDR && addr <= Z6II_HDMI_FIFO_ADDR + 28) {
        if (write) {
            return Z6II_HDMI_ACCESS_BAD_WIDTH_OR_DIRECTION;
        }
        if (!s->fifo_valid) {
            return Z6II_HDMI_ACCESS_FIFO_NOT_READY;
        }
        *value = s->fifo[(addr - Z6II_HDMI_FIFO_ADDR) / 4];
        ++s->fifo_reads;
        return Z6II_HDMI_ACCESS_OK;
    }
    uint8_t *reg;
    switch (addr) {
    case Z6II_HDMI_POWER_MASK_ADDR: reg = &s->power_mask; break;
    case Z6II_HDMI_TX_CONTROL_ADDR: reg = &s->tx_control; break;
    case Z6II_HDMI_DEVICE_ADDR: reg = &s->device; break;
    case Z6II_HDMI_OFFSET_ADDR: reg = &s->offset; break;
    case Z6II_HDMI_SEGMENT_DEVICE_ADDR: reg = &s->segment_device; break;
    case Z6II_HDMI_SEGMENT_ADDR: reg = &s->segment; break;
    case Z6II_HDMI_COMMAND_ADDR:
        if (write) {
            return z6ii_hdmi_core_submit(s, *value, now_ns);
        }
        reg = &s->command;
        break;
    default:
        /* Commands1/2 and the single-byte receiver are not established. */
        return Z6II_HDMI_ACCESS_UNSUPPORTED;
    }
    if (write) {
        *reg = *value;
    } else {
        *value = *reg;
    }
    return Z6II_HDMI_ACCESS_OK;
}

static inline const char *z6ii_hdmi_core_access_name(Z6IIHDMIAccess result)
{
    switch (result) {
    case Z6II_HDMI_ACCESS_OK: return "ok";
    case Z6II_HDMI_ACCESS_NOT_OWNED: return "not-owned";
    case Z6II_HDMI_ACCESS_BAD_WIDTH_OR_DIRECTION: return "bad-width-direction";
    case Z6II_HDMI_ACCESS_UNSUPPORTED: return "unsupported-contract";
    case Z6II_HDMI_ACCESS_BUSY: return "overlapping-or-unacked";
    case Z6II_HDMI_ACCESS_FIFO_NOT_READY: return "fifo-not-ready";
    case Z6II_HDMI_ACCESS_ACTIVE_RESET_BOUNDARY: return "active-reset-unverified";
    default: return "invalid-result";
    }
}

#endif
