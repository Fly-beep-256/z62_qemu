/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "nikon-z6ii-genadc.h"
#include <string.h>

#define CONTROL_KNOWN UINT32_C(0x57ff)
#define SCAN_KNOWN UINT32_C(0x1fff)
#define AUXILIARY_KNOWN UINT32_C(0x7000)
#define CONTINUOUS UINT32_C(0x4000)
#define SCAN_MODE UINT32_C(0x0300)
#define STATUS_BUSY UINT32_C(1)

static uint16_t selected(uint32_t control)
{
    return (uint16_t)((control & 0xffu) | ((control & 0x400u) >> 2));
}

static bool one_of(uint32_t value, uint32_t a, uint32_t b, uint32_t c)
{
    return value == a || value == b || value == c;
}

Z6IIGenADCResult z6ii_genadc_init(Z6IIGenADC *adc,
                                 const Z6IIGenADCConfig *config)
{
    Z6IIGenADCConfig saved_config;
    if (!adc || !config || !config->experimental_scan_contract ||
        !config->conversion_latency_ns ||
        !one_of(config->completion_status_mask, 2, 4, 8) ||
        !one_of(config->interrupt_enable_mask, 0x400, 0x800, 0x1000) ||
        (config->source != Z6II_GENADC_SOURCE_RECORDED &&
         config->source != Z6II_GENADC_SOURCE_SYNTHETIC_TEST) ||
        !config->source_label || !*config->source_label ||
        (config->frame_count && !config->frames)) {
        return Z6II_GENADC_BAD_CONFIG;
    }
    for (size_t n = 0; n < config->frame_count; n++) {
        if (config->frames[n].valid_channels & ~0x1ffu) {
            return Z6II_GENADC_BAD_CONFIG;
        }
        for (unsigned ch = 0; ch < Z6II_GENADC_CHANNELS; ch++) {
            if (config->frames[n].raw[ch] > 0x3ffu) {
                return Z6II_GENADC_BAD_CONFIG;
            }
        }
    }
    saved_config = *config;
    memset(adc, 0, sizeof(*adc));
    adc->config = saved_config;
    adc->initialized = true;
    adc->generation = 1;
    return Z6II_GENADC_OK;
}

Z6IIGenADCResult z6ii_genadc_reset(Z6IIGenADC *adc)
{
    Z6IIGenADCConfig config;
    uint64_t next_generation;
    if (!adc || !adc->initialized) {
        return Z6II_GENADC_BAD_CONFIG;
    }
    if (adc->generation == UINT64_MAX) {
        return Z6II_GENADC_TIME_RANGE;
    }
    config = adc->config;
    next_generation = adc->generation + 1;
    memset(adc, 0, sizeof(*adc));
    adc->config = config;
    adc->initialized = true;
    adc->generation = next_generation;
    return Z6II_GENADC_OK;
}

bool z6ii_genadc_owns(uint64_t address)
{
    return address >= Z6II_GENADC_BASE && address < Z6II_GENADC_BASE + 0x48;
}

static Z6IIGenADCResult write_control(Z6IIGenADC *adc, uint32_t value,
                                      uint64_t now_ns)
{
    bool start = (value & Z6II_GENADC_START) &&
                 !(adc->control & Z6II_GENADC_START);
    uint16_t channels = selected(value);
    if (value & ~CONTROL_KNOWN) {
        return Z6II_GENADC_UNMODELED;
    }
    if (start) {
        if (adc->active) {
            return Z6II_GENADC_BUSY;
        }
        if (!(value & Z6II_GENADC_POWER) ||
            (value & (Z6II_GENADC_STANDBY | CONTINUOUS)) ||
            (adc->scan & SCAN_MODE) || adc->auxiliary || !channels) {
            return Z6II_GENADC_UNSUPPORTED_MODE;
        }
        if (adc->frame_index >= adc->config.frame_count ||
            (adc->config.frames[adc->frame_index].valid_channels & channels)
             != channels) {
            return Z6II_GENADC_INPUT_UNAVAILABLE;
        }
        if (now_ns > UINT64_MAX - adc->config.conversion_latency_ns ||
            adc->generation == UINT64_MAX) {
            return Z6II_GENADC_TIME_RANGE;
        }
        adc->latched = adc->config.frames[adc->frame_index++];
        adc->selected_channels = channels;
        adc->deadline_ns = now_ns + adc->config.conversion_latency_ns;
        adc->active_generation = ++adc->generation;
        adc->active = true;
        adc->status |= STATUS_BUSY;
        adc->submitted++;
    } else if (adc->active && (!(value & Z6II_GENADC_START) ||
                               !(value & Z6II_GENADC_POWER) ||
                               (value & Z6II_GENADC_STANDBY))) {
        adc->active = false;
        adc->status &= ~STATUS_BUSY;
        adc->active_generation = 0;
        adc->deadline_ns = 0;
        adc->cancelled++;
    } else if (adc->active && (value & CONTINUOUS)) {
        return Z6II_GENADC_UNSUPPORTED_MODE;
    }
    adc->control = value;
    return Z6II_GENADC_OK;
}

Z6IIGenADCResult z6ii_genadc_access(Z6IIGenADC *adc, uint64_t address,
                                   unsigned size, bool write, uint64_t *value,
                                   uint64_t now_ns)
{
    uint32_t input, offset;
    if (!adc || !adc->initialized || !value) {
        return Z6II_GENADC_BAD_CONFIG;
    }
    if (!z6ii_genadc_owns(address) || size != 4 || (address & 3) ||
        (write && *value > UINT32_MAX)) {
        return Z6II_GENADC_UNMODELED;
    }
    offset = (uint32_t)(address - Z6II_GENADC_BASE);
    input = (uint32_t)*value;
    if (offset == 0) {
        if (write) {
            return write_control(adc, input, now_ns);
        }
        *value = adc->control;
    } else if (offset == 4) {
        if (write) {
            if (input & ~AUXILIARY_KNOWN) {
                return Z6II_GENADC_UNMODELED;
            }
            adc->auxiliary = input;
        } else {
            *value = adc->auxiliary;
        }
    } else if (offset == 8) {
        if (write) {
            if (input & ~SCAN_KNOWN) {
                return Z6II_GENADC_UNMODELED;
            }
            if (adc->active && ((input ^ adc->scan) & SCAN_MODE)) {
                return Z6II_GENADC_UNSUPPORTED_MODE;
            }
            adc->scan = input;
        } else {
            *value = adc->scan;
        }
    } else if (offset == 0x0c) {
        if (write) {
            if (input & ~UINT32_C(0xff)) {
                return Z6II_GENADC_UNMODELED;
            }
            /* Original ISR writes old_status XOR 0xE. W0C is an explicit
             * hypothesis. Busy and channel fields remain device-owned. */
            adc->status &= input | ~Z6II_GENADC_STATUS_EVENTS;
        } else {
            *value = adc->status;
        }
    } else if (offset >= 0x10 && offset <= 0x30) {
        unsigned ch = (offset - 0x10) / 4;
        if (write) {
            return Z6II_GENADC_UNMODELED;
        }
        if (!(adc->valid_results & (1u << ch))) {
            return Z6II_GENADC_RESULT_UNAVAILABLE;
        }
        *value = adc->results[ch];
    } else if (offset == 0x40 || offset == 0x44) {
        unsigned n = (offset - 0x40) / 4;
        if (write) {
            if (input > 0x3ffu) {
                return Z6II_GENADC_UNMODELED;
            }
            adc->threshold[n] = (uint16_t)input;
        } else {
            *value = adc->threshold[n];
        }
    } else {
        return Z6II_GENADC_UNMODELED;
    }
    return Z6II_GENADC_OK;
}

bool z6ii_genadc_next_due(const Z6IIGenADC *adc, uint64_t *deadline_ns,
                           uint64_t *generation)
{
    if (!adc || !adc->initialized || !adc->active || !deadline_ns ||
        !generation) {
        return false;
    }
    *deadline_ns = adc->deadline_ns;
    *generation = adc->active_generation;
    return true;
}

bool z6ii_genadc_complete(Z6IIGenADC *adc, uint64_t generation,
                          uint64_t now_ns)
{
    if (!adc || !adc->initialized || !adc->active ||
        generation != adc->active_generation || now_ns < adc->deadline_ns) {
        return false;
    }
    for (unsigned ch = 0; ch < Z6II_GENADC_CHANNELS; ch++) {
        if (adc->selected_channels & (1u << ch)) {
            adc->results[ch] = adc->latched.raw[ch];
        }
    }
    adc->valid_results |= adc->selected_channels;
    adc->status = (adc->status & ~STATUS_BUSY) |
                  adc->config.completion_status_mask;
    adc->control &= ~Z6II_GENADC_START; /* Explicit self-clear hypothesis. */
    adc->active = false;
    adc->active_generation = 0;
    adc->deadline_ns = 0;
    adc->completed++;
    return true;
}

bool z6ii_genadc_irq_pending(const Z6IIGenADC *adc)
{
    return adc && adc->initialized &&
           (adc->status & adc->config.completion_status_mask) &&
           (adc->scan & adc->config.interrupt_enable_mask);
}

const char *z6ii_genadc_result_name(Z6IIGenADCResult result)
{
    switch (result) {
    case Z6II_GENADC_OK: return "ok";
    case Z6II_GENADC_BAD_CONFIG: return "bad-config";
    case Z6II_GENADC_UNMODELED: return "unmodeled";
    case Z6II_GENADC_UNSUPPORTED_MODE: return "unsupported-mode";
    case Z6II_GENADC_INPUT_UNAVAILABLE: return "input-unavailable";
    case Z6II_GENADC_RESULT_UNAVAILABLE: return "result-unavailable";
    case Z6II_GENADC_BUSY: return "busy";
    case Z6II_GENADC_TIME_RANGE: return "time-range";
    }
    return "invalid-result";
}
