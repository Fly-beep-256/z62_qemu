/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Z6II C1.70 GENADC contract experiment, independent of QEMU.
 * Register locations, selection encoding and 10-bit results come from the
 * original Master ROM. Timing, reset, W0C, start/busy semantics and the
 * completion/enable pairing remain explicit experimental hypotheses.
 * This device never writes guest memory, callbacks, or readiness flags. */
#ifndef NIKON_Z6II_GENADC_H
#define NIKON_Z6II_GENADC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define Z6II_GENADC_BASE UINT64_C(0x2c012000)
#define Z6II_GENADC_CHANNELS 9u
#define Z6II_GENADC_SELECT_MASK UINT32_C(0x04ff)
#define Z6II_GENADC_START UINT32_C(0x0100)
#define Z6II_GENADC_POWER UINT32_C(0x0200)
#define Z6II_GENADC_STANDBY UINT32_C(0x1000)
#define Z6II_GENADC_STATUS_EVENTS UINT32_C(0x000e)
#define Z6II_GENADC_FIRMWARE_IRQ 0x9eu /* Firmware ID, not a QEMU GPIO index. */

typedef enum Z6IIGenADCSource {
    Z6II_GENADC_SOURCE_UNSPECIFIED,
    Z6II_GENADC_SOURCE_RECORDED,
    Z6II_GENADC_SOURCE_SYNTHETIC_TEST,
} Z6IIGenADCSource;

typedef struct Z6IIGenADCFrame {
    uint16_t raw[Z6II_GENADC_CHANNELS];
    uint16_t valid_channels; /* Logical ch0..ch8 bits, not register encoding. */
} Z6IIGenADCFrame;

typedef struct Z6IIGenADCConfig {
    /* Must be explicitly enabled. It acknowledges the hypotheses listed
     * above, rather than claiming an identified hardware specification. */
    bool experimental_scan_contract;
    uint64_t conversion_latency_ns;
    /* One of status2/4/8 and one of config400/800/1000. Their pairing has
     * not been measured; callers must select it and record their choice. */
    uint32_t completion_status_mask;
    uint32_t interrupt_enable_mask;
    Z6IIGenADCSource source;
    const char *source_label; /* Nonempty provenance or synthetic-test label. */
    /* Immutable sequence, consumed once per accepted conversion. A cancelled
     * conversion still consumed its input. No implicit repetition or zeros. */
    const Z6IIGenADCFrame *frames;
    size_t frame_count;
} Z6IIGenADCConfig;

typedef enum Z6IIGenADCResult {
    Z6II_GENADC_OK,
    Z6II_GENADC_BAD_CONFIG,
    Z6II_GENADC_UNMODELED,
    Z6II_GENADC_UNSUPPORTED_MODE,
    Z6II_GENADC_INPUT_UNAVAILABLE,
    Z6II_GENADC_RESULT_UNAVAILABLE,
    Z6II_GENADC_BUSY,
    Z6II_GENADC_TIME_RANGE,
} Z6IIGenADCResult;

typedef struct Z6IIGenADC {
    Z6IIGenADCConfig config;
    uint32_t control, auxiliary, scan, status;
    uint16_t results[Z6II_GENADC_CHANNELS];
    uint16_t valid_results, selected_channels;
    uint16_t threshold[2];
    Z6IIGenADCFrame latched;
    size_t frame_index;
    bool initialized, active;
    uint64_t generation, active_generation, deadline_ns;
    uint64_t submitted, completed, cancelled;
} Z6IIGenADC;

Z6IIGenADCResult z6ii_genadc_init(Z6IIGenADC *adc,
                                 const Z6IIGenADCConfig *config);
/* Reset invalidates timer tickets and rewinds the explicitly supplied input
 * sequence. The adapter must log that rewind when reusing recorded inputs. */
Z6IIGenADCResult z6ii_genadc_reset(Z6IIGenADC *adc);
bool z6ii_genadc_owns(uint64_t address);
Z6IIGenADCResult z6ii_genadc_access(Z6IIGenADC *adc, uint64_t address,
                                   unsigned size, bool write, uint64_t *value,
                                   uint64_t now_ns);
bool z6ii_genadc_next_due(const Z6IIGenADC *adc, uint64_t *deadline_ns,
                           uint64_t *generation);
/* A host virtual-clock timer supplies the ticket captured when scheduling.
 * Early, cancelled and stale callbacks do nothing. No guest callback here. */
bool z6ii_genadc_complete(Z6IIGenADC *adc, uint64_t generation,
                          uint64_t now_ns);
bool z6ii_genadc_irq_pending(const Z6IIGenADC *adc);
const char *z6ii_genadc_result_name(Z6IIGenADCResult result);

#endif
