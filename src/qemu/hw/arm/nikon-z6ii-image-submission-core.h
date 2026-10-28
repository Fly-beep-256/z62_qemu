/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Conservative admission history for the image controller. C1.70
 * 103bf7b6 arms command banks, 103bf9b4 submits sequence requests, and
 * 1036c0f2 writes the raw-controller +10/+08 pair. Their execution and
 * retirement are not supplied by this core. A reset word may be read only
 * before an unresolved submission; no frame counter establishes idleness.
 * Physical reset values and the complete status encoding remain unknown. */
#ifndef NIKON_Z6II_IMAGE_SUBMISSION_CORE_H
#define NIKON_Z6II_IMAGE_SUBMISSION_CORE_H

#include <stdbool.h>
#include <stdint.h>
#include "nikon-z6ii-image-unit-map.h"

typedef struct Z6IIImageSubmissionState {
    uint32_t unresolved;
    uint64_t unresolved_units;
    uint32_t unit_control[Z6II_IMAGE_UNIT_COUNT];
    uint64_t unit_arm_writes;
    uint64_t generation, control_writes, uncertain_requests;
    uint64_t reset_word_reads, rejected_reads;
    uint64_t pending_word_reads;
} Z6IIImageSubmissionState;

static inline void z6ii_image_submission_reset(Z6IIImageSubmissionState *s)
{
    /* The caller must cancel all modeled image work and clear controls.
     * Descriptor uploads, request clears and pulses cannot use this API. */
    s->unresolved = 0;
    s->unresolved_units = 0;
    for (unsigned i = 0; i < Z6II_IMAGE_UNIT_COUNT; ++i) {
        s->unit_control[i] = 0;
    }
    ++s->generation;
}

static inline bool z6ii_image_submission_empty(const Z6IIImageSubmissionState *s)
{
    return !s->unresolved && !s->unresolved_units;
}

static inline bool z6ii_image_submission_write(Z6IIImageSubmissionState *s,
                                               uint32_t address, uint32_t word)
{
    /* Original103b7114 ->103bf7b0 arms a selected unit with word1.
     * This is separate from +08/+0c parameters and +14/+10 uploads.
     * Record every nonzero base-word request conservatively; a clear
     * cannot establish that previously unexplained work has retired. */
    int unit = z6ii_image_unit_index(address);
    if (unit >= 0) {
        s->unit_control[unit] = word;
        ++s->control_writes;
        if (word) {
            s->unresolved_units |= UINT64_C(1) << unit;
            ++s->unit_arm_writes;
            ++s->uncertain_requests;
        }
        return true;
    }
    uint32_t uncertain = 0;
    switch (address) {
    case 0x20102000: uncertain = (word & 1) ? 1 : 0; break;
    case 0x20102100: uncertain = (word & 1) ? 2 : 0; break;
    case 0x20102608: uncertain = word ? 4 : 0; break;
    case 0x20102648: uncertain = word ? 8 : 0; break;
    case 0x20380008:
    case 0x20380010: uncertain = (word & 1) ? 16 : 0; break;
    case 0x203c0008:
    case 0x203c0010: uncertain = (word & 1) ? 32 : 0; break;
    case 0x20102680: uncertain = word ? 64 : 0; break;
    /* These are observable control/reset requests, with no proven
     * retirement relation. In particular a 1->0 pulse cannot clear an
     * unresolved start. Configuration at sequence +00 is not a start. */
    case 0x201020a4:
    case 0x20102620:
    case 0x20102660:
    case 0x20380000:
    case 0x20380004:
    case 0x2038000c:
    case 0x203c0000:
    case 0x203c0004:
    case 0x203c000c:
    case 0x203800e8:
    case 0x203800f0:
    case 0x203800d0:
    case 0x203c00e8:
    case 0x203c00f0:
        break;
    default:
        return false;
    }
    ++s->control_writes;
    if (uncertain) {
        s->unresolved |= uncertain;
        ++s->uncertain_requests;
    }
    return true;
}

static inline bool z6ii_image_reset_word(Z6IIImageSubmissionState *s,
                                        uint32_t *word)
{
    if (!z6ii_image_submission_empty(s)) {
        ++s->rejected_reads;
        return false;
    }
    ++s->reset_word_reads;
    *word = 0; /* Explicit model reset state, not a completion encoding. */
    return true;
}

static inline uint32_t z6ii_image_pending_word(Z6IIImageSubmissionState *s)
{
    /* Opt-in observation policy: original 103c0300/308 keeps its wait
     * pending when low2bits are3. Preserve every unresolved request and
     * supply no completion, retirement, DMA output or software flags. */
    if (!z6ii_image_submission_empty(s)) {
        ++s->pending_word_reads;
        return 3;
    }
    ++s->reset_word_reads;
    return 0;
}

#endif
