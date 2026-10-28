/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Mask1 input-cycle model. Original 1020C41A/444/462 establish reset,
 * clock-enable, start and stop through 20068000/04/08/0c/10/14. The native
 * bank0 bit0 consumer is known; interpreting one admitted TG input cycle as
 * this engine's completion is an explicit model hypothesis. No DMA, pixels,
 * metering statistics or application-state success is produced here. */
#ifndef NIKON_Z6II_ISP_FRAME_CORE_H
#define NIKON_Z6II_ISP_FRAME_CORE_H

#include <stdbool.h>
#include <stdint.h>

typedef struct Z6IIMask1InputCycle {
    bool pending;
    uint64_t admitted, completed, canceled;
} Z6IIMask1InputCycle;

static inline bool z6ii_isp_input_engine_active(uint32_t reset, uint32_t started,
                                               uint32_t clocks, uint32_t global_stop,
                                               uint32_t mask)
{
    return mask && !(global_stop & 3) && !(reset & mask) &&
           (started & mask) == mask && (clocks & mask) == mask;
}

static inline bool z6ii_mask1_engine_active(uint32_t reset, uint32_t started,
                                           uint32_t clocks, uint32_t global_stop)
{
    return z6ii_isp_input_engine_active(reset, started, clocks, global_stop, 1);
}

static inline void z6ii_mask1_input_cancel(Z6IIMask1InputCycle *s)
{
    if (s->pending) { ++s->canceled; }
    s->pending = false;
}

static inline void z6ii_mask1_input_begin(Z6IIMask1InputCycle *s, bool engine,
                                         bool input_enabled)
{
    z6ii_mask1_input_cancel(s);
    if (engine && input_enabled) {
        s->pending = true;
        ++s->admitted;
    }
}

static inline bool z6ii_mask1_input_end(Z6IIMask1InputCycle *s, bool engine)
{
    /* Input disable drains the admitted cycle. Engine stop/reset cancels it;
     * restarting an engine requires a newly admitted cycle. */
    if (!s->pending) { return false; }
    if (!engine) {
        z6ii_mask1_input_cancel(s);
        return false;
    }
    s->pending = false;
    ++s->completed;
    return true;
}

#endif
