/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Four-channel TIM2/3/4 configuration and internal upcounter candidate.
 * The admitted state comes from native register writes. ARR reset is unknown.
 * Input selection/filter/polarity can be configured while capture is disabled;
 * enabling capture is a strict external-signal boundary. DMA, external/slave
 * clocks, triggers and physical output pads are not supplied by this core.
 */
#ifndef EX1850_TIM234_CORE_H
#define EX1850_TIM234_CORE_H
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>

typedef struct EX1850TIM234 {
    uint32_t cr1, cr2, smcr, dier, sr, ccmr[2], ccer;
    uint32_t cnt, psc, active_psc, arr, active_arr, ccr[4], active_ccr[4];
    uint32_t width_mask;
    bool arr_known, active_arr_known;
    int64_t epoch;
    uint64_t phase, updates, compares[4];
} EX1850TIM234;

static inline void ex1850_tim234_reset(EX1850TIM234 *t, unsigned bits, int64_t now)
{
    memset(t, 0, sizeof(*t));
    t->width_mask = bits == 32 ? UINT32_MAX : UINT32_C(0xffff);
    t->epoch = now;
}

static inline uint32_t ex1850_tim234_channel(const EX1850TIM234 *t, unsigned n)
{
    return (t->ccmr[n / 2] >> ((n % 2) * 8)) & 0xff;
}

static inline bool ex1850_tim234_modes_valid(uint32_t value)
{
    if (value & 0xffff0000U) { return false; }
    for (unsigned n = 0; n < 2; n++) {
        uint32_t field = (value >> (n * 8)) & 0xff;
        if (field & 3) { continue; } /* Disabled input configuration only. */
        unsigned mode = (field >> 4) & 7;
        if ((field & 0x80) || (mode != 0 && mode != 6 && mode != 7)) { return false; }
    }
    return true;
}

static inline bool ex1850_tim234_capture_enabled(const EX1850TIM234 *t)
{
    for (unsigned n = 0; n < 4; n++) {
        if ((ex1850_tim234_channel(t, n) & 3) && (t->ccer & (1U << (n * 4)))) { return true; }
    }
    return false;
}

static inline bool ex1850_tim234_count_supported(const EX1850TIM234 *t)
{
    if (!t->active_arr_known || !t->active_arr || t->cnt > t->active_arr ||
        (t->cr1 & ~0x38fU) || (t->cr1 & 0x300) == 0x300 || t->cr2 || t->smcr ||
        (t->dier & ~0x1fU) || ex1850_tim234_capture_enabled(t)) { return false; }
    for (unsigned n = 0; n < 4; n++) {
        if (!(ex1850_tim234_channel(t, n) & 3) && t->active_ccr[n] > t->active_arr) { return false; }
    }
    return true;
}

static inline uint64_t ex1850_tim234_next_ticks(const EX1850TIM234 *t)
{
    uint64_t period = (uint64_t)t->active_arr + 1;
    uint64_t next = period - t->cnt;
    for (unsigned n = 0; n < 4; n++) {
        if (ex1850_tim234_channel(t, n) & 3) { continue; }
        uint64_t distance = ((uint64_t)t->active_ccr[n] + period - t->cnt) % period;
        if (!distance) { distance = period; }
        if (distance < next) { next = distance; }
    }
    return next;
}

static inline void ex1850_tim234_preloads(EX1850TIM234 *t)
{
    t->active_psc = t->psc;
    t->active_arr = t->arr;
    t->active_arr_known = t->arr_known;
    for (unsigned n = 0; n < 4; n++) {
        if (!(ex1850_tim234_channel(t, n) & 3)) { t->active_ccr[n] = t->ccr[n]; }
    }
}

static inline bool ex1850_tim234_add(uint64_t *value, uint64_t count)
{
    if (UINT64_MAX - *value < count) { return false; }
    *value += count; return true;
}

static inline bool ex1850_tim234_sync_impl(EX1850TIM234 *t, int64_t now, uint32_t hz)
{
    if (now < 0 || t->epoch < 0 || now < t->epoch || hz > 1000000000U) { return false; }
    uint64_t elapsed = now - t->epoch;
    t->epoch = now;
    if (!elapsed || !hz || !(t->cr1 & 1)) { return true; }
    if (!ex1850_tim234_count_supported(t)) { return false; }
    __uint128_t budget = (__uint128_t)elapsed * hz + t->phase;
    while (budget && (t->cr1 & 1)) {
        uint64_t divisor = (uint64_t)(t->active_psc + 1) * UINT64_C(1000000000);
        uint64_t period = (uint64_t)t->active_arr + 1;
        bool pending = t->active_psc != t->psc || t->active_arr != t->arr;
        for (unsigned n = 0; n < 4; n++) {
            if (!(ex1850_tim234_channel(t, n) & 3) && t->active_ccr[n] != t->ccr[n]) { pending = true; }
        }
        if (!t->cnt && !pending && !(t->cr1 & 0xa)) {
            __uint128_t whole = budget / ((__uint128_t)period * divisor);
            if (whole) {
                if (whole > UINT64_MAX || !ex1850_tim234_add(&t->updates, whole)) { return false; }
                t->sr |= 1;
                for (unsigned n = 0; n < 4; n++) {
                    if (!(ex1850_tim234_channel(t, n) & 3)) {
                        t->sr |= 2U << n;
                        if (!ex1850_tim234_add(&t->compares[n], whole)) { return false; }
                    }
                }
                budget %= (__uint128_t)period * divisor;
                if (!budget) { t->phase = 0; return true; }
            }
        }
        uint64_t next = ex1850_tim234_next_ticks(t);
        if (budget < (__uint128_t)next * divisor) {
            t->cnt += (uint32_t)(budget / divisor);
            t->phase = budget % divisor; return true;
        }
        budget -= (__uint128_t)next * divisor;
        bool update = next == period - t->cnt;
        t->cnt = (uint32_t)((uint64_t)t->cnt + next);
        if (update) {
            t->cnt = 0;
            if (!(t->cr1 & 2)) {
                ex1850_tim234_preloads(t);
                t->sr |= 1;
                if (!ex1850_tim234_add(&t->updates, 1)) { return false; }
                if (t->cr1 & 8) { t->cr1 &= ~1U; }
            }
        }
        for (unsigned n = 0; n < 4; n++) {
            if (!(ex1850_tim234_channel(t, n) & 3) && t->cnt == t->active_ccr[n]) {
                t->sr |= 2U << n;
                if (!ex1850_tim234_add(&t->compares[n], 1)) { return false; }
            }
        }
        if (!ex1850_tim234_count_supported(t)) { return false; }
    }
    t->phase = 0; return true;
}

static inline bool ex1850_tim234_core_sync(EX1850TIM234 *t, int64_t now, uint32_t hz)
{
    EX1850TIM234 c = *t;
    if (!ex1850_tim234_sync_impl(&c, now, hz)) { return false; }
    *t = c; return true;
}

static inline int64_t ex1850_tim234_deadline(const EX1850TIM234 *t, uint32_t hz)
{
    if (!hz || !(t->cr1 & 1) || !ex1850_tim234_count_supported(t)) { return -1; }
    __uint128_t numerator = (__uint128_t)ex1850_tim234_next_ticks(t) *
                            (t->active_psc + 1) * UINT64_C(1000000000) - t->phase;
    __uint128_t delay = (numerator + hz - 1) / hz;
    if (delay > (uint64_t)(INT64_MAX - t->epoch)) { return -1; }
    return t->epoch + (int64_t)delay;
}

static inline bool ex1850_tim234_read(const EX1850TIM234 *t, unsigned offset, uint32_t *v)
{
    switch (offset) {
    case 0x00: *v=t->cr1; return true;
    case 0x04: *v=t->cr2; return true;
    case 0x08: *v=t->smcr; return true;
    case 0x0c: *v=t->dier; return true;
    case 0x10: *v=t->sr; return true;
    case 0x18: case 0x1c: *v=t->ccmr[(offset-0x18)/4]; return true;
    case 0x20: *v=t->ccer; return true;
    case 0x24: *v=t->cnt; return true;
    case 0x28: *v=t->psc; return true;
    case 0x2c: if (!t->arr_known) { return false; } *v=t->arr; return true;
    case 0x34: case 0x38: case 0x3c: case 0x40: *v=t->ccr[(offset-0x34)/4]; return true;
    default: return false;
    }
}

static inline bool ex1850_tim234_write_impl(EX1850TIM234 *t, unsigned offset, uint32_t v)
{
    switch (offset) {
    case 0x00:
        if ((v & ~0x38fU) || (v & 0x300) == 0x300) { return false; }
        t->cr1=v; break;
    case 0x04: case 0x08:
        if (v) { return false; } /* External TRGO, slave/encoder modes stay strict. */
        break;
    case 0x0c:
        if (v & ~0x1fU) { return false; } t->dier=v; break;
    case 0x10: t->sr &= v & 0x1f; break; /* W0C never invents an event. */
    case 0x14:
        if (v & ~0x1fU || ((v & 1) && !t->arr_known)) { return false; }
        if (v & 1) {
            t->cnt=0; t->phase=0;
            if (!(t->cr1 & 2)) {
                ex1850_tim234_preloads(t);
                if (!(t->cr1 & 4)) { t->sr |= 1; }
            }
        }
        for (unsigned n=0;n<4;n++) {
            if ((v & (2U<<n)) && (ex1850_tim234_channel(t,n)&3)) { return false; }
        }
        t->sr |= v & 0x1e; break;
    case 0x18: case 0x1c:
        if (!ex1850_tim234_modes_valid(v)) { return false; }
        for (unsigned n=0;n<2;n++) {
            unsigned ch=(offset-0x18)/4*2+n;
            if (((v ^ t->ccmr[(offset-0x18)/4]) & (3U<<(n*8))) &&
                (t->ccer & (1U<<(ch*4)))) { return false; }
        }
        t->ccmr[(offset-0x18)/4]=v;
        for (unsigned n=0;n<4;n++) {
            if (!(ex1850_tim234_channel(t,n)&0xb)) { t->active_ccr[n]=t->ccr[n]; }
        }
        break;
    case 0x20:
        if (v & ~0xbbbbU) { return false; }
        for (unsigned n=0;n<4;n++) {
            if (!(ex1850_tim234_channel(t,n)&3) && (v & (8U<<(n*4)))) { return false; }
        }
        t->ccer=v; break;
    case 0x24:
        if (v > t->width_mask || (t->active_arr_known ? v>t->active_arr : v!=0)) { return false; }
        t->cnt=v; t->phase=0; break;
    case 0x28: if (v>0xffff) { return false; } t->psc=v; break;
    case 0x2c:
        if (!v || v>t->width_mask || t->cnt>v) { return false; }
        t->arr=v; t->arr_known=true;
        if (!(t->cr1&0x80)) { t->active_arr=v; t->active_arr_known=true; }
        break;
    case 0x34: case 0x38: case 0x3c: case 0x40: {
        if (v>t->width_mask) { return false; }
        unsigned n=(offset-0x34)/4;
        if (ex1850_tim234_channel(t,n)&3) { return false; } /* Capture latch is read-only. */
        t->ccr[n]=v;
        if (!(ex1850_tim234_channel(t,n)&8)) { t->active_ccr[n]=v; }
        break;
    }
    default: return false;
    }
    /* Configuration is not evidence for any external capture edge. */
    if (ex1850_tim234_capture_enabled(t)) { return false; }
    return !(t->cr1&1) || ex1850_tim234_count_supported(t);
}

static inline bool ex1850_tim234_write(EX1850TIM234 *t, unsigned offset, uint32_t v)
{
    EX1850TIM234 c=*t;
    if (!ex1850_tim234_write_impl(&c,offset,v)) { return false; }
    *t=c; return true;
}
#endif
