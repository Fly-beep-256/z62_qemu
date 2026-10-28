/* SPDX-License-Identifier: GPL-2.0-or-later */
/* TIM10: independent single-channel state, internal upcount and frozen OC1.
 * PSC is buffered; ARR/CCR1 are immediate in the admitted ARPE0/OC1PE0 mode.
 * CC1E is a software output-gate latch, never evidence of an AF/pad level.
 * CCR1>ARR uses a declared STM32-family overflow-compare model condition;
 * complete RM0402/RM0090 text and camera timing confirmation are unavailable.
 * Reserved CR2 word read0/write0 is an explicit generic-HAL bus hypothesis.
 * ARR reset is unresolved until the original guest writes ARR.
 * No capture, PWM, trigger, DMA, application callback or external completion.
 */
#ifndef EX1850_TIM10_CORE_H
#define EX1850_TIM10_CORE_H
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>

#define EX1850_TIM10_APB2_BIT UINT32_C(0x20000)
#define EX1850_TIM10_SR_MASK UINT32_C(3)
#define EX1850_TIM10_CCER_MASK UINT32_C(1)

typedef struct EX1850TIM10 {
    uint32_t cr1, dier, sr, ccmr1, ccer, cnt, psc, active_psc;
    uint32_t arr, active_arr, ccr1;
    bool arr_known, active_arr_known;
    int64_t epoch;
    uint64_t phase, updates, compares;
} EX1850TIM10;

static inline void ex1850_tim10_core_reset(EX1850TIM10 *t, int64_t now)
{
    memset(t, 0, sizeof(*t));
    t->epoch = now;
}

static inline uint32_t ex1850_tim10_apb2_kernel_hz(uint32_t hclk,
                                                 uint32_t cfgr,
                                                 uint32_t apb2enr)
{
    if (!(apb2enr & EX1850_TIM10_APB2_BIT)) { return 0; }
    unsigned ppre = (cfgr >> 13) & 7;
    return ppre < 4 ? hclk : (hclk >> (ppre - 3)) * 2;
}

static inline bool ex1850_tim10_core_irq(const EX1850TIM10 *t)
{
    return !!(t->sr & t->dier & EX1850_TIM10_SR_MASK);
}

static inline bool ex1850_tim10_shared25(const EX1850TIM10 *t, bool gate10,
                                         bool gate1, uint32_t tim1_sr,
                                         uint32_t tim1_dier)
{
    return (gate10 && ex1850_tim10_core_irq(t)) ||
           (gate1 && !!(tim1_sr & tim1_dier & 1));
}

static inline bool ex1850_tim10_core_output_level(const EX1850TIM10 *t,
                                                 uint32_t *value)
{
    (void)t; (void)value;
    return false; /* Frozen OC does not establish the current OC1REF or pad. */
}

static inline bool ex1850_tim10_count_supported(const EX1850TIM10 *t)
{
    return t->active_arr_known && t->active_arr &&
           t->active_arr <= 0xffff && t->cnt <= t->active_arr &&
           t->active_psc <= 0xffff && t->psc <= 0xffff && t->ccr1 <= 0xffff &&
           !(t->cr1 & ~1U) && !t->ccmr1 &&
           !(t->ccer & ~EX1850_TIM10_CCER_MASK) &&
           !(t->dier & ~EX1850_TIM10_SR_MASK);
}

static inline uint32_t ex1850_tim10_next_ticks(const EX1850TIM10 *t)
{
    uint32_t period = t->active_arr + 1;
    uint32_t next = period - t->cnt;
    if (t->ccr1 <= t->active_arr) {
        uint32_t distance = (t->ccr1 + period - t->cnt) % period;
        if (!distance) { distance = period; }
        if (distance < next) { next = distance; }
    }
    return next;
}

static inline bool ex1850_tim10_count_add(uint64_t *count, uint64_t delta)
{
    if (UINT64_MAX - *count < delta) { return false; }
    *count += delta;
    return true;
}

static inline bool ex1850_tim10_sync_impl(EX1850TIM10 *t, int64_t now,
                                          uint32_t kernel_hz)
{
    if (now < 0 || t->epoch < 0 || now < t->epoch ||
        kernel_hz > UINT32_C(1000000000)) { return false; }
    uint64_t elapsed = (uint64_t)(now - t->epoch);
    t->epoch = now;
    if (!elapsed || !kernel_hz || !(t->cr1 & 1)) { return true; }
    if (!ex1850_tim10_count_supported(t)) { return false; }
    __uint128_t budget = (__uint128_t)elapsed * kernel_hz + t->phase;
    while (budget) {
        uint64_t divisor = (uint64_t)(t->active_psc + 1) * UINT64_C(1000000000);
        uint32_t period = t->active_arr + 1;
        if (!t->cnt && t->active_psc == t->psc && t->active_arr == t->arr) {
            __uint128_t whole = budget / ((__uint128_t)period * divisor);
            if (whole) {
                if (whole > UINT64_MAX ||
                    !ex1850_tim10_count_add(&t->updates, (uint64_t)whole) ||
                    !ex1850_tim10_count_add(&t->compares, (uint64_t)whole)) {
                    return false;
                }
                /* One CC1 event per admitted upcount cycle: either equality
                 * or, when CCR1>ARR, the declared family model condition. */
                t->sr |= 3;
                budget %= (__uint128_t)period * divisor;
                if (!budget) { t->phase = 0; return true; }
            }
        }
        uint32_t next = ex1850_tim10_next_ticks(t);
        if (budget < (__uint128_t)next * divisor) {
            t->cnt += (uint32_t)(budget / divisor);
            t->phase = (uint64_t)(budget % divisor);
            return true;
        }
        budget -= (__uint128_t)next * divisor;
        bool update = next == period - t->cnt;
        t->cnt += next;
        if (update) {
            t->cnt = 0;
            t->active_psc = t->psc;
            t->active_arr = t->arr;
            t->active_arr_known = t->arr_known;
            t->sr |= 1;
            if (!ex1850_tim10_count_add(&t->updates, 1)) { return false; }
        }
        if (t->cnt == t->ccr1 || (update && t->ccr1 > t->active_arr)) {
            t->sr |= 2;
            if (!ex1850_tim10_count_add(&t->compares, 1)) { return false; }
        }
    }
    t->phase = 0;
    return true;
}

static inline bool ex1850_tim10_core_sync(EX1850TIM10 *t, int64_t now,
                                          uint32_t kernel_hz)
{
    EX1850TIM10 candidate = *t;
    if (!ex1850_tim10_sync_impl(&candidate, now, kernel_hz)) { return false; }
    *t = candidate;
    return true;
}

static inline int64_t ex1850_tim10_core_deadline(const EX1850TIM10 *t,
                                                uint32_t kernel_hz)
{
    if (!kernel_hz || kernel_hz > UINT32_C(1000000000) ||
        !(t->cr1 & 1) || t->epoch < 0 ||
        !ex1850_tim10_count_supported(t)) { return -1; }
    uint64_t divisor = (uint64_t)(t->active_psc + 1) * UINT64_C(1000000000);
    if (t->phase >= divisor) { return -1; }
    uint64_t numerator = (uint64_t)ex1850_tim10_next_ticks(t) * divisor - t->phase;
    uint64_t delay = (numerator + kernel_hz - 1) / kernel_hz;
    if (delay > (uint64_t)(INT64_MAX - t->epoch)) { return -1; }
    return t->epoch + (int64_t)delay;
}

static inline bool ex1850_tim10_core_read(const EX1850TIM10 *t,
                                          uint32_t offset, uint32_t *value)
{
    switch (offset) {
    case 0x00: *value = t->cr1; return true;
    case 0x04: *value = 0; return true; /* Explicit CR2 bus hypothesis only. */
    case 0x0c: *value = t->dier; return true;
    case 0x10: *value = t->sr; return true;
    case 0x18: *value = t->ccmr1; return true;
    case 0x20: *value = t->ccer; return true;
    case 0x24: *value = t->cnt; return true;
    case 0x28: *value = t->psc; return true;
    case 0x2c:
        if (!t->arr_known) { return false; }
        *value = t->arr; return true;
    case 0x34: *value = t->ccr1; return true;
    default: return false; /* EGR write-only, all other reserved words strict. */
    }
}

static inline bool ex1850_tim10_core_valid_write(const EX1850TIM10 *t,
                                                uint32_t offset, uint32_t v)
{
    switch (offset) {
    case 0x00:
        return !(v & ~1U) && (!(v & 1) || ex1850_tim10_count_supported(t));
    case 0x04: case 0x18: return v == 0;
    case 0x0c: return !(v & ~EX1850_TIM10_SR_MASK);
    case 0x10: return true; /* W0C: reserved written ones cannot create flags. */
    case 0x14: return !(v & ~3U) && (!(v & 1) || t->arr_known);
    case 0x20: return !(v & ~EX1850_TIM10_CCER_MASK);
    case 0x24:
        return v <= 0xffff && (t->active_arr_known ? v <= t->active_arr : v == 0);
    case 0x28: case 0x34: return v <= 0xffff;
    case 0x2c: return v && v <= 0xffff && t->cnt <= v;
    default: return false;
    }
}

static inline bool ex1850_tim10_core_write(EX1850TIM10 *t,
                                           uint32_t offset, uint32_t v)
{
    if (!ex1850_tim10_core_valid_write(t, offset, v)) { return false; }
    switch (offset) {
    case 0x00: t->cr1 = v; break;
    case 0x04: break; /* Explicit reserved-word write0, no new latch. */
    case 0x0c: t->dier = v; break;
    case 0x10: t->sr &= v & EX1850_TIM10_SR_MASK; break;
    case 0x14:
        if (v & 1) {
            t->cnt = 0; t->phase = 0;
            t->active_psc = t->psc;
            t->active_arr = t->arr;
            t->active_arr_known = true;
            t->sr |= 1;
        }
        if (v & 2) { t->sr |= 2; }
        break;
    case 0x18: t->ccmr1 = v; break;
    case 0x20: t->ccer = v; break;
    case 0x24: t->cnt = v; break;
    case 0x28: t->psc = v; break;
    case 0x2c:
        t->arr = t->active_arr = v;
        t->arr_known = t->active_arr_known = true;
        break;
    case 0x34: t->ccr1 = v; break;
    default: break;
    }
    return true;
}
#endif
