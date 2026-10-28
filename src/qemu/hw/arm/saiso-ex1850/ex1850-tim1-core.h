/* SPDX-License-Identifier: GPL-2.0-or-later */
/* STM32F412 TIM1 candidate: fresh four-channel state, APB2 bit0.
 * Admits internal upcount, RCR0 and frozen internal compare flags only;
 * CCER.CC2E and BDTR.MOE are software output-gate latches. In frozen mode
 * their writes do not supply a pad level or change the internal counter.
 * Counter use requires CCR1..4<=ARR. CCR>ARR special flag semantics are not
 * established by the frozen local references: latch while stopped, reject
 * enabling or entering that counting range; never silently skip a flag.
 * No PWM/pad output, capture, break, trigger, COM, DMA or completion source.
 * ARR reset is unresolved: reads/use reject until a native ARR write.
 * The board owns IRQ routing25/26/27 and TIM11 shared-line aggregation.
 */
#ifndef EX1850_TIM1_CORE_H
#define EX1850_TIM1_CORE_H
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>

#define EX1850_TIM1_SR_MASK UINT32_C(0x1f)
#define EX1850_TIM1_APB2_BIT UINT32_C(1)
#define EX1850_TIM1_APB2_SPI_MASK UINT32_C(0x3000)
#define EX1850_TIM1_CCER_MASK UINT32_C(0x10)
#define EX1850_TIM1_BDTR_MASK UINT32_C(0x8000)

typedef struct EX1850TIM1 {
    uint32_t cr1, cr2, smcr, dier, sr, ccmr1, ccmr2, ccer;
    uint32_t cnt, psc, active_psc, arr, active_arr, rcr, bdtr, ccr[4];
    bool arr_known, active_arr_known;
    int64_t epoch;
    uint64_t phase; /* source-clock numerator; denominator1e9, PSC retained */
    uint64_t updates, compares[4];
} EX1850TIM1;

static inline void ex1850_tim1_core_reset(EX1850TIM1 *t, int64_t now)
{
    memset(t, 0, sizeof(*t));
    t->epoch = now;
    /* arr=0 is storage only, not a known hardware reset value. */
}

static inline uint32_t ex1850_tim1_apb2_kernel_hz(uint32_t hclk,
                                               uint32_t cfgr,
                                               uint32_t apb2enr)
{
    if (!(apb2enr & EX1850_TIM1_APB2_BIT)) { return 0; }
    unsigned ppre = (cfgr >> 13) & 7;
    return ppre < 4 ? hclk : (hclk >> (ppre - 3)) * 2;
}

static inline bool ex1850_tim1_core_irq(const EX1850TIM1 *t, unsigned irq)
{
    uint32_t enabled = t->sr & t->dier;
    switch (irq) {
    case 24: return !!(enabled & UINT32_C(0x80));
    case 25: return !!(enabled & UINT32_C(1));
    case 26: return !!(enabled & UINT32_C(0x60));
    case 27: return !!(enabled & UINT32_C(0x1e));
    default: return false;
    }
}

static inline bool ex1850_tim1_shared26(const EX1850TIM1 *t, bool tim1_gate,
                                       bool tim11_gate, uint32_t tim11_sr,
                                       uint32_t tim11_dier)
{
    return (tim1_gate && ex1850_tim1_core_irq(t, 26)) ||
           (tim11_gate && !!(tim11_sr & tim11_dier & 3));
}

static inline bool ex1850_tim1_compare_range_supported(const EX1850TIM1 *t,
                                                      uint32_t arr)
{
    for (unsigned n = 0; n < 4; n++) {
        if (t->ccr[n] > arr) { return false; }
    }
    return true;
}

static inline bool ex1850_tim1_core_output_level(const EX1850TIM1 *t,
                                                unsigned channel,
                                                uint32_t *value)
{
    /* The official frozen-mode contract says comparison does not change
     * the channel level. It does not establish OC2REF/pad power-on/current
     * level, routing, loading or contention. Never supply a representative
     * level; board GPIO AF reads independently retain their strict boundary. */
    (void)t; (void)channel; (void)value;
    return false;
}

static inline uint32_t ex1850_tim1_next_ticks(const EX1850TIM1 *t)
{
    uint32_t period = t->active_arr + 1;
    uint32_t next = period - t->cnt;
    for (unsigned n = 0; n < 4; n++) {
        if (t->ccr[n] > t->active_arr) { continue; }
        uint32_t distance = (t->ccr[n] + period - t->cnt) % period;
        if (!distance) { distance = period; }
        if (distance < next) { next = distance; }
    }
    return next;
}

static inline bool ex1850_tim1_count_add(uint64_t *count, uint64_t delta)
{
    if (UINT64_MAX - *count < delta) { return false; }
    *count += delta;
    return true;
}

static inline bool ex1850_tim1_sync_impl(EX1850TIM1 *t, int64_t now,
                                        uint32_t kernel_hz)
{
    if (now < 0 || t->epoch < 0 || now < t->epoch ||
        kernel_hz > UINT32_C(1000000000)) {
        return false;
    }
    uint64_t elapsed = (uint64_t)(now - t->epoch);
    t->epoch = now;
    if (!elapsed || !kernel_hz || !(t->cr1 & 1)) { return true; }
    if (!t->active_arr_known || !t->active_arr || t->cnt > t->active_arr ||
        t->rcr || t->smcr || t->ccmr1 || t->ccmr2 ||
        (t->bdtr & ~EX1850_TIM1_BDTR_MASK) ||
        (t->ccer & ~EX1850_TIM1_CCER_MASK) ||
        !ex1850_tim1_compare_range_supported(t, t->active_arr)) {
        return false;
    }
    __uint128_t budget = (__uint128_t)elapsed * kernel_hz + t->phase;
    while (budget) {
        uint64_t divisor = (uint64_t)(t->active_psc + 1) * UINT64_C(1000000000);
        uint32_t period = t->active_arr + 1;
        /* A full-cycle shortcut is valid only after all pending preloads
         * already agree. A changed PSC must first traverse an actual UEV. */
        if (!t->cnt && t->active_psc == t->psc && t->active_arr == t->arr) {
            __uint128_t whole = budget / ((__uint128_t)period * divisor);
            if (whole) {
                if (whole > UINT64_MAX ||
                    !ex1850_tim1_count_add(&t->updates, (uint64_t)whole)) {
                    return false;
                }
                t->sr |= 1;
                for (unsigned n = 0; n < 4; n++) {
                    if (t->ccr[n] <= t->active_arr) {
                        t->sr |= 2U << n;
                        if (!ex1850_tim1_count_add(&t->compares[n],
                                                   (uint64_t)whole)) {
                            return false;
                        }
                    }
                }
                budget %= (__uint128_t)period * divisor;
                if (!budget) { t->phase = 0; return true; }
            }
        }
        uint32_t next = ex1850_tim1_next_ticks(t);
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
            if (!ex1850_tim1_count_add(&t->updates, 1)) { return false; }
        }
        for (unsigned n = 0; n < 4; n++) {
            if (t->cnt == t->ccr[n]) {
                t->sr |= 2U << n;
                if (!ex1850_tim1_count_add(&t->compares[n], 1)) { return false; }
            }
        }
    }
    t->phase = 0;
    return true;
}

static inline bool ex1850_tim1_core_sync(EX1850TIM1 *t, int64_t now,
                                         uint32_t kernel_hz)
{
    EX1850TIM1 candidate = *t;
    if (!ex1850_tim1_sync_impl(&candidate, now, kernel_hz)) { return false; }
    *t = candidate;
    return true;
}

static inline int64_t ex1850_tim1_core_deadline(const EX1850TIM1 *t,
                                               uint32_t kernel_hz)
{
    if (!kernel_hz || kernel_hz > UINT32_C(1000000000) ||
        !(t->cr1 & 1) || !t->active_arr_known ||
        !t->active_arr || t->cnt > t->active_arr || t->epoch < 0 ||
        t->rcr || t->smcr || t->ccmr1 || t->ccmr2 ||
        (t->bdtr & ~EX1850_TIM1_BDTR_MASK) ||
        (t->ccer & ~EX1850_TIM1_CCER_MASK) ||
        !ex1850_tim1_compare_range_supported(t, t->active_arr)) { return -1; }
    uint64_t divisor = (uint64_t)(t->active_psc + 1) * UINT64_C(1000000000);
    uint64_t numerator = (uint64_t)ex1850_tim1_next_ticks(t) * divisor - t->phase;
    uint64_t delay = (numerator + kernel_hz - 1) / kernel_hz;
    if (delay > (uint64_t)(INT64_MAX - t->epoch)) { return -1; }
    return t->epoch + (int64_t)delay;
}

static inline bool ex1850_tim1_core_read(const EX1850TIM1 *t,
                                         uint32_t offset, uint32_t *value)
{
    switch (offset) {
    case 0x00: *value = t->cr1; return true;
    case 0x04: *value = t->cr2; return true;
    case 0x08: *value = t->smcr; return true;
    case 0x0c: *value = t->dier; return true;
    case 0x10: *value = t->sr; return true;
    case 0x18: *value = t->ccmr1; return true;
    case 0x1c: *value = t->ccmr2; return true;
    case 0x20: *value = t->ccer; return true;
    case 0x24: *value = t->cnt; return true;
    case 0x28: *value = t->psc; return true;
    case 0x2c: if (!t->arr_known) { return false; } *value = t->arr; return true;
    case 0x30: *value = t->rcr; return true;
    case 0x34: case 0x38: case 0x3c: case 0x40:
        *value = t->ccr[(offset - 0x34) / 4]; return true;
    case 0x44: *value = t->bdtr; return true;
    default: return false; /* EGR is write-only; unmodeled registers strict. */
    }
}

static inline bool ex1850_tim1_core_valid_write(const EX1850TIM1 *t,
                                               uint32_t offset, uint32_t value)
{
    switch (offset) {
    case 0x00:
        return !(value & ~1U) && (!(value & 1) ||
               (t->active_arr_known && t->active_arr && t->cnt <= t->active_arr &&
                ex1850_tim1_compare_range_supported(t, t->active_arr)));
    case 0x04: case 0x08: case 0x18: case 0x1c: case 0x30: return value == 0;
    case 0x20: return !(value & ~EX1850_TIM1_CCER_MASK);
    case 0x44: return !(value & ~EX1850_TIM1_BDTR_MASK);
    case 0x0c: return !(value & ~EX1850_TIM1_SR_MASK);
    case 0x10: return true; /* W0C; reserved written ones cannot create flags. */
    case 0x14: return !(value & ~1U) && (!(value & 1) || t->arr_known);
    case 0x24: return value <= 0xffff &&
                     (t->active_arr_known ? value <= t->active_arr : value == 0);
    case 0x28: return value <= 0xffff;
    case 0x34: case 0x38: case 0x3c: case 0x40:
        return value <= 0xffff && (!(t->cr1 & 1) || value <= t->active_arr);
    case 0x2c: return value && value <= 0xffff && t->cnt <= value &&
                     (!(t->cr1 & 1) || ex1850_tim1_compare_range_supported(t, value));
    default: return false;
    }
}

static inline bool ex1850_tim1_core_write(EX1850TIM1 *t, uint32_t offset,
                                          uint32_t value)
{
    if (!ex1850_tim1_core_valid_write(t, offset, value)) { return false; }
    switch (offset) {
    case 0x00: t->cr1 = value; break;
    case 0x04: t->cr2 = value; break;
    case 0x08: t->smcr = value; break;
    case 0x0c: t->dier = value; break;
    case 0x10: t->sr &= value & EX1850_TIM1_SR_MASK; break;
    case 0x14:
        if (value & 1) {
            t->cnt = 0; t->phase = 0;
            t->active_psc = t->psc;
            t->active_arr = t->arr;
            t->active_arr_known = true;
            t->sr |= 1; /* Admitted UDIS=URS=RCR=0; software UEV sets UIF. */
        }
        break;
    case 0x18: t->ccmr1 = value; break;
    case 0x1c: t->ccmr2 = value; break;
    case 0x20: t->ccer = value; break;
    case 0x24: t->cnt = value; break;
    case 0x28: t->psc = value; break;
    case 0x2c:
        t->arr = t->active_arr = value;
        t->arr_known = t->active_arr_known = true; /* ARPE0 only. */
        break;
    case 0x30: t->rcr = value; break;
    case 0x34: case 0x38: case 0x3c: case 0x40:
        t->ccr[(offset - 0x34) / 4] = value; break;
    case 0x44: t->bdtr = value; break;
    default: break; /* All admitted control defaults already latch zero. */
    }
    return true;
}
#endif
