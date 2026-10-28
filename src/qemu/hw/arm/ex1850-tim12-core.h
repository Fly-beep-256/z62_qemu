/* SPDX-License-Identifier: GPL-2.0-or-later */
/* STM32F412 TIM12, 40001800, RCC APB1 bit6, IRQ43 shared with TIM8.
 * Pure elapsed-clock model used by the board and independent host checks.
 * Only internal upcount and frozen output comparison are admitted. Input
 * capture, slave/external triggers, DMA and output waveform modes are strict.
 * No firmware flags, callbacks, protocol data or wait results are supplied.
 */
#ifndef EX1850_TIM12_CORE_H
#define EX1850_TIM12_CORE_H
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>

typedef struct EX1850TIM12 {
    uint32_t cr1, dier, sr, ccer;
    uint32_t cnt, psc, active_psc, arr, active_arr, ccr[2];
    int64_t epoch;
    uint64_t phase; /* source-clock cycle numerator, denominator 1e9 */
    uint64_t updates, compares[2];
} EX1850TIM12;

static inline void ex1850_tim12_core_reset(EX1850TIM12 *t, int64_t now)
{
    memset(t, 0, sizeof(*t));
    t->arr = t->active_arr = 0xffff;
    t->epoch = now;
}

static inline uint32_t ex1850_tim12_distance(uint32_t point, uint32_t cnt)
{
    uint32_t distance = (point - cnt) & 0xffff;
    return distance ? distance : 0x10000;
}

static inline uint32_t ex1850_tim12_next_ticks(const EX1850TIM12 *t)
{
    uint32_t ticks = ex1850_tim12_distance(t->active_arr + 1, t->cnt);
    for (unsigned n = 0; n < 2; n++) {
        uint32_t compare = ex1850_tim12_distance(t->ccr[n], t->cnt);
        if (compare < ticks) { ticks = compare; }
    }
    return ticks;
}

static inline void ex1850_tim12_core_sync(EX1850TIM12 *t, int64_t now,
                                         uint32_t kernel_hz)
{
    int64_t elapsed = now - t->epoch;
    t->epoch = now;
    if (elapsed <= 0 || !kernel_hz || !(t->cr1 & 1) || !t->active_arr) {
        return;
    }
    __uint128_t budget = (__uint128_t)(uint64_t)elapsed * kernel_hz + t->phase;
    while (t->cr1 & 1) {
        uint64_t divisor = (uint64_t)(t->active_psc + 1) * UINT64_C(1000000000);
        uint32_t next = ex1850_tim12_next_ticks(t);
        if (budget < (__uint128_t)next * divisor) {
            t->cnt = (t->cnt + (uint64_t)(budget / divisor)) & 0xffff;
            t->phase = budget % divisor;
            return;
        }
        budget -= (__uint128_t)next * divisor;
        bool update = next == ex1850_tim12_distance(t->active_arr + 1, t->cnt);
        t->cnt = (t->cnt + next) & 0xffff;
        if (update) {
            t->cnt = 0;
            if (!(t->cr1 & 2)) { /* UDIS suppresses update and preload transfer. */
                t->active_psc = t->psc;
                t->active_arr = t->arr;
                t->sr |= 1;
                t->updates++;
                if (t->cr1 & 8) { t->cr1 &= ~1U; }
            }
        }
        for (unsigned n = 0; n < 2; n++) {
            if (t->cnt == t->ccr[n]) {
                t->sr |= 2U << n;
                t->compares[n]++;
            }
        }
        if (!t->active_arr) { break; }
    }
    t->phase = 0;
}

static inline bool ex1850_tim12_core_irq(const EX1850TIM12 *t)
{
    return (t->sr & t->dier & 7) != 0;
}

static inline int64_t ex1850_tim12_core_deadline(const EX1850TIM12 *t,
                                               uint32_t kernel_hz)
{
    if (!kernel_hz || !(t->cr1 & 1) || !t->active_arr) { return -1; }
    uint64_t divisor = (uint64_t)(t->active_psc + 1) * UINT64_C(1000000000);
    uint64_t numerator = (uint64_t)ex1850_tim12_next_ticks(t) * divisor - t->phase;
    uint64_t delay = (numerator + kernel_hz - 1) / kernel_hz;
    if (delay > (uint64_t)(INT64_MAX - t->epoch)) { return -1; }
    return t->epoch + delay;
}

static inline bool ex1850_tim12_core_read(EX1850TIM12 *t, uint32_t offset,
                                         uint32_t *value)
{
    switch (offset) {
    case 0x00: *value = t->cr1; return true;
    case 0x0c: *value = t->dier; return true;
    case 0x10: *value = t->sr; return true;
    case 0x20: *value = t->ccer; return true;
    case 0x24: *value = t->cnt; return true;
    case 0x28: *value = t->psc; return true;
    case 0x2c: *value = t->arr; return true;
    case 0x34: *value = t->ccr[0]; return true;
    case 0x38: *value = t->ccr[1]; return true;
    case 0x04: case 0x08: case 0x14: case 0x18:
        *value = 0; return true;
    default: return false;
    }
}

static inline bool ex1850_tim12_core_valid_write(uint32_t offset, uint32_t value)
{
    switch (offset) {
    case 0x00: return !(value & ~UINT32_C(0x8f));
    case 0x0c: return !(value & ~7U);
    case 0x10: return true; /* W0C; reserved ones do not generate flags. */
    case 0x14: return !(value & ~7U);
    case 0x20: return !(value & ~UINT32_C(0x33));
    case 0x24: case 0x28: case 0x2c: case 0x34: case 0x38:
        return !(value & ~UINT32_C(0xffff));
    case 0x04: case 0x08: case 0x18: return value == 0;
    default: return false;
    }
}

static inline bool ex1850_tim12_core_write(EX1850TIM12 *t, uint32_t offset,
                                          uint32_t value)
{
    if (!ex1850_tim12_core_valid_write(offset, value)) { return false; }
    switch (offset) {
    case 0x00: t->cr1 = value; break;
    case 0x0c: t->dier = value; break;
    case 0x10: t->sr &= value & 7; break;
    case 0x14:
        if (value & 1) {
            t->cnt = 0;
            t->phase = 0;
            if (!(t->cr1 & 2)) {
                t->active_psc = t->psc;
                t->active_arr = t->arr;
                if (!(t->cr1 & 4)) { t->sr |= 1; }
            }
        }
        t->sr |= value & 6; /* Guest CCxG events, frozen output comparison. */
        break;
    case 0x20: t->ccer = value; break;
    case 0x24: t->cnt = value; break;
    case 0x28: t->psc = value; break;
    case 0x2c:
        t->arr = value;
        if (!(t->cr1 & 0x80)) { t->active_arr = value; }
        break;
    case 0x34: t->ccr[0] = value; break;
    case 0x38: t->ccr[1] = value; break;
    default: break;
    }
    return true;
}
#endif
