/* SPDX-License-Identifier: GPL-2.0-or-later */
/* STM32F412 internal RTC alarm -> EXTI17 -> IRQ41, RM0402 pp232,237,
 * 241-242,630. This is an interrupt contract; event wake and SWIER are
 * not implemented. Configuration writes never replay an earlier edge. */
#ifndef EX1850_RTC_EXTI_CORE_H
#define EX1850_RTC_EXTI_CORE_H

#include <stdbool.h>
#include <stdint.h>

#define EX1850_RTC_EXTI_LINE (1U << 17)
#define EX1850_RTC_EXTI_IRQ 41U

typedef struct EX1850RTCEXTI {
    bool input, irq;
    uint64_t edges, selected_edges;
} EX1850RTCEXTI;

static inline bool ex1850_rtc_exti_input(EX1850RTCEXTI *e, bool level,
    uint32_t rtsr, uint32_t ftsr, uint32_t *pending)
{
    if (level == e->input) { return false; }
    e->input = level;
    e->edges++;
    if ((level ? rtsr : ftsr) & EX1850_RTC_EXTI_LINE) {
        *pending |= EX1850_RTC_EXTI_LINE;
        e->selected_edges++;
    }
    return true;
}

static inline bool ex1850_rtc_exti_irq(uint32_t pending, uint32_t imr)
{
    return !!(pending & imr & EX1850_RTC_EXTI_LINE);
}

static inline uint32_t ex1850_rtc_exti_w1c(uint32_t pending, uint32_t written)
{
    return pending & ~written;
}

#endif
