/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef EX1850_GPIO_EXTI_CORE_H
#define EX1850_GPIO_EXTI_CORE_H

#include <stdbool.h>
#include <stdint.h>

/* RM0402 Rev7, SYSCFG_EXTICR and EXTI_RTSR/FTSR/PR. The caller admits
 * only declared digital input pads and rejects unsupported EMR events.
 * Routing/trigger writes do not invent an edge; IMR does not erase PR. */
static inline uint16_t ex1850_gpio_exti_routes(const uint32_t exticr[4],
                                             unsigned bank, uint16_t changed)
{
    uint16_t routed = 0;
    for (unsigned pin = 0; pin < 16; pin++) {
        if ((changed & (1U << pin)) &&
            ((exticr[pin / 4] >> (4 * (pin % 4))) & 15) == bank) {
            routed |= 1U << pin;
        }
    }
    return routed;
}

static inline uint32_t ex1850_gpio_exti_pending(uint32_t pending,
                                               uint32_t rising_select,
                                               uint32_t falling_select,
                                               uint16_t routed,
                                               uint16_t previous,
                                               uint16_t levels)
{
    uint32_t rising = routed & ~previous & levels;
    uint32_t falling = routed & previous & ~levels;
    return pending | (rising & rising_select) | (falling & falling_select);
}

/* RM0402 Rev7 Table40: EXTI0..4 are separate, EXTI5..9 and EXTI10..15
 * are shared NVIC requests. Preserve all pending members of each group.
 * RTC17 has its own IRQ41 and is deliberately outside these masks. */
static inline uint32_t ex1850_gpio_exti_irq_mask(unsigned irq)
{
    if (irq >= 6 && irq <= 10) { return UINT32_C(1) << (irq - 6); }
    if (irq == 23) { return UINT32_C(0x03e0); }
    if (irq == 40) { return UINT32_C(0xfc00); }
    return 0;
}

static inline bool ex1850_gpio_exti_irq(uint32_t pending, uint32_t imr,
                                       unsigned irq)
{
    return !!(pending & imr & ex1850_gpio_exti_irq_mask(irq));
}

#endif
