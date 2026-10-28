/* SPDX-License-Identifier: GPL-2.0-or-later */
/* STM32F412 STOP via SLEEPDEEP + WFI. Clock and NVIC integration lives in
 * the board; this state never contains guest callbacks or RTOS flags. */
#ifndef EX1850_POWER_CORE_H
#define EX1850_POWER_CORE_H
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

typedef struct EX1850Power {
    uint32_t scr;
    bool stopped;
    int64_t entered_ns;
    uint64_t entries, wakes;
} EX1850Power;

static inline bool ex1850_power_scr(EX1850Power *p, uint32_t value)
{
    /* SLEEPONEXIT, SEVONPEND, security and event wake remain unsupported. */
    if (value & ~UINT32_C(4)) { return false; }
    if (p->stopped) { return false; }
    p->scr = value;
    return true;
}

static inline const char *ex1850_power_enter(EX1850Power *p, uint32_t pwr_cr,
                                            uint16_t insn, bool thumb,
                                            int64_t now)
{
    if (p->stopped || !(p->scr & 4)) { return "STOP-state-or-SLEEPDEEP"; }
    if (pwr_cr & 2) { return "STANDBY-not-modeled"; }
    if (!thumb || insn != 0xbf30) { return "deep-sleep-entry-is-not-WFI"; }
    p->stopped = true;
    p->entered_ns = now;
    p->entries++;
    return NULL;
}

static inline bool ex1850_power_wake(EX1850Power *p, bool enabled_pending_irq)
{
    if (!p->stopped || !enabled_pending_irq) { return false; }
    p->stopped = false;
    p->wakes++;
    return true;
}
#endif
