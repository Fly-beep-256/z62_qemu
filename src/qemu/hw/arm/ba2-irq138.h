/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef Z6II_BA2_IRQ138_H
#define Z6II_BA2_IRQ138_H
#include "ba2-core7494.h"
#include "ba2-tick139.h"
#define Z6II_BA2_IRQ138_VECTOR UINT32_C(0x40000038)
typedef uint32_t (*Z6IIBA2IRQ138SourcesFn)(void *);
typedef struct Z6IIBA2IRQ138 {
    const char *basis;
    uint32_t vector_pc, sr11, epc20, esr40, entry_esr40;
    bool active, exception_known, saved_flag, saved_flag_known;
    uint64_t entries, returns, tick_entries, tick_returns;
    unsigned active_source; /* 1=external FIFO/engine, 2=tick; nonnested frame */
    Z6IIBA2IRQ138SourcesFn external_sources;
    void *external_sources_opaque;
    Z6IIBA2Tick139 *tick139;
    uint32_t tick_vector_pc;
    Z6IIBA2RAMBatchReadFn ram_read;
    Z6IIBA2RAMBatchWriteFn ram_write;
    void *ram_opaque;
} Z6IIBA2IRQ138;
/* Explicit caller SR11 snapshot: bit2 is the IRQ-enable software candidate.
 * Raw ROM vector38 reaches BD63, then original ISR7383 and RFE0400. No host
 * GPR/stack save, FIFO consume, IRQ injection or protocol response occurs here.
 * EPC20/ESR40 become known only on actual level+EI entry. Non-nested IRQ and
 * preserved private compare flag are bounded policies, not silicon claims. */
Z6IIBA2CPUResult z6ii_ba2_cpu_enable_irq138_candidate(Z6IIBA2CPU *,
    Z6IIBA2IRQ138 *,uint32_t vector_pc,uint32_t caller_sr11_initial,
    Z6IIBA2RAMBatchReadFn,Z6IIBA2RAMBatchWriteFn,void *ram_opaque,
    const char *basis);
/* Optional original vector30 tick source. FIFO wins a simultaneous pending
 * boundary in this explicit bounded priority policy. Both sources use the
 * evidenced global EI bit2; OR1K TEE mappings are not assumed. */
Z6IIBA2CPUResult z6ii_ba2_irq138_bind_tick139_candidate(Z6IIBA2IRQ138 *,
    Z6IIBA2Tick139 *,uint32_t vector_pc,const char *basis);
/* Optional original source bitmap. No binding preserves old bool->2 behavior.
 * entries/returns count aggregate external IRQs when the bitmap is bound. */
Z6IIBA2CPUResult z6ii_ba2_irq138_bind_external_sources(Z6IIBA2IRQ138 *,
    Z6IIBA2IRQ138SourcesFn,void *,const char *basis);
Z6IIBA2CPUResult z6ii_ba2_irq138_poll(Z6IIBA2CPU *);
Z6IIBA2SPRResult z6ii_ba2_irq138_spr(Z6IIBA2CPU *,uint32_t selector,
    bool write,uint32_t *value,bool *handled);
Z6IIBA2CPUResult z6ii_ba2_irq138_rfe(Z6IIBA2CPU *,uint32_t *next);
bool z6ii_ba2_irq138_group_shape(const Z6IIBA2CPU *,const Z6IIBA2Decoded *);
Z6IIBA2CPUResult z6ii_ba2_irq138_group(Z6IIBA2CPU *,const Z6IIBA2Decoded *);
/* Eight-word atomic ordinary RAM access, separate from the old <=4 callbacks.
 * All ranges/permissions/alignment are checked before any RAM/output mutation. */
Z6IIBA2BusResult z6ii_ba2_irq138_ram_read_batch(void *,const uint32_t *,uint32_t *,unsigned);
Z6IIBA2BusResult z6ii_ba2_irq138_ram_write_batch(void *,const uint32_t *,const uint32_t *,unsigned);
#endif
