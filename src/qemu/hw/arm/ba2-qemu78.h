/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef Z6II_BA2_QEMU78_H
#define Z6II_BA2_QEMU78_H
#include "qapi/error.h"
#include "system/memory.h"
#include "ba2-core7494.h"

typedef struct Z6IIBA2QEMU78 Z6IIBA2QEMU78;
typedef struct {
    MemoryRegion *master_memory;
    /* All fields are explicit board options, never silent defaults. */
    const char *mode;                 /* reset-after-verified-copy-v1 */
    uint32_t program_base, reset_pc, ram_base;
    size_t ram_bytes;
    unsigned copy_channel, slice_steps;
    uint64_t total_steps, timer_period_ns; /* Explicit total=0 keeps bounded slices running. */
    Z6IIBA2DataEndian data_endian;
    bool allow_unaligned_data;
    const char *ram_policy;           /* synthetic-zero-v1 */
    const char *register_policy;      /* synthetic-zero-v1 */
    const char *controller_policy;    /* stop-on-access-v1 or original-triplet-fifo-candidate-v1 */
    const char *irq_policy;           /* absent-v1, fifo-level-stop-v1, or vector38 candidate */
    uint32_t irq_sr11_initial;
    const char *irq_basis;
    const char *tick139_policy;       /* original-periodic-tick-external-cycles-v1 */
    uint64_t tick139_source_hz, tick139_initial_source_cycles;
    const char *tick139_basis;        /* Explicit virtual-time clock input. */
    /* NULL keeps bn.entri unsupported; explicit stack candidate only. */
    const char *entri4_policy;        /* predecrement-candidate-v1 */
    const char *entri1n1_policy;      /* predecrement-local-word-candidate-v1 */
    const char *entri1n_policy;       /* entri1n-single-LR-Nword-v1; NULL disables */
    const char *jr9_policy;           /* direct-r9-candidate-v1 */
    const char *reti1n1_policy;       /* inverse-local-word-candidate-v1; NULL disables */
    const char *divu337_policy;       /* nonzero-uint32-candidate-v1; NULL disables */
    const char *movi_d7g3_policy;     /* exact-GNU-transformed3-candidate-v1; NULL disables */
    const char *movi_nontrap_policy;  /* GNU-signed4-nontrap-candidate-v1; NULL disables */
    const char *mov_gpr_policy;       /* bt-mov-gpr-v1; NULL disables */
    const char *bt_add_gpr_policy;    /* bt-add-gpr-v1; NULL disables */
    const char *bt_add_bn_addc_pair_policy; /* exact-D8EE-D8F0-carry-candidate-v1; NULL disables */
    const char *bg_beq_gpr_policy; /* bg-beq-gpr-v1; NULL disables */
    const char *bg_bgeu_gpr_policy; /* bg-bgeu-gpr-v1; NULL disables */
    const char *startup_isa_policy; /* startup-ISA-v1; NULL disables the startup batch */
    bool startup_irq_initial_enabled;
    const char *startup_irq_reset_basis; /* Required with startup_isa_policy. */
    const char *startup_bridge_policy; /* original-startup-mmio-candidate-v1; NULL disables */
    const char *window_policy;        /* committed-additive-ordinary-ram-v1; NULL disables */
    const char *transaction_config_policy; /* original-function-raw32-latches-v1; NULL disables */
    const char *engine140_policy; /* startup-mode9-descriptor-candidate-v1 */
    const char *engine140_basis;
    const char *engine140_backend_policy; /* NULL rejects unknown packing. */
    uint32_t engine140_backend_bytes; /* Explicit synthetic extent only. */
    const char *engine140_backend_basis;
    uint32_t startup_spr4800_initial; /* Explicit caller input with startup bridge. */
    const char *startup_bridge_basis;
    const char *msw_c0_policy;        /* bn-msw-C0-two-word-v1; NULL disables */
    const char *mlwz_c0_policy;       /* bn-mlwz-C0-two-word-v1; NULL disables */
    const char *sub_subb_pair_policy; /* exact-D8D9-D8DC-borrow-candidate-v1; NULL disables */
    const char *sub_subb_pair2_policy; /* exact-D8DF-D8E2-borrow-candidate-v1; NULL disables */
    /* Optional caller-owned strict bank; this adapter invents no SPR value.
     * All three callbacks + nonempty basis are required together. */
    Z6IIBA2SPRReadFn spr_read;
    Z6IIBA2SPRWriteFn spr_write;
    void (*spr_reset)(void *);
    void *spr_opaque;
    const char *spr_basis;
} Z6IIBA2QEMU78Config;

/* NULL config or NULL mode leaves the peer absent. With an explicit mode,
 * a functional Master and its enabled fifo-v1 endpoint are required.
 * This is an experimental peer reset policy, not verified silicon release. */
Z6IIBA2QEMU78 *z6ii_ba2_qemu78_create(const Z6IIBA2QEMU78Config *,
    bool functional_master, Z6IIIPU2402 *master_fifo,
    Z6IIBA2MasterIRQUpdateFn, void *master_irq_opaque, Error **errp);
void z6ii_ba2_qemu78_destroy(Z6IIBA2QEMU78 *);

/* Call pre immediately before the existing source read and post immediately
 * after the existing destination write, within one original DMA callback.
 * Pending/deadline checks belong to that original callback. A zero token is
 * an unrelated job. No hook performs a guest write, FIFO operation or reply. */
uint64_t z6ii_ba2_qemu78_copy_pre(void *, unsigned ch, uint32_t src,
    uint32_t dst, uint32_t len);
void z6ii_ba2_qemu78_copy_post(void *, uint64_t token, unsigned ch,
    uint32_t src, uint32_t dst, const uint8_t *actual_buffer, uint32_t len);
#endif
