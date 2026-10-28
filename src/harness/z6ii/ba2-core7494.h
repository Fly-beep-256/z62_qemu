/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef Z6II_BA2_CORE7494_H
#define Z6II_BA2_CORE7494_H
#include <stdbool.h>
#include <stdint.h>
#include "ba2-bus77.h"
#define Z6II_BA2_CORE_MAX_RAW 6u
typedef enum {
    Z6II_BA2_CPU_OK=0, Z6II_BA2_CPU_BAD_CONFIG,
    Z6II_BA2_CPU_BUS_FAULT, Z6II_BA2_CPU_UNKNOWN_OPCODE,
    Z6II_BA2_CPU_UNSUPPORTED_OPCODE, Z6II_BA2_CPU_UNSUPPORTED_IRQ,
    Z6II_BA2_CPU_BUDGET, Z6II_BA2_CPU_UNKNOWN_SPR, Z6II_BA2_CPU_SPR_FAULT
} Z6IIBA2CPUResult;
typedef Z6IIBA2BusResult (*Z6IIBA2FetchFn)(void *,uint32_t,uint8_t *,unsigned);
typedef struct {
    uint32_t pc; uint8_t raw[6]; unsigned length;
    const char *name,*exec_reference;
    int64_t field[128]; bool field_present[128];
    uint32_t source_line;
} Z6IIBA2Decoded;
typedef enum { Z6II_BA2_SPR_OK=0, Z6II_BA2_SPR_UNKNOWN, Z6II_BA2_SPR_FAULT } Z6IIBA2SPRResult;
typedef Z6IIBA2SPRResult (*Z6IIBA2SPRReadFn)(void *,uint32_t selector,uint32_t *value);
typedef Z6IIBA2SPRResult (*Z6IIBA2SPRWriteFn)(void *,uint32_t selector,uint32_t value);
struct Z6IIBA2IRQ138;
/* Atomic RAM batch callback: on failure, all RAM/output remains unchanged.
 * The owner must hold BQL or exclusively own the target RAM. No MMIO fallback. */
typedef Z6IIBA2BusResult (*Z6IIBA2RAMBatchWriteFn)(void *,const uint32_t *addresses,
                                               const uint32_t *values,unsigned count);
/* One atomic ordinary-RAM read batch; failed callbacks preserve RAM/output.
 * Caller holds BQL/exclusive mapped RAM access and uses a separate output array.
 * This callback supplies a model transaction, not silicon grouped-read timing. */
typedef Z6IIBA2BusResult (*Z6IIBA2RAMBatchReadFn)(void *,const uint32_t *addresses,
                                              uint32_t *values,unsigned count);
/* Staged ordinary RAM-only read32. No MMIO/payload fallback or RAM writes.
 * Caller owns endian/alignment policy and BQL/exclusive RAM ownership.
 * Failed reads must preserve RAM/output; the core commits no guest state. */
typedef Z6IIBA2BusResult (*Z6IIBA2RAMRead32Fn)(void *,uint32_t,uint32_t *);
/* Callback failures must preserve SPR state/output. No built-in SPR defaults. */
typedef struct {
    uint32_t r[32],pc;
    bool flag,flag_known; /* IRQ/SPR/flags unproved; no guessed reset SR. */
    uint64_t retired;
    Z6IIBA2CPUResult halted;
    Z6IIBA2BusResult bus_result;
    Z6IIBA2Decoded last;
    Z6IIBA2FetchFn fetch;
    Z6IIBA2ReadFn read;
    Z6IIBA2WriteFn write;
    Z6IIBA2IRQFn irq;
    void *bus_opaque;
    Z6IIBA2SPRReadFn spr_read;
    Z6IIBA2SPRWriteFn spr_write;
    void *spr_opaque;
    uint32_t last_spr_selector,last_spr_value;
    bool last_spr_write,last_spr_access;
    Z6IIBA2SPRResult last_spr_result;
    Z6IIBA2RAMBatchWriteFn entri4_atomic_write;
    void *entri4_opaque;
    const char *entri4_basis; /* Explicit opt-in ABI/old-decoder candidate; not a reset default. */
    Z6IIBA2RAMBatchWriteFn entri1n1_atomic_write;
    void *entri1n1_opaque;
    const char *entri1n1_basis; /* Independent opt-in; slot/word unit remain candidates. */
    const char *jr9_basis; /* Independent explicit opt-in to direct bn.jr r9. */
    Z6IIBA2RAMRead32Fn reti1n1_ram_read;
    void *reti1n1_opaque;
    const char *reti1n1_basis; /* Independent ordinary inverse candidate, default disabled. */
    const char *divu_basis; /* Independent nonzero bn.divu D3/A3/B7 candidate. */
    const char *movi_d7g3_basis; /* Independent bt.movi D7/G3 candidate, default disabled. */
    const char *movi_nontrap_basis; /* Independent all nontrap bt.movi D1..31/G-8..7 policy. */
    Z6IIBA2RAMBatchWriteFn entri1n_atomic_write;
    void *entri1n_opaque;
    const char *entri1n_basis; /* Independent single-LR/N-word candidate, default disabled. */
    const char *mov_gpr_basis; /* Independent bt.mov D1..31/A0..31 policy, default disabled. */
    Z6IIBA2RAMBatchWriteFn msw_c0_atomic_write;
    void *msw_c0_opaque;
    const char *msw_c0_basis; /* Independent C0/two-word RAM candidate, default disabled. */
    Z6IIBA2RAMBatchReadFn mlwz_c0_atomic_read;
    void *mlwz_c0_opaque;
    const char *mlwz_c0_basis; /* Independent C0/two-word RAM read, default disabled. */
    const char *sub_subb_pair_basis; /* Explicit exact-pair borrow candidate. */
    uint32_t sub_subb_pair_next_pc;
    uint64_t sub_subb_pair_next_retired;
    bool sub_subb_pair_pending;
    const char *sub_subb_pair2_basis; /* Independent second exact pair. */
    uint32_t sub_subb_pair2_next_pc;
    uint64_t sub_subb_pair2_next_retired;
    bool sub_subb_pair2_pending;
    const char *bt_add_gpr_basis; /* Independent ordinary bt.add, default disabled. */
    const char *bt_add_bn_addc_pair_basis; /* Independent exact unsigned pair. */
    uint32_t bt_add_bn_addc_pair_next_pc;
    uint64_t bt_add_bn_addc_pair_next_retired;
    bool bt_add_bn_addc_pair_pending;
    bool bt_add_bn_addc_pair_carry,bt_add_bn_addc_pair_carry_known;
    const char *bg_beq_gpr_basis; /* Independent ordinary equality; default disabled. */
    const char *bg_bgeu_gpr_basis; /* Independent unsigned comparison; default disabled. */
    Z6IIBA2RAMBatchReadFn startup_isa_ram_read;
    void *startup_isa_opaque;
    const char *startup_isa_basis; /* Independent default-disabled startup batch. */
    bool startup_irq_enabled,startup_irq_mask_known; /* Local model state, no delivery. */
    const char *startup_irq_reset_basis; /* Caller-owned initial-mask input, if supplied. */
    struct Z6IIBA2IRQ138 *startup_irq138; /* Owned original-vector IRQ candidate. */
    const char *reset_basis; /* Required: initial register snapshot is caller-owned. */
} Z6IIBA2CPU;
/* r0 is the explicit caller snapshot, with ordinary storage. No hardwired-zero
 * claim is made. Known opcode with unproved execution stops without retiring. */
Z6IIBA2CPUResult z6ii_ba2_cpu_init(Z6IIBA2CPU *,uint32_t pc,const uint32_t r[32],
    const char *reset_basis,Z6IIBA2FetchFn,Z6IIBA2ReadFn,Z6IIBA2WriteFn,
    Z6IIBA2IRQFn,void *bus_opaque);
void z6ii_ba2_cpu_set_spr_callbacks(Z6IIBA2CPU *,Z6IIBA2SPRReadFn,
    Z6IIBA2SPRWriteFn,void *spr_opaque);
/* Enables only decoded bn.entri F=4,N=0. Does not clear an existing halt.
 * Success saves r9..r12 at SP-4,-8,-12,-16 and then updates SP; no IRQ policy. */
Z6IIBA2CPUResult z6ii_ba2_cpu_enable_entri4_candidate(Z6IIBA2CPU *,
    Z6IIBA2RAMBatchWriteFn,void *opaque,const char *basis);
/* Enables only bn.entri F=1,N=1 independently of F4/N0. No existing halt cleared.
 * Saves r9 at old SP-4, then SP-=8, reserving one unmodified local word.
 * N*4 and slot order are old-decoder candidates, not certified silicon policy. */
Z6IIBA2CPUResult z6ii_ba2_cpu_enable_entri1n1_candidate(Z6IIBA2CPU *,
    Z6IIBA2RAMBatchWriteFn,void *opaque,const char *basis);
/* Independent default-disabled bn.entri/l_entri/length3 F1/N0..255 candidate.
 * Save r9 at oldSP-4 through one atomic RAM-only callback; on success reduce SP
 * by 4*(N+1), reserving N untouched local words. Underflow stops before callback.
 * GNU proves operand encoding; public software supplies the stack rule, not
 * certified silicon flags/IRQ/return/timing behavior. Does not clear a halt,
 * enable other APIs or expand reti/rtnei. With both F1 APIs enabled this callback
 * owns F1 entries; the old F1/N1 API remains independently usable. */
Z6IIBA2CPUResult z6ii_ba2_cpu_enable_entri1n_candidate(Z6IIBA2CPU *,
    Z6IIBA2RAMBatchWriteFn,void *opaque,const char *basis);
/* Enables only bn.jr A=r9; does not clear an existing halt. Direct PC=r9,
 * without LR/SP/flag writes or low-bit masking. Target checks are next-fetch
 * model policy, not certified BA2 silicon exception semantics. */
Z6IIBA2CPUResult z6ii_ba2_cpu_enable_jr9_candidate(Z6IIBA2CPU *,const char *basis);
/* Enables only ordinary bn.reti F=1,N=1; does not clear an existing halt.
 * Stage RAM[SP+4], then restore r9, SP+=8 and PC=r9 on read success.
 * PC/flag preservation and next-fetch target checks are explicit software
 * policy, not silicon/IRQ-return certification. rtnei and other F/N stop. */
Z6IIBA2CPUResult z6ii_ba2_cpu_enable_reti1n1_candidate(Z6IIBA2CPU *,
    Z6IIBA2RAMRead32Fn,void *opaque,const char *basis);
/* Independent default-disabled startup-ISA-v1 software candidate.
 * Ordinary bn.reti F1/N0..255 or F4/N0 is the inverse of modeled entri shapes.
 * RAM-only callback stages all saved words before GPR/SP/PC commit; next fetch
 * is deferred. bn.sb/lbz use decoded unsigned8 N and width1 bus callbacks.
 * bn.rtnei restores the supported F/N frame and continues at oldPC+3 rather
 * than branching to LR; it commits local EI only after all reads succeed.
 * GNU/ROM tail-call evidence supports this candidate; silicon rule unknown.
 * bn.bnei B0..31/Eunsigned3/Psigned8 compares caller GPR directly, then
 * PC=oldPC+P if unequal or oldPC+3 if equal; no flag/prefetch writes.
 * Exact 0401/0402 EI/DI update local known/enabled mask model state only.
 * They do not write GPR/SPR/FIFO or deliver an IRQ. Any nonzero external IRQ
 * query still hard-stops, including while the local mask is disabled.
 * GNU proves encoding; execution/initial mask are explicit software policy,
 * not silicon certification. API does not enable old candidates or clear halt. */
Z6IIBA2CPUResult z6ii_ba2_cpu_enable_startup_isa_candidate(Z6IIBA2CPU *,
    Z6IIBA2RAMBatchReadFn,void *opaque,const char *basis);
/* Optional explicit initial local-mask snapshot after enabling startup policy.
 * Absent snapshot means mask_known=false until EI/DI; no reset default inferred.
 * This setter preserves halt, other candidates, GPR/SPR/FIFO and private flags. */
Z6IIBA2CPUResult z6ii_ba2_cpu_set_startup_irq_mask_snapshot(Z6IIBA2CPU *,
    bool enabled,const char *basis);
/* Enables only bn.divu / l_divu with D=3,A=3,B=7 and nonzero r7.
 * Snapshot both uint32 inputs before r3 commit (D=A). No existing halt cleared.
 * Signed div, other registers and division by zero remain unsupported; flags
 * preservation is explicit software policy, not certified silicon behavior. */
Z6IIBA2CPUResult z6ii_ba2_cpu_enable_divu_candidate(Z6IIBA2CPU *,const char *basis);
/* Enables only bt.movi / b_movi, length 2, D=7,G=+3. Does not clear a halt.
 * Uses already decoded signed G (GNU width4, LSB swizzle, shift0), never raw
 * nibble C. Other destinations/immediates, including r0 trap aliases, stop.
 * Other state preservation is software policy, not silicon flag certification. */
Z6IIBA2CPUResult z6ii_ba2_cpu_enable_movi_d7g3_candidate(Z6IIBA2CPU *,const char *basis);
/* Independent default-disabled ordinary bt.movi/b_movi policy, length2,
 * D1..31 and decoded signed4 G=-8..7. D0 trap aliases remain unsupported.
 * Assign decoded G converted to uint32_t, then ordinary PC+=2/retired+=1.
 * r1/SP and r9/LR are ordinary destinations; no stack/return operation.
 * Does not enable the narrow D7/G3 API or clear a halt. Other state/flags
 * preservation is model policy; no silicon flags/timing/exception claim. */
Z6IIBA2CPUResult z6ii_ba2_cpu_enable_movi_nontrap_candidate(Z6IIBA2CPU *,const char *basis);
/* Independent default-disabled bt.mov/b_mov/length2 D1..31,A0..31.
 * Stage the caller snapshot source uint32, then commit r[D]; PC+=2/retired+=1.
 * All D0 forms remain unsupported, including RFE/EI/DI/SYS control aliases.
 * r0 retains ordinary caller storage; r1/SP and r9/LR are ordinary destinations.
 * No other API or latched halt changes. Other state/flags preservation is
 * explicit software policy, not certified silicon IRQ/flags/timing semantics. */
Z6IIBA2CPUResult z6ii_ba2_cpu_enable_mov_gpr_candidate(Z6IIBA2CPU *,const char *basis);
/* Independent default-disabled bn.msw/b_msw/length3 C0 candidate.
 * GNU proves A/B/K/C encoding; original firmware data flow supports C0 writing
 * two successive 32-bit words. This is not certified silicon semantics.
 * Accept A0..31,B0..30,K=unsigned6*4 only; snapshot old r[A], r[B], r[B+1].
 * Atomic ordinary RAM-only callback writes base+K and base+K+4 in that order.
 * Reject the complete 8-byte address range on uint32 wrap before callback.
 * B31 and all C1..3 stop. On callback failure no guest GPR/PC/retired commits.
 * Caller owns RAM mapping/permission/alignment/endian and exclusive ownership.
 * No MMIO fallback, other API enablement, or existing halt clearance.
 * Flags/state preservation and atomic failure handling are model policy. */
Z6IIBA2CPUResult z6ii_ba2_cpu_enable_msw_c0_candidate(Z6IIBA2CPU *,
    Z6IIBA2RAMBatchWriteFn,void *opaque,const char *basis);
/* Independent default-disabled bn.mlwz/b_mlwz/length3 C0 candidate.
 * GNU proves A/D/K/C fields; original r24/r25 use supports a two-word C0 model.
 * Public decoder marks execution unknown; count/flags remain silicon-unverified.
 * Accept A0..31,D0..30,K=unsigned6*4 only; snapshot old base before any GPR write.
 * Reject complete8-byte uint32 wrap, then call one atomic ordinary RAM-only read
 * for base+K/base+K+4. On success commit r[D]/r[D+1], PC+=3 and retired+=1.
 * On any callback failure, no GPR/PC/retired commit, even if temp outputs changed.
 * D31 and all C1..3 hard-stop. No payload/MMIO fallback or base postincrement.
 * Caller owns mapping/permission/alignment/endian and BQL/exclusive ownership.
 * r0 is caller storage; flags/state preservation and fault timing are model policy.
 * Does not enable msw/reti/other API or clear an existing halt. */
Z6IIBA2CPUResult z6ii_ba2_cpu_enable_mlwz_c0_candidate(Z6IIBA2CPU *,
    Z6IIBA2RAMBatchReadFn,void *opaque,const char *basis);

/* Independent default-disabled exact original double-word subtraction model.
 * Only 4000D8D9/60C6C5 sub D6/A6/B24 may produce a pending borrow; only the
 * adjacent 4000D8DC/68E7C8 subb D7/A7/B25 may consume it at recorded retired+1.
 * GNU proves fields; public subb execution is absent and sub flags are TODO.
 * Lower old r6<r24 is explicitly the candidate borrow direction: flag=borrow,
 * flag_known=true. Upper stages old r7/r25 and subtracts that 0/1 borrow.
 * Requires known flag and complete pending PC/raw/register/retired provenance.
 * Upper success consumes pending and marks flag_known=false; no claim about
 * architectural carry/overflow/high-word flags. Any intervening retired op
 * invalidates pending/known. Failure commits no GPR/PC/retired/flag/provenance.
 * Unpaired or other subb remains unsupported; ordinary other sub retains v17.
 * API changes basis/invalidates pending only: no flag initialization, halt
 * clearance, SPR/device writes or other API enablement. Silicon policy unproved. */
Z6IIBA2CPUResult z6ii_ba2_cpu_enable_sub_subb_pair_candidate(Z6IIBA2CPU *,
    const char *basis);

/* Independent default-disabled second exact paired-dataflow candidate.
 * Only 4000D8DF/60C625 sub D6/A6/B4 produces old-r6<old-r4 borrow;
 * only 4000D8E2/68E728 subb D7/A7/B5 consumes known borrow at recorded
 * nextPC/retired+1. Upper uses old-r7-old-r5-borrow with uint32 wrap,
 * consumes pair2 pending and marks flag_known=false. Any other retired op
 * invalidates pair2 pending/known; failures commit no guest/provenance state.
 * GNU proves fields, paired original dataflow supports inference; borrow
 * direction and flag effects are model policy, not certified silicon.
 * Separate API/basis/provenance never enables or widens the v18 first pair.
 * API changes only pair2 basis/pending, not flags/halt/other API state. */
Z6IIBA2CPUResult z6ii_ba2_cpu_enable_sub_subb_pair2_candidate(Z6IIBA2CPU *,
    const char *basis);

/* Independent default-disabled ordinary bt.add/bt_add/length2 D1..31,A0..31.
 * GNU line120 proves register5 encoding; fixed public ESIL lines116..128 gives
 * old r[D]+old r[A] -> r[D]. Stage both uint32 inputs before aliased commit.
 * Addition wraps modulo2^32; r0 remains caller snapshot storage, r1/SP and r9/LR
 * are ordinary GPRs. D0 and all other add/carry/control forms hard-stop.
 * Does not consume or produce architectural carry/overflow/IRQ/device state.
 * Existing flag/flag_known preservation is software model policy, not silicon
 * certification; the unchanged common tail invalidates pending exact pairs
 * after this intervening successful retirement. Faults preserve provenance.
 * API changes only its basis, never flags/pending/other APIs or a latched halt. */
Z6IIBA2CPUResult z6ii_ba2_cpu_enable_bt_add_gpr_candidate(Z6IIBA2CPU *,
    const char *basis);
/* Independent default-disabled exact original double-word unsigned add model.
 * Only 4000D8EE/0B06 bt.add D24/A6 produces bit32 of staged old-r24+old-r6.
 * Only adjacent 4000D8F0/67393F bn.addc D25/A25/B7 consumes that 0/1 carry
 * at recorded nextPC/retired+1, committing old-r25+old-r7+carry modulo2^32.
 * GNU proves encoding; fixed public decoder lacks addc and flags execution.
 * Paired firmware data flow supports this explicitly unverified candidate.
 * Uses private carry/known/pending, never architectural flag/flag_known.
 * Any other successful retirement invalidates pending/known; upper consumes
 * to unknown. Failure preserves GPR/PC/retired and all carry provenance.
 * API changes own basis/pending/known only, not carry value or flags/halt.
 * Does not enable ordinary bt.add or either sub/subb API, expand their ranges,
 * or add generic carry fallback, SPR/IRQ/device/Ready/timing effects. */
Z6IIBA2CPUResult z6ii_ba2_cpu_enable_bt_add_bn_addc_pair_candidate(Z6IIBA2CPU *,
    const char *basis);
/* Independent default-disabled bg.beq/b_beq/length4 A0..31,B0..31,U signed12.
 * Fixed GNU proves fields; fixed public software supplies direct GPR equality.
 * Equal: oldPC+(uint32)U modulo2^32; unequal: oldPC+4. Caller r0, SP/LR are
 * ordinary snapshot GPRs. No low-bit masking, target prefetch or flag dependency.
 * No GPR/flag writes in the branch; inherited common success-tail invalidation
 * still ends pending exact pairs (including sub-pair flag_known invalidation).
 * Failed steps preserve provenance. Next-fetch faults, flags and timing remain
 * explicit model policy, not certified silicon/IRQ/exception behavior.
 * API changes only own basis, never flags/pending/other APIs or a latched halt.
 * No other beq/immediate/control opcode, SPR/IRQ/device/Ready/timer effects. */
Z6IIBA2CPUResult z6ii_ba2_cpu_enable_bg_beq_gpr_candidate(Z6IIBA2CPU *,
    const char *basis);
/* Independent default-disabled bg.bgeu/b_bgeu/length4 A0..31,B0..31,U signed12.
 * Fixed GNU proves fields; fixed public ESIL emits raw GPR >= comparison.
 * Comparing uint32 snapshots is this candidate's explicit unsigned policy.
 * Unsigned >=: oldPC+(uint32)U modulo2^32; less: oldPC+4. Caller r0, SP/LR are
 * ordinary snapshot GPRs. No low-bit masking, target prefetch or flag dependency.
 * No GPR/flag writes in the branch; inherited common success-tail invalidation
 * still ends pending exact pairs (including sub-pair flag_known invalidation).
 * Failed steps preserve provenance. Next-fetch faults, flags and timing remain
 * explicit model policy, not certified silicon/IRQ/exception behavior.
 * API changes only own basis, never flags/pending/other APIs or a latched halt.
 * No other bgeu/signed/immediate/control opcode, SPR/IRQ/device/Ready/timer effects. */
Z6IIBA2CPUResult z6ii_ba2_cpu_enable_bg_bgeu_gpr_candidate(Z6IIBA2CPU *,
    const char *basis);
Z6IIBA2CPUResult z6ii_ba2_cpu_step(Z6IIBA2CPU *);
Z6IIBA2CPUResult z6ii_ba2_cpu_run(Z6IIBA2CPU *,uint64_t budget);
const char *z6ii_ba2_cpu_result_name(Z6IIBA2CPUResult);
#endif
