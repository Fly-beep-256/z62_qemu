/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Private minimum BA2 interpreter. Numeric decode table generated from the
 * fixed GNU ba-isa-ba2.c (a50c3ea); no upstream code is executed. Execution includes ordinary OR/AND, PC-relative jumps,
 * JAL (r9 linkage inferred from GNU DWARF column9 and original leaf jr9),
 * strict SPR callbacks for demonstrated reset addressing, LR9 return candidate,
 * ordinary LWZ/SW/ADDI and direct unsigned register BGTU. Unknown SPRs stop.
 * Endian/alignment and SPR storage are explicit caller contracts.
 * ADDI uses uint32 modular arithmetic and makes no flag/carry claims.
 * This is an explicit candidate, not an assertion of full BA2 reset semantics. */
#include <stddef.h>
#include <string.h>
#include "ba2-core7494.h"
#include "ba2-irq138.h"
typedef struct { const char *name,*exec_ref,*pattern; unsigned length,fixed,line; } Op;
typedef struct { unsigned width,lsb,sign,shift; } Letter;
#include "ba2-opcodes7494.inc"
#include "ba2-decode-index7494.h"
static unsigned startup_compare_kind(const Z6IIBA2Decoded *d) {
    if(!strcmp(d->name,"bn.sfeqi")&&!strcmp(d->exec_reference,"l_sfeq"))return 1;
    if(!strcmp(d->name,"bn.sfnei")&&!strcmp(d->exec_reference,"l_sfne"))return 2;
    if(!strcmp(d->name,"bn.sfgesi")&&!strcmp(d->exec_reference,"l_sfges"))return 3;
    if(!strcmp(d->name,"bn.sfgeui")&&!strcmp(d->exec_reference,"l_sfgeu"))return 4;
    if(!strcmp(d->name,"bn.sfgtsi")&&!strcmp(d->exec_reference,"l_sfgts"))return 5;
    if(!strcmp(d->name,"bn.sfgtui")&&!strcmp(d->exec_reference,"l_sfgtu"))return 6;
    if(!strcmp(d->name,"bn.sflesi")&&!strcmp(d->exec_reference,"l_sfles"))return 7;
    if(!strcmp(d->name,"bn.sfleui")&&!strcmp(d->exec_reference,"l_sfleu"))return 8;
    if(!strcmp(d->name,"bn.sfltsi")&&!strcmp(d->exec_reference,"l_sflts"))return 9;
    if(!strcmp(d->name,"bn.sfltui")&&!strcmp(d->exec_reference,"l_sfltu"))return 10;
    if(!strcmp(d->name,"bn.sfeq")&&!strcmp(d->exec_reference,"l_sfeq"))return 1;
    if(!strcmp(d->name,"bn.sfne")&&!strcmp(d->exec_reference,"l_sfne"))return 2;
    if(!strcmp(d->name,"bn.sfges")&&!strcmp(d->exec_reference,"l_sfges"))return 3;
    if(!strcmp(d->name,"bn.sfgeu")&&!strcmp(d->exec_reference,"l_sfgeu"))return 4;
    if(!strcmp(d->name,"bn.sfgts")&&!strcmp(d->exec_reference,"l_sfgts"))return 5;
    if(!strcmp(d->name,"bn.sfgtu")&&!strcmp(d->exec_reference,"l_sfgtu"))return 6;
    if(!strcmp(d->name,"bw.sfeqi")&&!strcmp(d->exec_reference,"l_sfeq"))return 1;
    if(!strcmp(d->name,"bw.sfnei")&&!strcmp(d->exec_reference,"l_sfne"))return 2;
    if(!strcmp(d->name,"bw.sfgesi")&&!strcmp(d->exec_reference,"l_sfges"))return 3;
    if(!strcmp(d->name,"bw.sfgeui")&&!strcmp(d->exec_reference,"l_sfgeu"))return 4;
    if(!strcmp(d->name,"bw.sfgtsi")&&!strcmp(d->exec_reference,"l_sfgts"))return 5;
    if(!strcmp(d->name,"bw.sfgtui")&&!strcmp(d->exec_reference,"l_sfgtu"))return 6;
    if(!strcmp(d->name,"bw.sflesi")&&!strcmp(d->exec_reference,"l_sfles"))return 7;
    if(!strcmp(d->name,"bw.sfleui")&&!strcmp(d->exec_reference,"l_sfleu"))return 8;
    if(!strcmp(d->name,"bw.sfltsi")&&!strcmp(d->exec_reference,"l_sflts"))return 9;
    if(!strcmp(d->name,"bw.sfltui")&&!strcmp(d->exec_reference,"l_sfltu"))return 10;
    return 0;
}
static uint64_t reverse(uint64_t v,unsigned n) {
    uint64_t o=0;for(unsigned i=0;i<n;i++){o=(o<<1)|(v&1);v>>=1;}return o;
}
static bool match_prefix(const Op *op,const uint8_t raw[6],unsigned have) {
    unsigned bits=(have<op->length?have:op->length)*8;
    for(unsigned i=0;i<bits;i++) {
        char c=op->pattern[i];
        if(c=='0'||c=='1') {
            unsigned bit=(raw[i/8]>>(7-(i%8)))&1;
            if(bit!=(unsigned)(c-'0'))return false;
        }
    }
    return true;
}
static Z6IIBA2CPUResult decode(Z6IIBA2CPU *cpu,Z6IIBA2Decoded *d) {
    memset(d,0,sizeof(*d));d->pc=cpu->pc;
    /* Preserve the original first fetch, opcode priority and short reads. */
    Z6IIBA2BusResult first=cpu->fetch(cpu->bus_opaque,cpu->pc,d->raw,1);
    if(first!=Z6II_BA2_BUS_OK) {
        cpu->bus_result=first;return Z6II_BA2_CPU_BUS_FAULT;
    }
    unsigned have=1;
    unsigned begin=ba2_decode_first_offsets[d->raw[0]];
    unsigned end=ba2_decode_first_offsets[(unsigned)d->raw[0]+1];
    for(;;) {
        const Op *best=NULL;bool partial=false,possible=false;
        for(unsigned i=begin;i<end;i++) {
            const Op *op=&ops[ba2_decode_first_ops[i]];
            if(!match_prefix(op,d->raw,have))continue;
            possible=true;
            if(op->length>have)partial=true;
            else if(!best||op->fixed>best->fixed)best=op;
        }
        if(best&&!partial) {
            d->name=best->name;d->exec_reference=best->exec_ref;
            d->source_line=best->line;d->length=best->length;
            for(unsigned i=0;i<best->length*8;i++) {
                unsigned char c=(unsigned char)best->pattern[i];
                if(c=='0'||c=='1'||c=='-')continue;
                if(c>=128||!letters[c].width)return Z6II_BA2_CPU_UNKNOWN_OPCODE;
                d->field_present[c]=true;
                d->field[c]=(d->field[c]<<1)|((d->raw[i/8]>>(7-(i%8)))&1);
            }
            for(unsigned c=0;c<128;c++) if(d->field_present[c]) {
                const Letter *l=&letters[c];uint64_t v=(uint64_t)d->field[c];
                if(l->lsb)v=reverse(v,l->width);
                int64_t sv=(int64_t)v;
                if(l->sign&&(v>>(l->width-1)))sv-=(INT64_C(1)<<l->width);
                d->field[c]=sv*(INT64_C(1)<<l->shift);
            }
            return Z6II_BA2_CPU_OK;
        }
        if(!possible||have>=6){d->length=have;return Z6II_BA2_CPU_UNKNOWN_OPCODE;}
        uint8_t next=0;Z6IIBA2BusResult r=cpu->fetch(cpu->bus_opaque,cpu->pc+have,&next,1);
        if(r!=Z6II_BA2_BUS_OK) {
            cpu->bus_result=r;d->length=have;return Z6II_BA2_CPU_BUS_FAULT;
        }
        d->raw[have++]=next;
    }
}
Z6IIBA2CPUResult z6ii_ba2_cpu_init(Z6IIBA2CPU *cpu,uint32_t pc,const uint32_t r[32],
    const char *basis,Z6IIBA2FetchFn fetch,Z6IIBA2ReadFn read,Z6IIBA2WriteFn write,
    Z6IIBA2IRQFn irq,void *opaque) {
    if(!cpu||!r||!basis||!basis[0]||!fetch)return Z6II_BA2_CPU_BAD_CONFIG;
    memset(cpu,0,sizeof(*cpu));memcpy(cpu->r,r,sizeof(cpu->r));cpu->pc=pc;
    cpu->reset_basis=basis;cpu->fetch=fetch;cpu->read=read;cpu->write=write;
    cpu->irq=irq;cpu->bus_opaque=opaque;return Z6II_BA2_CPU_OK;
}
void z6ii_ba2_cpu_set_spr_callbacks(Z6IIBA2CPU *cpu,Z6IIBA2SPRReadFn r,
    Z6IIBA2SPRWriteFn w,void *opaque) {
    if(!cpu)return;cpu->spr_read=r;cpu->spr_write=w;cpu->spr_opaque=opaque;
}
Z6IIBA2CPUResult z6ii_ba2_cpu_enable_entri4_candidate(Z6IIBA2CPU *cpu,
    Z6IIBA2RAMBatchWriteFn write,void *opaque,const char *basis) {
    if(!cpu||!write||!basis||!basis[0])return Z6II_BA2_CPU_BAD_CONFIG;
    cpu->entri4_atomic_write=write;cpu->entri4_opaque=opaque;cpu->entri4_basis=basis;
    return Z6II_BA2_CPU_OK;
}
Z6IIBA2CPUResult z6ii_ba2_cpu_enable_entri1n1_candidate(Z6IIBA2CPU *cpu,
    Z6IIBA2RAMBatchWriteFn write,void *opaque,const char *basis) {
    if(!cpu||!write||!basis||!basis[0])return Z6II_BA2_CPU_BAD_CONFIG;
    cpu->entri1n1_atomic_write=write;cpu->entri1n1_opaque=opaque;
    cpu->entri1n1_basis=basis;return Z6II_BA2_CPU_OK;
}
Z6IIBA2CPUResult z6ii_ba2_cpu_enable_entri1n_candidate(Z6IIBA2CPU *cpu,
    Z6IIBA2RAMBatchWriteFn write,void *opaque,const char *basis) {
    if(!cpu||!write||!basis||!basis[0])return Z6II_BA2_CPU_BAD_CONFIG;
    cpu->entri1n_atomic_write=write;cpu->entri1n_opaque=opaque;
    cpu->entri1n_basis=basis;return Z6II_BA2_CPU_OK;
}
Z6IIBA2CPUResult z6ii_ba2_cpu_enable_jr9_candidate(Z6IIBA2CPU *cpu,const char *basis) {
    if(!cpu||!basis||!basis[0])return Z6II_BA2_CPU_BAD_CONFIG;
    cpu->jr9_basis=basis;return Z6II_BA2_CPU_OK;
}
Z6IIBA2CPUResult z6ii_ba2_cpu_enable_reti1n1_candidate(Z6IIBA2CPU *cpu,
    Z6IIBA2RAMRead32Fn read,void *opaque,const char *basis) {
    if(!cpu||!read||!basis||!basis[0])return Z6II_BA2_CPU_BAD_CONFIG;
    cpu->reti1n1_ram_read=read;cpu->reti1n1_opaque=opaque;
    cpu->reti1n1_basis=basis;return Z6II_BA2_CPU_OK;
}
Z6IIBA2CPUResult z6ii_ba2_cpu_enable_startup_isa_candidate(Z6IIBA2CPU *cpu,
    Z6IIBA2RAMBatchReadFn read,void *opaque,const char *basis) {
    if(!cpu||!read||!basis||!basis[0])return Z6II_BA2_CPU_BAD_CONFIG;
    cpu->startup_isa_ram_read=read;cpu->startup_isa_opaque=opaque;
    cpu->startup_isa_basis=basis;return Z6II_BA2_CPU_OK;
}
Z6IIBA2CPUResult z6ii_ba2_cpu_set_startup_irq_mask_snapshot(Z6IIBA2CPU *cpu,
    bool enabled,const char *basis) {
    if(!cpu||!basis||!basis[0]||!cpu->startup_isa_basis||!cpu->startup_isa_basis[0])
        return Z6II_BA2_CPU_BAD_CONFIG;
    cpu->startup_irq_enabled=enabled;cpu->startup_irq_mask_known=true;
    cpu->startup_irq_reset_basis=basis;return Z6II_BA2_CPU_OK;
}
Z6IIBA2CPUResult z6ii_ba2_cpu_enable_divu_candidate(Z6IIBA2CPU *cpu,const char *basis) {
    if(!cpu||!basis||!basis[0])return Z6II_BA2_CPU_BAD_CONFIG;
    cpu->divu_basis=basis;return Z6II_BA2_CPU_OK;
}
Z6IIBA2CPUResult z6ii_ba2_cpu_enable_movi_d7g3_candidate(Z6IIBA2CPU *cpu,const char *basis) {
    if(!cpu||!basis||!basis[0])return Z6II_BA2_CPU_BAD_CONFIG;
    cpu->movi_d7g3_basis=basis;return Z6II_BA2_CPU_OK;
}
Z6IIBA2CPUResult z6ii_ba2_cpu_enable_movi_nontrap_candidate(Z6IIBA2CPU *cpu,const char *basis) {
    if(!cpu||!basis||!basis[0])return Z6II_BA2_CPU_BAD_CONFIG;
    cpu->movi_nontrap_basis=basis;return Z6II_BA2_CPU_OK;
}
static bool ordinary_bitwise(Z6IIBA2CPU *cpu,const Z6IIBA2Decoded *d,uint32_t *value,unsigned *dst) {
    if(!d->field_present['D']||!d->field_present['A'])return false;
    unsigned a=(unsigned)d->field['A'];*dst=(unsigned)d->field['D'];
    if(a>=32||*dst>=32)return false;
    uint32_t rhs=0;
    if(d->field_present['B']) {
        unsigned b=(unsigned)d->field['B'];if(b>=32)return false;rhs=cpu->r[b];
    } else if(d->field_present['h'])rhs=(uint32_t)d->field['h'];
    else if(d->field_present['N'])rhs=(uint32_t)d->field['N'];
    else return false;
    *value=!strcmp(d->exec_reference,"l_or")?(cpu->r[a]|rhs):(cpu->r[a]&rhs);
    return true;
}

Z6IIBA2CPUResult z6ii_ba2_cpu_enable_mov_gpr_candidate(Z6IIBA2CPU *cpu,const char *basis) {
    if(!cpu||!basis||!basis[0])return Z6II_BA2_CPU_BAD_CONFIG;
    cpu->mov_gpr_basis=basis;return Z6II_BA2_CPU_OK;
}
Z6IIBA2CPUResult z6ii_ba2_cpu_enable_msw_c0_candidate(Z6IIBA2CPU *cpu,
    Z6IIBA2RAMBatchWriteFn write,void *opaque,const char *basis) {
    if(!cpu||!write||!basis||!basis[0])return Z6II_BA2_CPU_BAD_CONFIG;
    cpu->msw_c0_atomic_write=write;cpu->msw_c0_opaque=opaque;
    cpu->msw_c0_basis=basis;return Z6II_BA2_CPU_OK;
}
Z6IIBA2CPUResult z6ii_ba2_cpu_enable_mlwz_c0_candidate(Z6IIBA2CPU *cpu,
    Z6IIBA2RAMBatchReadFn read,void *opaque,const char *basis) {
    if(!cpu||!read||!basis||!basis[0])return Z6II_BA2_CPU_BAD_CONFIG;
    cpu->mlwz_c0_atomic_read=read;cpu->mlwz_c0_opaque=opaque;
    cpu->mlwz_c0_basis=basis;return Z6II_BA2_CPU_OK;
}

Z6IIBA2CPUResult z6ii_ba2_cpu_enable_sub_subb_pair_candidate(Z6IIBA2CPU *cpu,
    const char *basis) {
    if(!cpu||!basis||!basis[0])return Z6II_BA2_CPU_BAD_CONFIG;
    cpu->sub_subb_pair_basis=basis;
    cpu->sub_subb_pair_pending=false; /* New provenance never inherits an old pair. */
    return Z6II_BA2_CPU_OK;
}

Z6IIBA2CPUResult z6ii_ba2_cpu_enable_sub_subb_pair2_candidate(Z6IIBA2CPU *cpu,
    const char *basis) {
    if(!cpu||!basis||!basis[0])return Z6II_BA2_CPU_BAD_CONFIG;
    cpu->sub_subb_pair2_basis=basis;
    cpu->sub_subb_pair2_pending=false;
    return Z6II_BA2_CPU_OK;
}

Z6IIBA2CPUResult z6ii_ba2_cpu_enable_bt_add_gpr_candidate(Z6IIBA2CPU *cpu,
    const char *basis) {
    if(!cpu||!basis||!basis[0])return Z6II_BA2_CPU_BAD_CONFIG;
    cpu->bt_add_gpr_basis=basis;return Z6II_BA2_CPU_OK;
}
Z6IIBA2CPUResult z6ii_ba2_cpu_enable_bt_add_bn_addc_pair_candidate(Z6IIBA2CPU *cpu,
    const char *basis) {
    if(!cpu||!basis||!basis[0])return Z6II_BA2_CPU_BAD_CONFIG;
    cpu->bt_add_bn_addc_pair_basis=basis;
    cpu->bt_add_bn_addc_pair_pending=false;
    cpu->bt_add_bn_addc_pair_carry_known=false;
    return Z6II_BA2_CPU_OK;
}
static bool register_field(const Z6IIBA2Decoded *d,unsigned key,unsigned *out) {
    if(!d->field_present[key]||d->field[key]<0||d->field[key]>=32)return false;
    *out=(unsigned)d->field[key];return true;
}
static bool one_immediate(const Z6IIBA2Decoded *d,const char *keys,uint32_t *out) {
    bool found=false;
    for(const char *p=keys;*p;p++)if(d->field_present[(unsigned char)*p]) {
        if(found)return false;
        *out=(uint32_t)d->field[(unsigned char)*p];found=true;
    }
    return found;
}
static bool ordinary_addi(const Z6IIBA2CPU *cpu,const Z6IIBA2Decoded *d,
                          uint32_t *value,unsigned *dst) {
    if(!register_field(d,'D',dst))return false;
    unsigned src=*dst;uint32_t immediate;
    if(!strcmp(d->name,"bt.addi")&&!strcmp(d->exec_reference,"bt_add")) {
        if(d->field_present['A']||!one_immediate(d,"G",&immediate))return false;
    } else if(!strcmp(d->exec_reference,"b_add")&&
              (!strcmp(d->name,"bn.addi")||!strcmp(d->name,"bg.addi")||
               !strcmp(d->name,"bw.addi"))) {
        if(!register_field(d,'A',&src)||!one_immediate(d,"OYg",&immediate))return false;
    } else return false;
    *value=cpu->r[src]+immediate;return true;
}

static bool ordinary_bn_sub(const Z6IIBA2CPU *cpu,const Z6IIBA2Decoded *d,
                            uint32_t *value,unsigned *dst) {
    /* GNU line228 proves three register5 fields; public ESIL line777 gives
     * rB,rA,-,rD,= (rA-rB). Both old inputs stage before any aliased commit.
     * uint32 wrap/r0 ordinary storage/unchanged flags/next-fetch timing are
     * model policy; public carry/overflow remains TODO. No subb/subs fallback. */
    unsigned a,b;
    if(strcmp(d->name,"bn.sub")||strcmp(d->exec_reference,"b_sub")||
       d->length!=3||!register_field(d,'D',dst)||
       !register_field(d,'A',&a)||!register_field(d,'B',&b))return false;
    uint32_t lhs=cpu->r[a],rhs=cpu->r[b];
    *value=lhs-rhs;return true;
}

static bool ordinary_memory(const Z6IIBA2CPU *cpu,const Z6IIBA2Decoded *d,
                            bool load,uint32_t *address,unsigned *reg) {
    unsigned base;uint32_t offset;
    if(!register_field(d,'A',&base)||!register_field(d,load?'D':'B',reg)||
       !one_immediate(d,"KWw",&offset))return false;
    *address=cpu->r[base]+offset;return true;
}
static bool register_bgtu(const Z6IIBA2CPU *cpu,const Z6IIBA2Decoded *d,
                         uint32_t *next) {
    unsigned a,b;uint32_t displacement;
    if(strcmp(d->exec_reference,"b_bgtu")||
       (strcmp(d->name,"bg.bgtu")&&strcmp(d->name,"bw.bgtu"))||
       !register_field(d,'A',&a)||!register_field(d,'B',&b)||
       !one_immediate(d,"Uu",&displacement))return false;
    if(cpu->r[a]>cpu->r[b])*next=cpu->pc+displacement;
    return true;
}

Z6IIBA2CPUResult z6ii_ba2_cpu_enable_bg_beq_gpr_candidate(Z6IIBA2CPU *cpu,
    const char *basis) {
    if(!cpu||!basis||!basis[0])return Z6II_BA2_CPU_BAD_CONFIG;
    cpu->bg_beq_gpr_basis=basis;return Z6II_BA2_CPU_OK;
}

static bool register_bg_beq_gpr_candidate(const Z6IIBA2CPU *cpu,
        const Z6IIBA2Decoded *d,uint32_t *next) {
    /* Fixed GNU line413/A/B/U proves encoding; fixed public execution compares
     * caller GPR values directly. No other b_beq form is inferred. */
    unsigned a,b;
    if(!cpu->bg_beq_gpr_basis||!cpu->bg_beq_gpr_basis[0]||
       strcmp(d->name,"bg.beq")||strcmp(d->exec_reference,"b_beq")||
       d->length!=4||!register_field(d,'A',&a)||!register_field(d,'B',&b)||
       !d->field_present['U']||d->field['U']<-2048||d->field['U']>2047)
        return false;
    if(cpu->r[a]==cpu->r[b])*next=cpu->pc+(uint32_t)d->field['U'];
    /* uint32 wrap, snapshot flags and next-fetch checks are model policy.
     * The unchanged common tail still invalidates existing pending pairs. */
    return true;
}

Z6IIBA2CPUResult z6ii_ba2_cpu_enable_bg_bgeu_gpr_candidate(Z6IIBA2CPU *cpu,
    const char *basis) {
    if(!cpu||!basis||!basis[0])return Z6II_BA2_CPU_BAD_CONFIG;
    cpu->bg_bgeu_gpr_basis=basis;return Z6II_BA2_CPU_OK;
}

static bool register_bg_bgeu_gpr_candidate(const Z6IIBA2CPU *cpu,
        const Z6IIBA2Decoded *d,uint32_t *next) {
    /* Fixed GNU line417/A/B/U proves encoding; fixed public execution compares
     * caller GPR values with >=; public ESIL engine context is retained as
     * evidence, not executed here. uint32 comparison is explicit model policy.
     * No other b_bgeu form is inferred. */
    unsigned a,b;
    if(!cpu->bg_bgeu_gpr_basis||!cpu->bg_bgeu_gpr_basis[0]||
       strcmp(d->name,"bg.bgeu")||strcmp(d->exec_reference,"b_bgeu")||
       d->length!=4||!register_field(d,'A',&a)||!register_field(d,'B',&b)||
       !d->field_present['U']||d->field['U']<-2048||d->field['U']>2047)
        return false;
    if(cpu->r[a]>=cpu->r[b])*next=cpu->pc+(uint32_t)d->field['U'];
    /* uint32 wrap, snapshot flags and next-fetch checks are model policy.
     * The unchanged common tail still invalidates existing pending pairs. */
    return true;
}

static bool register_bg_bne(const Z6IIBA2CPU *cpu,const Z6IIBA2Decoded *d,
                            uint32_t *next) {
    /* GNU line414 and A/B/U descriptors prove two 5-bit registers and signed12
     * PC-relative LSB-swizzled U. Public decoder/ESIL compares raw GPR values.
     * No flag dependency or other b_bne family is inferred. */
    unsigned a,b;
    if(strcmp(d->name,"bg.bne")||strcmp(d->exec_reference,"b_bne")||
       d->length!=4||!register_field(d,'A',&a)||!register_field(d,'B',&b)||
       !d->field_present['U']||d->field['U']<-2048||d->field['U']>2047)
        return false;
    if(cpu->r[a]!=cpu->r[b])*next=cpu->pc+(uint32_t)d->field['U'];
    /* uint32 wrap, unchanged flags/GPRs and next-step target fetch are explicit
     * model policy; silicon exception/IRQ/timing semantics are unverified. */
    return true;
}

Z6IIBA2CPUResult z6ii_ba2_cpu_step(Z6IIBA2CPU *cpu) {
    if(!cpu||!cpu->fetch)return Z6II_BA2_CPU_BAD_CONFIG;
    if(cpu->halted!=Z6II_BA2_CPU_OK)return cpu->halted;
    if(cpu->startup_irq138) {
        Z6IIBA2CPUResult irq_result=z6ii_ba2_irq138_poll(cpu);
        if(irq_result!=Z6II_BA2_CPU_OK) {cpu->halted=irq_result;return irq_result;}
    } else if(cpu->irq&&cpu->irq(cpu->bus_opaque)) {
        cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_IRQ;return cpu->halted;
    }
    cpu->last_spr_access=false;
    Z6IIBA2Decoded d;Z6IIBA2CPUResult r=decode(cpu,&d);cpu->last=d;
    if(r!=Z6II_BA2_CPU_OK){cpu->halted=r;return r;}
    uint32_t next=cpu->pc+d.length,value=0;unsigned dst=0;
    bool pair_produced=false;
    bool pair2_produced=false;
    bool add_pair_produced=false;
    if(!strcmp(d.exec_reference,"b_j")||!strcmp(d.exec_reference,"b_jal")) {
        bool rel=false;
        for(unsigned c=0;c<128;c++)if(d.field_present[c]&&relative[c]){
            if(rel){cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;}
            next=cpu->pc+(uint32_t)d.field[c];rel=true;
        }
        if(!rel){cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;}
        if(!strcmp(d.exec_reference,"b_jal"))cpu->r[9]=cpu->pc+d.length;
    } else if(!strcmp(d.name,"bn.return")&&!strcmp(d.exec_reference,"b_return")) {
        /* ABI/control-flow-supported LR9 candidate. No stack adjustment or
         * low-bit masking. The next fetch verifies the resulting mapping. */
        next=cpu->r[9];
    } else if(!strcmp(d.name,"bn.jr")&&!strcmp(d.exec_reference,"b_jr")) {
        /* Only original-stop A=r9, with independent opt-in. GNU proves encoding;
         * public old decoder explicitly assigns rA to PC. Do not infer jalr,
         * stack/flag effects, low-bit masking or target exception semantics. */
        unsigned a;
        if(!register_field(&d,'A',&a)||a!=9||!cpu->jr9_basis||!cpu->jr9_basis[0]) {
            cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;
        }
        next=cpu->r[9]; /* This jump retires; only the next fetch checks the target. */
    } else if(!strcmp(d.name,"bn.entri")&&!strcmp(d.exec_reference,"l_entri")) {
        /* Independent single-LR family from GNU F/N encoding and public
         * software's predecrement/N-word rule. One RAM-only atomic write avoids
         * widening the callback contract. Reserve locals without writing them;
         * other state/flags preservation is policy, not silicon certification. */
        if(cpu->startup_isa_basis&&cpu->startup_isa_basis[0]&&
           cpu->entri4_atomic_write&&cpu->entri4_basis&&cpu->entri4_basis[0]&&
           d.length==3&&d.field_present['F']&&d.field['F']>=0&&d.field['F']<=15&&
           d.field_present['N']&&d.field['N']>=0&&d.field['N']<=255) {
            /* GNU full F/N domain + public predecrement loop, opt-in software
             * policy. Full saved group is one RAM-only validated transaction;
             * locals reserve address space without writes. F0 saves no GPR. */
            unsigned f=(unsigned)d.field['F'];
            uint32_t frame=4*((uint32_t)d.field['N']+f);
            if(cpu->r[1]<frame) {
                cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;
            }
            uint32_t addresses[15],values[15];
            for(unsigned i=0;i<f;i++) {
                addresses[i]=cpu->r[1]-4*(i+1);values[i]=cpu->r[9+i];
            }
            if(f) {
                Z6IIBA2BusResult br=cpu->entri4_atomic_write(
                    cpu->entri4_opaque,addresses,values,f);cpu->bus_result=br;
                if(br!=Z6II_BA2_BUS_OK) {
                    cpu->halted=Z6II_BA2_CPU_BUS_FAULT;return cpu->halted;
                }
            }
            cpu->r[1]-=frame;
        } else
        if(d.length==3&&d.field_present['F']&&d.field_present['N']&&
           d.field['F']==1&&d.field['N']>=0&&d.field['N']<=255&&
           cpu->entri1n_atomic_write&&cpu->entri1n_basis&&cpu->entri1n_basis[0]) {
            uint32_t frame=4*((uint32_t)d.field['N']+1);
            if(cpu->r[1]<frame) {
                cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;
            }
            uint32_t address=cpu->r[1]-4,value_saved=cpu->r[9];
            Z6IIBA2BusResult br=cpu->entri1n_atomic_write(
                cpu->entri1n_opaque,&address,&value_saved,1);
            cpu->bus_result=br;
            if(br!=Z6II_BA2_BUS_OK) {
                cpu->halted=Z6II_BA2_CPU_BUS_FAULT;return cpu->halted;
            }
            cpu->r[1]-=frame;
        } else
        /* Narrow F1/N1 addition: original D36E fields/body + old TODO N*4.
         * The single saved LR is ordinary RAM; the local word is reserved only,
         * never initialized. Atomic callback failure cannot retire or change SP.
         * Ordinary reti has a separate opt-in; rtnei/IRQ and other entries stop. */
        if(d.field_present['F']&&d.field_present['N']&&
           d.field['F']==1&&d.field['N']==1) {
            if(!cpu->entri1n1_atomic_write||!cpu->entri1n1_basis||
               !cpu->entri1n1_basis[0]||cpu->r[1]<8) {
                cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;
            }
            uint32_t address=cpu->r[1]-4,value_saved=cpu->r[9];
            Z6IIBA2BusResult br=cpu->entri1n1_atomic_write(
                cpu->entri1n1_opaque,&address,&value_saved,1);
            cpu->bus_result=br;
            if(br!=Z6II_BA2_BUS_OK) {
                cpu->halted=Z6II_BA2_CPU_BUS_FAULT;return cpu->halted;
            }
            cpu->r[1]-=8;
        } else {
            /* Only the first reset-path shape F4/N0 is admitted, by explicit opt-in.
             * The fixed GNU table establishes fields, not push execution.
             * This candidate is based on the original ABI/control flow plus the
             * old decoder's explicit prologue rule; other shapes remain unknown. */
            if(!d.field_present['F']||!d.field_present['N']||
               d.field['F']!=4||d.field['N']!=0||!cpu->entri4_atomic_write||
               !cpu->entri4_basis||!cpu->entri4_basis[0]||cpu->r[1]<16) {
                cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;
            }
            uint32_t addresses[4],values[4];
            for(unsigned i=0;i<4;i++){addresses[i]=cpu->r[1]-4*(i+1);values[i]=cpu->r[9+i];}
            Z6IIBA2BusResult br=cpu->entri4_atomic_write(cpu->entri4_opaque,addresses,values,4);
            cpu->bus_result=br;
            if(br!=Z6II_BA2_BUS_OK) {
                cpu->halted=Z6II_BA2_CPU_BUS_FAULT;return cpu->halted;
            }
            cpu->r[1]-=16;
        }
    } else if((!strcmp(d.name,"bn.reti")&&!strcmp(d.exec_reference,"b_reti"))||
              (!strcmp(d.name,"bn.rtnei")&&!strcmp(d.exec_reference,"l_rtnei"))) {
        bool return_enable=!strcmp(d.exec_reference,"l_rtnei");
        if(cpu->startup_isa_basis&&cpu->startup_isa_basis[0]&&
           cpu->startup_isa_ram_read&&d.length==3&&d.field_present['F']&&
           d.field_present['N']&&d.field['N']>=0&&d.field['N']<=255&&
           d.field['F']>=0&&d.field['F']<=15) {
            unsigned f=(unsigned)d.field['F'];
            uint32_t n=(uint32_t)d.field['N'],sp=cpu->r[1];
            uint32_t frame=4*(n+f),addresses[15],values[15]={0};
            if(sp>UINT32_MAX-frame) {
                cpu->bus_result=Z6II_BA2_BUS_UNMAPPED;
                cpu->halted=Z6II_BA2_CPU_BUS_FAULT;return cpu->halted;
            }
            for(unsigned i=0;i<f;i++)addresses[i]=sp+4*(n+i);
            if(f) {
                Z6IIBA2BusResult br=cpu->startup_isa_ram_read(
                    cpu->startup_isa_opaque,addresses,values,f);
                cpu->bus_result=br;
                if(br!=Z6II_BA2_BUS_OK) {
                    cpu->halted=Z6II_BA2_CPU_BUS_FAULT;return cpu->halted;
                }
            }
            for(unsigned i=0;i<f;i++)cpu->r[9+f-1-i]=values[i];
            cpu->r[1]=sp+frame;
            if(!return_enable)next=cpu->r[9];
            if(return_enable) {
                /* Candidate GNU/ROM tail-call contract: rtnei restores the
                 * frame and locally enables IRQ, then continues at PC+3.
                 * Original kernel init uses rtnei followed by j to create idle.
                 * It does not perform reti's LR branch. Atomic RAM failure
                 * precedes all GPR/SP/EI commits. Silicon semantics unverified. */
                cpu->startup_irq_enabled=true;cpu->startup_irq_mask_known=true;
            }
        } else {
        /* GNU establishes F/N and opcode length. This is only the inverse of
         * the explicit entri F1/N1 software stack model, never IRQ/status return.
         * All failing guards/reads precede guest GPR/PC/retired commits. */
        if(return_enable||!d.field_present['F']||!d.field_present['N']||
           d.field['F']!=1||d.field['N']!=1||!cpu->reti1n1_ram_read||
           !cpu->reti1n1_basis||!cpu->reti1n1_basis[0]) {
            cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;
        }
        uint32_t sp=cpu->r[1],lr=0;
        if(sp>UINT32_MAX-8) {
            cpu->bus_result=Z6II_BA2_BUS_UNMAPPED;
            cpu->halted=Z6II_BA2_CPU_BUS_FAULT;return cpu->halted;
        }
        Z6IIBA2BusResult br=cpu->reti1n1_ram_read(cpu->reti1n1_opaque,sp+4,&lr);
        cpu->bus_result=br;
        if(br!=Z6II_BA2_BUS_OK) {
            cpu->halted=Z6II_BA2_CPU_BUS_FAULT;return cpu->halted;
        }
        cpu->r[9]=lr;cpu->r[1]=sp+8;
        next=lr; /* No mask/prefetch: the next step checks target mapping. */
        }
    } else if((!strcmp(d.name,"bn.divu")||!strcmp(d.name,"bw.divui"))&&
              !strcmp(d.exec_reference,"l_divu")) {
        /* GNU unsigned family: 3-byte D/A/B or 6-byte D/A/unsigned24 o.
         * Explicit startup software quotient; old D3/A3/B7 gate stays separate.
         * Nonzero inputs only. Zero-divisor traps, flags and latency unverified. */
        unsigned dst_div,lhs_reg,rhs_reg=0;
        bool immediate=!strcmp(d.name,"bw.divui");
        bool startup=cpu->startup_isa_basis&&cpu->startup_isa_basis[0];
        if(!register_field(&d,'D',&dst_div)||!register_field(&d,'A',&lhs_reg)||
           (immediate?(d.length!=6||!d.field_present['o']||
                       d.field['o']<0||d.field['o']>0xffffff):
                      (d.length!=3||!register_field(&d,'B',&rhs_reg)))||
           (!startup&&(immediate||dst_div!=3||lhs_reg!=3||rhs_reg!=7||
                       !cpu->divu_basis||!cpu->divu_basis[0]))) {
            cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;
        }
        uint32_t lhs=cpu->r[lhs_reg];
        uint32_t rhs=immediate?(uint32_t)d.field['o']:cpu->r[rhs_reg];
        if(!rhs) {
            cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;
        }
        cpu->r[dst_div]=lhs/rhs; /* Stage old inputs before D=A/B aliases. */
    } else if(!strcmp(d.name,"bn.addc")&&!strcmp(d.exec_reference,"b_addc")) {
        const uint8_t original_addc[3]={0x67,0x39,0x3f};
        if(!cpu->bt_add_bn_addc_pair_basis||!cpu->bt_add_bn_addc_pair_basis[0]||
           !cpu->bt_add_bn_addc_pair_pending||!cpu->bt_add_bn_addc_pair_carry_known||
           cpu->pc!=UINT32_C(0x4000d8f0)||d.length!=3||
           memcmp(d.raw,original_addc,3)||!d.field_present['D']||d.field['D']!=25||
           !d.field_present['A']||d.field['A']!=25||
           !d.field_present['B']||d.field['B']!=7||
           cpu->bt_add_bn_addc_pair_next_pc!=cpu->pc||
           cpu->bt_add_bn_addc_pair_next_retired!=cpu->retired) {
            cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;
        }
        uint32_t lhs=cpu->r[25],rhs=cpu->r[7];
        uint32_t carry=cpu->bt_add_bn_addc_pair_carry?1u:0u;
        cpu->r[25]=lhs+rhs+carry; /* Old aliased A=D is staged; uint32 wrap. */
        cpu->bt_add_bn_addc_pair_pending=false;
        cpu->bt_add_bn_addc_pair_carry_known=false;
    } else if(!strcmp(d.name,"bn.subb")&&!strcmp(d.exec_reference,"b_subb")&&
              cpu->pc==UINT32_C(0x4000d8e2)) {
        const uint8_t original2[3]={0x68,0xe7,0x28};
        if(!cpu->sub_subb_pair2_basis||!cpu->sub_subb_pair2_basis[0]||
           !cpu->sub_subb_pair2_pending||!cpu->flag_known||d.length!=3||
           memcmp(d.raw,original2,3)||!d.field_present['D']||d.field['D']!=7||
           !d.field_present['A']||d.field['A']!=7||
           !d.field_present['B']||d.field['B']!=5||
           cpu->sub_subb_pair2_next_pc!=cpu->pc||
           cpu->sub_subb_pair2_next_retired!=cpu->retired) {
            cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;
        }
        uint32_t lhs=cpu->r[7],rhs=cpu->r[5],borrow=cpu->flag?1u:0u;
        cpu->r[7]=lhs-rhs-borrow;
        cpu->sub_subb_pair2_pending=false;cpu->flag_known=false;
    } else if(!strcmp(d.name,"bn.subb")&&!strcmp(d.exec_reference,"b_subb")) {
        /* Exact paired-dataflow candidate; no generic carry/borrow assumption. */
        const uint8_t original[3]={0x68,0xe7,0xc8};
        if(!cpu->sub_subb_pair_basis||!cpu->sub_subb_pair_basis[0]||
           !cpu->sub_subb_pair_pending||!cpu->flag_known||
           cpu->pc!=UINT32_C(0x4000d8dc)||d.length!=3||
           memcmp(d.raw,original,3)||!d.field_present['D']||d.field['D']!=7||
           !d.field_present['A']||d.field['A']!=7||
           !d.field_present['B']||d.field['B']!=25||
           cpu->sub_subb_pair_next_pc!=cpu->pc||
           cpu->sub_subb_pair_next_retired!=cpu->retired) {
            cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;
        }
        uint32_t lhs=cpu->r[7],rhs=cpu->r[25],borrow=cpu->flag?1u:0u;
        cpu->r[7]=lhs-rhs-borrow; /* uint32 wrap; old aliased r7 staged first. */
        cpu->sub_subb_pair_pending=false;cpu->flag_known=false;
    } else if((!strcmp(d.name,"bn.mlwz")&&!strcmp(d.exec_reference,"b_mlwz"))||
              (!strcmp(d.name,"bn.msw")&&!strcmp(d.exec_reference,"b_msw"))) {
        /* GNU fields only. Counts {2,3,4,8} for C0..3 are inferred from the
         * original BD42 task frame and independent BD63 IRQ slot layout.
         * This explicit startup software policy is not silicon proof.
         * Legacy, non-startup execution remains strictly C0/two-word. */
        bool load=!strcmp(d.name,"bn.mlwz");
        bool full=cpu->startup_isa_basis&&cpu->startup_isa_basis[0];
        unsigned base_reg,first_reg;
        if(d.length!=3||!register_field(&d,'A',&base_reg)||
           !register_field(&d,load?'D':'B',&first_reg)||
           !d.field_present['C']||d.field['C']<0||d.field['C']>3||
           (!full&&d.field['C']!=0)||
           !d.field_present['K']||d.field['K']<0||d.field['K']>252||
           (d.field['K']&3)||
           (load?(!cpu->mlwz_c0_atomic_read||!cpu->mlwz_c0_basis||!cpu->mlwz_c0_basis[0]):
                 (!cpu->msw_c0_atomic_write||!cpu->msw_c0_basis||!cpu->msw_c0_basis[0]))) {
            cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;
        }
        static const unsigned counts[4]={2,3,4,8};
        unsigned count=counts[(unsigned)d.field['C']];
        if(first_reg+count>32) {
            cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;
        }
        uint64_t start=(uint64_t)cpu->r[base_reg]+(uint32_t)d.field['K'];
        if(start+4*count-1>UINT32_MAX) {
            cpu->bus_result=Z6II_BA2_BUS_UNMAPPED;
            cpu->halted=Z6II_BA2_CPU_BUS_FAULT;return cpu->halted;
        }
        uint32_t addresses[8],values[8]={0};
        for(unsigned i=0;i<count;i++) {
            addresses[i]=(uint32_t)start+4*i;
            if(!load)values[i]=cpu->r[first_reg+i];
        }
        Z6IIBA2BusResult br=load?
            cpu->mlwz_c0_atomic_read(cpu->mlwz_c0_opaque,addresses,values,count):
            cpu->msw_c0_atomic_write(cpu->msw_c0_opaque,addresses,values,count);
        cpu->bus_result=br;
        if(br!=Z6II_BA2_BUS_OK) {
            cpu->halted=Z6II_BA2_CPU_BUS_FAULT;return cpu->halted;
        }
        /* All load values staged before aliased base/destination commit. */
        if(load)for(unsigned i=0;i<count;i++)cpu->r[first_reg+i]=values[i];
    } else if(!strcmp(d.name,"bt.add")&&!strcmp(d.exec_reference,"bt_add")&&
              cpu->bt_add_bn_addc_pair_basis&&cpu->bt_add_bn_addc_pair_basis[0]&&
              cpu->pc==UINT32_C(0x4000d8ee)&&d.length==2&&
              d.raw[0]==0x0b&&d.raw[1]==0x06&&
              d.field_present['D']&&d.field['D']==24&&
              d.field_present['A']&&d.field['A']==6) {
        /* Exact firmware-pair policy: public software proves only ordinary add.
         * bit32 carry and its addc use remain explicitly silicon-unverified. */
        uint32_t lhs=cpu->r[24],rhs=cpu->r[6];
        uint64_t sum=(uint64_t)lhs+(uint64_t)rhs;
        cpu->r[24]=(uint32_t)sum;
        cpu->bt_add_bn_addc_pair_carry=(sum>>32)!=0;
        cpu->bt_add_bn_addc_pair_carry_known=true;
        cpu->bt_add_bn_addc_pair_pending=true;
        cpu->bt_add_bn_addc_pair_next_pc=next;
        cpu->bt_add_bn_addc_pair_next_retired=cpu->retired+1;
        add_pair_produced=true;
    } else if(!strcmp(d.name,"bt.add")&&!strcmp(d.exec_reference,"bt_add")) {
        /* GNU encoding + fixed public ESIL ordinary-GPR addition candidate.
         * Stage aliased old inputs; no flag/carry or device effect is inferred.
         * D0 and all other add forms remain outside this independent opt-in. */
        unsigned add_dst,add_src;
        if(d.length!=2||!register_field(&d,'D',&add_dst)||add_dst==0||
           !register_field(&d,'A',&add_src)||
           !cpu->bt_add_gpr_basis||!cpu->bt_add_gpr_basis[0]) {
            cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;
        }
        uint32_t lhs=cpu->r[add_dst],rhs=cpu->r[add_src];
        cpu->r[add_dst]=lhs+rhs;
    } else if(!strcmp(d.name,"bt.mov")&&!strcmp(d.exec_reference,"b_mov")&&
              d.length==2&&d.raw[0]==0x04&&d.raw[1]==0x00&&cpu->startup_irq138) {
        Z6IIBA2CPUResult rfe_result=z6ii_ba2_irq138_rfe(cpu,&next);
        if(rfe_result!=Z6II_BA2_CPU_OK) {cpu->halted=rfe_result;return rfe_result;}
    } else if(!strcmp(d.name,"bt.mov")&&!strcmp(d.exec_reference,"b_mov")&&
              d.length==2&&d.raw[0]==0x04&&(d.raw[1]==0x01||d.raw[1]==0x02)&&
              cpu->startup_isa_basis&&cpu->startup_isa_basis[0]) {
        /* GNU aliases and the public decoder establish EI/DI identity. The
         * explicitly enabled model records local mask state, not SPR11 bits,
         * silicon timing, pending priority, exception entry or FIFO activity.
         * External nonzero IRQ queries remain hard-stop at step entry. */
        cpu->startup_irq_enabled=d.raw[1]==0x01;
        cpu->startup_irq_mask_known=true;
    } else if(!strcmp(d.name,"bt.mov")&&!strcmp(d.exec_reference,"b_mov")) {
        /* GNU gives the two 5-bit register fields; public ESIL stages A to D.
         * D0 remains reserved here; exact EI/DI require the separate startup branch.
         * No special SP/LR effects or hardwired r0 are inferred. */
        unsigned mov_dst,mov_src;
        if(d.length!=2||!register_field(&d,'D',&mov_dst)||mov_dst==0||
           !register_field(&d,'A',&mov_src)||
           !cpu->mov_gpr_basis||!cpu->mov_gpr_basis[0]) {
            cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;
        }
        uint32_t source=cpu->r[mov_src];
        cpu->r[mov_dst]=source; /* Stage before commit, including D=A. */
    } else if(!strcmp(d.name,"bt.movi")&&!strcmp(d.exec_reference,"b_movi")) {
        /* GNU proves D width5 and signed4 G with LSB swizzle/shift0.
         * Public ordinary assignment excludes the earlier D0 trap branch.
         * Retain the narrow v9 policy independently of the nontrap opt-in. */
        unsigned mov_dst;
        if(d.length!=2||!register_field(&d,'D',&mov_dst)||mov_dst==0||
           !d.field_present['G']||d.field['G']<-8||d.field['G']>7||
           !((cpu->movi_nontrap_basis&&cpu->movi_nontrap_basis[0])||
             (mov_dst==7&&d.field['G']==3&&cpu->movi_d7g3_basis&&cpu->movi_d7g3_basis[0]))) {
            cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;
        }
        cpu->r[mov_dst]=(uint32_t)d.field['G'];
    } else if(ordinary_addi(cpu,&d,&value,&dst)) {
        cpu->r[dst]=value;
    } else if(!strcmp(d.name,"bn.jalr")&&!strcmp(d.exec_reference,"b_jalr")) {
        unsigned a;
        if(!cpu->startup_isa_basis||!cpu->startup_isa_basis[0]||d.length!=3||
           !register_field(&d,'A',&a)) {
            cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;
        }
        /* Public indirect-call software rule, next-PC LR policy as existing jal.
         * Target staged before LR9 write, including A9; fetch is next step. */
        uint32_t target=cpu->r[a];cpu->r[9]=next;next=target;
    } else if((!strcmp(d.name,"bn.xor")&&!strcmp(d.exec_reference,"l_xor"))||
              (!strcmp(d.name,"bn.nand")&&!strcmp(d.exec_reference,"b_nand"))) {
        unsigned a,b,reg;
        if(!cpu->startup_isa_basis||!cpu->startup_isa_basis[0]||d.length!=3||
           !register_field(&d,'A',&a)||!register_field(&d,'B',&b)||
           !register_field(&d,'D',&reg)) {
            cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;
        }
        uint32_t lhs=cpu->r[a],rhs=cpu->r[b];
        cpu->r[reg]=!strcmp(d.exec_reference,"b_nand")?~(lhs&rhs):lhs^rhs;
    } else if(!strcmp(d.name,"bn.ff1")&&!strcmp(d.exec_reference,"l_ff1")) {
        unsigned a,reg;
        if(!cpu->startup_isa_basis||!cpu->startup_isa_basis[0]||d.length!=3||
           !register_field(&d,'A',&a)||!register_field(&d,'D',&reg)) {
            cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;
        }
        /* Public decoder identifies LSB-first but leaves execution TODO.
         * Original D649 xor / ff1 / subtract1 / signed-negative branch implies
         * one-based bit index and zero->0. Explicit firmware-derived candidate. */
        uint32_t source=cpu->r[a],index=0;
        if(source){index=1;while(!(source&1u)){source>>=1;index++;}}
        cpu->r[reg]=index;
    } else if(!strcmp(d.name,"bn.bltsi")&&!strcmp(d.exec_reference,"b_blts")) {
        unsigned b;
        if(!cpu->startup_isa_basis||!cpu->startup_isa_basis[0]||d.length!=3||
           !register_field(&d,'B',&b)||!d.field_present['E']||d.field['E']<0||
           d.field['E']>7||!d.field_present['P']||d.field['P']<-128||d.field['P']>127) {
            cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;
        }
        /* GNU decoded E/P and public signed-less branch candidate. Avoid
         * implementation-defined uint32->int32 conversion for signed compare. */
        uint32_t lhs=cpu->r[b];
        if((lhs&UINT32_C(0x80000000))||lhs<(uint32_t)d.field['E'])
            next=cpu->pc+(uint32_t)d.field['P'];
    } else if((!strcmp(d.name,"bg.bgesi")&&!strcmp(d.exec_reference,"b_bges"))||
              (!strcmp(d.name,"bg.bltsi")&&!strcmp(d.exec_reference,"b_blts"))) {
        unsigned b;
        if(!cpu->startup_isa_basis||!cpu->startup_isa_basis[0]||d.length!=4||
           !register_field(&d,'B',&b)||!d.field_present['I']||
           d.field['I']<-16||d.field['I']>15||!d.field_present['U']||
           d.field['U']<-2048||d.field['U']>2047) {
            cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;
        }
        /* Biasing the sign bit gives signed32 order without implementation-
         * defined casts; GNU sign-extended immediate and relative U are used. */
        uint32_t lhs=cpu->r[b]^UINT32_C(0x80000000);
        uint32_t rhs=(uint32_t)d.field['I']^UINT32_C(0x80000000);
        bool less=lhs<rhs;
        if(less==!strcmp(d.exec_reference,"b_blts"))
            next=cpu->pc+(uint32_t)d.field['U'];
    } else if(!strcmp(d.name,"bn.add")&&!strcmp(d.exec_reference,"b_add")) {
        unsigned a,b,reg;
        if(!cpu->startup_isa_basis||!cpu->startup_isa_basis[0]||d.length!=3||
           !register_field(&d,'A',&a)||!register_field(&d,'B',&b)||
           !register_field(&d,'D',&reg)) {
            cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;
        }
        /* GNU fields/public ordinary add; stage aliases and wrap uint32.
         * Carry/overflow are not inferred by this separately gated policy. */
        uint32_t lhs=cpu->r[a],rhs=cpu->r[b];cpu->r[reg]=lhs+rhs;
    } else if(ordinary_bn_sub(cpu,&d,&value,&dst)) {
        const uint8_t original[3]={0x60,0xc6,0xc5};
        if(cpu->sub_subb_pair_basis&&cpu->sub_subb_pair_basis[0]&&
           cpu->pc==UINT32_C(0x4000d8d9)&&d.length==3&&
           !memcmp(d.raw,original,3)&&d.field['D']==6&&
           d.field['A']==6&&d.field['B']==24) {
            /* Model-only low-word borrow, captured before aliased r6 commit. */
            cpu->flag=cpu->r[6]<cpu->r[24];cpu->flag_known=true;
            cpu->sub_subb_pair_pending=true;pair_produced=true;
            cpu->sub_subb_pair_next_pc=next;
            cpu->sub_subb_pair_next_retired=cpu->retired+1;
        }
        const uint8_t original2[3]={0x60,0xc6,0x25};
        if(cpu->sub_subb_pair2_basis&&cpu->sub_subb_pair2_basis[0]&&
           cpu->pc==UINT32_C(0x4000d8df)&&d.length==3&&
           !memcmp(d.raw,original2,3)&&d.field['D']==6&&
           d.field['A']==6&&d.field['B']==4) {
            cpu->flag=cpu->r[6]<cpu->r[4];cpu->flag_known=true;
            cpu->sub_subb_pair2_pending=true;pair2_produced=true;
            cpu->sub_subb_pair2_next_pc=next;
            cpu->sub_subb_pair2_next_retired=cpu->retired+1;
        }
        cpu->r[dst]=value;
    } else if(register_bg_bgeu_gpr_candidate(cpu,&d,&next)) {
        /* Independent uint32 comparison; no branch RAM/SPR/device callbacks. */
    } else if(register_bg_beq_gpr_candidate(cpu,&d,&next)) {
        /* Independent equality candidate; no branch RAM/SPR/device callbacks. */
    } else if((!strcmp(d.name,"bn.bnei")&&!strcmp(d.exec_reference,"b_bne")) ||
              (!strcmp(d.name,"bn.beqi")&&!strcmp(d.exec_reference,"b_beq"))) {
        unsigned reg;
        if(!cpu->startup_isa_basis||!cpu->startup_isa_basis[0]||d.length!=3||
           !register_field(&d,'B',&reg)||!d.field_present['E']||
           d.field['E']<0||d.field['E']>7||!d.field_present['P']||
           d.field['P']<-128||d.field['P']>127) {
            cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;
        }
        /* Fixed GNU unsigned3 E/signed8 relative P; public lines477..495
         * compare caller GPR with E. Direct uint32 PC sum, next-step fetch,
         * no flags/GPR/IRQ effect: software policy, not silicon certification. */
        bool equal=cpu->r[reg]==(uint32_t)d.field['E'];
        if(equal==!strcmp(d.name,"bn.beqi"))
            next=cpu->pc+(uint32_t)d.field['P'];
    } else if((!strcmp(d.name,"bg.beqi")&&!strcmp(d.exec_reference,"b_beq")) ||
              (!strcmp(d.name,"bg.bnei")&&!strcmp(d.exec_reference,"b_bne")) ||
              (!strcmp(d.name,"bg.bgtui")&&!strcmp(d.exec_reference,"b_bgtu")) ||
              (!strcmp(d.name,"bg.bleui")&&!strcmp(d.exec_reference,"b_bleu"))) {
        unsigned reg;
        if(!cpu->startup_isa_basis||!cpu->startup_isa_basis[0]||d.length!=4||
           !register_field(&d,'B',&reg)||!d.field_present['I']||
           d.field['I']<-16||d.field['I']>15||!d.field_present['U']||
           d.field['U']<-2048||d.field['U']>2047) {
            cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;
        }
        /* Fixed GNU lines403/404: LSB-swizzled signed5 I, signed12 relative U.
         * Fixed public equality/inequality and line1439 unsigned-greater rule
         * compare the GPR with the GNU sign-extended immediate (uint32 for GT). PC uint32 wrap and next-step target fetch
         * are software policy. GNU b_bleu is the explicit complementary LE candidate;
         * public decoder has no LE handler. No flags/GPR/RAM/SPR/IRQ manufacture. */
        uint32_t immediate=(uint32_t)d.field['I'];
        bool taken;
        if(!strcmp(d.name,"bg.bgtui"))taken=cpu->r[reg]>immediate;
        else if(!strcmp(d.name,"bg.bleui"))taken=cpu->r[reg]<=immediate;
        else taken=(cpu->r[reg]==immediate)==!strcmp(d.name,"bg.beqi");
        if(taken)next=cpu->pc+(uint32_t)d.field['U'];
    } else if((!strcmp(d.name,"bn.slli")&&!strcmp(d.exec_reference,"l_sll"))||
              (!strcmp(d.name,"bn.srli")&&!strcmp(d.exec_reference,"l_srl"))) {
        unsigned src,reg;
        if(!cpu->startup_isa_basis||!cpu->startup_isa_basis[0]||d.length!=3||
           !register_field(&d,'A',&src)||!register_field(&d,'D',&reg)||
           !d.field_present['H']||d.field['H']<0||d.field['H']>31) {
            cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;
        }
        /* GNU H unsigned5, fixed public logical shifts. Stage aliased source;
         * uint32 left wrap/right zero-fill; no carry or flag is inferred. */
        uint32_t source=cpu->r[src];unsigned shift=(unsigned)d.field['H'];
        cpu->r[reg]=!strcmp(d.name,"bn.slli")?source<<shift:source>>shift;
    } else if(!strcmp(d.name,"bn.extbs")&&!strcmp(d.exec_reference,"b_extbs")) {
        unsigned src,reg;
        if(!cpu->startup_isa_basis||!cpu->startup_isa_basis[0]||d.length!=3||
           !register_field(&d,'A',&src)||!register_field(&d,'D',&reg)) {
            cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;
        }
        uint32_t source=cpu->r[src]&UINT32_C(0xff);
        cpu->r[reg]=(source&UINT32_C(0x80))?(source|UINT32_C(0xffffff00)):source;
    } else if(startup_compare_kind(&d)) {
        unsigned kind=startup_compare_kind(&d),a,b=0;
        bool wide=d.name[1]=='w';
        bool immediate=d.name[strlen(d.name)-1]=='i';
        if(!cpu->startup_isa_basis||!cpu->startup_isa_basis[0]||
           d.length!=(wide?6u:3u)||!register_field(&d,'A',&a)||
           (!immediate&&!register_field(&d,'B',&b))||
           (immediate&&(!d.field_present[wide?'g':'O']||
             (wide?(d.field['g']<INT32_MIN||d.field['g']>INT32_MAX):
                   (d.field['O']<-128||d.field['O']>127))))) {
            cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;
        }
        /* Complete GNU compare family. Stage old operands; signed32 order is
         * obtained by sign-bit bias, without implementation-defined casts.
         * Only interpreter-local predicate is committed; no guest SR/IRQ,
         * Ready, carry or peer completion is manufactured. */
        uint32_t lhs=cpu->r[a];
        uint32_t rhs=immediate?(uint32_t)d.field[wide?'g':'O']:cpu->r[b];
        bool signed_order=kind==3||kind==5||kind==7||kind==9;
        if(signed_order){lhs^=UINT32_C(0x80000000);rhs^=UINT32_C(0x80000000);}
        bool flag=false;
        switch(kind) {
        case 1:flag=lhs==rhs;break;case 2:flag=lhs!=rhs;break;
        case 3:case 4:flag=lhs>=rhs;break;
        case 5:case 6:flag=lhs>rhs;break;
        case 7:case 8:flag=lhs<=rhs;break;
        case 9:case 10:flag=lhs<rhs;break;
        }
        cpu->sub_subb_pair_pending=false;cpu->sub_subb_pair2_pending=false;
        cpu->flag=flag;cpu->flag_known=true;
    } else if(!strcmp(d.name,"bn.cmov")&&!strcmp(d.exec_reference,"l_cmov")) {
        unsigned a,b,reg;
        if(!cpu->startup_isa_basis||!cpu->startup_isa_basis[0]||!cpu->flag_known||
           d.length!=3||!register_field(&d,'A',&a)||
           !register_field(&d,'B',&b)||!register_field(&d,'D',&reg)) {
            cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;
        }
        /* Public conditional move: flag selects old A or old B, stage aliases.
         * Unknown predicate stops; no implicit flag or IRQ is introduced. */
        uint32_t source=cpu->flag?cpu->r[a]:cpu->r[b];cpu->r[reg]=source;
    } else if(!strcmp(d.name,"bn.extbz")&&!strcmp(d.exec_reference,"b_extbz")) {
        unsigned a,reg;
        if(!cpu->startup_isa_basis||!cpu->startup_isa_basis[0]||d.length!=3||
           !register_field(&d,'A',&a)||!register_field(&d,'D',&reg)) {
            cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;
        }
        cpu->r[reg]=cpu->r[a]&UINT32_C(0xff);
    } else if((!strcmp(d.name,"bn.bf")&&!strcmp(d.exec_reference,"b_bf"))||
              (!strcmp(d.name,"bn.bnf")&&!strcmp(d.exec_reference,"b_bnf"))) {
        if(!cpu->startup_isa_basis||!cpu->startup_isa_basis[0]||!cpu->flag_known||
           d.length!=3||!d.field_present['S']||d.field['S']<-2048||d.field['S']>2047) {
            cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;
        }
        /* Fixed GNU BA_R_FLAG and public relative condition; unknown flag stops.
         * Target fetch is next-step and uint32 PC addition is explicit policy. */
        if(cpu->flag==!strcmp(d.name,"bn.bf"))next=cpu->pc+(uint32_t)d.field['S'];
    } else if(register_bg_bne(cpu,&d,&next)) {
        /* Direct inequality; no prefetch or SPR/RAM callback on the branch. */
    } else if(register_bgtu(cpu,&d,&next)) {
        /* Direct register condition: no SR flag dependencies are inferred. */
    } else if((!strcmp(d.name,"bn.sb")&&!strcmp(d.exec_reference,"l_sb"))||
              (!strcmp(d.name,"bn.lbz")&&!strcmp(d.exec_reference,"l_lbz"))||
              (!strcmp(d.name,"bg.sb")&&!strcmp(d.exec_reference,"l_sb"))||
              (!strcmp(d.name,"bg.lbz")&&!strcmp(d.exec_reference,"l_lbz"))) {
        bool load=!strcmp(d.exec_reference,"l_lbz");
        bool wide=d.name[1]=='g';unsigned base,reg;
        if(!cpu->startup_isa_basis||!cpu->startup_isa_basis[0]||
           d.length!=(wide?4u:3u)||
           !register_field(&d,'A',&base)||!register_field(&d,load?'D':'B',&reg)||
           !d.field_present[wide?'Y':'N']||
           (wide?(d.field['Y']<-32768||d.field['Y']>32767):
                 (d.field['N']<0||d.field['N']>255))) {
            cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;
        }
        /* Fixed public byte access, GNU signed16 Y/unsigned8 N. Stage alias;
         * ordinary uint32 address sum delegates real mapping/device faults. */
        uint32_t address=cpu->r[base]+(uint32_t)d.field[wide?'Y':'N'];
        uint32_t data=load?0:(cpu->r[reg]&UINT32_C(0xff));
        Z6IIBA2BusResult br=Z6II_BA2_BUS_BAD_CONFIG;
        if(load&&cpu->read)br=cpu->read(cpu->bus_opaque,address,1,&data);
        if(!load&&cpu->write)br=cpu->write(cpu->bus_opaque,address,1,data);
        cpu->bus_result=br;
        if(br!=Z6II_BA2_BUS_OK) {
            cpu->halted=Z6II_BA2_CPU_BUS_FAULT;return cpu->halted;
        }
        if(load)cpu->r[reg]=data&UINT32_C(0xff);
    } else if(!strcmp(d.exec_reference,"l_lwz")||!strcmp(d.exec_reference,"l_sw")) {
        bool load=!strcmp(d.exec_reference,"l_lwz");uint32_t address;
        if(!ordinary_memory(cpu,&d,load,&address,&dst)) {
            cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;
        }
        Z6IIBA2BusResult br=Z6II_BA2_BUS_BAD_CONFIG;
        if(load&&cpu->read)br=cpu->read(cpu->bus_opaque,address,4,&value);
        if(!load&&cpu->write)br=cpu->write(cpu->bus_opaque,address,4,cpu->r[dst]);
        cpu->bus_result=br;
        if(br!=Z6II_BA2_BUS_OK) {
            cpu->halted=Z6II_BA2_CPU_BUS_FAULT;return cpu->halted;
        }
        if(load)cpu->r[dst]=value;
    } else if((!strcmp(d.exec_reference,"l_or")||!strcmp(d.exec_reference,"l_and")) &&
              ordinary_bitwise(cpu,&d,&value,&dst)) {
        cpu->r[dst]=value;
    } else if(!strcmp(d.exec_reference,"l_mfspr")||!strcmp(d.exec_reference,"l_mtspr")) {
        bool wr=!strcmp(d.exec_reference,"l_mtspr");
        if(!d.field_present['A']||!d.field_present['o']||
            d.field['A']<0||d.field['A']>=32||cpu->r[(unsigned)d.field['A']]!=0) {
            /* The original reset uses A=r0=0. Nonzero base combination rules
             * have not been independently established, so do not guess them. */
            cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;
        }
        unsigned reg=wr?(unsigned)d.field['B']:(unsigned)d.field['D'];
        if(reg>=32||!d.field_present[wr?'B':'D']){
            cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;
        }
        cpu->last_spr_access=true;cpu->last_spr_write=wr;
        cpu->last_spr_selector=(uint32_t)d.field['o'];
        uint32_t data=wr?cpu->r[reg]:0;
        Z6IIBA2SPRResult sr=Z6II_BA2_SPR_UNKNOWN;
        bool irq_handled=false;
        sr=z6ii_ba2_irq138_spr(cpu,cpu->last_spr_selector,wr,&data,&irq_handled);
        if(!irq_handled&&wr&&cpu->spr_write)sr=cpu->spr_write(cpu->spr_opaque,cpu->last_spr_selector,data);
        if(!irq_handled&&!wr&&cpu->spr_read)sr=cpu->spr_read(cpu->spr_opaque,cpu->last_spr_selector,&data);
        cpu->last_spr_result=sr;cpu->last_spr_value=data;
        if(sr!=Z6II_BA2_SPR_OK){
            cpu->halted=sr==Z6II_BA2_SPR_UNKNOWN?Z6II_BA2_CPU_UNKNOWN_SPR:Z6II_BA2_CPU_SPR_FAULT;
            return cpu->halted;
        }
        if(!wr)cpu->r[reg]=data;
    } else {
        cpu->halted=Z6II_BA2_CPU_UNSUPPORTED_OPCODE;return cpu->halted;
    }
    if(cpu->sub_subb_pair_pending&&!pair_produced) {
        /* Any other successfully retired instruction ends this exact pair. */
        cpu->sub_subb_pair_pending=false;cpu->flag_known=false;
    }
    if(cpu->sub_subb_pair2_pending&&!pair2_produced) {
        cpu->sub_subb_pair2_pending=false;cpu->flag_known=false;
    }
    if(cpu->bt_add_bn_addc_pair_pending&&!add_pair_produced) {
        cpu->bt_add_bn_addc_pair_pending=false;
        cpu->bt_add_bn_addc_pair_carry_known=false;
    }
    cpu->pc=next;cpu->retired++;return Z6II_BA2_CPU_OK;
}
Z6IIBA2CPUResult z6ii_ba2_cpu_run(Z6IIBA2CPU *cpu,uint64_t budget) {
    if(!cpu)return Z6II_BA2_CPU_BAD_CONFIG;
    for(uint64_t i=0;i<budget;i++) {
        Z6IIBA2CPUResult r=z6ii_ba2_cpu_step(cpu);if(r!=Z6II_BA2_CPU_OK)return r;
    }
    return Z6II_BA2_CPU_BUDGET; /* Budget yield is resumable; it does not set halted. */
}
const char *z6ii_ba2_cpu_result_name(Z6IIBA2CPUResult r) {
    static const char *names[]={"ok","bad-config","bus-fault","unknown-opcode",
        "unsupported-opcode","unsupported-irq","budget","unknown-spr","spr-fault"};
    return (unsigned)r<sizeof(names)/sizeof(names[0])?names[r]:"invalid-result";
}
