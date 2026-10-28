/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "ba2-irq138.h"
#include <string.h>

Z6IIBA2CPUResult z6ii_ba2_cpu_enable_irq138_candidate(Z6IIBA2CPU *cpu,
    Z6IIBA2IRQ138 *state,uint32_t vector,uint32_t sr11,
    Z6IIBA2RAMBatchReadFn read,Z6IIBA2RAMBatchWriteFn write,void *opaque,
    const char *basis)
{
    if(!cpu||!state||vector!=Z6II_BA2_IRQ138_VECTOR||!read||!write||
       !basis||!basis[0]||cpu->startup_irq138)return Z6II_BA2_CPU_BAD_CONFIG;
    *state=(Z6IIBA2IRQ138){.basis=basis,.vector_pc=vector,.sr11=sr11,
        .ram_read=read,.ram_write=write,.ram_opaque=opaque};
    cpu->startup_irq138=state;
    cpu->startup_irq_mask_known=true;cpu->startup_irq_enabled=(sr11&4)!=0;
    return Z6II_BA2_CPU_OK;
}

static uint32_t current_sr(const Z6IIBA2CPU *cpu)
{
    return (cpu->startup_irq138->sr11&~UINT32_C(4))|
        (cpu->startup_irq_enabled?UINT32_C(4):0);
}

Z6IIBA2CPUResult z6ii_ba2_irq138_bind_external_sources(Z6IIBA2IRQ138 *s,
    Z6IIBA2IRQ138SourcesFn sources, void *opaque, const char *basis)
{
    if (!s || !s->basis || !*s->basis || !sources || !basis || !*basis ||
        s->external_sources || s->active) {
        return Z6II_BA2_CPU_BAD_CONFIG;
    }
    s->external_sources = sources;
    s->external_sources_opaque = opaque;
    return Z6II_BA2_CPU_OK;
}

Z6IIBA2CPUResult z6ii_ba2_irq138_bind_tick139_candidate(Z6IIBA2IRQ138 *s,
    Z6IIBA2Tick139 *tick,uint32_t vector,const char *basis)
{
    if(!s||!s->basis||!s->basis[0]||!z6ii_ba2_tick139_invariant(tick)||
       vector!=Z6II_BA2_TICK139_VECTOR||!basis||!basis[0]||
       s->tick139||s->active)return Z6II_BA2_CPU_BAD_CONFIG;
    s->tick139=tick;s->tick_vector_pc=vector;
    return Z6II_BA2_CPU_OK;
}

Z6IIBA2CPUResult z6ii_ba2_irq138_poll(Z6IIBA2CPU *cpu)
{
    if(!cpu)return Z6II_BA2_CPU_BAD_CONFIG;
    Z6IIBA2IRQ138 *s=cpu->startup_irq138;
    uint32_t sources=s&&s->external_sources ?
        s->external_sources(s->external_sources_opaque) :
        ((cpu->irq&&cpu->irq(cpu->bus_opaque))?UINT32_C(2):0);
    if(sources&~UINT32_C(3))return Z6II_BA2_CPU_BAD_CONFIG;
    bool fifo=sources!=0; /* Legacy counter name: aggregate external source. */
    bool tick=s&&z6ii_ba2_tick139_level(s->tick139);
    if(!fifo&&!tick)return Z6II_BA2_CPU_OK;
    if(!s||!cpu->startup_irq_mask_known)return Z6II_BA2_CPU_UNSUPPORTED_IRQ;
    /* Actual level remains visible while masked and during the nonnested ISR.
     * No source ACK/clear or host FIFO pop accompanies CPU exception entry. */
    if(!cpu->startup_irq_enabled||s->active)return Z6II_BA2_CPU_OK;
    s->epc20=cpu->pc;s->esr40=current_sr(cpu);s->entry_esr40=s->esr40;
    s->saved_flag=cpu->flag;s->saved_flag_known=cpu->flag_known;
    s->active=true;s->exception_known=true;s->active_source=fifo?1:2;
    if(fifo)++s->entries;else ++s->tick_entries;
    cpu->startup_irq_enabled=false;cpu->startup_irq_mask_known=true;
    cpu->sub_subb_pair_pending=false;cpu->sub_subb_pair2_pending=false;
    cpu->bt_add_bn_addc_pair_pending=false;
    cpu->bt_add_bn_addc_pair_carry_known=false;
    cpu->pc=fifo?s->vector_pc:s->tick_vector_pc;
    return Z6II_BA2_CPU_OK;
}

Z6IIBA2SPRResult z6ii_ba2_irq138_spr(Z6IIBA2CPU *cpu,uint32_t selector,
    bool write,uint32_t *value,bool *handled)
{
    if(!handled)return Z6II_BA2_SPR_FAULT;
    *handled=false;
    if(!cpu||!value)return Z6II_BA2_SPR_FAULT;
    Z6IIBA2IRQ138 *s=cpu->startup_irq138;
    if(!s)return Z6II_BA2_SPR_UNKNOWN;
    Z6IIBA2SPRResult tr=z6ii_ba2_tick139_spr(s->tick139,selector,write,value,handled);
    if(*handled)return tr;
    if(selector!=0x11&&selector!=0x20&&selector!=0x40&&selector!=0x4802)
        return Z6II_BA2_SPR_UNKNOWN;
    *handled=true;
    if(selector==0x4802) {
        if(write)return Z6II_BA2_SPR_FAULT;
        /* Original 7386/7392 uses bit1 for FIFO and bit0 for 104xx engine. */
        uint32_t sources=s->external_sources ?
            s->external_sources(s->external_sources_opaque) :
            ((cpu->irq&&cpu->irq(cpu->bus_opaque))?UINT32_C(2):0);
        if(sources&~UINT32_C(3))return Z6II_BA2_SPR_FAULT;
        *value=sources;
        return Z6II_BA2_SPR_OK;
    }
    if(selector==0x11) {
        if(write) {
            s->sr11=*value;cpu->startup_irq_enabled=(*value&4)!=0;
            cpu->startup_irq_mask_known=true;
        } else if(cpu->startup_irq_mask_known)*value=current_sr(cpu);
        else return Z6II_BA2_SPR_UNKNOWN;
        return Z6II_BA2_SPR_OK;
    }
    if(!s->exception_known)return Z6II_BA2_SPR_UNKNOWN;
    uint32_t *target=selector==0x20?&s->epc20:&s->esr40;
    /* No speculative map from arbitrary changed ESR bits to private flags.
     * Original wrapper restores the same ESR; only the evidenced EI bit may vary. */
    if(write&&selector==0x40&&((*value^s->entry_esr40)&~UINT32_C(4)))
        return Z6II_BA2_SPR_FAULT;
    if(write)*target=*value;else *value=*target;
    return Z6II_BA2_SPR_OK;
}

Z6IIBA2CPUResult z6ii_ba2_irq138_rfe(Z6IIBA2CPU *cpu,uint32_t *next)
{
    if(!cpu||!next)return Z6II_BA2_CPU_BAD_CONFIG;
    Z6IIBA2IRQ138 *s=cpu->startup_irq138;
    if(!s||!s->active||!s->exception_known)return Z6II_BA2_CPU_UNSUPPORTED_OPCODE;
    *next=s->epc20;s->sr11=s->esr40;
    cpu->startup_irq_enabled=(s->esr40&4)!=0;cpu->startup_irq_mask_known=true;
    cpu->flag=s->saved_flag;cpu->flag_known=s->saved_flag_known;
    if(s->active_source==2)++s->tick_returns;else ++s->returns;
    s->active=false;s->active_source=0;
    return Z6II_BA2_CPU_OK;
}

bool z6ii_ba2_irq138_group_shape(const Z6IIBA2CPU *cpu,const Z6IIBA2Decoded *d)
{
    if(!cpu||!cpu->startup_irq138||!d||d->length!=3||
       !d->field_present['A']||d->field['A']!=1||!d->field_present['C']||
       !d->field_present['K'])return false;
    bool read=!strcmp(d->name,"bn.mlwz")&&!strcmp(d->exec_reference,"b_mlwz");
    bool write=!strcmp(d->name,"bn.msw")&&!strcmp(d->exec_reference,"b_msw");
    if(!read&&!write)return false;
    unsigned reg=read?'D':'B';
    if(!d->field_present[reg])return false;
    /* BD63/BD86 contiguous frame: 3..5 at0..8, 6..9 at12..24,
     * 23..30 at28..56, then single r31 at60. GNU proves C, not its count;
     * these three repeated original frame shapes supply the count candidate. */
    return (d->field['C']==1&&d->field[reg]==3&&d->field['K']==0)||
        (d->field['C']==2&&d->field[reg]==6&&d->field['K']==12)||
        (d->field['C']==3&&d->field[reg]==23&&d->field['K']==28);
}

Z6IIBA2CPUResult z6ii_ba2_irq138_group(Z6IIBA2CPU *cpu,const Z6IIBA2Decoded *d)
{
    if(!z6ii_ba2_irq138_group_shape(cpu,d))return Z6II_BA2_CPU_UNSUPPORTED_OPCODE;
    bool read=!strcmp(d->name,"bn.mlwz");
    unsigned first=(unsigned)d->field[read?'D':'B'];
    unsigned count=d->field['C']==1?3:d->field['C']==2?4:8;
    uint64_t start=(uint64_t)cpu->r[1]+(uint32_t)d->field['K'];
    if(start+4*count>UINT64_C(0x100000000)) {
        cpu->bus_result=Z6II_BA2_BUS_UNMAPPED;return Z6II_BA2_CPU_BUS_FAULT;
    }
    uint32_t addresses[8],values[8]={0};
    for(unsigned i=0;i<count;i++) {
        addresses[i]=(uint32_t)start+4*i;
        if(!read)values[i]=cpu->r[first+i];
    }
    Z6IIBA2IRQ138 *s=cpu->startup_irq138;
    Z6IIBA2BusResult result=read?s->ram_read(s->ram_opaque,addresses,values,count):
        s->ram_write(s->ram_opaque,addresses,values,count);
    cpu->bus_result=result;
    if(result!=Z6II_BA2_BUS_OK)return Z6II_BA2_CPU_BUS_FAULT;
    if(read)for(unsigned i=0;i<count;i++)cpu->r[first+i]=values[i];
    return Z6II_BA2_CPU_OK;
}

static Z6IIBA2BusResult ram_batch(void *opaque,const uint32_t *addresses,
    uint32_t *output,const uint32_t *input,unsigned count,bool write)
{
    Z6IIBA2Bus *b=opaque;Z6IIBA2BusResult result=Z6II_BA2_BUS_OK;uint32_t bad=0;
    if(!b||!b->initialized||!addresses||(!output&&!write)||(!input&&write)||
       !count||count>8||!b->config.ram||!b->config.ram_count||
       b->config.ram_count>Z6II_BA2_MAX_RAM_MAPS||
       (b->config.data_endian!=Z6II_BA2_DATA_LE&&b->config.data_endian!=Z6II_BA2_DATA_BE))
        result=Z6II_BA2_BUS_BAD_CONFIG;
    uint8_t *destination[8]={0};const uint8_t *source[8]={0};uint32_t values[8]={0};
    if(result==Z6II_BA2_BUS_OK)for(unsigned i=0;i<count;i++) {
        bad=addresses[i];
        if((uint64_t)bad+4>UINT64_C(0x100000000)) {result=Z6II_BA2_BUS_UNMAPPED;break;}
        if(!b->config.allow_unaligned_data&&(bad&3)) {result=Z6II_BA2_BUS_BAD_ALIGNMENT;break;}
        const Z6IIBA2MemoryMap *m=NULL;
        for(unsigned j=0;j<b->config.ram_count;j++) {
            const Z6IIBA2MemoryMap *candidate=&b->config.ram[j];
            if(bad>=candidate->base&&(uint64_t)bad-candidate->base<=candidate->size&&
               4<=candidate->size-((uint64_t)bad-candidate->base)) {m=candidate;break;}
        }
        if(!m) {result=Z6II_BA2_BUS_UNMAPPED;break;}
        if(!(m->permissions&(write?Z6II_BA2_MEM_WRITE:Z6II_BA2_MEM_READ))) {
            result=Z6II_BA2_BUS_PERMISSION;break;
        }
        if((write&&!m->writable_bytes)||(!write&&!m->bytes)) {result=Z6II_BA2_BUS_BAD_CONFIG;break;}
        if(write)destination[i]=m->writable_bytes+(bad-m->base);
        else source[i]=m->bytes+(bad-m->base);
    }
    if(result!=Z6II_BA2_BUS_OK) {
        if(b)b->fault=(Z6IIBA2BusFault){result,bad,4,write,false};
        return result;
    }
    /* Stage the complete caller input or source before a single commit phase. */
    if(write)memcpy(values,input,count*sizeof(values[0]));
    else for(unsigned i=0;i<count;i++)for(unsigned j=0;j<4;j++) {
        unsigned shift=b->config.data_endian==Z6II_BA2_DATA_LE?j*8:(3-j)*8;
        values[i]|=(uint32_t)source[i][j]<<shift;
    }
    if(write)for(unsigned i=0;i<count;i++)for(unsigned j=0;j<4;j++) {
        unsigned shift=b->config.data_endian==Z6II_BA2_DATA_LE?j*8:(3-j)*8;
        destination[i][j]=(uint8_t)(values[i]>>shift);
    }
    else memcpy(output,values,count*sizeof(values[0]));
    return Z6II_BA2_BUS_OK;
}
Z6IIBA2BusResult z6ii_ba2_irq138_ram_read_batch(void *b,const uint32_t *a,uint32_t *v,unsigned n)
{return ram_batch(b,a,v,NULL,n,false);}
Z6IIBA2BusResult z6ii_ba2_irq138_ram_write_batch(void *b,const uint32_t *a,const uint32_t *v,unsigned n)
{return ram_batch(b,a,NULL,v,n,true);}
