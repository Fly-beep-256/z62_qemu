/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "ba2-startup-ram-read.h"
#include <string.h>
static Z6IIBA2BusResult failed(Z6IIBA2Bus *b,Z6IIBA2BusResult r,uint32_t a) {
    if(b)b->fault=(Z6IIBA2BusFault){r,a,4,false,false};
    return r;
}
Z6IIBA2BusResult z6ii_ba2_startup_ram_read_batch(void *opaque,const uint32_t *addresses,
                                         uint32_t *out,unsigned count) {
    Z6IIBA2Bus *b=opaque;
    if(!b||!b->initialized||!addresses||!out||(!count||count>15)||
       !b->config.ram||!b->config.ram_count||
       b->config.ram_count>Z6II_BA2_MAX_RAM_MAPS||
       (b->config.data_endian!=Z6II_BA2_DATA_LE&&b->config.data_endian!=Z6II_BA2_DATA_BE))
        return failed(b,Z6II_BA2_BUS_BAD_CONFIG,0);
    uint32_t a[15],values[15]={0};const uint8_t *source[15];
    memcpy(a,addresses,count*sizeof(a[0]));
    for(unsigned i=0;i<count;i++) {
        if((uint64_t)a[i]+4>UINT64_C(0x100000000))
            return failed(b,Z6II_BA2_BUS_UNMAPPED,a[i]);
        if(!b->config.allow_unaligned_data&&(a[i]&3))
            return failed(b,Z6II_BA2_BUS_BAD_ALIGNMENT,a[i]);
        const Z6IIBA2MemoryMap *m=NULL;
        for(unsigned j=0;j<b->config.ram_count;j++) {
            const Z6IIBA2MemoryMap *candidate=&b->config.ram[j];
            if(a[i]>=candidate->base&&(uint64_t)a[i]-candidate->base<=candidate->size&&
               4<=candidate->size-((uint64_t)a[i]-candidate->base)) {
                m=candidate;break;
            }
        }
        if(!m)return failed(b,Z6II_BA2_BUS_UNMAPPED,a[i]);
        if(!(m->permissions&Z6II_BA2_MEM_READ))
            return failed(b,Z6II_BA2_BUS_PERMISSION,a[i]);
        if(!m->bytes)return failed(b,Z6II_BA2_BUS_BAD_CONFIG,a[i]);
        source[i]=m->bytes+(a[i]-m->base);
    }
    /* No source read happens until all checks have succeeded; ownership keeps
     * both source words stable until a single output commit. */
    for(unsigned i=0;i<count;i++)for(unsigned j=0;j<4;j++) {
        unsigned shift=b->config.data_endian==Z6II_BA2_DATA_LE?j*8:(3-j)*8;
        values[i]|=(uint32_t)source[i][j]<<shift;
    }
    memcpy(out,values,count*sizeof(values[0]));return Z6II_BA2_BUS_OK;
}

static Z6IIBA2BusResult write_failed(Z6IIBA2Bus *b,Z6IIBA2BusResult r,uint32_t a) {
    if(b)b->fault=(Z6IIBA2BusFault){r,a,4,true,false};return r;
}
/* Full GNU F domain stack write policy. All mapping/alias checks precede RAM
 * writes; this dedicated helper leaves the legacy bus batch bound unchanged. */
Z6IIBA2BusResult z6ii_ba2_startup_ram_write_batch(void *opaque,
    const uint32_t *addresses,const uint32_t *values,unsigned count) {
    Z6IIBA2Bus *b=opaque;uint32_t a[15],v[15];uint8_t *target[15];
    if(!b||!b->initialized||!addresses||!values||!count||count>15||
       !b->config.ram||!b->config.ram_count||
       b->config.ram_count>Z6II_BA2_MAX_RAM_MAPS||
       (b->config.data_endian!=Z6II_BA2_DATA_LE&&b->config.data_endian!=Z6II_BA2_DATA_BE))
        return write_failed(b,Z6II_BA2_BUS_BAD_CONFIG,0);
    memcpy(a,addresses,count*sizeof(a[0]));memcpy(v,values,count*sizeof(v[0]));
    for(unsigned i=0;i<count;i++) {
        if((uint64_t)a[i]+4>UINT64_C(0x100000000))
            return write_failed(b,Z6II_BA2_BUS_UNMAPPED,a[i]);
        if(!b->config.allow_unaligned_data&&(a[i]&3))
            return write_failed(b,Z6II_BA2_BUS_BAD_ALIGNMENT,a[i]);
        const Z6IIBA2MemoryMap *m=NULL;
        for(unsigned j=0;j<b->config.ram_count;j++) {
            const Z6IIBA2MemoryMap *c=&b->config.ram[j];
            if(a[i]>=c->base&&(uint64_t)a[i]-c->base<=c->size&&
               4<=c->size-((uint64_t)a[i]-c->base)){m=c;break;}
        }
        if(!m)return write_failed(b,Z6II_BA2_BUS_UNMAPPED,a[i]);
        if(!(m->permissions&Z6II_BA2_MEM_WRITE)||!m->writable_bytes)
            return write_failed(b,Z6II_BA2_BUS_PERMISSION,a[i]);
        target[i]=m->writable_bytes+(a[i]-m->base);
        for(unsigned j=0;j<i;j++) {
            uintptr_t x=(uintptr_t)target[i],y=(uintptr_t)target[j];
            if(((uint64_t)a[i]<(uint64_t)a[j]+4&&(uint64_t)a[j]<(uint64_t)a[i]+4)||
               (x<=UINTPTR_MAX-4&&y<=UINTPTR_MAX-4&&x<y+4&&y<x+4))
                return write_failed(b,Z6II_BA2_BUS_BAD_CONFIG,a[i]);
        }
    }
    for(unsigned i=0;i<count;i++)for(unsigned j=0;j<4;j++) {
        unsigned shift=b->config.data_endian==Z6II_BA2_DATA_LE?j*8:(3-j)*8;
        target[i][j]=(uint8_t)(v[i]>>shift);
    }
    return Z6II_BA2_BUS_OK;
}
