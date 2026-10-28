/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "ba2-mlwz-ram-read.h"
#include <string.h>
static Z6IIBA2BusResult failed(Z6IIBA2Bus *b,Z6IIBA2BusResult r,uint32_t a) {
    if(b)b->fault=(Z6IIBA2BusFault){r,a,4,false,false};
    return r;
}
Z6IIBA2BusResult z6ii_ba2_mlwz_ram_read_pair(void *opaque,const uint32_t *addresses,
                                         uint32_t *out,unsigned count) {
    Z6IIBA2Bus *b=opaque;
    if(!b||!b->initialized||!addresses||!out||count!=2||
       !b->config.ram||!b->config.ram_count||
       b->config.ram_count>Z6II_BA2_MAX_RAM_MAPS||
       (b->config.data_endian!=Z6II_BA2_DATA_LE&&b->config.data_endian!=Z6II_BA2_DATA_BE))
        return failed(b,Z6II_BA2_BUS_BAD_CONFIG,0);
    uint32_t a[2],values[2]={0,0};const uint8_t *source[2];
    memcpy(a,addresses,sizeof(a));
    for(unsigned i=0;i<2;i++) {
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
    for(unsigned i=0;i<2;i++)for(unsigned j=0;j<4;j++) {
        unsigned shift=b->config.data_endian==Z6II_BA2_DATA_LE?j*8:(3-j)*8;
        values[i]|=(uint32_t)source[i][j]<<shift;
    }
    memcpy(out,values,sizeof(values));return Z6II_BA2_BUS_OK;
}
