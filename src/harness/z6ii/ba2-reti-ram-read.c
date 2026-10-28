/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "ba2-reti-ram-read.h"
static Z6IIBA2BusResult failed(Z6IIBA2Bus *b,Z6IIBA2BusResult r,uint32_t a) {
    if(b)b->fault=(Z6IIBA2BusFault){r,a,4,false,false};
    return r;
}
Z6IIBA2BusResult z6ii_ba2_reti_ram_read32(void *opaque,uint32_t a,uint32_t *out) {
    Z6IIBA2Bus *b=opaque;
    if(!b||!b->initialized||!out)return failed(b,Z6II_BA2_BUS_BAD_CONFIG,a);
    if((uint64_t)a+4>UINT64_C(0x100000000))
        return failed(b,Z6II_BA2_BUS_UNMAPPED,a);
    if(!b->config.allow_unaligned_data&&(a&3))
        return failed(b,Z6II_BA2_BUS_BAD_ALIGNMENT,a);
    const Z6IIBA2MemoryMap *m=NULL;
    for(unsigned i=0;i<b->config.ram_count;i++) {
        const Z6IIBA2MemoryMap *candidate=&b->config.ram[i];
        if(a>=candidate->base&&(uint64_t)a-candidate->base<=candidate->size&&
           4<=candidate->size-((uint64_t)a-candidate->base)) {
            m=candidate;break;
        }
    }
    if(!m)return failed(b,Z6II_BA2_BUS_UNMAPPED,a);
    if(!(m->permissions&Z6II_BA2_MEM_READ))
        return failed(b,Z6II_BA2_BUS_PERMISSION,a);
    uint32_t value=0;
    for(unsigned i=0;i<4;i++) {
        unsigned shift=b->config.data_endian==Z6II_BA2_DATA_LE?i*8:(3-i)*8;
        value|=(uint32_t)m->bytes[a-m->base+i]<<shift;
    }
    *out=value;return Z6II_BA2_BUS_OK;
}
