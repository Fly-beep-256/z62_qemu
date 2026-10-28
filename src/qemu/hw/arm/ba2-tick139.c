/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "ba2-tick139.h"
#define TP UINT32_C(0x0fffffff)
#define IP UINT32_C(0x10000000)
#define IE UINT32_C(0x20000000)
#define MODE UINT32_C(0xc0000000)
#define RESTART UINT32_C(0x40000000)
bool z6ii_ba2_tick139_invariant(const Z6IIBA2Tick139 *s)
{
    return s && s->initialized && s->basis && s->basis[0] &&
        s->source_hz==UINT64_C(400000000) && s->ns_fraction_fifths<5 &&
        !(s->control&IP) &&
        ((s->control&MODE)==0 || (s->control&MODE)==RESTART) &&
        s->count<=TP && ((s->control&MODE)!=RESTART ||
        s->count<=(s->control&TP));
}
Z6IIBA2SPRResult z6ii_ba2_tick139_init(Z6IIBA2Tick139 *s,uint64_t hz,
                                    uint64_t initial,const char *basis)
{
    if(!s||hz!=UINT64_C(400000000)||!basis||!basis[0])
        return Z6II_BA2_SPR_FAULT;
    *s=(Z6IIBA2Tick139){.basis=basis,.source_hz=hz,
        .source_cycles=initial,.initialized=true};
    return Z6II_BA2_SPR_OK;
}
bool z6ii_ba2_tick139_level(const Z6IIBA2Tick139 *s)
{return z6ii_ba2_tick139_invariant(s)&&s->pending&&(s->control&IE)!=0;}
Z6IIBA2SPRResult z6ii_ba2_tick139_advance(Z6IIBA2Tick139 *s,uint64_t cycles)
{
    if(!z6ii_ba2_tick139_invariant(s))return Z6II_BA2_SPR_FAULT;
    /* Wrap is ordinary unsigned counter rollover. Division avoids iteration
     * and overflow even for a UINT64_MAX caller time delta. */
    if((s->control&MODE)==RESTART) {
        uint64_t period=(s->control&TP)+UINT64_C(1);
        uint64_t quotient=cycles/period,remainder=cycles%period;
        uint64_t sum=(uint64_t)s->count+remainder;
        uint64_t hits=quotient+sum/period;
        s->count=(uint32_t)(sum%period);
        s->events+=hits;
        if(hits)s->pending=true;
    }
    s->source_cycles+=cycles;s->elapsed_cycles+=cycles;
    return Z6II_BA2_SPR_OK;
}
Z6IIBA2SPRResult z6ii_ba2_tick139_advance_ns(Z6IIBA2Tick139 *s,uint64_t ns)
{
    if(!z6ii_ba2_tick139_invariant(s))return Z6II_BA2_SPR_FAULT;
    /* ns/5*2 cannot overflow uint64_t. Carry fifths, not floating point. */
    unsigned fifths=(unsigned)(ns%5)*2+s->ns_fraction_fifths;
    uint64_t cycles=ns/5*2+fifths/5;
    Z6IIBA2SPRResult r=z6ii_ba2_tick139_advance(s,cycles);
    if(r==Z6II_BA2_SPR_OK)s->ns_fraction_fifths=fifths%5;
    return r;
}
Z6IIBA2SPRResult z6ii_ba2_tick139_spr(Z6IIBA2Tick139 *s,uint32_t selector,
                                   bool write,uint32_t *value,bool *handled)
{
    if(!handled)return Z6II_BA2_SPR_FAULT;
    *handled=false;
    if(selector!=0x5000&&selector!=0x5001&&selector!=0x5004&&selector!=0x5005)
        return Z6II_BA2_SPR_UNKNOWN;
    if(!s)return Z6II_BA2_SPR_UNKNOWN;
    *handled=true;
    if(!z6ii_ba2_tick139_invariant(s)||!value)
        return Z6II_BA2_SPR_FAULT;
    if(selector==0x5004||selector==0x5005) {
        if(write)return Z6II_BA2_SPR_UNKNOWN;
        *value=selector==0x5004?(uint32_t)s->source_cycles:
            (uint32_t)(s->source_cycles>>32);
        return Z6II_BA2_SPR_OK;
    }
    if(selector==0x5001) {
        if(write) {
            if(*value>TP||((s->control&MODE)==RESTART&&
               *value>(s->control&TP)))return Z6II_BA2_SPR_FAULT;
            s->count=*value;
        } else *value=s->count;
        return Z6II_BA2_SPR_OK;
    }
    if(!write) {
        *value=(s->control&~IP)|(s->pending?IP:0);
        return Z6II_BA2_SPR_OK;
    }
    uint32_t mode=*value&MODE;
    if(mode!=0&&mode!=RESTART)return Z6II_BA2_SPR_FAULT;
    /* Original ACK writes the read value with IP=0. A write with IP=1 does
     * not create a hardware event; it preserves the current level. */
    if(!(*value&IP)&&s->pending) {
        s->pending=false;++s->acknowledgements;
    }
    s->control=*value&~IP;
    if(mode==RESTART&&s->count>(s->control&TP))s->count=0;
    return Z6II_BA2_SPR_OK;
}
