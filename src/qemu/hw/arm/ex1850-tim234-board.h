/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef EX1850_TIM234_BOARD_H
#define EX1850_TIM234_BOARD_H

static unsigned ex1850_tim234_hz(EX1850ResetState *s, unsigned n)
{
    uint32_t bit=1U<<n;
    if (!(s->apb1enr&bit) || (s->rcc_apb1rstr&bit)) { return 0; }
    unsigned ppre=(s->cfgr>>10)&7;
    return ppre<4 ? s->cpu_hz : (s->cpu_hz>>(ppre-3))*2;
}

static void ex1850_tim234_schedule(EX1850ResetState *s, unsigned n)
{
    timer_del(s->tim234_event[n]);
    unsigned hz=ex1850_tim234_hz(s,n);
    int64_t due=ex1850_tim234_deadline(&s->tim234[n],hz);
    if (due>=0) { timer_mod(s->tim234_event[n],due); }
    qemu_set_irq(qdev_get_gpio_in(DEVICE(s->armv7m), 28+n),
                 hz && !!(s->tim234[n].sr&s->tim234[n].dier&0x1f));
}

static void ex1850_tim234_clock_sync(EX1850ResetState *s, unsigned n)
{
    if (!ex1850_tim234_core_sync(&s->tim234[n],
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),ex1850_tim234_hz(s,n))) {
        fprintf(stderr,"EX1850_TIM234_TIME_BOUNDARY timer=%u pc=%08x "
                       "source=unsupported_counter_state completion_supplied=0\n",n+2,ex1850_pc());
        ex1850_unknown_access(s,0x40000024+n*0x400,4,false,0);
    }
}

static void ex1850_tim234_event(void *opaque)
{
    EX1850TIM234Event *e=opaque;
    ex1850_tim234_clock_sync(e->state,e->index);
    ex1850_tim234_schedule(e->state,e->index);
}

static bool ex1850_tim234_access(EX1850ResetState *s,hwaddr addr,
                                 unsigned size,bool write,uint64_t *value)
{
    if (addr<0x40000000 || addr>0x40000840 || (addr&3) || size!=4) { return false; }
    unsigned n=(addr-0x40000000)/0x400;
    unsigned off=(addr-0x40000000)%0x400;
    if (n>=3 || off>0x40 || !ex1850_tim234_hz(s,n) || (write && *value>UINT32_MAX)) { return false; }
    EX1850TIM234 c=s->tim234[n];
    uint32_t v=0;
    if (!ex1850_tim234_core_sync(&c,qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),ex1850_tim234_hz(s,n))) { return false; }
    bool ok=write ? ex1850_tim234_write(&c,off,(uint32_t)*value) : ex1850_tim234_read(&c,off,&v);
    if (!ok) {
        if (write && off==0x20) {
            EX1850TIM234 attempted=c; attempted.ccer=*value;
            if (ex1850_tim234_capture_enabled(&attempted)) {
                fprintf(stderr,"EX1850_TIM234_EXTERNAL_CAPTURE_BOUNDARY timer=%u "
                    "requested_CCER=%08" PRIx64 " CCMR1=%08x CCMR2=%08x pc=%08x "
                    "source=external_capture_edges_unprovided captured_bytes_supplied=0\n",
                    n+2,*value,c.ccmr[0],c.ccmr[1],ex1850_pc());
            }
        }
        return false;
    }
    s->tim234[n]=c;
    if (!write) { *value=v; }
    ex1850_tim234_schedule(s,n);
    uint64_t count=++s->tim234_access_counts[n][off/4];
    /* Retain the complete finite original configuration (207 requests,
     * including 56 accesses to TIM4 CCER). Sampling starts only afterward. */
    if (write || count<=256 || !(count&(count-1))) {
        fprintf(stderr,"EX1850_TIM234_%c timer=%u addr=%08" HWADDR_PRIx
            " size=%u value=%08" PRIx64 " pc=%08x CR1=%08x SR=%08x DIER=%08x "
            "CCMR1=%08x CCMR2=%08x CCER=%08x CNT=%08x PSC=%u ARR=%08x "
            "active_PSC=%u active_ARR=%08x virtual_ns=%" PRId64
            " source=original_guest_configuration_and_virtual_counter "
            "sampled_access_index=%" PRIu64 " external_capture_or_pad_supplied=0\n",
            write?'W':'R',n+2,addr,size,*value,ex1850_pc(),c.cr1,c.sr,c.dier,
            c.ccmr[0],c.ccmr[1],c.ccer,c.cnt,c.psc,c.arr,c.active_psc,c.active_arr,
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),count);
    }
    return true;
}
#endif
