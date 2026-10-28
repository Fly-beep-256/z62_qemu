/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Generated from WonderLantern/z6-qemu. Z6II save-table checked.
 * Functional MMIO shadow, reset-zero and1us ready completion hypotheses.
 * Z6II native callers: master10207310/102070c0, slave10053b18/100538b0. */
static const uint32_t z6ii_platform_saved_addresses[] = {
    0x20010038, 0x2001003c, 0x20010100, 0x20010104, 0x20010108,
    0x2001010c, 0x20010110, 0x20010114, 0x20010118, 0x2001011c,
    0x20015004, 0x20015020, 0x20015024, 0x20015028, 0x2001502c,
    0x20015030, 0x20015034, 0x20015038, 0x2001503c,
};

static void z6ii_platform_complete(void *opaque)
{
    Z6IIState *s = opaque;
    s->platform_regs[0x38 / 4] |= 1;
    fprintf(stderr, "Z6II_PLATFORM_COMPLETE ready=1\n");
}

static bool z6ii_platform_access(Z6IIState *s, hwaddr addr, unsigned size,
                               bool write, uint64_t *value)
{
    unsigned off, index;
    bool config = false, saved = false;
    if (!s->platform_profile || size != 4 || (addr & 3)) { return false; }
    /* Save/read and restore/write windows are paired by 101044e6/101042dc.
     * Shared backing is a model hypothesis, not a confirmed physical alias. */
    if ((!write && addr >= 0x20014800 && addr < 0x20015000) ||
        (write && addr >= 0x24074000 && addr < 0x24074800)) {
        if (write) {
            if (s->platform_regs[0x60 / 4] != 1) { return false; }
            s->platform_saved[(addr - 0x24074000) / 4] = *value;
        } else {
            /* Debugger inspection is side-effect free and need not open the gate. */
            if (current_cpu && s->platform_regs[0x44 / 4] != 1) { return false; }
            *value = s->platform_saved[(addr - 0x20014800) / 4];
        }
        z6ii_trace(s, addr, size, write, *value);
        return true;
    }
    if (addr < 0x20010000 || addr >= 0x20017000) { return false; }
    off = addr - 0x20010000;
    index = off / 4;
    for (unsigned n = 0; n < ARRAY_SIZE(z6ii_platform_saved_addresses); n++) {
        if (addr == z6ii_platform_saved_addresses[n]) { saved = true; break; }
    }
    /* Exact table-driven stores in 101042dc: four 23+8-word groups,
     * four 8-word groups, four scalar words, four 9-word groups and five tails. */
    config = (off >= 0x3000 && off < 0x3400 &&
              ((off & 0xff) < 0x5c || ((off & 0xff) >= 0xbc && (off & 0xff) < 0xdc))) ||
             (off >= 0x6a00 && off < 0x6a80) ||
             (off >= 0x5010 && off <= 0x501c) ||
             (off >= 0x2000 && off < 0x2064 && (off & 0x3f) < 0x24) ||
             (off >= 0x2100 && off < 0x2164 && (off & 0x3f) < 0x24) ||
             off == 0x2648 || off == 0x2490 || off == 0x24a0 ||
             off == 0x2790 || off == 0x2798 ||
             off == 0x2618 || off == 0x2628 || off == 0x2638 ||
             off == 0x2640 || off == 0x2658 || off == 0x2660 ||
             off == 0x27a8 || off == 0x27b0;
    if (!saved && !config && off != 0x34 && off != 0x44 && off != 0x60) {
        return false;
    }
    if (write) {
        if (saved && current_cpu && s->platform_regs[0x60 / 4] != 1) { return false; }
        if ((off == 0x34 || off == 0x44 || off == 0x60) && *value > 1) { return false; }
        s->platform_regs[index] = *value;
        s->platform_written[index] = true;
        if (off == 0x34 && *value == 1) {
            /* Observed command -> poll bit 0. One microsecond is an explicit
             * virtual latency hypothesis, not a measured hardware duration. */
            s->platform_regs[0x38 / 4] &= ~1U;
            timer_mod(s->platform_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 1000);
            fprintf(stderr, "Z6II_PLATFORM_COMMAND ready=0 latency_ns=1000\n");
        }
    } else {
        if (!saved && !s->platform_written[index]) { return false; }
        *value = s->platform_regs[index];
    }
    z6ii_trace(s, addr, size, write, *value);
    return true;
}

