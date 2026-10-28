/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Bounded STM32F412 RTC functional contract, RM0402 Rev7 pp617-622,
 * 630-642,648-649. LSE=32768Hz, 24h, shadow calendar and alarms A/B.
 * Initialization uses the allowed 2-cycle INITF choice and 4-cycle restart.
 * Initial oscillator phase and cross-domain latency are model choices, not
 * measured camera behavior. Alarm control uses independent 2-LSE-cycle
 * synchronizers; W0C flags use 2 APB cycles even with LSE stopped. Alarm
 * comparison occurs on counter updates (including subsecond reload at
 * restart), never merely because software enables or clears a flag.
 * No host date or retained backup data is used. */
#ifndef EX1850_RTC_CORE_H
#define EX1850_RTC_CORE_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define EX1850_RTC_HZ 32768U
#define EX1850_RTC_NS UINT64_C(1000000000)
#define EX1850_RTC_INITS (1U << 4)
#define EX1850_RTC_RSF (1U << 5)
#define EX1850_RTC_INITF (1U << 6)
#define EX1850_RTC_INIT (1U << 7)
#define EX1850_RTC_INIT_CYCLES 2U
#define EX1850_RTC_RESTART_CYCLES 4U
#define EX1850_RTC_ALRAE (1U << 8)
#define EX1850_RTC_ALRBE (1U << 9)
#define EX1850_RTC_ALRAIE (1U << 12)
#define EX1850_RTC_ALRBIE (1U << 13)
#define EX1850_RTC_ALARM_CONTROL UINT32_C(0x3300)
#define EX1850_RTC_ALARM_FLAGS UINT32_C(0x300)
#define EX1850_RTC_ALARM_CONTROL_CYCLES 2U

typedef void (*EX1850RTCOutput)(void *opaque, bool level,
                              uint64_t lse_cycle, int64_t virtual_ns);

typedef struct EX1850RTC {
    uint32_t isr, cr, prer, tafcr, tr, dr, ssr;
    uint32_t shadow_tr, shadow_dr, shadow_ssr, backup[20];
    unsigned wpr_stage, async_phase;
    bool clock_active, running, tr_locked, dr_locked;
    bool init_pending, restart_pending, sync_pending;
    int64_t epoch_ns;
    /* fraction is the numerator of the fractional active LSE cycle, with
     * denominator 1e9. Both it and whole cycles survive clock gating. */
    uint64_t cycles, fraction, counter_cycle, shadow_cycle;
    uint64_t init_due, restart_due, sync_due;
    uint64_t calendar_ticks, init_events, restart_events, sync_events;
    uint32_t alarm[2], alarm_ss[2], alarm_control;
    uint64_t alarm_control_due[4], alarm_events[2], alarm_clear_events[2];
    int64_t alarm_clear_due[2];
    int64_t alarm_last_ns[2], alarm_clear_last_ns[2];
    uint64_t alarm_last_cycle[2], output_edges;
    bool output_level;
    EX1850RTCOutput output;
    void *output_opaque;
} EX1850RTC;

typedef enum EX1850RTCResult {
    EX1850_RTC_OK,
    EX1850_RTC_UNSUPPORTED,
    EX1850_RTC_BAD_SIZE,
    EX1850_RTC_RESERVED_BITS,
    EX1850_RTC_INVALID_CALENDAR,
    EX1850_RTC_LOW_PCLK,
    EX1850_RTC_EARLY_INIT_CANCEL,
} EX1850RTCResult;

static inline unsigned ex1850_rtc_bcd(uint32_t value)
{
    return (value & 15) + 10 * ((value >> 4) & 15);
}

static inline uint32_t ex1850_rtc_encode(unsigned value)
{
    return value % 10 | ((value / 10) << 4);
}

static inline unsigned ex1850_rtc_days(unsigned month, unsigned year)
{
    static const unsigned days[12] = {
        31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
    };
    return days[month - 1] + (month == 2 && year % 4 == 0);
}

static inline void ex1850_rtc_inits(EX1850RTC *r)
{
    r->isr = (r->isr & ~EX1850_RTC_INITS) |
             ((r->dr & 0xff0000) ? EX1850_RTC_INITS : 0);
}

static inline void ex1850_rtc_reset(EX1850RTC *r, int64_t now)
{
    memset(r, 0, sizeof(*r));
    r->isr = 7;
    r->prer = 0x7f00ff;
    r->dr = r->shadow_dr = 0x2101;
    r->epoch_ns = now;
    r->running = true;
    r->sync_pending = true;
    r->sync_due = 2;
    for (unsigned i = 0; i < 4; i++) { r->alarm_control_due[i] = UINT64_MAX; }
    r->alarm_clear_due[0] = r->alarm_clear_due[1] = -1;
}

static inline void ex1850_rtc_bind_output(EX1850RTC *r,
                                         EX1850RTCOutput output, void *opaque)
{
    r->output = output;
    r->output_opaque = opaque;
}

static inline void ex1850_rtc_output_update(EX1850RTC *r, int64_t now)
{
    /* RM0402 p630 table114. OSEL/POL route the separate external pin and
     * do not invert, select or mask this internal interrupt signal. */
    bool level = !!((r->isr & (r->alarm_control >> 4)) & EX1850_RTC_ALARM_FLAGS);
    if (level != r->output_level) {
        r->output_level = level;
        r->output_edges++;
        if (r->output) { r->output(r->output_opaque, level, r->cycles, now); }
    }
}

static inline void ex1850_rtc_alarm_write_flags(EX1850RTC *r)
{
    r->isr &= ~UINT32_C(3);
    if (!(r->isr & EX1850_RTC_INIT) && !r->restart_pending) {
        r->isr |= (~r->alarm_control >> 8) & 3;
    }
}

static inline void ex1850_rtc_add_seconds(EX1850RTC *r, uint64_t seconds)
{
    unsigned second = ex1850_rtc_bcd(r->tr & 0x7f);
    unsigned minute = ex1850_rtc_bcd((r->tr >> 8) & 0x7f);
    unsigned hour = ex1850_rtc_bcd((r->tr >> 16) & 0x3f);
    unsigned day = ex1850_rtc_bcd(r->dr & 0x3f);
    unsigned month = ex1850_rtc_bcd((r->dr >> 8) & 0x1f);
    unsigned year = ex1850_rtc_bcd((r->dr >> 16) & 0xff);
    unsigned weekday = (r->dr >> 13) & 7;
    uint64_t time = hour * 3600 + minute * 60 + second + seconds;
    uint64_t days = time / 86400;
    weekday = (weekday - 1 + days % 7) % 7 + 1;
    time %= 86400;
    while (days) {
        unsigned left = ex1850_rtc_days(month, year) - day;
        if (days <= left) {
            day += days;
            break;
        }
        days -= left + 1;
        day = 1;
        if (++month > 12) {
            month = 1;
            year = (year + 1) % 100;
        }
    }
    r->tr = ex1850_rtc_encode(time % 60) |
            (ex1850_rtc_encode(time / 60 % 60) << 8) |
            (ex1850_rtc_encode(time / 3600) << 16);
    r->dr = ex1850_rtc_encode(day) | (ex1850_rtc_encode(month) << 8) |
            (weekday << 13) | (ex1850_rtc_encode(year) << 16);
    r->calendar_ticks += seconds;
    ex1850_rtc_inits(r);
}

static inline bool ex1850_rtc_alarm_calendar_match(const EX1850RTC *r,
                                                 uint32_t a)
{
    if (!(a & (1U << 7)) && (a & 0x7f) != (r->tr & 0x7f)) { return false; }
    if (!(a & (1U << 15)) && (a & 0x7f00) != (r->tr & 0x7f00)) { return false; }
    if (!(a & (1U << 23)) && (a & 0x7f0000) != (r->tr & 0x7f0000)) {
        return false;
    }
    if (!(a & (1U << 31))) {
        if (a & (1U << 30)) {
            if (((a >> 24) & 15) != ((r->dr >> 13) & 7)) { return false; }
        } else if (((a >> 24) & 0x3f) != (r->dr & 0x3f)) {
            return false;
        }
    }
    return true;
}

/* Find the first allowed time >= minimum in one day. All alarm bits are
 * readable/writable even for invalid BCD; an invalid unmasked value cannot
 * match the valid 24h calendar. Masked fields are ignored, including PM. */
static inline unsigned ex1850_rtc_alarm_time(uint32_t a, unsigned minimum)
{
    unsigned h = ex1850_rtc_bcd((a >> 16) & 0x3f);
    unsigned m = ex1850_rtc_bcd((a >> 8) & 0x7f);
    unsigned s = ex1850_rtc_bcd(a & 0x7f);
    if ((!(a & (1U << 23)) &&
         (h >= 24 || ((a >> 16) & 15) >= 10 || (a & (1U << 22)))) ||
        (!(a & (1U << 15)) && (m >= 60 || ((a >> 8) & 15) >= 10)) ||
        (!(a & (1U << 7)) && (s >= 60 || (a & 15) >= 10))) {
        return UINT32_MAX;
    }
    for (unsigned hour = minimum / 3600; hour < 24; hour++) {
        if (!(a & (1U << 23)) && hour != h) { continue; }
        unsigned min_minute = hour == minimum / 3600 ? minimum / 60 % 60 : 0;
        for (unsigned minute = min_minute; minute < 60; minute++) {
            if (!(a & (1U << 15)) && minute != m) { continue; }
            unsigned min_second = hour == minimum / 3600 &&
                minute == minimum / 60 % 60 ? minimum % 60 : 0;
            unsigned second = (a & (1U << 7)) ? min_second : s;
            if (second >= min_second) { return hour * 3600 + minute * 60 + second; }
        }
    }
    return UINT32_MAX;
}

/* Calendar fields recur within 62 days (the longest interval between dates
 * 31 is 61 days). Search days, not every second or LSE tick. The current
 * second is considered separately by the subsecond scheduler below. */
static inline uint64_t ex1850_rtc_alarm_next_second(const EX1850RTC *r,
                                                   uint32_t a)
{
    if (!(a & (1U << 31))) {
        unsigned day = (a >> 24) & ((a & (1U << 30)) ? 15 : 0x3f);
        if (a & (1U << 30)) {
            if (day < 1 || day > 7) { return UINT64_MAX; }
        } else if ((day & 15) >= 10 || ex1850_rtc_bcd(day) < 1 ||
                   ex1850_rtc_bcd(day) > 31) {
            return UINT64_MAX;
        }
    }
    if (ex1850_rtc_alarm_time(a, 0) == UINT32_MAX) { return UINT64_MAX; }
    unsigned time = ex1850_rtc_bcd((r->tr >> 16) & 0x3f) * 3600 +
                    ex1850_rtc_bcd((r->tr >> 8) & 0x7f) * 60 +
                    ex1850_rtc_bcd(r->tr & 0x7f);
    EX1850RTC c = *r;
    for (unsigned day = 0; day <= 62; day++) {
        if (day) { ex1850_rtc_add_seconds(&c, day == 1 ? 86400 - time : 86400); }
        /* Test only the date portion here. The time is found independently. */
        if (!ex1850_rtc_alarm_calendar_match(&c, a | UINT32_C(0x00808080))) {
            continue;
        }
        unsigned next = ex1850_rtc_alarm_time(a, day ? 0 : time + 1);
        if (next != UINT32_MAX) { return (uint64_t)day * 86400 + next - time; }
    }
    return UINT64_MAX;
}

static inline uint64_t ex1850_rtc_alarm_deadline_cycle(const EX1850RTC *r)
{
    if (!r->running) { return UINT64_MAX; }
    unsigned a = ((r->prer >> 16) & 0x7f) + 1;
    unsigned s = r->prer & 0x7fff;
    uint64_t second = r->cycles + (uint64_t)(r->ssr + 1) * a - r->async_phase;
    uint64_t due = UINT64_MAX;
    for (unsigned i = 0; i < 2; i++) {
        uint32_t bit = 1U << (8 + i);
        if (!(r->alarm_control & bit) || (r->isr & bit)) { continue; }
        unsigned n = (r->alarm_ss[i] >> 24) & 15;
        unsigned mask = (1U << n) - 1;
        unsigned low = r->alarm_ss[i] & mask;
        if (n && low > s) { continue; }
        if (n && ex1850_rtc_alarm_calendar_match(r, r->alarm[i])) {
            unsigned edges = (r->ssr - low) & mask;
            if (!edges) { edges = mask + 1; }
            if (edges <= r->ssr) {
                uint64_t current = r->cycles + (uint64_t)edges * a - r->async_phase;
                if (current < due) { due = current; }
            }
        }
        uint64_t delta = ex1850_rtc_alarm_next_second(r, r->alarm[i]);
        if (delta != UINT64_MAX) {
            unsigned below_reload = n ? ((s - low) & mask) : 0;
            uint64_t next = second + (delta - 1) * (s + 1) * a +
                            (uint64_t)below_reload * a;
            if (next < due) { due = next; }
        }
    }
    return due;
}

static inline void ex1850_rtc_alarm_compare(EX1850RTC *r,
                                            bool second_increment, int64_t now)
{
    for (unsigned i = 0; i < 2; i++) {
        uint32_t bit = 1U << (8 + i);
        unsigned n = (r->alarm_ss[i] >> 24) & 15;
        unsigned mask = (1U << n) - 1;
        if (r->running && (r->alarm_control & bit) && !(r->isr & bit) &&
            (n ? ((r->ssr & mask) == (r->alarm_ss[i] & mask)) : second_increment) &&
            ex1850_rtc_alarm_calendar_match(r, r->alarm[i])) {
            r->isr |= bit;
            r->alarm_events[i]++;
            r->alarm_last_cycle[i] = r->cycles;
            r->alarm_last_ns[i] = now;
        }
    }
    /* Combine simultaneous A/B before delivering their shared output. */
    ex1850_rtc_output_update(r, now);
}

static inline int64_t ex1850_rtc_cycle_time(uint64_t base_cycle,
    uint64_t base_fraction, int64_t base_ns, uint64_t cycle)
{
    if (cycle <= base_cycle) { return base_ns; }
    __uint128_t numerator = (__uint128_t)(cycle - base_cycle) * EX1850_RTC_NS - base_fraction;
    __uint128_t delta = (numerator + EX1850_RTC_HZ - 1) / EX1850_RTC_HZ;
    return delta > (uint64_t)(INT64_MAX - base_ns) ? INT64_MAX : base_ns + (int64_t)delta;
}

static inline void ex1850_rtc_count_to(EX1850RTC *r, uint64_t cycle)
{
    if (r->running) {
        unsigned a = ((r->prer >> 16) & 0x7f) + 1;
        unsigned s = r->prer & 0x7fff;
        uint64_t elapsed = cycle - r->counter_cycle + r->async_phase;
        uint64_t edges = elapsed / a;
        r->async_phase = elapsed % a;
        if (edges <= r->ssr) {
            r->ssr -= edges;
        } else {
            uint64_t remaining = edges - r->ssr - 1;
            uint64_t seconds = 1 + remaining / (s + 1);
            r->ssr = s - remaining % (s + 1);
            ex1850_rtc_add_seconds(r, seconds);
        }
    }
    r->counter_cycle = cycle;
}

static inline void ex1850_rtc_sample(EX1850RTC *r, uint64_t cycle)
{
    r->shadow_ssr = r->ssr;
    if (!r->tr_locked) {
        r->shadow_tr = r->tr;
    }
    if (!r->dr_locked) {
        r->shadow_dr = r->dr;
    }
    r->shadow_cycle = cycle;
    if (r->sync_pending && cycle >= r->sync_due) {
        r->isr |= EX1850_RTC_RSF;
        r->sync_pending = false;
        r->sync_events++;
    }
}

static inline void ex1850_rtc_interval(EX1850RTC *r, uint64_t cycle)
{
    uint64_t sample = cycle & ~UINT64_C(1);
    if (!(r->isr & EX1850_RTC_INIT) && !r->restart_pending) {
        if (sample > r->shadow_cycle) {
            /* Split at the latest two-LSE-cycle sample before counting the
             * final odd cycle. Odd prescalers must not mix seconds here. */
            ex1850_rtc_count_to(r, sample);
            ex1850_rtc_sample(r, sample);
        }
    } else {
        r->shadow_cycle = sample;
    }
    ex1850_rtc_count_to(r, cycle);
}

static inline void ex1850_rtc_sync_lse(EX1850RTC *r, int64_t now)
{
    uint64_t elapsed = now > r->epoch_ns ? (uint64_t)(now - r->epoch_ns) : 0;
    uint64_t base_cycle = r->cycles, base_fraction = r->fraction;
    int64_t base_ns = r->epoch_ns;
    uint64_t target = r->cycles;
    if (!r->clock_active) {
        r->epoch_ns = now;
        return;
    }
    /* Split seconds and remainder: neither multiplication can overflow for
     * nonnegative signed-64-bit virtual time. No repeated ceil periods. */
    uint64_t partial = (elapsed % EX1850_RTC_NS) * EX1850_RTC_HZ + r->fraction;
    target += (elapsed / EX1850_RTC_NS) * EX1850_RTC_HZ + partial / EX1850_RTC_NS;
    r->fraction = partial % EX1850_RTC_NS;
    for (;;) {
        uint64_t due = UINT64_MAX;
        if (r->init_pending && r->init_due < due) { due = r->init_due; }
        if (r->restart_pending && r->restart_due < due) { due = r->restart_due; }
        if (r->sync_pending && !r->restart_pending && r->sync_due < due) {
            due = r->sync_due;
        }
        for (unsigned i = 0; i < 4; i++) {
            if (r->alarm_control_due[i] < due) { due = r->alarm_control_due[i]; }
        }
        uint64_t alarm_due = ex1850_rtc_alarm_deadline_cycle(r);
        if (alarm_due < due) { due = alarm_due; }
        if (due > target) { break; }
        uint64_t previous_ticks = r->calendar_ticks;
        ex1850_rtc_interval(r, due);
        r->cycles = due;
        int64_t event_ns = ex1850_rtc_cycle_time(base_cycle, base_fraction, base_ns, due);
        if (alarm_due == due) {
            ex1850_rtc_alarm_compare(r, r->calendar_ticks != previous_ticks, event_ns);
        }
        if (r->init_pending && due == r->init_due) {
            r->init_pending = false;
            r->isr |= EX1850_RTC_INITF;
            r->init_events++;
        }
        if (r->restart_pending && due == r->restart_due) {
            r->restart_pending = false;
            r->running = true;
            r->async_phase = 0;
            r->ssr = r->prer & 0x7fff;
            r->restart_events++;
            r->sync_pending = true;
            r->sync_due = (due + 1) & ~UINT64_C(1);
            if (!(due & 1)) { ex1850_rtc_sample(r, due); }
            ex1850_rtc_alarm_write_flags(r);
            ex1850_rtc_alarm_compare(r, false, event_ns);
        }
        bool control_changed = false;
        for (unsigned i = 0; i < 4; i++) {
            if (r->alarm_control_due[i] == due) {
                uint32_t bit = 1U << (i < 2 ? 8 + i : 10 + i);
                r->alarm_control = (r->alarm_control & ~bit) | (r->cr & bit);
                r->alarm_control_due[i] = UINT64_MAX;
                control_changed = true;
            }
        }
        if (control_changed) {
            ex1850_rtc_alarm_write_flags(r);
            ex1850_rtc_output_update(r, event_ns);
        }
    }
    ex1850_rtc_interval(r, target);
    r->cycles = target;
    r->epoch_ns = now;
}

static inline void ex1850_rtc_sync(EX1850RTC *r, int64_t now)
{
    if (now < r->epoch_ns) { return; }
    for (;;) {
        int64_t due = INT64_MAX;
        bool clear_pending = false;
        for (unsigned i = 0; i < 2; i++) {
            if (r->alarm_clear_due[i] >= 0 && r->alarm_clear_due[i] <= now) {
                if (r->alarm_clear_due[i] < due) { due = r->alarm_clear_due[i]; }
                clear_pending = true;
            }
        }
        if (!clear_pending) { break; }
        /* At an exact coincident timestamp the new RTC event must survive.
         * Flush earlier LSE events, clear APB flags, then take the edge at
         * 'due'. Clear deadlines progress even when RTCEN/LSE is gated. */
        if (due > r->epoch_ns) { ex1850_rtc_sync_lse(r, due - 1); }
        for (unsigned i = 0; i < 2; i++) {
            if (r->alarm_clear_due[i] == due) {
                r->isr &= ~(1U << (8 + i));
                r->alarm_clear_due[i] = -1;
                r->alarm_clear_events[i]++;
                r->alarm_clear_last_ns[i] = due;
            }
        }
        ex1850_rtc_output_update(r, due);
        ex1850_rtc_sync_lse(r, due);
    }
    ex1850_rtc_sync_lse(r, now);
}

static inline void ex1850_rtc_set_clock(EX1850RTC *r, bool active, int64_t now)
{
    ex1850_rtc_sync(r, now);
    r->clock_active = active;
}

static inline int64_t ex1850_rtc_deadline(const EX1850RTC *r)
{
    uint64_t cycle = UINT64_MAX;
    int64_t deadline = -1;
    for (unsigned i = 0; i < 2; i++) {
        if (r->alarm_clear_due[i] >= 0 &&
            (deadline < 0 || r->alarm_clear_due[i] < deadline)) {
            deadline = r->alarm_clear_due[i];
        }
    }
    if (r->clock_active) {
        if (r->init_pending) { cycle = r->init_due; }
        if (r->restart_pending && r->restart_due < cycle) { cycle = r->restart_due; }
        if (r->sync_pending && !r->restart_pending && r->sync_due < cycle) {
            cycle = r->sync_due;
        }
        for (unsigned i = 0; i < 4; i++) {
            if (r->alarm_control_due[i] < cycle) { cycle = r->alarm_control_due[i]; }
        }
        uint64_t alarm = ex1850_rtc_alarm_deadline_cycle(r);
        if (alarm < cycle) { cycle = alarm; }
        if (r->running) {
            uint64_t second = r->cycles +
                ((r->ssr + 1) * (((r->prer >> 16) & 0x7f) + 1)) - r->async_phase;
            if (second < cycle) { cycle = second; }
        }
        if (cycle != UINT64_MAX) {
            int64_t due = ex1850_rtc_cycle_time(r->cycles, r->fraction, r->epoch_ns, cycle);
            if (deadline < 0 || due < deadline) { deadline = due; }
        }
    }
    return deadline;
}

static inline bool ex1850_rtc_calendar_valid(unsigned offset, uint32_t value)
{
    if (offset == 0) {
        return !(value & ~UINT32_C(0x003f7f7f)) &&
            ex1850_rtc_bcd(value & 0x7f) < 60 &&
            ex1850_rtc_bcd((value >> 8) & 0x7f) < 60 &&
            ex1850_rtc_bcd((value >> 16) & 0x3f) < 24 &&
            (value & 15) < 10 && ((value >> 8) & 15) < 10 &&
            ((value >> 16) & 15) < 10;
    }
    unsigned day = ex1850_rtc_bcd(value & 0x3f);
    unsigned month = ex1850_rtc_bcd((value >> 8) & 0x1f);
    unsigned year = ex1850_rtc_bcd((value >> 16) & 0xff);
    unsigned weekday = (value >> 13) & 7;
    return !(value & ~UINT32_C(0x00ffff3f)) &&
        month >= 1 && month <= 12 && day >= 1 &&
        day <= ex1850_rtc_days(month, year) && weekday >= 1 && weekday <= 7 &&
        (value & 15) < 10 && ((value >> 8) & 15) < 10 &&
        ((value >> 16) & 15) < 10 && ((value >> 20) & 15) < 10;
}

static inline EX1850RTCResult ex1850_rtc_access(EX1850RTC *r,
    unsigned offset, unsigned size, bool write, uint32_t *value,
    bool dbp, unsigned pclk, int64_t now, bool *ignored)
{
    ex1850_rtc_sync(r, now);
    *ignored = false;
    if (offset == 0x24 && write) {
        if (size != 1 && size != 4) { return EX1850_RTC_BAD_SIZE; }
        if (*value > 0xff) { return EX1850_RTC_RESERVED_BITS; }
        if (!dbp) { *ignored = true; return EX1850_RTC_OK; }
        r->wpr_stage = *value == 0xca ? 1 :
            (*value == 0x53 && r->wpr_stage == 1 ? 2 : 0);
        return EX1850_RTC_OK;
    }
    if (size != 4 || (offset & 3)) { return EX1850_RTC_BAD_SIZE; }
    if (offset == 0x28 && write) { return EX1850_RTC_UNSUPPORTED; }
    if (!write && (offset == 0 || offset == 4 || offset == 0x28)) {
        if (pclk < 7 * EX1850_RTC_HZ) { return EX1850_RTC_LOW_PCLK; }
        if (offset == 0x28) {
            *value = r->shadow_ssr;
            r->tr_locked = r->dr_locked = true;
        } else if (!offset) {
            *value = r->shadow_tr;
            r->dr_locked = true;
        } else {
            *value = r->shadow_dr;
            r->tr_locked = r->dr_locked = false;
            /* Do not update from live here; the next sample does that. */
        }
        return EX1850_RTC_OK;
    }
    if (offset == 0 || offset == 4) {
        if (!ex1850_rtc_calendar_valid(offset, *value)) {
            return EX1850_RTC_INVALID_CALENDAR;
        }
        *ignored = !dbp || r->wpr_stage != 2 || !(r->isr & EX1850_RTC_INITF);
        if (!*ignored) {
            if (!offset) { r->tr = *value; } else { r->dr = *value; }
            ex1850_rtc_inits(r);
        }
        return EX1850_RTC_OK;
    }
    if (offset == 0x0c) {
        if (!write) { *value = r->isr; return EX1850_RTC_OK; }
        *ignored = !dbp || r->wpr_stage != 2;
        if (!dbp) { return EX1850_RTC_OK; }
        bool before = !!(r->isr & EX1850_RTC_INIT);
        bool init = !!(*value & EX1850_RTC_INIT);
        if (r->wpr_stage == 2 && before && !init && !(r->isr & EX1850_RTC_INITF)) {
            return EX1850_RTC_EARLY_INIT_CANCEL;
        }
        /* RTC_ISR[31:8] is explicitly not protected by WPR (p619).
         * Only an already observed/set alarm flag schedules a W0C clear;
         * writing zero to an unset flag must not erase a future event. */
        for (unsigned i = 0; i < 2; i++) {
            uint32_t bit = 1U << (8 + i);
            if ((r->isr & bit) && !(*value & bit) && r->alarm_clear_due[i] < 0) {
                if (!pclk) { return EX1850_RTC_LOW_PCLK; }
                uint64_t delay = (2 * EX1850_RTC_NS + pclk - 1) / pclk;
                r->alarm_clear_due[i] = delay > (uint64_t)(INT64_MAX - now) ?
                    INT64_MAX : now + (int64_t)delay;
            }
        }
        if (r->wpr_stage != 2) { return EX1850_RTC_OK; }
        if (!(*value & EX1850_RTC_RSF)) {
            r->isr &= ~EX1850_RTC_RSF;
            r->sync_pending = !init;
            r->sync_due = (r->cycles + 2) & ~UINT64_C(1);
        }
        if (!before && init) {
            r->isr = (r->isr & ~EX1850_RTC_RSF) | EX1850_RTC_INIT;
            r->running = false;
            r->restart_pending = r->sync_pending = false;
            r->init_pending = true;
            r->init_due = r->cycles + EX1850_RTC_INIT_CYCLES;
        } else if (before && !init) {
            r->isr &= ~(EX1850_RTC_INIT | EX1850_RTC_INITF | EX1850_RTC_RSF);
            r->restart_pending = true;
            r->restart_due = r->cycles + EX1850_RTC_RESTART_CYCLES;
            r->sync_pending = false;
        }
        ex1850_rtc_alarm_write_flags(r);
        ex1850_rtc_inits(r);
        return EX1850_RTC_OK;
    }
    if (offset == 0x1c || offset == 0x20 || offset == 0x44 || offset == 0x48) {
        bool subseconds = offset >= 0x44;
        unsigned i = (offset - (subseconds ? 0x44 : 0x1c)) / 4;
        uint32_t *alarm = subseconds ? &r->alarm_ss[i] : &r->alarm[i];
        if (!write) { *value = *alarm; return EX1850_RTC_OK; }
        if (subseconds && (*value & ~UINT32_C(0x0f007fff))) {
            return EX1850_RTC_RESERVED_BITS;
        }
        bool allowed = (r->isr & EX1850_RTC_INITF) ||
            (subseconds ? !(r->cr & (1U << (8 + i))) : (r->isr & (1U << i)));
        *ignored = !dbp || r->wpr_stage != 2 || !allowed;
        if (!*ignored) { *alarm = *value; }
        return EX1850_RTC_OK;
    }
    uint32_t *reg, mask;
    if (offset >= 0x50 && offset <= 0x9c) {
        reg = &r->backup[(offset - 0x50) / 4];
        mask = UINT32_MAX;
    } else if (offset == 8) {
        reg = &r->cr;
        mask = 0x00743300;
    } else if (offset == 0x10) {
        reg = &r->prer;
        mask = 0x007f7fff;
    } else if (offset == 0x40) {
        reg = &r->tafcr;
        mask = 0x00040000;
    } else {
        return EX1850_RTC_UNSUPPORTED;
    }
    if (!write) { *value = *reg; return EX1850_RTC_OK; }
    if (*value & ~mask) { return EX1850_RTC_RESERVED_BITS; }
    /* TAFCR and BKPxR are exceptions to WPR, but still need PWR.DBP. */
    *ignored = !dbp || ((offset == 8 || offset == 0x10) && r->wpr_stage != 2) ||
               (offset == 0x10 && !(r->isr & EX1850_RTC_INITF));
    if (!*ignored) {
        uint32_t old = *reg;
        *reg = *value;
        if (offset == 8) {
            for (unsigned i = 0; i < 4; i++) {
                uint32_t bit = 1U << (i < 2 ? 8 + i : 10 + i);
                if ((old ^ *value) & bit) {
                    r->alarm_control_due[i] = ((*value ^ r->alarm_control) & bit) ?
                        r->cycles + EX1850_RTC_ALARM_CONTROL_CYCLES : UINT64_MAX;
                }
            }
        }
    }
    return EX1850_RTC_OK;
}

#endif
