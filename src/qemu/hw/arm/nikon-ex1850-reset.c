/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Offline EX1850 reset-entry boundary board. The unmodified official image
 * supplies its own reset vector and C initializer. ARMv7M/NVIC/bitband are
 * QEMU architectural models. MCU identity, SRAM size and CPU frequency are
 * explicit functional hypotheses; this is not a measured Z6II MCU board.
 * RCC oscillator/PLL/switch timers, TIM5's internal upcounter and
 * control latches and bounded Flash sector/x32 operations implement
 * a bounded STM32F4-family functional hypothesis. Status bits are hardware
 * state, independent of polling counts; HSE can be absent for a negative
 * control. No application/RTOS completion flag is supplied. The
 * Cortex-M clock now begins at the ROM's 16MHz HSI constant; the exact
 * physical MCU/reset defaults remain unverified family hypotheses.
 * Unknown MMIO terminates the
 * owned QEMU process before returning a value to guest code. No callbacks,
 * firmware ready-bit fixtures, packet replay, calibrated data or RTOS
 * results are supplied. Hardware oscillator/RTC status follows clock state.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/visitor.h"
#include "qemu/error-report.h"
#include "qemu/timer.h"
#include "qemu/main-loop.h"
#include "qemu/cutils.h"
#include "qemu/guest-random.h"
#include "chardev/char-fe.h"
#include "mcu_wire_posix.h"
#include "ex1850-tim12-core.h"
#include "ex1850-tim1-core.h"
#include "ex1850-tim10-core.h"
#include "ex1850-tim234-core.h"
#include "ex1850-spi-apb1-control.h"
#include "ex1850-spi2-dma-core.h"
#include "ex1850-usart2-core.h"
#include "ex1850-usart1-rx-core.h"
#include "ex1850-flash-core.h"
#include "ex1850-flash-wait-core.h"
#include "ex1850-rtc-core.h"
#include "ex1850-rtc-exti-core.h"
#include "ex1850-gpio-exti-core.h"
#include "ex1850-power-core.h"
#include "hw/boards.h"
#include "hw/arm/machines-qom.h"
#include "hw/arm/armv7m.h"
#include "hw/arm/boot.h"
#include "hw/qdev-properties.h"
#include "hw/qdev-clock.h"
#include "hw/irq.h"
#include "system/address-spaces.h"
#include "system/reset.h"
#include "system/system.h"
#include "qemu/notify.h"
#include "target/arm/cpu.h"
#include "accel/tcg/cpu-ops.h"
#include "hw/core/sysemu-cpu-ops.h"
#include "exec/translation-block.h"
#include "exec/cpu-common.h"
#include "exec/target_page.h"
#include "exec/cpu-interrupt.h"
/* Pinned QEMU 10.2.4 curr_cflags(), also used by its I/O-retry path. */
#include "accel/tcg/internal-common.h"

#define EX1850_BASE 0x08000000
#define EX1850_BYTES 0x80000
#define EX1850_RAM_BASE 0x20000000
#define EX1850_RAM_BYTES 0x40000
#define EX1850_SHA "4314c17d9a6676a4254aa4d74d4aa35411e3a793ea7056c06f9c83f160da3cb1"
#define EX1850_HSI_HZ 16000000
#define EX1850_HSE_HZ 10000000
#define EX1850_CPU_CPUID 0x410fc241
#define TYPE_EX1850_M4_R0P1 ARM_CPU_TYPE_NAME("nikon-ex1850-m4-r0p1")

/* Sampling affects text only. Initial accesses and logarithmic later samples
 * retain useful context without formatting millions of routine events. The
 * counters cover every call reaching this logger, including suppressed calls;
 * existing per-register filters can run before it. Pad edges, strict boundaries
 * and faults use independent unsampled messages and the bounded host sink. */
#define EX1850_LOG_SLOTS 256
#define EX1850_LOG_INITIAL 128
typedef struct EX1850LogCounter {
    const char *format;
    uint64_t total, emitted;
} EX1850LogCounter;
static EX1850LogCounter ex1850_log_counters[EX1850_LOG_SLOTS];
static uint64_t ex1850_log_slot_overflow;
static bool ex1850_log_summary_reported;

static void ex1850_log_summary(void)
{
    if (ex1850_log_summary_reported) { return; }
    ex1850_log_summary_reported = true;
    for (unsigned i = 0; i < ARRAY_SIZE(ex1850_log_counters); i++) {
        EX1850LogCounter *c = &ex1850_log_counters[i];
        if (!c->format) { continue; }
        fprintf(stderr, "EX1850_LOG_SUMMARY slot=%u token=%.*s calls=%" PRIu64
                " emitted=%" PRIu64 " suppressed=%" PRIu64
                " source=producer_logger_calls hardware_execution_unchanged=1\n",
                i, (int)strcspn(c->format, " "), c->format,
                c->total, c->emitted, c->total - c->emitted);
    }
    fprintf(stderr, "EX1850_LOG_POLICY initial_per_format=%u later_samples=powers_of_two"
            " slots=%u slot_overflow_calls=%" PRIu64
            " full_routine_log_retained=0 hardware_execution_unchanged=1\n",
            EX1850_LOG_INITIAL, EX1850_LOG_SLOTS, ex1850_log_slot_overflow);
}

static void ex1850_log_exit(Notifier *notifier, void *data)
{
    (void)notifier;
    (void)data;
    ex1850_log_summary();
}
static Notifier ex1850_log_exit_notifier = { .notify = ex1850_log_exit };

static void ex1850_sampled_log(const char *format, ...)
{
    uintptr_t key = (uintptr_t)format;
    unsigned first = ((key >> 4) ^ (key >> 12)) & (EX1850_LOG_SLOTS - 1);
    EX1850LogCounter *c = NULL;
    for (unsigned probe = 0; probe < EX1850_LOG_SLOTS; probe++) {
        EX1850LogCounter *candidate = &ex1850_log_counters[
            (first + probe) & (EX1850_LOG_SLOTS - 1)];
        if (!candidate->format || candidate->format == format) {
            candidate->format = format;
            c = candidate;
            break;
        }
    }
    if (!c) { ex1850_log_slot_overflow++; return; }
    uint64_t count = ++c->total;
    if (count > EX1850_LOG_INITIAL && (count & (count - 1))) { return; }
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    c->emitted++;
    if (count == EX1850_LOG_INITIAL) {
        fprintf(stderr, "EX1850_LOG_SAMPLING slot=%u token=%.*s initial_limit=%u"
                " later_samples=powers_of_two hardware_execution_unchanged=1\n",
                (unsigned)(c - ex1850_log_counters), (int)strcspn(format, " "),
                format, EX1850_LOG_INITIAL);
    }
}
#define EX1850_PWR_CR_RESET 0x0000c000
#define EX1850_HSE_START_NS 100000
#define EX1850_PLL_LOCK_NS 100000
#define EX1850_SWITCH_NS 1000
#define EX1850_LSE_START_NS 100000000
#define EX1850_LSE_HZ 32768
#define EX1850_RTC_TRANSITION_CYCLES 2
#define RCC_HSION (1U << 0)
#define RCC_HSIRDY (1U << 1)
#define RCC_HSEON (1U << 16)
#define RCC_HSERDY (1U << 17)
#define RCC_HSEBYP (1U << 18)
#define RCC_PLLON (1U << 24)
#define RCC_PLLRDY (1U << 25)
#define RCC_LSEON (1U << 0)
#define RCC_LSERDY (1U << 1)
#define RCC_RTCEN (1U << 15)
#define RCC_BDRST (1U << 16)
#define RTC_RSF (1U << 5)
#define RTC_INITF (1U << 6)
#define RTC_INIT (1U << 7)
#define EX1850_RNG_AHB2_BIT (1U << 6)
#define EX1850_RNG_RNGEN (1U << 2)
#define EX1850_RNG_IE (1U << 3)
#define EX1850_RNG_DRDY (1U << 0)
#define EX1850_RNG_CECS (1U << 1)
#define EX1850_RNG_SECS (1U << 2)
#define EX1850_RNG_CEIS (1U << 5)
#define EX1850_RNG_SEIS (1U << 6)
#define EX1850_RNG_WORD_CYCLES 42
#define EX1850_RNG_START_CYCLES 4
#define EX1850_RNG_CYCLE_SCALE UINT64_C(1000000000)

typedef struct EX1850FlashWait {
    EX1850FlashWaitInsn decoded;
    uint32_t regs[16], xpsr, pending_seen;
    int64_t due;
    uint64_t completed_before;
    bool active;
} EX1850FlashWait;

typedef struct EX1850M4R0P1 {
    ARMCPU parent;
    struct EX1850ResetState *board;
    EX1850FlashWait wait;
} EX1850M4R0P1;

static const SysemuCPUOps *ex1850_parent_sysemu_ops;
static const TCGCPUOps *ex1850_parent_tcg_ops;
static SysemuCPUOps ex1850_mcu_sysemu_ops;
static TCGCPUOps ex1850_mcu_tcg_ops;

typedef struct EX1850GPIOControl {
    uint32_t moder, otyper, speed, pupdr, odr, afrl, afrh;
} EX1850GPIOControl;

typedef struct EX1850I2CControl {
    uint32_t cr1, cr2, oar1, oar2, ccr, trise;
    uint32_t sr1, sr2, dr;
} EX1850I2CControl;

typedef enum EX1850I2CAddressContract {
    EX1850_I2C_UNPROVIDED,
    EX1850_I2C_EXPLICIT_ABSENT,
    EX1850_I2C_PCAL6524,
    EX1850_I2C_MAX77711,
} EX1850I2CAddressContract;

typedef struct EX1850TIM234Event {
    struct EX1850ResetState *state;
    unsigned index;
} EX1850TIM234Event;

typedef struct EX1850ResetState {
    MemoryRegion rom, rom_alias, ram, unknown, flash_registers;
    EX1850Flash flash;
    QEMUTimer *flash_event;
    bool flash_irq4_level;
    uint64_t flash_read_counts[6];
    uint32_t flash_last_reads[6];
    unsigned flash_resets;
    ARMv7MState *armv7m;
    MCUWireMapping wire;
    QEMUTimer *wire_timer;
    uint64_t wire_poll_ns, wire_rx_bytes;
    uint32_t wire_ack_edges;
    uint32_t apb1enr, rcc_apb1rstr, rcc_ahb1rstr;
    uint32_t apb2enr, rcc_apb2rstr, ahb1enr, ahb2enr, rcc_ahb2rstr;
    uint32_t rng_cr, rng_sr, rng_dr;
    unsigned rng_hz;
    QEMUTimer *rng_event;
    bool rng_irq80_level;
    uint64_t rng_words;
    /* Explicit public simulation entropy; not a physical RNG sample. */
    uint32_t rng_public_words[64];
    unsigned rng_public_count, rng_public_index;
    uint64_t rng_start_remaining, rng_word_remaining;
    int64_t rng_epoch;
    uint32_t pwr_cr;
    EX1850Power power;
    bool systick_resume_enabled;
    uint32_t rcc_cr, pllcfgr, cfgr, rcc_bdcr;
    Clock *cpuclk;
    QEMUTimer *hse_timer, *pll_timer, *switch_timer, *lse_timer;
    bool hse_present, lse_present;
    unsigned cpu_hz;
    uint64_t read_counts[8];
    uint32_t last_reads[8];
    uint32_t tim5_cr1, tim5_cr2, tim5_smcr, tim5_sr;
    uint32_t tim5_psc, tim5_effective_psc, tim5_arr, tim5_cnt;
    int64_t tim5_epoch;
    uint64_t tim5_access_counts[12];
    QEMUTimer *tim5_overflow;
    uint32_t tim11_cr1, tim11_sr, tim11_psc, tim11_effective_psc, tim11_arr, tim11_cnt;
    uint32_t tim11_dier, tim11_ccer, tim11_ccr1;
    bool tim11_due_update, tim11_due_compare;
    int64_t tim11_epoch;
    QEMUTimer *tim11_overflow;
    uint64_t tim11_access_counts[21];
    EX1850TIM12 tim12;
    EX1850TIM1 tim1;
    EX1850TIM10 tim10;
    QEMUTimer *tim10_event;
    uint64_t tim10_access_counts[14];
    EX1850TIM234 tim234[3];
    QEMUTimer *tim234_event[3];
    EX1850TIM234Event tim234_event_data[3];
    uint64_t tim234_access_counts[3][17];
    QEMUTimer *tim1_event;
    uint64_t tim1_access_counts[20];
    EX1850APB1SPIControl apb1_spi;
    QEMUTimer *tim12_event;
    uint64_t tim12_access_counts[15];
    /* STM32F412 single-ADC configuration hypothesis. No conversion has
     * been admitted, so reset SR/DR never stand for sampled input. */
    uint32_t adc1_registers[20], adc_common_ccr;
    uint64_t adc_access_counts[22];
    uint32_t adc_last_reads[22];
    bool adc_voltage_profile[16], adc_busy, adc_irq18_level;
    uint32_t adc_pin_mv[16], adc_vref_mv, adc_conversion_total;
    unsigned adc_active_channel;
    uint16_t adc_sampled_code;
    int64_t adc_enable_epoch, adc_conversion_due;
    QEMUTimer *adc_conversion_timer;
    EX1850GPIOControl gpio[8];
    bool gpio_pin_profile[8];
    bool gpio_masked_readpin;
    uint16_t gpio_pin_levels[8];
    uint16_t gpio_pin_known_mask[8];
    uint64_t gpio_host_edge_count;
    uint64_t gpio_access_counts[8][10][2];
    uint32_t gpio_last_access[8][10][2];
    uint32_t gpio_last_observed[8][10][2];
    uint64_t wire_gpio_access_counts[8];
    uint16_t wire_gpio_known[8], wire_gpio_levels[8];
    uint32_t syscfg_exticr[4];
    uint32_t exti_pr, exti_imr, exti_emr, exti_rtsr, exti_ftsr;
    EX1850I2CControl i2c1, i2c2;
    EX1850SPI2DMA spi2_dma;
    QEMUTimer *spi2_event;
    bool spi2_irq15_level, spi2_irq36_level, dma1_irq16_level;
    EX1850USART2 usart1;
    EX1850USART1Rx usart1_rx;
    CharFrontend usart1_chr;
    bool usart1_line_enabled, usart1_line_open;
    uint64_t usart1_line_tx_bytes, usart1_line_rx_bytes;
    uint64_t usart1_line_tx_failures, usart1_line_events, usart1_irq_count;
    QEMUTimer *usart1_event;
    bool usart1_irq37_level;
    uint64_t usart1_access_count;
    EX1850USART2 usart2;
    QEMUTimer *usart2_event;
    bool usart2_irq38_level;
    uint64_t usart2_access_count;
    /* Explicit offline electrical scenarios, never camera observations:
     * 0 strict/unprovided, 1 released pull-up bus, 2 held-low SDA. */
    unsigned i2c_bus_mode;
    bool i2c_slave_absent;
    bool i2c_absent_address[128];
    /* Optional PCAL6524 protocol hypothesis, address strap VSS=0x22,
     * powered and RESET released. These board conditions are unmeasured;
     * undefined input values require a separate explicit pin scenario. */
    bool i2c_pcal6524;
    /* Opt-in MAX77511/MAX77711 family contract (ADI pp52,64).
     * VIO valid and PHCFG1/0 floating imply 7-bit address4F. The board
     * report lists MAX77711B; no rail, voltage, PGOOD or reset net is known.
     * B2_CNFG_D reset is OTP: never seed it with the guest's expected88. */
    bool i2c_max77711, max77711_value_known, max77711_pointer_known;
    uint8_t max77711_pointer, max77711_b2_cnfg_d;
    EX1850I2CAddressContract i2c_active_device;
    bool i2c_addr_sr1_read, i2c_repeated_start;
    unsigned i2c_pending_phase;
    uint8_t pcal_pointer;
    /* Optional caller-declared digital input environment. These levels
     * are never a PCAL reset default or a camera measurement. */
    bool pcal_pin_profile, i2c_rx_in_flight, i2c_rx_nacked;
    bool i2c_stop_waits_for_receive;
    bool i2c_start_waits_for_transmit, i2c_stop_waits_for_transmit;
    uint32_t pcal_pin_levels;
    struct {
        int64_t when_ns;
        uint32_t mask, levels;
    } pcal_pin_events[64];
    unsigned pcal_pin_event_count, pcal_pin_event_next;
    uint64_t pcal_host_edge_count;
    QEMUTimer *pcal_pin_event_timer;
    uint8_t pcal_sampled_levels[3], pcal_latched_levels[3];
    uint8_t pcal_latched_pending[3], pcal_edge_pending[3];
    uint8_t i2c_rx_data[2], i2c_rx_register[2];
    unsigned i2c_rx_count, i2c_received_total;
    uint8_t pcal_registers[0x77], pcal_interrupt_sources[3];
    bool i2c_expect_pointer;
    uint8_t i2c_tx_data[2], i2c_tx_phase[2];
    unsigned i2c_tx_count;
    QEMUTimer *i2c_start_timer, *i2c_nack_timer, *i2c_stop_timer;
    QEMUTimer *i2c_external_input_timer;
    uint64_t i2c_sr_read_count[2];
    uint64_t i2c_control_read_count[16], i2c_control_repeat_count[16];
    uint32_t i2c_control_last_requested[16], i2c_control_last_state[16];
    EX1850RTC rtc;
    EX1850RTCEXTI rtc_exti;
    uint64_t rtc_isr_access_count;
    QEMUTimer *rtc_event;
    uint32_t io_count;
} EX1850ResetState;

static uint32_t ex1850_tim5_counter(EX1850ResetState *s);
static void ex1850_tim11_sync(EX1850ResetState *s);
static void ex1850_tim11_schedule(EX1850ResetState *s);
static void ex1850_tim12_sync(EX1850ResetState *s);
static void ex1850_tim12_schedule(EX1850ResetState *s);
static void ex1850_tim1_sync(EX1850ResetState *s);
static void ex1850_tim1_schedule(EX1850ResetState *s);
static void ex1850_tim1_irq_update(EX1850ResetState *s);
static void ex1850_tim10_sync(EX1850ResetState *s);
static void ex1850_tim10_schedule(EX1850ResetState *s);
static void ex1850_tim234_clock_sync(EX1850ResetState *s, unsigned n);
static void ex1850_tim234_schedule(EX1850ResetState *s, unsigned n);
static void ex1850_rtc_reschedule(EX1850ResetState *s);
static void ex1850_rtc_irq_update(EX1850ResetState *s);
static void ex1850_i2c_receive_schedule(EX1850ResetState *s);
static void ex1850_sync_timer_clocks(EX1850ResetState *s, const char *reason);
static void ex1850_update_clock(EX1850ResetState *s);
static bool ex1850_power_has_work(CPUState *cs);
static void ex1850_power_resume(CPUState *cs);

static uint32_t ex1850_pc(void)
{
    return current_cpu ? ARM_CPU(current_cpu)->env.regs[15] : 0;
}

static void ex1850_capture_boundary(EX1850ResetState *s)
{
    const char *snapshot = g_getenv("EX1850_BOUNDARY_SRAM_PATH");
    const char *flash_snapshot = g_getenv("EX1850_BOUNDARY_FLASH_PATH");
    uint8_t *ram = memory_region_get_ram_ptr(&s->ram);
    uint8_t *rom = memory_region_get_ram_ptr(&s->rom);
    GError *error = NULL;
    if (snapshot && !g_file_set_contents(snapshot, (gchar *)ram, EX1850_RAM_BYTES, &error)) {
        error_report("Cannot retain EX1850 boundary SRAM: %s", error->message);
        exit(67);
    }
    if (flash_snapshot && !g_file_set_contents(flash_snapshot, (gchar *)rom,
                                              EX1850_BYTES, &error)) {
        error_report("Cannot retain EX1850 boundary simulated Flash: %s", error->message);
        exit(67);
    }
    g_autofree gchar *ram_sha = g_compute_checksum_for_data(G_CHECKSUM_SHA256, ram, EX1850_RAM_BYTES);
    g_autofree gchar *rom_sha = g_compute_checksum_for_data(G_CHECKSUM_SHA256, rom, EX1850_BYTES);
    fprintf(stderr, "EX1850_BOUNDARY original_ROM_sha256=%s "
            "current_simulated_FLASH_sha256=%s SRAM_sha256=%s "
            "HCLK_hz=%u RCC_CR=%08x PLLCFGR=%08x CFGR=%08x "
            "TIM5_CNT=%08x TIM5_PSC=%u TIM5_ARR=%08x TIM5_CEN=%u "
            "virtual_ns=%" PRId64 " snapshot_is_observation_never_fixture=1\n",
            EX1850_SHA, rom_sha, ram_sha, s->cpu_hz, s->rcc_cr, s->pllcfgr, s->cfgr,
            ex1850_tim5_counter(s), s->tim5_effective_psc, s->tim5_arr, s->tim5_cr1 & 1,
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    fprintf(stderr, "EX1850_BOUNDARY_FLASH ACR=%08x SR=%08x CR=%08x "
            "functional_input=%u key_stage=%u key_failed=%u accepted=%" PRIu64
            " completed=%" PRIu64 " erases=%" PRIu64 " programs=%" PRIu64
            " errors=%" PRIu64 " pending_kind=%u pending_offset=%08x "
            "pending_bytes=%u pending_word=%08x pending_due_ns=%" PRId64
            " input_ROM_file_modified=0\n", s->flash.acr, s->flash.sr, s->flash.cr,
            s->flash.config.functional, s->flash.key_stage, s->flash.key_failed,
            s->flash.accepted, s->flash.completed, s->flash.erases,
            s->flash.programs, s->flash.errors, s->flash.pending.kind,
            s->flash.pending.offset, s->flash.pending.bytes, s->flash.pending.word,
            s->flash.pending.due);
    fprintf(stderr, "EX1850_BOUNDARY_SPI2 CR1=%08x CR2=%08x SR=%08x "
            "DMA1_S4_CR=%08x NDTR=%u PAR=%08x M0AR=%08x HISR=%08x "
            "accepted_total=%" PRIu64 " shifted_total=%" PRIu64
            " receive_payload_known=0\n", s->spi2_dma.cr1, s->spi2_dma.cr2,
            s->spi2_dma.sr, s->spi2_dma.dma1[4].cr, s->spi2_dma.dma1[4].ndtr,
            s->spi2_dma.dma1[4].par, s->spi2_dma.dma1[4].m0ar, s->spi2_dma.hisr,
            s->spi2_dma.accepted_total, s->spi2_dma.shifted_total);
    ARMCPU *cpu = current_cpu ? ARM_CPU(current_cpu) : s->armv7m->cpu;
    fprintf(stderr, "EX1850_BOUNDARY_USART2 SR=%08x BRR=%04x CR1=%08x "
            "CR2=%08x CR3=%08x TX_accepted=%" PRIu64 " TX_completed=%" PRIu64
            " RX_supplied=%" PRIu64 " buffer_full=%u shifting=%u\n",
            s->usart2.sr, s->usart2.brr, s->usart2.cr1, s->usart2.cr2,
            s->usart2.cr3, s->usart2.tx_accepted, s->usart2.tx_completed,
            s->usart2.rx_supplied, s->usart2.buffer_full, s->usart2.shifting);
    fprintf(stderr, "EX1850_BOUNDARY_USART1 SR=%08x BRR=%04x CR1=%08x "
            "CR2=%08x CR3=%08x TX_accepted=%" PRIu64 " TX_completed=%" PRIu64
            " RX_supplied=%" PRIu64 " buffer_full=%u shifting=%u PCLK2_hz=%u\n",
            s->usart1.sr, s->usart1.brr, s->usart1.cr1, s->usart1.cr2,
            s->usart1.cr3, s->usart1.tx_accepted, s->usart1.tx_completed,
            s->usart1.rx_supplied, s->usart1.buffer_full, s->usart1.shifting,
            s->usart1.pclk_hz);
    fprintf(stderr, "EX1850_BOUNDARY_USART1_LINE enabled=%u open=%u "
            "TX_bytes=%" PRIu64 " RX_bytes=%" PRIu64 " RX_admitted=%" PRIu64
            " RX_completed=%" PRIu64 " RX_discarded=%" PRIu64 " RX_queue=%u "
            "TX_failures=%" PRIu64 " IRQ_edges=%" PRIu64 "\n",
            s->usart1_line_enabled, s->usart1_line_open,
            s->usart1_line_tx_bytes, s->usart1_line_rx_bytes,
            s->usart1_rx.admitted, s->usart1_rx.completed,
            s->usart1_rx.discarded, s->usart1_rx.count,
            s->usart1_line_tx_failures, s->usart1_irq_count);
    uint64_t gpio_reads = 0, gpio_writes = 0;
    for (unsigned bank = 0; bank < 8; bank++) {
        for (unsigned word = 0; word < 10; word++) {
            gpio_reads += s->gpio_access_counts[bank][word][0];
            gpio_writes += s->gpio_access_counts[bank][word][1];
        }
    }
    fprintf(stderr, "EX1850_BOUNDARY_POWER SCR=%08x stopped=%u "
            "STOP_entries=%" PRIu64 " STOP_wakes=%" PRIu64
            " GPIO_reads=%" PRIu64 " GPIO_writes=%" PRIu64
            " repeated_GPIO_log_sampling=1\n", s->power.scr, s->power.stopped,
            s->power.entries, s->power.wakes, gpio_reads, gpio_writes);
    fprintf(stderr, "EX1850_BOUNDARY_CPU");
    for (unsigned reg = 0; reg < 16; reg++) {
        fprintf(stderr, " r%u=%08x", reg, cpu->env.regs[reg]);
    }
    fprintf(stderr, " observation_never_replayed=1\n");
}

static G_NORETURN void ex1850_unknown_access(EX1850ResetState *s, hwaddr addr, unsigned size,
                                            bool write, uint64_t value)
{
    ex1850_capture_boundary(s);
    fprintf(stderr, "EX1850_UNMODELED %c addr=%08" HWADDR_PRIx
            " size=%u value=%08" PRIx64 " pc=%08x\n",
            write ? 'W' : 'R', addr, size, value, ex1850_pc());
    fflush(stderr);
    /* This dedicated offline process stops before supplying an unknown
     * read result or permitting another instruction to use it. */
    exit(66);
}

/* A model's missing address is not evidence of an unconnected physical
 * device. Add future source-backed device contracts here, before their
 * controller address-completion event may supply ACK, AF or input data. */
static EX1850I2CAddressContract ex1850_i2c_address_contract(EX1850ResetState *s,
                                                          uint8_t address7)
{
    if (s->i2c_slave_absent || s->i2c_absent_address[address7]) {
        return EX1850_I2C_EXPLICIT_ABSENT;
    }
    if (s->i2c_pcal6524 && address7 == 0x22) {
        return EX1850_I2C_PCAL6524;
    }
    if (s->i2c_max77711 && address7 == 0x4f) {
        return EX1850_I2C_MAX77711;
    }
    return EX1850_I2C_UNPROVIDED;
}

static G_NORETURN void ex1850_i2c_unknown_address(EX1850ResetState *s,
                                                 uint8_t address_byte,
                                                 unsigned size)
{
    const char *path = g_getenv("EX1850_I2C_REQUEST_PATH");
    GError *error = NULL;
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    uint32_t pc = ex1850_pc();
    /* This is the actual guest address-byte write, before DR/SB changes
     * and before any ninth-bit response is scheduled. A register pointer
     * or payload has not yet been transmitted: do not infer it from RAM. */
    g_autofree gchar *request = g_strdup_printf(
        "{\n  \"schema\": \"ex1850.i2c-address-request.v1\",\n"
        "  \"controller\": \"I2C1\", \"controller_base\": \"0x40005400\",\n"
        "  \"address_byte\": %u, \"address7\": %u, \"direction\": \"%s\",\n"
        "  \"mmio_address\": \"0x40005410\", \"mmio_bytes\": %u,\n"
        "  \"pc\": \"0x%08x\", \"virtual_ns\": %" PRId64 ",\n"
        "  \"contract\": \"unprovided\", \"response\": null,\n"
        "  \"device_identity\": null, \"device_evidence\": [],\n"
        "  \"register_pointer\": null, \"payload_bytes\": [],\n"
        "  \"stage\": \"before_address_DR_latch_and_ACK_NACK_decision\",\n"
        "  \"address_write_committed\": false, \"response_scheduled\": false,\n"
        "  \"request_is_observation_not_replay_fixture\": true,\n"
        "  \"original_rom_sha256\": \"%s\",\n"
        "  \"controller_before_write\": {\"CR1\": %u, \"CR2\": %u,"
        " \"SR1\": %u, \"SR2\": %u, \"DR\": %u, \"CCR\": %u, \"TRISE\": %u}\n}\n",
        address_byte, address_byte >> 1, address_byte & 1 ? "read" : "write",
        size, pc, now, EX1850_SHA, s->i2c1.cr1, s->i2c1.cr2,
        s->i2c1.sr1, s->i2c1.sr2, s->i2c1.dr, s->i2c1.ccr, s->i2c1.trise);
    if (path && !g_file_set_contents(path, request, -1, &error)) {
        error_report("Cannot retain EX1850 unresolved I2C request: %s", error->message);
        exit(67);
    }
    fprintf(stderr, "EX1850_UNMODELED_I2C_ADDRESS controller=I2C1 "
            "address_byte=%02x address7=%02x direction=%s pc=%08x "
            "virtual_ns=%" PRId64 " contract=unprovided "
            "address_write_committed=0 response_scheduled=0 ACK_supplied=0 NACK_supplied=0\n",
            address_byte, address_byte >> 1, address_byte & 1 ? "read" : "write", pc, now);
    ex1850_unknown_access(s, 0x40005410, size, true, address_byte);
}

#include "ex1850-spi2-dma-board.h"
#include "ex1850-usart2-board.h"
#include "ex1850-usart1-board.h"
#include "ex1850-usart1-chardev.h"
static void ex1850_flash_wait_release(EX1850ResetState *s);
#include "ex1850-flash-board.h"
#include "ex1850-flash-wait-board.h"
#include "ex1850-power-board.h"

static bool ex1850_gpio_log_sample(EX1850ResetState *s, hwaddr addr,
                                    bool write, uint32_t value, uint32_t observed)
{
    unsigned bank = (addr - 0x40020000) / 0x400;
    unsigned word = (addr & 0x3fc) / 4;
    if (bank >= 8 || word >= 10) { return true; }
    uint64_t count = ++s->gpio_access_counts[bank][word][write];
    uint32_t last = s->gpio_last_access[bank][word][write];
    uint32_t known = s->gpio_last_observed[bank][word][write];
    /* Original ReadPin loads different subsets of IDR in succession. Only
     * compare bits actually observed by both loads; zero representatives
     * for the other pads are not changes to those pads. */
    bool emit = count <= 8 || !(count & (count - 1)) ||
                (observed & ~known) || ((last ^ value) & observed);
    s->gpio_last_access[bank][word][write] =
        (last & ~observed) | (value & observed);
    s->gpio_last_observed[bank][word][write] = known | observed;
    return emit;
}

static bool ex1850_gpio_register(EX1850ResetState *s, hwaddr addr, uint32_t *value)
{
    if (addr < 0x40020000 || addr >= 0x40022000) {
        return false;
    }
    unsigned bank = (addr - 0x40020000) / 0x400;
    EX1850GPIOControl *g = &s->gpio[bank];
    switch (addr & 0x3fc) {
    case 0x00: *value = g->moder; break;
    case 0x04: *value = g->otyper; break;
    case 0x08: *value = g->speed; break;
    case 0x0c: *value = g->pupdr; break;
    /* IDR is deliberately absent: actual input pads and board connections
     * have not been supplied or inferred from desired boot status. */
    case 0x14: *value = g->odr; break;
    case 0x18: *value = 0; break; /* Atomic set/reset is write-only. */
    case 0x1c: *value = 0; break; /* No lock sequence supported yet. */
    case 0x20: *value = g->afrl; break;
    case 0x24: *value = g->afrh; break;
    default: return false;
    }
    if (!(s->ahb1enr & (1U << bank))) {
        /* Bounded family clock-gated control-register behavior. IDR remains
         * unmodeled even when its register interface clock is disabled. */
        *value = 0;
    }
    return true;
}

static void ex1850_gpio_exti_irq_update(EX1850ResetState *s)
{
    static const unsigned irqs[] = { 6, 7, 8, 9, 10, 23, 40 };
    if (!s->armv7m) { return; }
    for (unsigned i = 0; i < G_N_ELEMENTS(irqs); i++) {
        qemu_set_irq(qdev_get_gpio_in(DEVICE(s->armv7m), irqs[i]),
                     ex1850_gpio_exti_irq(s->exti_pr, s->exti_imr, irqs[i]));
    }
}

#include "nikon-ex1850-wire.h"

static void ex1850_rtc_irq_update(EX1850ResetState *s)
{
    bool level = ex1850_rtc_exti_irq(s->exti_pr, s->exti_imr);
    if (level != s->rtc_exti.irq) {
        s->rtc_exti.irq = level;
        fprintf(stderr, "EX1850_RTC_IRQ41 level=%u PR=%08x IMR=%08x "
                "input=%u pc=%08x virtual_ns=%" PRId64 " native_NVIC=1\n",
                level, s->exti_pr, s->exti_imr, s->rtc_exti.input,
                ex1850_pc(), qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    }
    if (s->armv7m) {
        qemu_set_irq(qdev_get_gpio_in(DEVICE(s->armv7m), EX1850_RTC_EXTI_IRQ), level);
    }
}

static void ex1850_rtc_output(void *opaque, bool level,
                             uint64_t lse_cycle, int64_t event_ns)
{
    EX1850ResetState *s = opaque;
    uint32_t before = s->exti_pr;
    if (ex1850_rtc_exti_input(&s->rtc_exti, level, s->exti_rtsr,
                            s->exti_ftsr, &s->exti_pr)) {
        fprintf(stderr, "EX1850_RTC_EXTI17_EDGE level=%u PR_before=%08x "
                "PR_after=%08x RTSR=%08x FTSR=%08x IMR=%08x ISR=%08x "
                "effective_control=%08x event_LSE_cycle=%" PRIu64
                " event_virtual_ns=%" PRId64 " observed_virtual_ns=%" PRId64
                " pc=%08x actual_RTC_internal_output=1\n", level, before,
                s->exti_pr, s->exti_rtsr, s->exti_ftsr, s->exti_imr,
                s->rtc.isr, s->rtc.alarm_control, lse_cycle, event_ns,
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), ex1850_pc());
    }
    ex1850_rtc_irq_update(s);
}

static bool ex1850_gpio_timer_input(EX1850ResetState *s, unsigned bank,
                                    unsigned pin)
{
    static const struct {
        uint8_t bank, pin, af, timer, channel;
    } pads[] = {
        {0, 0, 1, 0, 0}, {0, 5, 1, 0, 0}, {0, 15, 1, 0, 0},
        {0, 1, 1, 0, 1}, {1, 3, 1, 0, 1},
        {0, 2, 1, 0, 2}, {1, 10, 1, 0, 2},
        {0, 3, 1, 0, 3}, {1, 11, 1, 0, 3},
        {0, 6, 2, 1, 0}, {1, 4, 2, 1, 0}, {2, 6, 2, 1, 0},
        {0, 7, 2, 1, 1}, {1, 5, 2, 1, 1}, {2, 7, 2, 1, 1},
        {1, 0, 2, 1, 2}, {2, 8, 2, 1, 2},
        {1, 1, 2, 1, 3}, {2, 9, 2, 1, 3},
        {1, 6, 2, 2, 0}, {3, 12, 2, 2, 0},
        {1, 7, 2, 2, 1}, {3, 13, 2, 2, 1},
        {1, 8, 2, 2, 2}, {3, 14, 2, 2, 2},
        {1, 9, 2, 2, 3}, {3, 15, 2, 2, 3},
    };
    EX1850GPIOControl *g = &s->gpio[bank];
    unsigned af = ((pin < 8 ? g->afrl : g->afrh) >>
                   ((pin % 8) * 4)) & 15;
    for (unsigned n = 0; n < ARRAY_SIZE(pads); n++) {
        if (pads[n].bank != bank || pads[n].pin != pin || pads[n].af != af) {
            continue;
        }
        EX1850TIM234 *t = &s->tim234[pads[n].timer];
        unsigned channel = pads[n].channel;
        unsigned direct = ex1850_tim234_channel(t, channel) & 3;
        unsigned indirect = ex1850_tim234_channel(t, channel ^ 1) & 3;
        /* GPIO IDR samples the enabled digital pad buffer even with CCxE
         * clear. CCxS=1 selects its own TI; CCxS=2 selects the paired TI.
         * Reading a declared pad level does not generate capture events. */
        return direct == 1 || indirect == 2;
    }
    return false;
}

static bool ex1850_gpio_input_read(EX1850ResetState *s, hwaddr addr,
                                   unsigned size, uint32_t *value)
{
    if (addr < 0x40020000 || addr >= 0x40022000 ||
        (addr & 0x3fc) != 0x10 || (addr & 3) + size > 4) { return false; }
    unsigned bank = (addr - 0x40020000) / 0x400;
    if (!s->gpio_pin_profile[bank] || !(s->ahb1enr & (1U << bank))) {
        return false;
    }
    EX1850GPIOControl *g = &s->gpio[bank];
    uint16_t idr = 0, external_levels = s->gpio_pin_levels[bank];
    uint16_t observed_mask = 0xffff;
    bool masked_readpin = false;
    /* A word IDR load can contain unknown, unused alternate-function pads.
     * Admit an observational representative only at the unchanged original
     * ReadPin: LDR r0,[r0,#16]; ANDS r0,r1; conditional MOVS r0,#1; BX lr.
     * The immediate AND removes every unobserved bit before any subsequent
     * consumer. This does not model those pads or a generic IDR register. */
    if (s->gpio_masked_readpin && current_cpu && size == 4 && !(addr & 3) &&
        ex1850_pc() == 0x08043ac8) {
        ARMCPU *cpu = ARM_CPU(current_cpu);
        static const uint8_t readpin_bytes[] = {
            0x00, 0x69, 0x08, 0x40, 0x00, 0xd0, 0x01, 0x20, 0x70, 0x47
        };
        uint8_t *rom = memory_region_get_ram_ptr(&s->rom);
        uint32_t pin_mask = cpu->env.regs[1];
        if (cpu->env.regs[0] != addr - 0x10 || !pin_mask || pin_mask > 0xffff ||
            memcmp(rom + 0x43ac8, readpin_bytes, sizeof(readpin_bytes))) {
            return false;
        }
        observed_mask = pin_mask;
        masked_readpin = true;
    }
    /* An unrelated PG6 ACK must not block an original ReadPin of PG5. The
     * real ACK remains mandatory when the original instruction selects it. */
    if ((observed_mask & 0x40) &&
        !ex1850_wire_pg6_profile(s, bank, &external_levels)) { return false; }
    for (unsigned pin = 0; pin < 16; pin++) {
        if (!(observed_mask & (1U << pin))) { continue; }
        unsigned mode = (g->moder >> (2 * pin)) & 3;
        bool external = !!(external_levels & (1U << pin));
        bool level = false;
        if (mode == 0) {
            if (!(s->gpio_pin_known_mask[bank] & (1U << pin))) { return false; }
            level = external;
        }
        else if (mode == 1) {
            bool drive = !!(g->odr & (1U << pin));
            if (drive && (g->otyper & (1U << pin)) &&
                !(s->gpio_pin_known_mask[bank] & (1U << pin))) { return false; }
            level = drive && (!(g->otyper & (1U << pin)) || external);
        } else if (mode == 2) {
            if (!(s->gpio_pin_known_mask[bank] & (1U << pin)) ||
                !ex1850_gpio_timer_input(s, bank, pin)) { return false; }
            level = external;
        }
        /* Analog mode disables the digital Schmitt input. Declared input
         * levels dominate internal weak pulls; push-pull outputs are assumed
         * uncontended. These are offline pad hypotheses, not camera samples. */
        if (level) { idr |= 1U << pin; }
    }
    *value = (idr >> (8 * (addr & 3))) & ((UINT64_C(1) << (size * 8)) - 1);
    uint32_t returned_mask = (observed_mask >> (8 * (addr & 3))) &
        ((UINT64_C(1) << (size * 8)) - 1);
    if (ex1850_gpio_log_sample(s, addr, false, *value, returned_mask)) {
        fprintf(stderr, "EX1850_GPIO_INPUT R bank=%c addr=%08" HWADDR_PRIx
            " size=%u value=%08x IDR=%04x external_pin_levels_hypothesis=%04x "
            "MODER=%08x ODR=%04x external_known_mask=%04x observed_mask=%04x masked_original_readpin=%u "
            "unobserved_bits_zero_representative=%u pc=%08x virtual_ns=%" PRId64
            " physical_camera_sample=0 software_completion_supplied=0\n",
            'A' + bank, addr, size, *value, idr, s->gpio_pin_levels[bank],
            g->moder, g->odr, s->gpio_pin_known_mask[bank], observed_mask, masked_readpin, masked_readpin,
            ex1850_pc(), qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    }
    return true;
}

static bool ex1850_gpio_write(EX1850ResetState *s, hwaddr addr,
                              uint64_t value, unsigned size)
{
    uint32_t old;
    if ((addr & 3) + size > 4 || !ex1850_gpio_register(s, addr, &old)) {
        return false;
    }
    uint32_t mask = ((UINT64_C(1) << (size * 8)) - 1) << (8 * (addr & 3));
    uint32_t merged = (old & ~mask) | ((value << (8 * (addr & 3))) & mask);
    unsigned bank = (addr - 0x40020000) / 0x400;
    EX1850GPIOControl *g = &s->gpio[bank];
    if (!(s->ahb1enr & (1U << bank))) {
        if (ex1850_gpio_log_sample(s, addr, true, merged, UINT32_MAX)) {
            ex1850_sampled_log("EX1850_GPIO_CONTROL W bank=%c addr=%08" HWADDR_PRIx
                " size=%u value=%08x pc=%08x clock_enabled=0 write_ignored=1\n",
                'A' + bank, addr, size, merged, ex1850_pc());
        }
        return true;
    }
    switch (addr & 0x3fc) {
    case 0x00: g->moder = merged; break;
    case 0x04:
        if (merged & ~0xffffU) { return false; }
        g->otyper = merged; break;
    case 0x08: g->speed = merged; break;
    case 0x0c: g->pupdr = merged; break;
    case 0x14:
        if (merged & ~0xffffU) { return false; }
        g->odr = merged; break;
    case 0x18: g->odr = (g->odr & ~(merged >> 16)) | (merged & 0xffff); break;
    case 0x1c:
        if (merged) { return false; }
        break;
    case 0x20: g->afrl = merged; break;
    case 0x24: g->afrh = merged; break;
    default: return false;
    }
    uint32_t wire_written = (addr & 0x3fc) == 0x14 ? mask & 0xffff :
        (addr & 0x3fc) == 0x18 ? (merged & 0xffff) | (merged >> 16) : 0;
    ex1850_wire_gpio_changed(s, bank, wire_written);
    /* BSRR request words can alternate while ODR stays unchanged. Sample
     * the resulting output latch, retaining each request in the counter. */
    uint32_t sampled = (addr & 0x3fc) == 0x18 ? g->odr : merged;
    if (ex1850_gpio_log_sample(s, addr, true, sampled, UINT32_MAX)) {
        ex1850_sampled_log("EX1850_GPIO_CONTROL W bank=%c addr=%08" HWADDR_PRIx
            " size=%u value=%08x ODR=%04x pc=%08x virtual_ns=%" PRId64
            " board_input_and_external_response_supplied=0\n",
            'A' + bank, addr, size, merged, g->odr, ex1850_pc(),
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    }
    return true;
}

static bool ex1850_syscfg_exticr_access(EX1850ResetState *s, hwaddr addr,
                                       unsigned size, bool write,
                                       uint64_t *value)
{
    if (addr < 0x40013808 || addr > 0x40013814 || (addr & 3) || size != 4) {
        return false;
    }
    /* Observe earlier ACK changes under the old routing before a guest
     * EXTICR write can change the source of an EXTI line. */
    ex1850_wire_poll(s);
    unsigned index = (addr - 0x40013808) / 4;
    bool clock_enabled = !!(s->apb2enr & (1U << 14));
    if (write) {
        if (*value & ~UINT64_C(0xffff)) { return false; }
        for (unsigned nibble = 0; nibble < 4; nibble++) {
            if (((*value >> (nibble * 4)) & 15) > 7) { return false; }
        }
        if (clock_enabled) { s->syscfg_exticr[index] = *value; }
    } else {
        *value = clock_enabled ? s->syscfg_exticr[index] : 0;
    }
    ex1850_sampled_log("EX1850_SYSCFG_CONTROL %c reg=EXTICR%u value=%08" PRIx64
            " stored=%08x clock_enabled=%u pc=%08x virtual_ns=%" PRId64
            " reset_portA_family_hypothesis=1 external_pin_events_supplied=0\n",
            write ? 'W' : 'R', index + 1, *value, s->syscfg_exticr[index],
            clock_enabled, ex1850_pc(), qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    return true;
}

static bool ex1850_exti_control_access(EX1850ResetState *s, hwaddr addr,
                                     unsigned size, bool write,
                                     uint64_t *value)
{
    /* F4-family reset0 and PR write-one-to-clear are control semantics.
     * Live wire mode admits PG6 edges from actual master GPIO writes plus
     * declared digital pad edges from explicit host inputs. Unprovided
     * sources and event wakeup delivery remain unsupported. Selected edges
     * coalesce in PR until original guest W1C; each shared IRQ aggregates
     * all its GPIO lines, independently of the RTC17 internal source.
     * Mask/edge controls are guest-written latches, not pending events.
     * Reading pending after arming an unknown source remains a boundary.
     * This peripheral is not gated by the separate SYSCFG configuration
     * clock. These family defaults are not measurements of the Z6II MCU. */
    if (size != 4) { return false; }
    uint32_t *reg;
    const char *name;
    switch (addr) {
    case 0x40013c00: reg = &s->exti_imr; name = "IMR"; break;
    case 0x40013c04: reg = &s->exti_emr; name = "EMR"; break;
    case 0x40013c08: reg = &s->exti_rtsr; name = "RTSR"; break;
    case 0x40013c0c: reg = &s->exti_ftsr; name = "FTSR"; break;
    case 0x40013c14: reg = &s->exti_pr; name = "PR"; break;
    default: return false;
    }
    /* Import already-published edges before sampling PR, changing its
     * trigger controls or clearing it. An old edge must not be imported
     * after W1C and spuriously resurrect a just-cleared pending bit. */
    ex1850_wire_poll(s);
    ex1850_rtc_reschedule(s);
    uint32_t before = *reg;
    if (write) {
        if (*value & ~UINT64_C(0x007fffff)) { return false; }
        if (addr == 0x40013c04 && *value) {
            return false; /* EXTI event wake delivery is not modeled. */
        }
        if (addr == 0x40013c14) {
            *reg = ex1850_rtc_exti_w1c(*reg, (uint32_t)*value);
        } else {
            *reg = *value;
        }
    } else {
        if (addr == 0x40013c14 && (s->exti_rtsr || s->exti_ftsr) &&
            !ex1850_wire_exti_supported(s)) { return false; }
        *value = *reg;
    }
    ex1850_wire_poll(s); /* W1C/mask writes update every GPIO IRQ immediately. */
    ex1850_rtc_irq_update(s);
    fprintf(stderr, "EX1850_EXTI_CONTROL %c reg=%s value=%08" PRIx64
            " before=%08x after=%08x pc=%08x virtual_ns=%" PRId64
            " live_PG6_ack_source=%u software_pending_fixture=0\n",
            write ? 'W' : 'R', name, *value, before, *reg, ex1850_pc(),
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), !!s->wire.bus);
    return true;
}

static void ex1850_reg_log(EX1850ResetState *s, unsigned id,
                           const char *name, bool write, uint32_t value)
{
    uint64_t count = ++s->read_counts[id];
    if (write || count <= 8 || value != s->last_reads[id] || !(count & (count - 1))) {
        fprintf(stderr, "EX1850_%s %c value=%08x pc=%08x virtual_ns=%" PRId64
                " sampled_access_index=%" PRIu64 "\n", name,
                write ? 'W' : 'R', value, ex1850_pc(),
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), count);
    }
    s->last_reads[id] = value;
}

static unsigned ex1850_tim5_hz(EX1850ResetState *s)
{
    if (!(s->apb1enr & (1U << 3))) { return 0; }
    unsigned ppre = (s->cfgr >> 10) & 7;
    unsigned kernel = s->cpu_hz;
    if (ppre >= 4) {
        kernel = (kernel >> (ppre - 3)) * 2;
    }
    return kernel / (s->tim5_effective_psc + 1);
}

static uint32_t ex1850_tim5_counter(EX1850ResetState *s)
{
    uint64_t count = s->tim5_cnt;
    if (s->tim5_cr1 & 1) {
        int64_t elapsed = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) - s->tim5_epoch;
        count += (uint64_t)MAX(elapsed, 0) * ex1850_tim5_hz(s) / 1000000000;
    }
    return count % ((uint64_t)s->tim5_arr + 1);
}

static void ex1850_tim5_sync(EX1850ResetState *s)
{
    s->tim5_cnt = ex1850_tim5_counter(s);
    s->tim5_epoch = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
}

static void ex1850_tim5_schedule(EX1850ResetState *s)
{
    timer_del(s->tim5_overflow);
    unsigned hz = ex1850_tim5_hz(s);
    if ((s->tim5_cr1 & 1) && hz) {
        uint64_t ticks = (uint64_t)s->tim5_arr + 1 - s->tim5_cnt;
        uint64_t delay = (ticks * UINT64_C(1000000000) + hz - 1) / hz;
        timer_mod(s->tim5_overflow, s->tim5_epoch + delay);
    }
}

static void ex1850_tim5_wrap(void *opaque)
{
    EX1850ResetState *s = opaque;
    if (s->tim5_cr1 & 1) {
        s->tim5_cnt = 0;
        s->tim5_epoch = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
        s->tim5_effective_psc = s->tim5_psc;
        s->tim5_sr |= 1; /* Hardware update flag; DIER/IRQ is not enabled. */
        fprintf(stderr, "EX1850_TIM5_EVENT overflow=1 UIF=1 virtual_ns=%" PRId64 "\n",
                s->tim5_epoch);
        ex1850_tim5_schedule(s);
    }
}

static void ex1850_tim5_log(EX1850ResetState *s, hwaddr addr, unsigned size,
                            bool write, uint32_t value)
{
    unsigned id = (addr - 0x40000c00) / 4;
    uint64_t count = ++s->tim5_access_counts[id];
    if (write || count <= 8 || !(count & (count - 1))) {
        fprintf(stderr, "EX1850_TIM5_%c addr=%08" HWADDR_PRIx " size=%u value=%08x "
                "pc=%08x counter_hz=%u virtual_ns=%" PRId64 " sampled_access_index=%" PRIu64 "\n",
                write ? 'W' : 'R', addr, size, value, ex1850_pc(), ex1850_tim5_hz(s),
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), count);
    }
}

static bool ex1850_tim5_register(EX1850ResetState *s, hwaddr addr, uint32_t *value)
{
    if (!(s->apb1enr & (1U << 3))) {
        return false;
    }
    switch (addr & ~3U) {
    case 0x40000c00: *value = s->tim5_cr1; return true;
    case 0x40000c04: *value = s->tim5_cr2; return true;
    case 0x40000c08: *value = s->tim5_smcr; return true;
    case 0x40000c0c: *value = 0; return true; /* DIER reset; nonzero write stops. */
    case 0x40000c10: *value = s->tim5_sr; return true;
    case 0x40000c14: *value = 0; return true; /* Event generation is write-only. */
    case 0x40000c24: *value = ex1850_tim5_counter(s); return true;
    case 0x40000c28: *value = s->tim5_psc; return true;
    case 0x40000c2c: *value = s->tim5_arr; return true;
    default: return false;
    }
}

static bool ex1850_tim5_write(EX1850ResetState *s, hwaddr addr,
                              uint64_t value, unsigned size)
{
    uint32_t old;
    if ((addr & 3) + size > 4 || !ex1850_tim5_register(s, addr, &old)) {
        return false;
    }
    uint32_t mask = ((UINT64_C(1) << (size * 8)) - 1) << (8 * (addr & 3));
    uint32_t merged = (old & ~mask) | ((value << (8 * (addr & 3))) & mask);
    ex1850_tim5_sync(s);
    switch (addr & ~3U) {
    case 0x40000c00:
        if (merged & ~1U) { return false; } /* Current native internal upcounter. */
        s->tim5_cr1 = merged;
        break;
    case 0x40000c04:
    case 0x40000c08:
    case 0x40000c0c:
        if (merged) { return false; } /* Unmodeled trigger/slave/IRQ features. */
        break;
    case 0x40000c10:
        s->tim5_sr &= merged; /* RC_W0 flag clearing. */
        break;
    case 0x40000c14:
        if (merged & ~1U) { return false; }
        if (merged & 1) {
            s->tim5_effective_psc = s->tim5_psc;
            s->tim5_cnt = 0;
            s->tim5_sr |= 1;
            fprintf(stderr, "EX1850_TIM5_EVENT UG=1 UIF=1 effective_PSC=%u ARR=%08x "
                    "virtual_ns=%" PRId64 " software_completion_fixture=0\n",
                    s->tim5_effective_psc, s->tim5_arr, s->tim5_epoch);
        }
        break;
    case 0x40000c24: s->tim5_cnt = merged % ((uint64_t)s->tim5_arr + 1); break;
    case 0x40000c28:
        if (merged & ~UINT32_C(0xffff)) { return false; }
        s->tim5_psc = merged;
        break;
    case 0x40000c2c:
        s->tim5_arr = merged;
        s->tim5_cnt %= (uint64_t)s->tim5_arr + 1;
        break;
    default: return false;
    }
    ex1850_tim5_schedule(s);
    ex1850_tim5_log(s, addr, size, true, merged);
    return true;
}

static unsigned ex1850_tim11_hz(EX1850ResetState *s)
{
    if (!(s->apb2enr & (1U << 18))) { return 0; }
    unsigned ppre = (s->cfgr >> 13) & 7;
    unsigned kernel = s->cpu_hz;
    if (ppre >= 4) { kernel = (kernel >> (ppre - 3)) * 2; }
    return kernel / (s->tim11_effective_psc + 1);
}

static uint32_t ex1850_tim11_counter(EX1850ResetState *s)
{
    uint64_t count = s->tim11_cnt;
    if ((s->tim11_cr1 & 1) && s->tim11_arr) {
        int64_t elapsed = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) - s->tim11_epoch;
        count += (uint64_t)MAX(elapsed, 0) * ex1850_tim11_hz(s) / 1000000000;
    }
    return count % ((uint64_t)s->tim11_arr + 1);
}

static void ex1850_tim11_sync(EX1850ResetState *s)
{
    s->tim11_cnt = ex1850_tim11_counter(s);
    s->tim11_epoch = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
}

static void ex1850_tim11_irq_update(EX1850ResetState *s)
{
    /* One authoritative IRQ26 aggregator retains both TIM1 and TIM11.
     * Neither source directly clears the other timer's shared level. */
    ex1850_tim1_irq_update(s);
}

static void ex1850_tim11_schedule(EX1850ResetState *s)
{
    timer_del(s->tim11_overflow);
    unsigned hz = ex1850_tim11_hz(s);
    if ((s->tim11_cr1 & 1) && s->tim11_arr && hz) {
        uint64_t period = (uint64_t)s->tim11_arr + 1;
        uint64_t update = period - s->tim11_cnt;
        uint64_t compare = period + 1;
        if (s->tim11_ccr1 <= s->tim11_arr) {
            compare = (s->tim11_ccr1 + period - s->tim11_cnt) % period;
            if (!compare) { compare = period; }
        }
        uint64_t ticks = MIN(update, compare);
        s->tim11_due_update = ticks == update;
        s->tim11_due_compare = ticks == compare;
        uint64_t delay = (ticks * UINT64_C(1000000000) + hz - 1) / hz;
        timer_mod(s->tim11_overflow, s->tim11_epoch + delay);
    }
    ex1850_tim11_irq_update(s);
}

static void ex1850_tim11_wrap(void *opaque)
{
    EX1850ResetState *s = opaque;
    if ((s->tim11_cr1 & 1) && s->tim11_arr && ex1850_tim11_hz(s)) {
        bool update = s->tim11_due_update, compare = s->tim11_due_compare;
        ex1850_tim11_sync(s);
        if (update) {
            s->tim11_cnt = 0;
            s->tim11_effective_psc = s->tim11_psc;
            s->tim11_sr |= 1;
        }
        if (compare) { s->tim11_sr |= 2; }
        fprintf(stderr, "EX1850_TIM11_EVENT update=%u compare=%u UIF=%u CC1IF=%u "
                "virtual_ns=%" PRId64 " source=clocked_internal_counter_match "
                "application_completion_supplied=0 external_capture_supplied=0\n",
                update, compare, !!(s->tim11_sr & 1), !!(s->tim11_sr & 2), s->tim11_epoch);
        ex1850_tim11_schedule(s);
    }
}

static bool ex1850_tim11_access(EX1850ResetState *s, hwaddr addr,
                                unsigned size, bool write, uint64_t *value)
{
    if (addr < 0x40014800 || addr > 0x40014850 || (addr & 3) || size != 4 ||
        !(s->apb2enr & (1U << 18))) { return false; }
    unsigned offset = addr - 0x40014800;
    uint32_t *reg = NULL;
    uint32_t mask = 0;
    switch (offset) {
    case 0x00: reg = &s->tim11_cr1; mask = 1; break;
    case 0x0c: reg = &s->tim11_dier; mask = 3; break;
    case 0x10: reg = &s->tim11_sr; mask = 3; break;
    case 0x20: reg = &s->tim11_ccer; mask = 3; break;
    case 0x24: reg = &s->tim11_cnt; mask = 0xffff; break;
    case 0x28: reg = &s->tim11_psc; mask = 0xffff; break;
    case 0x2c: reg = &s->tim11_arr; mask = 0xffff; break;
    case 0x34: reg = &s->tim11_ccr1; mask = 0xffff; break;
    case 0x04: case 0x08: case 0x18: case 0x50:
        /* CCMR1's native CC1S0/OC1M0 is output comparison with frozen
         * pin output. Input capture, other OC modes and remapping are strict. */
        /* TIM11 has no CR2/SMCR. The generic original HAL nevertheless
         * reads/clears SMCR while selecting its internal clock. Reserved
         * word read0/write0 is an explicit family bus hypothesis. */
        if (write && *value) { return false; }
        if (!write) { *value = 0; }
        break;
    case 0x14:
        if (write) {
            if (*value & ~UINT64_C(3)) { return false; }
            ex1850_tim11_sync(s);
            if (*value & 1) {
                s->tim11_effective_psc = s->tim11_psc;
                s->tim11_cnt = 0;
                s->tim11_sr |= 1; /* Actual original UG, not a ready bit. */
            }
            if (*value & 2) { s->tim11_sr |= 2; } /* Actual original CC1G. */
            ex1850_tim11_schedule(s);
        } else { *value = 0; }
        break;
    default: return false;
    }
    if (reg) {
        if (write) {
            if (offset != 0x10 && (*value & ~mask)) { return false; }
            ex1850_tim11_sync(s);
            if (offset == 0x10) { *reg &= *value & mask; } /* W0C */
            else { *reg = *value; }
            ex1850_tim11_schedule(s);
        } else { *value = offset == 0x24 ? ex1850_tim11_counter(s) : *reg; }
    }
    uint64_t count = ++s->tim11_access_counts[offset / 4];
    if (write || count <= 8 || !(count & (count - 1))) {
        fprintf(stderr, "EX1850_TIM11_%c addr=%08" HWADDR_PRIx " value=%08" PRIx64
                " pc=%08x counter_hz=%u virtual_ns=%" PRId64
                " sampled_access_index=%" PRIu64
                " IRQ26_source=original_DIER_and_clocked_SR external_capture_supplied=0\n",
                write ? 'W' : 'R', addr, *value, ex1850_pc(), ex1850_tim11_hz(s),
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), count);
    }
    return true;
}

static unsigned ex1850_tim12_kernel_hz(EX1850ResetState *s)
{
    if (!(s->apb1enr & (1U << 6))) { return 0; }
    unsigned ppre = (s->cfgr >> 10) & 7;
    unsigned kernel = s->cpu_hz;
    if (ppre >= 4) { kernel = (kernel >> (ppre - 3)) * 2; }
    return kernel;
}

static void ex1850_tim12_sync(EX1850ResetState *s)
{
    uint64_t updates = s->tim12.updates;
    uint64_t compare1 = s->tim12.compares[0], compare2 = s->tim12.compares[1];
    ex1850_tim12_core_sync(&s->tim12, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
                           ex1850_tim12_kernel_hz(s));
    if (updates != s->tim12.updates || compare1 != s->tim12.compares[0] ||
        compare2 != s->tim12.compares[1]) {
        fprintf(stderr, "EX1850_TIM12_EVENT update_delta=%" PRIu64
                " compare1_delta=%" PRIu64 " compare2_delta=%" PRIu64
                " CNT=%04x SR=%08x DIER=%08x active_PSC=%u active_ARR=%04x "
                "virtual_ns=%" PRId64 " source=elapsed_virtual_clock "
                "IRQ43_source=actual_DIER_and_SR software_completion_supplied=0\n",
                s->tim12.updates - updates, s->tim12.compares[0] - compare1,
                s->tim12.compares[1] - compare2, s->tim12.cnt, s->tim12.sr,
                s->tim12.dier, s->tim12.active_psc, s->tim12.active_arr,
                s->tim12.epoch);
    }
}

static void ex1850_tim12_schedule(EX1850ResetState *s)
{
    timer_del(s->tim12_event);
    int64_t deadline = ex1850_tim12_core_deadline(&s->tim12,
                                                ex1850_tim12_kernel_hz(s));
    if (deadline >= 0) { timer_mod(s->tim12_event, deadline); }
    /* Original guest vector0804170C dispatches TIM12 channels and TIM8
     * break. TIM8 has no admitted activation/control path on this board;
     * unknown TIM8 activation still terminates before it can share IRQ43. */
    if (s->armv7m) {
        qemu_set_irq(qdev_get_gpio_in(DEVICE(s->armv7m), 43),
                     !!(ex1850_tim12_kernel_hz(s) && ex1850_tim12_core_irq(&s->tim12)));
    }
}

static void ex1850_tim12_event(void *opaque)
{
    EX1850ResetState *s = opaque;
    ex1850_tim12_sync(s);
    ex1850_tim12_schedule(s);
}

static bool ex1850_tim12_access(EX1850ResetState *s, hwaddr addr,
                                unsigned size, bool write, uint64_t *value)
{
    if (addr < 0x40001800 || addr > 0x40001838 || (addr & 3) || size != 4 ||
        !(s->apb1enr & (1U << 6))) { return false; }
    unsigned offset = addr - 0x40001800;
    uint32_t ignored;
    if ((write && (*value > UINT32_MAX ||
                    !ex1850_tim12_core_valid_write(offset, *value))) ||
        (!write && !ex1850_tim12_core_read(&s->tim12, offset, &ignored))) {
        return false;
    }
    ex1850_tim12_sync(s);
    if (write) { ex1850_tim12_core_write(&s->tim12, offset, *value); }
    else {
        uint32_t result;
        ex1850_tim12_core_read(&s->tim12, offset, &result);
        *value = result;
    }
    ex1850_tim12_schedule(s);
    uint64_t count = ++s->tim12_access_counts[offset / 4];
    if (write || count <= 8 || !(count & (count - 1))) {
        fprintf(stderr, "EX1850_TIM12_%c addr=%08" HWADDR_PRIx
                " size=%u value=%08" PRIx64 " pc=%08x kernel_hz=%u "
                "active_PSC=%u active_ARR=%04x CNT=%04x UIF=%u "
                "IRQ43_level=%u virtual_ns=%" PRId64
                " sampled_access_index=%" PRIu64 " original_guest_control_only=1\n",
                write ? 'W' : 'R', addr, size, *value, ex1850_pc(),
                ex1850_tim12_kernel_hz(s), s->tim12.active_psc, s->tim12.active_arr,
                s->tim12.cnt, !!(s->tim12.sr & 1), ex1850_tim12_core_irq(&s->tim12),
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), count);
    }
    return true;
}

static bool ex1850_tim8_reset_idle_access(EX1850ResetState *s, hwaddr addr,
                                         unsigned size, bool write, uint64_t *value)
{
    if (size != 4 || (addr != 0x40010410 && addr != 0x4001040c) ||
        (write && addr != 0x40010410)) { return false; }
    /* The original shared IRQ43 checks TIM8 break SR/DIER after TIM12.
     * No TIM8 control/activation write is admitted, so its reset flags and
     * event-source enable remain zero. This does not supply a timer event. */
    uint64_t requested = *value;
    if (!write) { *value = 0; }
    fprintf(stderr, "EX1850_TIM8_IDLE %c addr=%08" HWADDR_PRIx
            " requested=%08" PRIx64 " state=0 pc=%08x "
            "source=reset_and_no_admitted_activation virtual_ns=%" PRId64 "\n",
            write ? 'W' : 'R', addr, requested, ex1850_pc(),
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    return true;
}

#include "ex1850-tim1-board.h"
#include "ex1850-tim10-board.h"
#include "ex1850-tim234-board.h"

static unsigned ex1850_adc_hz(EX1850ResetState *s)
{
    if (!(s->apb2enr & (1U << 8))) { return 0; }
    unsigned ppre = (s->cfgr >> 13) & 7;
    unsigned pclk = s->cpu_hz;
    if (ppre >= 4) { pclk >>= ppre - 3; }
    return pclk / (2 * (((s->adc_common_ccr >> 16) & 3) + 1));
}

static void ex1850_adc_irq_update(EX1850ResetState *s)
{
    bool eoc_irq = (s->adc1_registers[0] & 2U) && (s->adc1_registers[1] & 0x20U);
    bool ovr_irq = (s->adc1_registers[0] & 0x20U) && (s->adc1_registers[1] & 0x04000000U);
    bool level = (s->apb2enr & (1U << 8)) && (eoc_irq || ovr_irq);
    if (level != s->adc_irq18_level) {
        s->adc_irq18_level = level;
        ex1850_sampled_log("EX1850_ADC_IRQ18 level=%u SR=%08x CR1=%08x "
                "conversions=%u virtual_ns=%" PRId64
                " source=clocked_ADC_SR_and_guest_CR1_only\n",
                level, s->adc1_registers[0], s->adc1_registers[1],
                s->adc_conversion_total, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    }
    if (s->armv7m) {
        qemu_set_irq(qdev_get_gpio_in(DEVICE(s->armv7m), 18), level);
    }
}

static void ex1850_adc_conversion_complete(void *opaque)
{
    EX1850ResetState *s = opaque;
    if (!s->adc_busy) { return; }
    /* Active configuration and kernel-clock changes are rejected before
     * acceptance. ADON=0 explicitly cancels this timer. */
    g_assert(s->adc1_registers[2] & 1);
    g_assert(ex1850_adc_hz(s));
    g_assert(qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) >= s->adc_conversion_due);
    /* STM32F412 RM0402 13.12.1: OVR detection is enabled only when DMA=1 or EOCS=1. */
    if ((s->adc1_registers[0] & 2) && (s->adc1_registers[2] & 0x00000500U)) {
        s->adc1_registers[0] |= 0x20;
    }
    s->adc1_registers[0x4c / 4] = s->adc_sampled_code;
    s->adc1_registers[0] |= 2;
    s->adc_busy = false;
    s->adc_conversion_total++;
    ex1850_sampled_log("EX1850_ADC_CONVERSION_EVENT channel=%u code=%u EOC=1 "
            "OVR=%u conversions=%u due_ns=%" PRId64 " virtual_ns=%" PRId64
            " source=original_start_plus_clocked_conversion_and_explicit_voltage "
            "RTOS_completion_supplied=0 factory_calibration_supplied=0\n",
            s->adc_active_channel, s->adc_sampled_code,
            !!(s->adc1_registers[0] & 0x20), s->adc_conversion_total,
            s->adc_conversion_due, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    ex1850_adc_irq_update(s);
}

static bool ex1850_adc_start_single(EX1850ResetState *s, uint32_t requested)
{
    unsigned channel = s->adc1_registers[0x34 / 4] & 31;
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    unsigned hz = ex1850_adc_hz(s);
    if (channel >= 16 || !s->adc_voltage_profile[channel] || !s->adc_vref_mv ||
        s->adc_busy || !(s->adc1_registers[2] & 1) ||
        (s->adc1_registers[1] & ~UINT32_C(0x04000020)) || (s->adc1_registers[0x2c / 4] & 0x00f00000) ||
        (requested & ~UINT32_C(0x4f000401)) || !(requested & 1) ||
        (s->adc_common_ccr & ~UINT32_C(0x00030000)) || !hz || hz > 36000000 ||
        now - s->adc_enable_epoch < 3000 || timer_pending(s->switch_timer)) {
        return false;
    }
    /* Public STM32F4 ADC pin mux. Board wiring and applied voltages are
     * independent, explicit hypotheses; the ROM must select analog mode. */
    unsigned bank = channel < 8 ? 0 : channel < 10 ? 1 : 2;
    unsigned pin = channel < 8 ? channel : channel < 10 ? channel - 8 : channel - 10;
    if (((s->gpio[bank].moder >> (2 * pin)) & 3) != 3) { return false; }
    static const unsigned samples[8] = {3, 15, 28, 56, 84, 112, 144, 480};
    unsigned sample_word = s->adc1_registers[channel < 10 ? 0x10 / 4 : 0x0c / 4];
    unsigned sample_code = (sample_word >> (3 * (channel < 10 ? channel : channel - 10))) & 7;
    unsigned cycles = samples[sample_code] + 12; /* Only 12-bit single regular mode. */
    uint64_t delay = ((uint64_t)cycles * UINT64_C(1000000000) + hz - 1) / hz;
    uint64_t ideal = (uint64_t)s->adc_pin_mv[channel] * 4096 / s->adc_vref_mv;
    s->adc_sampled_code = MIN(ideal, UINT64_C(4095));
    s->adc_active_channel = channel;
    s->adc1_registers[2] = requested & ~UINT32_C(0x40000000); /* HW clears SWSTART. */
    s->adc1_registers[0] |= 0x10; /* Hardware regular-start flag, not EOC. */
    s->adc_busy = true;
    s->adc_conversion_due = now + delay;
    timer_mod(s->adc_conversion_timer, s->adc_conversion_due);
    ex1850_sampled_log("EX1850_ADC_START channel=%u GPIO=%c%u analog_mux_selected=1 "
            "input_mv=%u reference_mv=%u resolution=12 sample_cycles=%u "
            "processing_cycles=12 ADC_hz=%u start_ns=%" PRId64 " due_ns=%" PRId64
            " STRT=1 EOC_created_by_START=0 source=explicit_offline_voltage_hypothesis "
            "physical_camera_sample=0 calibration_applied=0\n",
            channel, 'A' + bank, pin, s->adc_pin_mv[channel], s->adc_vref_mv,
            samples[sample_code], hz, now, s->adc_conversion_due);
    return true;
}

static bool ex1850_adc_control_access(EX1850ResetState *s, hwaddr addr,
                                      unsigned size, bool write, uint64_t *value)
{
    if (size != 4 || (addr & 3) || !(s->apb2enr & (1U << 8))) { return false; }
    uint32_t *reg = NULL, mask = 0;
    unsigned index = 0;
    bool read_only = false, clear_zero = false, accepted_start = false;
    if (addr == 0x40012300) {
        /* ADC1 is the only ADC in this family hypothesis. No conversion
         * or injected/external start has ever been accepted. */
        if (write) { return false; }
        *value = s->adc1_registers[0] & 0x3f;
        index = 20;
    } else if (addr == 0x40012304) {
        reg = &s->adc_common_ccr;
        mask = 0x00c3ef00; /* TSVREFE/VBATE, ADCPRE, DMA/DDS, DELAY. */
        index = 21;
        if (write && (*value & 0x0000e000)) { return false; } /* DMA backend. */
    } else if (addr >= 0x40012000 && addr <= 0x4001204c) {
        unsigned offset = addr - 0x40012000;
        index = offset / 4;
        reg = &s->adc1_registers[index];
        switch (offset) {
        case 0x00: mask = 0x3f; clear_zero = true; break; /* SR W0C. */
        case 0x04: mask = 0x07c0ffff; break;
        case 0x08:
            mask = 0x7f7f0f03;
            if (write && (*value & 0x40400000)) {
                if ((*value & 0x40400000) == 0x40000000) {
                    accepted_start = ex1850_adc_start_single(s, *value);
                }
                if (accepted_start) { break; }
                unsigned channel = s->adc1_registers[0x34 / 4] & 31;
                fprintf(stderr, "EX1850_ADC_CONVERSION_BOUNDARY requested=%08" PRIx64
                        " ADC1_ADON=%u regular_channel=%u sequence_length=%u "
                        "CCR=%08x pc=%08x virtual_ns=%" PRId64
                        " current_request_input_or_mode_unmodeled=1 "
                        "conversion_started=0 EOC_created_for_current_request=0\n",
                        *value, s->adc1_registers[2] & 1, channel,
                        ((s->adc1_registers[0x2c / 4] >> 20) & 15) + 1,
                        s->adc_common_ccr, ex1850_pc(), qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
                ex1850_unknown_access(s, addr, size, true, *value);
            }
            /* A nonzero external regular/injected trigger enable crosses
             * the unmodeled trigger backend before it can create events. */
            if (write && (*value & 0x30300300)) { return false; }
            break;
        case 0x0c: mask = 0x07ffffff; break; /* Channels10..18. */
        case 0x10: mask = 0x3fffffff; break; /* Channels0..9. */
        case 0x14: case 0x18: case 0x1c: case 0x20:
        case 0x24: case 0x28: mask = 0x0fff; break;
        case 0x2c: mask = 0x00ffffff; break;
        case 0x30: case 0x34: mask = 0x3fffffff; break;
        case 0x38: mask = 0x003fffff; break;
        case 0x3c: case 0x40: case 0x44: case 0x48: case 0x4c:
            read_only = true; break;
        default: return false;
        }
    } else { return false; }
    uint64_t requested = *value;
    if (reg) {
        if (write) {
            if (read_only || (!clear_zero && (*value & ~mask))) { return false; }
            if (s->adc_busy && !accepted_start && addr != 0x40012000 &&
                !(addr == 0x40012008 && !(*value & 1))) { return false; }
            if (!accepted_start) {
                if (addr == 0x40012008) {
                    if (!(*reg & 1) && (*value & 1)) {
                        s->adc_enable_epoch = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
                    }
                    if (!(*value & 1)) {
                        timer_del(s->adc_conversion_timer);
                        s->adc_busy = false;
                    }
                }
                if (clear_zero) { *reg &= *value & mask; }
                else { *reg = *value; }
            }
        } else {
            *value = *reg;
            if (addr == 0x4001204c) { s->adc1_registers[0] &= ~2U; }
        }
        ex1850_adc_irq_update(s);
    }
    uint64_t count = ++s->adc_access_counts[index];
    if (write || count <= 8 || !(count & (count - 1)) || s->adc_last_reads[index] != *value) {
        ex1850_sampled_log("EX1850_ADC_CONTROL %c addr=%08" HWADDR_PRIx
                " requested=%08" PRIx64 " state=%08x pc=%08x virtual_ns=%" PRId64
                " sampled_access_index=%" PRIu64
                " source=original_guest_configuration_or_family_reset "
                "conversion_busy=%u conversions=%u EOC_source=clocked_conversion_only\n",
                write ? 'W' : 'R', addr, write ? requested : *value, reg ? *reg : 0,
                ex1850_pc(), qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), count,
                s->adc_busy, s->adc_conversion_total);
    }
    s->adc_last_reads[index] = *value;
    return true;
}

static unsigned ex1850_pll_hz(EX1850ResetState *s)
{
    unsigned m = s->pllcfgr & 0x3f;
    unsigned n = (s->pllcfgr >> 6) & 0x1ff;
    unsigned p = 2 * (((s->pllcfgr >> 16) & 3) + 1);
    unsigned source = (s->pllcfgr & (1U << 22)) ? EX1850_HSE_HZ : EX1850_HSI_HZ;
    /* Encoded digital multiplier/divider only; analog operating ranges and
     * jitter are not a measured physical MCU model. */
    return m && n ? (uint64_t)source * n / m / p : 0;
}

/* RM0402 Rev7 sections15.3..15.7: the F412 default CLK48 source is PLLQ.
 * This is a functional digital model with simulated QEMU entropy, not a
 * physical noise/health-test or measured analog timing model. The CMSIS
 * F412 CR contract used by this ROM exposes RNGEN/IE only; CED and the
 * alternate PLLI2SQ source remain explicit unsupported MMIO boundaries. */
static unsigned ex1850_rng_source_hz(EX1850ResetState *s)
{
    unsigned m = s->pllcfgr & 0x3f;
    unsigned n = (s->pllcfgr >> 6) & 0x1ff;
    unsigned q = (s->pllcfgr >> 24) & 15;
    bool hse = !!(s->pllcfgr & (1U << 22));
    uint32_t source_ready = hse ? RCC_HSERDY : RCC_HSIRDY;
    if ((s->rcc_cr & (RCC_PLLON | RCC_PLLRDY | source_ready)) !=
        (RCC_PLLON | RCC_PLLRDY | source_ready) || !m || !n || q < 2) {
        return 0;
    }
    return (uint64_t)(hse ? EX1850_HSE_HZ : EX1850_HSI_HZ) * n / m / q;
}

static bool ex1850_rng_accessible(EX1850ResetState *s)
{
    return (s->ahb2enr & EX1850_RNG_AHB2_BIT) &&
           !(s->rcc_ahb2rstr & EX1850_RNG_AHB2_BIT);
}

static void ex1850_rng_irq_update(EX1850ResetState *s)
{
    bool level = ex1850_rng_accessible(s) && !s->power.stopped &&
                 (s->rng_cr & (EX1850_RNG_RNGEN | EX1850_RNG_IE)) ==
                 (EX1850_RNG_RNGEN | EX1850_RNG_IE) &&
                 (s->rng_sr & (EX1850_RNG_DRDY | EX1850_RNG_CEIS | EX1850_RNG_SEIS));
    if (level != s->rng_irq80_level) {
        s->rng_irq80_level = level;
        ex1850_sampled_log("EX1850_RNG_IRQ irq=80 level=%u CR=%08x SR=%08x "
                "virtual_ns=%" PRId64 " source=RNG_register_state\n",
                level, s->rng_cr, s->rng_sr, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    }
    if (s->armv7m) {
        qemu_set_irq(qdev_get_gpio_in(DEVICE(s->armv7m), 80), level);
    }
}

static uint64_t ex1850_rng_remaining(EX1850ResetState *s)
{
    return s->rng_start_remaining +
           ((s->rng_sr & EX1850_RNG_DRDY) ? 0 : s->rng_word_remaining);
}

static void ex1850_rng_sync(EX1850ResetState *s)
{
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    uint64_t remaining = ex1850_rng_remaining(s);
    if (s->rng_hz && remaining && now > s->rng_epoch) {
        uint64_t ns = now - s->rng_epoch;
        uint64_t until = (remaining + s->rng_hz - 1) / s->rng_hz;
        /* Clamp before multiplication; an idle full buffer cannot create
         * unbounded entropy work when virtual time advances a long way. */
        uint64_t ticks = ns >= until ? remaining : ns * s->rng_hz;
        uint64_t startup = MIN(ticks, s->rng_start_remaining);
        s->rng_start_remaining -= startup;
        ticks -= startup;
        if (!(s->rng_sr & EX1850_RNG_DRDY)) {
            s->rng_word_remaining -= MIN(ticks, s->rng_word_remaining);
            if (!s->rng_start_remaining && !s->rng_word_remaining) {
                /* In the healthy functional profile a zero DR denotes
                 * empty/error, as specified by RM0402. No seed fault is
                 * injected from a synthetic host randomness failure. */
                if (s->rng_public_count) {
                    if (s->rng_public_index == s->rng_public_count) {
                        fprintf(stderr, "EX1850_UNMODELED_ENTROPY event=public_word_stream_exhausted "
                                "provided=%u virtual_ns=%" PRId64 " guest_state_written=0\n",
                                s->rng_public_count, now);
                        exit(66);
                    }
                    s->rng_dr = s->rng_public_words[s->rng_public_index++];
                } else {
                    do {
                        qemu_guest_getrandom_nofail(&s->rng_dr, sizeof(s->rng_dr));
                    } while (!s->rng_dr);
                }
                s->rng_sr |= EX1850_RNG_DRDY;
                s->rng_word_remaining = EX1850_RNG_WORD_CYCLES * EX1850_RNG_CYCLE_SCALE;
                uint64_t words = ++s->rng_words;
                if (words <= 4 || !(words & (words - 1))) {
                    ex1850_sampled_log("EX1850_RNG_DATA words=%" PRIu64 " DRDY=1 "
                            "value=%08x virtual_ns=%" PRId64
                            " entropy=%s public_word_index=%u physical_TRNG_sample=0\n",
                            words, s->rng_dr, now,
                            s->rng_public_count ? "declared_public_synthetic_word" : "QEMU_guest_random",
                            s->rng_public_index);
                }
            }
        }
    }
    s->rng_epoch = now;
}

static void ex1850_rng_clocks_changed(EX1850ResetState *s)
{
    ex1850_rng_sync(s); /* Finish elapsed work with the previous RNG clock. */
    bool running = ex1850_rng_accessible(s) && !s->power.stopped &&
                   s->cpu_hz && (s->rng_cr & EX1850_RNG_RNGEN);
    unsigned source_hz = ex1850_rng_source_hz(s);
    if (running) {
        bool bad_clock = !source_hz || (uint64_t)source_hz * 16 <= s->cpu_hz;
        if (bad_clock) {
            if (!(s->rng_sr & EX1850_RNG_CECS)) { s->rng_sr |= EX1850_RNG_CEIS; }
            s->rng_sr |= EX1850_RNG_CECS;
        } else {
            s->rng_sr &= ~EX1850_RNG_CECS;
        }
    }
    /* RM0402 clock errors report frequency quality but do not invalidate
     * random data. The checker must not itself gate the sampling clock;
     * an absent PLLQ source still supplies zero elapsed RNG work. */
    unsigned hz = running && !(s->rng_sr & EX1850_RNG_SECS) ?
                  source_hz : 0;
    if (hz != s->rng_hz) {
        ex1850_sampled_log("EX1850_RNG_CLOCK source=PLLQ source_hz=%u effective_hz=%u "
                "HCLK_hz=%u CR=%08x SR=%08x AHB2ENR=%08x AHB2RSTR=%08x "
                "virtual_ns=%" PRId64 " physical_clock_verified=0\n",
                source_hz, hz, s->cpu_hz, s->rng_cr, s->rng_sr, s->ahb2enr,
                s->rcc_ahb2rstr, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    }
    s->rng_hz = hz;
    uint64_t remaining = ex1850_rng_remaining(s);
    if (s->rng_event) {
        if (hz && remaining) {
            timer_mod(s->rng_event, s->rng_epoch + (remaining + hz - 1) / hz);
        } else {
            timer_del(s->rng_event);
        }
    }
    ex1850_rng_irq_update(s);
}

static void ex1850_rng_event(void *opaque)
{
    ex1850_rng_clocks_changed(opaque);
}

static void ex1850_rng_peripheral_reset(EX1850ResetState *s)
{
    s->rng_cr = s->rng_sr = s->rng_dr = 0;
    s->rng_hz = 0;
    s->rng_start_remaining = 0;
    s->rng_word_remaining = EX1850_RNG_WORD_CYCLES * EX1850_RNG_CYCLE_SCALE;
    s->rng_epoch = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    if (s->rng_event) { timer_del(s->rng_event); }
    ex1850_rng_irq_update(s);
}

static void ex1850_rng_reset(void *opaque)
{
    EX1850ResetState *s = opaque;
    s->ahb2enr &= ~EX1850_RNG_AHB2_BIT;
    s->rcc_ahb2rstr &= ~EX1850_RNG_AHB2_BIT;
    ex1850_rng_peripheral_reset(s);
}

static bool ex1850_rng_access(EX1850ResetState *s, hwaddr addr, unsigned size,
                               bool write, uint64_t *value)
{
    if (addr < 0x50060800 || addr >= 0x50060c00) { return false; }
    if (size != 4 || (addr & 3) || addr > 0x50060808 || *value > UINT32_MAX) {
        ex1850_unknown_access(s, addr, size, write, *value);
    }
    ex1850_rng_clocks_changed(s);
    uint32_t requested = *value;
    if (!ex1850_rng_accessible(s)) {
        if (!write) { *value = 0; }
    } else if (addr == 0x50060800) {
        if (write) {
            if (requested & ~(EX1850_RNG_RNGEN | EX1850_RNG_IE)) {
                ex1850_unknown_access(s, addr, size, write, *value);
            }
            if ((s->rng_cr ^ requested) & EX1850_RNG_RNGEN) {
                s->rng_start_remaining = (requested & EX1850_RNG_RNGEN) ?
                    EX1850_RNG_START_CYCLES * EX1850_RNG_CYCLE_SCALE : 0;
                s->rng_word_remaining = EX1850_RNG_WORD_CYCLES * EX1850_RNG_CYCLE_SCALE;
            }
            s->rng_cr = requested;
        } else {
            *value = s->rng_cr;
        }
    } else if (addr == 0x50060804) {
        if (write) {
            /* ST LL/HAL use inverse masks, including reserved one bits.
             * Only CEIS/SEIS are writable, and both are write-zero-clear. */
            s->rng_sr &= requested | ~(EX1850_RNG_CEIS | EX1850_RNG_SEIS);
        } else {
            *value = s->rng_sr;
        }
    } else if (!write) {
        *value = (s->rng_sr & EX1850_RNG_DRDY) ? s->rng_dr : 0;
        s->rng_dr = 0;
        s->rng_sr &= ~EX1850_RNG_DRDY;
    } /* Writes to the read-only DR do not create data or ready state. */
    ex1850_rng_clocks_changed(s);
    ex1850_sampled_log("EX1850_RNG_ACCESS %c addr=%08" HWADDR_PRIx
            " value=%08x CR=%08x SR=%08x pc=%08x virtual_ns=%" PRId64
            " software_completion_supplied=0\n", write ? 'W' : 'R', addr,
            write ? requested : (uint32_t)*value, s->rng_cr, s->rng_sr,
            ex1850_pc(), qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    return true;
}

static unsigned ex1850_source_hz(EX1850ResetState *s, unsigned source)
{
    switch (source) {
    case 0: return (s->rcc_cr & RCC_HSIRDY) ? EX1850_HSI_HZ : 0;
    case 1: return (s->rcc_cr & RCC_HSERDY) ? EX1850_HSE_HZ : 0;
    case 2: return (s->rcc_cr & RCC_PLLRDY) ? ex1850_pll_hz(s) : 0;
    default: return 0; /* No unimplemented alternate clock source. */
    }
}

static void ex1850_update_clock(EX1850ResetState *s)
{
    static const unsigned shifts[16] = {0, 0, 0, 0, 0, 0, 0, 0,
                                       1, 2, 3, 4, 6, 7, 8, 9};
    unsigned hz = ex1850_source_hz(s, (s->cfgr >> 2) & 3);
    hz >>= shifts[(s->cfgr >> 4) & 15];
    if (s->power.stopped) { hz = 0; }
    ex1850_flash_sync(s);
    if ((s->flash.sr & EX1850_FLASH_BSY) && hz < 1000000) {
        ex1850_flash_boundary(&s->flash, "HCLK-change-below-one-MHz-while-busy");
        ex1850_flash_stop(s, 0x40023808, 4, true, s->cfgr);
    }
    if (hz != s->cpu_hz) {
        /* Both counters were synchronized before CFGR changed, while
         * their old HCLK/APB divisors were still effective. */
        s->cpu_hz = hz;
        clock_update_hz(s->cpuclk, hz);
        fprintf(stderr, "EX1850_HCLK hz=%u CFGR=%08x PLLCFGR=%08x "
                "virtual_ns=%" PRId64 " measured_physical_clock=0\n",
                hz, s->cfgr, s->pllcfgr, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    }
    ex1850_spi2_clocks_changed(s);
    ex1850_usart1_clocks_changed(s);
    ex1850_usart2_clocks_changed(s);
    ex1850_tim5_schedule(s);
    ex1850_tim11_schedule(s);
    ex1850_tim12_schedule(s);
    ex1850_tim1_schedule(s);
    ex1850_tim10_schedule(s);
    for (unsigned n = 0; n < 3; n++) { ex1850_tim234_schedule(s, n); }
    ex1850_rng_clocks_changed(s);
}

static void ex1850_sync_timer_clocks(EX1850ResetState *s, const char *reason)
{
    ex1850_spi2_sync(s);
    ex1850_usart1_sync(s);
    ex1850_usart2_sync(s);
    unsigned old5_hz = ex1850_tim5_hz(s), old11_hz = ex1850_tim11_hz(s);
    ex1850_tim5_sync(s);
    ex1850_tim11_sync(s);
    ex1850_tim12_sync(s);
    ex1850_tim1_sync(s);
    ex1850_tim10_sync(s);
    for (unsigned n = 0; n < 3; n++) { ex1850_tim234_clock_sync(s, n); }
    fprintf(stderr, "EX1850_TIMER_CLOCK_SYNC reason=%s old_HCLK_hz=%u "
            "old_CFGR=%08x old_TIM5_hz=%u old_TIM11_hz=%u "
            "TIM5_CNT=%08x TIM11_CNT=%04x TIM12_CNT=%04x virtual_ns=%" PRId64
            " source=elapsed_virtual_time_at_old_clock software_completion_supplied=0\n",
            reason, s->cpu_hz, s->cfgr, old5_hz, old11_hz, s->tim5_cnt, s->tim11_cnt, s->tim12.cnt,
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
}

static void ex1850_request_switch(EX1850ResetState *s)
{
    unsigned source = s->cfgr & 3;
    if (source != ((s->cfgr >> 2) & 3) && ex1850_source_hz(s, source)) {
        timer_mod(s->switch_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + EX1850_SWITCH_NS);
    }
}

static void ex1850_switch_ready(void *opaque)
{
    EX1850ResetState *s = opaque;
    unsigned source = s->cfgr & 3;
    if (ex1850_source_hz(s, source)) {
        ex1850_sync_timer_clocks(s, "SYSCLK_source_switch");
        s->cfgr = (s->cfgr & ~0xcU) | (source << 2);
        fprintf(stderr, "EX1850_CLOCK_EVENT source_selected=%u CFGR=%08x "
                "virtual_ns=%" PRId64 "\n", source, s->cfgr,
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
        ex1850_update_clock(s);
    }
}

static void ex1850_start_pll_if_possible(EX1850ResetState *s)
{
    unsigned source = (s->pllcfgr & (1U << 22)) ? RCC_HSERDY : RCC_HSIRDY;
    if ((s->rcc_cr & RCC_PLLON) && !(s->rcc_cr & RCC_PLLRDY) &&
        (s->rcc_cr & source) && ex1850_pll_hz(s) && !timer_pending(s->pll_timer)) {
        timer_mod(s->pll_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + EX1850_PLL_LOCK_NS);
    }
}

static void ex1850_hse_ready(void *opaque)
{
    EX1850ResetState *s = opaque;
    if (s->hse_present && (s->rcc_cr & RCC_HSEON)) {
        s->rcc_cr |= RCC_HSERDY;
        fprintf(stderr, "EX1850_CLOCK_EVENT HSE_stable=1 virtual_ns=%" PRId64 "\n",
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
        ex1850_start_pll_if_possible(s);
        ex1850_request_switch(s);
        ex1850_rng_clocks_changed(s);
    }
}

static void ex1850_pll_ready(void *opaque)
{
    EX1850ResetState *s = opaque;
    unsigned source = (s->pllcfgr & (1U << 22)) ? RCC_HSERDY : RCC_HSIRDY;
    if ((s->rcc_cr & RCC_PLLON) && (s->rcc_cr & source) && ex1850_pll_hz(s)) {
        s->rcc_cr |= RCC_PLLRDY;
        fprintf(stderr, "EX1850_CLOCK_EVENT PLL_locked=1 PLLCFGR=%08x "
                "PLLP_hz=%u virtual_ns=%" PRId64 "\n", s->pllcfgr,
                ex1850_pll_hz(s), qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
        ex1850_request_switch(s);
        ex1850_rng_clocks_changed(s);
    }
}

static bool ex1850_rtc_clock_active(EX1850ResetState *s)
{
    return (s->rcc_bdcr & (RCC_LSERDY | RCC_RTCEN | RCC_BDRST)) ==
           (RCC_LSERDY | RCC_RTCEN) && ((s->rcc_bdcr >> 8) & 3) == 1;
}

static void ex1850_rtc_events(EX1850ResetState *s, const uint64_t before[8])
{
    EX1850RTC *r = &s->rtc;
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    if (r->init_events != before[0]) {
        fprintf(stderr, "EX1850_RTC_CLOCK_EVENT init_mode_entered=1 ISR=%08x "
                "virtual_ns=%" PRId64 " transition_cycles_hypothesis=%u "
                "event_LSE_cycle=%" PRIu64 " application_success_fixture=0\n",
                r->isr, now, EX1850_RTC_INIT_CYCLES, r->init_due);
    }
    if (r->restart_events != before[1]) {
        fprintf(stderr, "EX1850_RTC_CLOCK_EVENT counting_restarted=1 ISR=%08x "
                "SSR=%04x virtual_ns=%" PRId64 " restart_cycles=%u "
                "event_LSE_cycle=%" PRIu64 " INITS_is_not_run_enable=1\n",
                r->isr, r->ssr, now, EX1850_RTC_RESTART_CYCLES, r->restart_due);
    }
    if (r->sync_events != before[2]) {
        fprintf(stderr, "EX1850_RTC_CLOCK_EVENT shadow_synchronized=1 ISR=%08x "
                "virtual_ns=%" PRId64 " transition_cycles_hypothesis=%u "
                "event_LSE_cycle=%" PRIu64 " application_success_fixture=0\n",
                r->isr, now, EX1850_RTC_TRANSITION_CYCLES, r->sync_due);
    }
    if (r->calendar_ticks != before[3] &&
        (r->calendar_ticks <= 4 || !(r->calendar_ticks & (r->calendar_ticks - 1)) ||
         r->calendar_ticks - before[3] > 1)) {
        fprintf(stderr, "EX1850_RTC_CLOCK_EVENT calendar_increment=%" PRIu64
                " TR=%08x DR=%08x virtual_ns=%" PRId64 " host_wall_date_used=0 "
                "LSE_cycle=%" PRIu64 " SSR=%04x no_period_rounding_drift=1\n",
                r->calendar_ticks, r->tr, r->dr, now, r->cycles, r->ssr);
    }
    for (unsigned i = 0; i < 2; i++) {
        if (r->alarm_events[i] != before[4 + i]) {
            fprintf(stderr, "EX1850_RTC_ALARM_EVENT alarm=%c flag_set=1 "
                    "count=%" PRIu64 " ISR=%08x ALRMR=%08x ALRMSSR=%08x "
                    "event_LSE_cycle=%" PRIu64 " event_virtual_ns=%" PRId64
                    " observed_virtual_ns=%" PRId64 " original_control_required=1\n",
                    'A' + i, r->alarm_events[i], r->isr, r->alarm[i], r->alarm_ss[i],
                    r->alarm_last_cycle[i], r->alarm_last_ns[i], now);
        }
        if (r->alarm_clear_events[i] != before[6 + i]) {
            fprintf(stderr, "EX1850_RTC_ALARM_EVENT alarm=%c flag_cleared=1 "
                    "count=%" PRIu64 " ISR=%08x event_virtual_ns=%" PRId64
                    " observed_virtual_ns=%" PRId64 " delay_APB_cycles=2\n",
                    'A' + i, r->alarm_clear_events[i], r->isr,
                    r->alarm_clear_last_ns[i], now);
        }
    }
}

static void ex1850_rtc_schedule(EX1850ResetState *s)
{
    int64_t due = ex1850_rtc_deadline(&s->rtc);
    if (due < 0) { timer_del(s->rtc_event); }
    else { timer_mod(s->rtc_event, due); }
}

static void ex1850_rtc_reschedule(EX1850ResetState *s)
{
    uint64_t before[] = {s->rtc.init_events, s->rtc.restart_events,
                         s->rtc.sync_events, s->rtc.calendar_ticks,
                         s->rtc.alarm_events[0], s->rtc.alarm_events[1],
                         s->rtc.alarm_clear_events[0], s->rtc.alarm_clear_events[1]};
    ex1850_rtc_set_clock(&s->rtc, ex1850_rtc_clock_active(s),
                        qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    ex1850_rtc_events(s, before);
    ex1850_rtc_schedule(s);
}

static void ex1850_rtc_event(void *opaque)
{
    ex1850_rtc_reschedule(opaque);
}

static void ex1850_rtc_isr_log(EX1850ResetState *s, bool write,
                               uint32_t requested, bool protected)
{
    uint64_t count = ++s->rtc_isr_access_count;
    if (write || count <= 8 || !(count & (count - 1))) {
        fprintf(stderr, "EX1850_RTC_ISR %c requested=%08x state=%08x "
                "low_control_write_ignored_DBP_or_WPR=%u DBP=%u "
                "high_flags_bypass_WPR=1 clear_A_due_ns=%" PRId64
                " clear_B_due_ns=%" PRId64 " pc=%08x virtual_ns=%" PRId64
                " sampled_access_index=%" PRIu64 "\n", write ? 'W' : 'R',
                requested, s->rtc.isr, protected, !!(s->pwr_cr & 0x100),
                s->rtc.alarm_clear_due[0], s->rtc.alarm_clear_due[1], ex1850_pc(),
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), count);
    }
}

static bool ex1850_i2c_control_register(EX1850ResetState *s, hwaddr addr,
                                        uint32_t **reg, uint32_t *mask)
{
    switch (addr) {
    /* PE/SWRST plus START/STOP/ACK/POS latches in an explicitly selected
     * electrical scenario. Optional address/pointer ACK is a declared
     * candidate-device protocol; external receive data is still absent. */
    case 0x40005400: *reg = &s->i2c1.cr1; *mask = 0x8f01; return true;
    case 0x40005404: *reg = &s->i2c1.cr2; *mask = 0x073f; return true;
    case 0x40005408: *reg = &s->i2c1.oar1; *mask = 0x40fe; return true;
    case 0x4000540c: *reg = &s->i2c1.oar2; *mask = 0x00fe; return true;
    case 0x4000541c: *reg = &s->i2c1.ccr; *mask = 0xcfff; return true;
    case 0x40005420: *reg = &s->i2c1.trise; *mask = 0x003f; return true;
    default: return false;
    }
}

static void ex1850_i2c_irq_update(EX1850ResetState *s)
{
    if (!s->armv7m) { return; }
    /* ROM callback maps identify I2C1 EV=IRQ31 and ER=IRQ32. Hardware
     * SB/ADDR/BTF/TXE/RXNE and AF assert actual NVIC input lines.
     * Receive data requires an explicit external pin scenario. This
     * function never supplies an application completion notification. */
    qemu_set_irq(qdev_get_gpio_in(DEVICE(s->armv7m), 31),
                 !!((s->i2c1.cr2 & 0x200) &&
                    ((s->i2c1.sr1 & 7) ||
                     ((s->i2c1.cr2 & 0x400) && (s->i2c1.sr1 & 0xc0)))));
    qemu_set_irq(qdev_get_gpio_in(DEVICE(s->armv7m), 32),
                 !!((s->i2c1.cr2 & 0x100) && (s->i2c1.sr1 & 0x400)));
}

static bool ex1850_i2c2_control_register(EX1850ResetState *s, hwaddr addr,
                                        uint32_t **reg, uint32_t *mask)
{
    /* Configuration and reset latches only. I2C2 SR1/SR2/DR, pads,
     * START/STOP, interrupts, ACK and receive data remain strict. */
    switch (addr) {
    case 0x40005800: *reg = &s->i2c2.cr1; *mask = 0x8001; return true;
    case 0x40005804: *reg = &s->i2c2.cr2; *mask = 0x073f; return true;
    case 0x40005808: *reg = &s->i2c2.oar1; *mask = 0x40fe; return true;
    case 0x4000580c: *reg = &s->i2c2.oar2; *mask = 0x00fe; return true;
    case 0x4000581c: *reg = &s->i2c2.ccr; *mask = 0xcfff; return true;
    case 0x40005820: *reg = &s->i2c2.trise; *mask = 0x003f; return true;
    default: return false;
    }
}

static void ex1850_i2c2_control_log(EX1850ResetState *s, hwaddr addr,
                                    bool write, uint32_t requested,
                                    uint32_t state)
{
    fprintf(stderr, "EX1850_I2C2_CONTROL %c addr=%08" HWADDR_PRIx
            " requested=%08x state=%08x pc=%08x virtual_ns=%" PRId64
            " clock_enabled=%u board_bus_state_and_device_data_supplied=0\n", write ? 'W' : 'R',
            addr, requested, state, ex1850_pc(), qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
            !!(s->apb1enr & (1U << 22)));
}

static void ex1850_i2c_controller_reset(EX1850ResetState *s, unsigned controller)
{
    EX1850I2CControl *i2c = controller == 1 ? &s->i2c1 : &s->i2c2;
    memset(i2c, 0, sizeof(*i2c));
    i2c->trise = 2;
    if (controller == 1) {
        timer_del(s->i2c_start_timer);
        timer_del(s->i2c_nack_timer);
        timer_del(s->i2c_stop_timer);
        timer_del(s->i2c_external_input_timer);
        s->i2c_addr_sr1_read = false;
        s->i2c_pending_phase = 0;
        s->i2c_active_device = EX1850_I2C_UNPROVIDED;
        s->i2c_repeated_start = false;
        s->i2c_rx_in_flight = false;
        s->i2c_rx_nacked = false;
        s->i2c_rx_count = 0;
        s->i2c_tx_count = 0;
        s->i2c_expect_pointer = false;
        s->i2c_stop_waits_for_receive = false;
        s->i2c_start_waits_for_transmit = false;
        s->i2c_stop_waits_for_transmit = false;
        ex1850_i2c_irq_update(s);
    }
    /* Controller reset never resets the external GPIO expander, changes
     * its pins or supplies a transfer. I2C2 MMIO remains a strict boundary. */
    fprintf(stderr, "EX1850_I2C_RESET controller=%u source=original_APB1RSTR_write "
            "control_reset=1 external_device_reset=0 application_completion=0 "
            "virtual_ns=%" PRId64 "\n", controller,
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
}

static bool ex1850_i2c_pin_route(EX1850ResetState *s)
{
    EX1850GPIOControl *g = &s->gpio[1];
    /* The original code configures PB8=SCL/PB9=SDA, AF4, open drain.
     * This checks the actual guest-written control latches. Pad voltages
     * and pull-up existence remain explicit unmeasured bus assumptions. */
    return (s->ahb1enr & 2) && ((g->moder >> 16) & 15) == 10 &&
           (g->otyper & 0x300) == 0x300 && (g->afrh & 0xff) == 0x44;
}

static int64_t ex1850_i2c_scl_period(EX1850ResetState *s)
{
    uint32_t divider = s->i2c1.ccr & 0xfff;
    unsigned ppre = (s->cfgr >> 10) & 7;
    unsigned pclk = s->cpu_hz;
    if (ppre >= 4) { pclk >>= ppre - 3; }
    unsigned multiplier = (s->i2c1.ccr & 0x8000) ?
                          ((s->i2c1.ccr & 0x4000) ? 25 : 3) : 2;
    return divider && pclk ?
        ((int64_t)divider * multiplier * 1000000000 + pclk - 1) / pclk : 0;
}

static bool ex1850_pcal_register_defined(unsigned reg)
{
    return (reg <= 0x0e && (reg & 3) != 3) ||
           (reg >= 0x40 && reg <= 0x45) ||
           (reg >= 0x48 && reg <= 0x5a && (reg & 3) != 3) ||
           reg == 0x5c || (reg >= 0x60 && reg <= 0x65) ||
           (reg >= 0x68 && reg <= 0x76 && (reg & 3) != 3);
}

static void ex1850_pcal_pointer_advance(EX1850ResetState *s)
{
    unsigned reg = s->pcal_pointer & 0x7f;
    if (s->pcal_pointer & 0x80) {
        do { reg = reg == 0x76 ? 0 : reg + 1; }
        while (!ex1850_pcal_register_defined(reg));
    } else if (reg == 0x5c) {
        return;
    } else if (reg >= 0x40 && reg <= 0x45) {
        reg = reg == 0x45 ? 0x40 : reg + 1;
    } else if (reg >= 0x60 && reg <= 0x65) {
        reg = reg == 0x65 ? 0x60 : reg + 1;
    } else {
        reg = (reg & 3) == 2 ? reg - 2 : reg + 1;
    }
    s->pcal_pointer = (s->pcal_pointer & 0x80) | reg;
}

static void ex1850_pcal_cold_register_reset(EX1850ResetState *s)
{
    /* PCAL6524 Rev2 Table6, pages12..14. This is the selected external
     * device's cold power/reset hypothesis, never an MCU-reset side effect.
     * Undefined input/status registers are resolved only by pin behavior. */
    memset(s->pcal_registers, 0, sizeof(s->pcal_registers));
    memset(s->pcal_interrupt_sources, 0, sizeof(s->pcal_interrupt_sources));
    memset(s->pcal_latched_pending, 0, sizeof(s->pcal_latched_pending));
    memset(s->pcal_edge_pending, 0, sizeof(s->pcal_edge_pending));
    for (unsigned port = 0; port < 3; port++) {
        s->pcal_sampled_levels[port] = s->pcal_pin_levels >> (8 * port);
        s->pcal_latched_levels[port] = s->pcal_sampled_levels[port];
    }
    for (unsigned reg = 0; reg <= 0x76; reg++) {
        if ((reg >= 4 && reg <= 6) || (reg >= 0x0c && reg <= 0x0e) ||
            (reg >= 0x40 && reg <= 0x45) || (reg >= 0x50 && reg <= 0x52) ||
            (reg >= 0x54 && reg <= 0x56)) {
            s->pcal_registers[reg] = 0xff;
        }
    }
    s->pcal_pointer = 0;
}

static unsigned ex1850_pcal_edge_mode(EX1850ResetState *s, unsigned port,
                                      unsigned pin)
{
    return (s->pcal_registers[0x60 + 2 * port + pin / 4] >>
            (2 * (pin % 4))) & 3;
}

static void ex1850_pcal_refresh_interrupts(EX1850ResetState *s)
{
    for (unsigned port = 0; port < 3; port++) {
        uint8_t external = s->pcal_pin_levels >> (8 * port);
        uint8_t inputs = s->pcal_registers[0x0c + port];
        uint8_t latch = s->pcal_registers[0x48 + port] & inputs;
        uint8_t edge_inputs = 0;
        for (unsigned pin = 0; pin < 8; pin++) {
            if (ex1850_pcal_edge_mode(s, port, pin)) {
                edge_inputs |= 1U << pin;
            }
        }
        /* Rev2 pp21-22: selected edges are latched independently of the
         * input-data latch. Masking, changing the pin to output or IE=00
         * clears its old edge source. Level mode still compares sampled
         * inputs, retaining a latched input until its acknowledgement. */
        s->pcal_edge_pending[port] &= inputs & edge_inputs &
                                      ~s->pcal_registers[0x54 + port];
        s->pcal_interrupt_sources[port] = s->pcal_edge_pending[port] |
            ((s->pcal_latched_pending[port] |
              ((external ^ s->pcal_sampled_levels[port]) & ~latch)) &
             inputs & ~edge_inputs);
    }
}

static void ex1850_pcal_input_edges(EX1850ResetState *s, uint32_t previous)
{
    for (unsigned port = 0; port < 3; port++) {
        uint8_t external = s->pcal_pin_levels >> (8 * port);
        uint8_t inputs = s->pcal_registers[0x0c + port];
        uint8_t latch = s->pcal_registers[0x48 + port] & inputs;
        uint8_t changed = ((previous >> (8 * port)) ^ external) & inputs;
        uint8_t acquire = changed & latch & ~s->pcal_latched_pending[port];
        s->pcal_latched_levels[port] =
            (s->pcal_latched_levels[port] & ~acquire) | (external & acquire);
        s->pcal_latched_pending[port] =
            (s->pcal_latched_pending[port] | acquire) & latch;
        for (unsigned pin = 0; pin < 8; pin++) {
            uint8_t bit = 1U << pin;
            unsigned mode = ex1850_pcal_edge_mode(s, port, pin);
            bool rising = (external & bit) != 0;
            if ((changed & bit) && (mode == 3 ||
                (mode == 1 && rising) || (mode == 2 && !rising))) {
                s->pcal_edge_pending[port] |= bit;
            }
        }
    }
    ex1850_pcal_refresh_interrupts(s);
}

static void ex1850_pcal_pin_event(void *opaque)
{
    EX1850ResetState *s = opaque;
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    while (s->pcal_pin_event_next < s->pcal_pin_event_count &&
           s->pcal_pin_events[s->pcal_pin_event_next].when_ns <= now) {
        unsigned index = s->pcal_pin_event_next++;
        uint32_t previous = s->pcal_pin_levels;
        uint32_t mask = s->pcal_pin_events[index].mask;
        s->pcal_pin_levels = (previous & ~mask) |
                            (s->pcal_pin_events[index].levels & mask);
        ex1850_pcal_input_edges(s, previous);
        fprintf(stderr, "EX1850_PCAL_PIN_EVENT index=%u virtual_ns=%" PRId64
                " scheduled_ns=%" PRId64 " mask=%06x previous=%06x levels=%06x"
                " source=timed_external_pin_scenario input_latch=%02x,%02x,%02x"
                " interrupt_status=%02x,%02x,%02x MCU_EXTI_connection=unprovided"
                " guest_RAM_write=0 protocol_packet_supplied=0\n",
                index, now, s->pcal_pin_events[index].when_ns, mask, previous,
                s->pcal_pin_levels, s->pcal_latched_pending[0],
                s->pcal_latched_pending[1], s->pcal_latched_pending[2],
                s->pcal_interrupt_sources[0] & ~s->pcal_registers[0x54],
                s->pcal_interrupt_sources[1] & ~s->pcal_registers[0x55],
                s->pcal_interrupt_sources[2] & ~s->pcal_registers[0x56]);
    }
    if (s->pcal_pin_event_next < s->pcal_pin_event_count) {
        timer_mod(s->pcal_pin_event_timer,
                  s->pcal_pin_events[s->pcal_pin_event_next].when_ns);
    }
}

/* Host input changes the external PCAL pads only. The original MCU still
 * owns I2C reads, debounce, callbacks and the EXPEED KEY packet producer. */
static void ex1850_pcal_host_get(Object *obj, Visitor *v, const char *name,
                                void *opaque, Error **errp)
{
    EX1850ResetState *s = opaque;
    uint64_t levels = s->pcal_pin_levels;
    visit_type_uint64(v, name, &levels, errp);
}

static void ex1850_pcal_host_set(Object *obj, Visitor *v, const char *name,
                                void *opaque, Error **errp)
{
    EX1850ResetState *s = opaque;
    uint64_t levels = 0;
    if (!visit_type_uint64(v, name, &levels, errp)) {
        return;
    }
    if (!s->i2c_pcal6524 || !s->pcal_pin_profile || levels > 0xffffff) {
        error_setg(errp, "PCAL host input requires explicit PCAL6524 pads and 24-bit levels");
        return;
    }
    uint32_t previous = s->pcal_pin_levels;
    s->pcal_pin_levels = levels;
    ex1850_pcal_input_edges(s, previous);
    fprintf(stderr, "EX1850_PCAL_HOST_EDGE index=%" PRIu64
            " virtual_ns=%" PRId64 " host_ns=%" PRId64
            " previous=%06x levels=%06x source=external_host_input"
            " guest_RAM_write=0 protocol_packet_supplied=0\n",
            ++s->pcal_host_edge_count, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
            qemu_clock_get_ns(QEMU_CLOCK_REALTIME), previous,
            s->pcal_pin_levels);
}

/* Runtime changes of explicitly declared digital input pads. EXTI pending
 * derives only from an actual routed edge; the original guest selects its
 * trigger, controls IMR/NVIC, and clears sticky PR. PG6 live wire ownership
 * and unsupported event wakeup remain explicit boundaries. */
static unsigned ex1850_gpio_host_bank(const char *name)
{
    return name[strlen(name) - 1] - 'A';
}

static void ex1850_gpio_host_get(Object *obj, Visitor *v, const char *name,
                                void *opaque, Error **errp)
{
    EX1850ResetState *s = opaque;
    unsigned bank = ex1850_gpio_host_bank(name);
    if (bank >= 8 || !s->gpio_pin_profile[bank]) {
        error_setg(errp, "GPIO host input requires an explicit port profile");
        return;
    }
    uint64_t levels = s->gpio_pin_levels[bank];
    visit_type_uint64(v, name, &levels, errp);
}

static void ex1850_gpio_host_set(Object *obj, Visitor *v, const char *name,
                                void *opaque, Error **errp)
{
    EX1850ResetState *s = opaque;
    unsigned bank = ex1850_gpio_host_bank(name);
    uint64_t levels = 0;
    if (!visit_type_uint64(v, name, &levels, errp)) {
        return;
    }
    if (bank >= 8 || !s->gpio_pin_profile[bank] || levels > 0xffff) {
        error_setg(errp, "GPIO host input requires explicit A..H pads and 16-bit levels");
        return;
    }
    uint16_t previous = s->gpio_pin_levels[bank];
    uint16_t changed = previous ^ levels;
    if (changed & ~s->gpio_pin_known_mask[bank]) {
        error_setg(errp, "GPIO host input cannot change undeclared input pads");
        return;
    }
    for (unsigned pin = 0; pin < 16; pin++) {
        if (!(changed & (1U << pin))) {
            continue;
        }
        if (((s->gpio[bank].moder >> (2 * pin)) & 3) != 0) {
            error_setg(errp, "GPIO host input supports digital input mode only");
            return;
        }
        if (bank == 6 && pin == 6 && s->wire.bus) {
            error_setg(errp, "GPIO PG6 is owned by the live EXPEED wire");
            return;
        }
        unsigned route = (s->syscfg_exticr[pin / 4] >> (4 * (pin % 4))) & 15;
        if (route == bank && (s->exti_emr & (1U << pin))) {
            error_setg(errp, "GPIO host input cannot drive an unmodeled EXTI event wake source");
            return;
        }
    }
    ex1850_wire_poll(s);
    uint16_t routed = ex1850_gpio_exti_routes(s->syscfg_exticr, bank, changed);
    uint32_t pr_before = s->exti_pr;
    s->gpio_pin_levels[bank] = levels;
    if (!changed) {
        return;
    }
    s->exti_pr = ex1850_gpio_exti_pending(s->exti_pr, s->exti_rtsr,
        s->exti_ftsr, routed, previous, levels);
    ex1850_gpio_exti_irq_update(s);
    fprintf(stderr, "EX1850_GPIO_HOST_EDGE index=%" PRIu64
            " bank=%c previous=%04x levels=%04x changed=%04x known_mask=%04x"
            " MODER=%08x routed=%04x EXTICR=%04x,%04x,%04x,%04x"
            " RTSR=%08x FTSR=%08x IMR=%08x EMR=%08x"
            " PR_before=%08x PR_after=%08x virtual_ns=%" PRId64 " host_ns=%" PRId64
            " source=external_host_input guest_RAM_write=0"
            " protocol_packet_supplied=0 native_EXTI_IRQ_delivery=1\n",
            ++s->gpio_host_edge_count, 'A' + bank, previous,
            s->gpio_pin_levels[bank], changed, s->gpio_pin_known_mask[bank],
            s->gpio[bank].moder, routed, s->syscfg_exticr[0], s->syscfg_exticr[1],
            s->syscfg_exticr[2], s->syscfg_exticr[3], s->exti_rtsr, s->exti_ftsr,
            s->exti_imr, s->exti_emr, pr_before, s->exti_pr,
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
            qemu_clock_get_ns(QEMU_CLOCK_REALTIME));
}

static bool ex1850_pcal_register_read(EX1850ResetState *s, unsigned reg,
                                      uint8_t *value)
{
    if (!ex1850_pcal_register_defined(reg) || (reg >= 0x68 && reg <= 0x6a)) {
        return false;
    }
    if (reg <= 2 || (reg >= 0x6c && reg <= 0x6e)) {
        if (!s->pcal_pin_profile) { return false; }
        unsigned port = reg <= 2 ? reg : reg - 0x6c;
        uint8_t inputs = s->pcal_registers[0x0c + port];
        uint8_t external = s->pcal_pin_levels >> (port * 8);
        uint8_t output = s->pcal_registers[4 + port];
        uint8_t od = ((s->pcal_registers[0x5c] & (1U << port)) ? 0xff : 0) ^
                     s->pcal_registers[0x70 + port];
        /* Declared driven input levels; no contention on push-pull outputs.
         * Open-drain outputs always read0, even when released (pp15,23).
         * Per-pin IOCR reverses the port ODEN mode (p24). Extended input
         * registers read current levels without acknowledging an interrupt. */
        if (reg <= 2) {
            uint8_t latched = s->pcal_latched_pending[port];
            external = (external & ~latched) |
                       (s->pcal_latched_levels[port] & latched);
        }
        *value = (external & inputs) | (output & ~inputs & ~od);
        if (reg <= 2) {
            *value ^= s->pcal_registers[8 + port] & inputs;
            s->pcal_sampled_levels[port] = s->pcal_pin_levels >> (8 * port);
            s->pcal_latched_pending[port] = 0;
            s->pcal_edge_pending[port] = 0;
            ex1850_pcal_refresh_interrupts(s);
        }
        return true;
    }
    if (reg >= 0x58 && reg <= 0x5a) {
        unsigned port = reg - 0x58;
        *value = s->pcal_interrupt_sources[port] & ~s->pcal_registers[0x54 + port];
        return true;
    }
    *value = s->pcal_registers[reg];
    return true;
}

static void ex1850_pcal_register_write(EX1850ResetState *s, uint8_t data)
{
    unsigned reg = s->pcal_pointer & 0x7f;
    /* Input-port writes ACK with no effect (p15). Other read-only writes
     * remain a boundary. Debounce controls stay strict when enabled. */
    if (!ex1850_pcal_register_defined(reg) ||
        (reg >= 0x58 && reg <= 0x5a) || (reg >= 0x6c && reg <= 0x6e) ||
        (reg >= 0x74 && data) || (reg == 0x5c && (data & ~7))) {
        ex1850_unknown_access(s, 0x40005410, 1, true, data);
    }
    if (reg >= 0x68 && reg <= 0x6a) {
        unsigned port = reg - 0x68;
        uint8_t external = s->pcal_pin_levels >> (8 * port);
        s->pcal_interrupt_sources[port] &= ~data;
        s->pcal_latched_pending[port] &= ~data;
        s->pcal_edge_pending[port] &= ~data;
        s->pcal_sampled_levels[port] =
            (s->pcal_sampled_levels[port] & ~data) | (external & data);
        ex1850_pcal_refresh_interrupts(s);
        /* Write-one clearing bit self-returns0, p23. */
    } else if (reg > 2) {
        s->pcal_registers[reg] = data;
        if ((reg >= 0x0c && reg <= 0x0e) ||
            (reg >= 0x48 && reg <= 0x4a) ||
            (reg >= 0x54 && reg <= 0x56) ||
            (reg >= 0x60 && reg <= 0x65)) {
            ex1850_pcal_input_edges(s, s->pcal_pin_levels);
        }
    }
    fprintf(stderr, "EX1850_PCAL_REGISTER W reg=%02x byte=%02x latch=%02x "
            "source=clocked_original_DR_byte virtual_ns=%" PRId64
            " application_completion_supplied=0 dynamic_pin_events=%u\n",
            reg, data, s->pcal_registers[reg], qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
            s->pcal_pin_event_count);
    ex1850_pcal_pointer_advance(s);
}

static const char *ex1850_i2c_device_name(EX1850ResetState *s)
{
    return s->i2c_active_device == EX1850_I2C_MAX77711 ?
           "MAX77511_MAX77711_candidate" : "PCAL6524_candidate";
}

static unsigned ex1850_i2c_device_address(EX1850ResetState *s)
{
    return s->i2c_active_device == EX1850_I2C_MAX77711 ? 0x4f : 0x22;
}

static bool ex1850_i2c_buffered_device(EX1850ResetState *s)
{
    return s->i2c_active_device == EX1850_I2C_MAX77711 ||
           (s->i2c_active_device == EX1850_I2C_PCAL6524 && s->pcal_pin_profile);
}

static unsigned ex1850_i2c_device_pointer(EX1850ResetState *s)
{
    return s->i2c_active_device == EX1850_I2C_MAX77711 ?
           s->max77711_pointer : s->pcal_pointer & 0x7f;
}

static void ex1850_i2c_device_pointer_advance(EX1850ResetState *s)
{
    if (s->i2c_active_device == EX1850_I2C_MAX77711) {
        /* ADI p52: sequential register data uses an incrementing pointer.
         * The next register is still unimplemented and cannot return data. */
        s->max77711_pointer++;
    } else {
        ex1850_pcal_pointer_advance(s);
    }
}

static bool ex1850_i2c_device_register_read(EX1850ResetState *s, unsigned reg,
                                            uint8_t *value)
{
    if (s->i2c_active_device == EX1850_I2C_MAX77711) {
        if (!s->max77711_pointer_known || reg != 0x23 ||
            !s->max77711_value_known) { return false; }
        *value = s->max77711_b2_cnfg_d;
        return true;
    }
    return ex1850_pcal_register_read(s, reg, value);
}

static void ex1850_i2c_device_register_write(EX1850ResetState *s, uint8_t data)
{
    if (s->i2c_active_device != EX1850_I2C_MAX77711) {
        ex1850_pcal_register_write(s, data);
        return;
    }
    if (!s->max77711_pointer_known || s->max77711_pointer != 0x23) {
        ex1850_unknown_access(s, 0x40005410, 1, true, data);
    }
    /* ADI p64: VOUTREG2 is full-byte Write/Read; values aboveD2 clamp toD2.
     * This latch does not model actual volts, DVS, buck enable, sequencer,
     * OTP/RNG2, protection state, fault IRQ, nRSTIO or either EXPEED ready. */
    s->max77711_b2_cnfg_d = MIN(data, 0xd2);
    s->max77711_value_known = true;
    fprintf(stderr, "EX1850_MAX77711_REGISTER W reg=23 byte=%02x latch=%02x "
            "clamped=%u source=clocked_original_DR_byte virtual_ns=%" PRId64
            " OTP_reset_supplied=0 voltage_or_power_good_supplied=0 "
            "EXPEED_ready_or_MCU_completion_supplied=0\n", data,
            s->max77711_b2_cnfg_d, data > 0xd2, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    ex1850_i2c_device_pointer_advance(s);
}

static void ex1850_i2c_receive_schedule(EX1850ResetState *s)
{
    if (!ex1850_i2c_buffered_device(s) || s->i2c_rx_in_flight ||
        s->i2c_rx_nacked || s->i2c_rx_count >= 2 ||
        !(s->i2c1.cr1 & 1) || (s->i2c1.sr2 & 7) != 3 ||
        !ex1850_i2c_pin_route(s)) { return; }
    int64_t period = ex1850_i2c_scl_period(s);
    if (!period) { return; }
    s->i2c_rx_in_flight = true;
    timer_mod(s->i2c_external_input_timer,
              qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + period * 9);
}

static void ex1850_i2c_receive_byte(EX1850ResetState *s)
{
    /* Two hardware receive slots (DR and shift register). RXNE reflects
     * one available byte; BTF reflects two full slots and stretches SCL
     * until the original DR read frees a slot. ACK/STOP come from actual
     * CR1 writes, never the guest's software transfer count or PC. */
    s->i2c_rx_in_flight = false;
    if (!(s->i2c1.cr1 & 1) || (s->i2c1.sr2 & 7) != 3 ||
        s->i2c_rx_count >= 2 || !ex1850_i2c_pin_route(s)) { return; }
    unsigned reg = ex1850_i2c_device_pointer(s);
    uint8_t data;
    if (!ex1850_i2c_device_register_read(s, reg, &data)) {
        ex1850_capture_boundary(s);
        fprintf(stderr, "EX1850_UNMODELED_DEVICE_EVENT event=I2C_receive_input "
                "device=%s address7=%02x reg=%02x "
                "CPU_MMIO_instruction_executed=0\n", ex1850_i2c_device_name(s),
                ex1850_i2c_device_address(s), reg);
        fflush(stderr);
        exit(66);
    }
    s->i2c_rx_data[s->i2c_rx_count] = data;
    s->i2c_rx_register[s->i2c_rx_count++] = reg;
    s->i2c_received_total++;
    ex1850_i2c_device_pointer_advance(s);
    bool ack = !!(s->i2c1.cr1 & 0x400);
    s->i2c_rx_nacked = !ack;
    s->i2c1.sr1 &= ~0xc4U;
    s->i2c1.sr1 |= 0x40 | (s->i2c_rx_count == 2 ? 4 : 0);
    ex1850_sampled_log("EX1850_I2C_RECEIVE_EVENT reg=%02x byte=%02x slots=%u "
            "RXNE=1 BTF=%u master_ACK=%u external_pin_levels_hypothesis=%06x "
            "total_received=%u virtual_ns=%" PRId64
            " byte_source=%s device=%s address7=%02x physical_camera_sample=0\n", reg, data,
            s->i2c_rx_count, s->i2c_rx_count == 2, ack, s->pcal_pin_levels,
            s->i2c_received_total, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
            s->i2c_active_device == EX1850_I2C_MAX77711 ?
            "original_guest_written_B2_CNFG_D_latch" :
            ((reg <= 2 || (reg >= 0x6c && reg <= 0x6e)) ?
             (s->pcal_pin_event_count ? "explicit_timed_pin_scenario" :
              "explicit_static_pin_scenario") : "cold_or_original_guest_written_device_register"),
            ex1850_i2c_device_name(s), ex1850_i2c_device_address(s));
    if (s->i2c_stop_waits_for_receive && (s->i2c1.cr1 & 0x200)) {
        s->i2c_stop_waits_for_receive = false;
        s->i2c_rx_nacked = true;
        timer_mod(s->i2c_stop_timer,
                  qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + ex1850_i2c_scl_period(s));
    } else {
        ex1850_i2c_receive_schedule(s);
    }
    ex1850_i2c_irq_update(s);
}

static bool ex1850_i2c_receive_DR_read(EX1850ResetState *s, hwaddr addr,
                                       unsigned size, uint32_t *value)
{
    if (addr != 0x40005410 || (size != 1 && size != 4) ||
        !ex1850_i2c_buffered_device(s) || !s->i2c_rx_count ||
        !(s->apb1enr & (1U << 21)) || !(s->i2c1.cr1 & 1)) { return false; }
    unsigned reg = s->i2c_rx_register[0];
    *value = s->i2c_rx_data[0];
    s->i2c_rx_count--;
    s->i2c_rx_data[0] = s->i2c_rx_data[1];
    s->i2c_rx_register[0] = s->i2c_rx_register[1];
    s->i2c1.sr1 &= ~0x44U;
    if (s->i2c_rx_count) { s->i2c1.sr1 |= 0x40; }
    ex1850_sampled_log("EX1850_I2C_RECEIVE_DR R reg=%02x byte=%02x remaining_slots=%u "
            "pc=%08x virtual_ns=%" PRId64 " software_completion_supplied=0\n",
            reg, *value, s->i2c_rx_count, ex1850_pc(),
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    ex1850_i2c_receive_schedule(s);
    ex1850_i2c_irq_update(s);
    return true;
}

static void ex1850_i2c_start_complete(void *opaque)
{
    EX1850ResetState *s = opaque;
    if ((s->i2c1.cr1 & 0x101) != 0x101 || !ex1850_i2c_pin_route(s) ||
        s->i2c_bus_mode != 1) { return; }
    s->i2c1.cr1 &= ~0x100U;
    s->i2c1.sr1 &= ~0x86U;
    if (s->i2c_pcal6524 || s->i2c_max77711) {
        s->i2c1.sr1 &= ~0x40U;
        s->i2c_rx_count = 0;
        s->i2c_rx_nacked = false;
        s->i2c_rx_in_flight = false;
        s->i2c_stop_waits_for_receive = false;
    }
    s->i2c_addr_sr1_read = false;
    s->i2c1.sr1 |= 1; /* SB from clocked START, not poll count. */
    s->i2c1.sr2 = 3; /* Master/busy after its own START. */
    ex1850_sampled_log("EX1850_I2C_EVENT START_complete SB=1 MSL=1 BUSY=1 repeated=%u "
            "virtual_ns=%" PRId64 " configured_SCL_period_ns=%" PRId64
            " slave_ACK_supplied=0 physical_timing_verified=0\n",
            s->i2c_repeated_start, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
            ex1850_i2c_scl_period(s));
    ex1850_i2c_irq_update(s);
}

static void ex1850_i2c_unknown_external_input(void *opaque)
{
    EX1850ResetState *s = opaque;
    if ((s->i2c_active_device != EX1850_I2C_PCAL6524 &&
         s->i2c_active_device != EX1850_I2C_MAX77711) ||
        !(s->i2c1.cr1 & 1) || (s->i2c1.sr2 & 4)) { return; }
    if (ex1850_i2c_buffered_device(s)) {
        ex1850_i2c_receive_byte(s);
        return;
    }
    fprintf(stderr, "EX1850_EXTERNAL_INPUT_BOUNDARY device=PCAL6524_candidate "
            "address7=22 reg=%02x bytes_received=0 RXNE_or_receive_BTF_supplied=0 "
            "documented_default=undefined_X virtual_ns=%" PRId64
            " CPU_MMIO_read_instruction_not_executed=1\n", s->pcal_pointer & 0x7f,
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    /* A hardware receive deadline, not a CPU DR read or arrived byte.
     * The CPU context need not be meaningful during a timer callback. */
    ex1850_capture_boundary(s);
    fprintf(stderr, "EX1850_UNMODELED_DEVICE_EVENT event=I2C_receive_input "
            "device=PCAL6524_candidate address7=22 reg=%02x "
            "CPU_MMIO_instruction_executed=0\n", s->pcal_pointer & 0x7f);
    fflush(stderr);
    exit(66);
}

static void ex1850_i2c_absent_slave_nack(void *opaque)
{
    EX1850ResetState *s = opaque;
    if (!(s->i2c1.cr1 & 1) ||
        !(s->i2c1.sr2 & 1)) { return; }
    if (ex1850_i2c_buffered_device(s) && s->i2c_tx_count) {
        /* DR and shift-register slots. TXE means the DR slot is empty;
         * BTF needs both slots empty after a complete clocked ninth bit.
         * Pointer and payload bytes are actual DR writes, never RAM or PC. */
        uint8_t data = s->i2c_tx_data[0];
        if (s->i2c_tx_phase[0] == 2) {
            if (s->i2c_active_device == EX1850_I2C_MAX77711) {
                s->max77711_pointer = data;
                s->max77711_pointer_known = true;
            } else {
                s->pcal_pointer = data;
            }
            ex1850_sampled_log("EX1850_I2C_EVENT pointer_shift_complete pointer=%02x ACK=1 "
                    "source=%s_protocol_contract virtual_ns=%" PRId64
                    " external_input_data_supplied=0\n", data, ex1850_i2c_device_name(s),
                    qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
        } else {
            ex1850_i2c_device_register_write(s, data);
        }
        s->i2c_tx_count--;
        s->i2c_tx_data[0] = s->i2c_tx_data[1];
        s->i2c_tx_phase[0] = s->i2c_tx_phase[1];
        s->i2c1.sr1 = (s->i2c1.sr1 & ~0x84U) | 0x80 |
                      (s->i2c_tx_count ? 0 : 4);
        ex1850_sampled_log("EX1850_I2C_TRANSMIT_EVENT byte=%02x ACK=1 remaining_slots=%u "
                "TXE=1 BTF=%u virtual_ns=%" PRId64 " software_completion_supplied=0\n",
                data, s->i2c_tx_count, !s->i2c_tx_count,
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
        if (s->i2c_tx_count) {
            timer_mod(s->i2c_nack_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                      ex1850_i2c_scl_period(s) * 9);
        } else if (s->i2c_stop_waits_for_transmit && (s->i2c1.cr1 & 0x200)) {
            s->i2c_stop_waits_for_transmit = false;
            timer_mod(s->i2c_stop_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                      ex1850_i2c_scl_period(s));
        } else if (s->i2c_start_waits_for_transmit && (s->i2c1.cr1 & 0x100)) {
            s->i2c_start_waits_for_transmit = false;
            timer_mod(s->i2c_start_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                      ex1850_i2c_scl_period(s));
        }
        ex1850_i2c_irq_update(s);
        return;
    }
    if (s->i2c_active_device == EX1850_I2C_PCAL6524 && s->i2c_pending_phase == 2) {
        /* This bounded implementation needs only the first original
         * pointer 00h. Other registers stay strict until implemented. */
        if (s->i2c1.dr != 0) {
            ex1850_unknown_access(s, 0x40005410, 1, true, s->i2c1.dr);
        }
        s->pcal_pointer = s->i2c1.dr;
        s->i2c_pending_phase = 0;
        s->i2c1.sr1 |= 0x84; /* DR empty and pointer byte fully shifted. */
        ex1850_sampled_log("EX1850_I2C_EVENT pointer_shift_complete pointer=%02x ACK=1 "
                "TXE=1 BTF=1 source=PCAL6524_protocol_hypothesis virtual_ns=%" PRId64
                " external_input_data_supplied=0\n", s->pcal_pointer,
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
        ex1850_i2c_irq_update(s);
        return;
    }
    if (s->i2c_pending_phase == 1 &&
        (s->i2c_active_device == EX1850_I2C_PCAL6524 ||
         s->i2c_active_device == EX1850_I2C_MAX77711)) {
        s->i2c_pending_phase = 0;
        bool read = !!(s->i2c1.dr & 1);
        if (ex1850_i2c_buffered_device(s) && !read) { s->i2c_expect_pointer = true; }
        s->i2c1.sr1 |= 2 | (read ? 0 : 0x80);
        s->i2c1.sr2 = read ? 3 : 7;
        ex1850_sampled_log("EX1850_I2C_EVENT address_shift_complete address_byte=%02x "
                "address7=%02x ACK=1 ADDR=1 direction=%s "
                "source=%s "
                "virtual_ns=%" PRId64 " external_input_data_supplied=0\n",
                s->i2c1.dr, ex1850_i2c_device_address(s), read ? "read" : "write",
                s->i2c_active_device == EX1850_I2C_MAX77711 ?
                "explicit_MAX77711_VIO_valid_PHCFG_floating_hypothesis" :
                "explicit_PCAL6524_power_RESET_and_VSS_address_hypothesis",
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
        ex1850_i2c_irq_update(s);
        return;
    }
    if (ex1850_i2c_address_contract(s, s->i2c1.dr >> 1) !=
        EX1850_I2C_EXPLICIT_ABSENT) {
        /* Unprovided addresses must have stopped at the original DR write. */
        ex1850_unknown_access(s, 0x40005410, 1, true, s->i2c1.dr);
    }
    s->i2c1.sr1 |= 0x400; /* The undriven ninth bit is NACK/AF. */
    ex1850_sampled_log("EX1850_I2C_EVENT address_shift_complete address_byte=%02x "
            "address7=%02x ACK=0 AF=1 reason=explicit_absent_slave "
            "virtual_ns=%" PRId64 " application_success_supplied=0\n",
            s->i2c1.dr, s->i2c1.dr >> 1, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    ex1850_i2c_irq_update(s);
}

static void ex1850_i2c_stop_complete(void *opaque)
{
    EX1850ResetState *s = opaque;
    if (!(s->i2c1.cr1 & 0x200)) { return; }
    s->i2c1.cr1 &= ~0x200U;
    timer_del(s->i2c_external_input_timer);
    if (ex1850_i2c_buffered_device(s) && (s->i2c1.sr2 & 4)) {
        /* End master-transmitter events at the STOP condition. The next
         * START/address phase must not inherit a completed byte's BTF/TXE.
         * Receive DR slots, if any, still require actual original reads. */
        s->i2c1.sr1 &= ~0x84U;
    }
    s->i2c1.sr2 = s->i2c_bus_mode == 2 ? 2 : 0;
    ex1850_sampled_log("EX1850_I2C_EVENT STOP_complete BUSY=%u "
            "virtual_ns=%" PRId64 " device_data_supplied=0\n",
            !!(s->i2c1.sr2 & 2), qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    ex1850_i2c_irq_update(s);
}

static bool ex1850_i2c_status_read(EX1850ResetState *s, hwaddr addr,
                                  unsigned size, uint32_t *value)
{
    if (size != 4 || (addr != 0x40005414 && addr != 0x40005418) ||
        !s->i2c_bus_mode || !(s->apb1enr & (1U << 21))) { return false; }
    if ((s->i2c1.cr1 & 1) && !ex1850_i2c_pin_route(s)) { return false; }
    if (addr == 0x40005418 && !(s->i2c1.sr2 & 1)) {
        s->i2c1.sr2 = (s->i2c1.cr1 & 1) && s->i2c_bus_mode == 2 ? 2 : 0;
    }
    *value = addr == 0x40005414 ? s->i2c1.sr1 : s->i2c1.sr2;
    if (addr == 0x40005414 && (s->i2c1.sr1 & 2)) {
        s->i2c_addr_sr1_read = true;
    } else if (addr == 0x40005418 && s->i2c_addr_sr1_read && (s->i2c1.sr1 & 2)) {
        s->i2c_addr_sr1_read = false;
        s->i2c1.sr1 &= ~2U; /* Actual SR1 then SR2 clears ADDR. */
        if ((s->i2c_active_device == EX1850_I2C_PCAL6524 ||
             s->i2c_active_device == EX1850_I2C_MAX77711) && !(s->i2c1.sr2 & 4)) {
            if (ex1850_i2c_buffered_device(s)) {
                ex1850_i2c_receive_schedule(s);
            } else {
                int64_t period = ex1850_i2c_scl_period(s);
                timer_mod(s->i2c_external_input_timer,
                          qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + period * 9);
            }
        }
        ex1850_i2c_irq_update(s);
    }
    uint64_t count = ++s->i2c_sr_read_count[addr == 0x40005418];
    if (count <= 8 || !(count & (count - 1))) {
        ex1850_sampled_log("EX1850_I2C_STATUS R addr=%08" HWADDR_PRIx
                " value=%08x pc=%08x virtual_ns=%" PRId64
                " sampled_access_index=%" PRIu64 " bus_assumption=%u\n",
                addr, *value, ex1850_pc(), qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
                count, s->i2c_bus_mode);
    }
    return true;
}

static void ex1850_i2c_control_log(EX1850ResetState *s, hwaddr addr,
                                   bool write, uint32_t requested,
                                   uint32_t state)
{
    uint64_t read_count = 0, repeats = 0;
    if (!write && addr >= 0x40005400 && addr < 0x40005440) {
        unsigned index = (addr - 0x40005400) / 4;
        read_count = ++s->i2c_control_read_count[index];
        if (s->i2c_control_last_requested[index] != requested ||
            s->i2c_control_last_state[index] != state) {
            s->i2c_control_repeat_count[index] = 0;
            s->i2c_control_last_requested[index] = requested;
            s->i2c_control_last_state[index] = state;
        }
        repeats = ++s->i2c_control_repeat_count[index];
        /* Sample identical polling reads; retain every value change and write. */
        if (repeats > 8 && (repeats & (repeats - 1))) {
            return;
        }
    }
    ex1850_sampled_log("EX1850_I2C_CONTROL %c addr=%08" HWADDR_PRIx
            " requested=%08x state=%08x pc=%08x virtual_ns=%" PRId64
            " candidate_device_protocol_ACK_enabled=%u clock_enabled=%u"
            " sampled_read_index=%" PRIu64 " identical_read_index=%" PRIu64
            " external_input_data_supplied=0\n",
            write ? 'W' : 'R', addr, requested, state, ex1850_pc(),
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), s->i2c_pcal6524 || s->i2c_max77711,
            !!(s->apb1enr & (1U << 21)), read_count, repeats);
}

static void ex1850_rtc_control_log(EX1850ResetState *s, const char *name,
                                   bool write, uint32_t requested,
                                   uint32_t state, bool protected)
{
    fprintf(stderr, "EX1850_RTC_CONTROL %c reg=%s requested=%08x state=%08x "
            "write_ignored_protected_or_outside_init=%u pc=%08x virtual_ns=%" PRId64
            " effective_alarm_control=%08x control_AE_due_cycle=%" PRIu64
            " control_BE_due_cycle=%" PRIu64 " control_AIE_due_cycle=%" PRIu64
            " control_BIE_due_cycle=%" PRIu64 " factory_calendar_or_backup_supplied=0\n",
            write ? 'W' : 'R', name,
            requested, state, protected, ex1850_pc(),
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), s->rtc.alarm_control,
            s->rtc.alarm_control_due[0], s->rtc.alarm_control_due[1],
            s->rtc.alarm_control_due[2], s->rtc.alarm_control_due[3]);
}

static void ex1850_lse_ready(void *opaque)
{
    EX1850ResetState *s = opaque;
    if (s->lse_present && (s->rcc_bdcr & RCC_LSEON) &&
        !(s->rcc_bdcr & RCC_BDRST)) {
        s->rcc_bdcr |= RCC_LSERDY;
        fprintf(stderr, "EX1850_CLOCK_EVENT LSE_stable=1 virtual_ns=%" PRId64
                " nominal_LSE_hz_hypothesis=%u physical_start_time_verified=0\n",
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), EX1850_LSE_HZ);
        ex1850_rtc_reschedule(s);
    }
}

static bool ex1850_rtc_mmio(EX1850ResetState *s, hwaddr addr,
                               unsigned size, bool write, uint64_t *value)
{
    if (addr < 0x40002800 || addr >= 0x400028a0) { return false; }
    uint32_t data = *value, requested = data;
    bool ignored;
    unsigned offset = addr - 0x40002800;
    unsigned pclk = s->cpu_hz;
    unsigned ppre = (s->cfgr >> 10) & 7;
    if (ppre >= 4) { pclk >>= ppre - 3; }
    uint64_t before[] = {s->rtc.init_events, s->rtc.restart_events,
                         s->rtc.sync_events, s->rtc.calendar_ticks,
                         s->rtc.alarm_events[0], s->rtc.alarm_events[1],
                         s->rtc.alarm_clear_events[0], s->rtc.alarm_clear_events[1]};
    EX1850RTCResult result = ex1850_rtc_access(&s->rtc, offset, size,
        write, &data, !!(s->pwr_cr & 0x100), pclk,
        qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), &ignored);
    ex1850_rtc_events(s, before);
    ex1850_rtc_schedule(s);
    if (result != EX1850_RTC_OK) {
        fprintf(stderr, "EX1850_RTC_BOUNDARY result=%u addr=%08" HWADDR_PRIx
                " size=%u write=%u requested=%08x pc=%08x virtual_ns=%" PRId64 "\n",
                result, addr, size, write, requested, ex1850_pc(),
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
        ex1850_unknown_access(s, addr, size, write, *value);
    }
    if (!write) { *value = data; }
    if (offset == 0x0c) {
        ex1850_rtc_isr_log(s, write, write ? requested : data, ignored);
    } else if (offset == 0x1c || offset == 0x20 || offset == 0x44 || offset == 0x48) {
        bool subseconds = offset >= 0x44;
        unsigned i = (offset - (subseconds ? 0x44 : 0x1c)) / 4;
        fprintf(stderr, "EX1850_RTC_ALARM_CONTROL %c reg=ALRM%c%s "
                "requested=%08x state=%08x ignored_DBP_WPR_or_write_window=%u "
                "ISR=%08x CR=%08x effective_control=%08x pc=%08x virtual_ns=%" PRId64 "\n",
                write ? 'W' : 'R', 'A' + i, subseconds ? "SSR" : "R",
                write ? requested : data, subseconds ? s->rtc.alarm_ss[i] : s->rtc.alarm[i],
                ignored, s->rtc.isr, s->rtc.cr, s->rtc.alarm_control,
                ex1850_pc(), qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    } else if (offset == 0x28) {
        fprintf(stderr, "EX1850_RTC_SUBSECOND R addr=%08" HWADDR_PRIx
                " value=%08x live_SSR=%04x PREDIV_S=%u pc=%08x virtual_ns=%" PRId64
                " LSE_cycle=%" PRIu64 " shadow_sample_cycle=%" PRIu64
                " TR_locked=%u DR_locked=%u SSR_locked=0\n", addr, data,
                s->rtc.ssr, s->rtc.prer & 0x7fff, ex1850_pc(),
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), s->rtc.cycles,
                s->rtc.shadow_cycle, s->rtc.tr_locked, s->rtc.dr_locked);
    } else if (offset == 0 || offset == 4) {
        if (write) {
            fprintf(stderr, "EX1850_RTC_CALENDAR W addr=%08" HWADDR_PRIx
                    " requested=%08x TR=%08x DR=%08x write_ignored_protected_or_outside_init=%u "
                    "pc=%08x virtual_ns=%" PRId64 " original_guest_register_write=1\n",
                    addr, requested, s->rtc.tr, s->rtc.dr, ignored, ex1850_pc(),
                    qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
        } else {
            fprintf(stderr, "EX1850_RTC_CALENDAR R addr=%08" HWADDR_PRIx
                    " value=%08x pc=%08x virtual_ns=%" PRId64
                    " retained_factory_calendar_supplied=0 TR_locked=%u DR_locked=%u "
                    "shadow_sample_cycle=%" PRIu64 "\n", addr, data, ex1850_pc(),
                    qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), s->rtc.tr_locked,
                    s->rtc.dr_locked, s->rtc.shadow_cycle);
        }
    } else if (offset >= 0x50) {
        unsigned index = (offset - 0x50) / 4;
        fprintf(stderr, "EX1850_RTC_BACKUP %c index=%u value=%08x state=%08x "
                "write_ignored_DBP=%u pc=%08x virtual_ns=%" PRId64
                " retained_factory_backup_supplied=0\n", write ? 'W' : 'R', index,
                write ? requested : data, s->rtc.backup[index], ignored, ex1850_pc(),
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    } else if (offset == 0x24) {
        fprintf(stderr, "EX1850_RTC_WPR W value=%02x unlocked=%u "
                "write_ignored_DBP=%u pc=%08x RTC_status_from_device_clock_no_factory_fixture=1\n",
                requested, s->rtc.wpr_stage == 2, ignored, ex1850_pc());
    } else {
        const char *name = offset == 8 ? "CR" : offset == 0x10 ? "PRER" : "TAFCR";
        uint32_t state = offset == 8 ? s->rtc.cr : offset == 0x10 ? s->rtc.prer : s->rtc.tafcr;
        ex1850_rtc_control_log(s, name, write, write ? requested : data, state, ignored);
    }
    return true;
}

static bool ex1850_register(EX1850ResetState *s, hwaddr addr, uint32_t **reg,
                             unsigned *id, const char **name)
{
    switch (addr & ~3U) {
    case 0x40023800: *reg = &s->rcc_cr; *id = 0; *name = "RCC_CR"; return true;
    case 0x40023804: *reg = &s->pllcfgr; *id = 1; *name = "RCC_PLLCFGR"; return true;
    case 0x40023808: *reg = &s->cfgr; *id = 2; *name = "RCC_CFGR"; return true;
    case 0x40023830: *reg = &s->ahb1enr; *id = 4; *name = "RCC_AHB1ENR"; return true;
    case 0x40023844: *reg = &s->apb2enr; *id = 5; *name = "RCC_APB2ENR"; return true;
    case 0x40023834: *reg = &s->ahb2enr; *id = 6; *name = "RCC_AHB2ENR"; return true;
    case 0x40023870: *reg = &s->rcc_bdcr; *id = 7; *name = "RCC_BDCR"; return true;
    default: return false;
    }
}

/* SPI3 disabled controls only. SPI2 is owned by its DMA backend;
 * SPI1/SPI4 wire state is independent. */
static bool ex1850_apb1_spi_control_access(EX1850ResetState *s, hwaddr addr,
                                          unsigned size, bool write, uint64_t *value)
{
    if (addr > UINT32_MAX || ex1850_apb1_spi_index((uint32_t)addr) < 0) { return false; }
    if (write && *value > UINT32_MAX) { ex1850_unknown_access(s, addr, size, true, *value); }
    uint32_t v = *value;
    EX1850APB1SPIResult result = ex1850_apb1_spi_access(&s->apb1_spi,
        s->apb1enr, s->rcc_apb1rstr, (uint32_t)addr, size, write, &v);
    if (result != EX1850_APB1_SPI_OK) {
        fprintf(stderr, "EX1850_APB1_SPI_BOUNDARY result=%u addr=%08" HWADDR_PRIx
                " size=%u write=%u value=%08x pc=%08x virtual_ns=%" PRId64
                " SR_DR_or_completion_supplied=0\n", result, addr, size, write, v,
                ex1850_pc(), qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
        ex1850_unknown_access(s, addr, size, write, *value);
    }
    *value = v;
    fprintf(stderr, "EX1850_APB1_SPI_CONTROL_%c addr=%08" HWADDR_PRIx
            " value=%08x apb1enr=%08x apb1rstr=%08x pc=%08x virtual_ns=%" PRId64
            " SPE_DMA_IRQ_or_transfer_supplied=0\n", write ? 'W' : 'R', addr, v,
            s->apb1enr, s->rcc_apb1rstr, ex1850_pc(), qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    return true;
}

static uint64_t ex1850_read(void *opaque, hwaddr addr, unsigned size)
{
    EX1850ResetState *s = opaque;
    uint32_t *reg;
    unsigned id;
    const char *name;
    uint32_t receive_value;
    ex1850_spi2_sync(s);
    ex1850_usart1_sync(s);
    ex1850_usart2_sync(s);
    ex1850_wire_poll(s);
    uint64_t wire_value = 0;
    if (ex1850_rng_access(s, addr, size, false, &wire_value)) { return wire_value; }
    if (ex1850_rtc_mmio(s, addr, size, false, &wire_value)) { return wire_value; }
    if (ex1850_spi2_board_access(s, addr, size, false, &wire_value)) { return wire_value; }
    if (ex1850_usart1_board_access(s, addr, size, false, &wire_value)) { return wire_value; }
    if (ex1850_usart2_board_access(s, addr, size, false, &wire_value)) { return wire_value; }
    if (ex1850_wire_access(s, addr, size, false, &wire_value)) { return wire_value; }
    if (ex1850_apb1_spi_control_access(s, addr, size, false, &wire_value)) { return wire_value; }
    if (ex1850_i2c_receive_DR_read(s, addr, size, &receive_value)) { return receive_value; }
    uint64_t adc_value = 0;
    if (ex1850_adc_control_access(s, addr, size, false, &adc_value)) { return adc_value; }
    uint64_t dma_value = 0;
    if (ex1850_dma1_access(s, addr, size, false, &dma_value)) { return dma_value; }
    uint64_t exti_value = 0;
    if (ex1850_exti_control_access(s, addr, size, false, &exti_value)) { return exti_value; }
    if (addr == 0x40023810 && size == 4) { return s->rcc_ahb1rstr; }
    if (addr == 0x40023814 && size == 4) { return s->rcc_ahb2rstr; }
    if (addr == 0x40023820 && size == 4) {
        fprintf(stderr, "EX1850_RCC_APB1RSTR R value=%08x pc=%08x virtual_ns=%" PRId64 "\n",
                s->rcc_apb1rstr, ex1850_pc(), qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
        return s->rcc_apb1rstr;
    }
    if (addr == 0x40023824 && size == 4) {
        fprintf(stderr, "EX1850_RCC_APB2RSTR R value=%08x pc=%08x virtual_ns=%" PRId64 "\n",
                s->rcc_apb2rstr, ex1850_pc(), qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
        return s->rcc_apb2rstr;
    }
    uint64_t syscfg_value = 0;
    if (ex1850_syscfg_exticr_access(s, addr, size, false, &syscfg_value)) {
        return syscfg_value;
    }
    uint32_t rtc_mask;
    uint32_t i2c_status;
    if (size == 4 && ex1850_i2c2_control_register(s, addr, &reg, &rtc_mask)) {
        uint32_t exposed = (s->apb1enr & (1U << 22)) ? *reg : 0;
        ex1850_i2c2_control_log(s, addr, false, exposed, *reg);
        return exposed;
    }
    if (ex1850_i2c_status_read(s, addr, size, &i2c_status)) {
        return i2c_status;
    }
    if (size == 4 && ex1850_i2c_control_register(s, addr, &reg, &rtc_mask)) {
        uint32_t exposed = (s->apb1enr & (1U << 21)) ? *reg : 0;
        ex1850_i2c_control_log(s, addr, false, exposed, *reg);
        return exposed;
    }
    uint32_t gpio_value;
    if (ex1850_gpio_input_read(s, addr, size, &gpio_value)) {
        return gpio_value;
    }
    if ((addr & 3) + size <= 4 && ex1850_gpio_register(s, addr, &gpio_value)) {
        if (ex1850_gpio_log_sample(s, addr, false, gpio_value, UINT32_MAX)) {
            ex1850_sampled_log("EX1850_GPIO_CONTROL R addr=%08" HWADDR_PRIx
                " size=%u value=%08x pc=%08x\n", addr, size, gpio_value, ex1850_pc());
        }
        return (gpio_value >> (8 * (addr & 3))) & ((UINT64_C(1) << (size * 8)) - 1);
    }
    uint32_t timer_value;
    uint64_t timer11_value = 0;
    if (ex1850_tim12_access(s, addr, size, false, &timer11_value)) { return timer11_value; }
    if (ex1850_tim8_reset_idle_access(s, addr, size, false, &timer11_value)) { return timer11_value; }
    if (ex1850_tim11_access(s, addr, size, false, &timer11_value)) { return timer11_value; }
    if (ex1850_tim1_access(s, addr, size, false, &timer11_value)) { return timer11_value; }
    if (ex1850_tim10_access(s, addr, size, false, &timer11_value)) { return timer11_value; }
    if (ex1850_tim234_access(s, addr, size, false, &timer11_value)) { return timer11_value; }
    if ((addr & 3) + size <= 4 && ex1850_tim5_register(s, addr, &timer_value)) {
        ex1850_tim5_log(s, addr, size, false, timer_value);
        return (timer_value >> (8 * (addr & 3))) & ((UINT64_C(1) << (size * 8)) - 1);
    }
    if ((addr & 3) + size <= 4 && ex1850_register(s, addr, &reg, &id, &name)) {
        ex1850_reg_log(s, id, name, false, *reg);
        return (*reg >> (8 * (addr & 3))) & ((UINT64_C(1) << (size * 8)) - 1);
    }
    if (addr == 0x40023840 && size == 4) {
        ex1850_sampled_log("EX1850_RCC_APB1ENR R value=%08x pc=%08x\n",
                s->apb1enr, ex1850_pc());
        s->io_count++;
        return s->apb1enr;
    }
    if (addr == 0x40007000 && size == 4 && (s->apb1enr & (1U << 28))) {
        fprintf(stderr, "EX1850_PWR_CR R value=%08x pc=%08x status_ready_supplied=0\n",
                s->pwr_cr, ex1850_pc());
        s->io_count++;
        return s->pwr_cr;
    }
    ex1850_unknown_access(s, addr, size, false, 0);
}

static void ex1850_write(void *opaque, hwaddr addr, uint64_t value,
                          unsigned size)
{
    EX1850ResetState *s = opaque;
    ex1850_spi2_sync(s);
    ex1850_usart1_sync(s);
    ex1850_usart2_sync(s);
    uint64_t wire_value = value;
    if (ex1850_rng_access(s, addr, size, true, &wire_value)) { return; }
    if (ex1850_rtc_mmio(s, addr, size, true, &wire_value)) { return; }
    if (ex1850_spi2_board_access(s, addr, size, true, &wire_value)) { return; }
    if (ex1850_usart1_board_access(s, addr, size, true, &wire_value)) { return; }
    if (ex1850_usart2_board_access(s, addr, size, true, &wire_value)) { return; }
    if (ex1850_wire_access(s, addr, size, true, &wire_value)) { return; }
    if (ex1850_apb1_spi_control_access(s, addr, size, true, &wire_value)) { return; }
    uint64_t adc_value = value;
    if (ex1850_adc_control_access(s, addr, size, true, &adc_value)) { return; }
    uint64_t timer11_value = value;
    if (ex1850_tim12_access(s, addr, size, true, &timer11_value)) { return; }
    if (ex1850_tim8_reset_idle_access(s, addr, size, true, &timer11_value)) { return; }
    if (ex1850_tim11_access(s, addr, size, true, &timer11_value)) { return; }
    if (ex1850_tim1_access(s, addr, size, true, &timer11_value)) { return; }
    if (ex1850_tim10_access(s, addr, size, true, &timer11_value)) { return; }
    if (ex1850_tim234_access(s, addr, size, true, &timer11_value)) { return; }
    uint64_t dma_value = value;
    if (ex1850_dma1_access(s, addr, size, true, &dma_value)) { return; }
    uint64_t exti_value = value;
    if (ex1850_exti_control_access(s, addr, size, true, &exti_value)) { return; }
    if (addr == 0x40023810 && size == 4) {
        if (value & ~UINT64_C(0x00200000)) {
            ex1850_unknown_access(s, addr, size, true, value);
        }
        if ((value & ~s->rcc_ahb1rstr) & (1U << 21)) {
            ex1850_spi2_dma_reset(&s->spi2_dma);
        }
        s->rcc_ahb1rstr = value;
        ex1850_spi2_clocks_changed(s);
        fprintf(stderr, "EX1850_DMA1_RESET register=%08x virtual_ns=%" PRId64
                " source=original_AHB1RSTR SPI2_reset=0\n",
                s->rcc_ahb1rstr, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
        return;
    }
    if (addr == 0x40023814 && size == 4) {
        if (value & ~UINT64_C(0x40)) {
            ex1850_unknown_access(s, addr, size, true, value);
        }
        ex1850_rng_sync(s);
        s->rcc_ahb2rstr = value;
        if (value & EX1850_RNG_AHB2_BIT) { ex1850_rng_peripheral_reset(s); }
        ex1850_rng_clocks_changed(s);
        ex1850_sampled_log("EX1850_RNG_RESET AHB2RSTR=%08x virtual_ns=%" PRId64
                " source=RCC_RNGRST\n", s->rcc_ahb2rstr,
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
        return;
    }
    if (addr == 0x40023820 && size == 4) {
        /* Public F412 TIM2/3/4RST bits0..2, TIM12RST bit6, SPI2/3RST bits14/15,
         * USART2RST bit17, I2C1RST/I2C2RST bits21/22, reset=0.
         * Actual DEV_ID=441; other reset bits remain strict. */
        if (value & ~UINT64_C(0x0062c047)) {
            ex1850_unknown_access(s, addr, size, true, value);
        }
        uint32_t before = s->rcc_apb1rstr;
        s->rcc_apb1rstr = value;
        for (unsigned n = 0; n < 3; n++) {
            if ((value & ~before) & (1U << n)) {
                ex1850_tim234_reset(&s->tim234[n], n == 0 ? 32 : 16,
                                   qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
                ex1850_tim234_schedule(s, n);
                fprintf(stderr, "EX1850_TIM234_RESET timer=%u source=original_APB1RSTR "
                        "pc=%08x completion_supplied=0\n", n + 2, ex1850_pc());
            }
        }
        uint32_t spi_reset = (value & ~before) & EX1850_APB1_SPI_MASK;
        if (spi_reset) {
            g_assert(ex1850_apb1_spi_reset(&s->apb1_spi, spi_reset));
            if (spi_reset & (1U << 14)) { ex1850_spi2_peripheral_reset(&s->spi2_dma); }
            fprintf(stderr, "EX1850_APB1_SPI_RESET rising_mask=%08x pc=%08x "
                    "virtual_ns=%" PRId64 " SPI1_SPI4_DMA_or_external_device_reset=0\n",
                    spi_reset, ex1850_pc(), qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
        }
        if ((value & ~before) & (1U << 6)) {
            ex1850_tim12_core_reset(&s->tim12, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
            ex1850_tim12_schedule(s);
            fprintf(stderr, "EX1850_TIM12_RESET source=APB1RSTR_bit6 pc=%08x "
                    "virtual_ns=%" PRId64 " completion_supplied=0\n",
                    ex1850_pc(), qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
        }
        for (unsigned n = 1; n <= 2; n++) {
            if ((value & ~before) & (1U << (20 + n))) {
                ex1850_i2c_controller_reset(s, n);
            }
        }
        ex1850_spi2_clocks_changed(s);
        ex1850_usart1_clocks_changed(s);
        ex1850_usart2_clocks_changed(s);
        fprintf(stderr, "EX1850_RCC_APB1RSTR W before=%08x after=%08" PRIx64
                " pc=%08x virtual_ns=%" PRId64 "\n", before, value,
                ex1850_pc(), qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
        return;
    }
    if (addr == 0x40023824 && size == 4) {
        if (!ex1850_tim1_apb2_reset(s, value)) {
            ex1850_unknown_access(s, addr, size, true, value);
        }
        ex1850_usart1_clocks_changed(s);
        return;
    }
    uint64_t syscfg_value = value;
    if (ex1850_syscfg_exticr_access(s, addr, size, true, &syscfg_value)) {
        return;
    }
    uint32_t *rtc_reg, rtc_mask;
    if (size == 4 && ex1850_i2c2_control_register(s, addr, &rtc_reg, &rtc_mask)) {
        if (value & ~rtc_mask) { ex1850_unknown_access(s, addr, size, true, value); }
        if ((s->apb1enr & (1U << 22)) && !(s->rcc_apb1rstr & (1U << 22))) {
            if (addr == 0x40005800 && (value & 0x8000)) {
                memset(&s->i2c2, 0, sizeof(s->i2c2));
                s->i2c2.cr1 = 0x8000;
                s->i2c2.trise = 2;
            } else {
                *rtc_reg = value;
            }
        }
        ex1850_i2c2_control_log(s, addr, true, value, *rtc_reg);
        return;
    }
    if (addr == 0x40005410 && (size == 1 || size == 4) && value <= 0xff &&
        s->i2c_bus_mode && (s->apb1enr & (1U << 21)) &&
        (s->i2c1.cr1 & 1) && (s->i2c1.sr1 & 1)) {
        EX1850I2CAddressContract contract = ex1850_i2c_address_contract(s, value >> 1);
        ex1850_sampled_log("EX1850_I2C_ADDRESS W requested_byte=%02" PRIx64
                " address7=%02" PRIx64 " pc=%08x virtual_ns=%" PRId64
                " connected_slave_unprovided=%u\n", value, value >> 1,
                ex1850_pc(), qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
                contract == EX1850_I2C_UNPROVIDED);
        if (contract == EX1850_I2C_UNPROVIDED) {
            /* The address write is a strict boundary until the external
             * device contract is supplied. Do not assert ADDR/ACK/data. */
            ex1850_i2c_unknown_address(s, value, size);
        }
        s->i2c_active_device = contract;
        s->i2c1.dr = value;
        s->i2c_pending_phase = 1;
        s->i2c1.sr1 &= ~1U; /* Native SR1 read then DR address write clears SB. */
        int64_t period = ex1850_i2c_scl_period(s);
        if (!period) { ex1850_unknown_access(s, addr, size, true, value); }
        timer_mod(s->i2c_nack_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + period * 9);
        ex1850_i2c_irq_update(s);
        return;
    }
    if (addr == 0x40005410 && (size == 1 || size == 4) && value <= 0xff &&
        (s->i2c_active_device == EX1850_I2C_PCAL6524 ||
         s->i2c_active_device == EX1850_I2C_MAX77711) && (s->i2c1.sr1 & 0x80) &&
        (s->i2c1.sr2 & 4) && !(s->i2c1.sr1 & 2)) {
        if (ex1850_i2c_buffered_device(s)) {
            if (s->i2c_tx_count >= 2 ||
                (s->i2c_expect_pointer &&
                 (s->i2c_active_device == EX1850_I2C_MAX77711 ? value != 0x23 :
                  !ex1850_pcal_register_defined(value & 0x7f)))) {
                ex1850_unknown_access(s, addr, size, true, value);
            }
            bool command = s->i2c_expect_pointer;
            s->i2c_expect_pointer = false;
            s->i2c_tx_data[s->i2c_tx_count] = value;
            s->i2c_tx_phase[s->i2c_tx_count++] = command ? 2 : 3;
            s->i2c1.dr = value;
            s->i2c1.sr1 &= ~0x84U;
            if (s->i2c_tx_count == 1) {
                s->i2c1.sr1 |= 0x80; /* DR moves to empty shifter. */
                timer_mod(s->i2c_nack_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                          ex1850_i2c_scl_period(s) * 9);
            }
            ex1850_sampled_log("EX1850_I2C_TRANSMIT_DR W byte=%02" PRIx64
                    " phase=%s occupied_slots=%u pc=%08x virtual_ns=%" PRId64
                    " BTF_supplied_before_ninth_bit=0\n", value,
                    command ? "pointer" : "payload", s->i2c_tx_count,
                    ex1850_pc(), qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
            ex1850_i2c_irq_update(s);
            return;
        }
        /* Command byte is taken from the actual guest DR write, not its
         * PC or RAM handle. Only the first documented input-pointer0 is
         * implemented; no GPIO input/register payload is returned. */
        if (value != 0) { ex1850_unknown_access(s, addr, size, true, value); }
        s->i2c1.dr = value;
        s->i2c_pending_phase = 2;
        s->i2c1.sr1 &= ~0x84U;
        fprintf(stderr, "EX1850_I2C_POINTER W byte=%02" PRIx64 " pc=%08x "
                "virtual_ns=%" PRId64 " device_register_data_supplied=0\n",
                value, ex1850_pc(), qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
        timer_mod(s->i2c_nack_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                  ex1850_i2c_scl_period(s) * 9);
        ex1850_i2c_irq_update(s);
        return;
    }
    if (addr == 0x40005414 && size == 4 && s->i2c_bus_mode &&
        (s->apb1enr & (1U << 21))) {
        /* AF is write-zero-to-clear. Writes cannot create SB/ADDR/RXNE,
         * nor any unmodeled hardware completion or error. */
        if (!(value & 0x400)) { s->i2c1.sr1 &= ~0x400U; }
        ex1850_sampled_log("EX1850_I2C_STATUS W addr=40005414 requested=%08" PRIx64
                " state=%08x pc=%08x virtual_ns=%" PRId64
                " readonly_success_flags_ignored=1\n", value, s->i2c1.sr1,
                ex1850_pc(), qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
        ex1850_i2c_irq_update(s);
        return;
    }
    if (size == 4 && ex1850_i2c_control_register(s, addr, &rtc_reg, &rtc_mask)) {
        if (value & ~rtc_mask) {
            ex1850_unknown_access(s, addr, size, true, value);
        }
        uint32_t previous = *rtc_reg;
        if (!(s->apb1enr & (1U << 21)) || (s->rcc_apb1rstr & (1U << 21))) {
            /* Reset holds controller control latches at reset; no bus
             * operation is started by writes while reset is asserted. */
            ex1850_i2c_control_log(s, addr, true, value, previous);
            return;
        }
        if (addr == 0x40005400 && (value & 0x8000)) {
            timer_del(s->i2c_start_timer);
            timer_del(s->i2c_nack_timer);
            timer_del(s->i2c_stop_timer);
            timer_del(s->i2c_external_input_timer);
            s->i2c_addr_sr1_read = false;
            s->i2c_pending_phase = 0;
            s->i2c_active_device = EX1850_I2C_UNPROVIDED;
            s->i2c_rx_count = 0;
            s->i2c_tx_count = 0;
            s->i2c_expect_pointer = false;
            s->i2c_rx_nacked = false;
            s->i2c_rx_in_flight = false;
            s->i2c_stop_waits_for_receive = false;
            s->i2c_start_waits_for_transmit = false;
            s->i2c_stop_waits_for_transmit = false;
            memset(&s->i2c1, 0, sizeof(s->i2c1));
            s->i2c1.cr1 = 0x8000;
            s->i2c1.trise = 2;
        } else {
            if (addr == 0x40005400 && ((value ^ previous) & 0xf00) &&
                !s->i2c_bus_mode) {
                ex1850_unknown_access(s, addr, size, true, value);
            }
            *rtc_reg = value;
            if (addr == 0x40005400 && (value & 0x100) && !(previous & 0x100)) {
                int64_t period = ex1850_i2c_scl_period(s);
                bool transmitting = ex1850_i2c_buffered_device(s) && s->i2c_tx_count &&
                                    (s->i2c1.sr2 & 7) == 7;
                bool start_pending_address = (s->pcal_pin_profile || s->i2c_max77711) &&
                                             (s->i2c1.sr1 & 1);
                if (s->i2c_bus_mode != 1 || !ex1850_i2c_pin_route(s) ||
                    !(value & 1) || !period ||
                    ((s->i2c1.sr2 & 1) &&
                     !((s->i2c_active_device == EX1850_I2C_PCAL6524 ||
                        s->i2c_active_device == EX1850_I2C_MAX77711) &&
                       (s->i2c1.sr1 & 4)) &&
                     !transmitting && !start_pending_address)) {
                    ex1850_unknown_access(s, addr, size, true, value);
                }
                s->i2c_repeated_start = !!(s->i2c1.sr2 & 1);
                if (start_pending_address) {
                    /* START is a level request, not a queue of bus events.
                     * An already-generated START/SB waits for its address DR
                     * write; an overlapping IRQ read-modify-write cannot
                     * generate a second byte-less START. Bounded functional
                     * request coalescing, not measured controller timing. */
                    s->i2c1.cr1 &= ~0x100U;
                    ex1850_sampled_log("EX1850_I2C_START_REQUEST existing_SB_pending=1 "
                            "generated_additional_bus_events=0 virtual_ns=%" PRId64
                            " controller_timing_physically_verified=0\n",
                            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
                } else if (transmitting) {
                    s->i2c_start_waits_for_transmit = true;
                } else {
                    timer_mod(s->i2c_start_timer,
                              qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + period);
                }
            }
            if (addr == 0x40005400 && (value & 0x200) && !(previous & 0x200)) {
                int64_t period = ex1850_i2c_scl_period(s);
                if (!period) { ex1850_unknown_access(s, addr, size, true, value); }
                if (ex1850_i2c_buffered_device(s) && (s->i2c1.sr2 & 7) == 3 &&
                    (s->i2c_rx_in_flight || (s->i2c1.sr1 & 2))) {
                    s->i2c_stop_waits_for_receive = true;
                } else if (ex1850_i2c_buffered_device(s) && s->i2c_tx_count &&
                           (s->i2c1.sr2 & 7) == 7) {
                    s->i2c_stop_waits_for_transmit = true;
                } else {
                    timer_mod(s->i2c_stop_timer,
                              qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + period);
                }
            }
        }
        ex1850_i2c_control_log(s, addr, true, value, *rtc_reg);
        ex1850_i2c_irq_update(s);
        return;
    }
    if (0x40020000 <= addr && addr < 0x40022000) {
        if (ex1850_gpio_write(s, addr, value, size)) {
            return;
        }
        ex1850_unknown_access(s, addr, size, true, value);
    }
    if (0x40000c00 <= addr && addr < 0x40000c30) {
        if (ex1850_tim5_write(s, addr, value, size)) {
            return;
        }
        ex1850_unknown_access(s, addr, size, true, value);
    }
    uint32_t *reg;
    unsigned id;
    const char *name;
    if ((addr & 3) + size <= 4 && ex1850_register(s, addr, &reg, &id, &name)) {
        uint32_t mask = ((UINT64_C(1) << (size * 8)) - 1) << (8 * (addr & 3));
        uint32_t merged = (*reg & ~mask) | ((value << (8 * (addr & 3))) & mask);
        uint32_t before = *reg;
        if ((addr & ~3U) == 0x40023800) {
            uint32_t writable = RCC_HSION | 0xf8 | RCC_HSEON | RCC_HSEBYP | RCC_PLLON;
            uint32_t readonly = RCC_HSIRDY | RCC_HSERDY | RCC_PLLRDY;
            if (((merged ^ before) & ~(writable | readonly)) || !(merged & RCC_HSION)) {
                ex1850_unknown_access(s, addr, size, true, value);
            }
            *reg = (before & ~writable) | (merged & writable);
            if (!(before & RCC_HSEON) && (*reg & RCC_HSEON) && s->hse_present) {
                timer_mod(s->hse_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + EX1850_HSE_START_NS);
            }
            if (!(*reg & RCC_HSEON)) {
                timer_del(s->hse_timer);
                *reg &= ~RCC_HSERDY;
            }
            if (!(*reg & RCC_PLLON)) {
                timer_del(s->pll_timer);
                *reg &= ~RCC_PLLRDY;
            }
            ex1850_start_pll_if_possible(s);
        } else if ((addr & ~3U) == 0x40023804) {
            if ((s->rcc_cr & RCC_PLLON) || (merged & ~UINT32_C(0x7f437fff))) {
                ex1850_unknown_access(s, addr, size, true, value);
            }
            *reg = merged;
        } else if ((addr & ~3U) == 0x40023808) {
            if (s->adc_busy && ((merged ^ before) & (3 | 0xfcf0))) {
                ex1850_unknown_access(s, addr, size, true, value);
            }
            uint32_t writable = 3 | 0xf0 | 0xfc00;
            if (((merged ^ before) & ~(writable | 0xc)) || (merged & 3) == 3) {
                ex1850_unknown_access(s, addr, size, true, value);
            }
            bool divisors_changed = !!((merged ^ before) & 0xfcf0);
            if (divisors_changed) {
                ex1850_sync_timer_clocks(s, "AHB_APB_divisor_write");
            }
            *reg = (before & ~writable) | (merged & writable);
            if (divisors_changed) { ex1850_update_clock(s); }
            ex1850_request_switch(s);
        } else if ((addr & ~3U) == 0x40023870) {
            /* Empty backup domain is an explicit cold-power hypothesis.
             * ROM changes bit3; its physical drive/mode naming is unknown.
             * Only the native LSE RTC clock source is supported. LSERDY
             * is hardware timer state, never an accepted software flag. */
            uint32_t writable = RCC_LSEON | 8 | 0x300 | RCC_RTCEN | RCC_BDRST;
            unsigned source = (merged >> 8) & 3;
            if (!(s->pwr_cr & 0x100) ||
                ((merged ^ before) & ~(writable | RCC_LSERDY)) || source > 1) {
                ex1850_unknown_access(s, addr, size, true, value);
            }
            ex1850_rtc_reschedule(s); /* Flush old-domain events before backup reset. */
            *reg = (before & ~writable) | (merged & writable);
            if (merged & RCC_BDRST) {
                *reg = RCC_BDRST;
                ex1850_rtc_reset(&s->rtc, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
                ex1850_rtc_bind_output(&s->rtc, ex1850_rtc_output, s);
                /* EXTI PR belongs to another reset domain. A real output
                 * fall may set it under FTSR; backup reset never erases PR. */
                ex1850_rtc_output(s, false, 0, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
                timer_del(s->lse_timer);
                timer_del(s->rtc_event);
                fprintf(stderr, "EX1850_RTC_BACKUP_RESET BDRST=1 "
                        "backup_marker_supplied=0 calendar_supplied=0 "
                        "virtual_ns=%" PRId64 "\n", qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
            } else if (!(*reg & RCC_LSEON)) {
                timer_del(s->lse_timer);
                *reg &= ~RCC_LSERDY;
            } else if (!(before & RCC_LSEON) && s->lse_present) {
                timer_mod(s->lse_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                                       EX1850_LSE_START_NS);
            }
            ex1850_rtc_reschedule(s);
        } else if ((addr & ~3U) == 0x40023830 || (addr & ~3U) == 0x40023834 ||
                   (addr & ~3U) == 0x40023844) {
            /* Enable latches only. Enabling a clock never creates ready,
             * DMA completion, GPIO input data or peripheral responses. */
            bool tim11_gate_changed = (addr & ~3U) == 0x40023844 &&
                                      !!((before ^ merged) & (1U << 18));
            bool tim1_gate_changed = (addr & ~3U) == 0x40023844 &&
                                     !!((before ^ merged) & EX1850_TIM1_APB2_BIT);
            bool tim10_gate_changed = (addr & ~3U) == 0x40023844 &&
                                      !!((before ^ merged) & EX1850_TIM10_APB2_BIT);
            if ((addr & ~3U) == 0x40023844 && s->adc_busy &&
                ((before ^ merged) & (1U << 8))) {
                ex1850_unknown_access(s, addr, size, true, value);
            }
            if (tim11_gate_changed) { ex1850_tim11_sync(s); }
            if (tim1_gate_changed) { ex1850_tim1_sync(s); }
            if (tim10_gate_changed) { ex1850_tim10_sync(s); }
            bool adc_gate_changed = (addr & ~3U) == 0x40023844 &&
                                    !!((before ^ merged) & (1U << 8));
            *reg = merged;
            if (adc_gate_changed) { ex1850_adc_irq_update(s); }
            if (tim11_gate_changed) { ex1850_tim11_schedule(s); }
            if (tim1_gate_changed) { ex1850_tim1_schedule(s); }
            if (tim10_gate_changed) { ex1850_tim10_schedule(s); }
        } else {
            ex1850_unknown_access(s, addr, size, true, value);
        }
        ex1850_spi2_clocks_changed(s);
        ex1850_usart1_clocks_changed(s);
        ex1850_usart2_clocks_changed(s);
        ex1850_rng_clocks_changed(s);
        if (s->wire.bus) {
            mcu_wire_gates(s->wire.bus, s->ahb1enr, s->apb2enr);
            for (unsigned bank = 0; bank < 8; bank++) {
                ex1850_wire_gpio_changed(s, bank, 0);
            }
            ex1850_wire_poll(s);
        }
        ex1850_reg_log(s, id, name, true, *reg);
        return;
    }
    if (addr == 0x40023840 && size == 4) {
        ex1850_sampled_log("EX1850_RCC_APB1ENR W before=%08x after=%08"
                PRIx64 " pc=%08x peripheral_completion=0\n",
                s->apb1enr, value, ex1850_pc());
        bool tim5_gate_changed = !!((s->apb1enr ^ value) & (1U << 3));
        bool tim12_gate_changed = !!((s->apb1enr ^ value) & (1U << 6));
        if (tim5_gate_changed) { ex1850_tim5_sync(s); }
        if (tim12_gate_changed) { ex1850_tim12_sync(s); }
        for (unsigned n = 0; n < 3; n++) {
            if ((s->apb1enr ^ value) & (1U << n)) { ex1850_tim234_clock_sync(s, n); }
        }
        s->apb1enr = value;
        ex1850_spi2_clocks_changed(s);
        ex1850_usart1_clocks_changed(s);
        ex1850_usart2_clocks_changed(s);
        if (tim5_gate_changed) { ex1850_tim5_schedule(s); }
        if (tim12_gate_changed) { ex1850_tim12_schedule(s); }
        for (unsigned n = 0; n < 3; n++) {
            ex1850_tim234_schedule(s, n);
        }
        s->io_count++;
        return;
    }
    if (addr == 0x40007000 && size == 4 && (s->apb1enr & (1U << 28)) &&
        !(value & ~UINT64_C(0x0000c301))) {
        fprintf(stderr, "EX1850_PWR_CR W before=%08x after=%08"
                PRIx64 " pc=%08x status_ready_supplied=0\n",
                s->pwr_cr, value, ex1850_pc());
        /* Includes native DBP bit8 backup-domain write-access control;
         * FPDS bit9 and LPDS bit0 are only writable selection latches.
         * No Flash/regulator transition occurs before SLEEPDEEP+WFI.
         * STOP, PDDS, wake flags, and PWR_CSR are not fabricated. */
        s->pwr_cr = value;
        s->io_count++;
        return;
    }
    ex1850_unknown_access(s, addr, size, true, value);
}

static const MemoryRegionOps ex1850_unknown_ops = {
    .read = ex1850_read,
    .write = ex1850_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 4 },
    .impl = { .min_access_size = 1, .max_access_size = 4 },
};

static void ex1850_reset_init(MachineState *machine)
{
    qemu_add_exit_notifier(&ex1850_log_exit_notifier);
    /* Strict device boundaries call exit(66) before normal QEMU cleanup. */
    atexit(ex1850_log_summary);
    EX1850ResetState *s = g_new0(EX1850ResetState, 1);
    const char *rng_public = g_getenv("EX1850_PUBLIC_RNG_WORDS");
    if (rng_public) {
        g_auto(GStrv) words = g_strsplit(rng_public, ",", -1);
        for (unsigned i = 0; words[i]; i++) {
            char *end = NULL;
            uint64_t value = g_ascii_strtoull(words[i], &end, 0);
            if (i >= G_N_ELEMENTS(s->rng_public_words) || !*words[i] ||
                words[i][0] == '-' || words[i][0] == '+' ||
                !end || *end || !value || value > UINT32_MAX) {
                error_report("EX1850_PUBLIC_RNG_WORDS requires 1..64 explicit nonzero u32 words");
                exit(1);
            }
            s->rng_public_words[s->rng_public_count++] = value;
        }
        fprintf(stderr, "EX1850_RNG_PUBLIC_PROFILE words=%u input=declared_public_synthetic_entropy "
                "on_exhaustion=strict_boundary physical_TRNG_sample=0 guest_RAM_written=0\n",
                s->rng_public_count);
    }
    MemoryRegion *memory = get_system_memory();
    DeviceState *dev;
    g_autofree gchar *image = NULL;
    gsize bytes = 0;
    GError *error = NULL;
    if (!machine->kernel_filename ||
        !g_file_get_contents(machine->kernel_filename, &image, &bytes, &error)) {
        error_report("EX1850 requires the selected original image: %s",
                     error ? error->message : "missing -kernel");
        exit(1);
    }
    g_autofree gchar *sha = g_compute_checksum_for_data(
        G_CHECKSUM_SHA256, (guchar *)image, bytes);
    if (bytes != EX1850_BYTES || strcmp(sha, EX1850_SHA)) {
        error_report("EX1850 source identity mismatch");
        exit(1);
    }
    memory_region_init_io(&s->unknown, OBJECT(machine), &ex1850_unknown_ops,
                           s, "EX1850.strict-unknown", UINT64_C(1) << 32);
    memory_region_add_subregion_overlap(memory, 0, &s->unknown, -100);
    /* Global board RAM/ROM regions use NULL for RAM migration ownership;
     * MachineState is not a DeviceState. */
    memory_region_init_rom_device(&s->rom, NULL, &ex1850_flash_array_ops, s,
                                  "EX1850.simulated-main-Flash", EX1850_BYTES,
                                  &error_fatal);
    /* Copy the immutable input once. Avoid rom_add_file()'s reset reload,
     * which would incorrectly restore bytes changed by guest programming. */
    memcpy(memory_region_get_ram_ptr(&s->rom), image, EX1850_BYTES);
    memory_region_add_subregion(memory, EX1850_BASE, &s->rom);
    memory_region_init_alias(&s->rom_alias, OBJECT(machine),
                             "EX1850.boot-ROM-alias", &s->rom, 0, EX1850_BYTES);
    memory_region_add_subregion_overlap(memory, 0, &s->rom_alias, 0);
    EX1850FlashConfig flash_config = {0};
    const char *flash_functional = g_getenv("EX1850_FLASH_FUNCTIONAL");
    if (flash_functional && strcmp(flash_functional, "0") && strcmp(flash_functional, "1")) {
        error_report("EX1850_FLASH_FUNCTIONAL must be 0 or 1");
        exit(1);
    }
    flash_config.functional = flash_functional && !strcmp(flash_functional, "1");
    const char *flash_names[] = {"EX1850_FLASH_VDD_MV", "EX1850_FLASH_NWRP",
        "EX1850_FLASH_ERASE_NS", "EX1850_FLASH_PROGRAM_NS"};
    uint64_t flash_values[4] = {0};
    for (unsigned i = 0; i < G_N_ELEMENTS(flash_names); i++) {
        const char *raw = g_getenv(flash_names[i]);
        char *end = NULL;
        if (!flash_config.functional) {
            if (raw) {
                error_report("Flash input %s requires EX1850_FLASH_FUNCTIONAL=1", flash_names[i]);
                exit(1);
            }
            continue;
        }
        flash_values[i] = raw ? g_ascii_strtoull(raw, &end, 0) : 0;
        if (!raw || !end || end == raw || *end || raw[0] == '-' ||
            flash_values[i] > (i == 0 ? 3600 : i == 1 ? 0xfff : INT64_MAX)) {
            error_report("Explicit Flash functional mode requires valid %s", flash_names[i]);
            exit(1);
        }
    }
    flash_config.vdd_mv = flash_values[0];
    flash_config.nwrp = flash_values[1];
    flash_config.erase_ns = flash_values[2];
    flash_config.program_ns = flash_values[3];
    if (!ex1850_flash_init(&s->flash, memory_region_get_ram_ptr(&s->rom),
                           EX1850_BYTES, flash_config)) {
        error_report("Flash sector/x32 model requires supplied array, VDD2700..3600mV, nWRP0..fff and positive virtual erase/program latencies");
        exit(1);
    }
    memory_region_init_io(&s->flash_registers, OBJECT(machine),
                          &ex1850_flash_register_ops, s, "EX1850.FLASH-registers", 0x18);
    memory_region_add_subregion(memory, 0x40023c00, &s->flash_registers);
    fprintf(stderr, "EX1850_FLASH_PROFILE functional=%u VDD_mV=%u nWRP=%03x "
            "erase_ns=%" PRId64 " program_ns=%" PRId64 " supplied_array_bytes=%x "
            "physical_voltage_protection_latency_capacity_verified=0 "
            "parallelism=x32 busy_AHB_stall=unimplemented_strict_boundary "
            "input_ROM_sha256=%s input_ROM_file_modified=0\n", flash_config.functional,
            flash_config.vdd_mv, flash_config.nwrp, flash_config.erase_ns,
            flash_config.program_ns, EX1850_BYTES, EX1850_SHA);
    ex1850_wire_attach(s);
    if (s->wire.bus) {
        memory_region_init_ram_ptr(&s->ram, NULL, "EX1850.live-wire-SRAM",
                                   EX1850_RAM_BYTES, s->wire.bus->sram);
    } else {
        memory_region_init_ram(&s->ram, NULL, "EX1850.SRAM-hypothesis",
                               EX1850_RAM_BYTES, &error_fatal);
    }
    memory_region_add_subregion(memory, EX1850_RAM_BASE, &s->ram);
    s->pwr_cr = EX1850_PWR_CR_RESET;
    /* STM32F4-family debug-pad reset defaults, still a declared MCU-family
     * hypothesis. None of these control defaults supply GPIO input levels. */
    s->gpio[0].moder = 0xa8000000;
    s->gpio[0].speed = 0x0c000000;
    s->gpio[0].pupdr = 0x64000000;
    s->gpio[1].moder = 0x00000280;
    s->gpio[1].speed = 0x000000c0;
    s->gpio[1].pupdr = 0x00000100;
    s->rcc_cr = RCC_HSION | RCC_HSIRDY | 0x80;
    s->pllcfgr = 0x24003010;
    s->cpu_hz = EX1850_HSI_HZ;
    ex1850_rng_peripheral_reset(s);
    s->tim5_arr = 0xffffffff;
    g_assert(ex1850_apb1_spi_reset(&s->apb1_spi, EX1850_APB1_SPI_MASK));
    ex1850_tim12_core_reset(&s->tim12, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    ex1850_tim1_core_reset(&s->tim1, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    ex1850_tim10_core_reset(&s->tim10, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    for (unsigned n = 0; n < 3; n++) {
        ex1850_tim234_reset(&s->tim234[n], n == 0 ? 32 : 16,
                           qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    }
    s->adc1_registers[0x24 / 4] = 0x0fff;
    s->i2c1.trise = 2;
    s->i2c2.trise = 2;
    ex1850_spi2_core_reset(&s->spi2_dma, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    ex1850_spi2_clocks_changed(s);
    ex1850_usart2_reset(&s->usart1, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    ex1850_usart1_rx_reset(&s->usart1_rx);
    ex1850_usart2_reset(&s->usart2, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    ex1850_usart1_clocks_changed(s);
    ex1850_usart2_clocks_changed(s);
    const char *i2c_bus = g_getenv("EX1850_I2C_BUS_MODE");
    if (!i2c_bus || !strcmp(i2c_bus, "strict")) { s->i2c_bus_mode = 0; }
    else if (!strcmp(i2c_bus, "released")) { s->i2c_bus_mode = 1; }
    else if (!strcmp(i2c_bus, "sda-low")) { s->i2c_bus_mode = 2; }
    else { error_report("EX1850_I2C_BUS_MODE must be strict, released or sda-low"); exit(1); }
    const char *i2c_slave = g_getenv("EX1850_I2C_SLAVE_MODE");
    if (!i2c_slave || !strcmp(i2c_slave, "strict")) { s->i2c_slave_absent = false; }
    else if (!strcmp(i2c_slave, "absent")) { s->i2c_slave_absent = true; }
    else if (!strcmp(i2c_slave, "pcal6524")) { s->i2c_pcal6524 = true; }
    else { error_report("EX1850_I2C_SLAVE_MODE must be strict, absent or pcal6524"); exit(1); }
    const char *max77711 = g_getenv("EX1850_I2C_MAX77711");
    if (max77711 && strcmp(max77711, "0") && strcmp(max77711, "1")) {
        error_report("EX1850_I2C_MAX77711 must be0 or1");
        exit(1);
    }
    s->i2c_max77711 = max77711 && !strcmp(max77711, "1");
    if (s->i2c_max77711 && s->i2c_slave_absent) {
        error_report("MAX77711 candidate and global absent are exclusive");
        exit(1);
    }
    if (s->i2c_max77711) {
        fprintf(stderr, "EX1850_I2C_ADDRESS_PROFILE address7=4f "
                "contract=MAX77511_MAX77711_candidate VIO_valid_hypothesis=1 "
                "PHCFG1_PHCFG0_floating_hypothesis=1 B2_CNFG_D_reset=OTP_unprovided "
                "rail_voltage_PGOOD_nRSTIO_and_EXPEED_ready_supplied=0\n");
    }
    const char *absent_addresses = g_getenv("EX1850_I2C_ABSENT_ADDRESSES");
    if (absent_addresses && *absent_addresses) {
        gchar **addresses = g_strsplit(absent_addresses, ",", -1);
        for (unsigned i = 0; addresses[i]; i++) {
            char *end = NULL;
            uint64_t address7 = g_ascii_strtoull(addresses[i], &end, 0);
            if (!end || end == addresses[i] || *end || address7 > 0x7f ||
                s->i2c_absent_address[address7] ||
                (s->i2c_pcal6524 && address7 == 0x22) ||
                (s->i2c_max77711 && address7 == 0x4f) || s->i2c_slave_absent) {
                error_report("EX1850_I2C_ABSENT_ADDRESSES requires distinct 7-bit addresses without an active device or global absent conflict");
                exit(1);
            }
            s->i2c_absent_address[address7] = true;
            fprintf(stderr, "EX1850_I2C_ADDRESS_PROFILE address7=%02x contract=explicit_absent source=unmeasured_negative_control\n",
                    (unsigned)address7);
        }
        g_strfreev(addresses);
    }
    const char *pin_levels = g_getenv("EX1850_PCAL_PIN_LEVELS");
    if (pin_levels && *pin_levels) {
        char *end = NULL;
        uint64_t parsed = g_ascii_strtoull(pin_levels, &end, 0);
        if (!s->i2c_pcal6524 || !end || *end || parsed > 0xffffff) {
            error_report("EX1850_PCAL_PIN_LEVELS requires pcal6524 and an explicit 24-bit level hypothesis");
            exit(1);
        }
        s->pcal_pin_profile = true;
        s->pcal_pin_levels = parsed;
    }
    if (s->i2c_pcal6524) { ex1850_pcal_cold_register_reset(s); }
    object_property_add(OBJECT(machine), "pcal-pin-levels", "uint64",
                        ex1850_pcal_host_get, ex1850_pcal_host_set, NULL, s);
    const char *pin_events = g_getenv("EX1850_PCAL_PIN_EVENTS");
    if (pin_events && *pin_events) {
        if (!s->pcal_pin_profile) {
            error_report("EX1850_PCAL_PIN_EVENTS requires explicit PCAL initial pin levels");
            exit(1);
        }
        gchar **events = g_strsplit(pin_events, ",", -1);
        int64_t epoch = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
        for (unsigned i = 0; events[i]; i++) {
            char *time_end = NULL, *mask_end = NULL, *end = NULL;
            uint64_t when = g_ascii_strtoull(events[i], &time_end, 0);
            uint64_t mask = time_end && *time_end == ':' ?
                g_ascii_strtoull(time_end + 1, &mask_end, 0) : 0;
            uint64_t levels = mask_end && *mask_end == ':' ?
                g_ascii_strtoull(mask_end + 1, &end, 0) : UINT64_MAX;
            if (i >= ARRAY_SIZE(s->pcal_pin_events) || !time_end ||
                time_end == events[i] || *time_end != ':' || !mask_end ||
                mask_end == time_end + 1 || *mask_end != ':' || !end ||
                end == mask_end + 1 || *end || !when ||
                when > INT64_MAX - epoch || !mask || mask > 0xffffff ||
                levels > 0xffffff || (levels & ~mask) ||
                (i && epoch + when <= s->pcal_pin_events[i - 1].when_ns)) {
                error_report("EX1850_PCAL_PIN_EVENTS requires at most64 ordered ns:24-bit-mask:masked-levels entries");
                exit(1);
            }
            s->pcal_pin_events[i].when_ns = epoch + when;
            s->pcal_pin_events[i].mask = mask;
            s->pcal_pin_events[i].levels = levels;
            s->pcal_pin_event_count++;
        }
        g_strfreev(events);
    }
    const char *adc_levels = g_getenv("EX1850_ADC_PIN_MV");
    const char *adc_reference = g_getenv("EX1850_ADC_VREF_MV");
    if (adc_levels && *adc_levels) {
        char *end = NULL;
        uint64_t reference = adc_reference ? g_ascii_strtoull(adc_reference, &end, 0) : 0;
        if (!end || *end || !reference || reference > 5000) {
            error_report("Explicit ADC pin voltages require EX1850_ADC_VREF_MV in1..5000");
            exit(1);
        }
        s->adc_vref_mv = reference;
        gchar **channels = g_strsplit(adc_levels, ",", -1);
        for (unsigned i = 0; channels[i]; i++) {
            char *split = NULL, *finish = NULL;
            uint64_t channel = g_ascii_strtoull(channels[i], &split, 0);
            uint64_t mv = split && *split == '=' ? g_ascii_strtoull(split + 1, &finish, 0) : UINT64_MAX;
            if (!split || split == channels[i] || *split != '=' || channel >= 16 ||
                !finish || finish == split + 1 || *finish || mv > reference ||
                s->adc_voltage_profile[channel]) {
                error_report("EX1850_ADC_PIN_MV requires distinct external channels0..15=mV, within explicit VREF");
                exit(1);
            }
            s->adc_voltage_profile[channel] = true;
            s->adc_pin_mv[channel] = mv;
            fprintf(stderr, "EX1850_ADC_PIN_PROFILE channel=%u mv=%u reference_mv=%u "
                    "source=explicit_offline_analog_voltage_hypothesis "
                    "physical_camera_sample=0 factory_calibration_supplied=0\n",
                    (unsigned)channel, s->adc_pin_mv[channel], s->adc_vref_mv);
        }
        g_strfreev(channels);
    } else if (adc_reference && *adc_reference) {
        error_report("EX1850_ADC_VREF_MV without declared ADC pins is not an input scenario");
        exit(1);
    }
    const char *gpio_levels = g_getenv("EX1850_GPIO_PIN_LEVELS");
    if (gpio_levels && *gpio_levels) {
        gchar **ports = g_strsplit(gpio_levels, ",", -1);
        for (unsigned i = 0; ports[i]; i++) {
            const char *entry = ports[i];
            char *end = NULL;
            uint64_t parsed = strlen(entry) >= 3 ? g_ascii_strtoull(entry + 2, &end, 0) : UINT64_MAX;
            if (entry[0] < 'A' || entry[0] > 'H' || entry[1] != '=' ||
                !end || end == entry + 2 || *end || parsed > 0xffff ||
                s->gpio_pin_profile[entry[0] - 'A']) {
                error_report("EX1850_GPIO_PIN_LEVELS requires distinct A..H=16-bit levels, comma separated");
                exit(1);
            }
            unsigned bank = entry[0] - 'A';
            s->gpio_pin_profile[bank] = true;
            s->gpio_pin_levels[bank] = parsed;
            s->gpio_pin_known_mask[bank] = 0xffff;
            fprintf(stderr, "EX1850_GPIO_PIN_PROFILE bank=%c levels=%04x "
                    "source=explicit_offline_digital_input_hypothesis "
                    "physical_camera_sample=0 is_documented_reset_value=0\n",
                    'A' + bank, s->gpio_pin_levels[bank]);
        }
        g_strfreev(ports);
    }
    const char *gpio_known = g_getenv("EX1850_GPIO_PIN_KNOWN_MASKS");
    if (gpio_known && *gpio_known) {
        uint8_t declared = 0;
        gchar **ports = g_strsplit(gpio_known, ",", -1);
        for (unsigned i = 0; ports[i]; i++) {
            const char *entry = ports[i];
            char *end = NULL;
            uint64_t parsed = strlen(entry) >= 3 ? g_ascii_strtoull(entry + 2, &end, 0) : UINT64_MAX;
            if (entry[0] < 'A' || entry[0] > 'H' || entry[1] != '=' ||
                !end || end == entry + 2 || *end || parsed > 0xffff) {
                error_report("EX1850_GPIO_PIN_KNOWN_MASKS requires A..H=16-bit masks");
                exit(1);
            }
            unsigned bank = entry[0] - 'A';
            if (!s->gpio_pin_profile[bank] || (declared & (1U << bank))) {
                error_report("GPIO known masks require distinct ports with declared input levels");
                exit(1);
            }
            declared |= 1U << bank;
            s->gpio_pin_known_mask[bank] = parsed;
            fprintf(stderr, "EX1850_GPIO_PIN_KNOWN_MASK bank=%c known_mask=%04x "
                    "unspecified_external_input_pads_strict=1\n", 'A' + bank,
                    s->gpio_pin_known_mask[bank]);
        }
        g_strfreev(ports);
    }
    for (unsigned bank = 0; bank < 8; bank++) {
        g_autofree char *name = g_strdup_printf("gpio-pin-levels-%c", 'A' + bank);
        object_property_add(OBJECT(machine), name, "uint64",
                            ex1850_gpio_host_get, ex1850_gpio_host_set, NULL, s);
    }
    const char *masked_gpio = g_getenv("EX1850_GPIO_MASKED_READPIN");
    if (masked_gpio && strcmp(masked_gpio, "0") && strcmp(masked_gpio, "1")) {
        error_report("EX1850_GPIO_MASKED_READPIN must be 0 or 1");
        exit(1);
    }
    s->gpio_masked_readpin = masked_gpio && !strcmp(masked_gpio, "1");
    if (s->gpio_masked_readpin) {
        fprintf(stderr, "EX1850_GPIO_MASKED_READPIN enabled=1 "
                "original_getter=08043ac8 original_bytes=0069084000d001207047 "
                "unused_bits_zero_representative=1 generic_IDR_modeled=0 "
                "selected_unknown_or_AF_pads_strict=1 firmware_modified=0\n");
    }
    s->i2c_start_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, ex1850_i2c_start_complete, s);
    s->i2c_nack_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, ex1850_i2c_absent_slave_nack, s);
    s->i2c_stop_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, ex1850_i2c_stop_complete, s);
    s->i2c_external_input_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, ex1850_i2c_unknown_external_input, s);
    s->pcal_pin_event_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, ex1850_pcal_pin_event, s);
    if (s->pcal_pin_event_count) {
        timer_mod(s->pcal_pin_event_timer, s->pcal_pin_events[0].when_ns);
    }
    s->tim5_overflow = timer_new_ns(QEMU_CLOCK_VIRTUAL, ex1850_tim5_wrap, s);
    s->tim11_overflow = timer_new_ns(QEMU_CLOCK_VIRTUAL, ex1850_tim11_wrap, s);
    s->tim12_event = timer_new_ns(QEMU_CLOCK_VIRTUAL, ex1850_tim12_event, s);
    s->tim1_event = timer_new_ns(QEMU_CLOCK_VIRTUAL, ex1850_tim1_event, s);
    s->tim10_event = timer_new_ns(QEMU_CLOCK_VIRTUAL, ex1850_tim10_event, s);
    for (unsigned n = 0; n < 3; n++) {
        s->tim234_event_data[n].state = s;
        s->tim234_event_data[n].index = n;
        s->tim234_event[n] = timer_new_ns(QEMU_CLOCK_VIRTUAL, ex1850_tim234_event,
                                        &s->tim234_event_data[n]);
    }
    s->spi2_event = timer_new_ns(QEMU_CLOCK_VIRTUAL, ex1850_spi2_event, s);
    ex1850_spi2_schedule(s);
    s->usart1_event = timer_new_ns(QEMU_CLOCK_VIRTUAL, ex1850_usart1_event, s);
    ex1850_usart1_schedule(s);
    s->usart2_event = timer_new_ns(QEMU_CLOCK_VIRTUAL, ex1850_usart2_event, s);
    ex1850_usart2_schedule(s);
    s->flash_event = timer_new_ns(QEMU_CLOCK_VIRTUAL, ex1850_flash_event, s);
    s->adc_conversion_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, ex1850_adc_conversion_complete, s);
    const char *hse = g_getenv("EX1850_HSE_PRESENT");
    if (hse && strcmp(hse, "0") && strcmp(hse, "1")) {
        error_report("EX1850_HSE_PRESENT must be 0 or 1");
        exit(1);
    }
    s->hse_present = !hse || !strcmp(hse, "1");
    s->hse_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, ex1850_hse_ready, s);
    s->pll_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, ex1850_pll_ready, s);
    s->rng_event = timer_new_ns(QEMU_CLOCK_VIRTUAL, ex1850_rng_event, s);
    s->switch_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, ex1850_switch_ready, s);
    const char *lse = g_getenv("EX1850_LSE_PRESENT");
    if (lse && strcmp(lse, "0") && strcmp(lse, "1")) {
        error_report("EX1850_LSE_PRESENT must be 0 or 1");
        exit(1);
    }
    s->lse_present = !lse || !strcmp(lse, "1");
    s->lse_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, ex1850_lse_ready, s);
    ex1850_rtc_reset(&s->rtc, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    ex1850_rtc_bind_output(&s->rtc, ex1850_rtc_output, s);
    s->rtc_event = timer_new_ns(QEMU_CLOCK_VIRTUAL, ex1850_rtc_event, s);
    s->cpuclk = clock_new(OBJECT(machine), "ROM-HSI-clock-family-reset-hypothesis");
    clock_set_hz(s->cpuclk, EX1850_HSI_HZ);
    dev = qdev_new(TYPE_ARMV7M);
    object_property_add_child(OBJECT(machine), "armv7m", OBJECT(dev));
    qdev_prop_set_string(dev, "cpu-type", TYPE_EX1850_M4_R0P1);
    qdev_prop_set_uint32(dev, "num-irq", 96);
    qdev_prop_set_uint8(dev, "num-prio-bits", 4);
    qdev_prop_set_bit(dev, "enable-bitband", true);
    qdev_connect_clock_in(dev, "cpuclk", s->cpuclk);
    object_property_set_link(OBJECT(dev), "memory", OBJECT(memory), &error_abort);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
    s->armv7m = ARMV7M(dev);
    ex1850_usart1_line_init(s);
    ex1850_rtc_irq_update(s);
    ((EX1850M4R0P1 *)s->armv7m->cpu)->board = s;
    /* Per-device host boundary handler, not a guest callback. The generic
     * NVIC retains stock behavior on every machine without this handler. */
    s->armv7m->nvic.sleep_control_write_boundary = ex1850_sleep_control_write;
    s->armv7m->nvic.sleep_control_boundary_opaque = s;
    qemu_register_reset(ex1850_flash_reset, s);
    qemu_register_reset(ex1850_power_reset, s);
    qemu_register_reset(ex1850_rng_reset, s);
    qemu_register_reset(ex1850_usart1_reset, s);
    /* Registers the architectural Cortex-M reset handler; the verified
     * original bytes are already in Flash and remain the vector source. */
    armv7m_load_kernel(s->armv7m->cpu, NULL, 0, EX1850_BYTES);
    fprintf(stderr, "EX1850_RNG_PROFILE source=PLLQ entropy=QEMU_guest_random "
            "first_word_cycles=46 refill_cycles=42 reference=RM0402_Rev7 "
            "CR=RNGEN_IE SR=DRDY_CECS_CEIS_W0C DR_read_clears_DRDY=1 "
            "IRQ=80 RCC_reset_and_clock_gate=1 disabled_ready_word_retained=1 "
            "analog_seed_health_tests_and_CED=unmodeled physical_TRNG_sample=0\n");
    if (s->wire.bus) {
        timer_mod(s->wire_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + s->wire_poll_ns);
    }
    fprintf(stderr, "EX1850_EXTERNAL_PIN_PROFILE device=PCAL6524 enabled=%u "
            "levels=%06x source=explicit_offline_digital_input_hypothesis "
            "is_documented_reset_value=0 physical_camera_sample=0\n",
            s->pcal_pin_profile, s->pcal_pin_levels);
    fprintf(stderr, "EX1850_PROFILE source_sha256=%s original_vector=1 "
            "C_initialized_RAM_fixture=0 packet_replay=0 "
            "CPU=Cortex-M4_r0p1 CPUID=410fc241 RAM_bytes=%x reset_CPU_hz=%u ROM_HSE_hz=%u "
            "physical_MCU_and_clock_verified=0 APB1ENR_reset=00000000 "
            "PWR_CR_reset=0000c000 PWR_status_ready_supplied=0 "
            "HSE_present=%u HSE_start_ns=%u PLL_lock_ns=%u clock_switch_ns=%u "
            "oscillator_status=virtual_timer_model RCC_read_log=sampled "
            "TIM5=internal_upcounter_APB1_PSC_ARR_IRQ_not_implemented "
            "AHB1ENR_reset_hypothesis=0 AHB2ENR_reset_hypothesis=0 APB2ENR_reset_hypothesis=0 "
            "GPIO=family_control_latches_A_to_H GPIO_IDR=optional_explicit_static_pin_scenario "
            "GPIO_alternate_function_and_dynamic_edges=unmodeled "
            "RTC=empty_BDCR_LSE_ISR_calendar24h_SSR_two_cycle_shadows "
            "RTC_ISR_reset_hypothesis=7 TR_reset_hypothesis=0 DR_reset_hypothesis=2101 "
            "retained_factory_RTC_supplied=0 host_wall_clock_used=0 "
            "I2C1=configuration_and_opt_in_clocked_START_NACK_STOP_candidate_protocol "
            "I2C_bus_assumption=%u absent_slave_negative_control=%u "
            "PCAL6524_power_RESET_VSS_address_protocol_hypothesis=%u "
            "I2C_RX_explicit_static_pin_and_cold_register_model=%u DMA_transfers=unmodeled "
            "LSE_present=%u LSE_start_ns=%u LSE_hz_hypothesis=%u "
            "NVIC_and_bitband=QEMU_architecture unknown_exit=66\n",
            sha, EX1850_RAM_BYTES, EX1850_HSI_HZ, EX1850_HSE_HZ,
            s->hse_present, EX1850_HSE_START_NS, EX1850_PLL_LOCK_NS, EX1850_SWITCH_NS,
            s->i2c_bus_mode, s->i2c_slave_absent, s->i2c_pcal6524, s->pcal_pin_profile,
            s->lse_present, EX1850_LSE_START_NS, EX1850_LSE_HZ);
}

static void ex1850_reset_machine_init(MachineClass *mc)
{
    static const char *const valid_cpu_types[] = {
        TYPE_EX1850_M4_R0P1,
        ARM_CPU_TYPE_NAME("cortex-m4"), NULL,
    };
    mc->desc = "Nikon EX1850 original reset vector; strict missing peripherals";
    mc->init = ex1850_reset_init;
    mc->valid_cpu_types = valid_cpu_types;
}

DEFINE_MACHINE_ARM("nikon-ex1850-reset", ex1850_reset_machine_init)

/* The physical Z6II sample returned CPUID 410FC241. Inherit the QEMU M4
 * architectural model and declare its observed r0p1 identity as a CPU type;
 * never write a guest register or change the original reset vector. */
static void ex1850_m4_r0p1_init(Object *obj)
{
    ARM_CPU(obj)->midr = EX1850_CPU_CPUID;
}

static void ex1850_m4_r0p1_class_init(ObjectClass *klass, const void *data)
{
    CPUClass *cc = CPU_CLASS(klass);
    (void)data;
    ex1850_parent_sysemu_ops = cc->sysemu_ops;
    ex1850_parent_tcg_ops = cc->tcg_ops;
    g_assert(ex1850_parent_sysemu_ops && ex1850_parent_tcg_ops);
    ex1850_mcu_sysemu_ops = *ex1850_parent_sysemu_ops;
    ex1850_mcu_tcg_ops = *ex1850_parent_tcg_ops;
    g_assert(!ex1850_mcu_tcg_ops.before_mmio);
    ex1850_mcu_sysemu_ops.has_work = ex1850_flash_wait_has_work;
    ex1850_mcu_tcg_ops.cpu_exec_halt = ex1850_flash_wait_exec_halt;
    ex1850_mcu_tcg_ops.cpu_exec_exit = ex1850_power_exec_exit;
    ex1850_mcu_tcg_ops.before_mmio = ex1850_flash_before_mmio;
    cc->sysemu_ops = &ex1850_mcu_sysemu_ops;
    cc->tcg_ops = &ex1850_mcu_tcg_ops;
}

static void ex1850_register_cpu_type(void)
{
    static const TypeInfo info = {
        .name = TYPE_EX1850_M4_R0P1,
        .parent = ARM_CPU_TYPE_NAME("cortex-m4"),
        .instance_size = sizeof(EX1850M4R0P1),
        .instance_init = ex1850_m4_r0p1_init,
        .class_init = ex1850_m4_r0p1_class_init,
    };
    type_register_static(&info);
}

type_init(ex1850_register_cpu_type)
