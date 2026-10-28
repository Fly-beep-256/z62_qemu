/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Z6II C1.70 per-engine startup probe. Based on the boot-interface research
 * in WonderLantern/z6-qemu (GPL-2.0-or-later). CPU/GIC/reset responses are
 * explicit functional hypotheses, not identified hardware specifications.
 * No USB, host devices or camera connection. Optional queue backing is a
 * new, run-local diagnostic file, never camera persistent configuration. */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "hw/boards.h"
#include "hw/arm/machines-qom.h"
#include "hw/loader.h"
#include "hw/cpu/a15mpcore.h"
#include "hw/cpu/cluster.h"
#include "hw/qdev-properties.h"
#include "hw/qdev-properties-system.h"
#include "hw/irq.h"
#include "hw/sd/sdhci.h"
#include "chardev/char-fe.h"
#include "qemu/cutils.h"
#include "qemu/timer.h"
#include "qemu/notify.h"
#include "qemu/host-utils.h"
#include "target/arm/cpu.h"
#include "system/runstate.h"
#include "system/reset.h"
#include "system/system.h"
#include "system/block-backend.h"
#include "system/address-spaces.h"
#include "accel/tcg/cpu-ops.h"
#include "hw/core/sysemu-cpu-ops.h"
#include "exec/translation-block.h"
#include "exec/cpu-common.h"
#include "exec/cpu-interrupt.h"
#include "accel/tcg/internal-common.h"
#include "qapi/visitor.h"
#include "qobject/qdict.h"
#include "qobject/qlist.h"
#include "qobject/qjson.h"
#include "nikon-z6ii-engine.h"
#include "saiso-ex1850/nikon-ex1850-board.h"
#include "nikon-z6ii-profile.h"
#include "nikon-z6ii-devices.h"
#include "nikon-z6ii-peer-parameter.h"
#include "nikon-z6ii-hdmi-core.h"
#include "nikon-z6ii-hdmi-i2c-reset-core.h"
#include "nikon-z6ii-hdmi-phy-i2c-core.h"
#include "nikon-z6ii-hdmi-phy-pll-core.h"
#include "nikon-z6ii-hdmi-irq-core.h"
#include "nikon-z6ii-hdmi-video.h"
#include "nikon-z6ii-genadc.h"
#include "nikon-z6ii-ipu2402.h"
#include "ba2-qemu78.h"
#include "ba2-reset-bank98.h"
#include "ba2-spr5000-storage-candidate.h"
#include "ba2-spr5001-4000-storage-candidates.h"
#include "ba2-spr5004-5005-snapshot-candidates.h"

/* Minimum two original identity sections observed in cold123. The host
 * reads this extent from the selected immutable model source. */
#define Z6II_PEER_DATA_SECTION_BYTES UINT32_C(0x200000)

typedef struct Z6IIState {
    const Z6IIProfile *profile;
    Z6IIEngineContext *engine;
    MemoryRegion rom, unknown, ram[24], aliases[24], diagnostic_peer, diagnostic_peer_status;
    MemoryRegion observed_peer_buffer;
    MemoryRegion observed_peer_data_buffer;
    MemoryRegion observed_peer_dma_buffer;
    MemoryRegion observed_slave_dma_buffer;
    MemoryRegion observed_peer_parameter_buffer;
    bool observed_peer_parameter_enabled, parameter_copy_pending;
    bool parameter_copy_seen;
    bool parameter_require_recorded_body;
    uint8_t *parameter_reference50, *parameter_reference47;
    Z6IIParameterCopy parameter_copy;
    QEMUTimer *parameter_copy_timer;
    bool observed_slave_dma_enabled;
    bool observed_peer_dma_enabled, fill1_enabled;
    uint32_t fill1[13];
    A15MPPrivState *priv;
    bool faulted;
    unsigned mmio_count;
    bool lcd98_trace_initialized;
    uint64_t lcd98_trace_attempts, lcd98_trace_written, lcd98_trace_incomplete;
    uint32_t early[9], fill[13], uart[16], config[0x8000 / 4];
    uint32_t ddr_regs[0x40000 / 4];
    bool ddr_written[0x40000 / 4];
    uint32_t startup_mapping[14];
    bool platform_profile;
    uint32_t platform_regs[0x7000 / 4], platform_saved[512];
    bool platform_written[0x7000 / 4];
    QEMUTimer *platform_timer;
    bool config_written[0x8000 / 4];
    QEMUTimer *clock_timer;
    uint32_t clock_transaction;
    int64_t counter_epoch;
    bool protocol_diagnostic;
    bool coupled_queues;
    bool coupled_notifications;
    MemoryRegion shared_events;
    uint32_t *shared_event_words;
    bool automatic_peer_irq;
    QEMUTimer *shared_event_timer;
    unsigned shared_event_poll_ns;
    bool shared_irq_level;
    bool coupled_link_configuration;
    bool coupled_gpio, gpio_connection, coupled_phy, coupled_stop, coupled_lanes;
    uint32_t coupled_gpio_known[12], coupled_gpio_last_read;
    uint32_t coupled_stop_seen;
    uint32_t coupled_lane_generation[2], coupled_lane_reported[8];
    bool coupled_gpio_read_seen, coupled_phy_request_seen, coupled_phy_complete_seen;
    uint32_t diagnostic_event_pending[2];
    uint32_t diagnostic_translation[2][40];
    bool serial_initialized[11];
    uint32_t serial_disabled[11], serial_config[11][0x68 / 4];
    uint32_t gpio_init[3];
    uint32_t peripheral_control[3];
    Z6IIFunctionalDevices *devices;
    QEMUTimer *exmcu_report_timer;
    uint8_t exmcu_original_packet[256];
    QEMUTimer *exmcu_sys_timer;
    uint8_t exmcu_sys_version_packet[256], exmcu_sys_state_packet[256];
    bool exmcu_sys_version_enabled, exmcu_sys_state_enabled;
    bool exmcu_sys_request_seen, exmcu_rx_awaiting_ack;
    unsigned exmcu_sys_stage, exmcu_sys_delay_ms;
    QEMUTimer *exmcu_key_timer;
    uint8_t exmcu_key_packet[256];
    unsigned exmcu_key_delay_ms;
    QEMUTimer *exmcu_power_timer;
    uint8_t exmcu_power_packet[256];
    unsigned exmcu_power_delay_ms;
    QEMUTimer *exmcu_service0d_timer;
    uint8_t exmcu_service0d_packet[256];
    unsigned exmcu_service0d_delay_ms;
    bool exmcu_service0d_enabled, exmcu_service0d_request_seen;
    QEMUTimer *exmcu_service0d_command01_timer;
    uint8_t exmcu_service0d_command01_packet[256];
    unsigned exmcu_service0d_command01_delay_ms;
    bool exmcu_service0d_command01_enabled, exmcu_service0d_command01_request_seen;
    uint32_t slave_2b20_config[14];
    bool slave_2b20_control_latch;
    uint32_t slave_2b20_control300;
    bool slave_pipeline_configuration, slave_pipeline_completion;
    bool slave_pipeline_held, slave_pipeline_released, slave_pipeline_committed;
    bool slave_pipeline_access_ready_line;
    uint32_t slave_pipeline_regs[0x1000 / 4];
    uint32_t slave_bridge_channel_regs[4][0x1000 / 4];
    bool slave_pipeline_written[0x1000 / 4];
    uint32_t slave_pipeline_status58, slave_pipeline_generation;
    QEMUTimer *slave_pipeline_timer;
    bool slave_sdhci_enabled, slave_sdhci_virtual_cards, slave_sdhci_formatted_cards;
    SDHCIState *slave_sdhci[2];
    uint16_t slave_sdhci_vendor_c2[2];
    uint32_t slave_sdhci_vendor_status_c8[2];
    bool slave_sdhci_irq_level[2];
    uint32_t slave_storage_irq_pending, slave_storage_irq_enable, slave_storage_irq_enable9;
    bool link_test_peer, link_ready, link_gpio, link_stop_command;
    uint32_t link_pending, link_mask, link_scheduled;
    uint32_t link_regs[0x10000 / 4];
    bool link_written[0x10000 / 4];
    QEMUTimer *link_timer;
    uint32_t assisted_gate34;
    uint32_t assisted_control2c012000;
    uint32_t assisted_control2c012004, assisted_control2c012008;
    uint32_t assisted_ipu_config[5];
    uint32_t ipu_transmit_words[3];
    unsigned ipu_transmit_count;
    unsigned flash_query_unlock, flash_query_mode;
    uint8_t *virtual_persistent_flash;
    uint32_t virtual_persistent_base;
    uint32_t supplied_persistent_source_start, supplied_persistent_source_end;
    /* Opt-in Z6II_PERSISTENT_OUTPUT_FILE: export the per-run flash at process exit. */
    char *persistent_output_path;
    uint64_t flash_program_halfwords, flash_erase_sectors;
    uint32_t flash_program_min, flash_program_max;
    Z6IIHDMICore hdmi;
    Z6IIHDMIVideo hdmi_video;
    Z6IIHDMIIRQCore hdmi_ih;
    bool hdmi_ih_enabled, hdmi_initial_hpd;
    Z6IIPhyI2CCore hdmi_phy_i2c;
    bool hdmi_phy_i2c_enabled;
    QEMUTimer *hdmi_phy_i2c_timer;
    uint64_t hdmi_phy_i2c_timer_generation;
    Z6IIPhyPLLCore hdmi_phy_pll;
    bool hdmi_phy_pll_enabled;
    QEMUTimer *hdmi_phy_pll_timer;
    uint64_t hdmi_phy_pll_timer_generation;
    Z6IIHDMIResetCore hdmi_i2c_reset;
    bool hdmi_i2c_reset_enabled;
    QEMUTimer *hdmi_i2c_reset_timer[2];
    uint64_t hdmi_i2c_reset_timer_generation[2];
    bool hdmi_enabled;
    QEMUTimer *hdmi_timer, *hdmi_hpd_timer;
    uint64_t hdmi_timer_generation;
    uint8_t *hdmi_edid;
    int hdmi_gic_input;
    bool hdmi_irq_level;
    unsigned hdmi_trace_count, hdmi_trace_limit;
    Z6IIHDMIHPDEvent hdmi_hpd_events[64];
    unsigned hdmi_hpd_count, hdmi_hpd_index;
    int64_t hdmi_hpd_epoch;
    Z6IIGenADC genadc;
    Z6IIGenADCFrame *genadc_frames;
    QEMUTimer *genadc_timer;
    uint64_t genadc_timer_generation;
    bool genadc_enabled, genadc_irq_level;
    int genadc_gic_input;
    unsigned genadc_trace_count, genadc_trace_limit;
    Z6IIIPU2402 ipu2402;
    bool ipu2402_enabled, ipu2402_irq_level;
    int ipu2402_gic_input;
    unsigned ipu2402_trace_count, ipu2402_trace_limit;
    Z6IIBA2QEMU78 *ba2_peer;
    Z6IIBA2ResetBank98 ba2_spr_bank;
    uint32_t ba2_spr_initial[3];
    Z6IIBA2SPR5000StorageCandidate ba2_spr5000;
    uint32_t ba2_spr5000_initial;
    bool ba2_spr5000_enabled;
    Z6IIBA2SPR5001StorageCandidate ba2_spr5001;
    uint32_t ba2_spr5001_initial;
    bool ba2_spr5001_enabled;
    Z6IIBA2SPR4000StorageCandidate ba2_spr4000;
    uint32_t ba2_spr4000_initial;
    bool ba2_spr4000_enabled;
    Z6IIBA2SPR5004SnapshotCandidate ba2_spr5004;
    uint32_t ba2_spr5004_initial;
    bool ba2_spr5004_enabled;
    Z6IIBA2SPR5005SnapshotCandidate ba2_spr5005;
    uint32_t ba2_spr5005_initial;
    bool ba2_spr5005_enabled;
} Z6IIState;

static void z6ii_trace(Z6IIState *s, hwaddr addr, unsigned size,
                      bool write, uint64_t value)
{
    if (s->mmio_count++ < 10000) {
        fprintf(stderr, "Z6II_MMIO role=%s %c addr=%08" HWADDR_PRIx
                " size=%u value=%08" PRIx64 " cpu=%d pc=%08x\n",
                s->profile->role, write ? 'W' : 'R', addr, size, value,
                current_cpu ? current_cpu->cpu_index : -1,
                current_cpu ? ARM_CPU(current_cpu)->env.regs[15] : 0);
    }
}

#include "nikon-z6ii-ddr.h"
#include "nikon-z6ii-platform.h"
#include "nikon-z6ii-exmcu.h"
#include "nikon-z6ii-coupled-link.h"
#include "nikon-z6ii-link.h"
#include "nikon-z6ii-slave-pipeline.h"
#include "nikon-z6ii-slave-storage.h"
static void z6ii_hdmi_phy_i2c_reset_state(Z6IIState *s);
static void z6ii_hdmi_phy_pll_board_reset_state(Z6IIState *s);
#include "nikon-z6ii-hdmi.h"
#include "nikon-z6ii-hdmi-phy-pll.h"
#include "nikon-z6ii-hdmi-phy-i2c.h"
#include "nikon-z6ii-hdmi-i2c-reset.h"
#include "nikon-z6ii-genadc-qemu.h"
#include "nikon-z6ii-ipu2402-qemu.h"
#include "nikon-z6ii-ba2-qemu.h"
#include "target/arm/tcg/z6ii-boot-observer.h"
#include "nikon-z6ii-cpu-wait.h"

static void z6ii_capseq_actuator_board_reset(void *opaque)
{
    Z6IIState *s = opaque;
    z6ii_capseq_actuator_reset(s->devices);
    /* Coupled DATA and direct DATA keep separate actual masked-write latches. */
    s->config[0x2018 / 4] &= ~0x100U;
}

static bool z6ii_slave_configuration_access(Z6IIState *s, hwaddr addr,
                                            unsigned size, bool write, uint64_t *value)
{
    /* Original slave10089F00 encodes config into24/28/2C;1008A0B8 reads
     * back those exact selected bits.10089C78/10089D5A are the matching
     * setter/getter for0C/10.10089E8E packs the same kind of configuration
     * into14/18 using BFI, with no computation result or IRQ. This does
     * not implement the unknown
     * processing IP, its status/completion or a sensor. Reset0 is an explicit
     * unmeasured hardware-input hypothesis; values then come from guest stores.
     * Original master and earlier strict/queue-only boards do not use it. */
    if (!s->devices || strcmp(s->profile->role, "slave") || size != 4) { return false; }
    if (z6ii_slave_pipeline_access(s, addr, size, write, value)) { return true; }
    if (z6ii_slave_storage_bridge_irq(s, addr, size, write, value)) { return true; }
    unsigned index;
    uint32_t mask;
    uint32_t pc = current_cpu ? ARM_CPU(current_cpu)->env.regs[15] : 0;
    if (addr == 0x2b200300) {
        if (!s->slave_2b20_control_latch || (write && (*value & ~1ULL))) {
            return false;
        }
        /*1008B254..25A reads/ORs bit0/stores, without polling this register.
         * This opt-in RESET0/writable-bit0 hypothesis is not a decoded IP
         * specification. Never generate a frame, status, IRQ or readiness.
         * Default remains an unknown device boundary. */
        if (write) { s->slave_2b20_control300 = *value; }
        else { *value = s->slave_2b20_control300; }
        fprintf(stderr, "Z6II_SLAVE_CONTROL300_HYPOTHESIS %c value=%08" PRIx64
                " reset_zero_hypothesis=1 bit0_latch_hypothesis=1 "
                "physical_semantics_verified=0 completion_IRQ_emulated=0 "
                "MCU_or_master_ready_supplied=0\n", write ? 'W' : 'R', *value);
        return true;
    }
    switch (addr) {
    case 0x2b20000c: index = 0; mask = 0x31111033; break;
    case 0x2b200010: index = 1; mask = 0x00010111; break;
    case 0x2b200024: index = 2; mask = 0x00010001; break;
    case 0x2b200028: index = 3; mask = 0xbbbbbbbb; break;
    case 0x2b20002c: index = 4; mask = 0xbbbbbbbb; break;
    case 0x2b200014: index = 5; mask = 0x31111013; break;
    case 0x2b200018: index = 6; mask = 0x00000111; break;
    /*1008A32E writes these four packed configuration words;
     *1008A3B8 reads back the same fields. No completion is generated. */
    case 0x2b20003c: index = 8; mask = 0x70010011; break;
    case 0x2b20004c: index = 9; mask = 0x00010001; break;
    case 0x2b200050: index = 10; mask = 0x11111111; break;
    case 0x2b200054: index = 11; mask = 0x00010001; break;
    /*04 also carries status bits queried by10089E4E. Do not service that
     * status getter. Only the matching config RMW/setter10089DC6 and
     * getter10089E1E are supported here;08 has the paired config fields. */
    case 0x2b200004:
        /* env.regs15 during TCG MMIO may be the translation-block start,
         * not the exact LDR PC. Accept only the original config RMW/getter
         * prefixes;10089E4E/52's different status getter stays excluded. */
        if (!write && !((pc >= 0x10089dc6 && pc <= 0x10089dce) ||
                        (pc >= 0x10089e1e && pc <= 0x10089e22))) { return false; }
        index = 12; mask = 0x00000111; break;
    case 0x2b200008:
        if (!write && !(pc >= 0x10089e1e && pc <= 0x10089e24)) { return false; }
        index = 13; mask = 0x00001101; break;
    /*10089E72 writes the mode/control word. Original1008B21E selects4
     * for the alternate branch of1008B0F0. Latch only observed0/4;
     * operation effects, samples and status/completion remain absent. */
    case 0x2b200000:
        if (write && !s->slave_pipeline_configuration && *value != 0 && *value != 4) { return false; }
        index = 7; mask = 0x0000011f; break;
    default: return false;
    }
    if (write) {
        if (*value & ~(uint64_t)mask) { return false; }
        s->slave_2b20_config[index] = *value;
        if (addr == 0x2b200000) { z6ii_slave_pipeline_commit(s, *value); }
    } else { *value = s->slave_2b20_config[index]; }
    fprintf(stderr, "Z6II_SLAVE_CONFIG_READBACK %c addr=%08" HWADDR_PRIx
            " value=%08" PRIx64 " reset_zero_hypothesis=1 computation_emulated=0 "
            "operation_effects_emulated=0 completion_IRQ_emulated=0\n",
            write ? 'W' : 'R', addr, *value);
    return true;
}

/* Research option for two-boot persistence: the firmware's own shutdown path
 * programs the per-run flash; this exports that medium when the process exits
 * so a later run can supply it as an explicit, analysis-only input. It never
 * writes guest state, and the exported bytes are an emulator product, not a
 * physical dump. Exit paths that skip atexit (SIGKILL) export nothing. */
static GSList *z6ii_persistent_output_boards;

static void z6ii_persistent_output_end(void)
{
    for (GSList *item = z6ii_persistent_output_boards; item; item = item->next) {
        Z6IIState *s = item->data;
        size_t length = 0x14000000 - s->virtual_persistent_base;
        g_autoptr(GError) error = NULL;
        g_autofree char *sum = g_compute_checksum_for_data(G_CHECKSUM_SHA256,
                                   s->virtual_persistent_flash, length);
        bool ok = g_file_set_contents(s->persistent_output_path,
                                      (const char *)s->virtual_persistent_flash,
                                      length, &error);
        fprintf(stderr, "Z6II_PERSISTENT_OUTPUT role=%s base=%08x bytes=%zu sha256=%s "
                "program_halfwords=%" PRIu64 " program_min=%08x program_max=%08x "
                "erased_sectors=%" PRIu64 " written=%d guest_writes=0 physical_dump=0 "
                "provenance=emulator_run_product\n",
                s->profile->role, s->virtual_persistent_base, length, sum,
                s->flash_program_halfwords, s->flash_program_min, s->flash_program_max,
                s->flash_erase_sectors, ok);
        if (!ok) { fprintf(stderr, "Z6II_PERSISTENT_OUTPUT_ERROR %s\n", error->message); }
    }
}

static void z6ii_persistent_output_init(Z6IIState *s)
{
    const char *path = z6ii_engine_getenv(s->engine, "Z6II_PERSISTENT_OUTPUT_FILE");
    if (!path) { return; }
    if (!*path) {
        error_report("Persistent flash output path is empty");
        exit(1);
    }
    s->persistent_output_path = g_strdup(path);
    if (!z6ii_persistent_output_boards && atexit(z6ii_persistent_output_end)) {
        error_report("Persistent flash output cannot register its exit export");
        exit(1);
    }
    z6ii_persistent_output_boards = g_slist_append(z6ii_persistent_output_boards, s);
    fprintf(stderr, "Z6II_PERSISTENT_OUTPUT_ARMED role=%s path=%s\n", s->profile->role, path);
}

static void z6ii_load_persistent_input(Z6IIState *s)
{
    const char *path = z6ii_engine_getenv(s->engine, "Z6II_PERSISTENT_INPUT_FILE");
    const char *base_text = z6ii_engine_getenv(s->engine, "Z6II_PERSISTENT_INPUT_BASE");
    const char *expected = z6ii_engine_getenv(s->engine, "Z6II_PERSISTENT_INPUT_SHA256");
    if (!path && !base_text && !expected) { return; }
    if (!path || !base_text || !expected || strlen(expected) != 64 || base_text[0] == '-') {
        error_report("Persistent flash input requires file, base and SHA-256");
        exit(1);
    }
    char *end = NULL;
    errno = 0;
    uint64_t base = g_ascii_strtoull(base_text, &end, 0);
    g_autofree char *data = NULL;
    gsize length = 0;
    g_autoptr(GError) error = NULL;
    if (errno || !end || end == base_text || *end || base < s->virtual_persistent_base ||
        base >= 0x14000000 || !g_file_get_contents(path, &data, &length, &error) ||
        !length || length > 0x14000000 - base) {
        error_report("Persistent flash input has invalid address, length or file: %s",
                     error ? error->message : "outside unpopulated external flash");
        exit(1);
    }
    g_autofree char *actual = g_compute_checksum_for_data(G_CHECKSUM_SHA256,
                                                         (const guchar *)data, length);
    if (g_ascii_strcasecmp(actual, expected)) {
        error_report("Persistent flash input SHA-256 mismatch");
        exit(1);
    }
    /* Populate the power-on medium before either CPU starts. Original
     * loaders, checks and callbacks consume these bytes. Original writes
     * change only this per-run copy; the host source stays read-only. */
    memcpy(s->virtual_persistent_flash + base - s->virtual_persistent_base, data, length);
    s->supplied_persistent_source_start = base;
    s->supplied_persistent_source_end = base + length;
    fprintf(stderr, "Z6II_PERSISTENT_INPUT role=%s base=%08" PRIx64 " bytes=%zu "
            "sha256=%s host_source_modified=0 guest_RAM_patch=0 provenance_verified=0\n",
            s->profile->role, base, length, actual);
}

static bool z6ii_flash_query(Z6IIState *s, hwaddr addr, unsigned size,
                             bool write, uint64_t *value)
{
    bool query_port = addr >= 0x10000000 && addr + size <= 0x10020000;
    bool persistent = addr >= s->virtual_persistent_base && addr + size <= 0x14000000;
    if (!s->devices || !(query_port || persistent) ||
        !size || size > 4 || (write && (size != 2 || (addr & 1)))) { return false; }
    unsigned off = addr - 0x10000000;
    if (write) {
        /* Original RAM-residentc2b90158/c2b90682 performs AMD-style
         * unlock->identify, reset, and CFI queries.c2b90714 erases sectors;
         * c2b902ac programs halfwords. Only ephemeral erased-state storage
         * beyond the mapped original image is writable, without host backing.
         * Unknown command sequences and writes to original ROM stop. */
        if (s->flash_query_mode == 3 && persistent) {
            uint32_t i = addr - s->virtual_persistent_base;
            s->virtual_persistent_flash[i] &= *value;
            s->virtual_persistent_flash[i+1] &= *value >> 8;
            s->flash_query_mode = 0;
            if (!s->flash_program_halfwords++ || addr < s->flash_program_min) { s->flash_program_min = addr; }
            if (addr > s->flash_program_max) { s->flash_program_max = addr; }
        } else if (s->flash_query_unlock == 5 && *value == 0x30 && persistent) {
            uint32_t block = addr & ~0x1ffffU;
            if (block < s->virtual_persistent_base || (uint64_t)block + 0x20000 > 0x14000000) { return false; }
            memset(s->virtual_persistent_flash + block - s->virtual_persistent_base, 0xff, 0x20000);
            s->flash_query_mode = s->flash_query_unlock = 0;
            s->flash_erase_sectors++;
            fprintf(stderr, "Z6II_VIRTUAL_FLASH_ERASE sector=%08x bytes=20000 original_ROM_writes=0 host_backing=absent\n", block);
        } else if (*value == 0xf0 && (off == 0 || off == 0xaaa)) {
            s->flash_query_mode = s->flash_query_unlock = 0;
        } else if (off == 0xaaa && *value == 0xaa && !s->flash_query_unlock) {
            s->flash_query_unlock = 1;
        } else if (off == 0x554 && *value == 0x55 && s->flash_query_unlock == 1) {
            s->flash_query_unlock = 2;
        } else if (off == 0xaaa && *value == 0x80 && s->flash_query_unlock == 2) {
            s->flash_query_unlock = 3;
        } else if (off == 0xaaa && *value == 0xaa && s->flash_query_unlock == 3) {
            s->flash_query_unlock = 4;
        } else if (off == 0x554 && *value == 0x55 && s->flash_query_unlock == 4) {
            s->flash_query_unlock = 5;
        } else if (off == 0xaaa && *value == 0xa0 && s->flash_query_unlock == 2) {
            s->flash_query_mode = 3; s->flash_query_unlock = 0;
        } else if (off == 0xaaa && *value == 0x90 && s->flash_query_unlock == 2) {
            s->flash_query_mode = 1; s->flash_query_unlock = 0;
            fprintf(stderr, "Z6II_FLASH_QUERY mode=identify synthetic=1 virtual_persistent_only=1\n");
        } else if (off == 0xaa && *value == 0x98) {
            s->flash_query_mode = 2; s->flash_query_unlock = 0;
            fprintf(stderr, "Z6II_FLASH_QUERY mode=CFI synthetic_bytes=4000000 sector=20000 buffer_program=0\n");
        } else { return false; }
    } else if (persistent) {
        *value = 0;
        for (unsigned i = 0; i < size; i++) {
            *value |= (uint64_t)s->virtual_persistent_flash[addr - s->virtual_persistent_base + i] << (i * 8);
        }
    } else if (size == 1 && s->flash_query_mode == 0 &&
               addr >= 0x10000080 && addr + size <= 0x10000084) {
        /* Native1039ccc6 reads four byte-sized boot-version characters
         * outside the official EG extent. Unknown/erased0xff is explicit
         * input, not a reconstructed first-stage bootloader or version. */
        *value = 0xff;
        fprintf(stderr, "Z6II_MISSING_BOOT_VERSION address=%08x value=ff "
                "erased_input_hypothesis=1 bootloader_image=absent\n", (uint32_t)addr);
    } else if (size != 2) { return false; }
    else if (s->flash_query_mode == 1) {
        /* Generic diagnostic IDs, not an identification of Nikon hardware. */
        *value = off == 0 ? 1 : off == 2 ? 0x227e : 0;
    } else if (s->flash_query_mode == 2) {
        unsigned word = off / 2;
        *value = word == 0x10 ? 'Q' : word == 0x11 ? 'R' : word == 0x12 ? 'Y' :
                 word == 0x13 ? 2 : word == 0x27 ? 26 :
                 word == 0x28 ? 1 : word == 0x2c ? 1 :
                 word == 0x2d ? 0xff : word == 0x2e ? 1 :
                 word == 0x30 ? 2 : 0;
    } else { *value = 0xffff; }
    z6ii_trace(s, addr, size, write, *value);
    return true;
}

static MemTxResult z6ii_unmodeled(Z6IIState *s, hwaddr addr, unsigned size,
                                bool write, uint64_t value)
{
    if (!current_cpu) {
        return MEMTX_DECODE_ERROR;
    }
    if (!s->faulted) {
        s->faulted = true;
        fprintf(stderr, "Z6II_UNMODELED role=%s %c addr=%08" HWADDR_PRIx
                " size=%u value=%08" PRIx64 " cpu=%d pc=%08x virtual_ns=%" PRId64 "\n",
                s->profile->role, write ? 'W' : 'R', addr, size, value,
                current_cpu->cpu_index, ARM_CPU(current_cpu)->env.regs[15],
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
        CPUState *cs;
        CPU_FOREACH(cs) {
            ARMCPU *cpu = ARM_CPU(cs);
            fprintf(stderr, "Z6II_CPU role=%s cpu=%d cpsr=%08x ttbr0=%016" PRIx64
                    " sctlr=%016" PRIx64 " vbar=%016" PRIx64 "\n",
                    s->profile->role, cs->cpu_index, cpsr_read(&cpu->env),
                    cpu->env.cp15.ttbr0_el[1], cpu->env.cp15.sctlr_el[1],
                    cpu->env.cp15.vbar_el[1]);
            fprintf(stderr, "Z6II_CPU_SECURE_BANK role=%s cpu=%d ttbr0=%016" PRIx64
                    " sctlr=%016" PRIx64 " vbar=%016" PRIx64 "\n",
                    s->profile->role, cs->cpu_index, cpu->env.cp15.ttbr0_el[3],
                    cpu->env.cp15.sctlr_el[3], cpu->env.cp15.vbar_el[3]);
            for (unsigned r = 0; r < 16; r++) {
                fprintf(stderr, "Z6II_REG role=%s cpu=%d r%u=%08x\n",
                        s->profile->role, cs->cpu_index, r, cpu->env.regs[r]);
            }
        }
        /* Stop at the first missing device. A decode error is returned, never
         * an invented successful register transaction. */
        qemu_system_shutdown_request_with_code(SHUTDOWN_CAUSE_GUEST_PANIC, 2);
    }
    return MEMTX_DECODE_ERROR;
}

static int z6ii_early_index(hwaddr addr)
{
    switch (addr) {
    case 0x04264000: return 0;
    case 0x04264020: return 1;
    case 0x04281020: return 2;
    case 0x04281028: return 3;
    case 0x0428102c: return 4;
    case 0x04266000: return 5;
    case 0x04266008: return 6;
    case 0x0426600c: return 7;
    case 0x04266010: return 8;
    default: return -1;
    }
}

static int z6ii_startup_mapping_index(hwaddr addr)
{
    /* Exact literals/stores1002bdd0..1002be4c. Values are retained without
     * asserting a physical routing/DDR/peer side effect. No reads accepted. */
    static const uint32_t addresses[] = {
        0x20016020, 0x20016024, 0x20016028, 0x2001602c,
        0x20016030, 0x20016034, 0x20016038, 0x2001603c,
        0x20016d50, 0x20016d54, 0x20016d58, 0x20016d5c,
        0x20016000, 0x20016d40,
    };
    for (unsigned n = 0; n < ARRAY_SIZE(addresses); n++) {
        if (addr == addresses[n]) { return n; }
    }
    return -1;
}

static bool z6ii_ram_range(Z6IIState *s, uint32_t addr, uint64_t bytes)
{
    for (unsigned i = 0; i < s->profile->num_windows; i++) {
        const Z6IIRAMWindow *r = &s->profile->windows[i];
        if (addr >= r->base && (uint64_t)addr + bytes <= r->base + r->size) {
            return true;
        }
    }
    return false;
}

static void z6ii_shared_event_irq(Z6IIState *s)
{
    if (!s->automatic_peer_irq || !s->priv) { return; }
    bool level = (z6ii_coupled_status(s) & s->link_mask) != 0;
    qemu_set_irq(qdev_get_gpio_in(DEVICE(s->priv), 127 - 32), level);
    if (level != s->shared_irq_level) {
        fprintf(stderr, "Z6II_SHARED_EVENT_IRQ role=%s level=%u irq=127 "
                "polling_hypothesis_ns=%u virtual_ns=%" PRId64 "\n",
                s->profile->role, level, s->shared_event_poll_ns,
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
        s->shared_irq_level = level;
    }
}

static uint8_t *z6ii_parameter_reference_load(const char *path, size_t expected_size,
                                             const char *expected_sha256)
{
    gchar *data = NULL;
    gsize size = 0;
    if (!g_file_get_contents(path, &data, &size, NULL) || size != expected_size) {
        error_report("Parameter reference must be a complete recorded RAM body");
        exit(1);
    }
    g_autofree char *sha = g_compute_checksum_for_data(G_CHECKSUM_SHA256,
                                                      (const uint8_t *)data, size);
    if (strcmp(sha, expected_sha256)) {
        error_report("Read-only parameter reference does not match its recorded identity");
        exit(1);
    }
    return (uint8_t *)data;
}

static uint8_t *z6ii_parameter_source_snapshot(Z6IIState *s, const Z6IIParameterCopy *p)
{
    const uint8_t *pool = memory_region_get_ram_ptr(&s->observed_peer_parameter_buffer);
    return g_memdup2(pool + p->source - Z6II_PARAMETER_BUS_BASE, p->source_extent);
}

static bool z6ii_parameter_source_is_recorded(Z6IIState *s, const Z6IIParameterCopy *p,
                                             const uint8_t *snapshot, const char *phase)
{
    if (!s->parameter_require_recorded_body) { return true; }
    const char *expected = z6ii_parameter_recorded_body_sha256(p);
    g_autofree char *actual = expected ? g_compute_checksum_for_data(G_CHECKSUM_SHA256,
        snapshot, p->payload_bytes) : NULL;
    bool valid = expected && !strcmp(expected, actual);
    const char *contract = valid ? "recorded-complete" : "uncovered";
    const char *table_sha256 = p->source == UINT32_C(0x48068000) ?
        Z6II_PARAMETER_CONTRACT_REGION47_TABLE_SHA256 : Z6II_PARAMETER_CONTRACT_TABLE_SHA256;
    if (!valid && expected && p->source == UINT32_C(0x47f00000) &&
        z6ii_parameter_region50_stage8_matches(snapshot, s->parameter_reference50,
                                               p->payload_bytes)) {
        valid = true;
        contract = "ROM-region50-stage8-ranges-with-cold-zero-gaps";
    }
    if (!valid && expected && p->source == UINT32_C(0x48068000) &&
        z6ii_parameter_region47_stage4_stage8_matches(snapshot, s->parameter_reference47,
                                                      p->payload_bytes)) {
        valid = true;
        contract = "ROM-region47-stage4-and-stage8-ranges-with-cold-zero-gaps";
    }
    fprintf(stderr, "Z6II_PARAMETER_SOURCE_PROVENANCE role=%s phase=%s source=%08x "
            "bytes=%" PRIu64 " valid=%u expected_sha256=%s actual_sha256=%s contract=%s "
            "ROM_table_sha256=%s read_only_reference_guest_seed=0 source_snapshot=1 "
            "unknown_source_bytes_admitted=0 Flash_body_correspondence_verified=0 virtual_ns=%" PRId64 "\n",
            s->profile->role, phase, p->source, p->payload_bytes, valid,
            expected ? expected : "uncovered", actual ? actual : "uncovered", contract,
            table_sha256,
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    return valid;
}

static void z6ii_parameter_copy_complete(void *opaque)
{
    Z6IIState *s = opaque;
    if (!s->parameter_copy_pending) { return; }
    const Z6IIParameterCopy *p = &s->parameter_copy;
    g_autofree uint8_t *snapshot = z6ii_parameter_source_snapshot(s, p);
    if (!z6ii_parameter_source_is_recorded(s, p, snapshot, "before_copy")) {
        s->parameter_copy_pending = false;
        s->faulted = true;
        fprintf(stderr, "Z6II_PARAMETER_SOURCE_BOUNDARY role=%s source=%08x "
                "bytes=%" PRIu64 " phase=before_copy destination_unchanged=1 IRQ_not_raised=1\n",
                s->profile->role, p->source, p->payload_bytes);
        qemu_system_shutdown_request_with_code(SHUTDOWN_CAUSE_GUEST_PANIC, 2);
        return;
    }
    g_autofree uint8_t *readback = g_malloc(p->width);
    GChecksum *src_hash = g_checksum_new(G_CHECKSUM_SHA256);
    GChecksum *dst_hash = g_checksum_new(G_CHECKSUM_SHA256);
    for (uint32_t row = 0; row < p->rows; row++) {
        const uint8_t *bytes = snapshot + (uint64_t)row * p->source_stride;
        uint32_t destination = p->destination + (uint64_t)row * p->destination_stride;
        g_checksum_update(src_hash, bytes, p->width);
        z6ii_engine_write(s->engine, destination, bytes, p->width);
        z6ii_engine_read(s->engine, destination, readback, p->width);
        g_checksum_update(dst_hash, readback, p->width);
    }
    s->parameter_copy_pending = false;
    s->parameter_copy_seen = true;
    s->fill[2] |= 1;
    /* Original ISR1006AA32 consumes status+8 bit0 and mask+4 before
     * dispatching41050C01. Do not manufacture bit4 or stop-control state2. */
    qemu_set_irq(qdev_get_gpio_in(DEVICE(s->priv), 103 - 32),
                 (s->fill[2] & s->fill[1]) != 0);
    fprintf(stderr, "Z6II_PARAMETER_COPY_COMPLETE role=%s source=%08x destination=%08x "
            "bytes=%" PRIu64 " source_sha256=%s destination_sha256=%s "
            "status_bit0=1 status_bit4_supplied=0 stop_status2_supplied=0 "
            "same_verified_source_snapshot_copied=1 "
            "physical_mapping_verified=0 physical_timing_verified=0 virtual_ns=%" PRId64 "\n",
            s->profile->role, p->source, p->destination, p->payload_bytes,
            g_checksum_get_string(src_hash), g_checksum_get_string(dst_hash),
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    g_checksum_free(src_hash);
    g_checksum_free(dst_hash);
}

static bool z6ii_parameter_copy_submit(Z6IIState *s)
{
    Z6IIParameterCopy p;
    if (!s->observed_peer_parameter_enabled || strcmp(s->profile->role, "slave") ||
        s->parameter_copy_pending ||
        !z6ii_parameter_decode(s->fill, &p) ||
        !z6ii_ram_range(s, p.destination, p.destination_extent)) {
        return false;
    }
    if (s->parameter_require_recorded_body) {
        g_autofree uint8_t *snapshot = z6ii_parameter_source_snapshot(s, &p);
        if (!z6ii_parameter_source_is_recorded(s, &p, snapshot, "submit")) { return false; }
    }
    s->parameter_copy = p;
    s->parameter_copy_pending = true;
    if (!s->parameter_copy_timer) {
        s->parameter_copy_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                              z6ii_parameter_copy_complete, s);
    }
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    int64_t delay = 1000 + p.payload_bytes * 10;
    timer_mod(s->parameter_copy_timer, now + delay);
    fprintf(stderr, "Z6II_PARAMETER_COPY_SUBMIT role=%s source=%08x destination=%08x "
            "width=%u source_stride=%u destination_stride=%u rows=%u bytes=%" PRIu64 " "
            "flags=%08x mode=%08x completion_deadline_ns=%" PRId64 " "
            "virtual_ns=%" PRId64 " timing_hypothesis_ns_per_byte=10 "
            "host_payload_in_device_API=0 physical_mapping_verified=0 physical_timing_verified=0\n",
            s->profile->role, p.source, p.destination, p.width, p.source_stride,
            p.destination_stride, p.rows, p.payload_bytes, s->fill[5], s->fill[6],
            now + delay, now);
    return true;
}

static bool z6ii_parameter_copy_stop(Z6IIState *s)
{
    if (!s->observed_peer_parameter_enabled || strcmp(s->profile->role, "slave") ||
        (!s->parameter_copy_pending && !s->parameter_copy_seen)) {
        return false;
    }
    bool pending = s->parameter_copy_pending;
    if (pending) { timer_del(s->parameter_copy_timer); }
    s->parameter_copy_pending = false;
    /* Original 1006ACE6..1006AD00 writes start=0, polls low two bits for
     * stopped=2, then reenables the channel. Cancel this model's atomic DMA
     * before acknowledging: no RAM writes or completion can occur after
     * the stop. Existing +8 completion stays available for the ISR's W1C;
     * bit4 is an error indication, not an acknowledgement to manufacture.
     * Physical stop latency remains unidentified. */
    s->fill[4] = 2;
    fprintf(stderr, "Z6II_PARAMETER_COPY_STOP role=%s pending_transfer_canceled=%u "
            "bytes_not_transferred=%" PRIu64 " destination_unchanged_by_stop=1 "
            "completion_event_created=0 retained_status=%08x stop_state=2 "
            "physical_timing_verified=0 virtual_ns=%" PRId64 "\n",
            s->profile->role, pending, pending ? s->parameter_copy.payload_bytes : 0,
            s->fill[2], qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    return true;
}

static bool z6ii_fill1_access(Z6IIState *s, hwaddr addr, unsigned size,
                                   bool write, uint64_t *value)
{
    if (size != 4 || (addr & 3) || addr < 0x20070040 || addr >= 0x20070074) { return false; }
    unsigned index = (addr - 0x20070040) / 4;
    uint32_t *r = s->fill1;
    if (!write) { *value = r[index]; }
    else if (index == 2) { r[2] &= ~((uint32_t)*value & 0x11); }
    else {
        uint32_t mask = index == 0 || index == 4 ? 1 :
                        index == 1 || index == 5 ? 0x11 :
                        index == 6 ? 0x03ffffff :
                        index >= 7 && index <= 10 ? 0xffff : UINT32_MAX;
        if (index == 3 || (*value & ~((uint64_t)mask))) { return false; }
        r[index] = *value;
        if (index == 4 && *value == 1) {
            /* Original26 and29 descriptors establish flags10 byte copy,
             * source stride, width, destination stride and row count.
             * Support those fields over the observed shared sections;
             * other formats and bus windows remain unsupported. */
            uint32_t src = r[11], dst = r[12], width = r[8];
            fprintf(stderr, "Z6II_FILL1_SUBMIT role=%s control0=%08x flags=%08x mode=%08x "
                    "source=%08x destination=%08x source_stride=%u width=%u destination_stride=%u rows=%u\n",
                    s->profile->role, r[0], r[5], r[6], src, dst, r[7], width, r[9], r[10]);
            uint8_t *source = NULL;
            uint32_t source_base = 0;
            uint64_t source_bytes = 0;
            if (!strcmp(s->profile->role, "slave") && s->observed_peer_dma_enabled) {
                source = memory_region_get_ram_ptr(&s->observed_peer_dma_buffer);
                source_base = 0x28300000; source_bytes = 0x100000;
            } else if (!strcmp(s->profile->role, "master") && s->observed_slave_dma_enabled) {
                source = memory_region_get_ram_ptr(&s->observed_slave_dma_buffer);
                source_base = 0x46b00000; source_bytes = 0x300000;
            }
            uint64_t extent = (uint64_t)r[9] * r[10];
            uint64_t source_extent = r[10] ? (uint64_t)r[7] * (r[10] - 1) + width : 0;
            bool copy = source && r[5] == 0x10 && !r[6] && width && r[10] &&
                        r[7] >= width && r[9] >= width && extent <= 0x1000000 &&
                        src >= source_base && (uint64_t)src + source_extent <= source_base + source_bytes &&
                        z6ii_ram_range(s, dst, extent);
            bool zero = !strcmp(s->profile->role, "master") && r[5] == 1 &&
                        !r[6] && !r[7] && !src && width && width <= 0x4000 &&
                        r[9] >= width && r[10] && extent <= 0x1000000 &&
                        z6ii_ram_range(s, dst, extent);
            if (copy) {
                g_autofree uint8_t *staged = g_malloc(width);
                GChecksum *checksum = g_checksum_new(G_CHECKSUM_SHA256);
                for (uint32_t row = 0; row < r[10]; row++) {
                    memcpy(staged, source + src - source_base + (uint64_t)row * r[7], width);
                    g_checksum_update(checksum, staged, width);
                    z6ii_engine_write(s->engine, dst + row * r[9], staged, width);
                }
                fprintf(stderr, "Z6II_DMA_COPY role=%s channel=1 source_bus=%08x "
                        "destination=%08x width=%u source_stride=%u destination_stride=%u rows=%u "
                        "bytes=%" PRIx64 " original_descriptor=1 original_peer_shared_bytes=1 "
                        "gic=104 data_before_IRQ=1 bus_mapping_hypothesis=1 timing_hypothesis=immediate "
                        "transferred_source_sha256=%s\n", s->profile->role, src, dst, width, r[7], r[9], r[10],
                        (uint64_t)width * r[10], g_checksum_get_string(checksum));
                g_checksum_free(checksum);
            } else if (zero) {
                /* Same original rectangular-zero descriptor as channel0;
                 * each guest's channel1 owns independent registers and IRQ. */
                static const uint8_t zeros[0x4000];
                for (uint32_t row = 0; row < r[10]; row++) {
                    z6ii_engine_write(s->engine, dst + row * r[9], zeros, width);
                }
                fprintf(stderr, "Z6II_DMA_ZERO role=master channel=1 destination=%08x "
                        "width=%u stride=%u rows=%u bytes=%" PRIx64 " data_before_IRQ=1 gic=104 "
                        "original_descriptor=1 timing_hypothesis=immediate\n", dst, width, r[9], r[10], extent);
            } else { return false; }
            r[2] |= 1;
            r[4] = 2;
        } else if (index == 4 && *value == 0) {
            /*1006ACB4 polls the original low2 stopped-state bits for2. */
            r[4] = 2;
        }
    }
    /* Experiment27: original1006AB58 clears control0, then starts the
     * transfer without setting it. It cannot be an extra DMA/IRQ gate.
     * Keep its latch; native signal mask and GIC still gate completion. */
    qemu_set_irq(qdev_get_gpio_in(DEVICE(s->priv), 104 - 32), (r[2] & r[1]) != 0);
    z6ii_trace(s, addr, size, write, *value);
    return true;
}

static void z6ii_poll_shared_events(void *opaque)
{
    Z6IIState *s = opaque;
    z6ii_coupled_phy_step(s);
    z6ii_shared_event_irq(s);
    /* Functional transport polling, not recovered physical wire latency.
     * Legacy processes have separate QEMU clocks; the unified machine shares
     * QEMU_CLOCK_VIRTUAL while each chip retains its local counter state. */
    timer_mod(s->shared_event_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + s->shared_event_poll_ns);
}

static bool z6ii_protocol_access(Z6IIState *s, hwaddr addr, unsigned size,
                                bool write, uint64_t *value)
{
    if (!s->protocol_diagnostic || size != 4 || (addr & 3)) {
        return false;
    }
    if (s->coupled_notifications) {
        /* Original 102df730 reads status, acknowledges it, then passes
         * (IRQ127,status) to 1038a488; that callback tests bit15 and bank1.
         * V2 exposes only queue status. V3 can additionally expose explicit
         * two-ended startup/stop hypotheses; original ISR consumers remain
         * mandatory. Polling and link hypotheses do not model physical latency. */
        if (addr == 0x2013d020 && !write) {
            *value = z6ii_coupled_status(s);
        } else if (addr == 0x2013d024) {
            if (write) { s->link_mask = *value; }
            else { *value = s->link_mask; }
            z6ii_shared_event_irq(s);
        } else if (addr == 0x2013d028 && write) {
            /* Status acknowledgement is not the event-bank clear. The
             * original queue callback clears bank1 before draining RAM. */
            uint64_t allowed = 0x8000 | (s->coupled_phy ? 3 : 0) | (s->coupled_stop ? 0x20 : 0);
            if (*value & ~allowed) { return false; }
            if (s->coupled_phy) {
                if (s->coupled_stop && (*value & 0x20)) {
                    /* Published only by the original ISR's hardware ack,
                     * not by the producer or by a parent/worker RAM write. */
                    qatomic_store_release(&s->shared_event_words[Z6II_LINK_STOP_ACK + z6ii_link_slot(s)],
                                          s->coupled_stop_seen);
                }
                qatomic_fetch_and(&s->shared_event_words[Z6II_LINK_STATUS + z6ii_link_slot(s)],
                                  ~(uint32_t)*value);
            }
        } else {
            goto event_banks;
        }
        z6ii_trace(s, addr, size, write, *value);
        return true;
    }
event_banks:
    /* Original102e0702/102e11a0 program eight input pages, masks,
     * output pages and two auxiliary arrays, with a bank offset of8000.
     * This diagnostic board retains only the observed configuration words.
     * The peer queue uses either snapshots or explicit shared backing. */
    for (unsigned bank = 0; bank < 2; bank++) {
        hwaddr base = 0x201350b0 + bank * 0x8000;
        if (addr >= base && addr < base + 0xa0) {
            unsigned index = (addr - base) / 4;
            if (write) { s->diagnostic_translation[bank][index] = *value; }
            else { *value = s->diagnostic_translation[bank][index]; }
            z6ii_trace(s, addr, size, write, *value);
            return true;
        }
        /* 102e0812 writes +8 to set and +c to clear the bitmap read
         * at+4 by102e0830. Legacy pending state stays local. The explicit
         * notification model shares bank0 with peer bank1; optional GIC
         * polling remains a functional interconnect hypothesis. */
        base = 0x20136000 + bank * 0x8000;
        if (addr >= base && addr < base + 0x10) {
            unsigned off = addr - base;
            unsigned local = !strcmp(s->profile->role, "slave");
            uint32_t *pending = s->coupled_notifications ?
                                &s->shared_event_words[local ^ bank] :
                                &s->diagnostic_event_pending[bank];
            if (write) {
                if (off == 8) { qatomic_fetch_or(pending, (uint32_t)*value); }
                else if (off == 12) { qatomic_fetch_and(pending, ~(uint32_t)*value); }
                else { return false; }
                z6ii_shared_event_irq(s);
            } else {
                if (off == 0) { *value = 0; }
                else if (off == 4) { *value = qatomic_read(pending); }
                else { return false; }
            }
            z6ii_trace(s, addr, size, write, *value);
            return true;
        }
    }
    return false;
}

static bool z6ii_serial_access(Z6IIState *s, hwaddr addr, unsigned size,
                              bool write, uint64_t *value)
{
    if (addr < 0x2c0a0000 || addr >= 0x2c0a0b00 || size != 4 || (addr & 3)) {
        return false;
    }
    unsigned ch = (addr - 0x2c0a0000) / 0x100, off = addr & 0xff;
    /* mas10242d8e / sla1005ecee: disable, then read hardware FIFO depth.
     * Master capacities come from two equal C1.70 runtime-context reads and
     * original10242fb6. Slave capacities retain the earlier donor hypothesis.
     * Data/IRQ/active transfers remain strict until separately implemented. */
    if (off == 0x60) {
        if (write) {
            if (*value > 1) { return false; }
            s->serial_disabled[ch] = *value;
            s->serial_initialized[ch] = true;
        } else {
            if (!s->serial_initialized[ch]) { return false; }
            *value = s->serial_disabled[ch];
        }
    } else {
        if (!s->serial_initialized[ch]) { return false; }
        if (off == 0x48 && !write) {
            unsigned capacity = z6ii_fd_serial_fifo_capacity(!strcmp(s->profile->role, "master"), ch);
            if (!capacity) { return false; }
            *value = capacity;
        } else {
            uint32_t mask;
            switch (off) {
            case 0x08: case 0x18: case 0x1c: case 0x38: case 0x20:
                mask = 0xff; break;
            case 0x0c: mask = 0xc3f; break;
            case 0x10: mask = 0x1fbf; break;
            case 0x34: mask = UINT32_MAX; break;
            case 0x3c: mask = 0xf; break;
            case 0x4c: mask = 0xffff; break;
            case 0x64: mask = 0; break;
            default: return false;
            }
            if (write) {
                if (*value & ~(uint64_t)mask) { return false; }
                s->serial_config[ch][off / 4] = *value;
            } else { *value = s->serial_config[ch][off / 4]; }
        }
    }
    z6ii_trace(s, addr, size, write, *value);
    return true;
}

static void z6ii_clock_complete(void *opaque)
{
    Z6IIState *s = opaque;
    uint32_t bit = 1U << ((s->clock_transaction >> 12) & 7);
    if (s->clock_transaction & 0x100) { s->config[0x700c / 4] |= bit; }
    else { s->config[0x700c / 4] &= ~bit; }
    s->config[0x7004 / 4] |= 1;
    qemu_set_irq(qdev_get_gpio_in(DEVICE(s->priv), 250 - 32),
                 (s->config[0x7004 / 4] & s->config[0x7008 / 4] & 1) != 0);
    fprintf(stderr, "Z6II_CLOCK_COMPLETE role=%s transaction=%08x functional_latency_ns=1000\n",
            s->profile->role, s->clock_transaction);
}

static bool z6ii_setup_access(Z6IIState *s, hwaddr addr, unsigned size,
                             bool write, uint64_t *value)
{
    unsigned off = addr - 0x04280000, i = off / 4;
    /* Native master10200dac / slave100537a4 clock/pin configuration and
     * master10200e56 / slave100538xx trigger-poll-ack. Configuration is
     * stored only at these exact offsets, with reads requiring prior writes. */
    bool config = off <= 0x28 || off == 0x30 || off == 0x34 || off == 0x38 ||
                  (s->devices && off >= 0x64 && off <= 0x70) || /* master103c8494 indexed configuration */
                  (off >= 0x78 && off <= 0x88) ||
                  (off >= 0x1000 && off <= 0x1014) ||
                  (s->devices && (off == 0x1018 || off == 0x101c)) ||
                  off == 0x1024 || (off >= 0x1138 && off <= 0x114c) ||
                  (off >= 0x2000 && off <= 0x242c && (off & 0xff) < 0x30);
    bool gate = off == 0x1058 || off == 0x105c ||
                (s->devices && off == 0x1034); /* master103b2cd0 locked bit set/clear */
    bool clock = off == 0x7000 || off == 0x7004 || off == 0x7008 ||
                 off == 0x700c || off == 0x7010;
    if (addr < 0x04280000 || off >= 0x8000 || size != 4 || (off & 3) ||
        (!config && !clock && !gate)) { return false; }
    if (write) {
        if (off == 0x7004) { s->config[i] &= ~*value; }
        else { s->config[i] = *value; }
        s->config_written[i] = true;
        if (off == 0x7010 && *value == 0xa1) {
            s->clock_transaction = s->config[0x7000 / 4];
            timer_mod(s->clock_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 1000);
            s->config_written[0x7004 / 4] = true;
        }
        if (off == 0x7004 || off == 0x7008) {
            qemu_set_irq(qdev_get_gpio_in(DEVICE(s->priv), 250 - 32),
                         (s->config[0x7004 / 4] & s->config[0x7008 / 4] & 1) != 0);
        }
    } else {
        if (!s->config_written[i] && !gate && off != 0x34 && off != 0x38 &&
            off != 0x7008 && off != 0x700c) { return false; }
        *value = s->config[i];
    }
    z6ii_trace(s, addr, size, write, *value);
    return true;
}

static MemTxResult z6ii_read_inner(void *opaque, hwaddr addr, uint64_t *value,
                           unsigned size, MemTxAttrs attrs)
{
    Z6IIState *s = opaque;
    int index = z6ii_early_index(addr);
    *value = 0;
    if (z6ii_flash_query(s, addr, size, false, value)) { return MEMTX_OK; }
    if (z6ii_ipu2402_qemu_owns(s, addr)) {
        return z6ii_ipu2402_qemu_access(s, addr, size, false, value) ?
               MEMTX_OK : MEMTX_ERROR;
    }
    if (s->genadc_enabled && z6ii_genadc_owns(addr)) {
        return z6ii_genadc_qemu_access(s, addr, size, false, value) ? MEMTX_OK :
               z6ii_unmodeled(s, addr, size, false, *value);
    }
    if (z6ii_hdmi_i2c_reset_owns(s, addr)) {
        return z6ii_hdmi_i2c_reset_qemu_access(s, addr, size, false, value) ? MEMTX_OK :
               z6ii_unmodeled(s, addr, size, false, *value);
    }
    if (z6ii_hdmi_phy_i2c_owns(s, addr)) {
        return z6ii_hdmi_phy_i2c_access(s, addr, size, false, value) ? MEMTX_OK :
               z6ii_unmodeled(s, addr, size, false, *value);
    }
    if (z6ii_hdmi_phy_pll_owns(s, addr)) {
        return z6ii_hdmi_phy_pll_access(s, addr, size, false, value) ? MEMTX_OK :
               z6ii_unmodeled(s, addr, size, false, *value);
    }
    if (z6ii_hdmi_owns(s, addr)) {
        return z6ii_hdmi_access(s, addr, size, false, value) ? MEMTX_OK :
               z6ii_unmodeled(s, addr, size, false, *value);
    }
    if (s->devices && size == 1 && addr == 0x2016c010) {
        /* Original10481cba checks bit1;10481cfa checks bits4..7. An absent
         * device reports0, an explicit status hypothesis, not successful
         * data transfer or media readiness. */
        z6ii_trace(s, addr, size, false, 0);
        return MEMTX_OK;
    }
    if (s->devices && size == 4 && addr == 0x04280000) {
        /* Original103c841c splits this hardware-revision word into low6
         * bits and the upper nibble. Unmeasured revision0 is an explicit
         * assisted-board input, matching the donor diagnostic assumption. */
        z6ii_trace(s, addr, size, false, 0);
        return MEMTX_OK;
    }
    if (s->devices && size == 4 && (addr == 0x2402000c || addr == 0x24020014 ||
                                   addr == 0x2402001c || addr == 0x24020080)) {
        /* Original10242a70 drains pending input before IPU initialization.
         * Empty FIFO/status0; signature0 deliberately makes10242b08 return
         * -21 instead of claiming an implemented IPU processing engine. */
        *value = 0;
        z6ii_trace(s, addr, size, false, *value);
        return MEMTX_OK;
    }
    if (s->devices && size == 4 && addr == 0x04281034) {
        /* Original103b2cd0 reads/modifies this gate word under its native
         * lock. Synthetic reset0; configuration readback, no hardware effect. */
        *value = s->assisted_gate34;
        z6ii_trace(s, addr, size, false, *value);
        return MEMTX_OK;
    }
    if (s->devices && size == 4 && addr == 0x2c012000) {
        /* Native10387f2a/62/8c/9a/fcc uses this configuration word.
         * Explicit synthetic reset0 and RMW readback only. The status at
         * +8/+c, IRQ158 and all processing completions remain unmodelled. */
        *value = s->assisted_control2c012000;
        z6ii_trace(s, addr, size, false, *value);
        return MEMTX_OK;
    }
    if (s->devices && size == 4 && (addr == 0x2c012004 || addr == 0x2c012008)) {
        /* Native10388014/+50 stores callback/config at+4;10388018/+26
         * and10387fae perform RMW at+8. Reset0 and configuration readback
         * only: no conversion results at+10..30, status at+c, or IRQ158. */
        *value = addr == 0x2c012004 ? s->assisted_control2c012004
                                 : s->assisted_control2c012008;
        z6ii_trace(s, addr, size, false, *value);
        return MEMTX_OK;
    }
    if (z6ii_coupled_gpio_access(s, addr, size, false, value)) { return MEMTX_OK; }
    if (z6ii_slave_storage_access(s, addr, size, false, value)) { return MEMTX_OK; }
    if (s->fill1_enabled && addr >= 0x20070040 && addr < 0x20070074) {
        return z6ii_fill1_access(s, addr, size, false, value) ? MEMTX_OK :
               z6ii_unmodeled(s, addr, size, false, *value);
    }
    if (z6ii_slave_configuration_access(s, addr, size, false, value)) { return MEMTX_OK; }
    if (z6ii_link_access(s, addr, size, false, value)) { return MEMTX_OK; }
    if (s->devices && addr >= 0x12500000 && addr + size <= 0x14000000) {
        /* Original103c8480/10248328 consume absent persistent regions.
         * Erased flash is explicit synthetic input; no calibration supplied. */
        *value = size == 4 ? UINT32_MAX : ((UINT64_C(1) << (size * 8)) - 1);
        return MEMTX_OK;
    }
    if (s->devices && z6ii_fd_devices_access(s->devices, addr, size, false, value)) {
        if (s->devices->faulted) { return z6ii_unmodeled(s, addr, size, false, *value); }
        return MEMTX_OK;
    }
    if (size == 4 && (addr == 0x2c020000 || addr == 0x2c030000 || addr == 0x2c080000)) {
        unsigned n = addr == 0x2c020000 ? 0 : addr == 0x2c030000 ? 1 : 2;
        *value = s->peripheral_control[n];
        z6ii_trace(s, addr, size, false, *value);
        return MEMTX_OK;
    }
    if (z6ii_serial_access(s, addr, size, false, value)) { return MEMTX_OK; }
    if (z6ii_protocol_access(s, addr, size, false, value)) { return MEMTX_OK; }
    if (z6ii_platform_access(s, addr, size, false, value)) {
        return MEMTX_OK;
    } else if (index < 0 && z6ii_setup_access(s, addr, size, false, value)) {
        return MEMTX_OK;
    } else if (size == 4 && (addr == 0x04266008 || addr == 0x0426600c)) {
        uint64_t ticks = ((uint64_t)s->early[7] << 32) | s->early[6];
        if (s->early[5] & 1) {
            ticks += muldiv64(qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) - s->counter_epoch,
                              48000000, 1000000000);
        }
        *value = addr == 0x04266008 ? (uint32_t)ticks : ticks >> 32;
    } else if (size == 4 && (index >= 2 || index == 0)) {
        *value = s->early[index];
    } else if (addr >= 0x2c090000 && addr + size <= 0x2c090010 && size <= 2) {
        unsigned off = addr - 0x2c090000;
        for (unsigned n = 0; n < size; n++) {
            uint8_t v = s->uart[off + n];
            if (off + n == 3 && (s->uart[1] & 1)) {
                v |= 2; /* virtual serial sink consumed TX */
            }
            *value |= (uint64_t)v << (8 * n);
        }
    } else if (size == 4 && !(addr & 3) && addr >= 0x20070000 && addr < 0x20070034) {
        *value = s->fill[(addr - 0x20070000) / 4];
    } else if (size == 4 && (addr == 0x04280034 || addr == 0x04280038)) {
        *value = s->config[(addr - 0x04280000) / 4];
    } else if (size == 4 && !(addr & 3) && addr >= 0x20020000 && addr < 0x20060000 &&
               s->ddr_written[(addr - 0x20020000) / 4]) {
        *value = s->ddr_regs[(addr - 0x20020000) / 4];
    } else {
        return z6ii_unmodeled(s, addr, size, false, 0);
    }
    z6ii_trace(s, addr, size, false, *value);
    return MEMTX_OK;
}

static MemTxResult z6ii_write_inner(void *opaque, hwaddr addr, uint64_t value,
                            unsigned size, MemTxAttrs attrs)
{
    Z6IIState *s = opaque;
    int index = z6ii_early_index(addr);
    int mapping_index = z6ii_startup_mapping_index(addr);
    if (s->fill1_enabled && addr >= 0x20070040 && addr < 0x20070074) {
        return z6ii_fill1_access(s, addr, size, true, &value) ? MEMTX_OK :
               z6ii_unmodeled(s, addr, size, true, value);
    }
    if (z6ii_flash_query(s, addr, size, true, &value)) { return MEMTX_OK; }
    if (z6ii_ipu2402_qemu_owns(s, addr)) {
        return z6ii_ipu2402_qemu_access(s, addr, size, true, &value) ?
               MEMTX_OK : MEMTX_ERROR;
    }
    if (s->genadc_enabled && z6ii_genadc_owns(addr)) {
        return z6ii_genadc_qemu_access(s, addr, size, true, &value) ? MEMTX_OK :
               z6ii_unmodeled(s, addr, size, true, value);
    }
    if (z6ii_hdmi_i2c_reset_owns(s, addr)) {
        return z6ii_hdmi_i2c_reset_qemu_access(s, addr, size, true, &value) ? MEMTX_OK :
               z6ii_unmodeled(s, addr, size, true, value);
    }
    if (z6ii_hdmi_phy_i2c_owns(s, addr)) {
        return z6ii_hdmi_phy_i2c_access(s, addr, size, true, &value) ? MEMTX_OK :
               z6ii_unmodeled(s, addr, size, true, value);
    }
    if (z6ii_hdmi_phy_pll_owns(s, addr)) {
        return z6ii_hdmi_phy_pll_access(s, addr, size, true, &value) ? MEMTX_OK :
               z6ii_unmodeled(s, addr, size, true, value);
    }
    if (z6ii_hdmi_owns(s, addr)) {
        return z6ii_hdmi_access(s, addr, size, true, &value) ? MEMTX_OK :
               z6ii_unmodeled(s, addr, size, true, value);
    }
    if (s->devices && size == 4 && addr == 0x24020004) {
        /* Original10242822..2e transmits a3-word control message. An absent
         * IPU may consume input, but no completion is produced in this mode. */
        if (s->ipu_transmit_count >= 3) { return z6ii_unmodeled(s, addr, size, true, value); }
        s->ipu_transmit_words[s->ipu_transmit_count++] = value;
        z6ii_trace(s, addr, size, true, value);
        return MEMTX_OK;
    }
    if (s->devices && size == 4 && addr == 0x24020008 && value == 2 && s->ipu_transmit_count == 3) {
        fprintf(stderr, "Z6II_IPU_ABSENT_COMMAND id=%08x argument1=%08x argument2=%08x reply=absent pixels=0\n",
                s->ipu_transmit_words[0], s->ipu_transmit_words[1], s->ipu_transmit_words[2]);
        s->ipu_transmit_count = 0;
        return MEMTX_OK;
    }
    if (s->devices && size == 4 &&
        ((addr == 0x24020010 && value == 0x1d00) ||
         (addr == 0x24020020 && value == 0x7ffff) ||
         (addr == 0x24020018 && value == UINT32_MAX) ||
         (addr == 0x2402001c && (value == 0x3b || value == 4)))) {
        /* Original10242a80..aa0 empty-IPU initialization only. */
        s->assisted_ipu_config[(addr - 0x24020010) / 4] = value;
        z6ii_trace(s, addr, size, true, value);
        return MEMTX_OK;
    }
    if (s->devices && size == 4 && addr == 0x04281034) {
        s->assisted_gate34 = value;
        z6ii_trace(s, addr, size, true, value);
        return MEMTX_OK;
    }
    if (s->devices && size == 4 && addr == 0x2c012000) {
        /* Only configuration bits explicitly touched in the original
         * routines above. No readiness bit or interrupt is synthesized. */
        if (value & ~UINT64_C(0x57ff)) {
            return z6ii_unmodeled(s, addr, size, true, value);
        }
        s->assisted_control2c012000 = value;
        fprintf(stderr, "Z6II_CONTROL_CONFIG address=2c012000 value=%08x "
                "reset_zero_hypothesis=1 processing=absent completion_irq=0\n", (uint32_t)value);
        z6ii_trace(s, addr, size, true, value);
        return MEMTX_OK;
    }
    if (s->devices && size == 4 && (addr == 0x2c012004 || addr == 0x2c012008)) {
        if (addr == 0x2c012008 && (value & ~UINT64_C(0x1fff))) {
            return z6ii_unmodeled(s, addr, size, true, value);
        }
        if (addr == 0x2c012004) { s->assisted_control2c012004 = value; }
        else { s->assisted_control2c012008 = value; }
        fprintf(stderr, "Z6II_CONVERTER_CONFIG address=%08x value=%08x "
                "reset_zero_hypothesis=1 conversion=absent completion_irq=0\n",
                (uint32_t)addr, (uint32_t)value);
        z6ii_trace(s, addr, size, true, value);
        return MEMTX_OK;
    }
    if (z6ii_coupled_gpio_access(s, addr, size, true, &value)) { return MEMTX_OK; }
    if (z6ii_slave_storage_access(s, addr, size, true, &value)) { return MEMTX_OK; }
    if (z6ii_slave_configuration_access(s, addr, size, true, &value)) { return MEMTX_OK; }
    if (z6ii_link_access(s, addr, size, true, &value)) { return MEMTX_OK; }
    if (s->devices && z6ii_fd_devices_access(s->devices, addr, size, true, &value)) {
        if (s->devices->faulted) { return z6ii_unmodeled(s, addr, size, true, value); }
        return MEMTX_OK;
    }
    if (size == 4 && (addr == 0x2c020000 || addr == 0x2c030000 || addr == 0x2c080000)) {
        unsigned n = addr == 0x2c020000 ? 0 : addr == 0x2c030000 ? 1 : 2;
        /* mas102dee12/24 set enable bit28 and master gate bit31. */
        uint32_t mask = n == 2 ? 3 : 0x90000000;
        if (value & ~(uint64_t)mask) { return z6ii_unmodeled(s, addr, size, true, value); }
        s->peripheral_control[n] = value;
        z6ii_trace(s, addr, size, true, value);
        return MEMTX_OK;
    }
    if (z6ii_serial_access(s, addr, size, true, &value)) { return MEMTX_OK; }
    if (z6ii_protocol_access(s, addr, size, true, &value)) { return MEMTX_OK; }
    if (z6ii_platform_access(s, addr, size, true, &value)) {
        return MEMTX_OK;
    } else if (index < 0 && z6ii_setup_access(s, addr, size, true, &value)) {
        return MEMTX_OK;
    } else if (size == 4 && z6ii_ddr_write(s, addr, value)) {
        return MEMTX_OK;
    } else if (size == 4 && mapping_index >= 0) {
        s->startup_mapping[mapping_index] = value;
    } else if (size == 4 && index >= 0) {
        if (index == 8 && value != 48000000) {
            return z6ii_unmodeled(s, addr, size, true, value);
        }
        if (index == 5 && !(value & 1) && (s->early[5] & 1)) {
            uint64_t ticks = ((uint64_t)s->early[7] << 32) | s->early[6];
            ticks += muldiv64(qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) - s->counter_epoch,
                              48000000, 1000000000);
            s->early[6] = ticks; s->early[7] = ticks >> 32;
        }
        if (index == 5 && (value & 1) && !(s->early[5] & 1)) {
            s->counter_epoch = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
        }
        s->early[index] = value;
    } else if (addr >= 0x2c090000 && addr + size <= 0x2c090010 && size <= 2) {
        unsigned off = addr - 0x2c090000;
        for (unsigned n = 0; n < size; n++) {
            s->uart[off + n] = value >> (8 * n);
        }
        if (off == 4 && (s->uart[1] & 1)) {
            fprintf(stdout, "%c", (uint8_t)value); fflush(stdout);
        }
    } else if (size == 4 && !(addr & 3) && addr >= 0x20070000 && addr < 0x20070034) {
        unsigned off = addr - 0x20070000;
        if (off == 8) {
            s->fill[2] &= ~value;
        } else {
            s->fill[off / 4] = value;
            if (off == 0x10 && (value & 1)) {
                if (z6ii_parameter_copy_submit(s)) {
                    z6ii_trace(s, addr, size, true, value);
                    return MEMTX_OK;
                }
                uint32_t base = s->fill[12], width = s->fill[8] & 0xffff;
                uint32_t stride = s->fill[9] & 0xffff, rows = s->fill[10];
                static const uint8_t zeros[0x4000];
                uint64_t bytes = (uint64_t)rows * stride;
                bool bss = width == sizeof(zeros) && stride == width;
                /* Original102de4ec..5ca programs a rectangular GUI clear:
                 * observed width/stride0xb40 with480 rows and0xf00 with540
                 * rows,zero fill and RAM destination. The driver stores
                 * width and stride as independent16-bit fields. Support
                 * this zero-fill operation for a fully backed RAM extent.
                 * Original102de3ca registers103(dec) on102de382; its ISR
                 * consumes+8 and dispatches41050c01. Perform the actual
                 * RAM clear before signalling completion; no menu pixels
                 * or original state words are manufactured by this model. */
                bool gui = s->devices && !strcmp(s->profile->role, "master") &&
                           width && width <= sizeof(zeros) && stride >= width &&
                           !s->fill[7] && !s->fill[11] && s->fill[5] == 1;
                if ((!bss && !gui) || !rows ||
                    !z6ii_ram_range(s, base, bytes) || s->fill[6] || !(s->fill[5] & 1)) {
                    return z6ii_unmodeled(s, addr, size, true, value);
                }
                for (uint32_t n = 0; n < rows; n++) {
                    z6ii_engine_write(s->engine, base + n * stride, zeros, width);
                }
                s->fill[2] |= 1;
                if (s->devices) { s->fill[4] = 2; }
                fprintf(stderr, "Z6II_DMA_ZERO role=%s base=%08x bytes=%" PRIx64
                        " width=%u rows=%u GUI=%u functional=1 completion_hypothesis=1\n",
                        s->profile->role, base, bytes, width, rows, gui);
            } else if (off == 0x10 && !value) {
                if (z6ii_parameter_copy_stop(s)) {
                    z6ii_trace(s, addr, size, true, value);
                    return MEMTX_OK;
                }
                /* Original102de636 polls low2 bits for the stopped state2. */
                if (s->devices) { s->fill[4] = 2; }
            }
        }
        if (s->devices) {
            qemu_set_irq(qdev_get_gpio_in(DEVICE(s->priv), 103 - 32),
                         (s->fill[2] & s->fill[1]) != 0);
        }
    } else if (size == 4 && !(addr & 3) &&
               (addr == 0x04280030 || addr == 0x04280034 || addr == 0x04280038 ||
                (addr >= 0x04282000 && addr <= 0x0428242c && (addr & 0xff) < 0x30))) {
        /* Native table loop master10200ef8..f28 / slave10053bd8..c08:
         *12 entries x5 words at+000/+100/+200/+300/+400. Pin/config
         * stores retained; electrical behavior is not claimed. */
        unsigned n = (addr - 0x04280000) / 4;
        s->config[n] = value;
        s->config_written[n] = true;
    } else if (size == 4 &&
               ((addr == 0x0426f004 && value == 0) ||
                ((addr == 0x0426f000 || addr == 0x0426f010) && value == 0xff))) {
        /* Original mas10388142 / sla10066c0e: initialize GPIO IRQ
         * control=0, acknowledge ff, mask ff. No input edges synthesized. */
        unsigned n = addr == 0x0426f004 ? 0 : addr == 0x0426f000 ? 1 : 2;
        s->gpio_init[n] = value;
    } else {
        return z6ii_unmodeled(s, addr, size, true, value);
    }
    z6ii_trace(s, addr, size, true, value);
    return MEMTX_OK;
}

static void z6ii_boot_i2c_board_snapshot(Z6IIState *s, hwaddr addr, unsigned size,
    bool write, uint64_t value, MemTxResult result)
{
    if (addr < 0x2c018000 || addr >= 0x2c01c000) { return; }
    unsigned ch = (addr - 0x2c018000) / 0x1000;
    Z6IIFunctionalDevices *d = s->devices;
    z6ii_boot_i2c_mmio_observe(current_cpu ? &ARM_CPU(current_cpu)->env : NULL,
        addr, size, write, value, result, d ? d->i2c_regs[ch] : NULL,
        d ? d->i2c_tx[ch] : NULL, d ? d->i2c_tx_count[ch] : 0,
        d && d->i2c_pending[ch], d ? d->i2c_deadline[ch] : -1,
        d ? d->i2c_generation[ch] : 0);
}


/* Default-off LCD adapter evidence. Runs after the actual dispatcher access;
 * does not issue another load/store or alter device state. Board MMIO runs
 * under the BQL. Counters cover the whole process, including board resets. */
#define Z6II_LCD98_TRACE_CAPACITY 65536
static GSList *z6ii_lcd98_trace_boards;

static void z6ii_lcd98_trace_end(void)
{
    for (GSList *item = z6ii_lcd98_trace_boards; item; item = item->next) {
        Z6IIState *s = item->data;
        if (fprintf(stderr, "Z6II_LCD98_TRACE_END role=%s attempts=%" PRIu64
            " written=%" PRIu64 " overflow=%" PRIu64
            " incomplete=%" PRIu64 " guest_writes=0\n",
            s->profile->role, s->lcd98_trace_attempts, s->lcd98_trace_written,
            s->lcd98_trace_attempts > Z6II_LCD98_TRACE_CAPACITY ?
                s->lcd98_trace_attempts - Z6II_LCD98_TRACE_CAPACITY : 0,
            s->lcd98_trace_incomplete) < 0) {
            s->lcd98_trace_incomplete++;
        }
    }
}

static void z6ii_lcd98_trace(Z6IIState *s, hwaddr addr, unsigned size, bool write,
                            uint64_t value, MemTxResult result)
{
    if (addr < 0x20140000u || addr >= 0x2014c000u) {
        return;
    }
    const char *enable = z6ii_engine_getenv(s->engine, "Z6II_LCD98_TRACE");
    if (!enable || strcmp(enable, "1")) { return; }
    if (!s->lcd98_trace_initialized) {
        s->lcd98_trace_initialized = true;
        if (!z6ii_lcd98_trace_boards && atexit(z6ii_lcd98_trace_end)) {
            error_report("LCD98 trace cannot register its final record");
            exit(1);
        }
        z6ii_lcd98_trace_boards = g_slist_append(z6ii_lcd98_trace_boards, s);
    }
    uint64_t index = s->lcd98_trace_attempts++;
    if (index >= Z6II_LCD98_TRACE_CAPACITY) {
        return;
    }
    if (fprintf(stderr, "Z6II_LCD98_MMIO role=%s index=%" PRIu64
            " addr=%08" HWADDR_PRIx " size=%u write=%u value=%" PRIx64
            " result=%u\n", s->profile->role, index, addr, size, write, value,
            (unsigned)result) < 0) {
        s->lcd98_trace_incomplete++;
    } else {
        s->lcd98_trace_written++;
    }
}

/* Trace the actual result of each selected access, including decode errors.
 * The observer is inert unless explicitly enabled; guest behavior is retained. */
static MemTxResult z6ii_read(void *opaque, hwaddr addr, uint64_t *value,
                             unsigned size, MemTxAttrs attrs)
{
    Z6IIState *s = opaque;
    MemTxResult result = z6ii_read_inner(opaque, addr, value, size, attrs);
    z6ii_boot_mmio_observe(current_cpu ? &ARM_CPU(current_cpu)->env : NULL,
                          addr, size, false, *value, result, s->ipu_transmit_words);
    z6ii_boot_i2c_board_snapshot(s, addr, size, false, *value, result);
    z6ii_lcd98_trace(s, addr, size, false, (result == MEMTX_OK ? *value : 0), result);
    z6ii_capseq_gpio_mmio_trace(s->engine, addr, size, false,
                               result == MEMTX_OK ? *value : 0, result);
    return result;
}

static MemTxResult z6ii_write(void *opaque, hwaddr addr, uint64_t value,
                              unsigned size, MemTxAttrs attrs)
{
    Z6IIState *s = opaque;
    MemTxResult result = z6ii_write_inner(opaque, addr, value, size, attrs);
    z6ii_boot_mmio_observe(current_cpu ? &ARM_CPU(current_cpu)->env : NULL,
                          addr, size, true, value, result, s->ipu_transmit_words);
    z6ii_boot_i2c_board_snapshot(s, addr, size, true, value, result);
    z6ii_lcd98_trace(s, addr, size, true, value, result);
    z6ii_capseq_gpio_mmio_trace(s->engine, addr, size, true, value, result);
    return result;
}

static const MemoryRegionOps z6ii_ops = {
    .read_with_attrs = z6ii_read, .write_with_attrs = z6ii_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1, .valid.max_access_size = 4,
    .impl.min_access_size = 1, .impl.max_access_size = 4,
};

/* Run-local MAP_SHARED transport. The header and the 64 KiB strides are
 * deliberately outside guest-visible queue RAM. No register, configuration,
 * flash, ready bit or interrupt is inferred from this host transport. */
static int z6ii_open_queue_backing(Z6IIState *s, const Z6IIProfile *profile, bool notifications, unsigned flags)
{
    const char *path = z6ii_engine_getenv(s->engine, "Z6II_QUEUE_BACKING");
    const char *role = z6ii_engine_getenv(s->engine, "Z6II_QUEUE_ROLE");
    struct stat st;
    uint8_t header[196];
    unsigned version = flags ? 3 : notifications ? 2 : 1;
    const char *magic = flags ? "Z6II-QUEUE-v3\0\0\0" :
                        notifications ? "Z6II-QUEUE-v2\0\0\0" : "Z6II-QUEUE-v1\0\0\0";
    int fd;
    if (!path || path[0] != '/' || !role || strcmp(role, profile->role)) {
        error_report("Z6II coupled queues require an absolute backing path and matching role");
        exit(1);
    }
    fd = open(path, O_RDWR | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        st.st_uid != getuid() || (st.st_mode & 0777) != 0600 ||
        st.st_nlink != 1 || st.st_size != (notifications ? 0x40000 : 0x30000) ||
        pread(fd, header, sizeof(header), 0) != sizeof(header) ||
        memcmp(header, magic, 16) || ldl_le_p(header + 16) != version ||
        (flags && ldl_le_p(header + 192) != flags) || ldl_le_p(header + 20) != 0xd000 ||
        ldl_le_p(header + 24) != 0x10000 || ldl_le_p(header + 28) != 2 ||
        memcmp(header + 32, z6ii_master_profile.sha256, 64) ||
        memcmp(header + 96, z6ii_slave_profile.sha256, 64) ||
        (0x10000 % getpagesize())) {
        error_report("Z6II coupled queue backing identity/layout/ownership mismatch");
        exit(1);
    }
    return fd;
}

static void z6ii_shared_queue(Z6IIEngineContext *engine, MemoryRegion *mr,
                              const char *name, int fd,
                              unsigned slot)
{
    int owned = dup(fd);
    if (owned < 0) {
        error_report("Cannot duplicate Z6II queue backing descriptor");
        exit(1);
    }
    z6ii_engine_shared_ram(engine, mr, name, 0xd000,
                            owned, (slot + 1) * 0x10000);
}

static void z6ii_init_engine(MachineState *machine, const Z6IIProfile *profile,
                             bool protocol_diagnostic, bool functional_devices,
                             bool coupled_queues, bool coupled_notifications,
                             Z6IIEngineContext *engine, const char *firmware)
{
    Z6IIState *s = g_new0(Z6IIState, 1);
    s->profile = profile;
    g_autofree char *z6ii_shared_event_control_name = g_strdup_printf("z6ii-shared-event-control-%s", profile->role);
    g_autofree char *z6ii_diagnostic_peer_status_name = g_strdup_printf("z6ii-diagnostic-peer-status-%s", profile->role);
    g_autofree char *z6ii_diagnostic_peer_snapshot_name = g_strdup_printf("z6ii-diagnostic-peer-snapshot-%s", profile->role);
    g_autofree char *z6ii_coupled_peer_queue_name = g_strdup_printf("z6ii-coupled-peer-queue-%s", profile->role);
    g_autofree char *z6ii_observed_master_parameter_sections_name = g_strdup_printf("z6ii-observed-master-parameter-sections-%s", profile->role);
    g_autofree char *z6ii_observed_slave_dma_buffer_sections_name = g_strdup_printf("z6ii-observed-slave-DMA-buffer-sections-%s", profile->role);
    g_autofree char *z6ii_observed_master_dma_source_section_name = g_strdup_printf("z6ii-observed-master-DMA-source-section-%s", profile->role);
    g_autofree char *z6ii_observed_master_data_section_name = g_strdup_printf("z6ii-observed-master-data-section-%s", profile->role);
    g_autofree char *z6ii_observed_master_buffer_section_name = g_strdup_printf("z6ii-observed-master-buffer-section-%s", profile->role);
    s->engine = engine;
    engine->board = s;
    fprintf(stderr, "Z6II_SERIAL_CAPACITY role=%s source=%s transfers=absent\n", profile->role,
            !strcmp(profile->role, "master") ? "C170_master_live_RAM" : "slave_donor_hypothesis");
    s->protocol_diagnostic = protocol_diagnostic;
    s->coupled_queues = coupled_queues;
    s->coupled_notifications = coupled_notifications;
    const char *control300 = z6ii_engine_getenv(s->engine, "Z6II_SLAVE_2B20_CONTROL_LATCH");
    if (control300 && (strcmp(control300, "1") || !functional_devices ||
                       !coupled_queues || strcmp(profile->role, "slave"))) {
        error_report("Slave2B20 control-latch hypothesis requires the explicit original slave boot board and value1");
        exit(1);
    }
    s->slave_2b20_control_latch = control300 != NULL;
    const char *pipeline = z6ii_engine_getenv(s->engine, "Z6II_SLAVE_PIPELINE_MODE");
    if (pipeline && ((!strcmp(pipeline, "config") || !strcmp(pipeline, "complete")) ?
                     (!functional_devices || !coupled_queues || strcmp(profile->role, "slave") || !control300) : true)) {
        error_report("Slave pipeline hypothesis requires original coupled slave, control latch, and config/complete mode");
        exit(1);
    }
    s->slave_pipeline_configuration = pipeline != NULL;
    s->slave_pipeline_completion = pipeline && !strcmp(pipeline, "complete");
    const char *access_line = z6ii_engine_getenv(s->engine, "Z6II_SLAVE_ACCESS_READY_LINE");
    if (access_line && (strcmp(access_line, "1") || !s->slave_pipeline_completion)) {
        error_report("Slave access-ready line hypothesis requires complete pipeline mode and value1");
        exit(1);
    }
    s->slave_pipeline_access_ready_line = access_line != NULL;
    const char *storage = z6ii_engine_getenv(s->engine, "Z6II_SLAVE_SDHCI_MODE");
    if (storage && ((strcmp(storage, "no-card") && strcmp(storage, "empty-card") &&
                     strcmp(storage, "fat-card")) ||
                    !s->slave_pipeline_access_ready_line)) {
        error_report("Slave SDHCI hypothesis requires complete original slave bridge and explicit card mode");
        exit(1);
    }
    s->slave_sdhci_enabled = storage != NULL;
    s->slave_sdhci_virtual_cards = storage && strcmp(storage, "no-card");
    s->slave_sdhci_formatted_cards = storage && !strcmp(storage, "fat-card");
    const char *fill1 = z6ii_engine_getenv(s->engine, "Z6II_SLAVE_FILL_CHANNEL1");
    if (fill1 && (strcmp(fill1, "1") || !s->slave_sdhci_enabled ||
                  strcmp(profile->role, "slave"))) {
        error_report("Slave fill channel1 requires the explicit original slave storage model and value1");
        exit(1);
    }
    const char *master_fill1 = z6ii_engine_getenv(s->engine, "Z6II_MASTER_FILL_CHANNEL1");
    if (master_fill1 && (strcmp(master_fill1, "1") || !functional_devices ||
                         !coupled_queues || strcmp(profile->role, "master"))) {
        error_report("Master fill channel1 requires the explicit original integrated master and value1");
        exit(1);
    }
    s->fill1_enabled = fill1 != NULL || master_fill1 != NULL;
    s->fill1[0] = 1; /* Previous observed channel1 reset contract. */
    if (pipeline) {
        s->slave_pipeline_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, z6ii_slave_pipeline_complete, s);
        fprintf(stderr, "Z6II_SLAVE_PIPELINE_PROFILE mode=%s reset_zero_hypothesis=1 "
                "completion_delay_ns=1000000 physical_semantics_verified=0 "
                "frames_generated=0 guest_RAM_readiness_written=0\n", pipeline);
    }
    if (s->slave_2b20_control_latch) {
        fprintf(stderr, "Z6II_SLAVE_CONTROL300_PROFILE enabled=1 addr=2b200300 "
                "reset_zero_hypothesis=1 bit0_latch_hypothesis=1 "
                "physical_semantics_verified=0 ready_or_result_flags_supplied=0\n");
    }
    const char *auto_irq = z6ii_engine_getenv(s->engine, "Z6II_QUEUE_AUTO_IRQ");
    if (auto_irq && (!coupled_notifications || strcmp(auto_irq, "1"))) {
        error_report("Automatic queue IRQ requires explicit notification model and value 1");
        exit(1);
    }
    s->automatic_peer_irq = auto_irq != NULL;
    const char *poll_ns = z6ii_engine_getenv(s->engine, "Z6II_SHARED_EVENT_POLL_NS");
    if (poll_ns && (!s->automatic_peer_irq ||
                   (strcmp(poll_ns, "1000") && strcmp(poll_ns, "10000") && strcmp(poll_ns, "100000")))) {
        error_report("Shared-event poll hypothesis requires automatic IRQ and1000/10000/100000ns");
        exit(1);
    }
    s->shared_event_poll_ns = poll_ns ? strtoul(poll_ns, NULL, 10) : 1000;
    const char *link_config = z6ii_engine_getenv(s->engine, "Z6II_LINK_CONFIGURATION");
    if (link_config && (!coupled_queues || strcmp(link_config, "1"))) {
        error_report("Link configuration latches require explicit coupled model and value 1");
        exit(1);
    }
    s->coupled_link_configuration = link_config != NULL;
    const char *gpio = z6ii_engine_getenv(s->engine, "Z6II_COUPLED_GPIO");
    const char *wire = z6ii_engine_getenv(s->engine, "Z6II_GPIO_CONNECTION");
    const char *phy = z6ii_engine_getenv(s->engine, "Z6II_COUPLED_PHY");
    const char *stop = z6ii_engine_getenv(s->engine, "Z6II_COUPLED_STOP");
    const char *lanes = z6ii_engine_getenv(s->engine, "Z6II_COUPLED_LANES");
    if ((gpio && (!coupled_notifications || !link_config || strcmp(gpio, "1"))) ||
        (wire && (!gpio || strcmp(wire, "1"))) ||
        (phy && (!wire || !auto_irq || strcmp(phy, "1"))) ||
        (stop && (!phy || strcmp(stop, "1"))) ||
        (lanes && (!stop || strcmp(lanes, "1")))) {
        error_report("Coupled GPIO/wire/PHY hypotheses require explicit prerequisites and value 1");
        exit(1);
    }
    s->coupled_gpio = gpio != NULL;
    s->gpio_connection = wire != NULL;
    s->coupled_phy = phy != NULL;
    s->coupled_stop = stop != NULL;
    s->coupled_lanes = lanes != NULL;
    unsigned flags = s->coupled_gpio | (s->gpio_connection << 1) | (s->coupled_phy << 2) |
                     (s->coupled_stop << 3) | (s->coupled_lanes << 4);
    int queue_fd = -1;
    unsigned local_slot = !strcmp(profile->role, "slave");
    if (coupled_queues) {
        queue_fd = z6ii_open_queue_backing(s, profile, coupled_notifications, flags);
        if (flags) {
            fprintf(stderr, "Z6II_COUPLED_LINK_HYPOTHESES role=%s V3_flags=%u "
                    "GPIO_write_enable=%u slave_pin10_to_master_pin3=%u two_ended_PHY=%u stop_notification=%u lane_idle=%u "
                    "physical_wiring_verified=0 physical_timing_known=0\n", profile->role,
                    flags, s->coupled_gpio, s->gpio_connection, s->coupled_phy, s->coupled_stop, s->coupled_lanes);
        }
        if (s->coupled_link_configuration) {
            fprintf(stderr, "Z6II_LINK_CONFIGURATION role=%s observed_register_latches=1 "
                    "read_requires_prior_write=1 scripted_peer=0 ready_assumed=0 PHY_emulated=0\n", profile->role);
        }
    } else if (z6ii_engine_getenv(s->engine, "Z6II_QUEUE_BACKING") || z6ii_engine_getenv(s->engine, "Z6II_QUEUE_ROLE")) {
        error_report("Queue backing is restricted to explicit coupled machine models");
        exit(1);
    }
    s->clock_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, z6ii_clock_complete, s);
    s->platform_profile = true;
    s->platform_regs[0x38 / 4] = 1;
    s->platform_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, z6ii_platform_complete, s);
    fprintf(stderr, "Z6II_PLATFORM_HYPOTHESIS role=%s initial=synthetic_zero ready_bit=1 latency_ns=1000\n",
            profile->role);
    if (!firmware) {
        error_report("Z6II probe requires the exact extracted C1.70 EG with its original CRC");
        exit(1);
    }
    g_autofree gchar *data = NULL;
    gsize length;
    g_autoptr(GError) error = NULL;
    if (!g_file_get_contents(firmware, &data, &length, &error)) {
        error_report("Cannot load Z6II input: %s", error->message); exit(1);
    }
    g_autofree char *sha = g_compute_checksum_for_data(G_CHECKSUM_SHA256,
                                                      (const guchar *)data, length);
    if (length != profile->bytes || strcmp(sha, profile->sha256)) {
        error_report("Z6II %s C1.70 input identity mismatch", profile->role); exit(1);
    }
    MemoryRegion *sysmem = engine->memory;
    memory_region_init_io(&s->unknown, OBJECT(machine), &z6ii_ops, s,
                          "z6ii-strict-unmodeled", UINT64_C(0x100000000));
    memory_region_add_subregion_overlap(sysmem, 0, &s->unknown, -100);
    g_autofree char *rom_name = g_strdup_printf("z6ii-%s-eg-rom", profile->role);
    memory_region_init_rom(&s->rom, NULL, rom_name, profile->rom_size, &error_fatal);
    memory_region_add_subregion(sysmem, 0x10020000, &s->rom);
    rom_add_blob_fixed_as(rom_name, data, length, 0x10020000, &engine->as);
    engine->rom = &s->rom;
    z6ii_boot_bind_original_rom(engine, &s->rom, length, sha);
    for (unsigned i = 0; i < profile->num_windows; i++) {
        const Z6IIRAMWindow *r = &profile->windows[i];
        g_autofree char *name = g_strdup_printf("z6ii-%s-ram-%u", profile->role, i);
        if (coupled_queues && r->base == profile->local_queue) {
            assert(r->size == 0xd000);
            z6ii_shared_queue(engine, &s->ram[i], name, queue_fd, local_slot);
        } else {
            memory_region_init_ram(&s->ram[i], NULL, name, r->size, &error_fatal);
        }
        memory_region_add_subregion(sysmem, r->base, &s->ram[i]);
    }
    const char *peer_buffer = z6ii_engine_getenv(s->engine, "Z6II_PEER_BUFFER_SECTION");
    if (peer_buffer) {
        /* Natural version exchange (wire bytes05/02) publishes C290D080. The slave's
         * original page table maps42900000 as a1MiB identity section and
         * its original copy code reads4290D080. Model only that observed
         * section; the host neither copies a payload nor edits guest state.
         * No other peer windows or cache/timing behavior is implied. */
        if (!coupled_queues || !functional_devices) {
            error_report("Observed peer buffer requires integrated two-ended functional model");
            exit(1);
        }
        int fd = open(peer_buffer, O_RDWR);
        struct stat info;
        if (fd < 0 || fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_size != 0x100000) {
            error_report("Observed peer buffer must be a run-local1MiB RAM file");
            exit(1);
        }
        z6ii_engine_shared_ram(engine, &s->observed_peer_buffer,
                z6ii_observed_master_buffer_section_name, 0x100000, fd, 0);
        uint32_t address = !strcmp(profile->role, "master") ? 0xC2900000 : 0x42900000;
        memory_region_add_subregion_overlap(sysmem, address, &s->observed_peer_buffer, 1);
        fprintf(stderr, "Z6II_PEER_BUFFER_SECTION role=%s address=%08x bytes=100000 "
                "master_original_RAM=C2900000 slave_aperture=42900000 host_payload_copies=0 "
                "single_observed_section_only=1 physical_mapping_verified=0 cache_coherence_emulated=0\n",
                profile->role, address);
    }
    const char *peer_data = z6ii_engine_getenv(s->engine, "Z6II_PEER_DATA_SECTION");
    if (peer_data) {
        /* cold123 Master ring slot37 (type38h/channel9/sequence37)
         * retains C2D02980. Original Slave10167444 LDRD reads42D02980
         * under its sampled identity descriptor42D14422. Original
         * domain0 and both ROM L1 tables bind C2C/C2D to42C/42D.
         * Share only those two sections; no payload or result copy. */
        if (!peer_buffer || !coupled_queues || !functional_devices) {
            error_report("Observed peer data requires the integrated peer-buffer model");
            exit(1);
        }
        int fd = open(peer_data, O_RDWR);
        struct stat info;
        if (fd < 0 || fstat(fd, &info) || !S_ISREG(info.st_mode) ||
            info.st_size != Z6II_PEER_DATA_SECTION_BYTES) {
            error_report("Observed peer data must match the two-section RAM extent");
            exit(1);
        }
        z6ii_engine_shared_ram(engine, &s->observed_peer_data_buffer,
                z6ii_observed_master_data_section_name, Z6II_PEER_DATA_SECTION_BYTES,
                fd, 0);
        uint32_t address = !strcmp(profile->role, "master") ? 0xC2C00000 : 0x42C00000;
        memory_region_add_subregion_overlap(sysmem, address, &s->observed_peer_data_buffer, 1);
        fprintf(stderr, "Z6II_PEER_DATA_SECTION role=%s address=%08x bytes=%x "
                "master_original_RAM=C2C00000 slave_aperture=42C00000 host_payload_copies=0 "
                "observed_sections=2 CPU_mapping_basis=original_domain0_ROM_L1_and_cold123_L1 "
                "physical_mapping_verified=0 cache_coherence_emulated=0\n",
                profile->role, address, Z6II_PEER_DATA_SECTION_BYTES);
    }
    const char *peer_dma = z6ii_engine_getenv(s->engine, "Z6II_PEER_DMA_SECTION");
    const char *peer_parameter = z6ii_engine_getenv(s->engine, "Z6II_PEER_PARAMETER_SECTION");
    if (peer_dma) {
        if (!peer_data || !coupled_queues || !functional_devices) {
            error_report("Observed peer DMA source requires integrated peer data sections");
            exit(1);
        }
        bool shared_pool = peer_parameter && !strcmp(peer_dma, peer_parameter);
        if (peer_parameter && !shared_pool) {
            error_report("Overlapping parameter and DMA views require the same backing file");
            exit(1);
        }
        int fd = open(peer_dma, O_RDWR);
        struct stat info;
        uint64_t expected_size = shared_pool ? Z6II_PARAMETER_SECTION_BYTES : 0x100000;
        uint64_t file_offset = shared_pool ? Z6II_PARAMETER_DMA_VIEW_OFFSET : 0;
        if (fd < 0 || fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_size != expected_size) {
            error_report("Observed peer DMA source has an invalid backing extent");
            exit(1);
        }
        z6ii_engine_shared_ram(engine, &s->observed_peer_dma_buffer,
                z6ii_observed_master_dma_source_section_name, 0x100000,
                fd, file_offset);
        s->observed_peer_dma_enabled = true;
        if (!strcmp(profile->role, "master")) {
            memory_region_add_subregion_overlap(sysmem, 0xC8300000, &s->observed_peer_dma_buffer, 1);
        }
        fprintf(stderr, "Z6II_PEER_DMA_SECTION role=%s master_original_RAM=C8300000 "
                "slave_DMA_bus=28300000 bytes=100000 CPU_aperture_added=0 "
                "host_fixture_payloads=0 shared_parameter_pool=%u backing_offset=%" PRIx64 " "
                "physical_mapping_verified=0\n", profile->role, shared_pool, file_offset);
    }
    const char *slave_dma = z6ii_engine_getenv(s->engine, "Z6II_SLAVE_DMA_SECTION");
    if (slave_dma) {
        /* Original master29 reads46B9F300 intoC711F340, width7F00,
         * rows40. Its source span ends46D9B300: three observed1MiB
         * sections of the slave C6B00000 RAM pool. Only this DMA view. */
        if (!peer_dma || !coupled_queues || !functional_devices) {
            error_report("Observed slave DMA buffer requires integrated original peer DMA");
            exit(1);
        }
        int fd = open(slave_dma, O_RDWR);
        struct stat info;
        if (fd < 0 || fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_size != 0x300000) {
            error_report("Observed slave DMA buffer must be a run-local3MiB RAM file");
            exit(1);
        }
        z6ii_engine_shared_ram(engine, &s->observed_slave_dma_buffer,
                z6ii_observed_slave_dma_buffer_sections_name, 0x300000, fd, 0);
        s->observed_slave_dma_enabled = true;
        /* Original domain0 converts a Slave C0000000 reference to Master
         * 40000000. Both original ROM L1 tables map 46B..46D and C6B..C6D
         * as identity sections. The CPU type7 consumer uses LDRD memcpy,
         * so it must see the same bytes already exposed to the DMA API. */
        uint32_t address = !strcmp(profile->role, "slave") ? 0xC6B00000 : 0x46B00000;
        memory_region_add_subregion_overlap(sysmem, address, &s->observed_slave_dma_buffer, 1);
        fprintf(stderr, "Z6II_SLAVE_DMA_SECTION role=%s slave_original_RAM=C6B00000 "
                "master_DMA_bus=46B00000 bytes=300000 CPU_aperture_added=1 "
                "CPU_mapping_basis=original_domain0_and_L1_identity_sections "
                "host_fixture_payloads=0 physical_mapping_verified=0\n", profile->role);
    }
    if (fill1 && !s->observed_peer_dma_enabled) {
        error_report("Slave fill channel1 requires its observed original master DMA source");
        exit(1);
    }
    if (peer_parameter) {
        if (!peer_data || !coupled_queues || !functional_devices) {
            error_report("Peer parameter copy requires integrated original peer data");
            exit(1);
        }
        int fd = open(peer_parameter, O_RDWR);
        struct stat info;
        if (fd < 0 || fstat(fd, &info) || !S_ISREG(info.st_mode) ||
            info.st_size != Z6II_PARAMETER_SECTION_BYTES) {
            error_report("Peer parameter copy requires the complete cold application RAM pool");
            exit(1);
        }
        z6ii_engine_shared_ram(engine, &s->observed_peer_parameter_buffer,
                z6ii_observed_master_parameter_sections_name, Z6II_PARAMETER_SECTION_BYTES,
                fd, 0);
        s->observed_peer_parameter_enabled = true;
        const char *guard = z6ii_engine_getenv(s->engine, "Z6II_PARAMETER_REQUIRE_RECORDED_BODY");
        if (guard && strcmp(guard, "1")) {
            error_report("Parameter source provenance guard requires explicit value1");
            exit(1);
        }
        s->parameter_require_recorded_body = !!guard;
        const char *ref50 = z6ii_engine_getenv(s->engine, "Z6II_PARAMETER_RECORDED50_REFERENCE");
        const char *ref47 = z6ii_engine_getenv(s->engine, "Z6II_PARAMETER_RECORDED47_REFERENCE");
        if ((ref50 || ref47) && (!guard || !ref50 || !ref47)) {
            error_report("Read-only parameter references require both recorded bodies and the source guard");
            exit(1);
        }
        if (ref50) {
            s->parameter_reference50 = z6ii_parameter_reference_load(ref50, 0x168000,
                "3131474120fa6a149b14709932bce810f9d801c2aabca01eda75e26bcc62fb93");
            s->parameter_reference47 = z6ii_parameter_reference_load(ref47, 0xd8000,
                "996d4ae717a00eb76d9b6ee42e92736bdf74069cc44a95af709ab228e0f6b76b");
            fprintf(stderr, "Z6II_PARAMETER_READ_ONLY_REFERENCES role=%s region50_bytes=168000 "
                    "region47_bytes=d8000 ROM_table=%08x ROM_table_sha256=%s "
                    "region47_ROM_table=%08x region47_ROM_table_sha256=%s "
                    "guest_RAM_seed=0 physical_Flash_container=0\n", profile->role,
                    Z6II_PARAMETER_CONTRACT_TABLE_ADDRESS, Z6II_PARAMETER_CONTRACT_TABLE_SHA256,
                    Z6II_PARAMETER_CONTRACT_REGION47_TABLE_ADDRESS,
                    Z6II_PARAMETER_CONTRACT_REGION47_TABLE_SHA256);
        }
        /* The original domain0 and both original L1 tables cover every
         * 1MiB section of the allocation pool. Share the ordinary Slave
         * CPU aperture as well as the existing parameter DMA view. */
        uint32_t address = !strcmp(profile->role, "master") ?
                           Z6II_PARAMETER_LOCAL_BASE : Z6II_PARAMETER_BUS_BASE;
        memory_region_add_subregion_overlap(sysmem, address,
                                             &s->observed_peer_parameter_buffer, 1);
        fprintf(stderr, "Z6II_PEER_PARAMETER_SECTION role=%s master_original_RAM=c7f00000 "
                "slave_DMA_bus=47f00000 bytes=%x slave_CPU_aperture_added=1 "
                "CPU_mapping_basis=original_domain0_and_L1_identity_sections "
                "host_payload_in_device_API=0 physical_mapping_verified=0 cache_coherence_emulated=0\n",
                profile->role, Z6II_PARAMETER_SECTION_BYTES);
    }
    if (protocol_diagnostic) {
        if (coupled_queues) {
            z6ii_shared_queue(engine, &s->diagnostic_peer, z6ii_coupled_peer_queue_name,
                               queue_fd, local_slot ^ 1);
        } else {
            memory_region_init_ram(&s->diagnostic_peer, NULL, z6ii_diagnostic_peer_snapshot_name,
                                   0xd000, &error_fatal);
        }
        memory_region_add_subregion(sysmem, profile->peer_queue_translated, &s->diagnostic_peer);
        fprintf(stderr, "Z6II_PROTOCOL_DIAGNOSTIC role=%s peer_input=%08x "
                "peer_translated=%08x queue_bytes=c618 local_snapshot=%u "
                "hardware_handshake=%s automatic_transfer=%u automatic_irq=%u\n",
                profile->role, profile->peer_queue_input, profile->peer_queue_translated,
                !coupled_queues, s->coupled_phy ? "explicit_two_ended_hypothesis" : "absent",
                coupled_queues, s->automatic_peer_irq);
        if (profile->peer_status_translated) {
            memory_region_init_ram(&s->diagnostic_peer_status, NULL, z6ii_diagnostic_peer_status_name,
                                   0x1000, &error_fatal);
            memory_region_add_subregion(sysmem, profile->peer_status_translated, &s->diagnostic_peer_status);
            fprintf(stderr, "Z6II_PEER_STATUS_DIAGNOSTIC role=%s page=%08x bytes=1000 "
                    "default_zero=1 readiness_assumed=0 automatic_transfer=0 automatic_irq=0\n",
                    profile->role, profile->peer_status_translated);
        }
    }
    if (queue_fd >= 0) {
        if (coupled_notifications) {
            int owned = dup(queue_fd);
            if (owned < 0) { error_report("Cannot duplicate shared events descriptor"); exit(1); }
            z6ii_engine_shared_ram(engine, &s->shared_events, z6ii_shared_event_control_name,
                                    0x4000, owned, 0x30000);
            s->shared_event_words = memory_region_get_ram_ptr(&s->shared_events);
            /* The event control is host transport metadata, never mapped
             * into guest address space or treated as camera configuration. */
            fprintf(stderr, "Z6II_COUPLED_NOTIFICATIONS role=%s outgoing_bank=0 incoming_bank=1 "
                    "status_bit=15 native_ISR=required automatic_irq=%u timing_emulated=0\n",
                    profile->role, s->automatic_peer_irq);
        }
        close(queue_fd);
        fprintf(stderr, "Z6II_COUPLED_QUEUES role=%s local_slot=%u peer_slot=%u "
                "mapped_bytes=d000 file_stride=10000 data_copy_by_host=0 "
                "other_RAM_shared=0 cache_coherency_emulated=0 event_routing=%s\n",
                profile->role, local_slot, local_slot ^ 1,
                coupled_notifications ? "bank0_to_peer_bank1_diagnostic" : "absent");
    }
    for (unsigned n = 0; n < engine->cpu_count; n++) {
        Object *cpu = object_new(engine->unified ? "nikon-z6ii-a15-arm-cpu" : machine->cpu_type);
        if (engine->cpu_parent) {
            g_autofree char *name = g_strdup_printf("cpu[%u]", n);
            object_property_add_child(engine->cpu_parent, name, cpu);
        }
        object_property_set_link(cpu, "memory", OBJECT(engine->memory), &error_fatal);
        object_property_set_int(cpu, "mp-affinity", n, &error_fatal);
        object_property_set_int(cpu, "core-count", engine->cpu_count, &error_fatal);
        object_property_set_int(cpu, "reset-cbar", 0x2c000000, &error_fatal);
        object_property_set_int(cpu, "cntfrq", 48000000, &error_fatal);
        if (engine->unified) {
            object_property_set_bool(cpu, "cntfrq-exact", true, &error_fatal);
        }
        object_property_set_bool(cpu, "has_el2", false, &error_fatal);
        qdev_realize(DEVICE(cpu), NULL, &error_fatal);
        object_unref(cpu);
    }
    DeviceState *priv = qdev_new(TYPE_A15MPCORE_PRIV);
    if (engine->cpu_parent) {
        object_property_add_child(engine->cpu_parent, "private-peripherals", OBJECT(priv));
    }
    s->priv = A15MPCORE_PRIV(priv);
    qdev_prop_set_uint32(DEVICE(&s->priv->gic), "revision", 1);
    qdev_prop_set_uint32(priv, "num-cpu", engine->cpu_count);
    qdev_prop_set_uint32(priv, "first-cpu-index", engine->cpu_base);
    qdev_prop_set_uint32(priv, "num-irq", 256);
    SysBusDevice *bus = SYS_BUS_DEVICE(priv);
    sysbus_realize_and_unref(bus, &error_fatal);
    memory_region_add_subregion(sysmem, 0x2c000000, sysbus_mmio_get_region(bus, 0));
    for (unsigned n = 0; n < engine->cpu_count; n++) {
        DeviceState *cpu = DEVICE(qemu_get_cpu(engine->cpu_base + n));
        sysbus_connect_irq(bus, n, qdev_get_gpio_in(cpu, ARM_CPU_IRQ));
        sysbus_connect_irq(bus, n + engine->cpu_count, qdev_get_gpio_in(cpu, ARM_CPU_FIQ));
        sysbus_connect_irq(bus, n + 2 * engine->cpu_count, qdev_get_gpio_in(cpu, ARM_CPU_VIRQ));
        sysbus_connect_irq(bus, n + 3 * engine->cpu_count, qdev_get_gpio_in(cpu, ARM_CPU_VFIQ));
    }
    if (s->automatic_peer_irq) {
        s->shared_event_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, z6ii_poll_shared_events, s);
        timer_mod(s->shared_event_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + s->shared_event_poll_ns);
        fprintf(stderr, "Z6II_SHARED_EVENT_POLL role=%s period_ns=%u functional_hypothesis=1 "
                "native_mask_required=1 global_lockstep=0 physical_latency_known=0\n",
                profile->role, s->shared_event_poll_ns);
    }
    z6ii_hdmi_init(s, functional_devices);
    z6ii_hdmi_i2c_reset_qemu_init(s, functional_devices);
    z6ii_hdmi_phy_i2c_init(s, functional_devices);
    z6ii_hdmi_phy_pll_init(s, functional_devices);
    z6ii_hdmi_video_init(&s->hdmi_video, engine,
                        !strcmp(s->profile->role, "master"),
                        s->hdmi_enabled, s->hdmi.generation);
    z6ii_genadc_qemu_init(s, functional_devices);
    z6ii_ipu2402_qemu_init(s, functional_devices);
    if (functional_devices) {
        /* Each EXPEED has its own ROM extent. Slave11fa0000 is outside
         * its10920000 mapped ROM end, despite being below the master's
         *12520000 end. This is empty per-run medium, not factory content. */
        s->virtual_persistent_base = 0x10020000 + profile->rom_size;
        s->virtual_persistent_flash = g_malloc(0x14000000 - s->virtual_persistent_base);
        memset(s->virtual_persistent_flash, 0xff, 0x14000000 - s->virtual_persistent_base);
        z6ii_load_persistent_input(s);
        z6ii_persistent_output_init(s);
        fprintf(stderr, "Z6II_VIRTUAL_FLASH role=%s start=%08x end=14000000 "
                "erased_ff=1 per_run_ephemeral=1 original_ROM_writes=0 factory_content=absent\n",
                profile->role, s->virtual_persistent_base);
        s->devices = z6ii_fd_devices_new(engine, s->priv, !strcmp(profile->role, "master"));
        s->devices->supplied_persistent_source_start = s->supplied_persistent_source_start;
        s->devices->supplied_persistent_source_end = s->supplied_persistent_source_end;
        z6ii_ba2_board_init(s);
        z6ii_slave_storage_init(s);
        z6ii_exmcu_transport_init(s);
        if (z6ii_capseq_actuator_init(s->devices, profile->role)) {
            qemu_register_reset(z6ii_capseq_actuator_board_reset, s);
        }
        s->link_test_peer = z6ii_engine_getenv(s->engine, "Z6II_LINK_TEST_PEER") != NULL;
        if (coupled_queues && s->link_test_peer) {
            error_report("Integrated two-ended boot cannot enable a scripted EXPEED peer");
            exit(1);
        }
        s->link_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, z6ii_link_complete, s);
        fprintf(stderr, "Z6II_LINK_MODEL role=%s scripted_peer=%u original_peer_firmware=0 "
                "queue_replies=absent irq_mapping_from_original_isr=1\n",
                profile->role, s->link_test_peer);
    }
    fprintf(stderr, "Z6II_PROFILE role=%s firmware_sha256=%s native_entry=10020000 "
            "crt=%08x rtos=%08x strict_mmio=1 ram_capacity_verified=0 peer=%s\n",
            profile->role, profile->sha256, profile->crt_entry, profile->rtos_entry,
            coupled_queues ? "shared_queue_only" : "absent");
    /* Initial PCs are set explicitly with generic-loader devices. */
}

static void z6ii_init_profile(MachineState *machine, const Z6IIProfile *profile,
                              bool protocol_diagnostic, bool functional_devices,
                              bool coupled_queues, bool coupled_notifications)
{
    Z6IIEngineContext *engine = z6ii_engine_new(profile->role, false, 0,
                                               machine->smp.cpus,
                                               get_system_memory());
    z6ii_init_engine(machine, profile, protocol_diagnostic, functional_devices,
                     coupled_queues, coupled_notifications, engine,
                     machine->firmware);
}

static void z6ii_master_init(MachineState *m) { z6ii_init_profile(m, &z6ii_master_profile, false, false, false, false); }
static void z6ii_slave_init(MachineState *m) { z6ii_init_profile(m, &z6ii_slave_profile, false, false, false, false); }
static void z6ii_master_protocol_init(MachineState *m) { z6ii_init_profile(m, &z6ii_master_profile, true, false, false, false); }
static void z6ii_slave_protocol_init(MachineState *m) { z6ii_init_profile(m, &z6ii_slave_profile, true, false, false, false); }
static void z6ii_master_assisted_init(MachineState *m) { z6ii_init_profile(m, &z6ii_master_profile, true, true, false, false); }
static void z6ii_slave_assisted_init(MachineState *m) { z6ii_init_profile(m, &z6ii_slave_profile, true, true, false, false); }
static void z6ii_master_coupled_init(MachineState *m) { z6ii_init_profile(m, &z6ii_master_profile, true, false, true, false); }
static void z6ii_slave_coupled_init(MachineState *m) { z6ii_init_profile(m, &z6ii_slave_profile, true, false, true, false); }
static void z6ii_master_notify_init(MachineState *m) { z6ii_init_profile(m, &z6ii_master_profile, true, false, true, true); }
static void z6ii_slave_notify_init(MachineState *m) { z6ii_init_profile(m, &z6ii_slave_profile, true, false, true, true); }
/* Explicit integration only. Existing strict/diagnostic/assisted machines keep
 * their behavior. These machines execute both original EGs from their entry;
 * existing functional peripherals and V3 link hypotheses are not a bootloader
 * image, factory configuration, EX MCU firmware, or a verified physical board. */
static void z6ii_master_boot_init(MachineState *m) { z6ii_init_profile(m, &z6ii_master_profile, true, true, true, true); }
static void z6ii_slave_boot_init(MachineState *m) { z6ii_init_profile(m, &z6ii_slave_profile, true, true, true, true); }
static void z6ii_class_common(MachineClass *mc)
{
    mc->default_cpu_type = "cortex-a15-arm-cpu";
    mc->max_cpus = mc->default_cpus = 2;
    mc->no_serial = mc->no_parallel = true;
}
static void z6ii_master_class(MachineClass *mc)
{
    z6ii_class_common(mc);
    mc->desc = "Nikon Z6II C1.70 master strict offline startup probe";
    mc->init = z6ii_master_init;
}
static void z6ii_slave_class(MachineClass *mc)
{
    z6ii_class_common(mc);
    mc->desc = "Nikon Z6II C1.70 slave strict offline startup probe";
    mc->init = z6ii_slave_init;
}
DEFINE_MACHINE_ARM("nikon-z6ii-master", z6ii_master_class)
DEFINE_MACHINE_ARM("nikon-z6ii-slave", z6ii_slave_class)
static void z6ii_master_protocol_class(MachineClass *mc)
{
    z6ii_class_common(mc);
    mc->desc = "Nikon Z6II master original protocol diagnostic with explicit peer snapshots";
    mc->init = z6ii_master_protocol_init;
}
static void z6ii_slave_protocol_class(MachineClass *mc)
{
    z6ii_class_common(mc);
    mc->desc = "Nikon Z6II slave original protocol diagnostic with explicit peer snapshots";
    mc->init = z6ii_slave_protocol_init;
}
DEFINE_MACHINE_ARM("nikon-z6ii-master-protocol", z6ii_master_protocol_class)
DEFINE_MACHINE_ARM("nikon-z6ii-slave-protocol", z6ii_slave_protocol_class)
static void z6ii_master_coupled_class(MachineClass *mc)
{
    z6ii_class_common(mc);
    mc->desc = "Nikon Z6II master native protocol with run-local shared queue backing";
    mc->init = z6ii_master_coupled_init;
}
static void z6ii_slave_coupled_class(MachineClass *mc)
{
    z6ii_class_common(mc);
    mc->desc = "Nikon Z6II slave native protocol with run-local shared queue backing";
    mc->init = z6ii_slave_coupled_init;
}
DEFINE_MACHINE_ARM("nikon-z6ii-master-coupled", z6ii_master_coupled_class)
DEFINE_MACHINE_ARM("nikon-z6ii-slave-coupled", z6ii_slave_coupled_class)
static void z6ii_master_notify_class(MachineClass *mc)
{
    z6ii_class_common(mc);
    mc->desc = "Nikon Z6II master diagnostic peer event banks and native ISR status";
    mc->init = z6ii_master_notify_init;
}
static void z6ii_slave_notify_class(MachineClass *mc)
{
    z6ii_class_common(mc);
    mc->desc = "Nikon Z6II slave diagnostic peer event banks and native ISR status";
    mc->init = z6ii_slave_notify_init;
}
DEFINE_MACHINE_ARM("nikon-z6ii-master-coupled-notify", z6ii_master_notify_class)
DEFINE_MACHINE_ARM("nikon-z6ii-slave-coupled-notify", z6ii_slave_notify_class)
static void z6ii_master_assisted_class(MachineClass *mc)
{
    z6ii_class_common(mc);
    mc->desc = "Nikon Z6II master assisted functional peripherals; strict unknown accesses";
    mc->init = z6ii_master_assisted_init;
}
static void z6ii_slave_assisted_class(MachineClass *mc)
{
    z6ii_class_common(mc);
    mc->desc = "Nikon Z6II slave assisted functional peripherals; strict unknown accesses";
    mc->init = z6ii_slave_assisted_init;
}
DEFINE_MACHINE_ARM("nikon-z6ii-master-assisted", z6ii_master_assisted_class)
DEFINE_MACHINE_ARM("nikon-z6ii-slave-assisted", z6ii_slave_assisted_class)
static void z6ii_master_boot_class(MachineClass *mc)
{
    z6ii_class_common(mc);
    mc->desc = "Nikon Z6II original master entry with integrated two-ended functional boot model";
    mc->init = z6ii_master_boot_init;
}
static void z6ii_slave_boot_class(MachineClass *mc)
{
    z6ii_class_common(mc);
    mc->desc = "Nikon Z6II original slave entry with integrated two-ended functional boot model";
    mc->init = z6ii_slave_boot_init;
}
DEFINE_MACHINE_ARM("nikon-z6ii-master-boot", z6ii_master_boot_class)
DEFINE_MACHINE_ARM("nikon-z6ii-slave-boot", z6ii_slave_boot_class)

/* A shared virtual time base does not merge the three physical buses.
 * Each EXPEED still sees its local pair of cores as MPIDR 0/1, including
 * its own GIC, ROM, RAM and DMA address space. The MCU boots its original
 * vector on a third bus. External pin/serial contracts remain explicit
 * hypotheses; this topology does not certify physical reset sequencing. */
#define TYPE_Z6II_NATIVE_MACHINE MACHINE_TYPE_NAME("nikon-z6ii-native")
OBJECT_DECLARE_SIMPLE_TYPE(Z6IINativeMachine, Z6II_NATIVE_MACHINE)

struct Z6IINativeMachine {
    MachineState parent;
    char *slave_firmware;
    MemoryRegion master_memory, slave_memory, mcu_memory;
    CPUClusterState cluster[3];
    GHashTable *shared_backings;
    Z6IIEngineContext *master, *slave;
    void *mcu;
};

static char *z6ii_native_slave_firmware_get(Object *obj, Error **errp)
{
    return g_strdup(Z6II_NATIVE_MACHINE(obj)->slave_firmware);
}

static void z6ii_native_slave_firmware_set(Object *obj, const char *value,
                                           Error **errp)
{
    Z6IINativeMachine *s = Z6II_NATIVE_MACHINE(obj);
    g_free(s->slave_firmware);
    s->slave_firmware = g_strdup(value);
}

static void z6ii_native_virtual_time_get(Object *obj, Visitor *v,
                                         const char *name, void *opaque,
                                         Error **errp)
{
    int64_t virtual_ns = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    visit_type_int64(v, name, &virtual_ns, errp);
}

/* Side-effect-free inspection of the actual owner objects. Reading this
 * property never dispatches MMIO, acknowledges an IRQ, or changes a timer. */
static char *z6ii_native_architecture_get(Object *obj, Error **errp)
{
    Z6IINativeMachine *s = Z6II_NATIVE_MACHINE(obj);
    g_autoptr(QDict) state = qdict_new();
    QList *cpus = qlist_new(), *domains = qlist_new(), *gics = qlist_new();
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    qdict_put_str(state, "schema", "z62.native-machine-state/1");
    qdict_put_int(state, "pid", getpid());
    qdict_put_str(state, "machine", "nikon-z6ii-native");
    qdict_put_str(state, "clock", "QEMU_CLOCK_VIRTUAL");
    qdict_put_int(state, "virtual_ns", now);
    qdict_put_bool(state, "observation_only", true);
    qdict_put_bool(state, "physical_clock_and_reset_relationship_verified", false);
    qdict_put_bool(state, "full_physical_Flash_boot_verified", false);
    qdict_put_int(state, "shared_RAMBlock_count", s->shared_backings ?
                   g_hash_table_size(s->shared_backings) : 0);
    CPUState *cs;
    CPU_FOREACH(cs) {
        ARMCPU *cpu = ARM_CPU(cs);
        Z6IIEngineContext *engine = z6ii_engine_for_cpu(cs);
        QDict *item = qdict_new();
        AddressSpace *as = cpu_get_address_space(cs, 0);
        g_autofree char *path = object_get_canonical_path(OBJECT(cs));
        g_autofree char *root = object_get_canonical_path(OBJECT(as->root));
        qdict_put_int(item, "global_cpu_index", cs->cpu_index);
        qdict_put_str(item, "role", engine ? engine->role : "MCU");
        qdict_put_int(item, "local_cpu", engine ? cs->cpu_index - engine->cpu_base : 0);
        qdict_put_str(item, "qom_path", path);
        qdict_put_str(item, "cpu_type", object_get_typename(OBJECT(cs)));
        /* Internal grouping is evidence for the debugger/TCG, not a claimed
         * physical cluster identifier. MPIDR remains separately local. */
        qdict_put_int(item, "QEMU_cluster_index", cs->cluster_index);
        if (engine) {
            qdict_put_int(item, "MPIDR", cpu->mp_affinity);
            qdict_put_int(item, "generic_timer_frequency_hz", cpu->gt_cntfrq_hz);
            qdict_put_bool(item, "generic_timer_exact_frequency", cpu->gt_cntfrq_exact);
        }
        qdict_put_int(item, "PC", cpu->env.regs[15]);
        qdict_put_bool(item, "halted", cs->halted);
        qdict_put_int(item, "interrupt_request", cs->interrupt_request);
        qdict_put_str(item, "cpu_memory_root_qom_path", root);
        qdict_put_str(item, "address_space_name", as->name);
        if (engine) {
            Z6IIA15CPU *a15 = (Z6IIA15CPU *)cs;
            qdict_put_bool(item, "cpu_root_matches_owner", as->root == engine->memory);
            qdict_put_bool(item, "waiting_for_MCU_output", a15->wait.active);
            qdict_put_int(item, "system_reset_count", a15->system_reset_count);
            qdict_put_int(item, "last_system_reset_virtual_ns", a15->last_system_reset_ns);
        }
        qlist_append(cpus, item);
    }
    Z6IIEngineContext *engines[] = {s->master, s->slave};
    for (unsigned n = 0; n < G_N_ELEMENTS(engines); n++) {
        Z6IIEngineContext *engine = engines[n];
        if (!engine || !engine->board) { continue; }
        Z6IIState *board = engine->board;
        GICState *gic = &board->priv->gic;
        QDict *domain = qdict_new(), *irq = qdict_new();
        g_autofree char *root = object_get_canonical_path(OBJECT(engine->memory));
        g_autofree char *gic_path = object_get_canonical_path(OBJECT(gic));
        uint64_t ticks = ((uint64_t)board->early[7] << 32) | board->early[6];
        if (board->early[5] & 1) {
            ticks += muldiv64(now - board->counter_epoch, 48000000, 1000000000);
        }
        qdict_put_str(domain, "role", engine->role);
        qdict_put_str(domain, "memory_root_qom_path", root);
        qdict_put_str(domain, "address_space_name", engine->as.name);
        qdict_put_int(domain, "first_cpu_index", engine->cpu_base);
        qdict_put_int(domain, "num_cpu", engine->cpu_count);
        qdict_put_str(domain, "clock", "QEMU_CLOCK_VIRTUAL");
        qdict_put_int(domain, "counter_frequency_hz", 48000000);
        qdict_put_bool(domain, "counter_enabled", board->early[5] & 1);
        qdict_put_int(domain, "counter_epoch_ns", board->counter_epoch);
        qdict_put_int(domain, "counter_ticks", ticks);
        QList *private_ram = qlist_new();
        const char *first_private_id = NULL;
        for (unsigned i = 0; i < board->profile->num_windows; i++) {
            MemoryRegion *mr = &board->ram[i];
            if (mr->alias || !mr->ram_block) { continue; }
            const char *id = qemu_ram_get_idstr(mr->ram_block);
            QDict *ram = qdict_new();
            qdict_put_str(ram, "ram_backing_id", id);
            qdict_put_str(ram, "name", memory_region_name(mr));
            qdict_put_int(ram, "mapped_address", mr->addr);
            qdict_put_int(ram, "bytes", memory_region_size(mr));
            qdict_put_int(ram, "QEMU_ram_offset", memory_region_get_ram_addr(mr));
            qlist_append(private_ram, ram);
            if (!first_private_id) { first_private_id = id; }
        }
        if (first_private_id) {
            qdict_put_str(domain, "private_ram_backing_id", first_private_id);
        }
        qdict_put(domain, "private_RAMBlocks", private_ram);
        qdict_put(domain, "shared_apertures", z6ii_engine_shared_aperture_state(engine));
        qdict_put_str(irq, "role", engine->role);
        qdict_put_str(irq, "qom_path", gic_path);
        qdict_put_int(irq, "first_cpu_index", gic->first_cpu_index);
        qdict_put_int(irq, "num_cpu", gic->num_cpu);
        qdict_put_int(irq, "num_irq", gic->num_irq);
        QList *counters = qlist_new();
        for (unsigned local = 0; local < gic->num_cpu; local++) {
            QDict *counter = qdict_new();
            qdict_put_int(counter, "local_cpu", local);
            qdict_put_int(counter, "interface_reads", gic->domain_interface_reads[local]);
            qdict_put_int(counter, "interface_writes", gic->domain_interface_writes[local]);
            qdict_put_int(counter, "SGI_sent", gic->domain_sgi_sent[local]);
            qdict_put_int(counter, "SGI_target_mask", gic->domain_sgi_targets[local]);
            qdict_put_int(counter, "IRQ_acks", gic->domain_irq_acks[local]);
            qdict_put_int(counter, "SGI_acks", gic->domain_sgi_acks[local]);
            qdict_put_int(counter, "PPI_edges", gic->domain_ppi_edges[local]);
            qlist_append(counters, counter);
        }
        qdict_put(irq, "observed_local_cpu_activity", counters);
        qlist_append(domains, domain);
        qlist_append(gics, irq);
    }
    if (s->mcu) {
        qlist_append(domains, nikon_ex1850_architecture_state(s->mcu, s->master->wire_bus));
    }
    qdict_put(state, "cpus", cpus);
    qdict_put(state, "domains", domains);
    qdict_put(state, "gics", gics);
    return g_string_free(qobject_to_json(QOBJECT(state)), false);
}

static void z6ii_native_init(MachineState *machine)
{
    Z6IINativeMachine *s = Z6II_NATIVE_MACHINE(machine);
    if (machine->smp.cpus != 5 || !machine->firmware ||
        !s->slave_firmware || !machine->kernel_filename) {
        error_report("nikon-z6ii-native requires -smp 5, -bios master, "
                     "slave-firmware=slave and -kernel original MCU ROM");
        exit(1);
    }
    memory_region_init(&s->master_memory, OBJECT(machine),
                        "z6ii-native-master-memory", UINT64_MAX);
    memory_region_init(&s->slave_memory, OBJECT(machine),
                        "z6ii-native-slave-memory", UINT64_MAX);
    memory_region_init(&s->mcu_memory, OBJECT(machine),
                        "z6ii-native-mcu-memory", UINT64_MAX);
    const char *cluster_names[] = {"master-cluster", "slave-cluster", "mcu-cluster"};
    for (unsigned n = 0; n < G_N_ELEMENTS(s->cluster); n++) {
        object_initialize_child(OBJECT(machine), cluster_names[n],
                                &s->cluster[n], TYPE_CPU_CLUSTER);
        qdev_prop_set_uint32(DEVICE(&s->cluster[n]), "cluster-id", n);
    }
    Z6IIEngineContext *master = z6ii_engine_new("master", true, 0, 2,
                                                &s->master_memory);
    Z6IIEngineContext *slave = z6ii_engine_new("slave", true, 2, 2,
                                               &s->slave_memory);
    s->shared_backings = g_hash_table_new_full(g_str_hash, g_str_equal,
                                               g_free, NULL);
    s->master = master;
    s->slave = slave;
    master->cpu_parent = OBJECT(&s->cluster[0]);
    slave->cpu_parent = OBJECT(&s->cluster[1]);
    master->shared_backings = slave->shared_backings = s->shared_backings;
    z6ii_init_engine(machine, &z6ii_master_profile, true, true, true, true,
                     master, machine->firmware);
    z6ii_init_engine(machine, &z6ii_slave_profile, true, true, true, true,
                     slave, s->slave_firmware);
    qdev_realize(DEVICE(&s->cluster[0]), NULL, &error_fatal);
    qdev_realize(DEVICE(&s->cluster[1]), NULL, &error_fatal);
    if (!master->wire_bus || !master->wire_path) {
        error_report("Unified Z6II requires a fresh original MCU wire endpoint");
        exit(1);
    }
    s->mcu = nikon_ex1850_init(machine, &s->mcu_memory,
                               machine->kernel_filename, true,
                               master->wire_bus, master->wire_path,
                               OBJECT(&s->cluster[2]));
    qdev_realize(DEVICE(&s->cluster[2]), NULL, &error_fatal);
    if (!qemu_get_cpu(4) || qemu_get_cpu(5)) {
        error_report("Unified Z6II topology did not create exactly five CPUs");
        exit(1);
    }
    fprintf(stderr, "Z62_UNIFIED_MACHINE cpus=5 master=0,1 slave=2,3 MCU=4 "
            "local_EXPEED_MPIDR=0,1 private_buses=3 clock=QEMU_CLOCK_VIRTUAL "
            "virtual_ns=%" PRId64 " reset_clock_relationship_verified=0 "
            "full_physical_Flash_boot_verified=0\n",
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
}

static void z6ii_native_finalize(Object *obj)
{
    g_free(Z6II_NATIVE_MACHINE(obj)->slave_firmware);
}

static void z6ii_native_class_init(ObjectClass *klass, const void *data)
{
    MachineClass *mc = MACHINE_CLASS(klass);
    mc->desc = "Nikon Z6II master/slave EXPEED and original MCU on one virtual clock";
    mc->init = z6ii_native_init;
    mc->default_cpu_type = TYPE_Z6II_A15;
    mc->min_cpus = mc->max_cpus = mc->default_cpus = 5;
    mc->no_serial = mc->no_parallel = true;
    object_class_property_add_str(klass, "slave-firmware",
                                   z6ii_native_slave_firmware_get,
                                   z6ii_native_slave_firmware_set);
    object_class_property_set_description(klass, "slave-firmware",
        "Verified original slave EG application image in its private address space");
    object_class_property_add(klass, "virtual-time-ns", "int",
                               z6ii_native_virtual_time_get, NULL, NULL, NULL);
    object_class_property_set_description(klass, "virtual-time-ns",
        "Read-only current QEMU_CLOCK_VIRTUAL shared by both EXPEEDs and the MCU");
    object_class_property_add_str(klass, "architecture-state", z6ii_native_architecture_get, NULL);
    object_class_property_set_description(klass, "architecture-state",
        "Read-only actual CPU, private memory, GIC/NVIC, shared RAM and clock state as JSON");
}

static void z6ii_native_register_types(void)
{
    static const TypeInfo machine = {
        .name = TYPE_Z6II_NATIVE_MACHINE,
        .parent = TYPE_MACHINE,
        .instance_size = sizeof(Z6IINativeMachine),
        .instance_finalize = z6ii_native_finalize,
        .class_init = z6ii_native_class_init,
        .interfaces = arm_machine_interfaces,
    };
    type_register_static(&machine);
}
type_init(z6ii_native_register_types)
