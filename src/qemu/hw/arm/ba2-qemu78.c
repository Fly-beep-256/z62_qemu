/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Original BA2 reset bytes + bounded virtual-time slices. The opt-in
 * controller routes unchanged frames through the Master-owned FIFO.
 * IRQ entry and optional startup ISA semantics remain explicit candidates. */
#include "qemu/osdep.h"
#include "qemu/timer.h"
#include "system/address-spaces.h"
#include "system/memory.h"
#include "system/reset.h"
#include "system/system.h"
#include "ba2-qemu78.h"
#include "ba2-bus79.h"
#include "ba2-reti-ram-read.h"
#include "ba2-mlwz-ram-read.h"
#include "ba2-startup-ram-read.h"
#include "ba2-controller136.h"
#include "ba2-startup-bridge137.h"
#include "ba2-irq138.h"
#include "ba2-tick139.h"
#include "ba2-window98.h"
#include "ba2-engine140.h"

#define PAYLOAD_SRC UINT32_C(0x107a99f4)
#define PAYLOAD_DST UINT32_C(0xc0c00000)
#define EXPECTED_SHA "2e765a41822d563b35f726240f9c9e817c95d749bebce45d90b3a9120a590a16"
#define IRQ138_POLICY "fifo-level-vector38-candidate-v1"
#define TRANSACTION_CONFIG_POLICY "original-function-raw32-latches-v1"
#define ENGINE140_POLICY "startup-mode9-descriptor-candidate-v1"
typedef enum { PEER_HOLD, PEER_RUNNING, PEER_STOPPED } PeerState;
struct Z6IIBA2QEMU78 {
    Z6IIBA2QEMU78Config config;
    Z6IIBA2CPU cpu;
    Z6IIBA2Bus bus;
    Z6IIBA2Controller136 controller;
    Z6IIBA2StartupBridge137 bridge;
    Z6IIBA2IRQ138 irq138;
    Z6IIBA2Tick139 tick139;
    Z6IIBA2Engine140 engine140;
    int64_t tick139_last_ns;
    Z6IIBA2MemoryMap ram_map;
    uint8_t *payload, *ram;
    QEMUTimer *timer;
    Notifier exit_notifier;
    Z6IIIPU2402 *master_fifo;
    Z6IIBA2MasterIRQUpdateFn master_irq_update;
    void *master_irq_opaque;
    PeerState state;
    uint64_t sequence, pending_token;
    uint64_t window_binding_commits;
    uint64_t bridge_repeated_10478_writes, bridge_repeated_10478_suppressed;
    uint64_t window_wait_polls;
    bool window_wait_reported;
    bool source_valid;
    char source_sha[65];
};

static bool policy(const char *s, const char *expected)
{
    return s && !strcmp(s, expected);
}

/* Direct ordinary RAM/ROM only. Never CPU, MMIO or address-space reads.
 * No guest backing pointer escapes this synchronous BQL-held callback. */
static bool direct_sha(Z6IIBA2QEMU78 *p, uint32_t address, size_t length, bool require_rom,
                       char out[65])
{
    bool valid = false;
    if (!length || (uint64_t)address + length > UINT64_C(0x100000000)) {
        return false;
    }
    MemoryRegionSection section = memory_region_find(p->config.master_memory,
                                                     address, length);
    if (section.mr) {
        uint64_t bytes = memory_region_size(section.mr);
        valid = section.offset_within_address_space == address &&
            int128_ge(section.size, int128_make64(length)) &&
            memory_region_is_ram(section.mr) &&
            !memory_region_is_ram_device(section.mr) &&
            memory_region_is_rom(section.mr) == require_rom &&
            (require_rom || !section.readonly) && bytes >= length &&
            section.offset_within_region <= bytes - length;
        if (valid) {
            char *sha = g_compute_checksum_for_data(G_CHECKSUM_SHA256,
                (const uint8_t *)memory_region_get_ram_ptr(section.mr) +
                section.offset_within_region, length);
            g_strlcpy(out, sha, 65);
            g_free(sha);
        }
        memory_region_unref(section.mr);
    }
    return valid;
}

static void report_peer(Z6IIBA2QEMU78 *p, const char *event,
                        const char *reason, Z6IIBA2CPUResult result)
{
    fprintf(stderr, "%s now_ns=%" PRId64
        " reason=%s cpu_result=%s pc=%08x retired=%" PRIu64
        " op=%s raw=", event, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), reason,
        z6ii_ba2_cpu_result_name(result), p->cpu.pc, p->cpu.retired,
        p->cpu.last.name ? p->cpu.last.name : "none");
    for (unsigned i = 0; i < p->cpu.last.length && i < 6; i++) {
        fprintf(stderr, "%02x", p->cpu.last.raw[i]);
    }
    fprintf(stderr, " bus_result=%u fault_addr=%08x fault_size=%u"
        " fault_write=%u fault_fetch=%u tx_words=%u rx_words=%u"
        " SPR_access=%u SPR_selector=%08x SPR_write=%u SPR_value=%08x SPR_result=%u"
        " startup_irq_known=%u startup_irq_enabled=%u"
        " irq_entries=%" PRIu64 " irq_returns=%" PRIu64 " irq_active=%u"
        " irq_active_source=%u tick_entries=%" PRIu64 " tick_returns=%" PRIu64
        " tick_policy=%s tick_source_hz=%" PRIu64
        " tick_source_cycles=%" PRIu64 " tick_elapsed_cycles=%" PRIu64
        " tick_events=%" PRIu64 " tick_ACKs=%" PRIu64
        " tick_control=%08x tick_count=%08x tick_pending=%u tick_fraction_fifths=%u"
        " tick_time_source=qemu-virtual-ns"
        " irq_SR11=%08x irq_EPC20=%08x irq_ESR40=%08x"
        " controller_rx_frames=%" PRIu64 " controller_rx_words=%" PRIu64
        " controller_tx_frames=%" PRIu64 " controller_tx_words=%" PRIu64
        " controller_rx_next=%u controller_tx_staged=%u"
        " controller_raw=%08x controller_mask=%08x"
        " bridge_window_reads=%" PRIu64 " bridge_reset_transactions=%" PRIu64
        " bridge_reset_completions=%" PRIu64 " bridge_enables=%" PRIu64
        " bridge_config_written=%08x bridge_control=%08x"
        " bridge_repeated_10478_writes=%" PRIu64
        " bridge_repeated_10478_suppressed=%" PRIu64
        " SPR4800=%08x SPR4800_reads=%" PRIu64 " SPR4800_writes=%" PRIu64
        " host_business_writes=0 automatic_reply=0 shared_RAM_policy=%s"
        " window_wait_polls=%" PRIu64 " window_waiting=%u"
        " transaction_config_policy=%s engine140_policy=%s engine140_backend=%s"
        " engine140_raw=%08x engine140_submissions=%" PRIu64
        " engine140_completions=%" PRIu64 " engine140_rejected=%" PRIu64
        " engine140_last_reject=%u engine140_bytes=%" PRIu64
        " engine140_raw_reads=%" PRIu64 " engine140_W1Cs=%" PRIu64
        " engine140_ACKs=%" PRIu64 " engine140_source=%08x engine140_destination=%08x"
        " mode9_transform_verified=0 registers=",
        p->bus.fault.result, p->bus.fault.address, p->bus.fault.size,
        p->bus.fault.write, p->bus.fault.fetch,
        p->master_fifo->tx.count, p->master_fifo->rx.count,
        p->cpu.last_spr_access, p->cpu.last_spr_selector,
        p->cpu.last_spr_write, p->cpu.last_spr_value, p->cpu.last_spr_result,
        p->cpu.startup_irq_mask_known, p->cpu.startup_irq_enabled,
        p->irq138.entries, p->irq138.returns, p->irq138.active,
        p->irq138.active_source, p->irq138.tick_entries, p->irq138.tick_returns,
        p->config.tick139_policy ? p->config.tick139_policy : "disabled",
        p->tick139.source_hz, p->tick139.source_cycles, p->tick139.elapsed_cycles,
        p->tick139.events, p->tick139.acknowledgements,
        p->tick139.control, p->tick139.count, p->tick139.pending,
        p->tick139.ns_fraction_fifths,
        p->irq138.sr11, p->irq138.epc20, p->irq138.esr40,
        p->controller.rx_frames_taken, p->controller.rx_read_words,
        p->controller.tx_frames_committed, p->controller.tx_word_writes,
        p->controller.rx_next, p->controller.tx_staged,
        z6ii_ba2_controller136_raw(&p->controller), p->controller.interrupt_mask,
        p->bridge.window_reads, p->bridge.reset_transactions,
        p->bridge.reset_completions, p->bridge.enable_writes,
        p->bridge.config_written, p->bridge.control,
        p->bridge_repeated_10478_writes, p->bridge_repeated_10478_suppressed,
        p->bridge.spr4800, p->bridge.spr_reads, p->bridge.spr_writes,
        p->config.window_policy ? p->config.window_policy : "disabled",
        p->window_wait_polls, p->window_wait_reported,
        p->config.transaction_config_policy ? p->config.transaction_config_policy : "disabled",
        p->config.engine140_policy ? p->config.engine140_policy : "disabled",
        p->config.engine140_backend_policy ? p->config.engine140_backend_policy : "strict-reject",
        p->engine140.raw, p->engine140.submissions, p->engine140.completions,
        p->engine140.rejected, (unsigned)p->engine140.last_reject,
        p->engine140.transferred_bytes, p->engine140.raw_reads,
        p->engine140.w1c_writes, p->engine140.completed_acks,
        p->engine140.source_cpu, p->engine140.destination_cpu);
    for (unsigned i = 0; i < 32; i++) {
        fprintf(stderr, "%s%08x", i ? "," : "", p->cpu.r[i]);
    }
    fputc('\n', stderr);
}

static void stop_peer(Z6IIBA2QEMU78 *p, const char *reason,
                      Z6IIBA2CPUResult result)
{
    timer_del(p->timer);
    p->state = PEER_STOPPED;
    report_peer(p, "Z6II_BA2_PEER_STOP", reason, result);
}

static void peer_exit_snapshot(Notifier *notifier, void *data)
{
    Z6IIBA2QEMU78 *p = container_of(notifier, Z6IIBA2QEMU78, exit_notifier);
    (void)data;
    if (p->state == PEER_RUNNING) {
        /* The host ends this observation; the guest has not halted. */
        report_peer(p, "Z6II_BA2_PEER_SNAPSHOT", "qemu-exit-observation",
                    Z6II_BA2_CPU_BUDGET);
    }
}

static Z6IIBA2BusResult controller_read(void *opaque, uint32_t addr,
                                       unsigned size, uint32_t *out)
{
    Z6IIBA2QEMU78 *p = opaque;
    if (policy(p->config.controller_policy, Z6II_BA2_CONTROLLER136_POLICY)) {
        Z6IIBA2BusResult r = p->config.startup_bridge_policy ?
            z6ii_ba2_startup_bridge137_read(&p->bridge, addr, size, out) :
            z6ii_ba2_controller136_read(&p->controller, addr, size, out);
        fprintf(stderr, "%s pc=%08x access=R"
            " addr=%08x size=%u value=%08x result=%u tx_words=%u rx_words=%u"
            " local_rx_next=%u local_tx_staged=%u\n",
            addr < Z6II_BA2_CONTROLLER136_BASE ? "Z6II_BA2_BRIDGE_ACCESS" :
                                               "Z6II_BA2_CONTROLLER_ACCESS",
            p->cpu.pc, addr, size,
            r == Z6II_BA2_BUS_OK ? *out : 0, r,
            p->master_fifo->tx.count, p->master_fifo->rx.count,
            p->controller.rx_next, p->controller.tx_staged);
        return r;
    }
    fprintf(stderr, "Z6II_BA2_CONTROLLER_UNSUPPORTED pc=%08x access=R"
        " addr=%08x size=%u controller_binding_verified=0 FIFO_consumed=0\n",
        p->cpu.pc, addr, size);
    return Z6II_BA2_BUS_DEVICE_FAULT;
}

static Z6IIBA2BusResult controller_write(void *opaque, uint32_t addr,
                                        unsigned size, uint32_t value)
{
    Z6IIBA2QEMU78 *p = opaque;
    if (policy(p->config.controller_policy, Z6II_BA2_CONTROLLER136_POLICY)) {
        uint64_t frames_before = p->controller.tx_frames_committed;
        uint64_t engine_before = p->engine140.submissions;
        Z6IIBA2BusResult r = p->config.startup_bridge_policy ?
            z6ii_ba2_startup_bridge137_write(&p->bridge, addr, size, value) :
            z6ii_ba2_controller136_write(&p->controller, addr, size, value);
        /* Execute every guest write. Only coalesce this exact successful
         * idle-loop log; failed/changed accesses and FIFO frames stay intact. */
        bool repeated = p->cpu.pc == UINT32_C(0x4000bed1) &&
            addr == UINT32_C(0x80010478) && size == 4 && value == 1 &&
            r == Z6II_BA2_BUS_OK;
        if (repeated) {
            ++p->bridge_repeated_10478_writes;
        }
        if (repeated && p->bridge_repeated_10478_writes > 64) {
            ++p->bridge_repeated_10478_suppressed;
        } else {
            fprintf(stderr, "%s pc=%08x access=W"
            " addr=%08x size=%u value=%08x result=%u tx_words=%u rx_words=%u"
            " local_rx_next=%u local_tx_staged=%u\n",
            addr < Z6II_BA2_CONTROLLER136_BASE ? "Z6II_BA2_BRIDGE_ACCESS" :
                                               "Z6II_BA2_CONTROLLER_ACCESS",
            p->cpu.pc, addr, size, value, r,
            p->master_fifo->tx.count, p->master_fifo->rx.count,
            p->controller.rx_next, p->controller.tx_staged);
        }
        if (p->engine140.submissions != engine_before) {
            fprintf(stderr, "Z6II_BA2_ENGINE140_TRANSACTION pc=%08x result=%u"
                " submissions=%" PRIu64 " completions=%" PRIu64
                " rejected=%" PRIu64 " reject=%u raw=%08x bytes=%" PRIu64
                " source=%08x destination=%08x backend=%s mode9_transform_verified=0\n",
                p->cpu.pc, r, p->engine140.submissions, p->engine140.completions,
                p->engine140.rejected, (unsigned)p->engine140.last_reject,
                p->engine140.raw, p->engine140.transferred_bytes,
                p->engine140.source_cpu, p->engine140.destination_cpu,
                p->config.engine140_backend_policy ? p->config.engine140_backend_policy : "strict-reject");
        }
        if (p->controller.tx_frames_committed != frames_before) {
            fprintf(stderr, "Z6II_BA2_PEER_FRAME pc=%08x index=%" PRIu64
                " words=%08x,%08x,%08x host_business_reply=0\n",
                p->cpu.pc, p->controller.tx_frames_committed,
                p->controller.tx_stage[0], p->controller.tx_stage[1],
                p->controller.tx_stage[2]);
        }
        return r;
    }
    fprintf(stderr, "Z6II_BA2_CONTROLLER_UNSUPPORTED pc=%08x access=W"
        " addr=%08x size=%u value=%08x controller_binding_verified=0"
        " FIFO_injected=0\n", p->cpu.pc, addr, size, value);
    return Z6II_BA2_BUS_DEVICE_FAULT;
}

static bool controller_irq(void *opaque)
{
    Z6IIBA2QEMU78 *p = opaque;
    return p->config.startup_bridge_policy ?
        z6ii_ba2_startup_bridge137_irq(&p->bridge) :
        z6ii_ba2_controller136_irq(&p->controller);
}

static uint32_t controller_irq_sources(void *opaque)
{
    Z6IIBA2QEMU78 *p = opaque;
    return z6ii_ba2_startup_bridge137_irq_sources(&p->bridge);
}

static Z6IIBA2SPRResult peer_spr_read(void *opaque, uint32_t selector,
                                     uint32_t *out)
{
    Z6IIBA2QEMU78 *p = opaque;
    if (p->config.startup_bridge_policy && selector == Z6II_BA2_STARTUP_BRIDGE137_SPR) {
        Z6IIBA2SPRResult r = z6ii_ba2_startup_bridge137_spr_read(&p->bridge, selector, out);
        fprintf(stderr, "Z6II_BA2_SPR4800_ACCESS pc=%08x access=R value=%08x"
            " result=%u reads=%" PRIu64 " writes=%" PRIu64 "\n",
            p->cpu.pc, r == Z6II_BA2_SPR_OK ? *out : 0, r,
            p->bridge.spr_reads, p->bridge.spr_writes);
        return r;
    }
    return p->config.spr_read ? p->config.spr_read(p->config.spr_opaque, selector, out) :
                                Z6II_BA2_SPR_UNKNOWN;
}

static Z6IIBA2SPRResult peer_spr_write(void *opaque, uint32_t selector,
                                      uint32_t value)
{
    Z6IIBA2QEMU78 *p = opaque;
    if (p->config.startup_bridge_policy && selector == Z6II_BA2_STARTUP_BRIDGE137_SPR) {
        Z6IIBA2SPRResult r = z6ii_ba2_startup_bridge137_spr_write(&p->bridge, selector, value);
        fprintf(stderr, "Z6II_BA2_SPR4800_ACCESS pc=%08x access=W value=%08x"
            " result=%u reads=%" PRIu64 " writes=%" PRIu64 "\n",
            p->cpu.pc, value, r, p->bridge.spr_reads, p->bridge.spr_writes);
        return r;
    }
    return p->config.spr_write ? p->config.spr_write(p->config.spr_opaque, selector, value) :
                                 Z6II_BA2_SPR_UNKNOWN;
}

static void schedule_peer(Z6IIBA2QEMU78 *p)
{
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    if (now > INT64_MAX - (int64_t)p->config.timer_period_ns) {
        stop_peer(p, "virtual-time-overflow", Z6II_BA2_CPU_BAD_CONFIG);
        return;
    }
    timer_mod(p->timer, now + (int64_t)p->config.timer_period_ns);
}

/* Binding exists only inside one synchronous BQL-held timer callback. No
 * ordinary RAM pointer or stack map remains reachable after this slice. */
static Z6IIBA2BusResult bind_slice_windows(Z6IIBA2QEMU78 *p,
    Z6IIBA2MemoryMap maps[3], MemoryRegionSection sections[2], unsigned *count)
{
    Z6IIBA2Window98Range ranges[2];
    Z6IIBA2BusResult result;
    *count = 0;
    maps[0] = p->ram_map;
    if (!p->config.window_policy) {
        return Z6II_BA2_BUS_OK;
    }
    result = z6ii_ba2_window98_plan(p->master_fifo, Z6II_BA2_PAYLOAD_BYTES,
                                  p->config.ram_bytes, ranges, count);
    if (result != Z6II_BA2_BUS_OK) {
        return result;
    }
    for (unsigned i = 0; i < *count; ++i) {
        const Z6IIBA2Window98Range *range = &ranges[i];
        sections[i] = memory_region_find(p->config.master_memory, range->master_address,
                                        range->size);
        MemoryRegionSection *section = &sections[i];
        if (!section->mr || !memory_region_is_ram(section->mr) ||
            memory_region_is_ram_device(section->mr)) {
            return Z6II_BA2_BUS_UNMAPPED;
        }
        if (memory_region_is_rom(section->mr) || section->readonly) {
            return Z6II_BA2_BUS_PERMISSION;
        }
        uint64_t bytes = memory_region_size(section->mr);
        if (section->offset_within_address_space != range->master_address ||
            !int128_ge(section->size, int128_make64(range->size)) ||
            bytes < range->size || section->offset_within_region > bytes - range->size) {
            return Z6II_BA2_BUS_UNMAPPED;
        }
        uint8_t *ram = (uint8_t *)memory_region_get_ram_ptr(section->mr) +
                       section->offset_within_region;
        Z6IIBA2MemoryMap backing = {
            .base = range->master_address, .size = range->size,
            .bytes = ram, .writable_bytes = ram,
            .permissions = Z6II_BA2_MEM_READ | Z6II_BA2_MEM_WRITE,
            .mapping_basis = "actual writable ordinary Master QEMU RAM; slice-held reference",
        };
        result = z6ii_ba2_window98_bind(range, &backing, &maps[i + 1]);
        if (result != Z6II_BA2_BUS_OK) {
            return result;
        }
    }
    Z6IIBA2BusConfig config = p->bus.config;
    Z6IIBA2Bus validated;
    config.ram = maps;
    config.ram_count = 1 + *count;
    result = z6ii_ba2_bus_init(&validated, &config);
    if (result != Z6II_BA2_BUS_OK) {
        return result;
    }
    p->bus.config = validated.config;
    if (*count && p->window_binding_commits != p->master_fifo->window_commits) {
        for (unsigned i = 0; i < *count; ++i) {
            fprintf(stderr, "Z6II_BA2_WINDOW_BIND now_ns=%" PRId64
                " commit=%" PRIu64 " index=%u base=%08x master=%08x bytes=%zx"
                " policy=%s ordinary_RAM=1 guest_zero_fill=0 silicon_verified=0\n",
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), p->master_fifo->window_commits,
                ranges[i].index, ranges[i].base, ranges[i].master_address,
                ranges[i].size, p->config.window_policy);
        }
        p->window_binding_commits = p->master_fifo->window_commits;
    }
    return Z6II_BA2_BUS_OK;
}

static void release_slice_windows(Z6IIBA2QEMU78 *p,
    const Z6IIBA2MemoryMap maps[3], MemoryRegionSection sections[2],
    unsigned count, bool ran)
{
    /* Restore persistent private RAM before releasing sections or returning. */
    p->bus.config.ram = &p->ram_map;
    p->bus.config.ram_count = 1;
    for (unsigned i = 0; i < count; ++i) {
        if (sections[i].mr) {
            if (ran) {
                memory_region_set_dirty(sections[i].mr, sections[i].offset_within_region,
                                        maps[i + 1].size);
            }
            memory_region_unref(sections[i].mr);
        }
    }
}

static void run_slice(void *opaque)
{
    Z6IIBA2QEMU78 *p = opaque;
    if (p->state != PEER_RUNNING) {
        return;
    }
    /* The shared-window candidate has no valid reset register values before
     * Master commits its descriptor. Hold execution on that real prerequisite
     * rather than letting host scheduling turn the first read into a fault.
     * No guest instruction, FIFO word, RAM value or completion is produced.
     * Reset-release timing on physical silicon remains unverified. */
    if (p->config.startup_bridge_policy && p->config.window_policy &&
        (!p->master_fifo->window_valid || !p->master_fifo->window_commits)) {
        if (!p->window_wait_reported) {
            fprintf(stderr, "Z6II_BA2_WINDOW_WAIT now_ns=%" PRId64
                " pc=%08x retired=%" PRIu64 " window_valid=%u commits=%" PRIu64
                " prerequisite=actual-Master-committed-map guest_progress=0\n",
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), p->cpu.pc, p->cpu.retired,
                p->master_fifo->window_valid, p->master_fifo->window_commits);
            p->window_wait_reported = true;
        }
        ++p->window_wait_polls;
        schedule_peer(p);
        return;
    }
    if (p->window_wait_reported) {
        fprintf(stderr, "Z6II_BA2_WINDOW_RESUME now_ns=%" PRId64
            " pc=%08x retired=%" PRIu64 " polls=%" PRIu64 " commits=%" PRIu64
            " register_value_injected=0\n",
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), p->cpu.pc, p->cpu.retired,
            p->window_wait_polls, p->master_fifo->window_commits);
        p->window_wait_reported = false;
    }
    if (p->config.tick139_policy) {
        int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
        if (now < p->tick139_last_ns ||
            z6ii_ba2_tick139_advance_ns(&p->tick139,
                (uint64_t)(now - p->tick139_last_ns)) != Z6II_BA2_SPR_OK) {
            stop_peer(p, "periodic-clock-advance-failed", Z6II_BA2_CPU_BAD_CONFIG);
            return;
        }
        p->tick139_last_ns = now;
    }
    uint64_t slice = p->config.slice_steps;
    if (p->config.total_steps) {
        uint64_t remaining = p->config.total_steps - p->cpu.retired;
        slice = MIN(remaining, slice);
    }
    Z6IIBA2MemoryMap maps[3] = {0};
    MemoryRegionSection sections[2] = {0};
    unsigned count;
    Z6IIBA2BusResult binding = bind_slice_windows(p, maps, sections, &count);
    if (binding != Z6II_BA2_BUS_OK) {
        release_slice_windows(p, maps, sections, count, false);
        p->bus.fault = (Z6IIBA2BusFault) { .result = binding };
        stop_peer(p, "committed-window-binding-failed", Z6II_BA2_CPU_BUS_FAULT);
        return;
    }
    Z6IIBA2CPUResult result = z6ii_ba2_cpu_run(&p->cpu, slice);
    release_slice_windows(p, maps, sections, count, true);
    if (result != Z6II_BA2_CPU_BUDGET) {
        stop_peer(p, "original-core-stop", result);
    } else if (p->config.total_steps && p->cpu.retired >= p->config.total_steps) {
        stop_peer(p, "total-step-budget", result);
    } else {
        schedule_peer(p);
    }
}

static void reset_peer(void *opaque)
{
    Z6IIBA2QEMU78 *p = opaque;
    timer_del(p->timer);
    p->state = PEER_HOLD;
    p->pending_token = 0;
    p->window_binding_commits = 0;
    p->bridge_repeated_10478_writes = 0;
    p->bridge_repeated_10478_suppressed = 0;
    p->window_wait_polls = 0;
    p->window_wait_reported = false;
    p->source_valid = false;
    memset(p->source_sha, 0, sizeof(p->source_sha));
    memset(&p->cpu, 0, sizeof(p->cpu));
    memset(&p->irq138, 0, sizeof(p->irq138));
    memset(&p->tick139, 0, sizeof(p->tick139));
    memset(&p->engine140, 0, sizeof(p->engine140));
    p->tick139_last_ns = 0;
    z6ii_ba2_controller136_reset(&p->controller);
    memset(&p->controller, 0, sizeof(p->controller));
    memset(&p->bridge, 0, sizeof(p->bridge));
    memset(&p->bus, 0, sizeof(p->bus));
    memset(p->ram, 0, p->config.ram_bytes);
    memset(p->payload, 0, Z6II_BA2_PAYLOAD_BYTES);
    if (p->config.spr_reset) {
        p->config.spr_reset(p->config.spr_opaque);
    }
    fprintf(stderr, "Z6II_BA2_PEER_RESET state=hold-until-verified-copy"
        " reset_release_verified=0 ram_policy=synthetic-zero-v1"
        " master_FIFO_reset_here=0 guest_writes=0\n");
}

Z6IIBA2QEMU78 *z6ii_ba2_qemu78_create(const Z6IIBA2QEMU78Config *c,
    bool functional_master, Z6IIIPU2402 *master_fifo,
    Z6IIBA2MasterIRQUpdateFn update, void *irq_opaque, Error **errp)
{
    if (!c || !c->mode) {
        return NULL;
    }
    if (!functional_master || !master_fifo || !update ||
        !policy(c->mode, "reset-after-verified-copy-v1") ||
        c->program_base != 0x40000000 || c->reset_pc != 0x40000008 ||
        c->ram_base != 0x60000000 || c->ram_bytes != 0x44000 ||
        c->copy_channel > 3 || !c->slice_steps || c->slice_steps > 65536 ||
        c->total_steps > 10000000 ||
        !c->timer_period_ns || c->timer_period_ns > 1000000000 ||
        (c->data_endian != Z6II_BA2_DATA_LE && c->data_endian != Z6II_BA2_DATA_BE) ||
        !policy(c->ram_policy, "synthetic-zero-v1") ||
        !policy(c->register_policy, "synthetic-zero-v1") ||
        (!policy(c->controller_policy, "stop-on-access-v1") &&
         !policy(c->controller_policy, Z6II_BA2_CONTROLLER136_POLICY)) ||
        (!policy(c->irq_policy, "absent-v1") &&
         !(policy(c->irq_policy, "fifo-level-stop-v1") &&
           policy(c->controller_policy, Z6II_BA2_CONTROLLER136_POLICY)) &&
         !(policy(c->irq_policy, IRQ138_POLICY) &&
           policy(c->controller_policy, Z6II_BA2_CONTROLLER136_POLICY))) ||
        (policy(c->irq_policy, IRQ138_POLICY) &&
         (!c->startup_isa_policy || !c->irq_basis || !c->irq_basis[0] ||
          !!(c->irq_sr11_initial & 4) != c->startup_irq_initial_enabled)) ||
        (!policy(c->irq_policy, IRQ138_POLICY) &&
         (c->irq_basis || c->irq_sr11_initial)) ||
        (c->tick139_policy &&
         (!policy(c->tick139_policy, Z6II_BA2_TICK139_POLICY) ||
          !policy(c->irq_policy, IRQ138_POLICY) ||
          c->tick139_source_hz != UINT64_C(400000000) ||
          !c->tick139_basis || !c->tick139_basis[0])) ||
        (!c->tick139_policy &&
         (c->tick139_source_hz || c->tick139_initial_source_cycles || c->tick139_basis)) ||
        (policy(c->controller_policy, Z6II_BA2_CONTROLLER136_POLICY) &&
         master_fifo->signature != 0x100) ||
        (c->entri4_policy &&
         !policy(c->entri4_policy, "predecrement-candidate-v1")) ||
        (c->entri1n1_policy &&
         !policy(c->entri1n1_policy, "predecrement-local-word-candidate-v1")) ||
        (c->entri1n_policy &&
         !policy(c->entri1n_policy, "entri1n-single-LR-Nword-v1")) ||
        (c->jr9_policy && !policy(c->jr9_policy, "direct-r9-candidate-v1")) ||
        (c->reti1n1_policy && !policy(c->reti1n1_policy, "inverse-local-word-candidate-v1")) ||
        (c->divu337_policy && !policy(c->divu337_policy, "nonzero-uint32-candidate-v1")) ||
        (c->movi_d7g3_policy && !policy(c->movi_d7g3_policy, "exact-GNU-transformed3-candidate-v1")) ||
        (c->movi_nontrap_policy && !policy(c->movi_nontrap_policy, "GNU-signed4-nontrap-candidate-v1")) ||
        (c->mov_gpr_policy && !policy(c->mov_gpr_policy, "bt-mov-gpr-v1")) ||
        (c->bt_add_gpr_policy && !policy(c->bt_add_gpr_policy, "bt-add-gpr-v1")) ||
        (c->bt_add_bn_addc_pair_policy && !policy(c->bt_add_bn_addc_pair_policy, "exact-D8EE-D8F0-carry-candidate-v1")) ||
        (c->bg_beq_gpr_policy && !policy(c->bg_beq_gpr_policy, "bg-beq-gpr-v1")) ||
        (c->bg_bgeu_gpr_policy && !policy(c->bg_bgeu_gpr_policy, "bg-bgeu-gpr-v1")) ||
        (c->startup_isa_policy && !policy(c->startup_isa_policy, "startup-ISA-v1")) ||
        (c->startup_isa_policy &&
         (!c->startup_irq_reset_basis || !c->startup_irq_reset_basis[0])) ||
        (!c->startup_isa_policy && c->startup_irq_reset_basis) ||
        (c->startup_bridge_policy &&
         (!policy(c->startup_bridge_policy, Z6II_BA2_STARTUP_BRIDGE137_POLICY) ||
          !c->startup_isa_policy ||
          !policy(c->controller_policy, Z6II_BA2_CONTROLLER136_POLICY) ||
          !c->startup_bridge_basis || !c->startup_bridge_basis[0])) ||
        (!c->startup_bridge_policy &&
         (c->startup_bridge_basis || c->startup_spr4800_initial)) ||
        (c->window_policy &&
         (!policy(c->window_policy, Z6II_BA2_WINDOW98_POLICY) ||
          !c->startup_bridge_policy || c->allow_unaligned_data)) ||
        (c->transaction_config_policy &&
         (!policy(c->transaction_config_policy, TRANSACTION_CONFIG_POLICY) ||
          !c->startup_bridge_policy || c->allow_unaligned_data)) ||
        (c->engine140_policy &&
         (!policy(c->engine140_policy, ENGINE140_POLICY) || !c->window_policy ||
          !c->transaction_config_policy || !policy(c->irq_policy, IRQ138_POLICY) ||
          !c->engine140_basis || !c->engine140_basis[0] ||
          c->data_endian != Z6II_BA2_DATA_LE || c->allow_unaligned_data)) ||
        (!c->engine140_policy &&
         (c->engine140_basis || c->engine140_backend_policy)) ||
        (c->engine140_backend_policy &&
         (!policy(c->engine140_backend_policy, Z6II_BA2_ENGINE140_OPAQUE_POLICY) ||
          c->engine140_backend_bytes != Z6II_BA2_ENGINE140_OPAQUE_BYTES ||
          !c->engine140_backend_basis || !c->engine140_backend_basis[0])) ||
        (!c->engine140_backend_policy &&
         (c->engine140_backend_bytes || c->engine140_backend_basis)) ||
        (c->msw_c0_policy && !policy(c->msw_c0_policy, "bn-msw-C0-two-word-v1")) ||
        (c->mlwz_c0_policy && !policy(c->mlwz_c0_policy, "bn-mlwz-C0-two-word-v1")) ||
        (c->sub_subb_pair_policy && !policy(c->sub_subb_pair_policy, "exact-D8D9-D8DC-borrow-candidate-v1")) ||
        (c->sub_subb_pair2_policy && !policy(c->sub_subb_pair2_policy, "exact-D8DF-D8E2-borrow-candidate-v1")) ||
        ((c->spr_read || c->spr_write || c->spr_reset || c->spr_basis) &&
         (!c->spr_read || !c->spr_write || !c->spr_reset ||
          !c->spr_basis || !c->spr_basis[0]))) {
        error_setg(errp, "BA2 reset probe requires explicit valid layout, policies,"
            " bounded timer configuration and functional Master fifo-v1");
        return NULL;
    }
    Z6IIBA2QEMU78 *p = g_new0(Z6IIBA2QEMU78, 1);
    p->config = *c;
    p->master_fifo = master_fifo;
    p->master_irq_update = update;
    p->master_irq_opaque = irq_opaque;
    p->payload = g_malloc0(Z6II_BA2_PAYLOAD_BYTES);
    p->ram = g_malloc0(c->ram_bytes);
    p->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, run_slice, p);
    p->exit_notifier.notify = peer_exit_snapshot;
    qemu_add_exit_notifier(&p->exit_notifier);
    qemu_register_reset(reset_peer, p);
    reset_peer(p);
    fprintf(stderr, "Z6II_BA2_PEER_MODEL mode=%s program_base=%08x reset_pc=%08x"
        " ram_base=%08x ram_bytes=%zx endian=%s allow_unaligned=%u"
        " copy_channel=%u slice=%u total=%" PRIu64 " period_ns=%" PRIu64
        " RAM_binding_verified=0 register_reset_verified=0"
        " reset_release_verified=0 controller=%s IRQ=%s"
        " IRQ_vector=%08x IRQ_SR11_initial=%08x IRQ_basis=%s"
        " execution_policy=%s"
        " linked_FIFO_in_use=%u command1_generated_at_init=0 command900F_generated_at_init=0"
        " entri4_policy=%s entri4_silicon_stack_order_verified=0"
        " entri1n1_policy=%s entri1n1_silicon_stack_and_local_word_verified=0"
        " entri1n_policy=%s entri1n_silicon_stack_and_Nword_verified=0"
        " jr9_policy=%s jr9_next_fetch_fault_timing_silicon_verified=0"
        " divu337_policy=%s divu_flags_and_div0_silicon_verified=0"
        " movi_d7g3_policy=%s movi_flags_and_latency_silicon_verified=0"
        " movi_nontrap_policy=%s movi_D0_traps=unsupported"
        " mov_gpr_policy=%s mov_gpr_D0_aliases=unsupported"
        " bt_add_gpr_policy=%s bt_add_gpr_D0_aliases=unsupported bt_add_gpr_silicon_flags_verified=0"
        " bt_add_bn_addc_pair_policy=%s bt_add_bn_addc_pair_silicon_carry_verified=0"
        " bg_beq_gpr_policy=%s bg_beq_gpr_flags=unchanged"
        " bg_bgeu_gpr_policy=%s bg_bgeu_gpr_flags=unchanged"
        " startup_isa_policy=%s"
        " startup_irq_initial_enabled=%u startup_irq_reset_basis=%s"
        " startup_bridge_policy=%s SPR4800_initial=%08x"
        " startup_bridge_basis=%s window_policy=%s window_mapping_silicon_verified=0"
        " transaction_config_policy=%s"
        " msw_c0_policy=%s msw_C0_two_word_silicon_semantics_verified=0"
        " mlwz_c0_policy=%s mlwz_C0_two_word_silicon_semantics_verified=0"
        " sub_subb_pair_policy=%s sub_subb_pair_silicon_carry_borrow_verified=0"
        " sub_subb_pair2_policy=%s sub_subb_pair2_silicon_carry_borrow_verified=0"
        " reti1n1_policy=%s reti1n1_silicon_return_verified=0 SPR_basis=%s\n",
        c->mode, c->program_base, c->reset_pc, c->ram_base, c->ram_bytes,
        c->data_endian == Z6II_BA2_DATA_LE ? "le" : "be",
        c->allow_unaligned_data, c->copy_channel, c->slice_steps,
        c->total_steps, c->timer_period_ns,
        c->controller_policy, c->irq_policy,
        policy(c->irq_policy, IRQ138_POLICY) ? Z6II_BA2_IRQ138_VECTOR : 0,
        c->irq_sr11_initial, c->irq_basis ? c->irq_basis : "absent",
        c->total_steps ? "finite-step-observation" : "continuous-bounded-slices",
        policy(c->controller_policy, Z6II_BA2_CONTROLLER136_POLICY),
        c->entri4_policy ? c->entri4_policy : "disabled",
        c->entri1n1_policy ? c->entri1n1_policy : "disabled",
        c->entri1n_policy ? c->entri1n_policy : "disabled",
        c->jr9_policy ? c->jr9_policy : "disabled",
        c->divu337_policy ? c->divu337_policy : "disabled",
        c->movi_d7g3_policy ? c->movi_d7g3_policy : "disabled",
        c->movi_nontrap_policy ? c->movi_nontrap_policy : "disabled",
        c->mov_gpr_policy ? c->mov_gpr_policy : "disabled",
        c->bt_add_gpr_policy ? c->bt_add_gpr_policy : "disabled",
        c->bt_add_bn_addc_pair_policy ? c->bt_add_bn_addc_pair_policy : "disabled",
        c->bg_beq_gpr_policy ? c->bg_beq_gpr_policy : "disabled",
        c->bg_bgeu_gpr_policy ? c->bg_bgeu_gpr_policy : "disabled",
        c->startup_isa_policy ? c->startup_isa_policy : "disabled",
        c->startup_irq_initial_enabled,
        c->startup_irq_reset_basis ? c->startup_irq_reset_basis : "unknown",
        c->startup_bridge_policy ? c->startup_bridge_policy : "disabled",
        c->startup_spr4800_initial,
        c->startup_bridge_basis ? c->startup_bridge_basis : "absent",
        c->window_policy ? c->window_policy : "disabled",
        c->transaction_config_policy ? c->transaction_config_policy : "disabled",
        c->msw_c0_policy ? c->msw_c0_policy : "disabled",
        c->mlwz_c0_policy ? c->mlwz_c0_policy : "disabled",
        c->sub_subb_pair_policy ? c->sub_subb_pair_policy : "disabled",
        c->sub_subb_pair2_policy ? c->sub_subb_pair2_policy : "disabled",
        c->reti1n1_policy ? c->reti1n1_policy : "disabled",
        c->spr_basis ? c->spr_basis : "absent; unknown-selector-hard-stop");
    fprintf(stderr, "Z6II_BA2_TICK139_INPUT policy=%s source_hz=%" PRIu64
        " initial_source_cycles=%" PRIu64 " time_source=qemu-virtual-ns"
        " vector=%08x retired_instruction_clock=0 basis=%s\n",
        c->tick139_policy ? c->tick139_policy : "disabled",
        c->tick139_source_hz, c->tick139_initial_source_cycles,
        c->tick139_policy ? Z6II_BA2_TICK139_VECTOR : 0,
        c->tick139_basis ? c->tick139_basis : "disabled");
    fprintf(stderr, "Z6II_BA2_ENGINE140_INPUT policy=%s backend=%s bytes=%u"
        " basis=%s backend_basis=%s mode9_transform_verified=0\n",
        c->engine140_policy ? c->engine140_policy : "disabled",
        c->engine140_backend_policy ? c->engine140_backend_policy : "strict-reject",
        c->engine140_backend_bytes, c->engine140_basis ? c->engine140_basis : "absent",
        c->engine140_backend_basis ? c->engine140_backend_basis : "absent");
    return p;
}

void z6ii_ba2_qemu78_destroy(Z6IIBA2QEMU78 *p)
{
    if (!p) {
        return;
    }
    qemu_unregister_reset(reset_peer, p);
    qemu_remove_exit_notifier(&p->exit_notifier);
    timer_del(p->timer);
    timer_free(p->timer);
    g_free(p->payload);
    g_free(p->ram);
    g_free(p);
}

uint64_t z6ii_ba2_qemu78_copy_pre(void *opaque, unsigned ch, uint32_t src,
                                uint32_t dst, uint32_t len)
{
    Z6IIBA2QEMU78 *p = opaque;
    if (!p || ch != p->config.copy_channel || src != PAYLOAD_SRC ||
        dst != PAYLOAD_DST || len != Z6II_BA2_PAYLOAD_BYTES) {
        return 0;
    }
    if (p->state != PEER_HOLD || p->pending_token || p->sequence == UINT64_MAX) {
        stop_peer(p, "duplicate-or-unpaired-copy", Z6II_BA2_CPU_BAD_CONFIG);
        return 0;
    }
    p->pending_token = ++p->sequence;
    p->source_valid = direct_sha(p, src, len, true, p->source_sha);
    fprintf(stderr, "Z6II_BA2_PAYLOAD_PRE token=%" PRIu64
        " ch=%u source=%08x destination=%08x bytes=%x direct_ROM=%u sha=%s\n",
        p->pending_token, ch, src, dst, len, p->source_valid,
        p->source_valid ? p->source_sha : "unavailable");
    return p->pending_token;
}

void z6ii_ba2_qemu78_copy_post(void *opaque, uint64_t token, unsigned ch,
    uint32_t src, uint32_t dst, const uint8_t *actual_buffer, uint32_t len)
{
    Z6IIBA2QEMU78 *p = opaque;
    if (!p || !token) {
        return;
    }
    if (p->state != PEER_HOLD || token != p->pending_token ||
        ch != p->config.copy_channel || src != PAYLOAD_SRC ||
        dst != PAYLOAD_DST || len != Z6II_BA2_PAYLOAD_BYTES || !actual_buffer) {
        stop_peer(p, "copy-post-identity-mismatch", Z6II_BA2_CPU_BAD_CONFIG);
        return;
    }
    char destination_sha[65] = { 0 };
    char *buffer_sha = g_compute_checksum_for_data(G_CHECKSUM_SHA256,
                                                  actual_buffer, len);
    bool destination_valid = direct_sha(p, dst, len, false, destination_sha);
    bool verified = p->source_valid && destination_valid &&
        !strcmp(p->source_sha, EXPECTED_SHA) && !strcmp(buffer_sha, EXPECTED_SHA) &&
        !strcmp(destination_sha, EXPECTED_SHA);
    fprintf(stderr, "Z6II_BA2_PAYLOAD_POST token=%" PRIu64
        " source_pre_sha=%s actual_buffer_sha=%s destination_post_sha=%s"
        " direct_RAM=%u verified=%u guest_writes_here=0\n", token,
        p->source_valid ? p->source_sha : "unavailable", buffer_sha,
        destination_valid ? destination_sha : "unavailable",
        destination_valid, verified);
    g_free(buffer_sha);
    p->pending_token = 0;
    if (!verified) {
        stop_peer(p, "payload-verification-failed", Z6II_BA2_CPU_BAD_CONFIG);
        return;
    }
    memcpy(p->payload, actual_buffer, len);
    p->ram_map = (Z6IIBA2MemoryMap) {
        .base = p->config.ram_base, .size = p->config.ram_bytes,
        .bytes = p->ram, .writable_bytes = p->ram,
        .permissions = Z6II_BA2_MEM_READ | Z6II_BA2_MEM_WRITE,
        .mapping_basis = "static-link-layout; private synthetic-zero-v1; external-binding-unproved",
    };
    Z6IIBA2BusConfig bus_config = {
        .payload = {
            .base = p->config.program_base, .size = len, .bytes = p->payload,
            .permissions = Z6II_BA2_MEM_READ | Z6II_BA2_MEM_EXEC,
            .mapping_basis = "original-payload triple-SHA; static-link-base; external-binding-unproved",
        },
        .ram = &p->ram_map, .ram_count = 1,
        .mmio = {
            .base = p->config.startup_bridge_policy ? Z6II_BA2_STARTUP_BRIDGE137_BASE :
                                                     Z6II_BA2_CONTROLLER136_BASE,
            .size = p->config.startup_bridge_policy ? Z6II_BA2_STARTUP_BRIDGE137_BYTES :
                                                     Z6II_BA2_CONTROLLER136_BYTES,
            .read = controller_read, .write = controller_write, .opaque = p,
            .peer_irq = (policy(p->config.irq_policy, "fifo-level-stop-v1") ||
                         policy(p->config.irq_policy, IRQ138_POLICY)) ? controller_irq : NULL,
            .mapping_basis = p->config.startup_bridge_policy ? p->config.startup_bridge_basis :
                                                              p->config.controller_policy,
        },
        .data_endian = p->config.data_endian,
        .allow_unaligned_data = p->config.allow_unaligned_data,
        .master_fifo = p->master_fifo,
        .fifo_binding_basis = "explicit Master-owned FIFO endpoint; original-triplet transport candidate",
        .master_irq_update = p->master_irq_update,
        .master_irq_opaque = p->master_irq_opaque,
    };
    uint32_t initial_r[32] = { 0 };
    Z6IIBA2BusResult bus_result = z6ii_ba2_bus_init(&p->bus, &bus_config);
    Z6IIBA2CPUResult result = Z6II_BA2_CPU_BAD_CONFIG;
    if (bus_result == Z6II_BA2_BUS_OK &&
        policy(p->config.controller_policy, Z6II_BA2_CONTROLLER136_POLICY)) {
        bus_result = z6ii_ba2_controller136_init(&p->controller, &p->bus,
            p->config.controller_policy,
            "original BA2 register shape and unchanged three-word transport; silicon wiring unproved");
    }
    if (bus_result == Z6II_BA2_BUS_OK) {
        if (p->config.startup_bridge_policy) {
            bus_result = z6ii_ba2_startup_bridge137_init(&p->bridge, &p->controller,
                p->master_fifo, p->config.startup_bridge_policy,
                p->config.startup_spr4800_initial, p->config.startup_bridge_basis);
        }
    }
    if (bus_result == Z6II_BA2_BUS_OK) {
        if (p->config.transaction_config_policy) {
            bus_result = z6ii_ba2_startup_bridge137_enable_transaction_config_candidate(
                &p->bridge, "original 4000BAB4..4000BC96 configuration function;"
                " exact-address raw32 latches; no DMA, IRQ, Ready or protocol reply");
        }
    }
    if (bus_result == Z6II_BA2_BUS_OK && p->config.engine140_policy) {
        bus_result = z6ii_ba2_engine140_init(&p->engine140, &p->bus,
            &p->bridge, p->config.engine140_basis);
        if (bus_result == Z6II_BA2_BUS_OK && p->config.engine140_backend_policy) {
            bus_result = z6ii_ba2_engine140_enable_opaque_synthetic(&p->engine140,
                p->config.engine140_backend_policy, p->config.engine140_backend_bytes,
                p->config.engine140_backend_basis);
        }
    }
    if (bus_result == Z6II_BA2_BUS_OK) {
        result = z6ii_ba2_cpu_init(&p->cpu, p->config.reset_pc, initial_r,
            "synthetic-zero-v1; original reset vector; silicon-release-and-register-reset-unproved",
            z6ii_ba2_bus_fetch, z6ii_ba2_bus_read, z6ii_ba2_bus_write,
            z6ii_ba2_bus_irq, &p->bus);
    }
    if (result != Z6II_BA2_CPU_OK) {
        stop_peer(p, "peer-init-failed", result);
        return;
    }
    z6ii_ba2_cpu_set_spr_callbacks(&p->cpu, peer_spr_read, peer_spr_write, p);
    if (p->config.entri4_policy) {
        result = z6ii_ba2_cpu_enable_entri4_candidate(&p->cpu,
            p->config.startup_isa_policy ? z6ii_ba2_startup_ram_write_batch :
                                          z6ii_ba2_bus_write_ram_batch, &p->bus,
            "predecrement-candidate-v1; F4/N0; r9..r12 at old-SP-4..16;"
            " old-decoder-TODO and ABI candidate; silicon slot order unproved");
        if (result != Z6II_BA2_CPU_OK) {
            stop_peer(p, "entri4-candidate-init-failed", result);
            return;
        }
    }
    if (p->config.entri1n1_policy) {
        result = z6ii_ba2_cpu_enable_entri1n1_candidate(&p->cpu,
            z6ii_ba2_bus_write_ram_batch, &p->bus,
            "predecrement-local-word-candidate-v1; F1/N1; r9 at old-SP-4;"
            " reserved old-SP-8; silicon slot order and local word unproved");
        if (result != Z6II_BA2_CPU_OK) {
            stop_peer(p, "entri1n1-candidate-init-failed", result);
            return;
        }
    }
    /* F1/N0..255 uses its own RAM-only callback and remains opt-in. */
    if (p->config.entri1n_policy) {
        result = z6ii_ba2_cpu_enable_entri1n_candidate(&p->cpu,
            z6ii_ba2_bus_write_ram_batch, &p->bus,
            "entri1n-single-LR-Nword-v1; F1/N0..255; save RAM[oldSP-4];"
            " reserve N local words without writes; no IRQ/status inference");
        if (result != Z6II_BA2_CPU_OK) {
            stop_peer(p, "entri1n-candidate-init-failed", result);
            return;
        }
    }
    if (p->config.jr9_policy) {
        result = z6ii_ba2_cpu_enable_jr9_candidate(&p->cpu,
            "direct-r9-candidate-v1; fixed GNU A9 and public r9,pc,=;"
            " next-fetch fault timing remains existing software-core contract");
        if (result != Z6II_BA2_CPU_OK) {
            stop_peer(p, "jr9-candidate-init-failed", result);
            return;
        }
    }
    if (p->config.reti1n1_policy) {
        result = z6ii_ba2_cpu_enable_reti1n1_candidate(&p->cpu,
            z6ii_ba2_reti_ram_read32, &p->bus,
            "inverse-local-word-candidate-v1; ordinary RAM[SP+4] return;"
            " no ROM/MMIO fallback or inferred IRQ/flags");
        if (result != Z6II_BA2_CPU_OK) {
            stop_peer(p, "reti1n1-candidate-init-failed", result);
            return;
        }
    }
    if (p->config.divu337_policy) {
        result = z6ii_ba2_cpu_enable_divu_candidate(&p->cpu,
            "nonzero-uint32-candidate-v1; exact GNU D3/A3/B7; snapshot operands;"
            " div0 and signed div hard-stop; flags/latency/silicon behavior unproved");
        if (result != Z6II_BA2_CPU_OK) {
            stop_peer(p, "divu337-candidate-init-failed", result);
            return;
        }
    }
    if (p->config.movi_d7g3_policy) {
        result = z6ii_ba2_cpu_enable_movi_d7g3_candidate(&p->cpu,
            "exact-GNU-transformed3-candidate-v1; bt.movi D7/G3;"
            " GNU LSB swizzle/sign4/shift0; flags/latency silicon behavior unproved");
        if (result != Z6II_BA2_CPU_OK) {
            stop_peer(p, "movi-d7g3-candidate-init-failed", result);
            return;
        }
    }
    if (p->config.movi_nontrap_policy) {
        result = z6ii_ba2_cpu_enable_movi_nontrap_candidate(&p->cpu,
            "GNU-signed4-nontrap-candidate-v1; bt.movi D1..31/G-8..7;"
            " D0 traps hard-stop; state/flags are explicit software policy");
        if (result != Z6II_BA2_CPU_OK) {
            stop_peer(p, "movi-nontrap-candidate-init-failed", result);
            return;
        }
    }
    if (p->config.mov_gpr_policy) {
        result = z6ii_ba2_cpu_enable_mov_gpr_candidate(&p->cpu,
            "bt-mov-gpr-v1; bt.mov D1..31/A0..31; snapshot uint32 source;"
            " D0 aliases hard-stop; no inferred flags/SPR/IRQ effects");
        if (result != Z6II_BA2_CPU_OK) {
            stop_peer(p, "mov-gpr-candidate-init-failed", result);
            return;
        }
    }
    if (p->config.bt_add_gpr_policy) {
        result = z6ii_ba2_cpu_enable_bt_add_gpr_candidate(&p->cpu,
            "bt-add-gpr-v1; fixed GNU D/A fields and public oldD+oldA uint32 GPR sum;"
            " D0 aliases hard-stop; silicon flags unproved");
        if (result != Z6II_BA2_CPU_OK) {
            stop_peer(p, "bt-add-gpr-candidate-init-failed", result);
            return;
        }
    }
    if (p->config.bt_add_bn_addc_pair_policy) {
        result = z6ii_ba2_cpu_enable_bt_add_bn_addc_pair_candidate(&p->cpu,
            "exact-D8EE-D8F0-carry-candidate-v1; original adjacent low/high add pair;"
            " bit32 predecessor carry credential; silicon carry unproved");
        if (result != Z6II_BA2_CPU_OK) {
            stop_peer(p, "bt-add-bn-addc-pair-candidate-init-failed", result);
            return;
        }
    }
    if (p->config.bg_beq_gpr_policy) {
        result = z6ii_ba2_cpu_enable_bg_beq_gpr_candidate(&p->cpu,
            "bg-beq-gpr-v1; fixed GNU A/B and signed12 relative U; public register equality;"
            " taken oldPC+U uint32, otherwise oldPC+4; snapshot flags unchanged");
        if (result != Z6II_BA2_CPU_OK) {
            stop_peer(p, "bg-beq-gpr-candidate-init-failed", result);
            return;
        }
    }
    if (p->config.bg_bgeu_gpr_policy) {
        result = z6ii_ba2_cpu_enable_bg_bgeu_gpr_candidate(&p->cpu,
            "bg-bgeu-gpr-v1; public unsigned GPR compare and GNU relative branch fields");
        if (result != Z6II_BA2_CPU_OK) {
            stop_peer(p, "bg-bgeu-gpr-candidate-init-failed", result);
            return;
        }
    }
    if (p->config.startup_isa_policy) {
        z6ii_ba2_cpu_set_startup_irq_mask_snapshot(&p->cpu,
            p->config.startup_irq_initial_enabled, p->config.startup_irq_reset_basis);
        result = z6ii_ba2_cpu_enable_startup_isa_candidate(&p->cpu,
            z6ii_ba2_startup_ram_read_batch, &p->bus,
            "startup-ISA-v1; continuous original reset path; staged ordinary RAM returns;"
            " original bytes; unknown ISA/SPR/device still stop");
        if (result != Z6II_BA2_CPU_OK) {
            stop_peer(p, "startup-isa-candidate-init-failed", result);
            return;
        }
    }
    if (p->config.msw_c0_policy) {
        result = z6ii_ba2_cpu_enable_msw_c0_candidate(&p->cpu,
            p->config.startup_isa_policy ? z6ii_ba2_startup_ram_write_batch :
                                          z6ii_ba2_bus_write_ram_batch, &p->bus,
            "bn-msw-C0-two-word-v1; C0 RAM-only old-base/source-pair snapshot;"
            " original paired-word dataflow candidate; silicon semantics unproved");
        if (result != Z6II_BA2_CPU_OK) {
            stop_peer(p, "msw-c0-candidate-init-failed", result);
            return;
        }
    }
    if (p->config.mlwz_c0_policy) {
        result = z6ii_ba2_cpu_enable_mlwz_c0_candidate(&p->cpu,
            p->config.startup_isa_policy ? z6ii_ba2_startup_ram_read_batch :
                                          z6ii_ba2_mlwz_ram_read_pair, &p->bus,
            "bn-mlwz-C0-two-word-v1; C0 RAM-only old-base snapshot;"
            " precheck both words before staged GPR commit; silicon semantics unproved");
        if (result != Z6II_BA2_CPU_OK) {
            stop_peer(p, "mlwz-c0-candidate-init-failed", result);
            return;
        }
    }
    if (p->config.sub_subb_pair_policy) {
        result = z6ii_ba2_cpu_enable_sub_subb_pair_candidate(&p->cpu,
            "exact-D8D9-D8DC-borrow-candidate-v1; original adjacent low/high pair;"
            " predecessor provenance required; silicon carry/borrow unproved");
        if (result != Z6II_BA2_CPU_OK) {
            stop_peer(p, "sub-subb-pair-candidate-init-failed", result);
            return;
        }
    }
    if (p->config.sub_subb_pair2_policy) {
        result = z6ii_ba2_cpu_enable_sub_subb_pair2_candidate(&p->cpu,
            "exact-D8DF-D8E2-borrow-candidate-v1; original adjacent low/high pair;"
            " predecessor provenance required; silicon carry/borrow unproved");
        if (result != Z6II_BA2_CPU_OK) {
            stop_peer(p, "sub-subb-pair2-candidate-init-failed", result);
            return;
        }
    }
    if (policy(p->config.irq_policy, IRQ138_POLICY)) {
        result = z6ii_ba2_cpu_enable_irq138_candidate(&p->cpu, &p->irq138,
            Z6II_BA2_IRQ138_VECTOR, p->config.irq_sr11_initial,
            z6ii_ba2_startup_ram_read_batch, z6ii_ba2_startup_ram_write_batch,
            &p->bus, p->config.irq_basis);
        if (result != Z6II_BA2_CPU_OK) {
            stop_peer(p, "vector38-irq-candidate-init-failed", result);
            return;
        }
    }
    if (p->config.engine140_policy &&
        z6ii_ba2_irq138_bind_external_sources(&p->irq138, controller_irq_sources, p,
            "original-7386-FIFO-bit1-7392-engine-bit0; explicit-device-source-bitmap")
            != Z6II_BA2_CPU_OK) {
        stop_peer(p, "external-source-bitmap-init-failed", Z6II_BA2_CPU_BAD_CONFIG);
        return;
    }
    if (p->config.tick139_policy) {
        if (z6ii_ba2_tick139_init(&p->tick139, p->config.tick139_source_hz,
                p->config.tick139_initial_source_cycles, p->config.tick139_basis)
                != Z6II_BA2_SPR_OK ||
            z6ii_ba2_irq138_bind_tick139_candidate(&p->irq138, &p->tick139,
                Z6II_BA2_TICK139_VECTOR, p->config.tick139_basis)
                != Z6II_BA2_CPU_OK) {
            stop_peer(p, "periodic-clock-init-failed", Z6II_BA2_CPU_BAD_CONFIG);
            return;
        }
        p->tick139_last_ns = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    }
    p->state = PEER_RUNNING;
    fprintf(stderr, "Z6II_BA2_PEER_START token=%" PRIu64 " pc=%08x"
        " original_vector=1 payload_sha=%s data_pre_copied=0 firmware_BSS_clear_executed=0"
        " SP_GP_host_assigned=0 reset_release_verified=0\n",
        token, p->cpu.pc, EXPECTED_SHA);
    schedule_peer(p);
}
