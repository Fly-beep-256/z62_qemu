/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Independent opt-in functional capture/ISP. Original MMIO submissions own
 * all DMA destinations. No application state, GUI or resource table writes.
 * IRQ99 causes 2/1000 and IRQ102 bank causes 4/8 remain Z6-derived candidate
 * contracts; adapter tests do not establish acceptance by Z6II firmware. */

typedef struct Z6IIBayerSpan {
    uint32_t address;
    uint64_t length;
    uintptr_t host;
} Z6IIBayerSpan;

static bool z6ii_bayer_span(Z6IIFunctionalDevices *s, uint32_t address, uint64_t length,
                            Z6IIBayerSpan *span)
{
    if (!z6ii_lcd_read_ram(s, address, NULL, length)) { return false; }
    MemoryRegionSection section = memory_region_find(s->engine->memory,
                                                    address, length);
    if (!section.mr) { return false; }
    *span = (Z6IIBayerSpan){address, length,
        (uintptr_t)memory_region_get_ram_ptr(section.mr) + section.offset_within_region};
    memory_region_unref(section.mr);
    return true;
}

static bool z6ii_bayer_overlap(const Z6IIBayerSpan *a, const Z6IIBayerSpan *b)
{
    /* Compare backing RAM, including aliases with different bus addresses. */
    return a->host < b->host + b->length && b->host < a->host + a->length;
}

static void z6ii_bayer_reject(Z6IIFunctionalDevices *s, const char *reason)
{
    ++s->bayer.rejected;
    if (s->bayer.rejected <= 16 || !(s->bayer.rejected & 255)) {
        fprintf(stderr, "Z6II_BAYER_REJECT reason=%s count=%" PRIu64
                " raw_pending=%u isp_pending=%u output_completion=0\n",
                reason, s->bayer.rejected, s->bayer.raw_pending,
                s->bayer.isp_job_pending);
    }
}

static void z6ii_bayer_cancel(Z6IIFunctionalDevices *s, bool drop_raw,
                              const char *reason)
{
    bool pending = s->bayer.isp_job_pending || (drop_raw && s->bayer.raw_pending);
    timer_del(s->bayer.timer);
    s->bayer.isp_job_pending = false;
    if (drop_raw) { s->bayer.raw_pending = false; }
    ++s->bayer.generation;
    if (pending) {
        fprintf(stderr, "Z6II_BAYER_CANCEL reason=%s generation=%" PRIu64
                " raw_pending=%u new_completion=0\n",
                reason, s->bayer.generation, s->bayer.raw_pending);
    }
}

static Z6IIBayerConfig z6ii_bayer_config(Z6IIFunctionalDevices *s)
{
    Z6IIBayerConfig c = {0};
    c.global_stop = s->capture_control[0] & 3;
    c.input = s->capture_control[2];
    memcpy(c.gates, s->capture_isp_gate, sizeof(c.gates));
    c.mode = s->capture_processing[0x1500 / 4];
    c.width = s->capture_processing[0x1504 / 4];
    c.height = s->capture_processing[0x1508 / 4];
    c.stride = s->capture_processing[0x1808 / 4];
    c.bank = s->capture_processing[0x183c / 4] & 1;
    for (unsigned f = 0; f < 4; ++f) {
        c.capture[f] = s->capture_processing[(0x1850 + c.bank*0x10 + f*4) / 4];
        c.source[f] = s->image_processor_config[0][0x310 / 4 + f];
        for (unsigned ch = 0; ch < 3; ++ch) {
            c.output[f][ch] = s->image_command_lists[0][f*16 + ch + 3];
        }
    }
    c.raw_enable = s->image_processor_config[0][8 / 4] & 1;
    c.raw_geometry = s->image_processor_config[0][0x48 / 4];
    c.raw_stride = s->image_processor_config[0][0x30c / 4];
    c.engine = s->engine_regs[1] & 1;
    c.command[0] = s->image_command_config[0][0] & 1;
    c.command[1] = s->image_command_config[1][0] & 1;
    c.sequence = s->image_sequence_config[8 / 4] & 1;
    for (unsigned ch = 0; ch < 3; ++ch) {
        memcpy(c.transfer[ch], s->image_transfer_config[ch + 3], sizeof(c.transfer[ch]));
    }
    return c;
}


/* Capture-tick snapshots only: distinct configurations, at most twelve.
 * This reports why an original submission is unavailable and never arms DMA. */
static void z6ii_bayer_blocked(Z6IIFunctionalDevices *s, unsigned reason)
{
    const Z6IIBayerConfig *c = &s->bayer.config;
    if (s->bayer.blocked_config_valid && s->bayer.blocked_reason == reason &&
        !memcmp(c, &s->bayer.last_blocked_config, sizeof(*c))) { return; }
    s->bayer.last_blocked_config = *c;
    s->bayer.blocked_config_valid = true;
    s->bayer.blocked_reason = reason;
    if (s->bayer.blocked_reports >= 12) { return; }
    ++s->bayer.blocked_reports;
    static const char *const names[] = {
        "unknown", "capture_not_ready", "stop_latched", "RAW_pending", "ISP_pending"
    };
    fprintf(stderr, "Z6II_BAYER_BLOCKED reason=%s report=%u limit=12 virtual_ns=%" PRId64
            " global_stop=%08x input=%08x gates=%08x,%08x,%08x mode=%08x"
            " width=%08x height=%08x stride=%u bank=%u capture=%08x,%08x,%08x,%08x"
            " raw_enable=%u raw_geometry=%08x raw_stride=%u engine=%u commands=%u,%u"
            " sequence=%u source=%08x,%08x,%08x,%08x stop_latched=%u"
            " raw_pending=%u isp_pending=%u frames=%" PRIu64,
            names[reason], s->bayer.blocked_reports, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
            c->global_stop, c->input, c->gates[0], c->gates[1], c->gates[2], c->mode,
            c->width, c->height, c->stride, c->bank,
            c->capture[0], c->capture[1], c->capture[2], c->capture[3],
            c->raw_enable, c->raw_geometry, c->raw_stride, c->engine,
            c->command[0], c->command[1], c->sequence,
            c->source[0], c->source[1], c->source[2], c->source[3],
            s->bayer.stop_latched, s->bayer.raw_pending, s->bayer.isp_job_pending,
            s->bayer.next_frame_id);
    for (unsigned f = 0; f < 4; ++f) {
        fprintf(stderr, " output%u=%08x,%08x,%08x", f,
                c->output[f][0], c->output[f][1], c->output[f][2]);
    }
    for (unsigned ch = 0; ch < 3; ++ch) {
        fprintf(stderr, " transfer%u=", ch + 3);
        for (unsigned i = 0; i < 13; ++i) {
            fprintf(stderr, "%s%08x", i ? "," : "", c->transfer[ch][i]);
        }
    }
    fprintf(stderr, " guest_writes=0\n");
}

static bool z6ii_bayer_capture_ready(const Z6IIBayerConfig *c)
{
    return c->input && !c->global_stop && !(c->gates[0] & 0x400) &&
           (c->gates[1] & 0x400) && (c->gates[2] & 0x400) &&
           c->mode == 0 && c->width == 0x07f20000 &&
           c->height == 0x059a0000 && c->stride == 4080;
}

static bool z6ii_bayer_descriptors(Z6IIFunctionalDevices *s,
                                   Z6IIBayerSpan inputs[4],
                                   Z6IIBayerSpan outputs[24])
{
    const Z6IIBayerConfig *c = &s->bayer.config;
    const uint64_t bytes = UINT64_C(4080) * 1434;
    if (!s->bayer.raw_pending || !z6ii_bayer_capture_ready(c) ||
        !c->raw_enable || !c->engine || !c->command[1] || !c->sequence) {
        return false;
    }
    if (c->raw_geometry != 0x07f2059a || c->raw_stride != 4080) {
        z6ii_bayer_reject(s, "ISP_RAW_format"); return false;
    }
    for (unsigned f = 0; f < 4; ++f) {
        if (c->source[f] != s->bayer.source[f] ||
            !z6ii_bayer_span(s, c->source[f], bytes, &inputs[f])) {
            z6ii_bayer_reject(s, "RAW_not_this_submission"); return false;
        }
    }
    for (unsigned f = 0; f < 4; ++f) {
        for (unsigned ch = 0; ch < 3; ++ch) {
            const uint32_t *r = c->transfer[ch];
            unsigned w = r[8] & 0x7fff, h = r[8] >> 16, stride = r[4];
            uint32_t dst = c->output[f][ch];
            uint64_t ybytes = (uint64_t)stride * h;
            uint64_t uv = (uint64_t)dst + r[10];
            unsigned i = (f*3 + ch)*2;
            if (r[0] != 0x09000201 || !w || !h || (w & 1) || (h & 1) ||
                w > 1920 || h > 1280 || stride < w || stride > 2048 ||
                r[10] < ybytes || uv > UINT32_MAX ||
                !z6ii_bayer_span(s, dst, ybytes, &outputs[i]) ||
                !z6ii_bayer_span(s, uv, ybytes / 2, &outputs[i + 1])) {
                z6ii_bayer_reject(s, "NV12_output_descriptor"); return false;
            }
        }
    }
    for (unsigned i = 0; i < 24; ++i) {
        for (unsigned j = 0; j < 4; ++j) {
            if (z6ii_bayer_overlap(&outputs[i], &inputs[j])) {
                z6ii_bayer_reject(s, "RAW_output_overlap"); return false;
            }
        }
        for (unsigned j = 0; j < i; ++j) {
            if (z6ii_bayer_overlap(&outputs[i], &outputs[j])) {
                z6ii_bayer_reject(s, "output_overlap"); return false;
            }
        }
    }
    return true;
}

static void z6ii_bayer_schedule(Z6IIFunctionalDevices *s)
{
    Z6IIBayerSpan inputs[4], outputs[24];
    if (!s->bayer.enabled || s->bayer.isp_job_pending ||
        !z6ii_bayer_descriptors(s, inputs, outputs)) { return; }
    s->bayer.isp_job_pending = true;
    s->bayer.armed_generation = s->bayer.generation;
    timer_mod(s->bayer.timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
              s->model->timing.isp_job_ns);
}

static void z6ii_bayer_capture_tick(Z6IIFunctionalDevices *s)
{
    if (!s->bayer.enabled || !s->capture_tg_running ||
        s->capture_tg_draining) { return; }
    s->bayer.config = z6ii_bayer_config(s);
    if (!z6ii_bayer_capture_ready(&s->bayer.config)) {
        z6ii_bayer_blocked(s, 1); return;
    }
    if (s->bayer.stop_latched) {
        const Z6IIBayerConfig *c = &s->bayer.config;
        if (!c->raw_enable || !c->engine || !c->command[1] || !c->sequence) {
            z6ii_bayer_blocked(s, 2); return;
        }
        s->bayer.stop_latched = false;
    }
    if (s->bayer.raw_pending || s->bayer.isp_job_pending) {
        z6ii_bayer_blocked(s, s->bayer.isp_job_pending ? 4 : 3);
        ++s->bayer.backpressure;
        if (s->bayer.backpressure <= 4 || !(s->bayer.backpressure & 255)) {
            fprintf(stderr, "Z6II_BAYER_BACKPRESSURE count=%" PRIu64
                    " overwritten_frames=0\n", s->bayer.backpressure);
        }
        return;
    }
    const size_t bytes = (size_t)4080 * 1434;
    Z6IIBayerSpan spans[4];
    for (unsigned f = 0; f < 4; ++f) {
        if (!z6ii_bayer_span(s, s->bayer.config.capture[f], bytes, &spans[f])) {
            z6ii_bayer_reject(s, "capture_RAM_extent"); return;
        }
        for (unsigned j = 0; j < f; ++j) {
            if (z6ii_bayer_overlap(&spans[f], &spans[j])) {
                z6ii_bayer_reject(s, "capture_ring_overlap"); return;
            }
        }
    }
    g_autofree uint8_t *raw = g_malloc(bytes);
    g_autofree uint8_t *check = g_malloc(bytes);
    uint64_t first_id = s->bayer.next_frame_id + 1;
    for (unsigned f = 0; f < 4; ++f) {
        uint64_t id = first_id + f;
        z6ii_bayer_generate(raw, id);
        if (address_space_write(&s->engine->as, spans[f].address,
                MEMTXATTRS_UNSPECIFIED, raw, bytes) != MEMTX_OK ||
            address_space_read(&s->engine->as, spans[f].address,
                MEMTXATTRS_UNSPECIFIED, check, bytes) != MEMTX_OK ||
            memcmp(raw, check, bytes)) {
            z6ii_bayer_reject(s, "capture_write_readback"); return;
        }
        g_autofree char *hash = g_compute_checksum_for_data(G_CHECKSUM_SHA256, check, bytes);
        s->bayer.source[f] = spans[f].address;
        s->bayer.frame_id[f] = id;
        g_strlcpy(s->bayer.sha[f], hash, sizeof(s->bayer.sha[f]));
        ++s->bayer.total_raw_frames;
        if (s->bayer.raw_batches < 2 || !(s->bayer.raw_batches & 255)) {
            fprintf(stderr, "Z6II_BAYER_RAW frame_id=%" PRIu64
                    " slot=%u destination=%08x bytes=%zu sha256=%s readback=1\n",
                    id, f, spans[f].address, bytes, hash);
        }
    }
    s->bayer.next_frame_id += 4;
    ++s->bayer.raw_batches;
    ++s->bayer.total_raw_batches;
    s->bayer.raw_pending = true;
    /* A RAW DMA really completed. This cause is separate from ISP output. */
    s->image_processor_config[0][0x24 / 4] |= 2;
    z6ii_fd_image_raw_irq(s);
    if (s->bayer.raw_batches <= 2 || !(s->bayer.raw_batches & 255)) {
        fprintf(stderr, "Z6II_BAYER_CAPTURE batches=%" PRIu64
                " frames=%" PRIu64 " bank=%u irq99_cause=2 candidate_contract=1\n",
                s->bayer.raw_batches, s->bayer.next_frame_id, s->bayer.config.bank);
    }
    z6ii_bayer_schedule(s);
}

static void z6ii_bayer_isp_tick(void *opaque)
{
    Z6IIFunctionalDevices *s = opaque;
    Z6IIBayerSpan inputs[4], outputs[24];
    if (!s->bayer.isp_job_pending ||
        s->bayer.armed_generation != s->bayer.generation) { return; }
    s->bayer.isp_job_pending = false;
    if (!z6ii_bayer_descriptors(s, inputs, outputs)) { return; }
    const size_t bytes = (size_t)4080 * 1434;
    g_autofree uint8_t *raw = g_malloc(bytes);
    g_autofree uint8_t *check = g_malloc(bytes);
    /* Check all inputs before any output writes. A modified DMA input cannot
     * masquerade as the source's last submitted batch. */
    for (unsigned f = 0; f < 4; ++f) {
        if (address_space_read(&s->engine->as, inputs[f].address,
                MEMTXATTRS_UNSPECIFIED, raw, bytes) != MEMTX_OK) { goto failed; }
        g_autofree char *hash = g_compute_checksum_for_data(G_CHECKSUM_SHA256, raw, bytes);
        if (strcmp(hash, s->bayer.sha[f])) { goto failed; }
    }
    if (!s->bayer.pixels) {
        s->bayer.pixels = nikon_isp_images_new(&z6ii_bayer_geometry, false);
    }
    if (!s->bayer.pixels) { goto failed; }
    for (unsigned f = 0; f < 4; ++f) {
        if (address_space_read(&s->engine->as, inputs[f].address,
                MEMTXATTRS_UNSPECIFIED, raw, bytes) != MEMTX_OK) { goto failed; }
        nikon_isp_images_input(s->bayer.pixels, raw);
        for (unsigned ch = 0; ch < 3; ++ch) {
            const uint32_t *r = s->bayer.config.transfer[ch];
            unsigned w = r[8] & 0x7fff, h = r[8] >> 16, stride = r[4];
            const uint8_t *image = nikon_isp_images_output(s->bayer.pixels, ch, w, h, stride);
            if (!image) { goto failed; }
            unsigned i = (f*3 + ch)*2;
            for (unsigned plane = 0; plane < 2; ++plane) {
                const Z6IIBayerSpan *out = &outputs[i + plane];
                const uint8_t *data = image + (plane ? outputs[i].length : 0);
                if (address_space_write(&s->engine->as, out->address,
                        MEMTXATTRS_UNSPECIFIED, data, out->length) != MEMTX_OK ||
                    address_space_read(&s->engine->as, out->address,
                        MEMTXATTRS_UNSPECIFIED, check, out->length) != MEMTX_OK ||
                    memcmp(data, check, out->length)) { goto failed; }
            }
            if (s->bayer.completed_batches < 2 || !(s->bayer.completed_batches & 255)) {
                g_autofree char *hash = g_compute_checksum_for_data(G_CHECKSUM_SHA256,
                    image, outputs[i].length + outputs[i + 1].length);
                fprintf(stderr, "Z6II_BAYER_ISP_OUTPUT frame_id=%" PRIu64
                        " channel=%u raw=%08x raw_sha256=%s y=%08x uv=%08x"
                        " width=%u height=%u stride=%u sha256=%s readback=1\n",
                        s->bayer.frame_id[f], ch + 3, inputs[f].address,
                        s->bayer.sha[f], outputs[i].address, outputs[i + 1].address,
                        w, h, stride, hash);
            }
        }
        ++s->bayer.total_isp_frames;
    }
    ++s->bayer.completed_batches;
    ++s->bayer.total_isp_batches;
    s->bayer.raw_pending = false;
    uint32_t banks = 8 | (s->bayer.config.command[0] ? 4 : 0);
    s->engine_regs[8] |= banks;
    z6ii_fd_engine_irq(s);
    s->image_processor_config[0][0x24 / 4] |= 0x1000;
    z6ii_fd_image_raw_irq(s);
    if (s->bayer.completed_batches <= 2 || !(s->bayer.completed_batches & 255)) {
        fprintf(stderr, "Z6II_BAYER_ISP_COMPLETE batches=%" PRIu64
                " raw_inputs=4 outputs=12 irq99_cause=1000 irq102_cause=%x"
                " generation=%" PRIu64 " candidate_contract=1 bit_accurate=0\n",
                s->bayer.completed_batches, banks, s->bayer.generation);
    }
    return;
failed:
    s->bayer.raw_pending = false;
    z6ii_bayer_reject(s, "ISP_memory_or_input_integrity");
}

static void z6ii_bayer_after_access(Z6IIFunctionalDevices *s, hwaddr addr)
{
    if (!s->bayer.enabled ||
        !((addr >= 0x20060000 && addr <= 0x20060024) ||
          (addr >= 0x20068000 && addr < 0x2006a000) ||
          (addr >= 0x20100000 && addr < 0x20102700) ||
          (addr >= 0x20380000 && addr < 0x20390000))) { return; }
    Z6IIBayerConfig c = z6ii_bayer_config(s);
    if ((addr >= 0x20069500 && addr <= 0x20069510) || addr == 0x20069808 ||
        addr == 0x2006983c || (addr >= 0x20069850 && addr <= 0x2006986c)) {
        ++s->bayer.capture_config_writes;
        if (addr >= 0x20069850 && addr <= 0x2006986c) {
            ++s->bayer.capture_address_writes;
            if (s->capture_processing[(addr - 0x20068000) / 4]) {
                ++s->bayer.capture_nonzero_address_writes;
            }
        }
    }
    if (memcmp(&c, &s->bayer.config, sizeof(c))) {
        bool capture_changed = memcmp(&c, &s->bayer.config,
                                      offsetof(Z6IIBayerConfig, raw_enable)) != 0;
        bool stopped = c.global_stop || !c.input ||
                       (s->bayer.config.raw_enable && !c.raw_enable) ||
                       (s->bayer.config.engine && !c.engine) ||
                       (s->bayer.config.command[1] && !c.command[1]) ||
                       (s->bayer.config.sequence && !c.sequence);
        if (stopped) { s->bayer.stop_latched = true; }
        z6ii_bayer_cancel(s, capture_changed || stopped,
                          stopped ? "stop_or_disable" : "descriptor_change");
        s->bayer.config = c;
    }
    z6ii_bayer_schedule(s);
}

static bool z6ii_bayer_access(Z6IIFunctionalDevices *s, hwaddr addr,
                              unsigned size, bool write, uint64_t *value)
{
    if (!s->bayer.enabled || size != 4 || (addr & 3)) { return false; }
    uint32_t *reg = NULL;
    if (addr >= 0x20380008 && addr < 0x20390000) {
        unsigned off = addr & 0xffff;
        reg = &s->image_processor_config[0][off / 4];
        if (off == 0x24) {
            if (write) { *reg &= ~(uint32_t)*value; }
            else { *value = *reg; }
            z6ii_fd_image_raw_irq(s);
            return true;
        }
        if (!write && off != 8 && off != 0x20 && off != 0x3c4) { return false; }
        if (off == 0x20 && write) {
            *reg = *value; z6ii_fd_image_raw_irq(s); return true;
        }
    } else if (write && addr >= 0x20102200 && addr < 0x20102400) {
        reg = &s->image_command_lists[(addr - 0x20102200) / 0x100][(addr & 0xff) / 4];
    } else if (write && addr >= 0x20100400 && addr < 0x20100800 &&
               (addr & 0x3f) <= 0x30) {
        reg = &s->image_transfer_config[(addr - 0x20100400) / 0x40][(addr & 0x3f) / 4];
    } else if (addr >= 0x20102000 && addr <= 0x201021a4) {
        unsigned bank = (addr - 0x20102000) / 0x100, off = addr & 0xff;
        if (bank < 2 && (off == 0 || off == 4 || off == 8 || off == 0x10 ||
            off == 0x14 || off == 0x18 || off == 0xa4)) {
            reg = &s->image_command_config[bank][off / 4];
        } else if (!write && bank == 0 && off >= 0x40 && off <= 0x7c) {
            *value = s->bayer.isp_job_pending ? 3 : 0; return true;
        }
    } else if (write && addr >= 0x20102600 && addr <= 0x20102690) {
        unsigned off = addr - 0x20102600, pair = off & 0x3f;
        if ((off < 0x80 && (pair == 0 || pair == 4 || pair == 8 ||
             pair == 0xc || pair == 0x10 || pair == 0x18 || pair == 0x20)) ||
            off == 0x80 || off == 0x84 || off == 0x90) {
            reg = &s->image_sequence_config[off / 4];
        }
    }
    if (!reg) { return false; }
    if (write) { *reg = *value; }
    else { *value = *reg; }
    return true;
}

static void z6ii_bayer_reset(void *opaque)
{
    Z6IIFunctionalDevices *s = opaque;
    if (!s->bayer.enabled) { return; }
    ++s->bayer.reset_count;
    z6ii_bayer_cancel(s, true, "board_reset");
    timer_del(s->capture_tg_timer);
    timer_del(s->engine_timer);
    timer_del(s->capture_isp_stop_timer);
    timer_del(s->image_process_timer);
    timer_del(s->image_drain_timer);
    s->capture_tg_running = s->capture_tg_draining = false;
    memset(s->capture_control, 0, sizeof(s->capture_control));
    memset(s->capture_processing, 0, sizeof(s->capture_processing));
    memset(s->capture_isp_gate, 0, sizeof(s->capture_isp_gate));
    memset(s->image_processor_config, 0, sizeof(s->image_processor_config));
    memset(s->image_command_config, 0, sizeof(s->image_command_config));
    memset(s->image_sequence_config, 0, sizeof(s->image_sequence_config));
    memset(s->image_transfer_config, 0, sizeof(s->image_transfer_config));
    memset(s->image_command_lists, 0, sizeof(s->image_command_lists));
    memset(s->engine_regs, 0, sizeof(s->engine_regs));
    memset(&s->bayer.config, 0, sizeof(s->bayer.config));
    s->bayer.stop_latched = false;
    s->bayer.blocked_config_valid = false;
    s->bayer.blocked_reason = s->bayer.blocked_reports = 0;
    memset(&s->bayer.last_blocked_config, 0, sizeof(s->bayer.last_blocked_config));
    s->bayer.next_frame_id = s->bayer.raw_batches = s->bayer.completed_batches = 0;
    z6ii_fd_image_raw_irq(s);
    z6ii_fd_engine_irq(s);
    g_clear_pointer(&s->bayer.pixels, nikon_isp_images_free);
}

/* One side-effect-free exit snapshot; lifetime DMA/write counters survive
 * board resets. A capture-tick snapshot alone is not a whole-run total. */
static void z6ii_bayer_exit_summary(Notifier *notifier, void *data)
{
    Z6IIBayerPipeline *b = container_of(notifier, Z6IIBayerPipeline, exit_notifier);
    Z6IIFunctionalDevices *s = container_of(b, Z6IIFunctionalDevices, bayer);
    Z6IIBayerConfig c = z6ii_bayer_config(s);
    fprintf(stderr, "Z6II_BAYER_FINAL virtual_ns=%" PRId64
            " resets=%" PRIu64 " capture_config_writes=%" PRIu64
            " capture_address_writes=%" PRIu64 " capture_nonzero_address_writes=%" PRIu64
            " raw_frames_total=%" PRIu64 " isp_frames_total=%" PRIu64
            " raw_batches_total=%" PRIu64 " isp_batches_total=%" PRIu64
            " global_stop=%08x input=%08x gates=%08x,%08x,%08x mode=%08x"
            " width=%08x height=%08x stride=%u bank=%u raw_enable=%u raw_geometry=%08x"
            " raw_stride=%u engine=%u commands=%u,%u sequence=%u stop_latched=%u"
            " raw_pending=%u isp_pending=%u summary_guest_writes=0\n",
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), b->reset_count,
            b->capture_config_writes, b->capture_address_writes,
            b->capture_nonzero_address_writes, b->total_raw_frames, b->total_isp_frames,
            b->total_raw_batches, b->total_isp_batches,
            c.global_stop, c.input, c.gates[0], c.gates[1], c.gates[2], c.mode,
            c.width, c.height, c.stride, c.bank, c.raw_enable, c.raw_geometry,
            c.raw_stride, c.engine, c.command[0], c.command[1], c.sequence,
            b->stop_latched, b->raw_pending, b->isp_job_pending);
    for (unsigned bank = 0; bank < 2; ++bank) {
        fprintf(stderr, "Z6II_BAYER_FINAL_BUFFERS bank=%u capture=", bank);
        for (unsigned f = 0; f < 4; ++f) {
            fprintf(stderr, "%s%08x", f ? "," : "",
                    s->capture_processing[(0x1850 + bank * 0x10 + f * 4) / 4]);
        }
        fprintf(stderr, "\n");
    }
    fprintf(stderr, "Z6II_BAYER_FINAL_ISP source=%08x,%08x,%08x,%08x",
            c.source[0], c.source[1], c.source[2], c.source[3]);
    for (unsigned f = 0; f < 4; ++f) {
        fprintf(stderr, " output%u=%08x,%08x,%08x", f,
                c.output[f][0], c.output[f][1], c.output[f][2]);
    }
    fprintf(stderr, "\n");
}

static void z6ii_bayer_init(Z6IIFunctionalDevices *s, bool display)
{
    const char *mode = display ? z6ii_engine_getenv(s->engine, "Z6II_BAYER_SOURCE") : NULL;
    s->bayer.enabled = g_strcmp0(mode, "dynamic-rggb12-v1") == 0;
    if (mode && g_strcmp0(mode, "disabled") && !s->bayer.enabled) {
        error_report("Unknown Z6II Bayer source mode"); exit(1);
    }
    if (!s->bayer.enabled) { return; }
    if (!s->capture_tg_enabled || s->capture_test_pulse || s->capture_periodic_test ||
        s->image_process_test || s->z6_profile || s->capture_native0_data) {
        error_report("Z6II dynamic Bayer source requires independent functional TG"); exit(1);
    }
    s->bayer.timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, z6ii_bayer_isp_tick, s);
    s->bayer.generation = 1;
    qemu_register_reset(z6ii_bayer_reset, s);
    s->bayer.exit_notifier.notify = z6ii_bayer_exit_summary;
    qemu_add_exit_notifier(&s->bayer.exit_notifier);
    fprintf(stderr, "Z6II_BAYER_MODEL mode=%s width=2034 height=1434 stride=4080"
            " packing=LE_u16_RGGB12 black=64 white=4095 generator=on_demand"
            " raw_format_assumed=1 completion_contract=candidate_Z6 ISP_bit_accurate=0\n", mode);
}
