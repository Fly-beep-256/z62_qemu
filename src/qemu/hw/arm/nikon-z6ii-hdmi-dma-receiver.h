/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Snapshot-only HDMI receiver bridge. Serialized calls; caller-owned storage.
 * A verified firmware binding must come from board code with submitter evidence.
 * Synthetic adapter tests use a separate binding AND a synthetic receiver.
 * This bridge never writes guest memory, raises a device IRQ, or sets Ready. */
#ifndef NIKON_Z6II_HDMI_DMA_RECEIVER_H
#define NIKON_Z6II_HDMI_DMA_RECEIVER_H

#include "nikon-z6ii-hdmi-dma-core.h"
#include "nikon-z6ii-hdmi-receiver-core.h"

typedef enum Z6IIHDMIDmaBindingKind {
    Z6II_HDMI_DMA_VERIFIED_FIRMWARE = 1,
    Z6II_HDMI_DMA_SYNTHETIC_ADAPTER = 2
} Z6IIHDMIDmaBindingKind;

typedef enum Z6IIHDMIDmaSourceKind {
    Z6II_HDMI_DMA_NO_SOURCE = 0,
    Z6II_HDMI_DMA_GUEST_CPU_MMIO = 1,
    Z6II_HDMI_DMA_SYNTHETIC_SOURCE = 2
} Z6IIHDMIDmaSourceKind;

typedef enum Z6IIHDMIDmaGate {
    Z6II_HDMI_DMA_GATE_OK = 0,
    Z6II_HDMI_DMA_GATE_UNBOUND,
    Z6II_HDMI_DMA_GATE_SOURCE,
    Z6II_HDMI_DMA_GATE_ROUTE,
    Z6II_HDMI_DMA_GATE_LAYOUT,
    Z6II_HDMI_DMA_GATE_SESSION,
    Z6II_HDMI_DMA_GATE_DESCRIPTOR
} Z6IIHDMIDmaGate;

typedef struct Z6IIHDMIDmaBinding {
    Z6IIHDMIDmaBindingKind kind;
    int32_t cpu_index; /* Exact guest CPU for firmware; -1 for synthetic tests. */
    uint32_t submit_pc, submit_mmio_address;
    unsigned submit_size; /* Only explicitly verified 1/2/4-byte writes. */
    uint32_t submit_value_mask, submit_value;
    uint32_t format, rate_num, rate_den, matrix, range;
} Z6IIHDMIDmaBinding;

typedef struct Z6IIHDMIDmaSource {
    Z6IIHDMIDmaSourceKind kind;
    int32_t cpu_index;
    uint32_t pc, mmio_address, mmio_value;
    unsigned mmio_size;
} Z6IIHDMIDmaSource;

typedef struct Z6IIHDMIDmaSnapshot {
    const Z6iiDmaFrame *frame;
    const uint8_t *bytes;
    size_t count;
} Z6IIHDMIDmaSnapshot;

typedef struct Z6IIHDMIDmaReceiver {
    Z6iiDmaCore dma;
    Z6IIHDMIReceiver *receiver;
    Z6IIHDMIRxRead read_ram;
    void *ram_opaque;
    Z6IIHDMIDmaBinding binding;
    Z6IIHDMIRxFrame active_frame;
    Z6IIHDMIDmaBindingKind active_kind;
    bool initialized, bound, has_completed;
    Z6iiDmaFrame last_completed;
    uint64_t original_dma_submissions, original_video_frames;
    uint64_t synthetic_dma_submissions, synthetic_frames;
    uint64_t rejected_submissions, failed_exports;
    Z6IIHDMIDmaGate last_gate;
    Z6iiDmaResult last_dma_result;
    Z6IIHDMIRxResult last_rx_result;
} Z6IIHDMIDmaReceiver;

static inline uint32_t z6ii_hdmi_dma_write_mask(unsigned size)
{
    switch (size) {
    case 1: return UINT32_C(0xff);
    case 2: return UINT32_C(0xffff);
    case 4: return UINT32_MAX;
    default: return 0;
    }
}

static inline const char *z6ii_hdmi_dma_gate_name(Z6IIHDMIDmaGate gate)
{
    static const char *const names[] = {
        "ok", "unbound", "wrong-source", "wrong-route", "bad-layout",
        "wrong-session", "bad-descriptor"
    };
    return (unsigned)gate < sizeof(names) / sizeof(names[0]) ?
           names[gate] : "invalid-gate";
}

static inline size_t z6ii_hdmi_dma_read_ram(void *opaque, uint32_t address,
                                          uint8_t *buffer, size_t bytes)
{
    Z6IIHDMIDmaReceiver *s = opaque;
    return s->read_ram(s->ram_opaque, address, buffer, bytes) ? bytes : 0;
}

/* Addresses remain the original guest plane addresses, but every byte comes
 * from the submit-time snapshot, never from RAM at completion time. */
static inline bool z6ii_hdmi_dma_snapshot_read(void *opaque, uint64_t address,
                                             uint8_t *buffer, size_t bytes)
{
    const Z6IIHDMIDmaSnapshot *view = opaque;
    if (!view || !view->frame || !view->bytes || !buffer || !bytes ||
        view->frame->request.plane_count != 1) {
        return false;
    }
    const Z6iiDmaFrame *f = view->frame;
    uint64_t base = f->request.planes[0].address;
    size_t start = f->plane_offsets[0], length = f->plane_lengths[0];
    if (address < base || address - base > length ||
        start > view->count || length > view->count - start) {
        return false;
    }
    size_t offset = (size_t)(address - base);
    if (bytes > length - offset) { return false; }
    memcpy(buffer, view->bytes + start + offset, bytes);
    return true;
}

static inline bool z6ii_hdmi_dma_publish(void *opaque, const Z6iiDmaFrame *frame,
                                       const uint8_t *bytes, size_t count)
{
    Z6IIHDMIDmaReceiver *s = opaque;
    Z6IIHDMIDmaSnapshot view = { frame, bytes, count };
    bool synthetic = s->active_kind == Z6II_HDMI_DMA_SYNTHETIC_ADAPTER;
    if (s->receiver->synthetic != synthetic ||
        s->active_frame.source_sequence != frame->token ||
        s->active_frame.pts_ns != frame->submitted_ns) {
        s->last_rx_result = Z6II_HDMI_RX_BAD_DESCRIPTOR;
    } else {
        s->last_rx_result = z6ii_hdmi_rx_submit(s->receiver, &s->active_frame,
                                         z6ii_hdmi_dma_snapshot_read, &view);
    }
    if (s->last_rx_result != Z6II_HDMI_RX_OK) {
        ++s->failed_exports;
        return false;
    }
    if (synthetic) { ++s->synthetic_frames; }
    else { ++s->original_video_frames; }
    return true;
}

static inline bool z6ii_hdmi_dma_receiver_init(Z6IIHDMIDmaReceiver *s,
                   Z6IIHDMIReceiver *receiver, Z6IIHDMIRxRead read_ram,
                   void *ram_opaque, uint8_t *storage, size_t capacity,
                   uint64_t generation, uint64_t now_ns)
{
    if (!s || !receiver || !read_ram) { return false; }
    memset(s, 0, sizeof(*s));
    s->receiver = receiver;
    s->read_ram = read_ram;
    s->ram_opaque = ram_opaque;
    s->last_rx_result = Z6II_HDMI_RX_DISABLED;
    s->last_gate = Z6II_HDMI_DMA_GATE_UNBOUND;
    Z6iiDmaOps ops = {
        .read = z6ii_hdmi_dma_read_ram,
        .publish = z6ii_hdmi_dma_publish,
        .irq_level = NULL, /* Device completion/IRQ is owned by the board. */
        .opaque = s
    };
    s->initialized = z6ii_dma_init(&s->dma, ops, storage, capacity,
                                   generation, now_ns);
    return s->initialized;
}

/* No env-var, FIFO getter, display image, or host descriptor enables this.
 * Board code must supply a confirmed route, trigger and packed color contract.
 * The binding is copied; a busy frame cannot be rebound. */
static inline bool z6ii_hdmi_dma_bind(Z6IIHDMIDmaReceiver *s,
                                    const Z6IIHDMIDmaBinding *binding)
{
    size_t row_bytes, frame_bytes;
    if (!s || !s->initialized || !binding || s->dma.state != Z6II_DMA_IDLE ||
        !s->receiver->initialized || s->receiver->closed || s->receiver->failed) {
        return false;
    }
    bool synthetic = binding->kind == Z6II_HDMI_DMA_SYNTHETIC_ADAPTER;
    uint32_t mask = z6ii_hdmi_dma_write_mask(binding->submit_size);
    if ((binding->kind != Z6II_HDMI_DMA_VERIFIED_FIRMWARE && !synthetic) ||
        synthetic != s->receiver->synthetic ||
        (synthetic ? binding->cpu_index != -1 : binding->cpu_index < 0) ||
        !binding->submit_pc || !binding->submit_mmio_address || !mask ||
        !binding->submit_value_mask || (binding->submit_value_mask & ~mask) ||
        (binding->submit_value & ~binding->submit_value_mask)) {
        return false;
    }
    Z6IIHDMIRxFrame sample = {
        .width = 2, .height = 1, .stride = 6,
        .format = binding->format, .rate_num = binding->rate_num,
        .rate_den = binding->rate_den, .matrix = binding->matrix,
        .range = binding->range
    };
    if (!z6ii_hdmi_rx_layout(&sample, &row_bytes, &frame_bytes)) { return false; }
    s->binding = *binding;
    s->bound = true;
    return true;
}

/* This gate is also used before QEMU reads the firmware descriptor. */
static inline Z6IIHDMIDmaGate z6ii_hdmi_dma_gate_source(
            const Z6IIHDMIDmaReceiver *s, const Z6IIHDMIDmaSource *source,
            Z6iiDmaOrigin origin)
{
    if (!s || !s->initialized || !s->bound) {
        return Z6II_HDMI_DMA_GATE_UNBOUND;
    }
    bool synthetic = s->binding.kind == Z6II_HDMI_DMA_SYNTHETIC_ADAPTER;
    if (!source || s->receiver->synthetic != synthetic ||
        (synthetic ?
          (source->kind != Z6II_HDMI_DMA_SYNTHETIC_SOURCE ||
           origin != Z6II_DMA_PROTOCOL_TEST) :
          (source->kind != Z6II_HDMI_DMA_GUEST_CPU_MMIO ||
           origin != Z6II_DMA_HDMI ||
           source->cpu_index != s->binding.cpu_index))) {
        return Z6II_HDMI_DMA_GATE_SOURCE;
    }
    uint32_t mask = z6ii_hdmi_dma_write_mask(source->mmio_size);
    if (source->pc != s->binding.submit_pc ||
        source->mmio_address != s->binding.submit_mmio_address ||
        source->mmio_size != s->binding.submit_size ||
        !mask || (source->mmio_value & ~mask) ||
        (source->mmio_value & s->binding.submit_value_mask) !=
          s->binding.submit_value) {
        return Z6II_HDMI_DMA_GATE_ROUTE;
    }
    return Z6II_HDMI_DMA_GATE_OK;
}

static inline Z6iiDmaResult z6ii_hdmi_dma_reject(Z6IIHDMIDmaReceiver *s,
                     Z6IIHDMIDmaGate gate, Z6iiDmaResult result)
{
    if (s) {
        ++s->rejected_submissions;
        s->last_gate = gate;
        s->last_dma_result = result;
    }
    return result;
}

/* The production board must call the QEMU wrapper rather than fabricate source
 * metadata or a request on the host. This lower layer also supports explicit
 * synthetic contract tests, which can never increment original_video_frames. */
static inline Z6iiDmaResult z6ii_hdmi_dma_receiver_submit(
              Z6IIHDMIDmaReceiver *s, const Z6iiDmaRequest *request,
              const Z6IIHDMIDmaSource *source, uint64_t now_ns,
              uint64_t delay_ns, uint64_t *token)
{
    size_t row_bytes, frame_bytes;
    if (token) { *token = 0; }
    Z6IIHDMIDmaGate gate = z6ii_hdmi_dma_gate_source(s, source,
                                    request ? request->origin : Z6II_DMA_UNATTRIBUTED);
    if (gate != Z6II_HDMI_DMA_GATE_OK) {
        return z6ii_hdmi_dma_reject(s, gate, Z6II_DMA_INVALID);
    }
    if (!request || !token || request->submit_pc != source->pc ||
        request->submit_mmio_address != source->mmio_address ||
        request->submit_mmio_value != source->mmio_value) {
        return z6ii_hdmi_dma_reject(s, Z6II_HDMI_DMA_GATE_SOURCE, Z6II_DMA_INVALID);
    }
    Z6IIHDMIRxFrame rx = {
        .address = request->planes[0].address, .pts_ns = now_ns,
        .width = request->width, .height = request->height,
        .stride = request->planes[0].stride, .format = s->binding.format,
        .rate_num = s->binding.rate_num, .rate_den = s->binding.rate_den,
        .matrix = s->binding.matrix, .range = s->binding.range
    };
    if (request->plane_count != 1 ||
        !memchr(request->format, 0, sizeof(request->format)) ||
        strcmp(request->format, z6ii_hdmi_rx_format_name(rx.format)) ||
        !z6ii_hdmi_rx_layout(&rx, &row_bytes, &frame_bytes) ||
        request->planes[0].rows != request->height ||
        request->planes[0].row_bytes != row_bytes) {
        return z6ii_hdmi_dma_reject(s, Z6II_HDMI_DMA_GATE_LAYOUT, Z6II_DMA_INVALID);
    }
    if (s->receiver->frames && !z6ii_hdmi_rx_same_stream(&rx, &s->receiver->first)) {
        return z6ii_hdmi_dma_reject(s, Z6II_HDMI_DMA_GATE_SESSION, Z6II_DMA_INVALID);
    }
    Z6iiDmaResult result = z6ii_dma_submit(&s->dma, request, now_ns, delay_ns, token);
    s->last_gate = Z6II_HDMI_DMA_GATE_OK;
    s->last_dma_result = result;
    if (result != Z6II_DMA_OK) { ++s->rejected_submissions; return result; }
    rx.source_sequence = *token;
    s->active_frame = rx;
    s->active_kind = s->binding.kind;
    if (s->active_kind == Z6II_HDMI_DMA_SYNTHETIC_ADAPTER) {
        ++s->synthetic_dma_submissions;
    } else {
        ++s->original_dma_submissions;
    }
    return result;
}

static inline Z6iiDmaResult z6ii_hdmi_dma_receiver_complete(
        Z6IIHDMIDmaReceiver *s, uint64_t token, uint64_t generation, uint64_t now_ns)
{
    if (!s || !s->initialized) { return Z6II_DMA_INVALID; }
    Z6iiDmaResult result = z6ii_dma_complete(&s->dma, token, generation, now_ns);
    s->last_dma_result = result;
    if (result == Z6II_DMA_OK) {
        s->last_completed = s->dma.frame;
        s->has_completed = true;
    }
    return result;
}

static inline Z6iiDmaResult z6ii_hdmi_dma_receiver_ack(Z6IIHDMIDmaReceiver *s)
{
    if (!s || !s->initialized) { return Z6II_DMA_INVALID; }
    return s->last_dma_result = z6ii_dma_ack(&s->dma);
}

static inline Z6iiDmaResult z6ii_hdmi_dma_receiver_cancel(
                    Z6IIHDMIDmaReceiver *s, uint64_t token, uint64_t generation)
{
    if (!s || !s->initialized) { return Z6II_DMA_INVALID; }
    return s->last_dma_result = z6ii_dma_cancel(&s->dma, token, generation);
}

static inline Z6iiDmaResult z6ii_hdmi_dma_receiver_reset(
                    Z6IIHDMIDmaReceiver *s, uint64_t generation, uint64_t now_ns)
{
    if (!s || !s->initialized) { return Z6II_DMA_INVALID; }
    Z6iiDmaResult result = z6ii_dma_reset(&s->dma, generation, now_ns);
    s->last_dma_result = result;
    if (result == Z6II_DMA_OK) {
        memset(&s->active_frame, 0, sizeof(s->active_frame));
        s->active_kind = 0; /* Static verified binding is retained; old frame is gone. */
    }
    return result;
}
#endif
