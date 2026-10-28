/* SPDX-License-Identifier: GPL-2.0-or-later */
/* ARM QEMU adapter. Include after qemu/osdep.h, target/arm/cpu.h,
 * system/address-spaces.h, and qemu/timer.h. The caller holds the BQL.
 * No Nikon descriptor decoder/route is supplied: unbound always rejects.
 * Attach only in a verified CPU MMIO submit handler, and call complete from
 * the board's existing verified completion event. No timer/IRQ is created. */
#ifndef NIKON_Z6II_HDMI_DMA_RECEIVER_QEMU_H
#define NIKON_Z6II_HDMI_DMA_RECEIVER_QEMU_H

#include "nikon-z6ii-hdmi-dma-receiver.h"
#include "nikon-z6ii-hdmi-receiver-qemu.h"

#define Z6II_HDMI_DMA_DESCRIPTOR_LIMIT 4096u

/* Static verified decoder output has layout only; it cannot claim PC/origin.
 * It must validate format/route flags in the original descriptor rather than
 * guess packing. The binding supplies the confirmed packed color contract. */
typedef struct Z6IIHDMIDmaDescriptorLayout {
    uint32_t width, height, plane_count;
    Z6iiDmaPlane planes[Z6II_DMA_MAX_PLANES];
} Z6IIHDMIDmaDescriptorLayout;

typedef bool (*Z6IIHDMIDmaResolve)(uint32_t actual_mmio_value, uint32_t *address);
typedef bool (*Z6IIHDMIDmaDecode)(const uint8_t *descriptor, size_t bytes,
                               Z6IIHDMIDmaDescriptorLayout *layout);

typedef struct Z6IIHDMIDmaQEMU {
    Z6IIHDMIDmaReceiver bridge;
    AddressSpace *address_space;
    size_t descriptor_bytes;
    Z6IIHDMIDmaResolve resolve;
    Z6IIHDMIDmaDecode decode;
} Z6IIHDMIDmaQEMU;

static inline bool z6ii_hdmi_dma_qemu_init(Z6IIHDMIDmaQEMU *s,
        Z6IIHDMIReceiver *receiver, AddressSpace *as, uint8_t *storage,
        size_t capacity, uint64_t generation)
{
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    if (!s || !as || now < 0) { return false; }
    memset(s, 0, sizeof(*s));
    s->address_space = as;
    return z6ii_hdmi_dma_receiver_init(&s->bridge, receiver,
               z6ii_hdmi_rx_qemu_read, as, storage, capacity, generation, now);
}

/* Board-owned evidence gate. No environment variable or synthetic entry point
 * can bind this original-firmware adapter. Invalid binds leave prior state. */
static inline bool z6ii_hdmi_dma_qemu_bind_verified(Z6IIHDMIDmaQEMU *s,
        const Z6IIHDMIDmaBinding *binding, size_t descriptor_bytes,
        Z6IIHDMIDmaResolve resolve, Z6IIHDMIDmaDecode decode)
{
    if (!s || !binding || binding->kind != Z6II_HDMI_DMA_VERIFIED_FIRMWARE ||
        !descriptor_bytes || descriptor_bytes > Z6II_HDMI_DMA_DESCRIPTOR_LIMIT ||
        !resolve || !decode || !z6ii_hdmi_dma_bind(&s->bridge, binding)) {
        return false;
    }
    s->descriptor_bytes = descriptor_bytes;
    s->resolve = resolve;
    s->decode = decode;
    return true;
}

static inline Z6iiDmaResult z6ii_hdmi_dma_qemu_submit(Z6IIHDMIDmaQEMU *s,
        uint64_t mmio_address, uint64_t mmio_value, unsigned mmio_size,
        uint64_t delay_ns, uint64_t *token)
{
    uint8_t descriptor[Z6II_HDMI_DMA_DESCRIPTOR_LIMIT];
    uint32_t descriptor_address = 0;
    Z6IIHDMIDmaDescriptorLayout layout = {0};
    if (token) { *token = 0; }
    if (!s) { return Z6II_DMA_INVALID; }
    if (!s->bridge.bound || !s->resolve || !s->decode) {
        return z6ii_hdmi_dma_reject(&s->bridge, Z6II_HDMI_DMA_GATE_UNBOUND,
                                   Z6II_DMA_INVALID);
    }
    if (!current_cpu) {
        return z6ii_hdmi_dma_reject(&s->bridge, Z6II_HDMI_DMA_GATE_SOURCE,
                                   Z6II_DMA_INVALID);
    }
    if (mmio_address > UINT32_MAX || mmio_value > UINT32_MAX) {
        return z6ii_hdmi_dma_reject(&s->bridge, Z6II_HDMI_DMA_GATE_ROUTE,
                                   Z6II_DMA_INVALID);
    }
    Z6IIHDMIDmaSource source = {
        .kind = Z6II_HDMI_DMA_GUEST_CPU_MMIO,
        .cpu_index = current_cpu->cpu_index,
        .pc = ARM_CPU(current_cpu)->env.regs[15],
        .mmio_address = mmio_address, .mmio_value = mmio_value,
        .mmio_size = mmio_size
    };
    Z6IIHDMIDmaGate gate = z6ii_hdmi_dma_gate_source(&s->bridge, &source,
                                                   Z6II_DMA_HDMI);
    if (gate != Z6II_HDMI_DMA_GATE_OK) {
        return z6ii_hdmi_dma_reject(&s->bridge, gate, Z6II_DMA_INVALID);
    }
    if (!token || !s->descriptor_bytes ||
        s->descriptor_bytes > sizeof(descriptor) ||
        !s->resolve(source.mmio_value, &descriptor_address) ||
        !descriptor_address ||
        (uint64_t)descriptor_address + s->descriptor_bytes >
           UINT64_C(0x100000000)) {
        return z6ii_hdmi_dma_reject(&s->bridge, Z6II_HDMI_DMA_GATE_DESCRIPTOR,
                                   Z6II_DMA_INVALID);
    }
    if (!z6ii_hdmi_rx_qemu_read(s->address_space, descriptor_address,
                               descriptor, s->descriptor_bytes)) {
        return z6ii_hdmi_dma_reject(&s->bridge, Z6II_HDMI_DMA_GATE_DESCRIPTOR,
                                   Z6II_DMA_READ_FAULT);
    }
    if (!s->decode(descriptor, s->descriptor_bytes, &layout)) {
        return z6ii_hdmi_dma_reject(&s->bridge, Z6II_HDMI_DMA_GATE_DESCRIPTOR,
                                   Z6II_DMA_INVALID);
    }
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    if (now < 0) {
        return z6ii_hdmi_dma_reject(&s->bridge, Z6II_HDMI_DMA_GATE_DESCRIPTOR,
                                   Z6II_DMA_CLOCK_REVERSED);
    }
    Z6iiDmaRequest request = {
        .generation = s->bridge.dma.generation,
        .descriptor_address = descriptor_address,
        .width = layout.width, .height = layout.height,
        .plane_count = layout.plane_count,
        .submit_pc = source.pc, .submit_mmio_address = source.mmio_address,
        .submit_mmio_value = source.mmio_value, .origin = Z6II_DMA_HDMI
    };
    memcpy(request.planes, layout.planes, sizeof(request.planes));
    snprintf(request.format, sizeof(request.format), "%s",
               z6ii_hdmi_rx_format_name(s->bridge.binding.format));
    return z6ii_hdmi_dma_receiver_submit(&s->bridge, &request, &source,
                                         (uint64_t)now, delay_ns, token);
}

static inline Z6iiDmaResult z6ii_hdmi_dma_qemu_complete(
                      Z6IIHDMIDmaQEMU *s, uint64_t token, uint64_t generation)
{
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    if (!s || now < 0) { return Z6II_DMA_CLOCK_REVERSED; }
    /* Host export failure remains separate from board hardware completion. */
    return z6ii_hdmi_dma_receiver_complete(&s->bridge, token, generation, now);
}

static inline Z6iiDmaResult z6ii_hdmi_dma_qemu_reset(
                                         Z6IIHDMIDmaQEMU *s, uint64_t generation)
{
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    if (!s || now < 0) { return Z6II_DMA_CLOCK_REVERSED; }
    return z6ii_hdmi_dma_receiver_reset(&s->bridge, generation, now);
}

/* Call from the existing board exit hook; no extra observer/notifier is added. */
static inline void z6ii_hdmi_dma_qemu_summary(const Z6IIHDMIDmaQEMU *s)
{
    const Z6IIHDMIDmaReceiver *b = &s->bridge;
    fprintf(stderr, "Z6II_HDMI_DMA_SUMMARY bound=%u generation=%" PRIu64
            " original_dma_submissions=%" PRIu64 " original_video_frames=%" PRIu64
            " synthetic_dma_submissions=%" PRIu64 " synthetic_frames=%" PRIu64
            " rejected=%" PRIu64 " failed_exports=%" PRIu64 " gate=%s rx=%s"
            " guest_writes=0 hardware_completion_generated=0 irq_routes=0\n",
            b->bound, b->dma.generation, b->original_dma_submissions,
            b->original_video_frames, b->synthetic_dma_submissions,
            b->synthetic_frames, b->rejected_submissions, b->failed_exports,
            z6ii_hdmi_dma_gate_name(b->last_gate),
            z6ii_hdmi_rx_result_name(b->last_rx_result));
}
#endif
