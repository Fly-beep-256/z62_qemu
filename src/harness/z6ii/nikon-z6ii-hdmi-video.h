/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Host receiver lifetime for the Master board. No Nikon video submit route is
 * installed until its CPU/PC, descriptor layout and completion are verified. */
#ifndef NIKON_Z6II_HDMI_VIDEO_H
#define NIKON_Z6II_HDMI_VIDEO_H

#include "nikon-z6ii-hdmi-dma-receiver-qemu.h"
#include "nikon-z6ii-hdmi-receiver-lifecycle.h"

typedef struct Z6IIHDMIVideo {
    Z6IIHDMIRxQEMU rx;
    Z6IIHDMIDmaQEMU dma;
    uint8_t *snapshot;
    size_t snapshot_capacity;
    bool initialized;
} Z6IIHDMIVideo;

static inline void z6ii_hdmi_video_close(void *opaque)
{
    Z6IIHDMIVideo *v = opaque;
    if (!v->initialized) { return; }
    if (v->dma.bridge.dma.state == Z6II_DMA_BUSY) {
        z6ii_hdmi_dma_receiver_cancel(&v->dma.bridge,
            v->dma.bridge.dma.frame.token, v->dma.bridge.dma.generation);
    }
    z6ii_hdmi_dma_qemu_summary(&v->dma);
    g_free(v->snapshot);
    v->snapshot = NULL;
    v->initialized = false;
}

static inline void z6ii_hdmi_video_init(Z6IIHDMIVideo *v, bool master,
                                      bool hdmi_enabled, uint64_t board_generation)
{
    memset(v, 0, sizeof(*v));
    if (!master) { return; }
    const char *directory = getenv("Z6II_HDMI_RX_DIRECTORY");
    const char *capacity_text = getenv("Z6II_HDMI_RX_SNAPSHOT_BYTES");
    if (!directory) {
        if (capacity_text || getenv("Z6II_HDMI_RX_MAX_FRAMES") ||
            getenv("Z6II_HDMI_RX_MAX_BYTES")) {
            error_report("HDMI receiver budgets require Z6II_HDMI_RX_DIRECTORY");
            exit(1);
        }
        return;
    }
    if (!hdmi_enabled) {
        error_report("HDMI receiver requires an enabled Master HDMI model");
        exit(1);
    }
    Z6IIHDMIRxResult result = z6ii_hdmi_rx_qemu_init(&v->rx);
    if (result != Z6II_HDMI_RX_OK) {
        error_report("HDMI receiver open failed: %s", z6ii_hdmi_rx_result_name(result));
        exit(1);
    }
    uint64_t capacity = MIN(v->rx.receiver.max_bytes,
                            (uint64_t)Z6II_HDMI_RX_FRAME_LIMIT);
    if (capacity_text &&
        !z6ii_hdmi_rx_u64(capacity_text, Z6II_HDMI_RX_FRAME_LIMIT, &capacity)) {
        error_report("Z6II_HDMI_RX_SNAPSHOT_BYTES requires 1..%u bytes",
                     Z6II_HDMI_RX_FRAME_LIMIT);
        exit(1);
    }
    v->snapshot_capacity = capacity;
    v->snapshot = g_malloc(v->snapshot_capacity);
    if (!z6ii_hdmi_dma_qemu_init(&v->dma, &v->rx.receiver,
              &address_space_memory, v->snapshot, v->snapshot_capacity, 1)) {
        error_report("HDMI DMA receiver initialization failed");
        exit(1);
    }
    v->initialized = true;
    v->rx.before_close = z6ii_hdmi_video_close;
    v->rx.before_close_opaque = v;
    /* The DDC core starts at generation 0 and advances on its own jobs.
     * Video snapshots have a separate, nonzero board-reset epoch. */
    fprintf(stderr, "Z6II_HDMI_VIDEO_OPEN snapshot_bytes=%zu generation=1"
            " board_generation=%" PRIu64
            " bound=0 resolver=absent decoder=absent original_frames=0"
            " guest_writes=0 irq_routes=0\n", v->snapshot_capacity, board_generation);
}

static inline void z6ii_hdmi_video_reset(Z6IIHDMIVideo *v, uint64_t board_generation)
{
    if (!v->initialized) { return; }
    uint64_t generation = v->dma.bridge.dma.generation;
    if (generation == UINT64_MAX) {
        error_report("HDMI DMA receiver reset epoch exhausted");
        exit(1);
    }
    ++generation;
    Z6iiDmaResult result = z6ii_hdmi_dma_qemu_reset(&v->dma, generation);
    if (result != Z6II_DMA_OK) {
        error_report("HDMI DMA reset rejected: result=%u generation=%" PRIu64,
                     result, generation);
        exit(1);
    }
    fprintf(stderr, "Z6II_HDMI_VIDEO_RESET generation=%" PRIu64
            " board_generation=%" PRIu64
            " bound=%u pending_snapshot_cancelled=1 guest_writes=0 video_completion=0\n",
            generation, board_generation, v->dma.bridge.bound);
}
#endif
