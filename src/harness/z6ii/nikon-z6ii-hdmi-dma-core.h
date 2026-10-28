/* Private stage 98 transport mechanism. This defines no Nikon MMIO or IRQ route.
 * The board adapter must establish submission, packing, plane geometry and origin
 * from firmware/runtime evidence. All calls and callbacks must be serialized.
 * Snapshot occurs at submit; complete must run on QEMU virtual time, never wall time.
 * The caller owns storage and must keep it alive until ack/cancel/reset.
 */
#ifndef Z6II_HDMI_DMA_CORE_H
#define Z6II_HDMI_DMA_CORE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define Z6II_DMA_MAX_PLANES 3
#define Z6II_DMA_FORMAT_BYTES 24

typedef enum Z6iiDmaOrigin {
    Z6II_DMA_UNATTRIBUTED = 0,
    Z6II_DMA_HDMI = 1,
    Z6II_DMA_LCD = 2,
    Z6II_DMA_PROTOCOL_TEST = 3
} Z6iiDmaOrigin;

typedef enum Z6iiDmaState {
    Z6II_DMA_IDLE = 0,
    Z6II_DMA_BUSY,
    Z6II_DMA_DONE,
    Z6II_DMA_ERROR
} Z6iiDmaState;

typedef enum Z6iiDmaResult {
    Z6II_DMA_OK = 0,
    Z6II_DMA_INVALID,
    Z6II_DMA_OCCUPIED,
    Z6II_DMA_STALE,
    Z6II_DMA_READ_FAULT,
    Z6II_DMA_EARLY,
    Z6II_DMA_CLOCK_REVERSED
} Z6iiDmaResult;

typedef struct Z6iiDmaPlane {
    uint32_t address;
    uint32_t row_bytes;
    uint32_t stride;
    uint32_t rows;
} Z6iiDmaPlane;

typedef struct Z6iiDmaRequest {
    uint64_t generation;
    uint32_t descriptor_address;
    uint32_t width, height;
    uint32_t plane_count;
    uint32_t submit_pc;
    uint32_t submit_mmio_address, submit_mmio_value;
    Z6iiDmaOrigin origin;
    char format[Z6II_DMA_FORMAT_BYTES]; /* Explicit caller packing; never inferred. */
    Z6iiDmaPlane planes[Z6II_DMA_MAX_PLANES];
} Z6iiDmaRequest;

typedef struct Z6iiDmaFrame {
    Z6iiDmaRequest request;
    uint64_t token;
    uint64_t submitted_ns, deadline_ns, completed_ns;
    size_t byte_count;
    size_t plane_offsets[Z6II_DMA_MAX_PLANES];
    size_t plane_lengths[Z6II_DMA_MAX_PLANES];
    bool export_ok;
} Z6iiDmaFrame;

typedef struct Z6iiDmaOps {
    /* Exact reads required. The adapter translates QEMU address_space_read errors. */
    size_t (*read)(void *opaque, uint32_t address, uint8_t *dst, size_t count);
    /* Receives an immutable snapshot; copy before return. No recursive core calls. */
    bool (*publish)(void *opaque, const Z6iiDmaFrame *frame,
                    const uint8_t *snapshot, size_t count);
    /* Optional signal only. No GIC line/default route exists in this core. */
    void (*irq_level)(void *opaque, bool asserted);
    void *opaque;
} Z6iiDmaOps;

typedef struct Z6iiDmaCore {
    Z6iiDmaOps ops;
    uint8_t *storage;
    size_t capacity;
    uint64_t generation, next_token, last_ns;
    Z6iiDmaState state;
    Z6iiDmaResult error;
    Z6iiDmaFrame frame;
    bool irq_enabled, irq_asserted;
} Z6iiDmaCore;

static inline void z6ii_dma_signal(Z6iiDmaCore *c, bool level)
{
    if (c->irq_asserted != level) {
        c->irq_asserted = level;
        if (c->ops.irq_level) {
            c->ops.irq_level(c->ops.opaque, level);
        }
    }
}

static inline bool z6ii_dma_init(Z6iiDmaCore *c, Z6iiDmaOps ops,
                                 uint8_t *storage, size_t capacity,
                                 uint64_t generation, uint64_t now_ns)
{
    if (!c || !ops.read || !ops.publish || !storage || !capacity || !generation) {
        return false;
    }
    memset(c, 0, sizeof(*c));
    c->ops = ops;
    c->storage = storage;
    c->capacity = capacity;
    c->generation = generation;
    c->next_token = 1;
    c->last_ns = now_ns;
    return true;
}

static inline Z6iiDmaResult z6ii_dma_submit(Z6iiDmaCore *c,
                                           const Z6iiDmaRequest *request,
                                           uint64_t now_ns, uint64_t delay_ns,
                                           uint64_t *token)
{
    Z6iiDmaFrame frame = {0};
    size_t total = 0;
    uint32_t i;
    if (!c || !request || !token) {
        return Z6II_DMA_INVALID;
    }
    *token = 0;
    if (request->generation != c->generation) {
        return Z6II_DMA_STALE;
    }
    if (c->state != Z6II_DMA_IDLE) {
        return Z6II_DMA_OCCUPIED;
    }
    if (now_ns < c->last_ns) {
        return Z6II_DMA_CLOCK_REVERSED;
    }
    if (!request->descriptor_address || !request->width || !request->height ||
        !request->plane_count || request->plane_count > Z6II_DMA_MAX_PLANES ||
        request->origin < Z6II_DMA_UNATTRIBUTED || request->origin > Z6II_DMA_PROTOCOL_TEST ||
        !request->format[0] || !memchr(request->format, 0, sizeof(request->format)) ||
        delay_ns > UINT64_MAX - now_ns || c->next_token == UINT64_MAX) {
        return Z6II_DMA_INVALID;
    }
    for (i = 0; i < request->plane_count; i++) {
        const Z6iiDmaPlane *p = &request->planes[i];
        uint64_t count = (uint64_t)p->stride * p->rows;
        uint64_t end = (uint64_t)p->address + count;
        if (!p->rows || !p->row_bytes || p->stride < p->row_bytes ||
            count > SIZE_MAX || count > c->capacity - total ||
            end > UINT64_C(0x100000000)) {
            return Z6II_DMA_INVALID;
        }
        frame.plane_offsets[i] = total;
        frame.plane_lengths[i] = (size_t)count;
        total += (size_t)count;
    }
    frame.request = *request; /* Copy before read/callback; caller mutation cannot race. */
    frame.token = c->next_token++;
    frame.submitted_ns = now_ns;
    frame.deadline_ns = now_ns + delay_ns;
    frame.byte_count = total;
    for (i = 0; i < frame.request.plane_count; i++) {
        size_t count = frame.plane_lengths[i];
        size_t got = c->ops.read(c->ops.opaque, frame.request.planes[i].address,
                                 c->storage + frame.plane_offsets[i], count);
        if (got != count) {
            memset(c->storage, 0, total);
            c->state = Z6II_DMA_ERROR;
            c->error = Z6II_DMA_READ_FAULT;
            c->last_ns = now_ns;
            memset(&c->frame, 0, sizeof(c->frame));
            *token = 0;
            return Z6II_DMA_READ_FAULT;
        }
    }
    c->frame = frame;
    c->last_ns = now_ns;
    c->state = Z6II_DMA_BUSY;
    c->error = Z6II_DMA_OK;
    *token = frame.token;
    return Z6II_DMA_OK;
}

/* Timer callbacks retain token AND generation. A stale timer cannot complete a
 * new frame after cancellation/reset, even if it wakes at a later valid time. */
static inline Z6iiDmaResult z6ii_dma_complete(Z6iiDmaCore *c, uint64_t token,
                                             uint64_t generation, uint64_t now_ns)
{
    if (!c || !token) {
        return Z6II_DMA_INVALID;
    }
    if (generation != c->generation || token != c->frame.token) {
        return Z6II_DMA_STALE;
    }
    if (c->state != Z6II_DMA_BUSY) {
        return Z6II_DMA_OCCUPIED;
    }
    if (now_ns < c->last_ns) {
        return Z6II_DMA_CLOCK_REVERSED;
    }
    c->last_ns = now_ns;
    if (now_ns < c->frame.deadline_ns) {
        return Z6II_DMA_EARLY;
    }
    c->frame.completed_ns = now_ns;
    c->frame.export_ok = c->ops.publish(c->ops.opaque, &c->frame,
                                       c->storage, c->frame.byte_count);
    /* Host recorder backpressure/failure is recorded separately. It must not
     * prevent the adapter's modeled hardware completion. */
    c->state = Z6II_DMA_DONE;
    z6ii_dma_signal(c, c->irq_enabled);
    return Z6II_DMA_OK;
}

static inline void z6ii_dma_set_irq_enabled(Z6iiDmaCore *c, bool enabled)
{
    c->irq_enabled = enabled;
    z6ii_dma_signal(c, enabled && c->state == Z6II_DMA_DONE);
}

static inline Z6iiDmaResult z6ii_dma_ack(Z6iiDmaCore *c)
{
    if (c->state != Z6II_DMA_DONE && c->state != Z6II_DMA_ERROR) {
        return Z6II_DMA_OCCUPIED;
    }
    z6ii_dma_signal(c, false);
    memset(c->storage, 0, c->frame.byte_count);
    memset(&c->frame, 0, sizeof(c->frame));
    c->state = Z6II_DMA_IDLE;
    c->error = Z6II_DMA_OK;
    return Z6II_DMA_OK;
}

static inline Z6iiDmaResult z6ii_dma_cancel(Z6iiDmaCore *c, uint64_t token,
                                           uint64_t generation)
{
    if (generation != c->generation || !token || token != c->frame.token) {
        return Z6II_DMA_STALE;
    }
    if (c->state != Z6II_DMA_BUSY) {
        return Z6II_DMA_OCCUPIED;
    }
    memset(c->storage, 0, c->frame.byte_count);
    memset(&c->frame, 0, sizeof(c->frame));
    c->state = Z6II_DMA_IDLE;
    return Z6II_DMA_OK;
}

/* A board reset advances generation; equality/reuse is rejected. */
static inline Z6iiDmaResult z6ii_dma_reset(Z6iiDmaCore *c,
                                          uint64_t generation, uint64_t now_ns)
{
    if (generation <= c->generation) {
        return Z6II_DMA_STALE;
    }
    if (now_ns < c->last_ns) {
        return Z6II_DMA_CLOCK_REVERSED;
    }
    z6ii_dma_signal(c, false);
    memset(c->storage, 0, c->frame.byte_count);
    memset(&c->frame, 0, sizeof(c->frame));
    c->generation = generation;
    c->last_ns = now_ns;
    c->state = Z6II_DMA_IDLE;
    c->error = Z6II_DMA_OK;
    c->irq_enabled = false;
    return Z6II_DMA_OK;
}
#endif
