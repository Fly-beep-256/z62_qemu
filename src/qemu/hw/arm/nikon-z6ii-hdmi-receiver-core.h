/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Explicit HDMI frame receiver. No MMIO, firmware descriptor interpretation,
 * timing generator, completion IRQ or guest write is implemented here. */
#ifndef NIKON_Z6II_HDMI_RECEIVER_CORE_H
#define NIKON_Z6II_HDMI_RECEIVER_CORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define Z6II_HDMI_RX_METADATA_LIMIT (4u * 1024u * 1024u)
#define Z6II_HDMI_RX_FRAME_LIMIT (64u * 1024u * 1024u)

typedef enum Z6IIHDMIRxFormat {
    Z6II_HDMI_RX_RGB24 = 1,
    Z6II_HDMI_RX_BGR24 = 2,
    Z6II_HDMI_RX_UYVY8 = 3,
    Z6II_HDMI_RX_YUYV8 = 4,
} Z6IIHDMIRxFormat;

typedef enum Z6IIHDMIRxResult {
    Z6II_HDMI_RX_OK,
    Z6II_HDMI_RX_DISABLED,
    Z6II_HDMI_RX_BAD_DESCRIPTOR,
    Z6II_HDMI_RX_NONMONOTONIC,
    Z6II_HDMI_RX_RECONFIGURE,
    Z6II_HDMI_RX_LIMIT,
    Z6II_HDMI_RX_READ_ERROR,
    Z6II_HDMI_RX_IO_ERROR,
    Z6II_HDMI_RX_CLOSED,
} Z6IIHDMIRxResult;

typedef struct Z6IIHDMIRxFrame {
    uint64_t address, pts_ns, source_sequence;
    uint32_t width, height, stride, format;
    uint32_t rate_num, rate_den;
    /* RGB requires matrix=0/range=0. YUV requires explicit 601 or 709
     * and range=0 (full) or 1 (limited). Nothing is inferred from MMIO. */
    uint32_t matrix, range;
} Z6IIHDMIRxFrame;

typedef bool (*Z6IIHDMIRxRead)(void *opaque, uint64_t address,
                             uint8_t *buffer, size_t bytes);

typedef struct Z6IIHDMIReceiver {
    char *directory;
    bool initialized, closed, failed, synthetic;
    Z6IIHDMIRxFrame first, last;
    uint64_t frames, bytes, stored_bytes, duplicates, rejected;
    uint64_t max_frames, max_bytes, last_pixel_index;
    uint8_t *last_snapshot;
    uint64_t metadata_bytes;
    int last_errno;
    Z6IIHDMIRxResult last_result;
} Z6IIHDMIReceiver;

static inline const char *z6ii_hdmi_rx_result_name(Z6IIHDMIRxResult result)
{
    static const char *const names[] = {
        "ok", "disabled", "bad-descriptor", "nonmonotonic", "reconfigure",
        "limit", "read-error", "io-error", "closed"
    };
    return (unsigned)result < sizeof(names) / sizeof(names[0]) ?
           names[result] : "invalid-result";
}

static inline const char *z6ii_hdmi_rx_format_name(uint32_t format)
{
    switch (format) {
    case Z6II_HDMI_RX_RGB24: return "rgb24";
    case Z6II_HDMI_RX_BGR24: return "bgr24";
    case Z6II_HDMI_RX_UYVY8: return "uyvy422-8";
    case Z6II_HDMI_RX_YUYV8: return "yuyv422-8";
    default: return "unsupported";
    }
}

static inline bool z6ii_hdmi_rx_layout(const Z6IIHDMIRxFrame *f,
                                     size_t *row_bytes, size_t *frame_bytes)
{
    unsigned bpp;
    if (!f || !f->width || f->width > 4096 || !f->height ||
        f->height > 2160 || !f->rate_num || !f->rate_den ||
        f->rate_num > 1000000 || f->rate_den > 1000000 ||
        (uint64_t)f->rate_num > (uint64_t)240 * f->rate_den ||
        f->pts_ns > INT64_MAX || f->range > 1) {
        return false;
    }
    switch (f->format) {
    case Z6II_HDMI_RX_RGB24:
    case Z6II_HDMI_RX_BGR24:
        if (f->matrix || f->range) { return false; }
        bpp = 3;
        break;
    case Z6II_HDMI_RX_UYVY8:
    case Z6II_HDMI_RX_YUYV8:
        if ((f->width & 1) || (f->matrix != 601 && f->matrix != 709)) {
            return false;
        }
        bpp = 2;
        break;
    default: return false;
    }
    *row_bytes = (size_t)f->width * bpp;
    *frame_bytes = *row_bytes * f->height;
    uint64_t span = (uint64_t)(f->height - 1) * f->stride + *row_bytes;
    return f->stride >= *row_bytes &&
           *frame_bytes <= Z6II_HDMI_RX_FRAME_LIMIT &&
           f->address <= UINT64_MAX - span;
}

static inline Z6IIHDMIRxResult z6ii_hdmi_rx_reject(Z6IIHDMIReceiver *r,
                                                 Z6IIHDMIRxResult result)
{
    ++r->rejected;
    r->last_result = result;
    if (result == Z6II_HDMI_RX_IO_ERROR) {
        r->failed = true;
        r->last_errno = errno;
    }
    return result;
}

static inline bool z6ii_hdmi_rx_write_all(int fd, const uint8_t *p, size_t n)
{
    while (n) {
        ssize_t written = write(fd, p, n);
        if (written < 0 && errno == EINTR) { continue; }
        if (written <= 0) { return false; }
        p += written;
        n -= written;
    }
    return true;
}

/* Publish without replacement. A failed transaction retains its .part file;
 * metadata is published last and is the only consumer commit marker. */
static inline bool z6ii_hdmi_rx_publish(Z6IIHDMIReceiver *r, const char *name,
                                      const uint8_t *p, size_t n)
{
    size_t length = strlen(r->directory) + strlen(name) + 8;
    char *final = malloc(length), *part = malloc(length);
    int fd = -1, saved = 0;
    bool ok = false;
    if (!final || !part) { errno = ENOMEM; goto done; }
    snprintf(final, length, "%s/%s", r->directory, name);
    snprintf(part, length, "%s/%s.part", r->directory, name);
    fd = open(part, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) { goto done; }
    if (!z6ii_hdmi_rx_write_all(fd, p, n) || fsync(fd)) { goto done; }
    if (close(fd)) { fd = -1; goto done; }
    fd = -1;
    if (link(part, final)) { goto done; }
    /* Only a just-published temporary link is removed; captures and prior
     * sessions are never overwritten or removed. */
    if (unlink(part)) { goto done; }
    ok = true;
done:
    saved = errno;
    if (fd >= 0) { close(fd); }
    free(final);
    free(part);
    errno = saved;
    return ok;
}

static inline Z6IIHDMIRxResult z6ii_hdmi_rx_init(Z6IIHDMIReceiver *r,
                      const char *directory, uint64_t max_frames,
                      uint64_t max_bytes, bool synthetic)
{
    char text[512];
    memset(r, 0, sizeof(*r));
    if (!directory) { return Z6II_HDMI_RX_DISABLED; }
    if (directory[0] != '/' || !max_frames || !max_bytes) {
        return z6ii_hdmi_rx_reject(r, Z6II_HDMI_RX_BAD_DESCRIPTOR);
    }
    r->directory = malloc(strlen(directory) + 1);
    if (!r->directory) { errno = ENOMEM; goto fail; }
    strcpy(r->directory, directory);
    if (mkdir(directory, 0700)) { goto fail; }
    r->max_frames = max_frames;
    r->max_bytes = max_bytes;
    r->synthetic = synthetic;
    int n = snprintf(text, sizeof(text),
        "{\"schema\":\"z6ii-hdmi-rx-v1\",\"provenance\":\"%s\","
        "\"source_claim_requires_submitter_evidence\":true,"
        "\"clock\":\"caller-supplied-ns\",\"max_frames\":%" PRIu64 ","
        "\"max_bytes\":%" PRIu64 ",\"metadata_limit\":%u,"
        "\"guest_writes\":0,\"hardware_completion_generated\":false}\n",
        synthetic ? "synthetic-qemu-local" : "firmware-hdmi-submission",
        max_frames, max_bytes, Z6II_HDMI_RX_METADATA_LIMIT);
    if (n < 0 || (size_t)n >= sizeof(text) ||
        !z6ii_hdmi_rx_publish(r, "session.json", (uint8_t *)text, n)) {
        goto fail;
    }
    r->metadata_bytes = n;
    r->initialized = true;
    return Z6II_HDMI_RX_OK;
fail:
    z6ii_hdmi_rx_reject(r, Z6II_HDMI_RX_IO_ERROR);
    free(r->directory);
    r->directory = NULL;
    return r->last_result;
}

static inline bool z6ii_hdmi_rx_same_stream(const Z6IIHDMIRxFrame *a,
                                           const Z6IIHDMIRxFrame *b)
{
    return a->width == b->width && a->height == b->height &&
           a->format == b->format && a->rate_num == b->rate_num &&
           a->rate_den == b->rate_den && a->matrix == b->matrix &&
           a->range == b->range;
}

static inline Z6IIHDMIRxResult z6ii_hdmi_rx_submit(Z6IIHDMIReceiver *r,
                 const Z6IIHDMIRxFrame *f, Z6IIHDMIRxRead read_ram, void *opaque)
{
    size_t row_bytes, frame_bytes;
    char pixels[64], marker[64], text[768];
    uint8_t *snapshot;
    bool reused;
    if (!r->initialized) { return Z6II_HDMI_RX_DISABLED; }
    if (r->closed || r->failed) {
        return z6ii_hdmi_rx_reject(r, Z6II_HDMI_RX_CLOSED);
    }
    if (!read_ram || !z6ii_hdmi_rx_layout(f, &row_bytes, &frame_bytes)) {
        return z6ii_hdmi_rx_reject(r, Z6II_HDMI_RX_BAD_DESCRIPTOR);
    }
    if (r->frames && (f->pts_ns <= r->last.pts_ns ||
                     f->source_sequence <= r->last.source_sequence)) {
        return z6ii_hdmi_rx_reject(r, Z6II_HDMI_RX_NONMONOTONIC);
    }
    if (r->frames && !z6ii_hdmi_rx_same_stream(f, &r->first)) {
        return z6ii_hdmi_rx_reject(r, Z6II_HDMI_RX_RECONFIGURE);
    }
    snprintf(marker, sizeof(marker), "frame-%020" PRIu64 ".json", r->frames);
    if (r->frames >= r->max_frames ||
        r->metadata_bytes + sizeof(text) + 1024 > Z6II_HDMI_RX_METADATA_LIMIT) {
        return z6ii_hdmi_rx_reject(r, Z6II_HDMI_RX_LIMIT);
    }
    snapshot = malloc(frame_bytes);
    if (!snapshot) { errno = ENOMEM;
        return z6ii_hdmi_rx_reject(r, Z6II_HDMI_RX_IO_ERROR); }
    bool ok = true;
    if (f->stride == row_bytes) {
        ok = read_ram(opaque, f->address, snapshot, frame_bytes);
    } else {
        for (uint32_t row = 0; row < f->height; row++) {
            if (!read_ram(opaque, f->address + (uint64_t)row * f->stride,
                          snapshot + row * row_bytes, row_bytes)) {
                ok = false;
                break;
            }
        }
    }
    if (!ok) {
        free(snapshot);
        return z6ii_hdmi_rx_reject(r, Z6II_HDMI_RX_READ_ERROR);
    }
    reused = r->last_snapshot && !memcmp(r->last_snapshot, snapshot, frame_bytes);
    if (!reused && (r->stored_bytes > r->max_bytes ||
                    frame_bytes > r->max_bytes - r->stored_bytes)) {
        free(snapshot);
        return z6ii_hdmi_rx_reject(r, Z6II_HDMI_RX_LIMIT);
    }
    uint64_t pixel_index = reused ? r->last_pixel_index : r->frames;
    snprintf(pixels, sizeof(pixels), "frame-%020" PRIu64 ".pixels", pixel_index);
    int n = snprintf(text, sizeof(text),
        "{\"index\":%" PRIu64 ",\"source_sequence\":%" PRIu64 ","
        "\"pts_ns\":%" PRIu64 ",\"address\":\"0x%016" PRIx64 "\","
        "\"width\":%u,\"height\":%u,\"guest_stride\":%u,"
        "\"row_bytes\":%zu,\"bytes\":%zu,\"format\":\"%s\","
        "\"rate_num\":%u,\"rate_den\":%u,\"matrix\":%u,\"range\":%u,"
        "\"payload_reused\":%s,\"pixels\":\"%s\"}\n",
        r->frames, f->source_sequence, f->pts_ns, f->address,
        f->width, f->height, f->stride, row_bytes, frame_bytes,
        z6ii_hdmi_rx_format_name(f->format), f->rate_num, f->rate_den,
        f->matrix, f->range, reused ? "true" : "false", pixels);
    if (n < 0 || (size_t)n >= sizeof(text) ||
        r->metadata_bytes + n + 1024 > Z6II_HDMI_RX_METADATA_LIMIT) {
        free(snapshot);
        return z6ii_hdmi_rx_reject(r, Z6II_HDMI_RX_LIMIT);
    }
    ok = reused || z6ii_hdmi_rx_publish(r, pixels, snapshot, frame_bytes);
    if (!ok || !z6ii_hdmi_rx_publish(r, marker, (uint8_t *)text, n)) {
        free(snapshot);
        return z6ii_hdmi_rx_reject(r, Z6II_HDMI_RX_IO_ERROR);
    }
    if (!r->frames) { r->first = *f; }
    r->last = *f;
    ++r->frames;
    r->bytes += frame_bytes;
    r->metadata_bytes += n;
    if (reused) {
        ++r->duplicates;
        free(snapshot);
    } else {
        free(r->last_snapshot);
        r->last_snapshot = snapshot;
        r->last_pixel_index = pixel_index;
        r->stored_bytes += frame_bytes;
    }
    r->last_result = Z6II_HDMI_RX_OK;
    return Z6II_HDMI_RX_OK;
}

static inline Z6IIHDMIRxResult z6ii_hdmi_rx_close(Z6IIHDMIReceiver *r)
{
    char text[512];
    if (!r->initialized) { return Z6II_HDMI_RX_DISABLED; }
    if (r->closed) {
        return r->failed ? Z6II_HDMI_RX_IO_ERROR : Z6II_HDMI_RX_OK;
    }
    int n = snprintf(text, sizeof(text),
        "{\"frames\":%" PRIu64 ",\"bytes\":%" PRIu64 ","
        "\"stored_bytes\":%" PRIu64 ",\"duplicate_frames\":%" PRIu64 ","
        "\"first_pts_ns\":%" PRIu64 ",\"last_pts_ns\":%" PRIu64 ","
        "\"rejected\":%" PRIu64 ",\"failed\":%s,\"last_result\":\"%s\","
        "\"last_errno\":%d,\"guest_writes\":0}\n",
        r->frames, r->bytes, r->stored_bytes, r->duplicates,
        r->first.pts_ns, r->last.pts_ns,
        r->rejected, r->failed ? "true" : "false",
        z6ii_hdmi_rx_result_name(r->last_result), r->last_errno);
    if (n < 0 || (size_t)n >= sizeof(text) ||
        !z6ii_hdmi_rx_publish(r, "closed.json", (uint8_t *)text, n)) {
        z6ii_hdmi_rx_reject(r, Z6II_HDMI_RX_IO_ERROR);
    }
    r->closed = true;
    free(r->last_snapshot);
    r->last_snapshot = NULL;
    free(r->directory);
    r->directory = NULL;
    return r->failed ? Z6II_HDMI_RX_IO_ERROR : Z6II_HDMI_RX_OK;
}

#endif
