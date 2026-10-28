/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Opt-in lifecycle only. Include after receiver core/adapter, qemu/notify.h,
 * and system/system.h. No pixel source or register ownership is added. */
#ifndef NIKON_Z6II_HDMI_RECEIVER_LIFECYCLE_H
#define NIKON_Z6II_HDMI_RECEIVER_LIFECYCLE_H

#include "nikon-z6ii-engine.h"

typedef struct Z6IIHDMIRxQEMU {
    Z6IIHDMIReceiver receiver;
    Notifier exit_notifier;
    bool notifier_registered;
    void (*before_close)(void *opaque);
    void *before_close_opaque;
} Z6IIHDMIRxQEMU;

static inline bool z6ii_hdmi_rx_u64(const char *text, uint64_t maximum,
                                   uint64_t *value)
{
    uint64_t result = 0;
    if (!text || !*text) { return false; }
    for (const char *p = text; *p; p++) {
        if (*p < '0' || *p > '9') { return false; }
        unsigned digit = *p - '0';
        if (result > maximum / 10 ||
            (result == maximum / 10 && digit > maximum % 10)) { return false; }
        result = result * 10 + digit;
    }
    if (!result) { return false; }
    *value = result;
    return true;
}

static inline void z6ii_hdmi_rx_exit(Notifier *notifier, void *data)
{
    (void)data;
    Z6IIHDMIRxQEMU *s = (Z6IIHDMIRxQEMU *)((char *)notifier -
                              offsetof(Z6IIHDMIRxQEMU, exit_notifier));
    if (s->before_close) { s->before_close(s->before_close_opaque); }
    Z6IIHDMIRxResult result = z6ii_hdmi_rx_close(&s->receiver);
    fprintf(stderr, "Z6II_HDMI_RX_CLOSE frames=%" PRIu64
            " stored_bytes=%" PRIu64 " duplicates=%" PRIu64
            " result=%s guest_writes=0\n", s->receiver.frames,
            s->receiver.stored_bytes, s->receiver.duplicates,
            z6ii_hdmi_rx_result_name(result));
}

static inline Z6IIHDMIRxResult z6ii_hdmi_rx_qemu_open(Z6IIHDMIRxQEMU *s,
                 const char *directory, const char *frames, const char *bytes)
{
    uint64_t max_frames, max_bytes;
    memset(s, 0, sizeof(*s));
    if (!directory) { return Z6II_HDMI_RX_DISABLED; }
    if (!z6ii_hdmi_rx_u64(frames, 1000000, &max_frames) ||
        !z6ii_hdmi_rx_u64(bytes, UINT64_C(4294967296), &max_bytes)) {
        return Z6II_HDMI_RX_BAD_DESCRIPTOR;
    }
    Z6IIHDMIRxResult result = z6ii_hdmi_rx_init(&s->receiver, directory,
                                              max_frames, max_bytes, false);
    if (result == Z6II_HDMI_RX_OK) {
        s->exit_notifier.notify = z6ii_hdmi_rx_exit;
        qemu_add_exit_notifier(&s->exit_notifier);
        s->notifier_registered = true;
        fprintf(stderr, "Z6II_HDMI_RX_OPEN max_frames=%" PRIu64
                " max_bytes=%" PRIu64 " producer_attached=0"
                " source_claim_requires_submitter_evidence=1 guest_writes=0\n",
                max_frames, max_bytes);
    }
    return result;
}

static inline Z6IIHDMIRxResult z6ii_hdmi_rx_qemu_init(Z6IIHDMIRxQEMU *s, Z6IIEngineContext *engine)
{
    return z6ii_hdmi_rx_qemu_open(s, z6ii_engine_getenv(engine, "Z6II_HDMI_RX_DIRECTORY"),
                    z6ii_engine_getenv(engine, "Z6II_HDMI_RX_MAX_FRAMES"),
                    z6ii_engine_getenv(engine, "Z6II_HDMI_RX_MAX_BYTES"));
}

#endif
