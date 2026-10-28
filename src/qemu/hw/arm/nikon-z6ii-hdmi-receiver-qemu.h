/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Independent receiver adapter, called ONLY by a verified HDMI producer.
 * Include after qemu/osdep.h, system/address-spaces.h and the receiver core.
 * The caller holds the BQL while the snapshot is made. */
#ifndef NIKON_Z6II_HDMI_RECEIVER_QEMU_H
#define NIKON_Z6II_HDMI_RECEIVER_QEMU_H

static inline bool z6ii_hdmi_rx_qemu_read(void *opaque, uint64_t address,
                                        uint8_t *buffer, size_t bytes)
{
    AddressSpace *as = opaque;
    if (!bytes || address > UINT64_MAX - bytes) { return false; }
    hwaddr current = address, remaining = bytes;
    /* Preflight the entire requested row/span before doing any reads.
     * A buffer into MMIO must never produce a side-effecting read. */
    while (remaining) {
        hwaddr translated, length = remaining;
        MemoryRegion *mr = address_space_translate(as, current, &translated,
                                                   &length, false,
                                                   MEMTXATTRS_UNSPECIFIED);
        if (!mr || !length || length > remaining || !memory_region_is_ram(mr) ||
            memory_region_is_rom(mr)) {
            return false;
        }
        current += length;
        remaining -= length;
    }
    return address_space_read(as, address, MEMTXATTRS_UNSPECIFIED,
                              buffer, bytes) == MEMTX_OK;
}

static inline Z6IIHDMIRxResult z6ii_hdmi_rx_qemu_submit(
                         Z6IIHDMIReceiver *receiver,
                         const Z6IIHDMIRxFrame *frame, AddressSpace *as)
{
    /* This return value acknowledges host persistence only. It must not be
     * reused as evidence for a silicon frame-done bit or firmware Ready. */
    return z6ii_hdmi_rx_submit(receiver, frame, z6ii_hdmi_rx_qemu_read,
                               as);
}

#endif
