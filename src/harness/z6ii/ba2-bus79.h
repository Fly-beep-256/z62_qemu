/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef Z6II_BA2_BUS79_H
#define Z6II_BA2_BUS79_H
#include "ba2-bus77.h"
#define Z6II_BA2_RAM_BATCH_MAX 32u
/* Optional callback for one grouped store. Ordinary RAM only, exactly 4 bytes
 * each, explicit bus endian/alignment, no overlapping destination bytes.
 * Snapshots input arrays, prechecks ALL targets, then commits without further
 * fallible callbacks. Failure preserves every RAM byte and records first fault.
 * Caller owns BQL / exclusive access to backing and config throughout the call.
 * This is a software transaction; it defines no silicon grouped-store policy. */
Z6IIBA2BusResult z6ii_ba2_bus_write_ram_batch(void *opaque,
    const uint32_t *addresses, const uint32_t *values, unsigned count);
#endif
