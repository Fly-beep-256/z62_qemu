/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef Z6II_BA2_BUS77_H
#define Z6II_BA2_BUS77_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "nikon-z6ii-ipu2402.h"

/* No implicit ARM VA/PA conversion, peer reset PC, opcode, or protocol reply.
 * The caller must verify the original payload SHA before binding its bytes:
 * 2e765a41822d563b35f726240f9c9e817c95d749bebce45d90b3a9120a590a16.
 * 40000000 payload / 60000000 RAM / 80010500 device are static candidates;
 * their external bindings require explicit configuration and provenance. */
#define Z6II_BA2_PAYLOAD_BYTES UINT32_C(0x3b1c0)
#define Z6II_BA2_MAX_RAM_MAPS 4u
#define Z6II_BA2_MEM_READ 1u
#define Z6II_BA2_MEM_WRITE 2u
#define Z6II_BA2_MEM_EXEC 4u

typedef enum {
    Z6II_BA2_BUS_OK = 0,
    Z6II_BA2_BUS_BAD_CONFIG,
    Z6II_BA2_BUS_UNMAPPED,
    Z6II_BA2_BUS_PERMISSION,
    Z6II_BA2_BUS_BAD_WIDTH,
    Z6II_BA2_BUS_BAD_ALIGNMENT,
    Z6II_BA2_BUS_DEVICE_FAULT
} Z6IIBA2BusResult;

typedef enum { Z6II_BA2_DATA_LE = 1, Z6II_BA2_DATA_BE = 2 } Z6IIBA2DataEndian;

typedef struct {
    uint32_t base;
    size_t size;
    const uint8_t *bytes;
    uint8_t *writable_bytes; /* Same allocation as bytes; NULL when readonly. */
    unsigned permissions;
    const char *mapping_basis; /* Required, including unproved external binding. */
} Z6IIBA2MemoryMap;

typedef Z6IIBA2BusResult (*Z6IIBA2ReadFn)(void *, uint32_t, unsigned, uint32_t *);
typedef Z6IIBA2BusResult (*Z6IIBA2WriteFn)(void *, uint32_t, unsigned, uint32_t);
typedef bool (*Z6IIBA2IRQFn)(void *);
typedef void (*Z6IIBA2MasterIRQUpdateFn)(void *);

typedef struct {
    uint32_t base;
    size_t size;
    Z6IIBA2ReadFn read;
    Z6IIBA2WriteFn write;
    Z6IIBA2IRQFn peer_irq; /* Query only: no SPR number, vector or priority implied. */
    void *opaque;
    const char *mapping_basis;
} Z6IIBA2MMIOMap;

typedef struct {
    Z6IIBA2MemoryMap payload; /* Exactly original 3B1C0 bytes; READ|EXEC, never WRITE. */
    const Z6IIBA2MemoryMap *ram;
    unsigned ram_count;
    Z6IIBA2MMIOMap mmio; /* One explicit window, or size=0 to leave absent. */
    Z6IIBA2DataEndian data_endian;
    bool allow_unaligned_data; /* Explicit model policy, not an ISA assertion. */
    Z6IIIPU2402 *master_fifo; /* Optional named endpoint; no inferred wiring. */
    const char *fifo_binding_basis;
    Z6IIBA2MasterIRQUpdateFn master_irq_update;
    void *master_irq_opaque;
} Z6IIBA2BusConfig;

typedef struct {
    Z6IIBA2BusResult result;
    uint32_t address;
    unsigned size;
    bool write;
    bool fetch;
} Z6IIBA2BusFault;

typedef struct {
    Z6IIBA2BusConfig config;
    Z6IIBA2BusFault fault; /* Last failed access; CPU adds its own PC/raw/registers. */
    bool initialized;
} Z6IIBA2Bus;

Z6IIBA2BusResult z6ii_ba2_bus_init(Z6IIBA2Bus *, const Z6IIBA2BusConfig *);
/* Callback signatures for the independent core. Fetch returns original bytes;
 * successful data accesses alone perform explicit BE/LE conversion. Failure
 * preserves output and memory. No partial accesses across map boundaries. */
Z6IIBA2BusResult z6ii_ba2_bus_fetch(void *, uint32_t, uint8_t *, unsigned);
Z6IIBA2BusResult z6ii_ba2_bus_read(void *, uint32_t, unsigned, uint32_t *);
Z6IIBA2BusResult z6ii_ba2_bus_write(void *, uint32_t, unsigned, uint32_t);
bool z6ii_ba2_bus_irq(void *);

/* These are called by original BA2 execution's identified device operations,
 * never by a timer/reset/window commit. Both preserve all opaque words and
 * use the existing Master FIFO as the sole owner. The MMIO implementation is
 * supplied separately; this layer invents no controller register semantics. */
Z6IIIPU2402Result z6ii_ba2_bus_take_tx(Z6IIBA2Bus *, uint32_t frame[3]);
Z6IIIPU2402Result z6ii_ba2_bus_push_rx(Z6IIBA2Bus *, const uint32_t frame[3]);
#endif
