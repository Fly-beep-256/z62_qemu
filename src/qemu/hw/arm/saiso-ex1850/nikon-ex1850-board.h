/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef NIKON_EX1850_BOARD_H
#define NIKON_EX1850_BOARD_H

#include "hw/boards.h"
#include "system/memory.h"

/* Embed the original reset-vector machine without changing its MCU model. */
struct MCUWireBus;
void *nikon_ex1850_init(MachineState *machine, MemoryRegion *memory,
                        const char *firmware, bool unified,
                        struct MCUWireBus *shared_wire, const char *wire_path,
                        Object *cpu_parent);
uint32_t nikon_ex1850_cpu_hz(void *board);
QDict *nikon_ex1850_architecture_state(void *board,
                                     struct MCUWireBus *master_wire);

#endif
