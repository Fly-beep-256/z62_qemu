/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef BA2_STARTUP_RAM_READ_H
#define BA2_STARTUP_RAM_READ_H
#include "ba2-core7494.h"
Z6IIBA2BusResult z6ii_ba2_startup_ram_read_batch(void *,const uint32_t *,uint32_t *,unsigned);
Z6IIBA2BusResult z6ii_ba2_startup_ram_write_batch(void *,const uint32_t *,const uint32_t *,unsigned);
#endif
