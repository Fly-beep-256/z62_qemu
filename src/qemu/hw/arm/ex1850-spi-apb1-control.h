/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Review candidate only: STM32F412 SPI2/SPI3 disabled control latches.
 *
 * Original 0803AD18 -> 0804545E configures SPI3 as CR1=0x2bb, CR2=0,
 * and clears I2SMOD; 0802D5EC -> 0804545E configures SPI2 as CR1=0x31f.
 * This helper does not own SPI1/SPI4, a wire bus, SR/DR, CRC, DMA or IRQ.
 * SPE, DMA/interrupt enables and all status/data accesses stay strict.
 * A return of OK means one admitted control access, never boot or transfer
 * completion. RCC inputs must be the original guest-written register state.
 */
#ifndef EX1850_SPI_APB1_CONTROL_H
#define EX1850_SPI_APB1_CONTROL_H
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define EX1850_APB1_SPI2_BASE UINT32_C(0x40003800)
#define EX1850_APB1_SPI3_BASE UINT32_C(0x40003c00)
#define EX1850_APB1_SPI_MASK UINT32_C(0x0000c000)

typedef struct EX1850APB1SPIControl {
    uint32_t cr1[2], cr2[2], i2scfgr[2]; /* [0] SPI2; [1] SPI3 */
} EX1850APB1SPIControl;

typedef enum EX1850APB1SPIResult {
    EX1850_APB1_SPI_OK = 0,
    EX1850_APB1_SPI_OTHER_ADDRESS,
    EX1850_APB1_SPI_BAD_ACCESS,
    EX1850_APB1_SPI_CLOCK_OFF,
    EX1850_APB1_SPI_RESET_HELD,
    EX1850_APB1_SPI_STATUS_UNMODELED,
    EX1850_APB1_SPI_DATA_UNMODELED,
    EX1850_APB1_SPI_ACTIVE_UNMODELED,
    EX1850_APB1_SPI_MODE_UNMODELED,
    EX1850_APB1_SPI_REGISTER_UNMODELED,
} EX1850APB1SPIResult;

static inline int ex1850_apb1_spi_index(uint32_t address)
{
    if (address >= EX1850_APB1_SPI2_BASE &&
        address < EX1850_APB1_SPI2_BASE + 0x24) { return 0; }
    if (address >= EX1850_APB1_SPI3_BASE &&
        address < EX1850_APB1_SPI3_BASE + 0x24) { return 1; }
    return -1;
}

/* Caller passes only the SPI2RST/SPI3RST asserted bits, e.g. the relevant
 * rising-edge mask. Reset is independent of peripheral clock gating.
 * Other peripherals, DMA, GPIO, RAM and IRQs are outside this structure.
 * A held reset must still be supplied to access(); do not silently release it.
 */
static inline bool ex1850_apb1_spi_reset(EX1850APB1SPIControl *c,
                                        uint32_t asserted)
{
    if (!c || (asserted & ~EX1850_APB1_SPI_MASK)) { return false; }
    for (unsigned n = 0; n < 2; n++) {
        if (asserted & (UINT32_C(1) << (14 + n))) {
            c->cr1[n] = 0;
            c->cr2[n] = 0;
            c->i2scfgr[n] = 0;
        }
    }
    return true;
}

/* Exact 32-bit accesses to CR1, CR2, I2SCFGR only. Disabled normal 8-bit SPI
 * control bits CPHA,CPOL,MSTR,BR,LSBFIRST,SSI,SSM may be latched. CR2 may
 * latch only SSOE (inactive while SPE=0); original tested profiles write zero.
 * Nonzero I2S configuration, CRC, bidirectional/receive-only/16-bit modes and
 * activation require a separate evidence-backed model.
 * Rejection leaves both *value and all state unchanged. In particular, a
 * gate-off access is a boundary, not an invented zero read / ignored write.
 */
static inline EX1850APB1SPIResult ex1850_apb1_spi_access(
    EX1850APB1SPIControl *c, uint32_t apb1enr, uint32_t apb1rstr,
    uint32_t address, unsigned size, bool write, uint32_t *value)
{
    int n = ex1850_apb1_spi_index(address);
    if (n < 0) { return EX1850_APB1_SPI_OTHER_ADDRESS; }
    if (!c || !value || size != 4 || (address & 3)) {
        return EX1850_APB1_SPI_BAD_ACCESS;
    }
    uint32_t gate = UINT32_C(1) << (14 + n);
    if (!(apb1enr & gate)) { return EX1850_APB1_SPI_CLOCK_OFF; }
    if (apb1rstr & gate) { return EX1850_APB1_SPI_RESET_HELD; }
    uint32_t offset = address - (n ? EX1850_APB1_SPI3_BASE :
                                     EX1850_APB1_SPI2_BASE);
    switch (offset) {
    case 0x00:
        if (!write) { *value = c->cr1[n]; return EX1850_APB1_SPI_OK; }
        if (*value & UINT32_C(0x40)) {
            return EX1850_APB1_SPI_ACTIVE_UNMODELED;
        }
        if (*value & ~UINT32_C(0x3bf)) {
            return EX1850_APB1_SPI_MODE_UNMODELED;
        }
        c->cr1[n] = *value;
        return EX1850_APB1_SPI_OK;
    case 0x04:
        if (!write) { *value = c->cr2[n]; return EX1850_APB1_SPI_OK; }
        if (*value & UINT32_C(0xe3)) {
            return EX1850_APB1_SPI_ACTIVE_UNMODELED;
        }
        if (*value & ~UINT32_C(0x4)) {
            return EX1850_APB1_SPI_MODE_UNMODELED;
        }
        c->cr2[n] = *value;
        return EX1850_APB1_SPI_OK;
    case 0x08:
        return EX1850_APB1_SPI_STATUS_UNMODELED;
    case 0x0c:
        return EX1850_APB1_SPI_DATA_UNMODELED;
    case 0x1c:
        if (!write) { *value = c->i2scfgr[n]; return EX1850_APB1_SPI_OK; }
        if (*value) { return EX1850_APB1_SPI_MODE_UNMODELED; }
        c->i2scfgr[n] = 0;
        return EX1850_APB1_SPI_OK;
    default:
        return EX1850_APB1_SPI_REGISTER_UNMODELED;
    }
}
#endif
