/* Run-local cold bus creation and stopped-endpoint inspection only. */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "mcu_wire_bus.h"

int main(int argc, char **argv)
{
    if (argc != 3 || argv[2][0] != '/' ||
        (strcmp(argv[1], "create-cold") && strcmp(argv[1], "inspect-stopped"))) {
        fprintf(stderr, "usage: mcu-wire-host create-cold|inspect-stopped /absolute/bus\n");
        return 2;
    }
    int create = !strcmp(argv[1], "create-cold");
    int fd = open(argv[2], create ? O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW : O_RDONLY | O_NOFOLLOW, 0600);
    if (fd < 0) { perror("open run-local bus"); return 3; }
    if (create && ftruncate(fd, sizeof(MCUWireBus))) {
        perror("size cold bus"); close(fd); unlink(argv[2]); return 3;
    }
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size != sizeof(MCUWireBus)) {
        fprintf(stderr, "regular ABI%u-sized bus required\n", MCU_WIRE_ABI); close(fd); return 4;
    }
    MCUWireBus *bus = mmap(NULL, sizeof(*bus), create ? PROT_READ | PROT_WRITE : PROT_READ, MAP_SHARED, fd, 0);
    if (bus == MAP_FAILED) { perror("map bus"); close(fd); return 3; }
    if (create) {
        mcu_wire_init(bus);
        if (msync(bus, sizeof(*bus), MS_SYNC)) { perror("flush cold bus"); return 3; }
    }
    if (mcu_wire_validate(bus) != MCU_WIRE_OK || atomic_load_explicit(&bus->h.lock, memory_order_acquire)) {
        fprintf(stderr, "invalid ABI or busy/stale bus; do not alter lock\n");
        munmap(bus, sizeof(*bus)); close(fd); return 5;
    }
    /* inspect-stopped requires the caller to have closed both owned guests.
     * It never clears a lock, writes RAM, or reinitializes a used bus. */
    MCUWireCore c;
    memcpy(&c, &bus->h.core, sizeof(c));
    printf("{\"operation\":\"%s\",\"abi\":%u,\"bytes\":%zu,\"lock\":0,"
           "\"requires_stopped_endpoints\":%s,\"ahb1enr\":%u,\"apb2enr\":%u,"
           "\"spi_cr1\":[%u,%u],\"spi_cr2\":[%u,%u],"
           "\"spi_dr\":[%u,%u],\"spi_sr\":[%u,%u],\"spi_ovr_dr_read\":[%u,%u],"
           "\"dma_cr\":[%u,%u],\"dma_ndtr\":[%u,%u],\"dma_transferred\":[%u,%u],"
           "\"mcu_known\":%u,\"mcu_level\":%u,\"master_ack_known\":%u,"
           "\"master_ack_level\":%u,\"master_ack_edges\":%u,"
           "\"shifted_bytes\":[%" PRIu64 ",%" PRIu64 "],"
           "\"spi_received_bytes\":[%" PRIu64 ",%" PRIu64 "],"
           "\"spi_overrun_bytes\":[%" PRIu64 ",%" PRIu64 "],"
           "\"spi_ovr_clears\":[%" PRIu64 ",%" PRIu64 "]}\n",
           argv[1], bus->h.abi, sizeof(*bus), create ? "false" : "true",
           c.ahb1enr, c.apb2enr, c.spi_cr1[0], c.spi_cr1[1], c.spi_cr2[0], c.spi_cr2[1],
           c.spi_dr[0], c.spi_dr[1], c.spi_sr[0], c.spi_sr[1],
           c.spi_ovr_dr_read[0], c.spi_ovr_dr_read[1],
           c.dma[0].reg[0], c.dma[1].reg[0], c.dma[0].reg[1], c.dma[1].reg[1],
           c.dma[0].transferred, c.dma[1].transferred,
           c.mcu_known, c.mcu_level, c.master_ack_known, c.master_ack_level,
           c.master_ack_edge_count, c.shifted_bytes[0], c.shifted_bytes[1],
           c.spi_received_bytes[0], c.spi_received_bytes[1],
           c.spi_overrun_bytes[0], c.spi_overrun_bytes[1],
           c.spi_ovr_clears[0], c.spi_ovr_clears[1]);
    munmap(bus, sizeof(*bus)); close(fd);
    return 0;
}
