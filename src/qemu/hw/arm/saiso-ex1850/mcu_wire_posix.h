/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Existing fresh run-local file only. This connector never initializes or
 * resets another endpoint's SRAM/state. One MCU and one master per file. */
#ifndef Z6II_MCU_WIRE_POSIX_H
#define Z6II_MCU_WIRE_POSIX_H
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "mcu_wire_bus.h"

typedef struct MCUWireMapping {
    MCUWireBus *bus;
    int fd;
} MCUWireMapping;

static inline int mcu_wire_attach(const char *path, unsigned role,
                                 MCUWireMapping *mapping)
{
    struct stat st;
    struct flock endpoint_lock = {0};
    int fd;
    MCUWireBus *bus;
    if (!path || path[0] != '/' || (role != 1 && role != 2)) {
        errno = EINVAL; return -1;
    }
    fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) { return -1; }
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size != sizeof(*bus)) {
        int saved = errno ? errno : EINVAL;
        close(fd); errno = saved; return -1;
    }
    endpoint_lock.l_type = F_WRLCK;
    endpoint_lock.l_whence = SEEK_SET;
    endpoint_lock.l_start = role;
    endpoint_lock.l_len = 1;
    if (fcntl(fd, F_SETLK, &endpoint_lock)) {
        int saved = errno;
        close(fd); errno = saved; return -1;
    }
    bus = mmap(NULL, sizeof(*bus), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (bus == MAP_FAILED) {
        int saved = errno;
        close(fd); errno = saved; return -1;
    }
    if (mcu_wire_validate(bus) != MCU_WIRE_OK) {
        munmap(bus, sizeof(*bus)); close(fd); errno = EINVAL; return -1;
    }
    mapping->bus = bus; mapping->fd = fd;
    return 0;
}

static inline void mcu_wire_detach(MCUWireMapping *mapping)
{
    if (mapping->bus) {
        munmap(mapping->bus, sizeof(*mapping->bus));
        close(mapping->fd); mapping->bus = NULL; mapping->fd = -1;
    }
}

static inline void mcu_wire_snapshot(MCUWireBus *bus, MCUWireCore *core)
{
    mcu_wire_lock(bus); *core = bus->h.core; mcu_wire_unlock(bus);
}

/* Master-only host causality experiment. ABI and MCU state are unchanged.
 * A try-lock prevents the wait itself from exceeding its host deadline while
 * another process owns the wire lock. No guessed pad value is returned. */
static inline int mcu_wire_try_snapshot(MCUWireBus *bus, MCUWireCore *core)
{
    uint32_t unlocked = 0;
    if (!atomic_compare_exchange_strong_explicit(&bus->h.lock, &unlocked, 1,
                                                 memory_order_acquire,
                                                 memory_order_relaxed)) {
        return 0;
    }
    *core = bus->h.core;
    mcu_wire_unlock(bus);
    return 1;
}

static inline int mcu_wire_host_monotonic_ns(uint64_t *value)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) { return -1; }
    *value = (uint64_t)now.tv_sec * UINT64_C(1000000000) + now.tv_nsec;
    return 0;
}

enum MCUWireHostWaitResult {
    MCU_WIRE_HOST_WAIT_READY,
    MCU_WIRE_HOST_WAIT_TIMEOUT,
    MCU_WIRE_HOST_WAIT_ERROR,
    MCU_WIRE_HOST_WAIT_REJECTED,
};

/* A pending master word waits for the original MCU to rearm its next frame.
 * Only NOT_READY is retryable. Acquisition and every retry are deadline-bound;
 * no lock is held during sleep, and no bytes move on timeout or rejection.
 * clock_result retains the device error independently of the host outcome. */
static inline int mcu_wire_host_wait_clock16(MCUWireBus *bus, unsigned channel,
                                uint16_t tx, uint16_t *rx, uint64_t deadline_ns,
                                MCUWireCore *failure, int *clock_result,
                                uint64_t *observed_ns)
{
    for (;;) {
        uint64_t now;
        if (mcu_wire_host_monotonic_ns(&now)) { return MCU_WIRE_HOST_WAIT_ERROR; }
        *observed_ns = now;
        if (now >= deadline_ns) { return MCU_WIRE_HOST_WAIT_TIMEOUT; }
        uint32_t unlocked = 0;
        if (atomic_compare_exchange_strong_explicit(&bus->h.lock, &unlocked, 1,
                                                    memory_order_acquire,
                                                    memory_order_relaxed)) {
            if (mcu_wire_host_monotonic_ns(&now)) {
                mcu_wire_unlock(bus); return MCU_WIRE_HOST_WAIT_ERROR;
            }
            *observed_ns = now;
            if (now >= deadline_ns) {
                mcu_wire_unlock(bus); return MCU_WIRE_HOST_WAIT_TIMEOUT;
            }
            *clock_result = mcu_wire_clock16_locked(bus, channel, tx, rx, failure);
            mcu_wire_unlock(bus);
            if (*clock_result == MCU_WIRE_OK) { return MCU_WIRE_HOST_WAIT_READY; }
            if (*clock_result != MCU_WIRE_NOT_READY) {
                return MCU_WIRE_HOST_WAIT_REJECTED;
            }
        }
        uint64_t remaining = deadline_ns - now;
        struct timespec pause = {0, remaining < 500000 ? remaining : 500000};
        if (nanosleep(&pause, NULL) && errno != EINTR) {
            return MCU_WIRE_HOST_WAIT_ERROR;
        }
    }
}

/* Called only with an explicit future CLOCK_MONOTONIC deadline. Each lock is
 * released before the next bounded host sleep; the core remains producer-owned.
 * have_snapshot distinguishes real observations from unavailable lock state. */
static inline int mcu_wire_host_wait_known(MCUWireBus *bus, uint32_t needed,
                                          uint64_t deadline_ns, MCUWireCore *core,
                                          int *have_snapshot, uint64_t *observed_ns)
{
    for (;;) {
        uint64_t now;
        if (mcu_wire_host_monotonic_ns(&now)) { return MCU_WIRE_HOST_WAIT_ERROR; }
        *observed_ns = now;
        if (now >= deadline_ns) { return MCU_WIRE_HOST_WAIT_TIMEOUT; }
        if (mcu_wire_try_snapshot(bus, core)) {
            *have_snapshot = 1;
            if (mcu_wire_host_monotonic_ns(&now)) { return MCU_WIRE_HOST_WAIT_ERROR; }
            *observed_ns = now;
            if (now >= deadline_ns) { return MCU_WIRE_HOST_WAIT_TIMEOUT; }
            if ((core->mcu_known & needed) == needed) {
                return MCU_WIRE_HOST_WAIT_READY;
            }
        }
        uint64_t remaining = deadline_ns - now;
        struct timespec pause = {0, remaining < 500000 ? remaining : 500000};
        if (nanosleep(&pause, NULL) && errno != EINTR) {
            return MCU_WIRE_HOST_WAIT_ERROR;
        }
    }
}
#endif
