/* SPDX-License-Identifier: GPL-2.0-or-later
 * Structural fixture only. Never used as original firmware boot evidence.
 * The runner installs .text in private RAM at 0x80000000, after recording
 * the unmodified production machine's initial state and ROM identities.
 */
.syntax unified
.arch armv7-a
.arch_extension sec
.arm
.text
.global e6_mpidr, e6_mpidr_done
e6_mpidr:
    mrc p15, 0, r0, c0, c0, 5
    ldr r1, =0x8000f000
    str r0, [r1]
e6_mpidr_done:
    b .

.global e6_store, e6_store_done
e6_store:
    str r0, [r1]
e6_store_done:
    b .

.global e6_gic_enable, e6_gic_enable_done
e6_gic_enable:
    cpsid if
    ldr r0, =0x2c001000
    mov r1, #1
    str r1, [r0]
    ldr r0, =0x2c002000
    str r1, [r0]
    mov r1, #255
    str r1, [r0, #4]
    ldr r0, =0x2c001100
    ldr r1, =0x68000000 /* PPI 27, 29 and 30 */
    str r1, [r0]
e6_gic_enable_done:
    b .

.global e6_sgi_send, e6_sgi_send_done
e6_sgi_send:
    ldr r0, =0x2c001f00
    str r1, [r0]
e6_sgi_send_done:
    b .

.global e6_gic_ack, e6_gic_ack_done
e6_gic_ack:
    ldr r1, =0x2c00200c
    ldr r0, [r1]
    ldr r2, =0x8000f008
    str r0, [r2]
e6_gic_ack_done:
    b .

.global e6_gic_eoi, e6_gic_eoi_done
e6_gic_eoi:
    ldr r0, =0x2c002010
    str r1, [r0]
e6_gic_eoi_done:
    b .

.global e6_virtual_timer, e6_virtual_timer_done
e6_virtual_timer:
    mov r0, #48
    mcr p15, 0, r0, c14, c3, 0 /* CNTV_TVAL: one virtual microsecond */
    mov r0, #1
    mcr p15, 0, r0, c14, c3, 1 /* CNTV_CTL */
    isb
e6_virtual_timer_done:
    b .

.global e6_virtual_timer_off, e6_virtual_timer_off_done
e6_virtual_timer_off:
    mov r0, #0
    mcr p15, 0, r0, c14, c3, 1
    isb
e6_virtual_timer_off_done:
    b .

.global e6_secure_timer, e6_secure_timer_done
e6_secure_timer:
    mov r0, #48
    mcr p15, 0, r0, c14, c2, 0 /* Secure CNTP_TVAL */
    mov r0, #1
    mcr p15, 0, r0, c14, c2, 1
    isb
e6_secure_timer_done:
    b .

.global e6_secure_timer_off, e6_secure_timer_off_done
e6_secure_timer_off:
    mov r0, #0
    mcr p15, 0, r0, c14, c2, 1
    isb
e6_secure_timer_off_done:
    b .

.global e6_counter, e6_counter_done
e6_counter:
    mrrc p15, 1, r0, r1, c14 /* CNTVCT */
    ldr r2, =0x8000f010
    str r0, [r2]
    str r1, [r2, #4]
    mrc p15, 0, r0, c14, c0, 0 /* CNTFRQ */
    str r0, [r2, #8]
e6_counter_done:
    b .

/* Exercise the actual nonsecure CNTP bank through guest security transitions.
 * No debugger CPSR/SCR/PC-return injection is used. */
.global e6_nonsecure_enter, e6_nonsecure_enter_done
e6_nonsecure_enter:
    cps #0x16 /* Secure Monitor */
    adr r1, .Lmonitor_vectors
    mcr p15, 0, r1, c12, c0, 1 /* MVBAR */
    mrc p15, 0, r0, c1, c1, 0 /* SCR */
    orr r0, r0, #1 /* NS */
    mcr p15, 0, r0, c1, c1, 0
    ldr r1, =0x8000f024
    str r0, [r1]
    isb
    cps #0x13 /* Nonsecure SVC */
e6_nonsecure_enter_done:
    b .

.global e6_physical_timer, e6_physical_timer_done
e6_physical_timer:
    mov r0, #48
    mcr p15, 0, r0, c14, c2, 0 /* Nonsecure CNTP_TVAL */
    mov r0, #1
    mcr p15, 0, r0, c14, c2, 1
    isb
e6_physical_timer_done:
    b .

.global e6_physical_timer_off, e6_physical_timer_off_done
e6_physical_timer_off:
    mov r0, #0
    mcr p15, 0, r0, c14, c2, 1
    isb
e6_physical_timer_off_done:
    b .

.global e6_secure_return, e6_secure_return_done
e6_secure_return:
    smc #0
e6_secure_return_done:
    b .

.balign 32
.Lmonitor_vectors:
    b .
    b .
    b .Lsecure_return
    b .
    b .
    b .
    b .
    b .
.Lsecure_return:
    mrc p15, 0, r0, c1, c1, 0
    bic r0, r0, #1
    mcr p15, 0, r0, c1, c1, 0
    ldr r1, =0x8000f028
    str r0, [r1]
    isb
    movs pc, lr
    .ltorg
