/* SPDX-License-Identifier: GPL-2.0-or-later
 * Structural fixture only; RAM entry at 0x2003e000. Flash is never patched.
 */
.syntax unified
.arch armv7e-m
.thumb
.text
.global mcu_mask, mcu_mask_done
.thumb_func
mcu_mask:
    cpsid i
mcu_mask_done:
    b .

.global mcu_store, mcu_store_done
.thumb_func
mcu_store:
    str r0, [r1]
mcu_store_done:
    b .

.global mcu_reset, mcu_reset_store, mcu_reset_done
.thumb_func
mcu_reset:
    ldr r0, =0xe000ed0c
    ldr r1, =0x05fa0004 /* AIRCR.VECTKEY | SYSRESETREQ */
    dsb
mcu_reset_store:
    str r1, [r0]
    dsb
mcu_reset_done:
    b .
    .ltorg
