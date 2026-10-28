/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Generated from the retained 19 original Thumb sites; no guest writes. */
#ifndef Z6II_SOURCE50_OBSERVER_H
#define Z6II_SOURCE50_OBSERVER_H

bool z6ii_s50_observer_enabled(void);

static inline unsigned z6ii_s50_site_id(uint32_t pc, uint32_t opcode)
{
    switch (pc) {
    case 0x10324b90u:
        return opcode == 0x0000b570u ? 1 : 0;
    case 0x103d04c6u:
        return opcode == 0x00006188u ? 2 : 0;
    case 0x103d04c8u:
        return opcode == 0x00004770u ? 3 : 0;
    case 0x10200af4u:
        return opcode == 0xf041fbdfu ? 4 : 0;
    case 0x10200af8u:
        return opcode == 0x00002004u ? 5 : 0;
    case 0x103c2bb6u:
        return opcode == 0xe92d4fffu ? 6 : 0;
    case 0x103c2c30u:
        return opcode == 0x00009007u ? 7 : 0;
    case 0x103c2ccau:
        return opcode == 0xf7e3f950u ? 8 : 0;
    case 0x103a5f88u:
        return opcode == 0x0000b1b0u ? 9 : 0;
    case 0x103c2cceu:
        return opcode == 0x0000e7d8u ? 10 : 0;
    case 0x103c2d00u:
        return opcode == 0x000062b0u ? 11 : 0;
    case 0x103c2d02u:
        return opcode == 0x0000b15au ? 12 : 0;
    case 0x103c2d08u:
        return opcode == 0xf8562024u ? 13 : 0;
    case 0x103c2d10u:
        return opcode == 0x00004790u ? 14 : 0;
    case 0x103cf818u:
        return opcode == 0xe92d43feu ? 15 : 0;
    case 0x103cf8dau:
        return opcode == 0x00002800u ? 16 : 0;
    case 0x103cf8e2u:
        return opcode == 0x000069b2u ? 17 : 0;
    case 0x103cf8e4u:
        return opcode == 0x0000b003u ? 18 : 0;
    case 0x103cf8eau:
        return opcode == 0x00004710u ? 19 : 0;
    default:
        return 0;
    }
}

static inline const char *z6ii_s50_site_name(unsigned site)
{
    switch (site) {
    case 1:
        return "phase_entry";
    case 2:
        return "bind_store_before";
    case 3:
        return "bind_return";
    case 4:
        return "stage_announcement_call";
    case 5:
        return "stage_announcement_return";
    case 6:
        return "producer_entry";
    case 7:
        return "event_value_constructed";
    case 8:
        return "copy_call";
    case 9:
        return "copy_ownership_result";
    case 10:
        return "copy_return";
    case 11:
        return "notification_mask_store_before";
    case 12:
        return "notification_mask_store_after";
    case 13:
        return "notification_callback_load";
    case 14:
        return "notification_callback_call";
    case 15:
        return "upper_dispatch_entry";
    case 16:
        return "pending_gate_return";
    case 17:
        return "upper_slot_load_before";
    case 18:
        return "upper_slot_load_after";
    case 19:
        return "upper_tail_BX";
    default:
        return "unknown";
    }
}

#endif /* Z6II_SOURCE50_OBSERVER_H */
