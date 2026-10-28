/* SPDX-License-Identifier: GPL-2.0-or-later */
/* No firmware is executed. Check that incomplete work cannot become idle
 * through configuration, request clears, reset pulses, or zero counters. */
#include <assert.h>
#include <stdio.h>
#include "../src/qemu/hw/arm/nikon-z6ii-image-submission-core.h"
#include "../src/qemu/hw/arm/nikon-z6ii-image-register-map.h"

int main(void)
{
    Z6IIImageSubmissionState s = {0};
    uint32_t word = 0xdeadbeef;
    z6ii_image_submission_reset(&s);
    assert(z6ii_image_reset_word(&s, &word) && word == 0);

    /* These are the actual unarmed words observed before the SRAM clear.
     * Sequence configuration 305/202 is distinct from a +08 request. */
    assert(z6ii_image_submission_write(&s, 0x20102000, 0x130));
    assert(z6ii_image_submission_write(&s, 0x20102100, 0x120));
    assert(!z6ii_image_submission_write(&s, 0x20102600, 0x305));
    assert(!z6ii_image_submission_write(&s, 0x20102640, 0x202));
    assert(!z6ii_image_submission_write(&s, 0x20100948, 0x100));
    assert(!z6ii_image_submission_write(&s, 0x2010094c, 0x200));
    assert(!z6ii_image_submission_write(&s, 0x20100954, 1));
    assert(!z6ii_image_submission_write(&s, 0x20100954, 0));
    assert(!z6ii_image_submission_write(&s, 0x20100950, 0xc2bba000));
    assert(z6ii_image_reset_word(&s, &word));

    /* A start with no completed frames is unresolved, rather than idle. */
    assert(z6ii_image_submission_write(&s, 0x20102000, 0x131));
    word = 0xdeadbeef;
    assert(!z6ii_image_reset_word(&s, &word) && word == 0xdeadbeef);
    assert(z6ii_image_submission_write(&s, 0x20102000, 0x130));
    assert(z6ii_image_submission_write(&s, 0x201020a4, 1));
    assert(z6ii_image_submission_write(&s, 0x201020a4, 0));
    assert(!z6ii_image_reset_word(&s, &word));

    assert(z6ii_image_submission_write(&s, 0x20102608, 2));
    assert(z6ii_image_submission_write(&s, 0x20102608, 0));
    assert(z6ii_image_submission_write(&s, 0x20102620, 1));
    assert(z6ii_image_submission_write(&s, 0x20102620, 0));
    assert((s.unresolved & 5) == 5 && !z6ii_image_reset_word(&s, &word));

    assert(z6ii_image_submission_write(&s, 0x20102100, 1));
    assert(z6ii_image_submission_write(&s, 0x20102648, 1));
    assert(z6ii_image_submission_write(&s, 0x20380010, 1));
    assert(z6ii_image_submission_write(&s, 0x203c0008, 1));
    assert(z6ii_image_submission_write(&s, 0x20102680, 1));
    assert(s.unresolved == 127);
    assert(z6ii_image_submission_write(&s, 0x203800e8, 0xffffff71));
    assert(z6ii_image_submission_write(&s, 0x203800f0, 0x8e));
    assert(s.unresolved == 127);
    uint32_t unresolved = s.unresolved;
    assert(z6ii_image_pending_word(&s) == 3 && s.unresolved == unresolved);
    assert(z6ii_image_pending_word(&s) == 3 && s.unresolved == unresolved);
    assert(z6ii_image_submission_write(&s, 0x203c0004, 3));
    assert(!z6ii_image_reset_word(&s, &word));

    /* A full modeled reset is a separate cancellation. Historical request
     * counts remain nonzero, so the result cannot depend on a zero count. */
    uint64_t starts = s.uncertain_requests;
    z6ii_image_submission_reset(&s);
    assert(s.uncertain_requests == starts && starts != 0);
    assert(s.generation == 2 && z6ii_image_reset_word(&s, &word));
    assert(word == 0 && s.unresolved == 0);
    assert(z6ii_image_pending_word(&s) == 0);

    /* A descriptor-list unit arm is an independent real submission. It
     * cannot disappear because no command/raw start or frame was counted. */
    int unit = z6ii_image_unit_index(0x20100940);
    assert(unit == 49 - 34);
    assert(z6ii_image_unit_index(0x20100948) == -1);
    assert(z6ii_image_unit_index(0x20100860) == -1);
    assert(z6ii_image_submission_write(&s, 0x20100940, 1));
    assert(s.unresolved == 0 && s.unresolved_units == (UINT64_C(1) << unit));
    assert(s.unit_control[unit] == 1 && s.unit_arm_writes == 1);
    assert(!z6ii_image_reset_word(&s, &word));
    assert(z6ii_image_pending_word(&s) == 3);
    assert(!z6ii_image_submission_write(&s, 0x20100948, 0));
    assert(!z6ii_image_submission_write(&s, 0x20100954, 1));
    assert(z6ii_image_submission_write(&s, 0x20100940, 0));
    assert(z6ii_image_submission_write(&s, 0x203800d0, 0));
    assert(!z6ii_image_reset_word(&s, &word));
    assert(s.unresolved_units == (UINT64_C(1) << unit));
    starts = s.uncertain_requests;
    z6ii_image_submission_reset(&s);
    assert(s.generation == 3 && s.unit_control[unit] == 0);
    assert(s.uncertain_requests == starts && s.unit_arm_writes == 1);
    assert(z6ii_image_submission_empty(&s));
    assert(z6ii_image_reset_word(&s, &word) && word == 0);

    assert(z6ii_image_configuration_word(0, 0x300));
    assert(z6ii_image_configuration_word(1, 0x304));
    assert(z6ii_image_configuration_word(1, 0x308));
    assert(!z6ii_image_configuration_word(0, 0x418));
    assert(!z6ii_image_configuration_word(0, 0xb4));
    assert(!z6ii_image_configuration_word(0, 0x118));
    assert(!z6ii_image_configuration_word(0, 0x350));
    assert(z6ii_image_configuration_word(0, 0xac));
    assert(!z6ii_image_configuration_word(1, 0xac));
    assert(z6ii_image_configuration_word(0, 0x2100));
    assert(z6ii_image_configuration_word(1, 0x22fc));
    assert(!z6ii_image_configuration_word(0, 0x2300));
    assert(!z6ii_image_configuration_word(0, 0x3001));
    assert(!z6ii_image_configuration_word(2, 0x300));
    assert(z6ii_image_control_word(0x24));
    assert(z6ii_image_control_word(0xe8));
    assert(!z6ii_image_control_word(0x28));
    assert(z6ii_image_control_value(0, 0xd0, 0));
    assert(!z6ii_image_control_value(0, 0xd0, 1));
    assert(!z6ii_image_control_value(1, 0xd0, 0));
    assert(!z6ii_image_configuration_word(0, 0xd0));
    assert(z6ii_image_configuration_word(0, 0x400));
    assert(z6ii_image_configuration_word(1, 0x40c));
    assert(z6ii_image_configuration_word(0, 0x470));
    assert(z6ii_image_configuration_word(0, 0x4c8));
    assert(z6ii_image_configuration_word(0, 0x500));
    assert(z6ii_image_configuration_word(0, 0x580));
    assert(z6ii_image_configuration_word(0, 0x660));
    assert(z6ii_image_configuration_word(0, 0x67c));
    assert(!z6ii_image_configuration_word(0, 0x474));
    assert(!z6ii_image_configuration_word(0, 0x484));
    assert(!z6ii_image_configuration_word(0, 0x4cc));
    assert(!z6ii_image_configuration_word(0, 0x680));
    assert(!z6ii_image_configuration_word(0, 0x800));
    assert(z6ii_image_configuration_word(0, 0x1100));
    assert(z6ii_image_configuration_word(1, 0x113c));
    assert(z6ii_image_configuration_word(1, 0x1200));
    assert(z6ii_image_configuration_word(0, 0x1244));
    assert(!z6ii_image_configuration_word(0, 0x1140));
    assert(!z6ii_image_configuration_word(0, 0x1248));
    assert(z6ii_image_configuration_word(0, 0x584));
    assert(z6ii_image_configuration_word(1, 0x588));
    assert(z6ii_image_configuration_word(0, 0x58c));
    assert(z6ii_image_configuration_word(0, 0x590));
    assert(z6ii_image_configuration_word(0, 0x1400));
    const uint32_t raw_results[] = {0x77c, 0x780, 0x9dc, 0x9e0, 0x9e4,
        0xbc0, 0xbc4, 0xbc8, 0xbcc, 0xbd0, 0xe1c, 0xf30};
    for (unsigned i = 0; i < sizeof(raw_results) / sizeof(raw_results[0]); ++i) {
        assert(!z6ii_image_configuration_word(0, raw_results[i]));
        assert(!z6ii_image_configuration_word(1, raw_results[i]));
    }
    puts("PASS: image reset reads reject unresolved command/raw/unit history and partial reset pulses");
    return 0;
}
