/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Lifecycle/race checks for an opt-in hardware input model. These tests do
 * not execute firmware and do not certify exposure or physical timing. */
#include <assert.h>
#include <stdio.h>
#include "../src/qemu/hw/arm/nikon-z6ii-isp-frame-core.h"

int main(void)
{
    Z6IIMask1InputCycle s = {0};
    bool engine = z6ii_mask1_engine_active(0, 1, 1, 0);
    assert(engine);
    assert(!z6ii_mask1_engine_active(1, 1, 1, 0));
    assert(!z6ii_mask1_engine_active(0, 0, 1, 0));
    assert(!z6ii_mask1_engine_active(0, 1, 0, 0));
    assert(!z6ii_mask1_engine_active(0, 1, 1, 1));
    assert(!z6ii_mask1_engine_active(0, 1, 1, 2));
    assert(!z6ii_mask1_input_end(&s, engine));
    /* Group8 input must not borrow group1 start/clock state. A group1
     * reset must not cancel an independently active group8 cycle. */
    assert(!z6ii_isp_input_engine_active(0, 1, 1, 0, 8));
    assert(z6ii_isp_input_engine_active(1, 8, 8, 0, 8));
    assert(!z6ii_isp_input_engine_active(8, 8, 8, 0, 8));
    assert(!z6ii_isp_input_engine_active(0, 8, 0, 0, 8));
    assert(!z6ii_isp_input_engine_active(0, 8, 8, 1, 8));
    assert(!z6ii_isp_input_engine_active(0, 0, 0, 0, 0));

    /* A submitted configuration with no started engine cannot complete. */
    z6ii_mask1_input_begin(&s, false, true);
    assert(!s.pending && !z6ii_mask1_input_end(&s, false));
    z6ii_mask1_input_begin(&s, engine, false);
    assert(!s.pending && !z6ii_mask1_input_end(&s, engine));

    z6ii_mask1_input_begin(&s, engine, true);
    assert(s.pending && s.admitted == 1 && s.completed == 0);
    assert(z6ii_mask1_input_end(&s, engine));
    assert(!s.pending && s.completed == 1);
    assert(!z6ii_mask1_input_end(&s, engine));

    /* A reset pulse must remain a cancellation even after reset clears. */
    z6ii_mask1_input_begin(&s, engine, true);
    z6ii_mask1_input_cancel(&s);
    assert(!z6ii_mask1_input_end(&s, engine) && s.completed == 1);

    z6ii_mask1_input_begin(&s, engine, true);
    assert(!z6ii_mask1_input_end(&s, false));
    assert(!s.pending && s.completed == 1);

    /* Stopping input after admission drains the final admitted cycle. The
     * following disabled-input cycle produces no new completion. */
    z6ii_mask1_input_begin(&s, engine, true);
    assert(z6ii_mask1_input_end(&s, engine));
    z6ii_mask1_input_begin(&s, engine, false);
    assert(!z6ii_mask1_input_end(&s, engine));

    /* Losing the end edge cannot duplicate the next admitted cycle. */
    z6ii_mask1_input_begin(&s, engine, true);
    uint64_t canceled = s.canceled;
    z6ii_mask1_input_begin(&s, engine, true);
    assert(s.canceled == canceled + 1);
    assert(z6ii_mask1_input_end(&s, engine));
    assert(!z6ii_mask1_input_end(&s, engine));
    printf("PASS: mask1 input admission, no-start, reset/stop, drain, and edge-loss lifecycle\n");
    return 0;
}
