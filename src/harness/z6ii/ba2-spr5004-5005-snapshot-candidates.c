/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <string.h>
#include "ba2-spr5004-5005-snapshot-candidates.h"
Z6IIBA2SPRResult z6ii_ba2_spr5004_snapshot_init(
    Z6IIBA2SPR5004SnapshotCandidate *state,uint32_t value,const char *basis)
{
    if(!state||!basis||!basis[0])return Z6II_BA2_SPR_FAULT;
    Z6IIBA2SPR5004SnapshotCandidate next;
    memset(&next,0,sizeof(next));
    next.value=value;next.initial_basis=basis;next.initialized=true;
    *state=next;return Z6II_BA2_SPR_OK;
}
Z6IIBA2SPRResult z6ii_ba2_spr5004_snapshot_enable(
    Z6IIBA2SPR5004SnapshotCandidate *state,const char *basis)
{
    if(!state||!state->initialized||!state->initial_basis||!state->initial_basis[0]||
       !basis||!basis[0])return Z6II_BA2_SPR_FAULT;
    state->enable_basis=basis;state->enabled=true;return Z6II_BA2_SPR_OK;
}
static Z6IIBA2SPRResult selected_state_5004(Z6IIBA2SPR5004SnapshotCandidate *state)
{
    if(!state||!state->initialized||!state->initial_basis||!state->initial_basis[0])
        return Z6II_BA2_SPR_FAULT;
    if(!state->enabled)return Z6II_BA2_SPR_UNKNOWN;
    if(!state->enable_basis||!state->enable_basis[0])return Z6II_BA2_SPR_FAULT;
    return Z6II_BA2_SPR_OK;
}
Z6IIBA2SPRResult z6ii_ba2_spr5004_snapshot_read(void *opaque,uint32_t selector,uint32_t *value)
{
    if(selector!=UINT32_C(0x5004))return Z6II_BA2_SPR_UNKNOWN;
    Z6IIBA2SPR5004SnapshotCandidate *state=opaque;
    Z6IIBA2SPRResult result=selected_state_5004(state);
    if(result!=Z6II_BA2_SPR_OK)return result;
    if(!value)return Z6II_BA2_SPR_FAULT;
    *value=state->value;state->reads++;return Z6II_BA2_SPR_OK;
}
Z6IIBA2SPRResult z6ii_ba2_spr5004_snapshot_write(void *opaque,uint32_t selector,uint32_t value)
{
    (void)opaque;(void)selector;(void)value;return Z6II_BA2_SPR_UNKNOWN;
}

Z6IIBA2SPRResult z6ii_ba2_spr5005_snapshot_init(
    Z6IIBA2SPR5005SnapshotCandidate *state,uint32_t value,const char *basis)
{
    if(!state||!basis||!basis[0])return Z6II_BA2_SPR_FAULT;
    Z6IIBA2SPR5005SnapshotCandidate next;
    memset(&next,0,sizeof(next));
    next.value=value;next.initial_basis=basis;next.initialized=true;
    *state=next;return Z6II_BA2_SPR_OK;
}
Z6IIBA2SPRResult z6ii_ba2_spr5005_snapshot_enable(
    Z6IIBA2SPR5005SnapshotCandidate *state,const char *basis)
{
    if(!state||!state->initialized||!state->initial_basis||!state->initial_basis[0]||
       !basis||!basis[0])return Z6II_BA2_SPR_FAULT;
    state->enable_basis=basis;state->enabled=true;return Z6II_BA2_SPR_OK;
}
static Z6IIBA2SPRResult selected_state_5005(Z6IIBA2SPR5005SnapshotCandidate *state)
{
    if(!state||!state->initialized||!state->initial_basis||!state->initial_basis[0])
        return Z6II_BA2_SPR_FAULT;
    if(!state->enabled)return Z6II_BA2_SPR_UNKNOWN;
    if(!state->enable_basis||!state->enable_basis[0])return Z6II_BA2_SPR_FAULT;
    return Z6II_BA2_SPR_OK;
}
Z6IIBA2SPRResult z6ii_ba2_spr5005_snapshot_read(void *opaque,uint32_t selector,uint32_t *value)
{
    if(selector!=UINT32_C(0x5005))return Z6II_BA2_SPR_UNKNOWN;
    Z6IIBA2SPR5005SnapshotCandidate *state=opaque;
    Z6IIBA2SPRResult result=selected_state_5005(state);
    if(result!=Z6II_BA2_SPR_OK)return result;
    if(!value)return Z6II_BA2_SPR_FAULT;
    *value=state->value;state->reads++;return Z6II_BA2_SPR_OK;
}
Z6IIBA2SPRResult z6ii_ba2_spr5005_snapshot_write(void *opaque,uint32_t selector,uint32_t value)
{
    (void)opaque;(void)selector;(void)value;return Z6II_BA2_SPR_UNKNOWN;
}
