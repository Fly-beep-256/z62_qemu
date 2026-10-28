/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <string.h>
#include "ba2-spr5001-4000-storage-candidates.h"
Z6IIBA2SPRResult z6ii_ba2_spr5001_storage_init(
    Z6IIBA2SPR5001StorageCandidate *state,uint32_t value,const char *basis)
{
    if(!state||!basis||!basis[0])return Z6II_BA2_SPR_FAULT;
    Z6IIBA2SPR5001StorageCandidate next;
    memset(&next,0,sizeof(next));
    next.value=value;next.initial_basis=basis;next.initialized=true;
    *state=next;
    return Z6II_BA2_SPR_OK;
}
Z6IIBA2SPRResult z6ii_ba2_spr5001_storage_enable(
    Z6IIBA2SPR5001StorageCandidate *state,const char *basis)
{
    if(!state||!state->initialized||!state->initial_basis||!state->initial_basis[0]||
       !basis||!basis[0])return Z6II_BA2_SPR_FAULT;
    state->enable_basis=basis;state->enabled=true;
    return Z6II_BA2_SPR_OK;
}
static Z6IIBA2SPRResult selected_state_5001(Z6IIBA2SPR5001StorageCandidate *state)
{
    if(!state||!state->initialized||!state->initial_basis||!state->initial_basis[0])
        return Z6II_BA2_SPR_FAULT;
    if(!state->enabled)return Z6II_BA2_SPR_UNKNOWN;
    if(!state->enable_basis||!state->enable_basis[0])return Z6II_BA2_SPR_FAULT;
    return Z6II_BA2_SPR_OK;
}
Z6IIBA2SPRResult z6ii_ba2_spr5001_storage_read(void *opaque,uint32_t selector,uint32_t *value)
{
    if(selector!=UINT32_C(0x5001))return Z6II_BA2_SPR_UNKNOWN;
    Z6IIBA2SPR5001StorageCandidate *state=opaque;
    Z6IIBA2SPRResult result=selected_state_5001(state);
    if(result!=Z6II_BA2_SPR_OK)return result;
    if(!value)return Z6II_BA2_SPR_FAULT;
    *value=state->value;state->reads++;
    return Z6II_BA2_SPR_OK;
}
Z6IIBA2SPRResult z6ii_ba2_spr5001_storage_write(void *opaque,uint32_t selector,uint32_t value)
{
    if(selector!=UINT32_C(0x5001))return Z6II_BA2_SPR_UNKNOWN;
    Z6IIBA2SPR5001StorageCandidate *state=opaque;
    Z6IIBA2SPRResult result=selected_state_5001(state);
    if(result!=Z6II_BA2_SPR_OK)return result;
    state->value=value;state->writes++;
    return Z6II_BA2_SPR_OK;
}

Z6IIBA2SPRResult z6ii_ba2_spr4000_storage_init(
    Z6IIBA2SPR4000StorageCandidate *state,uint32_t value,const char *basis)
{
    if(!state||!basis||!basis[0])return Z6II_BA2_SPR_FAULT;
    Z6IIBA2SPR4000StorageCandidate next;
    memset(&next,0,sizeof(next));
    next.value=value;next.initial_basis=basis;next.initialized=true;
    *state=next;
    return Z6II_BA2_SPR_OK;
}
Z6IIBA2SPRResult z6ii_ba2_spr4000_storage_enable(
    Z6IIBA2SPR4000StorageCandidate *state,const char *basis)
{
    if(!state||!state->initialized||!state->initial_basis||!state->initial_basis[0]||
       !basis||!basis[0])return Z6II_BA2_SPR_FAULT;
    state->enable_basis=basis;state->enabled=true;
    return Z6II_BA2_SPR_OK;
}
static Z6IIBA2SPRResult selected_state_4000(Z6IIBA2SPR4000StorageCandidate *state)
{
    if(!state||!state->initialized||!state->initial_basis||!state->initial_basis[0])
        return Z6II_BA2_SPR_FAULT;
    if(!state->enabled)return Z6II_BA2_SPR_UNKNOWN;
    if(!state->enable_basis||!state->enable_basis[0])return Z6II_BA2_SPR_FAULT;
    return Z6II_BA2_SPR_OK;
}
Z6IIBA2SPRResult z6ii_ba2_spr4000_storage_read(void *opaque,uint32_t selector,uint32_t *value)
{
    if(selector!=UINT32_C(0x4000))return Z6II_BA2_SPR_UNKNOWN;
    Z6IIBA2SPR4000StorageCandidate *state=opaque;
    Z6IIBA2SPRResult result=selected_state_4000(state);
    if(result!=Z6II_BA2_SPR_OK)return result;
    if(!value)return Z6II_BA2_SPR_FAULT;
    *value=state->value;state->reads++;
    return Z6II_BA2_SPR_OK;
}
Z6IIBA2SPRResult z6ii_ba2_spr4000_storage_write(void *opaque,uint32_t selector,uint32_t value)
{
    if(selector!=UINT32_C(0x4000))return Z6II_BA2_SPR_UNKNOWN;
    Z6IIBA2SPR4000StorageCandidate *state=opaque;
    Z6IIBA2SPRResult result=selected_state_4000(state);
    if(result!=Z6II_BA2_SPR_OK)return result;
    state->value=value;state->writes++;
    return Z6II_BA2_SPR_OK;
}

