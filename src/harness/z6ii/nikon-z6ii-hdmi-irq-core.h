/* SPDX-License-Identifier: GPL-2.0-or-later */
/* IH source groups used by the original Z6II HDMI ISR.
 * DDC is summary bit2; independently muted PLL and PHY-I2C
 * share summary bit3. Active-high group mutes
 * are corroborated by the DW HDMI interface. Initial mutes, summary
 * visibility under global mute and the absence of a wakeup lifecycle
 * are explicit functional policies, not Nikon silicon measurements.
 * No source status, GIC line, RTOS flag or video state is written here. */
#ifndef NIKON_Z6II_HDMI_IRQ_CORE_H
#define NIKON_Z6II_HDMI_IRQ_CORE_H
#include <stdbool.h>
#include <stdint.h>

#define Z6II_HDMI_IH_SUMMARY UINT32_C(0x201605c0)
#define Z6II_HDMI_IH_MUTE_FC0 UINT32_C(0x20160600)
#define Z6II_HDMI_IH_MUTE_FC1 UINT32_C(0x20160604)
#define Z6II_HDMI_IH_MUTE_FC2 UINT32_C(0x20160608)
#define Z6II_HDMI_IH_MUTE_AUDIO UINT32_C(0x2016060c)
#define Z6II_HDMI_IH_MUTE_DDC UINT32_C(0x20160614)
#define Z6II_HDMI_IH_MUTE_PLL UINT32_C(0x20160610)
#define Z6II_HDMI_IH_MUTE_PHY UINT32_C(0x20160620)
#define Z6II_HDMI_IH_MUTE_CEC UINT32_C(0x20160618)
#define Z6II_HDMI_IH_MUTE_VP UINT32_C(0x2016061c)
#define Z6II_HDMI_IH_MUTE_ALL UINT32_C(0x201607fc)

typedef struct Z6IIHDMIIRQCore {
    uint8_t ddc_mute, phy_mute, pll_mute, global_mute;
    uint8_t fc_mute[3], audio_mute, cec_mute, vp_mute;
} Z6IIHDMIIRQCore;

static inline void z6ii_hdmi_ih_reset(Z6IIHDMIIRQCore *s)
{
    s->ddc_mute = s->phy_mute = s->pll_mute = UINT8_MAX;
    s->fc_mute[0] = s->fc_mute[1] = s->fc_mute[2] = UINT8_MAX;
    s->audio_mute = s->cec_mute = s->vp_mute = UINT8_MAX;
    s->global_mute = 1;
}

static inline bool z6ii_hdmi_ih_owns(uint32_t addr)
{
    switch (addr & ~UINT32_C(3)) {
    case Z6II_HDMI_IH_SUMMARY:
    case Z6II_HDMI_IH_MUTE_FC0:
    case Z6II_HDMI_IH_MUTE_FC1:
    case Z6II_HDMI_IH_MUTE_FC2:
    case Z6II_HDMI_IH_MUTE_AUDIO:
    case Z6II_HDMI_IH_MUTE_CEC:
    case Z6II_HDMI_IH_MUTE_VP:
    case Z6II_HDMI_IH_MUTE_DDC:
    case Z6II_HDMI_IH_MUTE_PLL:
    case Z6II_HDMI_IH_MUTE_PHY:
    case Z6II_HDMI_IH_MUTE_ALL: return true;
    default: return false;
    }
}

static inline uint8_t z6ii_hdmi_ih_summary(const Z6IIHDMIIRQCore *s,
    uint8_t ddc_status, uint8_t phy_status, uint8_t pll_status)
{
    uint8_t summary = 0;
    if (ddc_status & (uint8_t)~s->ddc_mute & 3) { summary |= 4; }
    if (phy_status & (uint8_t)~s->phy_mute & 3) { summary |= 8; }
    if (pll_status & (uint8_t)~s->pll_mute & 3) { summary |= 8; }
    return summary;
}

static inline bool z6ii_hdmi_ih_irq(const Z6IIHDMIIRQCore *s,
    uint8_t ddc_status, uint8_t phy_status, uint8_t pll_status)
{
    /* Bit1 is retained as the separate wakeup mute. This board has no
     * wakeup IRQ lifecycle; only bit0 gates the normal shared IRQ. */
    return !(s->global_mute & 1) &&
           z6ii_hdmi_ih_summary(s, ddc_status, phy_status, pll_status);
}

static inline bool z6ii_hdmi_ih_access(Z6IIHDMIIRQCore *s, uint32_t addr,
    unsigned size, bool write, uint64_t *value,
    uint8_t ddc_status, uint8_t phy_status, uint8_t pll_status)
{
    if (!s || !value || !z6ii_hdmi_ih_owns(addr) || size != 1 ||
        (addr & 3) || (write && *value > UINT8_MAX)) { return false; }
    uint8_t *reg;
    switch (addr) {
    case Z6II_HDMI_IH_SUMMARY:
        if (write) { return false; }
        *value = z6ii_hdmi_ih_summary(s, ddc_status, phy_status, pll_status);
        return true;
    case Z6II_HDMI_IH_MUTE_DDC: reg = &s->ddc_mute; break;
    /* Retained masks for inactive sources. Configuration alone supplies
     * no source status, so these do not contribute to the summary yet. */
    case Z6II_HDMI_IH_MUTE_FC0: reg = &s->fc_mute[0]; break;
    case Z6II_HDMI_IH_MUTE_FC1: reg = &s->fc_mute[1]; break;
    case Z6II_HDMI_IH_MUTE_FC2: reg = &s->fc_mute[2]; break;
    case Z6II_HDMI_IH_MUTE_AUDIO: reg = &s->audio_mute; break;
    case Z6II_HDMI_IH_MUTE_CEC: reg = &s->cec_mute; break;
    case Z6II_HDMI_IH_MUTE_VP: reg = &s->vp_mute; break;
    case Z6II_HDMI_IH_MUTE_PLL: reg = &s->pll_mute; break;
    case Z6II_HDMI_IH_MUTE_PHY: reg = &s->phy_mute; break;
    case Z6II_HDMI_IH_MUTE_ALL:
        if (write && (*value & ~UINT64_C(3))) { return false; }
        reg = &s->global_mute;
        break;
    default: return false;
    }
    if (write) { *reg = *value; } else { *value = *reg; }
    return true;
}
#endif
