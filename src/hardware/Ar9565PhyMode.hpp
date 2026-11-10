// SPDX-License-Identifier: GPL-2.0-only
#ifndef SIMPLEATH_AR9565_PHY_MODE_HPP
#define SIMPLEATH_AR9565_PHY_MODE_HPP

#include "Ar9565Calibration.hpp"
#include "Ar9565Channel.hpp"
#include <cstddef>
#include <cstdint>

namespace simpleath
{
    enum class PhyModeResult : uint8_t
    {
        Ok,
        InvalidBackend,
        InvalidChannel,
        MissingAuthorization,
        InvalidBar,
        OwnershipLost,
        ReadFailed,
        WriteFailed,
        ReadbackMismatch,
    };

    struct PhyModeProgress
    {
            PhyModeResult result;
            size_t completedReads;
            size_t completedWrites;
            uint32_t lastOffset;
            bool requiresReset;
    };

    // Linux ath9k ar9003_hw_set_channel_regs(): program the AR9565 PHY
    // 20/40 MHz primary-channel mode, MAC extension-channel CCA joining,
    // and MAC TX/carrier-sense timeout limits. For channel 14, do not enable
    // HT, SGI or dynamic 40 MHz: 2484 MHz is legacy CCK-only.
    //
    // The native owner must verify the physical 2.4 GHz channel pair and
    // country/board/antenna authority, zero TX/automatic responses, quiescent
    // DMA, D0 power and one stable serial epoch BEFORE every callback. Call
    // after canonical INI and before RF bus acquisition. Every ambiguous
    // MMIO write, readback mismatch or later failure requires hardware reset.
    // This stage never enables RX/TX, claims calibration, or activates PHY.
    PhyModeProgress programAr9565ReceiveOnlyPhyMode(
        const RfChannelRequest &request,
        const CalibrationAndRegulatory &authorization,
        const RxAgcBackend &backend);
} // namespace simpleath
#endif
