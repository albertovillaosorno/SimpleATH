// Copyright:
//   - Copyright © 2026 Alberto Villa Osorno
// SPDX-License-Identifier:
//   - MIT
// Confidential:
//   - false
// License-File:
//   - LICENSE-MIT
// Provenance:
//   - SimpleATH original; independently developed or locally authored
//
// Boundary-Contract:
// - Owns:
//   - Native driver contracts and implementation for ar9565 phy mode.
// - Must-Not:
//   - Invent hardware readiness, weaken buffer bounds, or assume ABI
//     compatibility.
// - Allows:
//   - Inputs: validated register, protocol, platform, or device state from
//     callers.
//   - Outputs: bounded native transitions, messages, or explicit errors.
//   - Side effects: only the device and kernel operations owned by this module.
// - Split-When:
//   - A separate protocol stage needs independent validation and ownership.
// - Merge-When:
//   - The caller directly owns this narrow contract without reuse.
// - Summary:
//   - Native driver contracts and implementation for ar9565 phy mode.
// - Description:
//   - Implements or verifies the Ar9565PhyMode source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for ar9565 phy mode.

#ifndef SIMPLEATH_AR9565_PHY_MODE_HPP
#define SIMPLEATH_AR9565_PHY_MODE_HPP

#include "Ar9565Calibration.hpp"
#include "Ar9565Channel.hpp"
#include <stddef.h>
#include <stdint.h>

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
