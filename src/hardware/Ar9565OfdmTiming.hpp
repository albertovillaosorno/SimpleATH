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
//   - Native driver contracts and implementation for ar9565 ofdm timing.
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
//   - Native driver contracts and implementation for ar9565 ofdm timing.
// - Description:
//   - Implements or verifies the Ar9565OfdmTiming source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for ar9565 ofdm timing.

#ifndef SIMPLEATH_AR9565_OFDM_TIMING_HPP
#define SIMPLEATH_AR9565_OFDM_TIMING_HPP

#include "Ar9565Calibration.hpp"
#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    enum class OfdmTimingResult : uint8_t
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

    struct OfdmTimingProgress
    {
            OfdmTimingResult result;
            uint16_t synthesizerMhz;
            uint16_t normalMantissa;
            uint8_t normalExponent;
            uint16_t shortMantissa;
            uint8_t shortExponent;
            size_t completedReads;
            size_t completedWrites;
            uint32_t lastOffset;
            bool requiresReset;
    };

    // Programs the real AR9003 OFDM delta-slope and short guard-interval
    // coefficients (AR_PHY_TIMING3 and AR_PHY_SGI_DELTA) for an AR9565
    // full-rate 2.4-GHz HT20/HT40 channel. Based on Linux ath9k v6.12
    // ar9003_hw_set_delta_slope / ath9k_hw_get_delta_slope_vals. Channel
    // center is calculated from the 20-MHz pair, never from untrusted HT40
    // input. Does not authorize TX, RX, automatic responses or rates.
    //
    // Call after channel synthesizer setup with the RF bus released and
    // before enabling the PHY. The native owner must establish a live D0,
    // same-epoch BAR, quiesced MAC, permitted country/channel, RF-kill and
    // coexistence state for EVERY MMIO through permitWrite. Every posted
    // write ambiguity, owner loss or mismatched readback requires full reset.
    OfdmTimingProgress
    programAr9565OfdmTiming(const RfChannelRequest &request,
                            const CalibrationAndRegulatory &authorization,
                            const RxAgcBackend &backend);
} // namespace simpleath

#endif
