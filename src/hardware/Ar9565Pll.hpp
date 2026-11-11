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
//   - Native driver contracts and implementation for ar9565 pll.
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
//   - Native driver contracts and implementation for ar9565 pll.
// - Description:
//   - Implements or verifies the Ar9565Pll source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for ar9565 pll.

#ifndef SIMPLEATH_AR9565_PLL_HPP
#define SIMPLEATH_AR9565_PLL_HPP

#include "Ar9565Channel.hpp"
#include "Ar9565InitCatalog.hpp"
#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    enum class RfPllResult : uint8_t
    {
        Ok,
        InvalidBackend,
        InvalidChannel,
        MissingAuthorization,
        InvalidBar,
        OwnershipLost,
        ReadFailed,
        WriteFailed,
    };

    struct RfPllProgress
    {
            RfPllResult result;
            size_t completedWrites;
            size_t completedReads;
            uint32_t lastOffset;
            bool requiresReset;
    };

    // The AR9565-only BB+RTC PLL stage from ath9k_hw_init_pll in hw.c,
    // including the 9565-specific RTC bit, 1-ms BB lock interval and
    // 100-us RTC settle. It is intended after RTC reset and before channel
    // synthesizer programming. The owner must provide an already-awake RTC,
    // ordered/drained MMIO, real crystal provenance, live D0, exclusive MAC
    // quiescence, analog RF bus grant, epoch and board/country/RF-kill gates.
    // This is not a PLL lock measurement, calibration or TX permission.
    // Any partial write or loss of owner authority requires a full reset.
    RfPllProgress
    initializeAr9565Pll(const RfChannelRequest &request,
                        const CalibrationAndRegulatory &authorization,
                        const RfChannelBackend &backend);
} // namespace simpleath
#endif
