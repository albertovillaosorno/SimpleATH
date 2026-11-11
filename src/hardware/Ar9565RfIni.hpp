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
//   - Native driver contracts and implementation for ar9565 rf ini.
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
//   - Native driver contracts and implementation for ar9565 rf ini.
// - Description:
//   - Implements or verifies the Ar9565RfIni source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for ar9565 rf ini.

#ifndef SIMPLEATH_AR9565_RF_INI_HPP
#define SIMPLEATH_AR9565_RF_INI_HPP

#include "Ar9565InitCatalog.hpp"
#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    enum class RfIniResult : uint8_t
    {
        Ok,
        InvalidBackend,
        InvalidRecipe,
        InvalidBar,
        OwnershipLost,
        WriteFailed,
    };

    // Only the native PCI owner may provide this backend, inside its serialized
    // work-loop gate, after RTC reset and MAC/queues are quiesced. permitWrite
    // must recheck live D0, the requested receive/transmit prerequisites and
    // the owner epoch; ReceiveOnly keeps TX and automatic ACK/CTS blocked.
    // This interface NEVER claims a calibrated radio or TX readiness.
    struct RfIniBackend
    {
            void *context;
            uint64_t ownerEpoch;
            uint32_t barLengthBytes;
            bool (*permitWrite)(void *context, uint64_t epoch);
            bool (*write32)(void *context, uint32_t offset, uint32_t value);
            void (*delayMicros)(void *context, uint32_t micros);
    };

    struct RfIniProgress
    {
            RfIniResult result;
            size_t completedWrites;
            size_t completedPhases;
            uint32_t lastOffset;
            // A write callback may fail *after* the device accepts a write.
            // A partial or ambiguous phase must be recovered by hardware reset.
            bool requiresReset;
    };

    // Applies the pinned AR9565 split INI tables to an actual MMIO writer,
    // in Linux ath9k order. This is one stage of PHY initialization only:
    // channel synthesizer setup, calibration, power control, DMA, IRQ and the
    // AirPort interface must be completed independently before enabling RF/TX.
    // All BAR offsets and table provenance are checked before the first write.
    RfIniProgress applyAr9565RfIni(const RegisterRecipe &recipe,
                                   const CalibrationAndRegulatory &requirements,
                                   const RfIniBackend &backend);
} // namespace simpleath
#endif
