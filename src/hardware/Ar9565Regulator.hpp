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
//   - Native driver contracts and implementation for ar9565 regulator.
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
//   - Native driver contracts and implementation for ar9565 regulator.
// - Description:
//   - Implements or verifies the Ar9565Regulator source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for ar9565 regulator.

#ifndef SIMPLEATH_AR9565_REGULATOR_HPP
#define SIMPLEATH_AR9565_REGULATOR_HPP

#include "Ar9565Calibration.hpp"
#include "Ar9565Eeprom.hpp"
#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    struct RegulatorEvidence
    {
            // Must be derived from same-epoch physical board discovery,
            // native D0/ownership, and quiesced MAC/automatic responses.
            bool physicalBoardVerified;
            bool macAndAutomaticTxQuiesced;
    };

    enum class RegulatorResult : uint8_t
    {
        Ok,
        InvalidBackend,
        InvalidBoard,
        MissingAuthority,
        InvalidBar,
        OwnershipLost,
        ReadFailed,
        WriteFailed,
        ReadbackMismatch,
    };

    struct RegulatorProgress
    {
            RegulatorResult result;
            uint32_t programmedPmu1;
            size_t completedReads;
            size_t completedWrites;
            bool requiresReset;
    };

    // Linux ath9k ar9003_hw_internal_regulator_apply() for AR_SREV_9565:
    // featureEnable BIT(4) selects EEPROM swreg -> PMU1 (0x16340);
    // otherwise set PMU1_PWD without changing any unrelated fields.
    // Caller must use a restored physical NVM image and a live epoch lease.
    // No default/zeroed/builtin template may stand in for board power data.
    // MMIO callbacks must be ordered and strongly checked for D0/epoch loss.
    // A reported write failure may have posted to silicon: reset required.
    // Success establishes only regulator programming, not RF/BT readiness.
    RegulatorProgress
    configureAr9565InternalRegulator(const EepromImage &image,
                                     const RegulatorEvidence &evidence,
                                     const RxAgcBackend &backend);

    // ath9k ar9003_hw_apply_tuning_caps: EEPROM bit6 selects the physical
    // 7-bit IN/OUT XTAL load-cap DAC value. Unset means no hardware writes.
    struct XtalTuneProgress
    {
            RegulatorResult result;
            uint32_t programmedXtal;
            size_t completedReads;
            size_t completedWrites;
            bool requiresReset;
    };

    XtalTuneProgress
    configureAr9565XtalCapacitors(const EepromImage &image,
                                  const RegulatorEvidence &evidence,
                                  const RxAgcBackend &backend);
} // namespace simpleath
#endif
