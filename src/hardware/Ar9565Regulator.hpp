// SPDX-License-Identifier: AGPL-3.0-only
#ifndef SIMPLEATH_AR9565_REGULATOR_HPP
#define SIMPLEATH_AR9565_REGULATOR_HPP

#include "Ar9565Calibration.hpp"
#include "Ar9565Eeprom.hpp"
#include <cstddef>
#include <cstdint>

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
} // namespace simpleath
#endif
