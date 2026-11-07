// SPDX-License-Identifier: AGPL-3.0-only
#ifndef SIMPLEATH_AR9565_INIT_CATALOG_HPP
#define SIMPLEATH_AR9565_INIT_CATALOG_HPP

#include "Ar9565Core.hpp"
#include <stddef.h>
#include <stdint.h>

namespace simpleath
{

    enum class ChannelWidth : uint8_t
    {
        Ht20,
        Ht40
    };
    enum class TxGainProfile : uint8_t
    {
        LowOb,
        HighOb,
        HighPower
    };
    enum class RxGainProfile : uint8_t
    {
        Standard,
        WithoutExternalLna
    };

    enum class RegisterPhase : uint8_t
    {
        SocPreamble,
        MacCore,
        BasebandCore,
        RadioCore,
        RxGain,
        TxGain,
        SocPostamble,
        MacPostamble,
        BasebandPostamble,
        RadioPostamble,
        Japan2484Txfir
    };

    // Forward-declared generated type; avoids undefined strict-aliasing casts.
    namespace ini
    {
        struct RegisterValue;
    }

    struct RegisterTable
    {
            RegisterPhase phase;
            const ini::RegisterValue *data;
            size_t count;
    };

    // Source code and generated tables deliberately have identical two-field
    // layouts, but this is an independent public type for the hardware backend.
    struct RegisterRecipe
    {
            Revision silicon;
            ChannelWidth width;
            TxGainProfile txGain;
            RxGainProfile rxGain;
            Channel channel;
            RegisterTable phases[11];
            size_t count;
            size_t registerWrites;
            bool regulatoryAuthorized;
            bool implementationComplete;
    };

    struct CalibrationAndRegulatory
    {
            bool eepromContentsVerified;
            bool boardAntennaConfigurationVerified;
            bool localCountryRulesAvailable;
            bool channelPermitted;
            bool txPowerLimitsVerified;
            bool radioKillUnblocked;
            bool coexistenceConfigurationVerified;
    };

    // This code describes supported Linux ath9k revision-specific table
    // layouts. It never touches live PCI or MMIO, and does not claim to
    // implement Linux's calibration / board data / coexistence / 802.11 MAC
    // service layers. On failure, out is zeroed (no stale table pointers).
    Result createInitRecipe(Revision revision, const Channel &channel,
                            ChannelWidth width, TxGainProfile tx,
                            RxGainProfile rx,
                            const CalibrationAndRegulatory &preconditions,
                            RegisterRecipe &out);

    // Informational guard; also verifies the exact generated phase sequence,
    // table pointers, row counts, and register count for the requested silicon,
    // width, gain and channel. This does not establish runtime PCI ownership,
    // trusted source of the prerequisites or a working calibration backend.
    // Current source always emits implementationComplete=false, so it cannot
    // declare any recipe executable. "Prepared" never means TX permission.
    bool canBeginHardwareInitialization(
        const RegisterRecipe &recipe,
        const CalibrationAndRegulatory &preconditions);

} // namespace simpleath
#endif
