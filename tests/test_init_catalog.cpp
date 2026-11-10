// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Alberto Villa Osorno.
// Source table catalog contract only: no MMIO, PHY or radio initialization.
#include "hardware/Ar9565Core.hpp"
#include "hardware/Ar9565InitCatalog.hpp"
#include <cstddef>

using namespace simpleath;

namespace
{
    bool validRecipe(const RegisterRecipe &recipe, size_t expectedPhases)
    {
        if (recipe.count != expectedPhases || (recipe.registerWrites == 0U) ||
            recipe.implementationComplete || recipe.count > 11)
        {
            return false;
        }
        size_t writes = 0;
        for (size_t i = 0; i < recipe.count; ++i)
        {
            if ((recipe.phases[i].data == nullptr) ||
                (recipe.phases[i].count == 0U))
            {
                return false;
            }
            writes += recipe.phases[i].count;
        }
        return writes == recipe.registerWrites &&
               recipe.phases[0].phase == RegisterPhase::SocPreamble &&
               recipe.phases[4].phase == RegisterPhase::RxGain &&
               recipe.phases[5].phase == RegisterPhase::TxGain &&
               recipe.phases[9].phase == RegisterPhase::RadioPostamble;
    }
} // namespace

int main()
{
    Channel channel {};
    if (mapChannel(6, channel) != Result::Ok || channel.centerMhz != 2437)
    {
        return 1;
    }
    CalibrationAndRegulatory untrusted {};
    RegisterRecipe v10 {};
    if (createInitRecipe(Revision::V1_0, channel, ChannelWidth::Ht20,
                         TxGainProfile::LowOb, RxGainProfile::Standard,
                         untrusted, v10) != Result::Ok ||
        !validRecipe(v10, 10) || v10.regulatoryAuthorized ||
        canBeginHardwareInitialization(v10, untrusted))
    {
        return 2;
    }

    CalibrationAndRegulatory requirements {};
    requirements.eepromContentsVerified = true;
    requirements.boardAntennaConfigurationVerified = true;
    requirements.localCountryRulesAvailable = true;
    requirements.channelPermitted = true;
    requirements.txPowerLimitsVerified = true;
    requirements.radioKillUnblocked = true;
    requirements.coexistenceConfigurationVerified = true;
    RegisterRecipe v11 {};
    if (createInitRecipe(Revision::V1_1, channel, ChannelWidth::Ht20,
                         TxGainProfile::LowOb, RxGainProfile::Standard,
                         requirements, v11) != Result::Ok ||
        !validRecipe(v11, 10) || !v11.regulatoryAuthorized ||
        v11.phases[9].data == v10.phases[9].data ||
        canBeginHardwareInitialization(v11, requirements))
    {
        return 3;
    }
    RegisterRecipe forged = v11;
    forged.implementationComplete = true;
    if (canBeginHardwareInitialization(forged, requirements))
    {
        return 4;
    }
    forged.phases[9] = v10.phases[9];
    if (canBeginHardwareInitialization(forged, requirements))
    {
        return 5;
    }

    RegisterRecipe ht40 {};
    if (createInitRecipe(Revision::V1_1, channel, ChannelWidth::Ht40,
                         TxGainProfile::HighPower,
                         RxGainProfile::WithoutExternalLna, requirements,
                         ht40) != Result::Ok ||
        !validRecipe(ht40, 10) || ht40.phases[4].data == v11.phases[4].data ||
        ht40.phases[5].data == v11.phases[5].data ||
        ht40.phases[9].data == v11.phases[9].data ||
        canBeginHardwareInitialization(ht40, requirements))
    {
        return 6;
    }

    Channel japan {};
    if (mapChannel(14, japan) != Result::Ok || japan.centerMhz != 2484 ||
        !japan.requiresJapanAuthorization)
    {
        return 7;
    }
    RegisterRecipe special {};
    if (createInitRecipe(Revision::V1_1, japan, ChannelWidth::Ht20,
                         TxGainProfile::LowOb, RxGainProfile::Standard,
                         requirements, special) != Result::Ok ||
        !validRecipe(special, 11) ||
        special.phases[10].phase != RegisterPhase::Japan2484Txfir ||
        canBeginHardwareInitialization(special, requirements))
    {
        return 8;
    }
    RegisterRecipe rejected = special;
    if (createInitRecipe(Revision::V1_1, japan, ChannelWidth::Ht40,
                         TxGainProfile::LowOb, RxGainProfile::Standard,
                         requirements, rejected) != Result::InvalidChannel ||
        (rejected.count != 0U) || (rejected.registerWrites != 0U) ||
        rejected.regulatoryAuthorized || rejected.implementationComplete ||
        (rejected.phases[0].data != nullptr))
    {
        return 9;
    }
    rejected = v11;
    if (createInitRecipe(Revision::Unknown, channel, ChannelWidth::Ht20,
                         TxGainProfile::LowOb, RxGainProfile::Standard,
                         requirements,
                         rejected) != Result::UnsupportedRevision ||
        (rejected.count != 0U) || (rejected.phases[0].data != nullptr))
    {
        return 10;
    }
    rejected = v11;
    Channel inconsistent = channel;
    inconsistent.centerMhz = 2484;
    if (createInitRecipe(Revision::V1_0, inconsistent, ChannelWidth::Ht20,
                         TxGainProfile::LowOb, RxGainProfile::Standard,
                         requirements, rejected) != Result::InvalidChannel ||
        (rejected.count != 0U) || (rejected.phases[0].data != nullptr))
    {
        return 11;
    }
    rejected = v11;
    if (createInitRecipe(Revision::V1_0, channel, ChannelWidth::Ht20,
                         TxGainProfile::Unknown, RxGainProfile::Standard,
                         requirements, rejected) != Result::InvalidChannel ||
        (rejected.count != 0U) || (rejected.phases[0].data != nullptr))
    {
        return 12;
    }

    // Reusing a recipe's own channel is a legitimate in-place refresh. It
    // must snapshot the input before resetting stale phase pointers.
    RegisterRecipe aliased = v11;
    if (createInitRecipe(Revision::V1_1, aliased.channel, ChannelWidth::Ht40,
                         TxGainProfile::HighPower,
                         RxGainProfile::WithoutExternalLna, requirements,
                         aliased) != Result::Ok ||
        !validRecipe(aliased, 10) || aliased.channel.number != channel.number ||
        aliased.channel.centerMhz != channel.centerMhz ||
        aliased.channel.requiresJapanAuthorization ||
        aliased.phases[5].data != ht40.phases[5].data ||
        !aliased.regulatoryAuthorized)
    {
        return 13;
    }
    // The Japan-only channel and eleven phases must also survive aliasing.
    aliased = special;
    if (createInitRecipe(Revision::V1_1, aliased.channel, ChannelWidth::Ht20,
                         TxGainProfile::LowOb, RxGainProfile::Standard,
                         requirements, aliased) != Result::Ok ||
        !validRecipe(aliased, 11) || aliased.channel.number != 14 ||
        !aliased.channel.requiresJapanAuthorization ||
        aliased.phases[10].phase != RegisterPhase::Japan2484Txfir)
    {
        return 14;
    }
    // Invalid aliased input is still cleared, never retaining an old recipe.
    aliased = v11;
    aliased.channel.centerMhz = 1234;
    if (createInitRecipe(Revision::V1_1, aliased.channel, ChannelWidth::Ht20,
                         TxGainProfile::LowOb, RxGainProfile::Standard,
                         requirements, aliased) != Result::InvalidChannel ||
        (aliased.count != 0U) || (aliased.phases[0].data != nullptr) ||
        aliased.regulatoryAuthorized || aliased.implementationComplete)
    {
        return 15;
    }
    return 0;
}
