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
            !recipe.tablesComplete || recipe.count > 11)
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
        constexpr RegisterPhase expected[] {
            RegisterPhase::SocPreamble,
            RegisterPhase::MacCore,
            RegisterPhase::BasebandCore,
            RegisterPhase::RadioCore,
            RegisterPhase::SocPostamble,
            RegisterPhase::MacPostamble,
            RegisterPhase::BasebandPostamble,
            RegisterPhase::RadioPostamble,
            RegisterPhase::RxGain,
            RegisterPhase::TxGain,
        };
        for (size_t i = 0; i < sizeof(expected) / sizeof(expected[0]); ++i)
        {
            if (recipe.phases[i].phase != expected[i])
            {
                return false;
            }
        }
        return writes == recipe.registerWrites &&
               (expectedPhases == 10 ||
                recipe.phases[10].phase == RegisterPhase::Japan2484Txfir);
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
        v11.phases[7].data == v10.phases[7].data ||
        !canBeginHardwareInitialization(v11, requirements))
    {
        return 3;
    }
    RegisterRecipe forged = v11;
    forged.tablesComplete = false;
    if (canBeginHardwareInitialization(forged, requirements))
    {
        return 4;
    }
    forged = v11;
    forged.phases[7] = v10.phases[7];
    if (canBeginHardwareInitialization(forged, requirements))
    {
        return 5;
    }

    RegisterRecipe ht40 {};
    if (createInitRecipe(Revision::V1_1, channel, ChannelWidth::Ht40,
                         TxGainProfile::HighPower,
                         RxGainProfile::WithoutExternalLna, requirements,
                         ht40) != Result::Ok ||
        !validRecipe(ht40, 10) || ht40.phases[8].data == v11.phases[8].data ||
        ht40.phases[9].data == v11.phases[9].data ||
        ht40.phases[7].data == v11.phases[7].data ||
        !canBeginHardwareInitialization(ht40, requirements))
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
        !canBeginHardwareInitialization(special, requirements))
    {
        return 8;
    }
    RegisterRecipe rejected = special;
    if (createInitRecipe(Revision::V1_1, japan, ChannelWidth::Ht40,
                         TxGainProfile::LowOb, RxGainProfile::Standard,
                         requirements, rejected) != Result::InvalidChannel ||
        (rejected.count != 0U) || (rejected.registerWrites != 0U) ||
        rejected.regulatoryAuthorized || rejected.tablesComplete ||
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
        aliased.phases[9].data != ht40.phases[9].data ||
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
        aliased.regulatoryAuthorized || aliased.tablesComplete)
    {
        return 15;
    }
    // RX-only startup may execute the real table stage without pretending
    // that calibrated TX limits or a transmit country have been established.
    auto receive = requirements;
    receive.use = RadioInitialization::ReceiveOnly;
    receive.txPowerLimitsVerified = false;
    receive.localCountryRulesAvailable = false;
    RegisterRecipe passive {};
    if (createInitRecipe(Revision::V1_1, channel, ChannelWidth::Ht20,
                         TxGainProfile::LowOb, RxGainProfile::Standard, receive,
                         passive) != Result::Ok ||
        passive.regulatoryAuthorized ||
        !canBeginHardwareInitialization(passive, receive))
        return 16;
    receive.use = RadioInitialization::TransmitReceive;
    if (canBeginHardwareInitialization(passive, receive))
        return 17;
    receive.use = static_cast<RadioInitialization>(0xff);
    if (radioInitializationAuthorized(receive))
        return 18;
    return 0;
}
