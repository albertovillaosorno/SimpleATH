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
//   - Offline regression cases for init catalog.
// - Must-Not:
//   - Require physical hardware, mutate installed drivers, or suppress
//     failures.
// - Allows:
//   - Inputs: isolated fixtures and reproducible source-under-test inputs.
//   - Outputs: assertions and observable regression verdicts.
//   - Side effects: test-local temporary files and bounded subprocesses only.
// - Split-When:
//   - A separate protocol stage needs independent validation and ownership.
// - Merge-When:
//   - The caller directly owns this narrow contract without reuse.
// - Summary:
//   - Offline regression cases for init catalog.
// - Description:
//   - Implements or verifies the test_init_catalog source boundary.
// - Usage:
//   - Executed by offline host test discovery or the native test harness.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Offline regression cases for init catalog.
// Source table catalog contract only: no MMIO, PHY or radio initialization.
#include "bluetooth/UsbBytes.hpp"
#include "hardware/Ar9565Core.hpp"
#include "hardware/Ar9565InitCatalog.hpp"
#include <array>
#include <cstddef>
#include <cstdint>

using namespace simpleath;

namespace
{
    constexpr size_t kOrdinaryPhaseCount = 10U;
    constexpr size_t kRadioPostamblePhase = 7U;
    constexpr size_t kRxGainPhase = 8U;
    constexpr size_t kTxGainPhase = 9U;
    constexpr size_t kJapanPhase = 10U;
    constexpr uint8_t kGeneralChannelNumber = 6U;
    constexpr uint8_t kJapanChannelNumber = 14U;
    constexpr uint16_t kGeneralChannelMhz = 2437U;
    constexpr uint16_t kJapanChannelMhz = 2484U;
    constexpr uint16_t kInvalidChannelMhz = 1234U;
    constexpr uint8_t kUnsupportedMode = 0xffU;

    bool validRecipe(const RegisterRecipe &recipe, size_t expectedPhases)
    {
        if (recipe.count != expectedPhases || (recipe.registerWrites == 0U) ||
            !recipe.tablesComplete || recipe.count > kRegisterPhaseCapacity)
        {
            return false;
        }
        size_t writes = 0;
        for (size_t i = 0; i < recipe.count; ++i)
        {
            if ((usbByteOffset(&recipe.phases[0U], i)->data == nullptr) ||
                (usbByteOffset(&recipe.phases[0U], i)->count == 0U))
            {
                return false;
            }
            writes += usbByteOffset(&recipe.phases[0U], i)->count;
        }
        constexpr std::array<RegisterPhase, kOrdinaryPhaseCount> expected {
            {
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
            },
        };
        for (size_t i = 0; i < expected.size(); ++i)
        {
            if (usbByteOffset(&recipe.phases[0U], i)->phase != expected.at(i))
            {
                return false;
            }
        }
        return writes == recipe.registerWrites &&
               (expectedPhases == kOrdinaryPhaseCount ||
                recipe.phases[kJapanPhase].phase ==
                    RegisterPhase::Japan2484Txfir);
    }

    int
    verifyAliasingAndReceiveOnly(const RegisterRecipe &v11,
                                 const Channel &channel,
                                 const RegisterRecipe &ht40,
                                 const CalibrationAndRegulatory &requirements,
                                 const RegisterRecipe &special)
    {
        // Reusing a recipe's own channel is a legitimate in-place refresh. It
        // must snapshot the input before resetting stale phase pointers.
        RegisterRecipe aliased = v11;
        if (createInitRecipe(Revision::V1_1, aliased.channel,
                             ChannelWidth::Ht40, TxGainProfile::HighPower,
                             RxGainProfile::WithoutExternalLna, requirements,
                             aliased) != Result::Ok ||
            !validRecipe(aliased, kOrdinaryPhaseCount) ||
            aliased.channel.number != channel.number ||
            aliased.channel.centerMhz != channel.centerMhz ||
            aliased.channel.requiresJapanAuthorization ||
            aliased.phases[kTxGainPhase].data !=
                ht40.phases[kTxGainPhase].data ||
            !aliased.regulatoryAuthorized)
        {
            return __LINE__;
        }
        // The Japan-only channel and eleven phases must also survive aliasing.
        aliased = special;
        if (createInitRecipe(Revision::V1_1, aliased.channel,
                             ChannelWidth::Ht20, TxGainProfile::LowOb,
                             RxGainProfile::Standard, requirements,
                             aliased) != Result::Ok ||
            !validRecipe(aliased, kRegisterPhaseCapacity) ||
            aliased.channel.number != kJapanChannelNumber ||
            !aliased.channel.requiresJapanAuthorization ||
            aliased.phases[kJapanPhase].phase != RegisterPhase::Japan2484Txfir)
        {
            return __LINE__;
        }
        // Invalid aliased input is still cleared, never retaining an old
        // recipe.
        aliased = v11;
        aliased.channel.centerMhz = kInvalidChannelMhz;
        if (createInitRecipe(Revision::V1_1, aliased.channel,
                             ChannelWidth::Ht20, TxGainProfile::LowOb,
                             RxGainProfile::Standard, requirements,
                             aliased) != Result::InvalidChannel ||
            (aliased.count != 0U) || (aliased.phases[0].data != nullptr) ||
            aliased.regulatoryAuthorized || aliased.tablesComplete)
        {
            return __LINE__;
        }
        // RX-only startup may execute the real table stage without pretending
        // that calibrated TX limits or a transmit country have been
        // established.
        auto receive = requirements;
        receive.use = RadioInitialization::ReceiveOnly;
        receive.txPowerLimitsVerified = false;
        receive.localCountryRulesAvailable = false;
        RegisterRecipe passive {};
        if (createInitRecipe(Revision::V1_1, channel, ChannelWidth::Ht20,
                             TxGainProfile::LowOb, RxGainProfile::Standard,
                             receive, passive) != Result::Ok ||
            passive.regulatoryAuthorized ||
            !canBeginHardwareInitialization(passive, receive))
        {
            return __LINE__;
        }
        receive.use = RadioInitialization::TransmitReceive;
        if (canBeginHardwareInitialization(passive, receive))
        {
            return __LINE__;
        }
        receive.use = static_cast<RadioInitialization>(kUnsupportedMode);
        if (radioInitializationAuthorized(receive))
        {
            return __LINE__;
        }
        return 0;
    }

} // namespace

int main()
{
    Channel channel {};
    if (mapChannel(kGeneralChannelNumber, channel) != Result::Ok ||
        channel.centerMhz != kGeneralChannelMhz)
    {
        return __LINE__;
    }
    const CalibrationAndRegulatory untrusted {};
    RegisterRecipe v10 {};
    if (createInitRecipe(Revision::V1_0, channel, ChannelWidth::Ht20,
                         TxGainProfile::LowOb, RxGainProfile::Standard,
                         untrusted, v10) != Result::Ok ||
        !validRecipe(v10, kOrdinaryPhaseCount) || v10.regulatoryAuthorized ||
        canBeginHardwareInitialization(v10, untrusted))
    {
        return __LINE__;
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
        !validRecipe(v11, kOrdinaryPhaseCount) || !v11.regulatoryAuthorized ||
        v11.phases[kRadioPostamblePhase].data ==
            v10.phases[kRadioPostamblePhase].data ||
        !canBeginHardwareInitialization(v11, requirements))
    {
        return __LINE__;
    }
    RegisterRecipe forged = v11;
    forged.tablesComplete = false;
    if (canBeginHardwareInitialization(forged, requirements))
    {
        return __LINE__;
    }
    forged = v11;
    forged.phases[kRadioPostamblePhase] = v10.phases[kRadioPostamblePhase];
    if (canBeginHardwareInitialization(forged, requirements))
    {
        return __LINE__;
    }

    RegisterRecipe ht40 {};
    if (createInitRecipe(Revision::V1_1, channel, ChannelWidth::Ht40,
                         TxGainProfile::HighPower,
                         RxGainProfile::WithoutExternalLna, requirements,
                         ht40) != Result::Ok ||
        !validRecipe(ht40, kOrdinaryPhaseCount) ||
        ht40.phases[kRxGainPhase].data == v11.phases[kRxGainPhase].data ||
        ht40.phases[kTxGainPhase].data == v11.phases[kTxGainPhase].data ||
        ht40.phases[kRadioPostamblePhase].data ==
            v11.phases[kRadioPostamblePhase].data ||
        !canBeginHardwareInitialization(ht40, requirements))
    {
        return __LINE__;
    }

    Channel japan {};
    if (mapChannel(kJapanChannelNumber, japan) != Result::Ok ||
        japan.centerMhz != kJapanChannelMhz ||
        !japan.requiresJapanAuthorization)
    {
        return __LINE__;
    }
    RegisterRecipe special {};
    if (createInitRecipe(Revision::V1_1, japan, ChannelWidth::Ht20,
                         TxGainProfile::LowOb, RxGainProfile::Standard,
                         requirements, special) != Result::Ok ||
        !validRecipe(special, kRegisterPhaseCapacity) ||
        special.phases[kJapanPhase].phase != RegisterPhase::Japan2484Txfir ||
        !canBeginHardwareInitialization(special, requirements))
    {
        return __LINE__;
    }
    RegisterRecipe rejected = special;
    if (createInitRecipe(Revision::V1_1, japan, ChannelWidth::Ht40,
                         TxGainProfile::LowOb, RxGainProfile::Standard,
                         requirements, rejected) != Result::InvalidChannel ||
        (rejected.count != 0U) || (rejected.registerWrites != 0U) ||
        rejected.regulatoryAuthorized || rejected.tablesComplete ||
        (rejected.phases[0].data != nullptr))
    {
        return __LINE__;
    }
    rejected = v11;
    if (createInitRecipe(Revision::Unknown, channel, ChannelWidth::Ht20,
                         TxGainProfile::LowOb, RxGainProfile::Standard,
                         requirements,
                         rejected) != Result::UnsupportedRevision ||
        (rejected.count != 0U) || (rejected.phases[0].data != nullptr))
    {
        return __LINE__;
    }
    rejected = v11;
    Channel inconsistent = channel;
    inconsistent.centerMhz = kJapanChannelMhz;
    if (createInitRecipe(Revision::V1_0, inconsistent, ChannelWidth::Ht20,
                         TxGainProfile::LowOb, RxGainProfile::Standard,
                         requirements, rejected) != Result::InvalidChannel ||
        (rejected.count != 0U) || (rejected.phases[0].data != nullptr))
    {
        return __LINE__;
    }
    rejected = v11;
    if (createInitRecipe(Revision::V1_0, channel, ChannelWidth::Ht20,
                         TxGainProfile::Unknown, RxGainProfile::Standard,
                         requirements, rejected) != Result::InvalidChannel ||
        (rejected.count != 0U) || (rejected.phases[0].data != nullptr))
    {
        return __LINE__;
    }

    return verifyAliasingAndReceiveOnly(v11, channel, ht40, requirements,
                                        special);
}
