// SPDX-License-Identifier: AGPL-3.0-only
#include "Ar9565InitCatalog.hpp"
#include "generated/Ar9565InitTables.hpp"

namespace simpleath
{
    namespace
    {

        using ini::TableView;

        // The generated inputs are immutable and are never written to the
        // device automatically. A future PCI/MMIO transport must validate
        // mappings, delays, reset ordering, EEPROM calibration, and
        // interrupt/DMA lifecycles.
        void append(RegisterRecipe &recipe, RegisterPhase phase, TableView view)
        {
            if (recipe.count >=
                sizeof(recipe.phases) / sizeof(recipe.phases[0]))
                return;
            recipe.phases[recipe.count++] = {phase, view.rows, view.count};
            recipe.registerWrites += view.count;
        }

        TableView rxGain(RxGainProfile profile, ChannelWidth width)
        {
            if (profile == RxGainProfile::WithoutExternalLna)
                return width == ChannelWidth::Ht20
                           ? ini::kCommonWoXlnaRxGainTableHt20View
                           : ini::kCommonWoXlnaRxGainTableHt40View;
            return width == ChannelWidth::Ht20 ? ini::kRxGainHt20View
                                               : ini::kRxGainHt40View;
        }

        TableView txGain(TxGainProfile profile, ChannelWidth width)
        {
            if (profile == TxGainProfile::HighPower)
                return width == ChannelWidth::Ht20
                           ? ini::kTxGainHighPowerHt20View
                           : ini::kTxGainHighPowerHt40View;
            if (profile == TxGainProfile::HighOb)
                return width == ChannelWidth::Ht20 ? ini::kTxGainHighObHt20View
                                                   : ini::kTxGainHighObHt40View;
            return width == ChannelWidth::Ht20 ? ini::kTxGainLowObHt20View
                                               : ini::kTxGainLowObHt40View;
        }

    } // namespace

    bool
    canBeginHardwareInitialization(const RegisterRecipe &recipe,
                                   const CalibrationAndRegulatory &requirements)
    {
        if (!recipe.implementationComplete || !recipe.regulatoryAuthorized ||
            !requirements.eepromContentsVerified ||
            !requirements.boardAntennaConfigurationVerified ||
            !requirements.localCountryRulesAvailable ||
            !requirements.channelPermitted ||
            !requirements.txPowerLimitsVerified ||
            !requirements.radioKillUnblocked ||
            !requirements.coexistenceConfigurationVerified)
            return false;

        // Even when a future owner can legitimately mark the implementation
        // complete, a caller-mutated recipe is not an acceptable table list.
        // Compare every phase and immutable table view with the pinned,
        // revision-specific source recipe. This is still NOT hardware proof.
        RegisterRecipe expected {};
        if (createInitRecipe(recipe.silicon, recipe.channel, recipe.width,
                             recipe.txGain, recipe.rxGain, requirements,
                             expected) != Result::Ok ||
            // This source does not implement active radio initialization.
            // No caller may turn a source-disabled recipe into an executable
            // one simply by modifying its implementationComplete flag.
            !expected.implementationComplete ||
            !expected.regulatoryAuthorized || recipe.count != expected.count ||
            recipe.registerWrites != expected.registerWrites)
            return false;
        for (size_t i = 0; i < expected.count; ++i)
        {
            if (recipe.phases[i].phase != expected.phases[i].phase ||
                recipe.phases[i].data != expected.phases[i].data ||
                recipe.phases[i].count != expected.phases[i].count)
                return false;
        }
        return true;
    }

    Result createInitRecipe(Revision revision, const Channel &channel,
                            ChannelWidth width, TxGainProfile tx,
                            RxGainProfile rx,
                            const CalibrationAndRegulatory &requirements,
                            RegisterRecipe &out)
    {
        // The requested channel can be a member of the caller's old recipe.
        // Snapshot every borrowed input before clearing out, so a legitimate
        // in-place refresh never destroys its own channel or prerequisites.
        const Channel requestedChannel = channel;
        const CalibrationAndRegulatory requestedRequirements = requirements;
        // Do not expose a previous recipe's valid-looking table pointers or
        // flags when a new revision/channel request is rejected.
        out = {};
        if (revision != Revision::V1_0 && revision != Revision::V1_0_1 &&
            revision != Revision::V1_1)
            return Result::UnsupportedRevision;
        if ((width != ChannelWidth::Ht20 && width != ChannelWidth::Ht40) ||
            (tx != TxGainProfile::LowOb && tx != TxGainProfile::HighOb &&
             tx != TxGainProfile::HighPower) ||
            (rx != RxGainProfile::Standard &&
             rx != RxGainProfile::WithoutExternalLna))
            return Result::InvalidChannel;

        Channel expected {};
        if (mapChannel(requestedChannel.number, expected) != Result::Ok ||
            expected.centerMhz != requestedChannel.centerMhz ||
            expected.requiresJapanAuthorization !=
                requestedChannel.requiresJapanAuthorization)
            return Result::InvalidChannel;
        if (requestedChannel.number == 14 && width != ChannelWidth::Ht20)
            return Result::InvalidChannel;

        RegisterRecipe recipe {};
        recipe.silicon = revision;
        recipe.width = width;
        recipe.txGain = tx;
        recipe.rxGain = rx;
        recipe.channel = requestedChannel;
        // A correctly populated table is NOT permission to transmit.
        recipe.regulatoryAuthorized =
            requestedRequirements.localCountryRulesAvailable &&
            requestedRequirements.channelPermitted &&
            requestedRequirements.txPowerLimitsVerified;
        recipe.implementationComplete = false;

        const bool ht20 = width == ChannelWidth::Ht20;
        append(recipe, RegisterPhase::SocPreamble,
               ht20 ? ini::kSocPreambleHt20View : ini::kSocPreambleHt40View);
        append(recipe, RegisterPhase::MacCore,
               ht20 ? ini::kMacCoreHt20View : ini::kMacCoreHt40View);
        append(recipe, RegisterPhase::BasebandCore,
               ht20 ? ini::kBasebandCoreHt20View : ini::kBasebandCoreHt40View);
        append(recipe, RegisterPhase::RadioCore,
               ht20 ? ini::kRadioCoreHt20View : ini::kRadioCoreHt40View);
        append(recipe, RegisterPhase::RxGain, rxGain(rx, width));
        append(recipe, RegisterPhase::TxGain, txGain(tx, width));
        append(recipe, RegisterPhase::SocPostamble,
               ht20 ? ini::kSocPostambleHt20View : ini::kSocPostambleHt40View);
        append(recipe, RegisterPhase::MacPostamble,
               ht20 ? ini::kMacPostambleHt20View : ini::kMacPostambleHt40View);
        append(recipe, RegisterPhase::BasebandPostamble,
               ht20 ? ini::kBasebandPostambleHt20View
                    : ini::kBasebandPostambleHt40View);
        if (revision == Revision::V1_1)
            append(recipe, RegisterPhase::RadioPostamble,
                   ht20 ? ini::kRadioPostamble11Ht20View
                        : ini::kRadioPostamble11Ht40View);
        else
            append(recipe, RegisterPhase::RadioPostamble,
                   ht20 ? ini::kRadioPostamble10Ht20View
                        : ini::kRadioPostamble10Ht40View);

        if (requestedChannel.number == 14)
        {
            append(recipe, RegisterPhase::Japan2484Txfir,
                   ini::kJapan2484TxfirHt20View);
        }
        out = recipe;
        return Result::Ok;
    }

} // namespace simpleath
