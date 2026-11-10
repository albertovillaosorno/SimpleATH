// SPDX-License-Identifier: AGPL-3.0-only
#include "Ar9565RfIni.hpp"
#include "generated/Ar9565InitTables.hpp"

namespace simpleath
{
    namespace
    {
        constexpr size_t kWriteDelayInterval = 32;

        bool matchesCanonical(const RegisterRecipe &recipe,
                              const CalibrationAndRegulatory &requirements,
                              uint32_t barLength)
        {
            RegisterRecipe expected {};
            if (!canBeginHardwareInitialization(recipe, requirements) ||
                createInitRecipe(recipe.silicon, recipe.channel, recipe.width,
                                 recipe.txGain, recipe.rxGain, requirements,
                                 expected) != Result::Ok ||
                recipe.count != expected.count ||
                recipe.registerWrites != expected.registerWrites ||
                recipe.regulatoryAuthorized != expected.regulatoryAuthorized ||
                recipe.tablesComplete != expected.tablesComplete)
            {
                return false;
            }
            for (size_t i = 0; i < expected.count; ++i)
            {
                const auto &a = recipe.phases[i];
                const auto &b = expected.phases[i];
                if (a.phase != b.phase || a.data != b.data ||
                    a.count != b.count)
                {
                    return false;
                }
                for (size_t j = 0; j < a.count; ++j)
                {
                    const uint32_t offset = a.data[j].offset;
                    if ((offset & 3U) != 0U || offset > barLength ||
                        barLength - offset < sizeof(uint32_t))
                    {
                        return false;
                    }
                }
            }
            return true;
        }
    } // namespace

    RfIniProgress applyAr9565RfIni(const RegisterRecipe &recipe,
                                   const CalibrationAndRegulatory &requirements,
                                   const RfIniBackend &backend)
    {
        RfIniProgress progress {RfIniResult::InvalidBackend, 0, 0, 0, false};
        const RfIniBackend stable = backend;
        if (!stable.context || !stable.ownerEpoch || !stable.barLengthBytes ||
            !stable.permitWrite || !stable.write32 || !stable.delayMicros)
        {
            return progress;
        }
        progress.result = RfIniResult::InvalidRecipe;
        // Freeze the caller's recipe before invoking any callbacks. In
        // particular, a callback must not be able to swap a later table or
        // row count between the preflight and the actual register writes.
        const RegisterRecipe frozen = recipe;
        if (!matchesCanonical(frozen, requirements, stable.barLengthBytes))
        {
            return progress;
        }
        progress.result = RfIniResult::OwnershipLost;
        if (!stable.permitWrite(stable.context, stable.ownerEpoch))
        {
            return progress;
        }
        for (size_t phase = 0; phase < frozen.count; ++phase)
        {
            const auto &table = frozen.phases[phase];
            for (size_t row = 0; row < table.count; ++row)
            {
                if (!stable.permitWrite(stable.context, stable.ownerEpoch))
                {
                    progress.result = RfIniResult::OwnershipLost;
                    progress.requiresReset = progress.completedWrites != 0;
                    return progress;
                }
                progress.lastOffset = table.data[row].offset;
                // The callback may post to the PCI device before failing.
                progress.requiresReset = true;
                if (!stable.write32(stable.context, progress.lastOffset,
                                    table.data[row].value))
                {
                    progress.result = RfIniResult::WriteFailed;
                    return progress;
                }
                ++progress.completedWrites;
                if (progress.completedWrites % kWriteDelayInterval == 0)
                {
                    stable.delayMicros(stable.context, 1);
                }
            }
            ++progress.completedPhases;
        }
        // The final MMIO callback can also revoke the provider. A stale
        // epoch must never be published as a completed initialization stage.
        if (!stable.permitWrite(stable.context, stable.ownerEpoch))
        {
            progress.result = RfIniResult::OwnershipLost;
            return progress;
        }
        progress.requiresReset = false;
        progress.result = RfIniResult::Ok;
        return progress;
    }
} // namespace simpleath
