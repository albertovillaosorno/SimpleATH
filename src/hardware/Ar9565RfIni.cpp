// SPDX-License-Identifier: AGPL-3.0-only
#include "Ar9565RfIni.hpp"
#include "Ar9565Core.hpp"
#include "Ar9565InitCatalog.hpp"
#include "generated/Ar9565InitTables.hpp"
#include <cstddef>
#include <cstdint>

namespace simpleath
{
    namespace
    {
        constexpr size_t kWriteDelayInterval = 32;
        constexpr size_t kLargestGeneratedTableRows = 259;
        constexpr uint32_t kRegisterAlignmentMask = 3U;
        constexpr uint32_t kPostWriteDelayMicros = 1U;

        // Array iteration makes phase bounds explicit. There are precisely
        // eleven slots and the recipe may authorize only a prefix of them.
        const RegisterTable *phaseAt(const RegisterRecipe &recipe, size_t index)
        {
            if (index >= recipe.count || index >= kRegisterPhaseCapacity)
            {
                return nullptr;
            }
            size_t current = 0;
            for (const RegisterTable &phase : recipe.phases)
            {
                if (current == index)
                {
                    return &phase;
                }
                ++current;
            }
            return nullptr;
        }

        // The pinned ath9k source's largest table has 259 rows (RX gain).
        // Copy through the table's established length into bounded local
        // storage before walking the rows, without unchecked pointer offsets.
        bool
        snapshotRows(const RegisterTable &table,
                     ini::RegisterValue (&rows)[kLargestGeneratedTableRows])
        {
            // An unselected optional channel-14 phase has zero rows and may
            // correctly have no data pointer in the canonical recipe.
            if (table.count == 0)
            {
                return true;
            }
            if (table.data == nullptr ||
                table.count > kLargestGeneratedTableRows)
            {
                return false;
            }
            __builtin_memcpy(&rows[0], table.data,
                             table.count * sizeof(rows[0]));
            return true;
        }

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
            if (expected.count > kRegisterPhaseCapacity)
            {
                return false;
            }
            for (size_t phaseIndex = 0; phaseIndex < expected.count;
                 ++phaseIndex)
            {
                const RegisterTable *a = phaseAt(recipe, phaseIndex);
                const RegisterTable *b = phaseAt(expected, phaseIndex);
                if (a == nullptr || b == nullptr || a->phase != b->phase ||
                    a->data != b->data || a->count != b->count)
                {
                    return false;
                }
                ini::RegisterValue rows[kLargestGeneratedTableRows] {};
                if (!snapshotRows(*a, rows))
                {
                    return false;
                }
                size_t consumed = 0;
                for (const ini::RegisterValue &row : rows)
                {
                    if (consumed == a->count)
                    {
                        break;
                    }
                    const uint32_t offset = row.offset;
                    if ((offset & kRegisterAlignmentMask) != 0U ||
                        offset > barLength ||
                        barLength - offset < sizeof(uint32_t))
                    {
                        return false;
                    }
                    ++consumed;
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
        if (stable.context == nullptr || stable.ownerEpoch == 0U ||
            stable.barLengthBytes == 0U || stable.permitWrite == nullptr ||
            stable.write32 == nullptr || stable.delayMicros == nullptr)
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
        for (size_t phaseIndex = 0; phaseIndex < frozen.count; ++phaseIndex)
        {
            const RegisterTable *table = phaseAt(frozen, phaseIndex);
            ini::RegisterValue rows[kLargestGeneratedTableRows] {};
            if (table == nullptr || !snapshotRows(*table, rows))
            {
                progress.result = RfIniResult::InvalidRecipe;
                progress.requiresReset = progress.completedWrites != 0;
                return progress;
            }
            size_t consumed = 0;
            for (const ini::RegisterValue &row : rows)
            {
                if (consumed == table->count)
                {
                    break;
                }
                if (!stable.permitWrite(stable.context, stable.ownerEpoch))
                {
                    progress.result = RfIniResult::OwnershipLost;
                    progress.requiresReset = progress.completedWrites != 0;
                    return progress;
                }
                progress.lastOffset = row.offset;
                // The callback may post to the PCI device before failing.
                progress.requiresReset = true;
                if (!stable.write32(stable.context, progress.lastOffset,
                                    row.value))
                {
                    progress.result = RfIniResult::WriteFailed;
                    return progress;
                }
                ++progress.completedWrites;
                ++consumed;
                if (progress.completedWrites % kWriteDelayInterval == 0)
                {
                    stable.delayMicros(stable.context, kPostWriteDelayMicros);
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
