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
//   - Native driver contracts and implementation for diagnostic policy.
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
//   - Native driver contracts and implementation for diagnostic policy.
// - Description:
//   - Implements or verifies the DiagnosticPolicy source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for diagnostic policy.

#ifndef SIMPLEATH_DIAGNOSTIC_POLICY_HPP
#define SIMPLEATH_DIAGNOSTIC_POLICY_HPP
#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace simpleath
{
    enum class DiagnosticOverride : uint8_t
    {
        Automatic,
        Normal,
        Detailed,
    };
    enum class DiagnosticOrigin : uint8_t
    {
        Default,
        BootArgument,
        OpenCoreDebug,
    };

    struct DiagnosticSelection
    {
            bool detailed;
            DiagnosticOrigin origin;
    };

    // OpenCore exports TTT-VVV-YYYY-MM-DD: DBG optimized debug, NPT
    // unoptimized debug, REL release. Only verbosity is selected here;
    // no compiler, feature, device authorization or readiness state changes.
    inline DiagnosticSelection selectDiagnostics(DiagnosticOverride requested,
                                                 const uint8_t *version,
                                                 size_t bytes)
    {
        if (requested == DiagnosticOverride::Normal ||
            requested == DiagnosticOverride::Detailed)
        {
            return {
                requested == DiagnosticOverride::Detailed,
                DiagnosticOrigin::BootArgument,
            };
        }
        constexpr size_t kIdentifierBytes = 18;
        constexpr size_t kYearSeparator = 7;
        constexpr size_t kMonthSeparator = 12;
        constexpr size_t kDaySeparator = 15;
        if (requested != DiagnosticOverride::Automatic || version == nullptr ||
            (bytes != kIdentifierBytes && bytes != kIdentifierBytes + 1))
        {
            return {false, DiagnosticOrigin::Default};
        }
        // Copy only the bounded identifier, before inspecting borrowed data.
        uint8_t identifier[kIdentifierBytes + 1] {};
        memcpy(&identifier[0], version, bytes);
        if (identifier[kIdentifierBytes] != 0)
        {
            return {false, DiagnosticOrigin::Default};
        }
        size_t index = 0;
        for (const auto character : identifier)
        {
            if (index >= 3 && index < kIdentifierBytes)
            {
                const bool separator = index == 3 || index == kYearSeparator ||
                                       index == kMonthSeparator ||
                                       index == kDaySeparator;
                if (separator ? character != '-'
                              : character < '0' || character > '9')
                {
                    return {false, DiagnosticOrigin::Default};
                }
            }
            ++index;
        }
        const bool debug = identifier[0] == 'D' && identifier[1] == 'B' &&
                           identifier[2] == 'G';
        const bool noOptimization = identifier[0] == 'N' &&
                                    identifier[1] == 'P' &&
                                    identifier[2] == 'T';
        return {
            debug || noOptimization,
            debug || noOptimization ? DiagnosticOrigin::OpenCoreDebug
                                    : DiagnosticOrigin::Default,
        };
    }
} // namespace simpleath
#endif
