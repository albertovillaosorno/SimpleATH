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
//   - Offline regression cases for diagnostic policy.
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
//   - Offline regression cases for diagnostic policy.
// - Description:
//   - Implements or verifies the test_diagnostic_policy source boundary.
// - Usage:
//   - Executed by offline host test discovery or the native test harness.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Offline regression cases for diagnostic policy.

#include "diagnostics/DiagnosticPolicy.hpp"
#include <array>
#include <cstddef>
#include <cstdint>

namespace
{
    constexpr std::array<uint8_t, 19> kDebug {
        {
            'D', 'B', 'G', '-', '1', '0', '9', '-', '2', '0',
            '2', '6', '-', '1', '1', '-', '1', '0', 0,
        },
    };

    enum ExitCode : int
    {
        Passed,
        MissingMetadata,
        DebugSelection,
        NonTerminatedSelection,
        UnoptimizedSelection,
        ReleaseSelection,
        TruncatedSelection,
        MalformedSelection,
        OverridePrecedence,
        OverrideOrigin,
    };

    constexpr uint8_t kMalformedByte = 0xff;
    using simpleath::DiagnosticOrigin;
    using simpleath::DiagnosticOverride;
    using simpleath::selectDiagnostics;
} // namespace

int main()
{
    const auto missing =
        selectDiagnostics(DiagnosticOverride::Automatic, nullptr, 0);
    if (missing.detailed || missing.origin != DiagnosticOrigin::Default)
    {
        return MissingMetadata;
    }
    const auto debug = selectDiagnostics(DiagnosticOverride::Automatic,
                                         kDebug.data(), kDebug.size());
    if (!debug.detailed || debug.origin != DiagnosticOrigin::OpenCoreDebug)
    {
        return DebugSelection;
    }
    if (!selectDiagnostics(DiagnosticOverride::Automatic, kDebug.data(),
                           kDebug.size() - 1)
             .detailed)
    {
        return NonTerminatedSelection;
    }
    auto version = kDebug;
    version.at(0) = 'N';
    version.at(1) = 'P';
    version.at(2) = 'T';
    if (!selectDiagnostics(DiagnosticOverride::Automatic, version.data(),
                           version.size())
             .detailed)
    {
        return UnoptimizedSelection;
    }
    version.at(0) = 'R';
    version.at(1) = 'E';
    version.at(2) = 'L';
    if (selectDiagnostics(DiagnosticOverride::Automatic, version.data(),
                          version.size())
            .detailed)
    {
        return ReleaseSelection;
    }
    for (size_t bytes = 0; bytes < kDebug.size() - 1; ++bytes)
    {
        if (selectDiagnostics(DiagnosticOverride::Automatic, kDebug.data(),
                              bytes)
                .detailed)
        {
            return TruncatedSelection;
        }
    }
    for (size_t index = 3; index < kDebug.size(); ++index)
    {
        version = kDebug;
        version.at(index) = kMalformedByte;
        if (selectDiagnostics(DiagnosticOverride::Automatic, version.data(),
                              version.size())
                .detailed)
        {
            return MalformedSelection;
        }
    }
    if (!selectDiagnostics(DiagnosticOverride::Detailed, nullptr, 0).detailed ||
        selectDiagnostics(DiagnosticOverride::Normal, kDebug.data(),
                          kDebug.size())
            .detailed)
    {
        return OverridePrecedence;
    }
    if (selectDiagnostics(DiagnosticOverride::Normal, nullptr, 0).origin !=
        DiagnosticOrigin::BootArgument)
    {
        return OverrideOrigin;
    }
    return Passed;
}
