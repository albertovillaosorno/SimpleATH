// SPDX-License-Identifier: GPL-2.0-only
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
