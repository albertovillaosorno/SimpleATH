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
//   - Offline regression cases for mac quiesce.
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
//   - Offline regression cases for mac quiesce.
// - Description:
//   - Implements or verifies the test_mac_quiesce source boundary.
// - Usage:
//   - Executed by offline host test discovery or the native test harness.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Offline regression cases for mac quiesce.

#include "hardware/Ar9565Core.hpp"
#include "hardware/Ar9565MacControl.hpp"
#include <cstdint>
#include <initializer_list>

namespace
{
    constexpr uint32_t kRtcRegister = simpleath::kRtcStatusRegister;
    constexpr uint32_t kDiagnosticRegister = 0x8048U;
    constexpr uint32_t kRxRegister = 0x0008U;
    constexpr uint32_t kTxRegister = 0x0840U;
    constexpr uint32_t kObserveRegister = 0x806cU;
    constexpr uint32_t kStopRegister = 0x0880U;
    constexpr uint32_t kSelfGeneratedMaskRegister = 0x832cU;
    constexpr uint64_t kOwnerEpoch = 42U;
    constexpr uint32_t kCommandRegister = 0x0024U;
    constexpr uint32_t kSecondaryRegister = 0x402cU;
    constexpr uint32_t kBarBytes = 0x20000U;
    constexpr uint32_t kStopMask = 0x3ffU;
    constexpr uint32_t kInitialDiagnostic = 0x40U;
    constexpr uint32_t kStopDiagnosticBits = 0x02000026U;
    constexpr uint32_t kInitialRx = 0x0cU;
    constexpr uint32_t kInitialObserve = 0x00100000U;
    constexpr uint32_t kRtcWake = 8U;
    constexpr uint32_t kRtcInvalid = 0xffffffffU;
    constexpr uint32_t kRtcUnknown = 15U;
    constexpr unsigned kExpectedStopWrites = 5U;
    constexpr unsigned kStopTimeoutPolls = 1000U;
    constexpr int kStuckFailure = 3;
    constexpr int kRevokedFailure = 4;
    constexpr int kWriteFailure = 5;
    constexpr int kInvalidRtcFailure = 6;
    constexpr int kUnknownRtcFailure = 7;
    constexpr int kWakeTimeoutFailure = 8;
    constexpr int kMissingBackendFailure = 9;
    constexpr int kWakeThenStopFailure = 10;
    constexpr int kUnsupportedRtcFailure = 11;

    struct Hardware
    {
            uint32_t rtc = simpleath::kRtcOn;
            uint32_t diagnostic = kInitialDiagnostic;
            uint32_t rx = kInitialRx;
            uint32_t tx = kStopMask;
            uint32_t observe = kInitialObserve;
            uint32_t selfGeneratedMask = 0;
            uint64_t epoch = kOwnerEpoch;
            unsigned int selfGeneratedReads = 0;
            unsigned int permitChecks = 0;
            bool failSelfGeneratedRead = false;
            bool revokeAfterSelfGeneratedRead = false;
            unsigned int delays = 0;
            unsigned int writes = 0;
            unsigned int macReads = 0;
            bool revoked = false;
            bool stuck = false;
            bool wakeAfterDelay = false;
            bool failWrite = false;
            bool stopWritten = false;
    };

    bool read(void *opaque, uint32_t reg, uint32_t *value)
    {
        auto &hardware = *static_cast<Hardware *>(opaque);
        if (hardware.revoked)
        {
            return false;
        }
        switch (reg)
        {
            case kRtcRegister:
                *value = hardware.rtc;
                return true;
            case kDiagnosticRegister:
                *value = hardware.diagnostic;
                break;
            case kRxRegister:
                *value = hardware.rx;
                break;
            case kTxRegister:
                *value = hardware.tx;
                break;
            case kObserveRegister:
                *value = hardware.observe;
                break;
            case kSelfGeneratedMaskRegister:
                ++hardware.selfGeneratedReads;
                if (hardware.failSelfGeneratedRead)
                {
                    return false;
                }
                *value = hardware.selfGeneratedMask;
                if (hardware.revokeAfterSelfGeneratedRead)
                {
                    hardware.revoked = true;
                }
                break;
            default:
                return false;
        }
        ++hardware.macReads;
        return true;
    }

    // The bus's required callback ABI fixes the adjacent offset/value types.
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    bool write(void *opaque, uint32_t reg, uint32_t value)
    {
        auto &hardware = *static_cast<Hardware *>(opaque);
        if (hardware.revoked || hardware.failWrite)
        {
            return false;
        }
        ++hardware.writes;
        if (reg == kDiagnosticRegister)
        {
            hardware.diagnostic = value;
        }
        else if (reg == kStopRegister)
        {
            hardware.stopWritten = value == kStopMask;
        }
        else if (reg != kCommandRegister && reg != kSecondaryRegister &&
                 reg != kRxRegister)
        {
            return false;
        }
        return true;
    }

    void delay(void *opaque, uint32_t /*micros*/)
    {
        auto &hardware = *static_cast<Hardware *>(opaque);
        ++hardware.delays;
        if (hardware.wakeAfterDelay && hardware.rtc == kRtcWake)
        {
            hardware.rtc = simpleath::kRtcOn;
        }
        if (!hardware.stuck && hardware.stopWritten)
        {
            hardware.rx = hardware.tx = hardware.observe = 0;
        }
    }

    bool currentOwner(void *opaque, uint64_t epoch)
    {
        auto &hardware = *static_cast<Hardware *>(opaque);
        ++hardware.permitChecks;
        return epoch != 0 && epoch == hardware.epoch && !hardware.revoked;
    }

    simpleath::MacReceiveOnlyResult
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    verifyReceiveOnly(Hardware &hardware, uint32_t bar = kBarBytes,
                      uint64_t epoch = kOwnerEpoch)
    {
        const simpleath::RegisterBus bus {&hardware, read, write, bar};
        return simpleath::verifyAr9565ReceiveOnlyAutoResponsesDisabled(
            bus, epoch, currentOwner);
    }

    bool receiveOnlyGuardCases()
    {
        using simpleath::MacReceiveOnlyResult;
        Hardware clean;
        if (verifyReceiveOnly(clean) != MacReceiveOnlyResult::Ok ||
            clean.selfGeneratedReads != 1 || clean.permitChecks != 2 ||
            clean.writes != 0)
        {
            return false;
        }
        Hardware activeAutoResponses;
        activeAutoResponses.selfGeneratedMask = 1U;
        if (verifyReceiveOnly(activeAutoResponses) !=
                MacReceiveOnlyResult::AutoResponsesEnabled ||
            activeAutoResponses.selfGeneratedReads != 1)
        {
            return false;
        }
        Hardware floatingBar;
        floatingBar.selfGeneratedMask = UINT32_MAX;
        if (verifyReceiveOnly(floatingBar) != MacReceiveOnlyResult::ReadFailed)
        {
            return false;
        }
        Hardware failedRead;
        failedRead.failSelfGeneratedRead = true;
        if (verifyReceiveOnly(failedRead) != MacReceiveOnlyResult::ReadFailed)
        {
            return false;
        }
        Hardware stale;
        if (verifyReceiveOnly(stale, kBarBytes, kOwnerEpoch + 1U) !=
                MacReceiveOnlyResult::OwnershipLost ||
            stale.selfGeneratedReads != 0)
        {
            return false;
        }
        Hardware revokedMidRead;
        revokedMidRead.revokeAfterSelfGeneratedRead = true;
        if (verifyReceiveOnly(revokedMidRead) !=
                MacReceiveOnlyResult::OwnershipLost ||
            revokedMidRead.permitChecks != 2)
        {
            return false;
        }
        Hardware shortBar;
        if (verifyReceiveOnly(shortBar, kSelfGeneratedMaskRegister) !=
                MacReceiveOnlyResult::InvalidBar ||
            shortBar.permitChecks != 0)
        {
            return false;
        }
        const simpleath::RegisterBus missing {};
        return simpleath::verifyAr9565ReceiveOnlyAutoResponsesDisabled(
                   missing, kOwnerEpoch, currentOwner) ==
                   MacReceiveOnlyResult::InvalidBackend &&
               simpleath::verifyAr9565ReceiveOnlyAutoResponsesDisabled(
                   {&clean, read, write, kBarBytes}, 0, currentOwner) ==
                   MacReceiveOnlyResult::InvalidBackend;
    }

    simpleath::MacStopResult stop(Hardware &hardware)
    {
        const simpleath::RegisterBus bus {&hardware, read, write, kBarBytes};
        return simpleath::quiesceAr9565Mac(bus, delay);
    }
} // namespace

int main()
{
    using simpleath::MacStopResult;
    Hardware active;
    if (stop(active) != MacStopResult::Ok || active.delays != 1 ||
        active.writes != kExpectedStopWrites || !active.stopWritten ||
        active.diagnostic != (kInitialDiagnostic | kStopDiagnosticBits))
    {
        return 1;
    }
    for (const uint32_t rtc : {1U, 4U})
    {
        Hardware asleep;
        asleep.rtc = rtc;
        if (stop(asleep) != MacStopResult::Ok || asleep.writes != 1 ||
            asleep.macReads != 0U || asleep.delays != 0U || asleep.stopWritten)
        {
            return 2;
        }
    }
    Hardware stuck;
    stuck.stuck = true;
    if (stop(stuck) != MacStopResult::Timeout ||
        stuck.delays != kStopTimeoutPolls)
    {
        return kStuckFailure;
    }
    Hardware removed;
    removed.revoked = true;
    if (stop(removed) != MacStopResult::ReadFailed || removed.writes != 0U)
    {
        return kRevokedFailure;
    }
    Hardware failure;
    failure.failWrite = true;
    if (stop(failure) != MacStopResult::WriteFailed || failure.macReads != 0U)
    {
        return kWriteFailure;
    }
    Hardware invalid;
    invalid.rtc = kRtcInvalid;
    if (stop(invalid) != MacStopResult::ReadFailed || invalid.writes != 0U)
    {
        return kInvalidRtcFailure;
    }
    invalid.rtc = kRtcUnknown;
    if (stop(invalid) != MacStopResult::UnknownRtcState || invalid.writes != 0U)
    {
        return kUnknownRtcFailure;
    }
    Hardware waking;
    waking.rtc = kRtcWake;
    if (stop(waking) != MacStopResult::Timeout || waking.macReads != 0U ||
        waking.delays != kStopTimeoutPolls)
    {
        return kWakeTimeoutFailure;
    }
    Hardware wakeThenStop;
    wakeThenStop.rtc = kRtcWake;
    wakeThenStop.wakeAfterDelay = true;
    if (stop(wakeThenStop) != MacStopResult::Ok || wakeThenStop.delays != 2 ||
        wakeThenStop.writes != kExpectedStopWrites)
    {
        return kWakeThenStopFailure;
    }
    for (const uint32_t unknown : {0U, 3U})
    {
        Hardware unsupported;
        unsupported.rtc = unknown;
        if (stop(unsupported) != MacStopResult::UnknownRtcState ||
            unsupported.writes != 0U)
        {
            return kUnsupportedRtcFailure;
        }
    }
    const simpleath::RegisterBus missing {};
    if (simpleath::quiesceAr9565Mac(missing, delay) !=
        MacStopResult::InvalidBackend)
    {
        return kMissingBackendFailure;
    }
    return static_cast<int>(!receiveOnlyGuardCases());
}
