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
//   - Offline regression cases for station mac.
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
//   - Offline regression cases for station mac.
// - Description:
//   - Implements or verifies the test_station_mac source boundary.
// - Usage:
//   - Executed by offline host test discovery or the native test harness.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Offline regression cases for station mac.

#include "hardware/Ar9565Core.hpp"
#include "hardware/Ar9565MacControl.hpp"
#include <array>
#include <cstdint>

namespace
{
    constexpr uint32_t kStationIdLow = 0x8000U;
    constexpr uint32_t kStationIdHigh = 0x8004U;
    constexpr uint32_t kBssidRegisterLow = 0x8008U;
    constexpr uint32_t kBssidRegisterHigh = 0x800cU;
    constexpr uint32_t kBssidMaskLow = 0x80e0U;
    constexpr uint32_t kBssidMaskHigh = 0x80e4U;
    constexpr uint32_t kBarBytes = 0x9000U;
    constexpr uint64_t kEpoch = 17U;
    constexpr uint32_t kOriginalHigh = 0xa5a50000U;
    constexpr uint32_t kExpectedLow = 0x33221102U;
    constexpr uint32_t kExpectedHigh = 0xa5a55544U;
    constexpr unsigned int kExpectedPermits = 10U;
    constexpr unsigned int kExpectedWrites = 4U;
    constexpr unsigned int kBeforeFilterWrites = 6U;
    constexpr unsigned int kAfterFirstFilterWrite = 7U;
    constexpr uint32_t kExactBssidMaskHigh = 0x0000ffffU;
    constexpr int kFailedWriteCase = 5;
    constexpr int kFailedRevocationCase = 6;
    constexpr int kFailedReadbackCase = 7;
    constexpr int kFailedBackendCase = 8;

    struct FixtureOptions
    {
            uint64_t epoch {kEpoch};
            uint32_t bar {kBarBytes};
    };

    struct Hardware
    {
            uint32_t low {0};
            uint32_t high {kOriginalHigh};
            uint32_t bssidLow {0};
            uint32_t bssidHigh {0xfe000000U};
            uint32_t maskLow {0};
            uint32_t maskHigh {0};
            uint64_t epoch {kEpoch};
            unsigned int reads {0};
            unsigned int writes {0};
            unsigned int permits {0};
            unsigned int revokeOnPermit {0};
            unsigned int failOnWrite {0};
            bool rejectReads {false};
            bool mismatchReadback {false};
            bool mismatchMaskReadback {false};
            bool mismatchBssidReadback {false};
            uint8_t *borrowedBssid {nullptr};
    };

    bool permit(void *context, uint64_t epoch)
    {
        auto &hw = *static_cast<Hardware *>(context);
        ++hw.permits;
        if (hw.revokeOnPermit == hw.permits)
        {
            hw.epoch = 0;
        }
        return epoch == hw.epoch;
    }

    bool read(void *context, uint32_t offset, uint32_t *value)
    {
        auto &hw = *static_cast<Hardware *>(context);
        ++hw.reads;
        if (hw.rejectReads || value == nullptr)
        {
            return false;
        }
        if (offset == kStationIdLow)
        {
            *value = hw.low ^ (hw.mismatchReadback ? 1U : 0U);
            return true;
        }
        if (offset == kStationIdHigh)
        {
            *value = hw.high;
            return true;
        }
        if (offset == kBssidRegisterLow)
        {
            *value = hw.bssidLow;
            return true;
        }
        if (offset == kBssidRegisterHigh)
        {
            *value = hw.bssidHigh ^ (hw.mismatchBssidReadback ? 1U : 0U);
            return true;
        }
        if (offset == kBssidMaskLow)
        {
            *value = hw.maskLow;
            return true;
        }
        if (offset == kBssidMaskHigh)
        {
            *value = hw.maskHigh ^ (hw.mismatchMaskReadback ? 1U : 0U);
            return true;
        }
        return false;
    }

    // Callback ABI fixes the adjacent register/value arguments.
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    bool write(void *context, uint32_t offset, uint32_t value)
    {
        auto &hw = *static_cast<Hardware *>(context);
        ++hw.writes;
        if (hw.failOnWrite == hw.writes)
        {
            return false;
        }
        if (offset == kStationIdLow)
        {
            hw.low = value;
            return true;
        }
        if (offset == kStationIdHigh)
        {
            hw.high = value;
            return true;
        }
        if (offset == kBssidRegisterLow)
        {
            hw.bssidLow = value;
            if (hw.borrowedBssid != nullptr)
            {
                hw.borrowedBssid[4] = 0x01U;
            }
            return true;
        }
        if (offset == kBssidRegisterHigh)
        {
            hw.bssidHigh = value;
            return true;
        }
        if (offset == kBssidMaskLow)
        {
            hw.maskLow = value;
            return true;
        }
        if (offset == kBssidMaskHigh)
        {
            hw.maskHigh = value;
            return true;
        }
        return false;
    }

    unsigned int expectedWritesBeforeRevocation(unsigned int permitIndex)
    {
        if (permitIndex <= 2U)
        {
            return 0;
        }
        if (permitIndex == 3U)
        {
            return 1;
        }
        if (permitIndex <= kBeforeFilterWrites)
        {
            return 2;
        }
        if (permitIndex == kAfterFirstFilterWrite)
        {
            return 3;
        }
        return kExpectedWrites;
    }

    simpleath::MacIdentityProgress program(Hardware &hw, const uint8_t *address,
                                           FixtureOptions options = {})
    {
        const simpleath::RegisterBus bus {&hw, read, write, options.bar};
        return simpleath::programAr9565StationMac(bus, address, options.epoch,
                                                  permit);
    }

    int rejectInvalidInputs(const uint8_t *mac)
    {
        using simpleath::MacIdentityResult;
        Hardware invalid;
        const std::array<uint8_t, 6> zero {};
        const std::array<uint8_t, 6> multicast {0x03U, 1U, 2U, 3U, 4U, 5U};
        if (program(invalid, nullptr).result != MacIdentityResult::InvalidMac ||
            program(invalid, zero.data()).result !=
                MacIdentityResult::InvalidMac ||
            program(invalid, multicast.data()).result !=
                MacIdentityResult::InvalidMac ||
            program(invalid, mac, {0, kBarBytes}).result !=
                MacIdentityResult::InvalidBackend ||
            program(invalid, mac, {kEpoch, kBssidMaskHigh}).result !=
                MacIdentityResult::InvalidBackend ||
            invalid.reads != 0 || invalid.writes != 0 || invalid.permits != 0)
        {
            return 2;
        }
        Hardware denied;
        denied.epoch = 0;
        const auto preflight = program(denied, mac);
        if (preflight.result != MacIdentityResult::OwnershipLost ||
            preflight.requiresReset || denied.reads != 0 || denied.writes != 0)
        {
            return 3;
        }
        Hardware badRead;
        badRead.rejectReads = true;
        if (program(badRead, mac).result != MacIdentityResult::ReadFailed ||
            badRead.writes != 0)
        {
            return 4;
        }
        return 0;
    }

    simpleath::MacIdentityProgress programBssid(Hardware &hw,
                                                const uint8_t *bssid,
                                                uint16_t aid,
                                                FixtureOptions options = {})
    {
        const simpleath::RegisterBus bus {&hw, read, write, options.bar};
        return simpleath::programAr9565AssociationBssid(bus, bssid, aid,
                                                        options.epoch, permit);
    }

    simpleath::MacIdentityProgress clearBssid(Hardware &hw,
                                              FixtureOptions options = {})
    {
        const simpleath::RegisterBus bus {&hw, read, write, options.bar};
        return simpleath::clearAr9565AssociationBssid(bus, options.epoch,
                                                      permit);
    }

    int checkBssidClearing()
    {
        using simpleath::MacIdentityResult;
        Hardware selected;
        selected.bssidLow = 0x13682402U;
        selected.bssidHigh = 0x07d79955U;
        const auto cleared = clearBssid(selected);
        if (cleared.result != MacIdentityResult::Ok || cleared.requiresReset ||
            cleared.completedWrites != 2U || selected.bssidLow != 0 ||
            selected.bssidHigh != 0 || selected.writes != 2U ||
            selected.reads != 2U || selected.permits != 5U)
        {
            return 18;
        }
        Hardware missingBar;
        if (clearBssid(missingBar, {kEpoch, kBssidRegisterHigh}).result !=
                MacIdentityResult::InvalidBackend ||
            clearBssid(missingBar, {0, kBarBytes}).result !=
                MacIdentityResult::InvalidBackend ||
            missingBar.reads != 0 || missingBar.writes != 0 ||
            missingBar.permits != 0)
        {
            return 19;
        }
        Hardware stale;
        stale.epoch = 0;
        const auto rejected = clearBssid(stale);
        if (rejected.result != MacIdentityResult::OwnershipLost ||
            rejected.requiresReset || stale.reads != 0 || stale.writes != 0)
        {
            return 20;
        }
        for (unsigned int index = 1; index <= 2U; ++index)
        {
            Hardware broken;
            broken.bssidLow = 0x13682402U;
            broken.bssidHigh = 0x07d79955U;
            broken.failOnWrite = index;
            const auto attempt = clearBssid(broken);
            if (attempt.result != MacIdentityResult::WriteFailed ||
                !attempt.requiresReset || attempt.completedWrites != index - 1U)
            {
                return 21;
            }
        }
        for (unsigned int index = 1; index <= 5U; ++index)
        {
            Hardware revoked;
            revoked.revokeOnPermit = index;
            const auto attempt = clearBssid(revoked);
            const unsigned int writes =
                index == 1U ? 0U : (index == 2U ? 1U : 2U);
            if (attempt.result != MacIdentityResult::OwnershipLost ||
                attempt.requiresReset != (index != 1U) ||
                attempt.completedWrites != writes)
            {
                return 22;
            }
        }
        Hardware unreadable;
        unreadable.rejectReads = true;
        const auto badRead = clearBssid(unreadable);
        if (badRead.result != MacIdentityResult::ReadFailed ||
            !badRead.requiresReset || badRead.completedWrites != 2U)
        {
            return 23;
        }
        Hardware mismatch;
        mismatch.mismatchBssidReadback = true;
        const auto badValue = clearBssid(mismatch);
        if (badValue.result != MacIdentityResult::ReadbackMismatch ||
            !badValue.requiresReset || badValue.completedWrites != 2U)
        {
            return 24;
        }
        // A successful physical clear can be followed by a new selected AP
        // without retaining the former AID, but only after readback.
        constexpr uint8_t next[6] {2U, 0x55U, 0x66U, 0x77U, 0x88U, 0x99U};
        const auto programmed = programBssid(selected, next, 0);
        if (programmed.result != MacIdentityResult::Ok ||
            selected.bssidLow != 0x77665502U ||
            selected.bssidHigh != 0x00009988U)
        {
            return 25;
        }
        return 0;
    }

    int checkBssidProgramming()
    {
        using simpleath::MacIdentityResult;
        constexpr uint8_t selected[6] {2, 0x24U, 0x68U, 0x13U, 0x55U, 0x99U};
        Hardware start;
        const auto first = programBssid(start, selected, 0);
        if (first.result != MacIdentityResult::Ok || first.requiresReset ||
            first.completedWrites != 2U || start.permits != 5U ||
            start.reads != 2U || start.bssidLow != 0x13682402U ||
            start.bssidHigh != 0x00009955U)
        {
            return 9;
        }
        Hardware linked;
        const auto accepted = programBssid(linked, selected, 2007U);
        if (accepted.result != MacIdentityResult::Ok ||
            linked.bssidHigh != 0x07d79955U)
        {
            return 10;
        }
        constexpr uint8_t empty[6] {};
        constexpr uint8_t multicast[6] {3, 1, 2, 3, 4, 5};
        Hardware invalid;
        if (programBssid(invalid, selected, 2008U).result !=
                MacIdentityResult::InvalidMac ||
            programBssid(invalid, nullptr, 0).result !=
                MacIdentityResult::InvalidMac ||
            programBssid(invalid, empty, 0).result !=
                MacIdentityResult::InvalidMac ||
            programBssid(invalid, multicast, 0).result !=
                MacIdentityResult::InvalidMac ||
            programBssid(invalid, selected, 0, {0, kBarBytes}).result !=
                MacIdentityResult::InvalidBackend ||
            programBssid(invalid, selected, 0, {kEpoch, kBssidRegisterHigh})
                    .result != MacIdentityResult::InvalidBackend ||
            invalid.reads != 0 || invalid.writes != 0 || invalid.permits != 0)
        {
            return 11;
        }
        Hardware denied;
        denied.epoch = 0;
        const auto preflight = programBssid(denied, selected, 0);
        if (preflight.result != MacIdentityResult::OwnershipLost ||
            preflight.requiresReset || denied.writes != 0)
        {
            return 12;
        }
        for (unsigned int index = 1; index <= 2U; ++index)
        {
            Hardware broken;
            broken.failOnWrite = index;
            const auto rejected = programBssid(broken, selected, 0);
            if (rejected.result != MacIdentityResult::WriteFailed ||
                !rejected.requiresReset ||
                rejected.completedWrites != index - 1U)
            {
                return 13;
            }
        }
        for (unsigned int index = 1; index <= 5U; ++index)
        {
            Hardware revoked;
            revoked.revokeOnPermit = index;
            const auto rejected = programBssid(revoked, selected, 0);
            const size_t writes = index == 1U ? 0U : (index == 2U ? 1U : 2U);
            if (rejected.result != MacIdentityResult::OwnershipLost ||
                rejected.requiresReset != (index != 1U) ||
                rejected.completedWrites != writes)
            {
                return 14;
            }
        }
        Hardware unreadable;
        unreadable.rejectReads = true;
        const auto badRead = programBssid(unreadable, selected, 0);
        if (badRead.result != MacIdentityResult::ReadFailed ||
            !badRead.requiresReset || badRead.completedWrites != 2U)
        {
            return 15;
        }
        Hardware mismatched;
        mismatched.mismatchBssidReadback = true;
        const auto badValue = programBssid(mismatched, selected, 0);
        if (badValue.result != MacIdentityResult::ReadbackMismatch ||
            !badValue.requiresReset || badValue.completedWrites != 2U)
        {
            return 16;
        }
        uint8_t mutableBssid[6] {2, 0x24U, 0x68U, 0x13U, 0x55U, 0x99U};
        Hardware changing;
        changing.borrowedBssid = mutableBssid;
        const auto snapshot = programBssid(changing, mutableBssid, 42U);
        if (snapshot.result != MacIdentityResult::Ok || mutableBssid[4] != 1U ||
            changing.bssidHigh != 0x002a9955U)
        {
            return 17;
        }
        return checkBssidClearing();
    }

} // namespace

int main()
{
    using simpleath::MacIdentityResult;
    const std::array<uint8_t, 6> mac {0x02U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U};
    Hardware successful;
    const auto committed = program(successful, mac.data());
    if (committed.result != MacIdentityResult::Ok || committed.requiresReset ||
        committed.completedWrites != kExpectedWrites ||
        successful.low != kExpectedLow || successful.high != kExpectedHigh ||
        successful.maskLow != UINT32_MAX ||
        successful.maskHigh != kExactBssidMaskHigh ||
        successful.permits != kExpectedPermits)
    {
        return 1;
    }
    const int invalidResult = rejectInvalidInputs(mac.data());
    if (invalidResult != 0)
    {
        return invalidResult;
    }
    for (unsigned int failure = 1; failure <= kExpectedWrites; ++failure)
    {
        Hardware badWrite;
        badWrite.failOnWrite = failure;
        const auto attempted = program(badWrite, mac.data());
        if (attempted.result != MacIdentityResult::WriteFailed ||
            !attempted.requiresReset ||
            attempted.completedWrites != failure - 1U)
        {
            return kFailedWriteCase;
        }
    }
    for (unsigned int revoke = 2; revoke <= kExpectedPermits; ++revoke)
    {
        Hardware revoked;
        revoked.revokeOnPermit = revoke;
        const auto attempted = program(revoked, mac.data());
        const unsigned int expectedWrites =
            expectedWritesBeforeRevocation(revoke);
        if (attempted.result != MacIdentityResult::OwnershipLost ||
            attempted.requiresReset != (revoke > 2U) ||
            attempted.completedWrites != expectedWrites)
        {
            return kFailedRevocationCase;
        }
    }
    Hardware mismatch;
    mismatch.mismatchReadback = true;
    const auto readback = program(mismatch, mac.data());
    if (readback.result != MacIdentityResult::ReadbackMismatch ||
        !readback.requiresReset || readback.completedWrites != 2U)
    {
        return kFailedReadbackCase;
    }
    Hardware badMask;
    badMask.mismatchMaskReadback = true;
    const auto rejectedMask = program(badMask, mac.data());
    if (rejectedMask.result != MacIdentityResult::ReadbackMismatch ||
        !rejectedMask.requiresReset ||
        rejectedMask.completedWrites != kExpectedWrites)
    {
        return kFailedReadbackCase;
    }
    const simpleath::RegisterBus missing {};
    if (simpleath::programAr9565StationMac(missing, mac.data(), kEpoch, permit)
            .result != MacIdentityResult::InvalidBackend)
    {
        return kFailedBackendCase;
    }
    return checkBssidProgramming();
}
