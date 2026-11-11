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
    return 0;
}
