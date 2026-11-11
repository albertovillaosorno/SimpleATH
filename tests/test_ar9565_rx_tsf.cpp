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
//   - Offline regression cases for ar9565 rx tsf.
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
//   - Offline regression cases for ar9565 rx tsf.
// - Description:
//   - Implements or verifies the test_ar9565_rx_tsf source boundary.
// - Usage:
//   - Executed by offline host test discovery or the native test harness.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Offline regression cases for ar9565 rx tsf.

#include "hardware/Ar9565RxTsf.hpp"
#include <array>
#include <cstdint>
#include <initializer_list>

using namespace simpleath;

namespace
{
    constexpr uint64_t kEpoch = 19U;
    constexpr uint32_t kUpper = 0x8050U;
    constexpr uint32_t kLower = 0x804cU;
    constexpr uint32_t kBar = 0x9000U;

    struct Fake
    {
            std::array<uint32_t, kBar / 4U> words {};
            uint64_t hostClock {1000000U};
            uint64_t hostStep {60U};
            uint32_t reads {};
            uint32_t permits {};
            uint32_t failRead {UINT32_MAX};
            uint32_t revokeAfter {};
            uint32_t rolloverAtRead {};
            bool live {true};
    };

    bool permit(void *context, uint64_t epoch)
    {
        auto &fake = *static_cast<Fake *>(context);
        ++fake.permits;
        return fake.live && epoch == kEpoch &&
               (fake.revokeAfter == 0U || fake.reads < fake.revokeAfter);
    }

    bool read(void *context, uint32_t address, uint32_t *value)
    {
        auto &fake = *static_cast<Fake *>(context);
        ++fake.reads;
        if (address == fake.failRead || address >= kBar || value == nullptr)
        {
            return false;
        }
        if (fake.rolloverAtRead != 0U && fake.reads == fake.rolloverAtRead)
        {
            fake.words.at(kUpper / 4U) += 1U;
            fake.words.at(kLower / 4U) = 0x00000010U;
        }
        *value = fake.words.at(address / 4U);
        return true;
    }

    uint64_t micros(void *context)
    {
        auto &fake = *static_cast<Fake *>(context);
        const uint64_t previous = fake.hostClock;
        fake.hostClock += fake.hostStep;
        return previous;
    }

    RxTsfBackend backend(Fake &fake)
    {
        return {&fake, kEpoch, kBar, permit, read, micros};
    }

    int checkValid()
    {
        Fake fake {};
        fake.words.at(kUpper / 4U) = 2U;
        fake.words.at(kLower / 4U) = 10000U;
        RxTsfSample out {};
        if (captureAr9565RxTsf(backend(fake), 7000U, out) != RxTsfResult::Ok ||
            out.ownerEpoch != kEpoch || out.ageUsec != 3000U ||
            out.hardwareCaptureTsfUsec != ((uint64_t {2} << 32U) | 10000U) ||
            out.hardwareRxTsfUsec != ((uint64_t {2} << 32U) | 7000U) ||
            out.captureMonotonicUsec != 1000030U ||
            out.frameMonotonicUsec != 997030U || fake.reads != 3U)
        {
            return 1;
        }
        fake.words.at(kUpper / 4U) = 3U;
        fake.words.at(kLower / 4U) = 100U;
        fake.hostClock = 1000000U;
        fake.reads = 0U;
        if (captureAr9565RxTsf(backend(fake), UINT32_MAX - 899U, out) !=
                RxTsfResult::Ok ||
            out.ageUsec != 1000U || fake.reads != 3U)
        {
            return 2;
        }
        return 0;
    }

    int checkRollover()
    {
        Fake fake {};
        fake.words.at(kUpper / 4U) = 5U;
        fake.words.at(kLower / 4U) = 0xfffffff0U;
        fake.rolloverAtRead = 2U;
        RxTsfSample out {};
        if (captureAr9565RxTsf(backend(fake), UINT32_MAX - 49U, out) !=
                RxTsfResult::Ok ||
            out.ageUsec != 66U || fake.reads != 5U)
        {
            return 3;
        }
        fake.rolloverAtRead = 0U;
        fake.reads = 0U;
        fake.words.at(kUpper / 4U) = 1U;
        fake.words.at(kLower / 4U) = 0U;
        if (captureAr9565RxTsf(backend(fake), UINT32_MAX, out) !=
                RxTsfResult::Ok ||
            out.ageUsec != 1U)
        {
            return 4;
        }
        return 0;
    }

    int checkFailures()
    {
        Fake fake {};
        fake.words.at(kUpper / 4U) = 1U;
        fake.words.at(kLower / 4U) = 100000U;
        RxTsfSample out {};
        auto io = backend(fake);
        io.barLengthBytes = kUpper;
        if (captureAr9565RxTsf(io, 90000U, out) != RxTsfResult::InvalidBar ||
            fake.reads != 0U)
        {
            return 5;
        }
        io = backend(fake);
        io.permitRead = nullptr;
        if (captureAr9565RxTsf(io, 90000U, out) != RxTsfResult::InvalidBackend)
        {
            return 6;
        }
        fake.revokeAfter = 2U;
        if (captureAr9565RxTsf(backend(fake), 90000U, out) !=
                RxTsfResult::OwnershipLost ||
            out.ownerEpoch != 0U)
        {
            return 7;
        }
        fake.revokeAfter = 0U;
        fake.reads = 0U;
        fake.failRead = kLower;
        if (captureAr9565RxTsf(backend(fake), 90000U, out) !=
            RxTsfResult::ReadFailed)
        {
            return 8;
        }
        fake.failRead = UINT32_MAX;
        fake.reads = 0U;
        fake.hostStep = 3000U;
        if (captureAr9565RxTsf(backend(fake), 90000U, out) !=
            RxTsfResult::InvalidClock)
        {
            return 9;
        }
        fake.hostStep = 60U;
        fake.reads = 0U;
        if (captureAr9565RxTsf(backend(fake), 100001U, out) !=
                RxTsfResult::StaleFrame ||
            out.frameMonotonicUsec != 0U)
        {
            return 10;
        }
        fake.reads = 0U;
        fake.words.at(kLower / 4U) = 300000U;
        if (captureAr9565RxTsf(backend(fake), 1U, out) !=
            RxTsfResult::StaleFrame)
        {
            return 11;
        }
        return 0;
    }
} // namespace

int main()
{
    for (const int result : {checkValid(), checkRollover(), checkFailures()})
    {
        if (result != 0)
        {
            return result;
        }
    }
    return 0;
}
