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
//   - Offline regression cases for awdl rx tsf integration.
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
//   - Offline regression cases for awdl rx tsf integration.
// - Description:
//   - Implements or verifies the test_awdl_rx_tsf_integration source boundary.
// - Usage:
//   - Executed by offline host test discovery or the native test harness.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Offline regression cases for awdl rx tsf integration.

// Cross-module host regression: hardware RX TSF, not IRQ callback time,
// establishes MIF phase. Neither component authorizes real AirDrop.
#include "hardware/Ar9565RxTsf.hpp"
#include "wifi/AwdlAction.hpp"
#include "wifi/Frames.hpp"
#include <array>
#include <cstddef>
#include <cstdint>

using namespace simpleath;
using namespace simpleath::ieee80211;

namespace
{
    constexpr uint64_t kEpoch = 19U;
    constexpr uint32_t kUpper = 0x8050U;
    constexpr uint32_t kLower = 0x804cU;

    struct Fake
    {
            uint32_t upper {1U};
            uint32_t lower {10000U};
            uint64_t hostClock {5000000U};
            bool authorized {true};
            size_t reads {};
    };

    bool permit(void *context, uint64_t epoch)
    {
        return static_cast<Fake *>(context)->authorized && epoch == kEpoch;
    }

    bool read(void *context, uint32_t offset, uint32_t *out)
    {
        auto &fake = *static_cast<Fake *>(context);
        ++fake.reads;
        if (out == nullptr || (offset != kUpper && offset != kLower))
        {
            return false;
        }
        *out = offset == kUpper ? fake.upper : fake.lower;
        return true;
    }

    uint64_t clock(void *context)
    {
        auto &fake = *static_cast<Fake *>(context);
        const uint64_t current = fake.hostClock;
        fake.hostClock += 50U;
        return current;
    }
} // namespace

int main()
{
    const Mac peer {{0x02U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U}};
    const Mac station {{0x02U, 0xaaU, 0xbbU, 0xccU, 0xddU, 0xeeU}};
    const AwdlLocalMifTx tx {
        peer, peer, peer, 1U, 4U, 22U, 1U, 50U, 75U, 100U, 1U, 100U, 1U,
    };
    std::array<uint8_t, 256U> frame {};
    size_t written = 0U;
    if (makeAwdlChannelSixMif(tx, frame.data(), frame.size(), written) !=
        Result::Ok)
    {
        return 1;
    }
    Fake fake {};
    const RxTsfBackend io {
        &fake, kEpoch, 0x9000U, permit, read, clock,
    };
    RxTsfSample observed {};
    // The EDMA status3 stamp is 6 ms older than synchronous register read.
    if (captureAr9565RxTsf(io, 4000U, observed) != RxTsfResult::Ok ||
        observed.ageUsec != 6000U || observed.frameMonotonicUsec != 4994025U)
    {
        return 2;
    }
    AwdlNeighbors neighbors {};
    AwdlNeighbor candidate {};
    const uint64_t stampedMs = observed.frameMonotonicUsec / 1000U;
    if (neighbors.observeMifForLocal(stampedMs, station, frame.data(),
                                     written) != Result::Ok ||
        !neighbors.find(peer, 5000U, candidate) ||
        candidate.lastMifMs != 4994U || candidate.lastMifMs == 5000U)
    {
        return 3;
    }
    // Loss of the physical owner cannot fabricate a refreshed MIF anchor.
    fake.authorized = false;
    if (captureAr9565RxTsf(io, 8000U, observed) != RxTsfResult::OwnershipLost ||
        observed.frameMonotonicUsec != 0U ||
        !neighbors.find(peer, 5000U, candidate) || candidate.lastMifMs != 4994U)
    {
        return 4;
    }
    return 0;
}
