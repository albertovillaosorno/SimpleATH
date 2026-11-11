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
//   - Offline protocol and engine regressions for management reassembly.
// - Must-Not:
//   - Contact devices, validate FCS by assertion, or claim RF readiness.
// - Allows:
//   - Inputs: isolated, synthetic 802.11 management fragments.
//   - Outputs: deterministic protocol and engine checks.
//   - Side effects: test-local state only.
// - Split-When:
//   - Independent hardware-backed validation becomes necessary.
// - Merge-When:
//   - The fixed-capacity management parser is directly exercised here.
// - Summary:
//   - Tests ordering, identity, timeout, overflow and actual scan ingress.
// - Description:
//   - Synthetic management fragmentation without native macOS services.
// - Usage:
//   - Executed by tools/validate.py --tests.
// - Defaults:
//   - Missing, stale or unverified input remains rejected.
//
// Module: Offline management reassembly and WifiEngine RX regression.
#include "wifi/ManagementReassembly.hpp"
#include "wifi/WifiEngine.hpp"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace
{
    using namespace simpleath::ieee80211;
    // These numeric values are literal 802.11 wire bytes, not runtime policy.
    // NOLINTBEGIN(*avoid-magic-numbers,readability-magic-numbers)
    constexpr std::array<uint8_t, 6> kAp {{2, 1, 2, 3, 4, 5}};

    std::array<uint8_t, 49> beacon()
    {
        std::array<uint8_t, 49> frame {};
        frame[0] = 0x80;
        frame[4] = 0xff;
        frame[5] = 0xff;
        frame[6] = 0xff;
        frame[7] = 0xff;
        frame[8] = 0xff;
        frame[9] = 0xff;
        std::memcpy(frame.data() + 10, kAp.data(), 6);
        std::memcpy(frame.data() + 16, kAp.data(), 6);
        frame[22] = 0x30;
        frame[23] = 0x12;
        frame[32] = 100;
        frame[34] = 1;
        frame[36] = 0;
        frame[37] = 4;
        frame[38] = 'T';
        frame[39] = 'e';
        frame[40] = 's';
        frame[41] = 't';
        frame[42] = 1;
        frame[43] = 2;
        frame[44] = 0x82;
        frame[45] = 0x84;
        frame[46] = 3;
        frame[47] = 1;
        frame[48] = 6;
        return frame;
    }

    template <size_t N>
    std::vector<uint8_t> fragment(const std::array<uint8_t, N> &source,
                                  size_t start, size_t count, uint8_t index,
                                  bool more)
    {
        std::vector<uint8_t> frame(source.begin(), source.begin() + 24);
        frame.insert(frame.end(), source.begin() + start,
                     source.begin() + start + count);
        frame[1] = more ? 0x04 : 0U;
        frame[22] = static_cast<uint8_t>((source[22] & 0xf0U) | index);
        return frame;
    }

    int protocolContract()
    {
        const auto original = beacon();
        auto first = fragment(original, 24, 8, 0, true);
        auto last = fragment(original, 32, original.size() - 32, 1, false);
        ManagementReassembly receiver;
        ManagementFrameView complete {};
        if (receiver.ingest(first.data(), first.size(), 20, complete) !=
                ManagementFragmentResult::Pending ||
            complete.bytes != nullptr || complete.length != 0)
        {
            return __LINE__;
        }
        last[1] = 0x08; // A retransmitted final fragment can have Retry set.
        if (receiver.ingest(last.data(), last.size(), 21, complete) !=
                ManagementFragmentResult::Complete ||
            complete.length != original.size() ||
            std::memcmp(complete.bytes, original.data(), original.size()) != 0)
        {
            return __LINE__;
        }
        if (receiver.ingest(last.data(), last.size(), 22, complete) !=
                ManagementFragmentResult::Rejected ||
            complete.bytes != nullptr)
        {
            return __LINE__;
        }
        if (receiver.ingest(first.data(), first.size(), 30, complete) !=
            ManagementFragmentResult::Pending)
        {
            return __LINE__;
        }
        last[10] ^= 1U; // A different transmitter must not complete a frame.
        if (receiver.ingest(last.data(), last.size(), 31, complete) !=
                ManagementFragmentResult::Rejected ||
            receiver.ingest(last.data(), last.size(), 32, complete) !=
                ManagementFragmentResult::Rejected)
        {
            return __LINE__;
        }
        last[10] ^= 1U;
        if (receiver.ingest(first.data(), first.size(), 40, complete) !=
                ManagementFragmentResult::Pending ||
            receiver.ingest(last.data(), last.size(), 541, complete) !=
                ManagementFragmentResult::Rejected)
        {
            return __LINE__;
        }
        if (receiver.ingest(first.data(), first.size(), 550, complete) !=
                ManagementFragmentResult::Pending ||
            receiver.ingest(last.data(), last.size(), 549, complete) !=
                ManagementFragmentResult::Rejected)
        {
            return __LINE__;
        }
        first[1] |= 0x40U; // PMF fragments need authenticated owner.
        if (receiver.ingest(first.data(), first.size(), 600, complete) !=
            ManagementFragmentResult::Rejected)
        {
            return __LINE__;
        }
        first[1] &= 0xbfU;
        if (receiver.ingest(first.data(), first.size(), 610, complete) !=
            ManagementFragmentResult::Pending)
        {
            return __LINE__;
        }
        last[22] = 2U; // A missing intermediate fragment cannot be skipped.
        if (receiver.ingest(last.data(), last.size(), 611, complete) !=
            ManagementFragmentResult::Rejected)
        {
            return __LINE__;
        }
        last[22] = 1U;
        if (receiver.ingest(first.data(), first.size(), 620, complete) !=
            ManagementFragmentResult::Pending)
        {
            return __LINE__;
        }
        receiver.clear();
        if (receiver.ingest(last.data(), last.size(), 621, complete) !=
            ManagementFragmentResult::Rejected)
        {
            return __LINE__;
        }
        if (receiver.ingest(original.data(), original.size(), 622, complete) !=
                ManagementFragmentResult::Complete ||
            complete.bytes != original.data())
        {
            return __LINE__;
        }
        // Total reassembly cannot exceed an FCS-free legacy MPDU, even if
        // individual input fragments fit the hardware length limit.
        std::array<uint8_t, kManagementReassembledBytes> huge {};
        std::copy(original.begin(), original.begin() + 24, huge.begin());
        huge[1] = 0x04;
        if (receiver.ingest(huge.data(), huge.size(), 700, complete) !=
                ManagementFragmentResult::Pending ||
            receiver.ingest(last.data(), last.size(), 701, complete) !=
                ManagementFragmentResult::Rejected)
        {
            return __LINE__;
        }
        return 0;
    }

    int engineScanIngress()
    {
        const auto original = beacon();
        auto first = fragment(original, 24, 8, 0, true);
        auto last = fragment(original, 32, original.size() - 32, 1, false);
        WifiEngine receiver;
        EngineAction action {};
        uint8_t output[256] {};
        const InputTrust trust {true, true, true, false};
        if (receiver.startScan(true, true) != EngineResult::Ok ||
            receiver.acceptRx(first.data(), first.size(), trust, {-45, 10},
                              output, sizeof(output),
                              action) != EngineResult::NoAction ||
            receiver.scan().size() != 0U || action.kind != ActionKind::None)
        {
            return __LINE__;
        }
        if (receiver.acceptRx(last.data(), last.size(), trust, {-45, 11},
                              output, sizeof(output),
                              action) != EngineResult::Ok ||
            action.kind != ActionKind::ScanCacheUpdated ||
            receiver.scan().size() != 1U)
        {
            return __LINE__;
        }
        receiver.clear();
        if (receiver.startScan(true, true) != EngineResult::Ok ||
            receiver.acceptRx(first.data(), first.size(), trust, {-45, 20},
                              output, sizeof(output),
                              action) != EngineResult::NoAction)
        {
            return __LINE__;
        }
        receiver.radioStopped(21, false);
        if (receiver.startScan(true, true) != EngineResult::Ok ||
            receiver.acceptRx(last.data(), last.size(), trust, {-45, 22},
                              output, sizeof(output),
                              action) != EngineResult::InvalidReceivedFrame ||
            receiver.scan().size() != 0U)
        {
            return __LINE__;
        }
        return 0;
    }

    // NOLINTEND(*avoid-magic-numbers,readability-magic-numbers)
} // namespace

int main()
{
    const int protocol = protocolContract();
    if (protocol != 0)
    {
        return protocol;
    }
    return engineScanIngress();
}
