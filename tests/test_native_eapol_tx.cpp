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
//   - Offline regression cases for native EAPOL transmit policy.
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
//   - Offline regression cases for native EAPOL transmit policy.
// - Description:
//   - Implements or verifies the test_native_eapol_tx source boundary.
// - Usage:
//   - Executed by offline host test discovery or the native test harness.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Offline regression cases for native EAPOL transmit policy.

// Strict host-only EAPOL classification; no native radio, OS or MIC calls.
#include "wifi/Eapol.hpp"
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace
{
    using simpleath::ieee80211::classifyStationEapolTx;
    using simpleath::ieee80211::StationEapolTxMode;
    constexpr size_t kEapolBytes = 99U;
    constexpr uint8_t kMicSample = 0x5aU;

    void makeKey(uint8_t (&wire)[kEapolBytes], uint16_t flags)
    {
        std::memset(wire, 0, sizeof(wire));
        wire[0] = 2U; // EAPOL v2, EAPOL-Key, 95-byte fixed body.
        wire[1] = 3U;
        wire[3] = 95U;
        wire[4] = 2U; // RSN descriptor.
        wire[5] = static_cast<uint8_t>(flags >> 8U);
        wire[6] = static_cast<uint8_t>(flags);
        wire[16] = 3U; // Replay counter (last byte).
        wire[17] = 7U; // Nonzero SNonce for M2.
        wire[81] = kMicSample;
    }

    bool transmitModes()
    {
        uint8_t wire[kEapolBytes] {};
        makeKey(wire, 0x010aU);
        if (classifyStationEapolTx(wire, sizeof(wire)) !=
            StationEapolTxMode::ClearPairwise2)
        {
            return false;
        }
        makeKey(wire, 0x030aU);
        if (classifyStationEapolTx(wire, sizeof(wire)) !=
            StationEapolTxMode::ClearPairwise4)
        {
            return false;
        }
        makeKey(wire, 0x0302U);
        return classifyStationEapolTx(wire, sizeof(wire)) ==
               StationEapolTxMode::ProtectedGroup2;
    }

    bool rejectsUntrustedKeyModes()
    {
        uint8_t wire[kEapolBytes] {};
        uint8_t padded[kEapolBytes + 1U] {};
        makeKey(wire, 0x0302U);
        std::memcpy(padded, wire, sizeof(wire));
        if (classifyStationEapolTx(padded, sizeof(padded)) !=
                StationEapolTxMode::Reject ||
            classifyStationEapolTx(wire, kEapolBytes) !=
                StationEapolTxMode::ProtectedGroup2)
        {
            return false;
        }
        wire[8] = 16U; // Group2 is a zero-length group-key response.
        if (classifyStationEapolTx(wire, kEapolBytes) !=
            StationEapolTxMode::Reject)
        {
            return false;
        }
        makeKey(wire, 0x010aU);
        wire[17] = 0U; // M2 must carry an SNonce.
        if (classifyStationEapolTx(wire, kEapolBytes) !=
            StationEapolTxMode::Reject)
        {
            return false;
        }
        makeKey(wire, 0x038aU);
        if (classifyStationEapolTx(wire, kEapolBytes) !=
            StationEapolTxMode::Reject)
        {
            return false;
        }
        makeKey(wire, 0x0302U);
        wire[3] = 94U; // Header/body mismatch.
        if (classifyStationEapolTx(wire, kEapolBytes) !=
            StationEapolTxMode::Reject)
        {
            return false;
        }
        return classifyStationEapolTx(nullptr, kEapolBytes) ==
                   StationEapolTxMode::Reject &&
               classifyStationEapolTx(wire, 0U) == StationEapolTxMode::Reject;
    }
} // namespace

int main()
{
    return !transmitModes() ? 1 : !rejectsUntrustedKeyModes() ? 2 : 0;
}
