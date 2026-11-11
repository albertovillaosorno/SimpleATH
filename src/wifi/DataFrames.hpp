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
//   - Native driver contracts and implementation for data frames.
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
//   - Native driver contracts and implementation for data frames.
// - Description:
//   - Implements or verifies the DataFrames source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for data frames.

// Safe extraction of RFC 1042 LLC/SNAP payload from 802.11 data frames.
// This decoder does not perform encryption, decryption, or packet delivery.
#ifndef SIMPLEATH_WIFI_DATA_FRAMES_HPP
#define SIMPLEATH_WIFI_DATA_FRAMES_HPP

#include "Frames.hpp"

namespace simpleath
{
    namespace ieee80211
    {

        struct Msdu
        {
                Mac destination;
                Mac source;
                uint16_t etherType;
                const uint8_t *payload;
                size_t payloadLength;
                bool protectedFrame;
                bool qosFrame;
        };

        // A protected frame may be parsed only when the platform backend has
        // already verified decryption, replay/PN and MIC integrity, with no
        // hardware key miss. Crypto headers/trailers must already have been
        // removed, leaving plaintext LLC immediately after the 802.11 header.
        // AARP/IPX require bridge-tunnel SNAP OUI 00:00:f8; all other
        // Ethernet-II types, including EAPOL, require RFC 1042 OUI 00:00:00.
        // Input remains owned by the caller. A-MSDU aggregation, CF variants
        // and fragmented MSDUs are deliberately rejected. On ordinary error
        // the output is zeroed, including its borrowed payload pointer. An
        // output overlapping the frame returns OverlappingBuffers untouched.
        Result decodeLlcData(const uint8_t *frame, size_t frameBytes,
                             bool containsFcs, bool verifiedDecryptionAndMic,
                             Msdu &out);

        // Complete bounded QoS A-MSDU deaggregation into borrowed Ethernet
        // MSDUs. All subframes must be valid before ANY pointer is published.
        // The caller must independently establish FCS, association, CCMP
        // MIC/PN and destination authority. EAPOL cannot be aggregated here.
        // Output must not alias the source. Native callers must copy payloads
        // while retaining this immutable RX buffer.
        // 16 fixed views bound total nested RX kernel stack usage. Frames
        // with additional subframes fail atomically instead of allocating.
        constexpr size_t kMaximumAmsduSubframes = 16U;

        struct AmsduPayload
        {
                Msdu subframes[kMaximumAmsduSubframes] {};
                size_t count {};
        };

        Result decodeAmsduData(const uint8_t *frame, size_t frameBytes,
                               bool containsFcs, bool verifiedDecryptionAndMic,
                               AmsduPayload &out);

        // Ethernet-II packet handoff into a native OS-owned receive pool.
        // Caller must first prove DMA/FCS, station association, destination,
        // duplicate suppression and, for protected frames, CCMP MIC/replay.
        // This routine only copies an already accepted borrowed MSDU; it
        // neither authorizes its security state nor retains its payload.
        // On ordinary errors written is cleared; aliases are rejected before
        // any output mutation. Never call with a DMA lifetime that expired.
        Result encodeReceivedEthernet(const Msdu &msdu, uint8_t *out,
                                      size_t capacity, size_t &written);

    } // namespace ieee80211
} // namespace simpleath
#endif
