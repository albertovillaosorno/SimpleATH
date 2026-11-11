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
//   - Offline regression cases for station amsdu.
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
//   - Offline regression cases for station amsdu.
// - Description:
//   - Implements or verifies the test_station_amsdu source boundary.
// - Usage:
//   - Executed by offline host test discovery or the native test harness.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Offline regression cases for station amsdu.
// Synthetic QoS A-MSDU RX and SPP-CCMP security, never real radio traffic.
#include "wifi/DataFrames.hpp"
#include "wifi/DataPath.hpp"
#include "wifi/crypto/Ccmp.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace
{
    using namespace simpleath::ieee80211;
    using crypto::CcmpResult;
    using crypto::CcmpSession;
    constexpr uint64_t kEpoch = 9U;
    constexpr std::array<uint8_t, 6> kStation {
        {0x02, 0x10, 0x20, 0x30, 0x40, 0x50}};
    constexpr std::array<uint8_t, 6> kAp {{0x02, 0x60, 0x70, 0x80, 0x90, 0xa0}};
    constexpr std::array<uint8_t, 6> kBridge {
        {0x02, 0x01, 0x02, 0x03, 0x04, 0x05}};
    using Bytes = std::array<uint8_t, 512>;

    void setSubframe(Bytes &bytes, size_t start, bool broadcast,
                     uint8_t payload)
    {
        std::memcpy(&bytes.at(start), kStation.data(), kStation.size());
        if (broadcast)
        {
            std::memset(&bytes.at(start), 0xff, 6U);
        }
        std::memcpy(&bytes.at(start + 6U), kBridge.data(), kBridge.size());
        bytes.at(start + 12U) = 0U;
        bytes.at(start + 13U) = 9U; // 8-byte LLC + 1-byte IPv4 payload.
        bytes.at(start + 14U) = 0xaaU;
        bytes.at(start + 15U) = 0xaaU;
        bytes.at(start + 16U) = 3U;
        bytes.at(start + 20U) = 0x08U;
        bytes.at(start + 21U) = 0U;
        bytes.at(start + 22U) = payload;
    }

    size_t sample(Bytes &frame)
    {
        frame = {};
        frame.at(0U) = 0x88U; // QoS data.
        frame.at(1U) = 0x02U; // From DS.
        std::memcpy(&frame.at(4U), kStation.data(), kStation.size());
        std::memcpy(&frame.at(10U), kAp.data(), kAp.size());
        std::memcpy(&frame.at(16U), kAp.data(), kAp.size());
        frame.at(24U) = 0x80U; // QoS A-MSDU Present.
        setSubframe(frame, 26U, false, 'A');
        frame.at(49U) = 0U; // One pad after 23-byte subframe.
        setSubframe(frame, 50U, true, 'B');
        return 73U;
    }

    LinkContext link(LinkSecurity security)
    {
        LinkContext state {};
        std::memcpy(&state.station.bytes[0], kStation.data(), kStation.size());
        std::memcpy(&state.bssid.bytes[0], kAp.data(), kAp.size());
        state.security = security;
        state.associated = true;
        state.rfReady = true;
        state.channelPermitted = true;
        state.pairwiseAndGroupKeysInstalled =
            security == LinkSecurity::Wpa2Ccmp;
        return state;
    }

    bool empty(const AmsduPayload &value)
    {
        if (value.count != 0U)
        {
            return false;
        }
        for (const auto &frame : value.subframes)
        {
            if (frame.payload != nullptr || frame.payloadLength != 0U)
            {
                return false;
            }
        }
        return true;
    }

    int openAggregation()
    {
        Bytes frame {};
        const size_t bytes = sample(frame);
        auto state = link(LinkSecurity::Open);
        AmsduPayload decoded {};
        if (inspectStationAmsduRx(state, frame.data(), bytes, false, true,
                                  false, decoded) != DataPathResult::Ok ||
            decoded.count != 2U || decoded.subframes[0].payloadLength != 1U ||
            decoded.subframes[0].payload[0] != 'A' ||
            decoded.subframes[1].payload[0] != 'B' ||
            decoded.subframes[1].destination.bytes[0] != 0xffU ||
            !decoded.subframes[0].qosFrame)
        {
            return __LINE__;
        }
        std::array<uint8_t, 64> ethernet {};
        size_t written = 0U;
        if (encodeReceivedEthernet(decoded.subframes[0], ethernet.data(),
                                   ethernet.size(), written) != Result::Ok ||
            written != 15U ||
            std::memcmp(ethernet.data(), kStation.data(), 6U) != 0 ||
            std::memcmp(&ethernet.at(6U), kBridge.data(), 6U) != 0 ||
            ethernet.at(12U) != 0x08U || ethernet.at(14U) != 'A')
        {
            return __LINE__;
        }
        // The physical layer owns FCS verification; the parser only strips
        // the four trailing octets when explicitly told FCS is present.
        if (inspectStationAmsduRx(state, frame.data(), bytes + 4U, true, true,
                                  false, decoded) != DataPathResult::Ok ||
            decoded.count != 2U)
        {
            return __LINE__;
        }
        state.channelPermitted = false;
        if (inspectStationAmsduRx(state, frame.data(), bytes, false, true,
                                  false, decoded) !=
                DataPathResult::CountryNotAuthorized ||
            !empty(decoded))
        {
            return __LINE__;
        }
        state.channelPermitted = true;
        state.associated = false;
        if (inspectStationAmsduRx(state, frame.data(), bytes, false, true,
                                  false,
                                  decoded) != DataPathResult::NotAssociated ||
            !empty(decoded))
        {
            return __LINE__;
        }
        state.associated = true;
        if (inspectStationAmsduRx(state, frame.data(), bytes, false, false,
                                  false,
                                  decoded) != DataPathResult::InvalidRxStatus ||
            !empty(decoded))
        {
            return __LINE__;
        }
        return 0;
    }

    int rejectedAggregates()
    {
        Bytes frame {};
        const size_t bytes = sample(frame);
        const auto state = link(LinkSecurity::Open);
        AmsduPayload decoded {};
        // A late malformed subframe must not expose the first one.
        frame.at(50U + 20U) = 0U; // EtherType drops below 0x0600.
        if (inspectStationAmsduRx(state, frame.data(), bytes, false, true,
                                  false, decoded) !=
                DataPathResult::UnsupportedFrame ||
            !empty(decoded))
        {
            return __LINE__;
        }
        (void)sample(frame);
        frame.at(50U + 6U) = 0x81U; // Multicast source MAC.
        if (decodeAmsduData(frame.data(), bytes, false, false, decoded) !=
                Result::InvalidAddress ||
            !empty(decoded))
        {
            return __LINE__;
        }
        (void)sample(frame);
        frame.at(50U) = 0x02U;
        frame.at(51U) = 0xeeU; // Second subframe unicast for another STA.
        if (inspectStationAmsduRx(state, frame.data(), bytes, false, true,
                                  false, decoded) !=
                DataPathResult::NotForThisStation ||
            !empty(decoded))
        {
            return __LINE__;
        }
        (void)sample(frame);
        frame.at(50U + 20U) = 0x88U;
        frame.at(50U + 21U) = 0x8eU; // Aggregated EAPOL forbidden.
        if (decodeAmsduData(frame.data(), bytes, false, false, decoded) !=
                Result::InvalidSecurity ||
            !empty(decoded))
        {
            return __LINE__;
        }
        (void)sample(frame);
        frame.at(26U + 13U) = 0xffU; // Oversized length in first subframe.
        if (decodeAmsduData(frame.data(), bytes, false, false, decoded) !=
                Result::Truncated ||
            !empty(decoded))
        {
            return __LINE__;
        }
        (void)sample(frame);
        frame.at(24U) = 0U; // Aggregate marker not present.
        if (decodeAmsduData(frame.data(), bytes, false, false, decoded) !=
                Result::InvalidFrame ||
            !empty(decoded))
        {
            return __LINE__;
        }
        (void)sample(frame);
        frame.at(22U) = 1U; // Nonzero 802.11 fragment index.
        if (decodeAmsduData(frame.data(), bytes, false, false, decoded) !=
                Result::UnsupportedFrame ||
            !empty(decoded))
        {
            return __LINE__;
        }
        (void)sample(frame);
        frame.at(1U) |= 0x40U; // Protected without CCMP verification.
        if (decodeAmsduData(frame.data(), bytes, false, false, decoded) !=
                Result::InvalidSecurity ||
            !empty(decoded))
        {
            return __LINE__;
        }
        (void)sample(frame);
        frame.at(10U) = 0x04U; // Other AP BSSID.
        if (inspectStationAmsduRx(state, frame.data(), bytes, false, true,
                                  false, decoded) !=
                DataPathResult::NotFromAssociatedAccessPoint ||
            !empty(decoded))
        {
            return __LINE__;
        }
        return 0;
    }

    int aggregateCountLimit()
    {
        Bytes frame {};
        size_t cursor = sample(frame);
        // Rebuild 17 tiny subframes so a valid on-air MPDU exceeds the
        // intentionally small all-or-nothing fixed view budget.
        frame = {};
        frame.at(0U) = 0x88U;
        frame.at(1U) = 0x02U;
        std::memcpy(&frame.at(4U), kStation.data(), 6U);
        std::memcpy(&frame.at(10U), kAp.data(), 6U);
        std::memcpy(&frame.at(16U), kAp.data(), 6U);
        frame.at(24U) = 0x80U;
        cursor = 26U;
        for (size_t i = 0U; i < kMaximumAmsduSubframes + 1U; ++i)
        {
            setSubframe(frame, cursor, false, 'A');
            cursor += 23U;
            if (i != kMaximumAmsduSubframes)
            {
                frame.at(cursor++) = 0U;
            }
        }
        AmsduPayload decoded {};
        if (decodeAmsduData(frame.data(), cursor, false, false, decoded) !=
                Result::Truncated ||
            !empty(decoded))
        {
            return __LINE__;
        }
        // The complete initial 16-subframe prefix fits. Its last pad
        // belongs to the 17th frame, so the prefix ends just before it.
        const size_t sixteenBytes = cursor - 24U;
        if (decodeAmsduData(frame.data(), sixteenBytes, false, false,
                            decoded) != Result::Ok ||
            decoded.count != kMaximumAmsduSubframes)
        {
            return __LINE__;
        }
        return 0;
    }

    int protectedAggregation()
    {
        Bytes plain {};
        const size_t plainBytes = sample(plain);
        const auto state = link(LinkSecurity::Wpa2Ccmp);
        constexpr uint8_t kKey[16] {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                                    0xcc, 0xdd, 0xee, 0xff};
        CcmpSession legacy {};
        CcmpSession tx {};
        CcmpSession rx {};
        if (legacy.install(kKey, kAp.data(), 0U, kEpoch, 0U, 0U) !=
                CcmpResult::Ok ||
            tx.install(kKey, kAp.data(), 0U, kEpoch, 0U, 0U, true) !=
                CcmpResult::Ok ||
            rx.install(kKey, kAp.data(), 0U, kEpoch, 0U, 0U, true) !=
                CcmpResult::Ok)
        {
            return __LINE__;
        }
        Bytes wire {};
        size_t wireBytes = 0U;
        if (legacy.protect(kEpoch, plain.data(), plainBytes, wire.data(),
                           wire.size(),
                           wireBytes) != CcmpResult::UnsupportedFrame ||
            tx.protect(kEpoch, plain.data(), plainBytes, wire.data(),
                       wire.size(), wireBytes) != CcmpResult::Ok ||
            wireBytes != plainBytes + 16U)
        {
            return __LINE__;
        }
        std::array<uint8_t, 256> scratch {};
        AmsduPayload decoded {};
        if (inspectProtectedStationAmsduRx(state, wire.data(), wireBytes, false,
                                           true, legacy, kEpoch, scratch.data(),
                                           scratch.size(), decoded) !=
                DataPathResult::UnverifiedDecryption ||
            !empty(decoded))
        {
            return __LINE__;
        }
        // A single authenticated MPDU unlocks both subframes and advances
        // the same QoS TID PN exactly once.
        if (inspectProtectedStationAmsduRx(state, wire.data(), wireBytes, false,
                                           true, rx, kEpoch, scratch.data(),
                                           scratch.size(),
                                           decoded) != DataPathResult::Ok ||
            decoded.count != 2U || decoded.subframes[0].payload[0] != 'A' ||
            decoded.subframes[1].payload[0] != 'B' || rx.receiveFloor() != 1U)
        {
            return __LINE__;
        }
        if (inspectProtectedStationAmsduRx(state, wire.data(), wireBytes, false,
                                           true, rx, kEpoch, scratch.data(),
                                           scratch.size(), decoded) !=
                DataPathResult::UnverifiedDecryption ||
            !empty(decoded))
        {
            return __LINE__;
        }
        // Under negotiated SPP the A-MSDU bit participates in the CCMP
        // nonce and AAD. Clearing it must never reinterpret data securely.
        CcmpSession tamperedRx {};
        if (tamperedRx.install(kKey, kAp.data(), 0U, kEpoch, 0U, 0U, true) !=
            CcmpResult::Ok)
        {
            return __LINE__;
        }
        wire.at(24U) ^= 0x80U;
        size_t tamperedBytes = 0U;
        if (tamperedRx.unprotect(kEpoch, wire.data(), wireBytes, scratch.data(),
                                 scratch.size(),
                                 tamperedBytes) != CcmpResult::MicMismatch ||
            tamperedRx.receiveFloor() != 0U)
        {
            return __LINE__;
        }
        return 0;
    }

} // namespace

int main()
{
    if (const int result = openAggregation())
    {
        return result;
    }
    if (const int result = rejectedAggregates())
    {
        return result;
    }
    if (const int result = aggregateCountLimit())
    {
        return result;
    }
    return protectedAggregation();
}
