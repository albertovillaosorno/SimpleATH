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
//   - Offline regression cases for data frames.
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
//   - Offline regression cases for data frames.
// - Description:
//   - Implements or verifies the test_data_frames source boundary.
// - Usage:
//   - Executed by offline host test discovery or the native test harness.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Offline regression cases for data frames.
// Objective-C++ frontend and portable LLC RX; no Apple framework required.
#include "wifi/DataFrames.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

#if !defined(__OBJC__) || !defined(__cplusplus)
#error This test requires the Objective-C++ frontend.
#endif

namespace
{
    using namespace simpleath::ieee80211;

    constexpr int kDiagnosticModulo = 251;
    constexpr size_t kFrameBytes = 33U;
    constexpr size_t kMpduHeaderBytes = 24U;
    constexpr size_t kLlcBytes = 8U;
    constexpr size_t kDataOffset = kMpduHeaderBytes + kLlcBytes;
    constexpr size_t kTypeHigh = 30U;
    constexpr size_t kTypeLow = 31U;
    constexpr size_t kFromDsOffset = 1U;
    constexpr size_t kFirstAddressOffset = 4U;
    constexpr size_t kSecondAddressOffset = 10U;
    constexpr size_t kThirdAddressOffset = 16U;
    constexpr size_t kFirstAddressLast = 9U;
    constexpr size_t kSecondAddressLast = 15U;
    constexpr size_t kThirdAddressLast = 21U;
    constexpr size_t kLlcDsapOffset = 24U;
    constexpr size_t kLlcSsapOffset = 25U;
    constexpr size_t kLlcControlOffset = 26U;
    constexpr size_t kLlcOuiLast = 29U;
    constexpr uint8_t kDataSubtype = 0x08U;
    constexpr uint8_t kFromDs = 0x02U;
    constexpr uint8_t kProtected = 0x40U;
    constexpr uint8_t kSnapMarker = 0xaaU;
    constexpr uint8_t kLlcUnnumbered = 0x03U;
    constexpr uint8_t kIpv4High = 0x08U;
    constexpr uint8_t kIpv4Low = 0x00U;
    constexpr uint8_t kIpVersion = 0x45U;
    constexpr uint8_t kAarpHigh = 0x80U;
    constexpr uint8_t kAarpLow = 0xf3U;
    constexpr uint8_t kBridgeTunnelOui = 0xf8U;
    constexpr uint8_t kEapolHigh = 0x88U;
    constexpr uint8_t kEapolLow = 0x8eU;
    constexpr uint8_t kIpxHigh = 0x81U;
    constexpr uint8_t kIpxLow = 0x37U;
    constexpr uint16_t kEtherTypeIpv4 = 0x0800U;
    constexpr uint16_t kEtherTypeAarp = 0x80f3U;
    constexpr uint16_t kEtherTypeIpx = 0x8137U;
    constexpr size_t kMaxNoFcs = 2342U;
    constexpr size_t kMaxOnAir = 2346U;
    constexpr size_t kOversized = kMaxOnAir + 1U;
    constexpr size_t kDecodedFullPayload = kMaxNoFcs - kDataOffset;
    constexpr size_t kQosFrameBytes = 39U;
    constexpr size_t kQosHeaderBytes = 26U;
    constexpr size_t kQosLlcBytes = 9U;
    constexpr size_t kQosDataOffset = kQosHeaderBytes + kLlcBytes;
    constexpr size_t kQosPayloadEnd = kQosHeaderBytes + kQosLlcBytes;
    constexpr size_t kQosControlOffset = 24U;
    constexpr uint8_t kQosDataSubtype = 0x88U;
    constexpr uint8_t kQosAmsduPresent = 0x80U;
    constexpr uint8_t kSentinelByte = 0x5aU;
    constexpr uint8_t kFcsFirst = 0xdeU;
    constexpr uint8_t kFcsSecond = 0xadU;
    constexpr uint8_t kFcsThird = 0xbeU;
    constexpr uint8_t kFcsFourth = 0xefU;

    using Frame = std::array<uint8_t, kFrameBytes>;

    bool cleared(const Msdu &payload)
    {
        return payload.payload == nullptr && payload.payloadLength == 0U;
    }

    Frame sampleFrame()
    {
        Frame frame {};
        frame.at(0U) = kDataSubtype;
        frame.at(kFromDsOffset) = kFromDs;
        frame.at(kFirstAddressOffset) = kFromDs;
        frame.at(kSecondAddressOffset) = kFromDs;
        frame.at(kThirdAddressOffset) = kFromDs;
        frame.at(kFirstAddressLast) = 1U;
        frame.at(kSecondAddressLast) = 2U;
        frame.at(kThirdAddressLast) = kLlcUnnumbered;
        frame.at(kLlcDsapOffset) = kSnapMarker;
        frame.at(kLlcSsapOffset) = kSnapMarker;
        frame.at(kLlcControlOffset) = kLlcUnnumbered;
        frame.at(kTypeHigh) = kIpv4High;
        frame.at(kDataOffset) = kIpVersion;
        return frame;
    }

    int snapAndSecurity(Frame &frame)
    {
        Msdu payload {};
        if (decodeLlcData(frame.data(), frame.size(), false, false, payload) !=
                Result::Ok ||
            payload.payload != &frame.at(kDataOffset) ||
            payload.payloadLength != 1U ||
            payload.etherType != kEtherTypeIpv4)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        frame.at(kFromDsOffset) |= kProtected;
        if (decodeLlcData(frame.data(), frame.size(), false, false, payload) !=
                Result::InvalidSecurity ||
            !cleared(payload))
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        frame.at(kFromDsOffset) = kFromDs;
        frame.at(kTypeHigh) = kAarpHigh;
        frame.at(kTypeLow) = kAarpLow;
        if (decodeLlcData(frame.data(), frame.size(), false, false, payload) !=
            Result::UnsupportedFrame)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        // Only AARP and IPX may use the exceptional bridge-tunnel SNAP OUI.
        frame.at(kLlcOuiLast) = kBridgeTunnelOui;
        if (decodeLlcData(frame.data(), frame.size(), false, false, payload) !=
                Result::Ok ||
            payload.etherType != kEtherTypeAarp)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        frame.at(kTypeHigh) = kEapolHigh;
        frame.at(kTypeLow) = kEapolLow;
        if (decodeLlcData(frame.data(), frame.size(), false, false, payload) !=
                Result::UnsupportedFrame ||
            !cleared(payload))
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        frame.at(kTypeHigh) = kIpv4High;
        frame.at(kTypeLow) = kIpv4Low;
        if (decodeLlcData(frame.data(), frame.size(), false, false, payload) !=
                Result::UnsupportedFrame ||
            !cleared(payload))
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        frame.at(kTypeHigh) = kIpxHigh;
        frame.at(kTypeLow) = kIpxLow;
        if (decodeLlcData(frame.data(), frame.size(), false, false, payload) !=
                Result::Ok ||
            payload.etherType != kEtherTypeIpx)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        frame.at(kTypeHigh) = kAarpHigh;
        frame.at(kTypeLow) = kAarpLow;
        if (decodeLlcData(nullptr, 0U, false, false, payload) !=
                Result::NullBuffer ||
            !cleared(payload))
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        return 0;
    }

    int mpduCeiling(const Frame &frame)
    {
        // 2346 on-air bytes include a four-byte FCS. Stripped maximum=2342.
        std::array<uint8_t, kOversized> oversized {};
        for (size_t index = 0U; index < frame.size(); ++index)
        {
            oversized.at(index) = frame.at(index);
        }
        Msdu payload {};
        if (decodeLlcData(oversized.data(), kMaxNoFcs, false, false, payload) !=
                Result::Ok ||
            payload.payloadLength != kDecodedFullPayload ||
            payload.payload != &oversized.at(kDataOffset))
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        if (decodeLlcData(oversized.data(), kMaxOnAir, true, false, payload) !=
                Result::Ok ||
            payload.payloadLength != kDecodedFullPayload ||
            payload.payload != &oversized.at(kDataOffset))
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        if (decodeLlcData(oversized.data(), kMaxNoFcs + 1U, false, false,
                          payload) != Result::InvalidFrame ||
            !cleared(payload))
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        if (decodeLlcData(oversized.data(), oversized.size(), true, false,
                          payload) != Result::InvalidFrame ||
            !cleared(payload))
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        return 0;
    }

    int qosAndFcs(const Frame &frame)
    {
        std::array<uint8_t, kQosFrameBytes> qos {};
        for (size_t index = 0U; index < kMpduHeaderBytes; ++index)
        {
            qos.at(index) = frame.at(index);
        }
        qos.at(0U) = kQosDataSubtype;
        for (size_t index = 0U; index < kQosLlcBytes; ++index)
        {
            qos.at(kQosHeaderBytes + index) =
                frame.at(kMpduHeaderBytes + index);
        }
        qos.at(kQosPayloadEnd) = kFcsFirst;
        qos.at(kQosPayloadEnd + 1U) = kFcsSecond;
        qos.at(kQosPayloadEnd + 2U) = kFcsThird;
        qos.at(kQosPayloadEnd + 3U) = kFcsFourth;
        Msdu payload {};
        if (decodeLlcData(qos.data(), qos.size(), true, false, payload) !=
                Result::Ok ||
            !payload.qosFrame || payload.payload != &qos.at(kQosDataOffset) ||
            payload.payloadLength != 1U)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        qos.at(kQosControlOffset) = kQosAmsduPresent;
        if (decodeLlcData(qos.data(), qos.size(), true, false, payload) !=
                Result::UnsupportedFrame ||
            !cleared(payload))
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        return 0;
    }
    // The builder is intentionally offline: an already negotiated OPEN AP,
    // authorized radio/TID and available DMA mapping are external owners.
    int openAmsduTxRoundtrip()
    {
        const Mac station {{2U, 3U, 4U, 5U, 6U, 7U}};
        const Mac ap {{2U, 0U, 1U, 2U, 3U, 4U}};
        const Mac remote {{0U, 10U, 11U, 12U, 13U, 14U}};
        const uint8_t first[] {0x45U};
        const uint8_t second[] {0xabU, 0xcdU};
        AmsduTxSubframe subframes[2] {};
        subframes[0] = {remote, station, kEtherTypeIpv4, first, sizeof(first)};
        subframes[1] = {ap, station, kEtherTypeAarp, second, sizeof(second)};
        OpenStationAmsduTx request {};
        request.station = station;
        request.bssid = ap;
        request.macSequence = 0xabcU;
        request.tid = 5U;
        request.subframes = subframes;
        request.count = 2U;
        std::array<uint8_t, kMaxNoFcs + 1U> output {};
        output.fill(kSentinelByte);
        size_t written = 99U;
        constexpr size_t kFirstSubframeBytes = 14U + 8U + 1U;
        constexpr size_t kSecondSubframeOffset =
            kQosHeaderBytes + kFirstSubframeBytes + 1U;
        constexpr size_t kExpectedBytes = kSecondSubframeOffset + 14U + 8U + 2U;
        if (makeOpenStationAmsdu(request, output.data(), output.size(),
                                 written) != Result::Ok ||
            written != kExpectedBytes || output.at(0U) != kQosDataSubtype ||
            output.at(1U) != 0x01U || output.at(22U) != 0xc0U ||
            output.at(23U) != 0xabU || output.at(kQosControlOffset) != 0x85U ||
            output.at(kQosHeaderBytes + 12U) != 0U ||
            output.at(kQosHeaderBytes + 13U) != 9U ||
            output.at(kQosHeaderBytes + kFirstSubframeBytes) != 0U ||
            output.at(kSecondSubframeOffset + 12U) != 0U ||
            output.at(kSecondSubframeOffset + 13U) != 10U ||
            output.at(kSecondSubframeOffset + 14U + 5U) != kBridgeTunnelOui ||
            output.at(kExpectedBytes) != kSentinelByte)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        simpleath::ieee80211::Frame header {};
        AmsduPayload accepted {};
        if (parseFrame(output.data(), written, header) != Result::Ok ||
            !header.toDs || header.fromDs || !sameMac(header.source, station) ||
            !sameMac(header.bssid, ap) ||
            decodeAmsduData(output.data(), written, false, false, accepted) !=
                Result::Ok ||
            accepted.count != 2U ||
            !sameMac(accepted.subframes[0].destination, remote) ||
            !sameMac(accepted.subframes[1].source, station) ||
            accepted.subframes[0].etherType != kEtherTypeIpv4 ||
            accepted.subframes[1].etherType != kEtherTypeAarp ||
            accepted.subframes[0].payloadLength != sizeof(first) ||
            accepted.subframes[1].payloadLength != sizeof(second) ||
            accepted.subframes[0].payload[0] != first[0] ||
            accepted.subframes[1].payload[1] != second[1] ||
            !accepted.subframes[0].qosFrame ||
            accepted.subframes[1].protectedFrame)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        // The serializer validates all subframes before exposing a partial
        // buffer: wrong capacity, security or address leaves every byte.
        const auto original = output;
        written = 91U;
        if (makeOpenStationAmsdu(request, output.data(), kExpectedBytes - 1U,
                                 written) != Result::BufferTooSmall ||
            written != 0U || output != original)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        subframes[1].etherType = 0x888eU;
        written = 91U;
        if (makeOpenStationAmsdu(request, output.data(), output.size(),
                                 written) != Result::InvalidSecurity ||
            written != 0U || output != original)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        subframes[1].etherType = kEtherTypeAarp;
        subframes[1].source = remote;
        if (makeOpenStationAmsdu(request, output.data(), output.size(),
                                 written) != Result::InvalidAddress ||
            written != 0U || output != original)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        return 0;
    }

    int openAmsduTxBounds()
    {
        const Mac station {{2U, 3U, 4U, 5U, 6U, 7U}};
        const Mac ap {{2U, 0U, 1U, 2U, 3U, 4U}};
        const Mac remote {{0U, 10U, 11U, 12U, 13U, 14U}};
        const uint8_t first[] {0x45U, 0x00U};
        std::array<uint8_t, 2270U> second {};
        second.fill(0x5aU);
        AmsduTxSubframe subframes[2] {};
        subframes[0] = {remote, station, kEtherTypeIpv4, first, sizeof(first)};
        subframes[1] = {ap, station, kEtherTypeIpv4, second.data(),
                        second.size()};
        OpenStationAmsduTx request {station, ap, 0xfffU, 7U, subframes, 2U};
        std::array<uint8_t, kMaxNoFcs + 1U> output {};
        output.fill(kSentinelByte);
        size_t written = 0U;
        if (makeOpenStationAmsdu(request, output.data(), kMaxNoFcs, written) !=
                Result::Ok ||
            written != kMaxNoFcs || output.at(kMaxNoFcs) != kSentinelByte)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        AmsduPayload accepted {};
        if (decodeAmsduData(output.data(), written, false, false, accepted) !=
                Result::Ok ||
            accepted.count != 2U ||
            accepted.subframes[1].payloadLength != second.size())
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        second.fill(0x5aU);
        subframes[1].payloadLength += 1U;
        output.fill(kSentinelByte);
        written = 97U;
        if (makeOpenStationAmsdu(request, output.data(), output.size(),
                                 written) != Result::InvalidFrame ||
            written != 0U || output.at(0U) != kSentinelByte)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        subframes[1].payloadLength -= 1U;
        request.tid = 8U;
        if (makeOpenStationAmsdu(request, output.data(), output.size(),
                                 written) != Result::InvalidFrame ||
            output.at(0U) != kSentinelByte)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        request.tid = 7U;
        request.macSequence = 0x1000U;
        if (makeOpenStationAmsdu(request, output.data(), output.size(),
                                 written) != Result::InvalidFrame ||
            output.at(0U) != kSentinelByte)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        request.macSequence = 0xfffU;
        request.count = kMaximumAmsduSubframes + 1U;
        if (makeOpenStationAmsdu(request, output.data(), output.size(),
                                 written) != Result::InvalidFrame ||
            output.at(0U) != kSentinelByte)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        request.count = 2U;
        written = 123U;
        subframes[1].payload = output.data();
        subframes[1].payloadLength = 1U;
        if (makeOpenStationAmsdu(request, output.data(), output.size(),
                                 written) != Result::OverlappingBuffers ||
            written != 123U || output.at(0U) != kSentinelByte)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        subframes[1].payload = second.data();
        subframes[1].payloadLength = second.size();
        request.subframes =
            reinterpret_cast<const AmsduTxSubframe *>(output.data());
        if (makeOpenStationAmsdu(request, output.data(), output.size(),
                                 written) != Result::OverlappingBuffers ||
            written != 123U || output.at(0U) != kSentinelByte)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        return 0;
    }
} // namespace

int main()
{
    // @encode exercises Objective-C++ parsing while avoiding runtime linkage.
    const char *encoding = static_cast<const char *>(@encode(uint32_t));
    if (encoding == nullptr || *encoding == '\0')
    {
        return 1;
    }
    auto frame = sampleFrame();
    if (const int result = snapAndSecurity(frame))
    {
        return result;
    }
    if (const int result = mpduCeiling(frame))
    {
        return result;
    }
    if (const int result = qosAndFcs(frame))
    {
        return result;
    }
    if (const int result = openAmsduTxRoundtrip())
    {
        return result;
    }
    return openAmsduTxBounds();
}
