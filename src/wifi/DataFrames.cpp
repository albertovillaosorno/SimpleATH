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

#include "DataFrames.hpp"
#include "Frames.hpp"

#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    namespace ieee80211
    {
        static constexpr uint8_t kQosSubtype = 8;
        static constexpr uint8_t kAmsduPresent = 0x80;
        static constexpr uint8_t kSnapSap = 0xaa;
        static constexpr uint8_t kSnapControl = 0x03;
        static constexpr size_t kSnapControlOffset = 2;
        static constexpr uint8_t kBridgeTunnelOuiLast = 0xf8;
        static constexpr uint16_t kEthernetIiMin = 0x0600;
        static constexpr uint16_t kEtherTypeAarp = 0x80f3;
        static constexpr uint16_t kEtherTypeIpx = 0x8137;
        static constexpr uint16_t kEtherTypeEapol = 0x888e;
        static constexpr size_t kBaseHeaderBytes = 24;
        static constexpr size_t kFourthAddressBytes = 6;
        static constexpr size_t kQosControlBytes = 2;
        static constexpr size_t kFcsBytes = 4;
        static constexpr size_t kMaximumMpduBytesIncludingFcs = 2346;
        static constexpr size_t kLlcSnapBytes = 8;
        static constexpr uint32_t kBitsPerByte = 8;
        static constexpr size_t kEthernetHeaderBytes = 14;
        static constexpr size_t kEtherTypeHighOffset = 12;
        static constexpr size_t kEtherTypeLowOffset = 13;
        static constexpr size_t kAmsduSubframeHeaderBytes = 14U;
        static constexpr size_t kAmsduSubframeLengthOffset = 12U;
        static constexpr size_t kAmsduAlignment = 4U;
        static constexpr size_t kQosHeaderBytes =
            kBaseHeaderBytes + kQosControlBytes;
        static constexpr size_t kMaxFcsFreeBytes =
            kMaximumMpduBytesIncludingFcs - kFcsBytes;
        static constexpr uint8_t kQosDataFrameControl = 0x88U;
        static constexpr uint8_t kStationToApFrameControl = 0x01U;
        static constexpr size_t kFirstAddressOffset = 4U;
        static constexpr size_t kSecondAddressOffset = 10U;
        static constexpr size_t kThirdAddressOffset = 16U;
        static constexpr size_t kSequenceControlOffset = 22U;
        static constexpr size_t kSnapOuiLastOffset = 5U;
        static constexpr size_t kSnapEtherTypeHighOffset = 6U;
        static constexpr size_t kSnapEtherTypeLowOffset = 7U;

        static bool overlaps(const void *const firstBuffer, size_t firstBytes,
                             const void *const secondBuffer, size_t secondBytes)
        {
            if (firstBuffer == nullptr || secondBuffer == nullptr ||
                firstBytes == 0 || secondBytes == 0)
            {
                return false;
            }
            uintptr_t first = 0;
            uintptr_t second = 0;
            static_assert(sizeof(uintptr_t) == sizeof(firstBuffer),
                          "host pointer width must match uintptr_t");
            __builtin_memcpy(&first, static_cast<const void *>(&firstBuffer),
                             sizeof(firstBuffer));
            __builtin_memcpy(&second, static_cast<const void *>(&secondBuffer),
                             sizeof(secondBuffer));
            return first <= second ? second - first < firstBytes
                                   : first - second < secondBytes;
        }

        template <typename Byte>
        static Byte *pointerAt(Byte *base, size_t offset)
        {
            static_assert(sizeof(uintptr_t) == sizeof(base),
                          "host pointer must fit a uintptr_t");
            uintptr_t address = 0;
            __builtin_memcpy(static_cast<void *>(&address),
                             static_cast<const void *>(&base), sizeof(base));
            address += offset;
            Byte *result = nullptr;
            __builtin_memcpy(static_cast<void *>(&result),
                             static_cast<const void *>(&address),
                             sizeof(result));
            return result;
        }

        static Result validateSnap(const uint8_t *llc, uint16_t &etherType)
        {
            // The caller verified the complete fixed LLC/SNAP header span;
            // parse its private snapshot without unchecked pointer indices.
            uint8_t bytes[kLlcSnapBytes] {};
            __builtin_memcpy(&bytes[0], llc, sizeof(bytes));
            if (bytes[0] != kSnapSap || bytes[1] != kSnapSap ||
                bytes[kSnapControlOffset] != kSnapControl)
            {
                return Result::UnsupportedFrame;
            }
            const bool standardSnap =
                bytes[3] == 0 && bytes[4] == 0 && bytes[5] == 0;
            const bool bridgeTunnelSnap = bytes[3] == 0 && bytes[4] == 0 &&
                                          bytes[5] == kBridgeTunnelOuiLast;
            if (!standardSnap && !bridgeTunnelSnap)
            {
                return Result::UnsupportedFrame;
            }
            const uint16_t parsedEtherType =
                static_cast<uint16_t>(static_cast<uint16_t>(bytes[6])
                                      << kBitsPerByte) |
                static_cast<uint16_t>(bytes[7]);
            if (parsedEtherType < kEthernetIiMin)
            {
                return Result::InvalidFrame;
            }
            // IEEE 802.1H bridge-tunnel SNAP is reserved for Ethernet-II
            // AARP/IPX; other Ethernet-II types, particularly EAPOL-Key,
            // must use ordinary RFC 1042 SNAP. Never reinterpret a forged
            // bridge OUI as a valid pairwise handshake or IPv4 payload.
            const bool tunneledType = parsedEtherType == kEtherTypeAarp ||
                                      parsedEtherType == kEtherTypeIpx;
            if ((standardSnap && tunneledType) ||
                (bridgeTunnelSnap && !tunneledType))
            {
                return Result::UnsupportedFrame;
            }
            etherType = parsedEtherType;
            return Result::Ok;
        }

        Result decodeLlcData(const uint8_t *const frame, size_t frameBytes,
                             bool containsFcs, bool verifiedDecryptionAndMic,
                             Msdu &out)
        {
            // A malformed output reference can point into the DMA-backed
            // frame. Never clear it and destroy RX evidence before parsing.
            if (overlaps(&out, sizeof(out), frame, frameBytes))
            {
                return Result::OverlappingBuffers;
            }
            // Never leave a borrowed pointer from a previously accepted RX
            // buffer accessible after an ordinary failed parse.
            out = {};
            Frame header {};
            const Result result = parseFrame(frame, frameBytes, header);
            if (result != Result::Ok)
            {
                return result;
            }
            if (header.type != FrameType::Data)
            {
                return Result::UnsupportedFrame;
            }
            // This non-aggregating data path shares the 2346-byte on-air
            // MPDU ceiling used by station TX. A DMA buffer without its FCS
            // may contain at most 2342 bytes. Reject oversized RX before
            // borrowing a payload pointer for native Ethernet delivery.
            if (frameBytes >
                kMaximumMpduBytesIncludingFcs - (containsFcs ? 0U : kFcsBytes))
            {
                return Result::InvalidFrame;
            }
            // Only ordinary and QoS Data MSDUs have a reviewed payload
            // contract. Null-data and contention-free poll/ACK variants are
            // not ordinary Ethernet-II data for this station decoder.
            // A-MSDU and fragmentation need separate, bounded reassembly.
            if ((header.subtype != 0U && header.subtype != kQosSubtype) ||
                header.fragment != 0 || header.moreFragments)
            {
                return Result::UnsupportedFrame;
            }
            if (header.protectedFrame && !verifiedDecryptionAndMic)
            {
                return Result::InvalidSecurity;
            }
            if ((header.subtype & kQosSubtype) != 0)
            {
                // IEEE 802.11 QoS control bit 7 marks an A-MSDU. Subframes need
                // separate length/padding validation before they can be
                // delivered.
                const size_t qosOffset =
                    kBaseHeaderBytes +
                    (header.toDs && header.fromDs ? kFourthAddressBytes : 0U);
                if (frameBytes < qosOffset + kQosControlBytes)
                {
                    return Result::Truncated;
                }
                if ((*pointerAt(frame, qosOffset) & kAmsduPresent) != 0)
                {
                    return Result::UnsupportedFrame;
                }
            }
            if (containsFcs)
            {
                if (frameBytes < header.headerLength + kFcsBytes)
                {
                    return Result::Truncated;
                }
                frameBytes -= kFcsBytes;
            }
            if (frameBytes - header.headerLength < kLlcSnapBytes)
            {
                return Result::Truncated;
            }
            const uint8_t *const llc = pointerAt(frame, header.headerLength);
            uint16_t etherType = 0;
            const Result snapResult = validateSnap(llc, etherType);
            if (snapResult != Result::Ok)
            {
                return snapResult;
            }
            // The protected bit and decrypted payload are NOT evidence that a
            // key is authorized; the platform must prove decrypt+MIC+PN before
            // passing true.
            Msdu data {};
            data.destination = header.destination;
            data.source = header.source;
            data.etherType = etherType;
            data.payload = pointerAt(llc, kLlcSnapBytes);
            data.payloadLength =
                frameBytes - header.headerLength - kLlcSnapBytes;
            data.protectedFrame = header.protectedFrame;
            data.qosFrame = (header.subtype & kQosSubtype) != 0;
            out = data;
            return Result::Ok;
        }

        // Parse exactly one bounded subframe into a private borrowed view.
        // No caller-visible pointer or slot count changes on any failure.
        static Result decodeAmsduSubframe(const uint8_t *subframe,
                                          size_t remaining, bool protectedFrame,
                                          Msdu &out, size_t &consumed)
        {
            if (remaining < kAmsduSubframeHeaderBytes + kLlcSnapBytes)
            {
                return Result::Truncated;
            }
            uint8_t prefix[kAmsduSubframeHeaderBytes] {};
            __builtin_memcpy(&prefix[0], subframe, sizeof(prefix));
            const size_t msduLength =
                (static_cast<size_t>(prefix[kAmsduSubframeLengthOffset])
                 << kBitsPerByte) |
                static_cast<size_t>(prefix[kAmsduSubframeLengthOffset + 1U]);
            if (msduLength < kLlcSnapBytes ||
                msduLength > remaining - kAmsduSubframeHeaderBytes)
            {
                return Result::Truncated;
            }
            Msdu decoded {};
            __builtin_memcpy(&decoded.destination.bytes[0], &prefix[0],
                             kMacAddressBytes);
            __builtin_memcpy(&decoded.source.bytes[0],
                             &prefix[kMacAddressBytes], kMacAddressBytes);
            if (!validStationMac(decoded.source))
            {
                return Result::InvalidAddress;
            }
            uint8_t anyDestination = 0U;
            for (const uint8_t octet : decoded.destination.bytes)
            {
                anyDestination |= octet;
            }
            if (anyDestination == 0U)
            {
                return Result::InvalidAddress;
            }
            const uint8_t *const llc =
                pointerAt(subframe, kAmsduSubframeHeaderBytes);
            const Result snap = validateSnap(llc, decoded.etherType);
            if (snap != Result::Ok)
            {
                return snap;
            }
            // Aggregated EAPOL is never eligible for supplicant/PN handoff.
            if (decoded.etherType == kEtherTypeEapol)
            {
                return Result::InvalidSecurity;
            }
            decoded.payload = pointerAt(llc, kLlcSnapBytes);
            decoded.payloadLength = msduLength - kLlcSnapBytes;
            decoded.protectedFrame = protectedFrame;
            decoded.qosFrame = true;
            out = decoded;
            consumed = kAmsduSubframeHeaderBytes + msduLength;
            return Result::Ok;
        }

        // Fixed 16-entry array: select the next empty slot by a bounded
        // range traversal rather than unchecked caller-controlled indexing.
        static bool appendAmsduSubframe(AmsduPayload &out, const Msdu &next)
        {
            size_t index = 0U;
            for (auto &slot : out.subframes)
            {
                if (index == out.count)
                {
                    slot = next;
                    ++out.count;
                    return true;
                }
                ++index;
            }
            return false;
        }

        Result decodeAmsduData(const uint8_t *frame, size_t frameBytes,
                               bool containsFcs, bool verifiedDecryptionAndMic,
                               AmsduPayload &out)
        {
            if (overlaps(&out, sizeof(out), frame, frameBytes))
            {
                return Result::OverlappingBuffers;
            }
            out = {};
            Frame header {};
            const Result parsed = parseFrame(frame, frameBytes, header);
            if (parsed != Result::Ok)
            {
                return parsed;
            }
            // QoS Data only; the A-MSDU bit lives in QoS Control, before
            // optional HT Control. Do not reinterpret WDS or fragments.
            if (header.type != FrameType::Data ||
                header.subtype != kQosSubtype || header.fragment != 0U ||
                header.moreFragments || header.toDs == header.fromDs)
            {
                return Result::UnsupportedFrame;
            }
            if (header.protectedFrame && !verifiedDecryptionAndMic)
            {
                return Result::InvalidSecurity;
            }
            constexpr size_t kQosOffset = kBaseHeaderBytes;
            if (frameBytes < header.headerLength ||
                header.headerLength < kQosOffset + kQosControlBytes ||
                (*pointerAt(frame, kQosOffset) & kAmsduPresent) == 0U ||
                frameBytes > kMaximumMpduBytesIncludingFcs -
                                 (containsFcs ? 0U : kFcsBytes))
            {
                return Result::InvalidFrame;
            }
            if (containsFcs)
            {
                if (frameBytes < header.headerLength + kFcsBytes)
                {
                    return Result::Truncated;
                }
                frameBytes -= kFcsBytes;
            }
            AmsduPayload accepted {};
            size_t cursor = header.headerLength;
            while (cursor < frameBytes)
            {
                if (accepted.count == kMaximumAmsduSubframes)
                {
                    return Result::Truncated;
                }
                const uint8_t *const subframe = pointerAt(frame, cursor);
                Msdu msdu {};
                size_t consumed = 0U;
                const Result next =
                    decodeAmsduSubframe(subframe, frameBytes - cursor,
                                        header.protectedFrame, msdu, consumed);
                if (next != Result::Ok)
                {
                    return next;
                }
                if (!appendAmsduSubframe(accepted, msdu))
                {
                    return Result::Truncated;
                }
                cursor += consumed;
                if (cursor == frameBytes)
                {
                    break;
                }
                // Only inter-subframe padding is allowed. A trailing pad
                // cannot masquerade as a valid empty subframe.
                const size_t pad =
                    (kAmsduAlignment - (consumed % kAmsduAlignment)) %
                    kAmsduAlignment;
                if (pad > frameBytes - cursor ||
                    frameBytes - cursor - pad <
                        kAmsduSubframeHeaderBytes + kLlcSnapBytes)
                {
                    return Result::Truncated;
                }
                cursor += pad;
            }
            if (accepted.count == 0U)
            {
                return Result::Truncated;
            }
            out = accepted;
            return Result::Ok;
        }

        static const AmsduTxSubframe &
        checkedAmsduSubframe(const OpenStationAmsduTx &request, size_t index)
        {
            if (index >= request.count || index >= kMaximumAmsduSubframes)
            {
                __builtin_trap(); // Input count is bounded by the owner.
            }
            // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            return request.subframes[index];
        }

        static Result
        validateOpenAmsduGeometry(const OpenStationAmsduTx &request,
                                  size_t &needed)
        {
            // Complete payload geometry and security classification are
            // evaluated before writing ANY byte of the caller's output.
            needed = kQosHeaderBytes;
            for (size_t i = 0U; i < request.count; ++i)
            {
                const auto &item = checkedAmsduSubframe(request, i);
                uint8_t anyDestination = 0U;
                for (const uint8_t octet : item.destination.bytes)
                {
                    anyDestination |= octet;
                }
                if (!sameMac(item.source, request.station) ||
                    anyDestination == 0U)
                {
                    return Result::InvalidAddress;
                }
                if (item.payload == nullptr || item.payloadLength == 0U ||
                    item.payloadLength > kMaxFcsFreeBytes - kQosHeaderBytes -
                                             kAmsduSubframeHeaderBytes -
                                             kLlcSnapBytes)
                {
                    return Result::InvalidFrame;
                }
                if (item.etherType < kEthernetIiMin ||
                    item.etherType == kEtherTypeEapol)
                {
                    return Result::InvalidSecurity;
                }
                const size_t subframeBytes = kAmsduSubframeHeaderBytes +
                                             kLlcSnapBytes + item.payloadLength;
                const size_t pad = i + 1U == request.count
                                       ? 0U
                                       : (kAmsduAlignment -
                                          (subframeBytes % kAmsduAlignment)) %
                                             kAmsduAlignment;
                if (subframeBytes + pad > kMaxFcsFreeBytes - needed)
                {
                    return Result::InvalidFrame;
                }
                needed += subframeBytes + pad;
            }
            return Result::Ok;
        }

        static void writeOpenAmsdu(const OpenStationAmsduTx &request,
                                   uint8_t *output)
        {
            // Unprotected 802.11 QoS Data, ToDS=1, A-MSDU Present=1.
            // RA and BSSID are the AP; TA is the station. Each subframe
            // supplies its own Ethernet destination and same-station source.
            __builtin_memset(output, 0, kQosHeaderBytes);
            *pointerAt(output, 0U) = kQosDataFrameControl;
            *pointerAt(output, 1U) = kStationToApFrameControl;
            __builtin_memcpy(pointerAt(output, kFirstAddressOffset),
                             &request.bssid.bytes[0], kMacAddressBytes);
            __builtin_memcpy(pointerAt(output, kSecondAddressOffset),
                             &request.station.bytes[0], kMacAddressBytes);
            __builtin_memcpy(pointerAt(output, kThirdAddressOffset),
                             &request.bssid.bytes[0], kMacAddressBytes);
            const auto sequenceControl =
                static_cast<uint16_t>(request.macSequence << 4U);
            *pointerAt(output, kSequenceControlOffset) =
                static_cast<uint8_t>(sequenceControl);
            *pointerAt(output, kSequenceControlOffset + 1U) =
                static_cast<uint8_t>(sequenceControl >> kBitsPerByte);
            *pointerAt(output, kBaseHeaderBytes) =
                static_cast<uint8_t>(request.tid | kAmsduPresent);
            size_t offset = kQosHeaderBytes;
            for (size_t i = 0U; i < request.count; ++i)
            {
                const auto &item = checkedAmsduSubframe(request, i);
                const size_t msduBytes = kLlcSnapBytes + item.payloadLength;
                const size_t subframeBytes =
                    kAmsduSubframeHeaderBytes + msduBytes;
                uint8_t *const subframe = pointerAt(output, offset);
                __builtin_memcpy(subframe, &item.destination.bytes[0],
                                 kMacAddressBytes);
                __builtin_memcpy(pointerAt(subframe, kMacAddressBytes),
                                 &item.source.bytes[0], kMacAddressBytes);
                *pointerAt(subframe, kAmsduSubframeLengthOffset) =
                    static_cast<uint8_t>(msduBytes >> kBitsPerByte);
                *pointerAt(subframe, kAmsduSubframeLengthOffset + 1U) =
                    static_cast<uint8_t>(msduBytes);
                uint8_t *const llc =
                    pointerAt(subframe, kAmsduSubframeHeaderBytes);
                __builtin_memset(llc, 0, kLlcSnapBytes);
                *pointerAt(llc, 0U) = kSnapSap;
                *pointerAt(llc, 1U) = kSnapSap;
                *pointerAt(llc, kSnapControlOffset) = kSnapControl;
                if (item.etherType == kEtherTypeAarp ||
                    item.etherType == kEtherTypeIpx)
                {
                    *pointerAt(llc, kSnapOuiLastOffset) = kBridgeTunnelOuiLast;
                }
                *pointerAt(llc, kSnapEtherTypeHighOffset) =
                    static_cast<uint8_t>(item.etherType >> kBitsPerByte);
                *pointerAt(llc, kSnapEtherTypeLowOffset) =
                    static_cast<uint8_t>(item.etherType);
                __builtin_memcpy(pointerAt(llc, kLlcSnapBytes), item.payload,
                                 item.payloadLength);
                offset += subframeBytes;
                if (i + 1U != request.count)
                {
                    const size_t pad =
                        (kAmsduAlignment - (subframeBytes % kAmsduAlignment)) %
                        kAmsduAlignment;
                    __builtin_memset(pointerAt(output, offset), 0, pad);
                    offset += pad;
                }
            }
        }

        Result makeOpenStationAmsdu(const OpenStationAmsduTx &request,
                                    uint8_t *output, size_t capacity,
                                    size_t &written)
        {
            if (overlaps(&request, sizeof(request), &written,
                         sizeof(written)) ||
                overlaps(output, capacity, &request, sizeof(request)) ||
                overlaps(output, capacity, &written, sizeof(written)))
            {
                return Result::OverlappingBuffers;
            }
            if (request.count > kMaximumAmsduSubframes)
            {
                written = 0U;
                return Result::InvalidFrame;
            }
            const size_t entriesBytes = request.count * sizeof(AmsduTxSubframe);
            if (overlaps(output, capacity, request.subframes, entriesBytes) ||
                overlaps(&written, sizeof(written), request.subframes,
                         entriesBytes) ||
                overlaps(&request, sizeof(request), request.subframes,
                         entriesBytes))
            {
                return Result::OverlappingBuffers;
            }
            // Validate every borrowed span before clearing the caller count:
            // an alias must not corrupt a later subframe's input bytes.
            if (request.subframes != nullptr)
            {
                for (size_t i = 0U; i < request.count; ++i)
                {
                    const auto &item = checkedAmsduSubframe(request, i);
                    if (overlaps(output, capacity, item.payload,
                                 item.payloadLength) ||
                        overlaps(&written, sizeof(written), item.payload,
                                 item.payloadLength) ||
                        overlaps(&request, sizeof(request), item.payload,
                                 item.payloadLength) ||
                        overlaps(request.subframes, entriesBytes, item.payload,
                                 item.payloadLength))
                    {
                        return Result::OverlappingBuffers;
                    }
                }
            }
            written = 0U;
            if (output == nullptr || request.subframes == nullptr)
            {
                return Result::NullBuffer;
            }
            constexpr uint16_t kMacSequenceMax = 0x0fffU;
            constexpr uint8_t kMaxDataTid = 7U;
            if (request.count < 2U || request.macSequence > kMacSequenceMax ||
                request.tid > kMaxDataTid ||
                !validStationMac(request.station) ||
                !validStationMac(request.bssid) ||
                sameMac(request.station, request.bssid))
            {
                return Result::InvalidFrame;
            }
            size_t needed = 0U;
            const Result validation =
                validateOpenAmsduGeometry(request, needed);
            if (validation != Result::Ok)
            {
                return validation;
            }
            if (capacity < needed)
            {
                return Result::BufferTooSmall;
            }
            writeOpenAmsdu(request, output);
            written = needed;
            return Result::Ok;
        }

        Result encodeReceivedEthernet(const Msdu &msdu, uint8_t *out,
                                      size_t capacity, size_t &written)
        {
            // No caller-controlled output may mutate the validated MSDU,
            // borrowed DMA payload or the output length during serialization.
            if (overlaps(&written, sizeof(written), &msdu, sizeof(msdu)) ||
                overlaps(&written, sizeof(written), out, capacity) ||
                overlaps(&written, sizeof(written), msdu.payload,
                         msdu.payloadLength) ||
                overlaps(out, capacity, &msdu, sizeof(msdu)) ||
                overlaps(out, capacity, msdu.payload, msdu.payloadLength))
            {
                return Result::OverlappingBuffers;
            }
            written = 0;
            if (out == nullptr || msdu.payload == nullptr)
            {
                return Result::NullBuffer;
            }
            if (msdu.etherType < kEthernetIiMin ||
                msdu.payloadLength >
                    kMaximumMpduBytesIncludingFcs - kEthernetHeaderBytes)
            {
                return Result::InvalidFrame;
            }
            const size_t total = kEthernetHeaderBytes + msdu.payloadLength;
            if (capacity < total)
            {
                return Result::BufferTooSmall;
            }
            uint8_t header[kEthernetHeaderBytes] {};
            __builtin_memcpy(&header[0], &msdu.destination.bytes[0],
                             kMacAddressBytes);
            __builtin_memcpy(&header[kMacAddressBytes], &msdu.source.bytes[0],
                             kMacAddressBytes);
            header[kEtherTypeHighOffset] =
                static_cast<uint8_t>(msdu.etherType >> kBitsPerByte);
            header[kEtherTypeLowOffset] = static_cast<uint8_t>(msdu.etherType);
            __builtin_memcpy(out, &header[0], sizeof(header));
            uintptr_t tailAddress = 0;
            __builtin_memcpy(static_cast<void *>(&tailAddress),
                             static_cast<const void *>(&out), sizeof(out));
            tailAddress += sizeof(header);
            uint8_t *tail = nullptr;
            __builtin_memcpy(static_cast<void *>(&tail),
                             static_cast<const void *>(&tailAddress),
                             sizeof(tail));
            __builtin_memcpy(tail, msdu.payload, msdu.payloadLength);
            written = total;
            return Result::Ok;
        }

    } // namespace ieee80211
} // namespace simpleath
