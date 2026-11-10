#include "DataFrames.hpp"
#include "Frames.hpp"

#include <cstddef>
#include <cstdint>

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

        static const uint8_t *pointerAt(const uint8_t *base, size_t offset)
        {
            static_assert(sizeof(uintptr_t) == sizeof(base),
                          "host pointer must fit a uintptr_t");
            uintptr_t address = 0;
            __builtin_memcpy(static_cast<void *>(&address),
                             static_cast<const void *>(&base), sizeof(base));
            address += offset;
            const uint8_t *result = nullptr;
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
