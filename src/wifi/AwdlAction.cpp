// SPDX-License-Identifier: AGPL-3.0-only
// AWDL action-frame syntax described independently by Stute et al. (2018).
// No third-party implementation code is incorporated here.
#include "AwdlAction.hpp"
#include "Frames.hpp"
#include "bluetooth/UsbBytes.hpp"
#include <cstddef>
#include <cstdint>

namespace simpleath
{
    namespace ieee80211
    {
        namespace
        {
            constexpr uint32_t kBitsPerByte = 8U;
            constexpr size_t kTlvHeaderBytes = 3U;
            constexpr size_t kActionBodyBytes = 16U;
            constexpr size_t kVendorPrefixBytes = 6U;
            constexpr size_t kAwdlSubtypeOffset = 6U;
            constexpr size_t kReservedOffset = 7U;
            constexpr size_t kPhyTimeOffset = 8U;
            constexpr size_t kTargetTimeOffset = 12U;
            constexpr size_t kAwdlPaddingBytes = 2U;
            constexpr uint8_t kManagementActionSubtype = 13U;
            constexpr uint8_t kMasterIndicationSubtype = 3U;
            constexpr uint8_t kAwdlBssid[kMacAddressBytes] {
                0x00U, 0x25U, 0x00U, 0xffU, 0x94U, 0x73U,
            };
            constexpr uint8_t kVendorPrefix[kVendorPrefixBytes] {
                127U, 0x00U, 0x17U, 0xf2U, 0x08U, 0x10U,
            };
            constexpr size_t kAwdlDataHeaderBytes = 16U;
            constexpr size_t kAwdlDataSequenceOffset = 10U;
            constexpr size_t kAwdlDataReservedOffset = 12U;
            constexpr size_t kAwdlDataTypeOffset = 14U;
            constexpr size_t kIpv6HeaderBytes = 40U;
            constexpr size_t kIpv6PayloadBytesOffset = 4U;
            constexpr uint8_t kIpv6Version = 6U;
            constexpr uint8_t kAwdlQosDataSubtype = 8U;
            constexpr size_t kDataMacHeaderBytes = 24U;
            constexpr size_t kQosControlBytes = 2U;
            constexpr size_t kFcsBytes = 4U;
            constexpr size_t kMaxMpduWithFcs = 2346U;
            constexpr uint16_t kMacSequenceMax = 0x0fffU;
            constexpr uint8_t kMacSequenceShift = 4U;
            constexpr uint8_t kDataFrameControl = 0x08U;
            constexpr uint8_t kActionFrameControl = 0xd0U;
            constexpr size_t kTimestampBytes = 4U;
            constexpr uint8_t kQosDataFrameControl = 0x88U;
            constexpr size_t kDestinationOffset = 4U;
            constexpr size_t kSourceOffset = 10U;
            constexpr size_t kBssidOffset = 16U;
            constexpr size_t kMacSequenceOffset = 22U;
            constexpr uint8_t kAwdlDataLlc[kAwdlDataSequenceOffset] {
                0xaaU, 0xaaU, 0x03U, 0x00U, 0x17U,
                0xf2U, 0x08U, 0x00U, 0x03U, 0x04U,
            };
            constexpr uint8_t kIpv6EtherType[2] {0x86U, 0xddU};

            uint16_t readLittle16(const uint8_t *bytes)
            {
                uint8_t copy[2] {};
                __builtin_memcpy(&copy, bytes, sizeof(copy));
                return static_cast<uint16_t>(copy[0]) |
                       static_cast<uint16_t>(static_cast<uint16_t>(copy[1])
                                             << kBitsPerByte);
            }

            uint32_t readLittle32(const uint8_t *bytes)
            {
                uint8_t copy[4] {};
                __builtin_memcpy(&copy, bytes, sizeof(copy));
                return static_cast<uint32_t>(copy[0]) |
                       (static_cast<uint32_t>(copy[1]) << kBitsPerByte) |
                       (static_cast<uint32_t>(copy[2]) << (kBitsPerByte * 2U)) |
                       (static_cast<uint32_t>(copy[3]) << (kBitsPerByte * 3U));
            }

            bool overlaps(const void *first, size_t firstBytes,
                          const void *second, size_t secondBytes)
            {
                if (first == nullptr || second == nullptr || firstBytes == 0U ||
                    secondBytes == 0U)
                {
                    return false;
                }
                uintptr_t a = 0;
                uintptr_t b = 0;
                static_assert(sizeof(a) == sizeof(first), "pointer width");
                __builtin_memcpy(&a, static_cast<const void *>(&first),
                                 sizeof(a));
                __builtin_memcpy(&b, static_cast<const void *>(&second),
                                 sizeof(b));
                return a <= b ? b - a < firstBytes : a - b < secondBytes;
            }
        } // namespace

        AwdlTlvs::AwdlTlvs(const uint8_t *bytes, size_t length)
            : bytes_(bytes), length_(length)
        {
        }

        AwdlTlvStatus AwdlTlvs::next(AwdlTlv &out)
        {
            if (overlaps(&out, sizeof(out), this, sizeof(*this)) ||
                overlaps(&out, sizeof(out), bytes_, length_))
            {
                return AwdlTlvStatus::Truncated;
            }
            out = {};
            if (offset_ == length_)
            {
                return AwdlTlvStatus::End;
            }
            if (bytes_ == nullptr || length_ - offset_ < kTlvHeaderBytes)
            {
                // The AWDL on-air format permits one or two trailing zero
                // padding octets after its complete 16-bit-length TLVs.
                const size_t remaining = length_ - offset_;
                if (bytes_ == nullptr || remaining > kAwdlPaddingBytes)
                {
                    return AwdlTlvStatus::Truncated;
                }
                for (size_t index = offset_; index < length_; ++index)
                {
                    if (*usbByteOffset(bytes_, index) != 0U)
                    {
                        return AwdlTlvStatus::Truncated;
                    }
                }
                offset_ = length_;
                return AwdlTlvStatus::End;
            }
            // The source span has at least three bytes. Use bounded access
            // and subtraction before reading either length or payload.
            const uint16_t valueLength =
                readLittle16(usbByteOffset(bytes_, offset_ + 1U));
            if (valueLength > length_ - offset_ - kTlvHeaderBytes)
            {
                return AwdlTlvStatus::Truncated;
            }
            out = {
                *usbByteOffset(bytes_, offset_),
                valueLength,
                usbByteOffset(bytes_, offset_ + kTlvHeaderBytes),
            };
            offset_ += static_cast<size_t>(valueLength) + kTlvHeaderBytes;
            return AwdlTlvStatus::Element;
        }

        Result makeAwdlAction(const AwdlActionTx &request, uint8_t *output,
                              size_t capacity, size_t &written)
        {
            if (overlaps(output, capacity, &request, sizeof(request)) ||
                overlaps(output, capacity, &written, sizeof(written)) ||
                overlaps(output, capacity, request.tlvs, request.tlvBytes) ||
                overlaps(&written, sizeof(written), &request,
                         sizeof(request)) ||
                overlaps(&written, sizeof(written), request.tlvs,
                         request.tlvBytes))
            {
                return Result::OverlappingBuffers;
            }
            written = 0U;
            if (output == nullptr || request.tlvs == nullptr)
            {
                return Result::NullBuffer;
            }
            if (!validStationMac(request.source))
            {
                return Result::InvalidAddress;
            }
            uint8_t destinationAggregate = 0U;
            for (const uint8_t octet : request.destination.bytes)
            {
                destinationAggregate |= octet;
            }
            if (destinationAggregate == 0U)
            {
                return Result::InvalidAddress;
            }
            if (request.macSequence > kMacSequenceMax ||
                (request.subtype != 0U &&
                 request.subtype != kMasterIndicationSubtype))
            {
                return Result::UnsupportedFrame;
            }
            constexpr size_t kHeaderBytes =
                kDataMacHeaderBytes + kActionBodyBytes;
            if (request.tlvBytes > kMaxMpduWithFcs - kFcsBytes - kHeaderBytes)
            {
                return Result::InvalidFrame;
            }
            AwdlTlvs tlvs(request.tlvs, request.tlvBytes);
            AwdlTlv value {};
            size_t count = 0U;
            for (;;)
            {
                const AwdlTlvStatus status = tlvs.next(value);
                if (status == AwdlTlvStatus::End)
                {
                    break;
                }
                if (status == AwdlTlvStatus::Truncated)
                {
                    return Result::InvalidElement;
                }
                ++count;
            }
            if (count == 0U)
            {
                return Result::InvalidElement;
            }
            const size_t needed = kHeaderBytes + request.tlvBytes;
            if (capacity < needed)
            {
                return Result::BufferTooSmall;
            }
            __builtin_memset(output, 0, kHeaderBytes);
            *usbByteOffset(output, 0U) = kActionFrameControl;
            __builtin_memcpy(usbByteOffset(output, kDestinationOffset),
                             &request.destination.bytes, kMacAddressBytes);
            __builtin_memcpy(usbByteOffset(output, kSourceOffset),
                             &request.source.bytes, kMacAddressBytes);
            __builtin_memcpy(usbByteOffset(output, kBssidOffset), &kAwdlBssid,
                             kMacAddressBytes);
            const auto sequenceControl =
                static_cast<uint16_t>(request.macSequence << kMacSequenceShift);
            *usbByteOffset(output, kMacSequenceOffset) =
                static_cast<uint8_t>(sequenceControl);
            *usbByteOffset(output, kMacSequenceOffset + 1U) =
                static_cast<uint8_t>(sequenceControl >> kBitsPerByte);
            uint8_t *const body = usbByteOffset(output, kDataMacHeaderBytes);
            __builtin_memcpy(body, &kVendorPrefix, sizeof(kVendorPrefix));
            *usbByteOffset(body, kAwdlSubtypeOffset) = request.subtype;
            for (size_t octet = 0U; octet < kTimestampBytes; ++octet)
            {
                const auto shift = static_cast<uint32_t>(octet * kBitsPerByte);
                *usbByteOffset(body, kPhyTimeOffset + octet) =
                    static_cast<uint8_t>(request.phyTransmitUsec >> shift);
                *usbByteOffset(body, kTargetTimeOffset + octet) =
                    static_cast<uint8_t>(request.targetTransmitUsec >> shift);
            }
            __builtin_memcpy(usbByteOffset(output, kHeaderBytes), request.tlvs,
                             request.tlvBytes);
            written = needed;
            return Result::Ok;
        }

        Result makeAwdlIpv6Data(const AwdlIpv6Tx &request, uint8_t *output,
                                size_t capacity, size_t &written)
        {
            // Do not alter a borrowed packet, caller identity, or the result
            // count through a caller-constructed alias on any failure path.
            if (overlaps(output, capacity, &request, sizeof(request)) ||
                overlaps(output, capacity, &written, sizeof(written)) ||
                overlaps(output, capacity, request.ipv6, request.ipv6Bytes) ||
                overlaps(&written, sizeof(written), &request,
                         sizeof(request)) ||
                overlaps(&written, sizeof(written), request.ipv6,
                         request.ipv6Bytes))
            {
                return Result::OverlappingBuffers;
            }
            written = 0U;
            if (output == nullptr || request.ipv6 == nullptr)
            {
                return Result::NullBuffer;
            }
            if (!validStationMac(request.source))
            {
                return Result::InvalidAddress;
            }
            uint8_t destinationAggregate = 0U;
            for (const uint8_t octet : request.destination.bytes)
            {
                destinationAggregate |= octet;
            }
            if (destinationAggregate == 0U)
            {
                return Result::InvalidAddress;
            }
            if (request.macSequence > kMacSequenceMax)
            {
                return Result::InvalidFrame;
            }
            if (request.ipv6Bytes < kIpv6HeaderBytes)
            {
                return Result::Truncated;
            }
            // The maximum transmitted 802.11 MPDU includes four FCS bytes,
            // so size-check before interpreting any caller-provided IPv6.
            const size_t headerBytes =
                kDataMacHeaderBytes + (request.qos ? kQosControlBytes : 0U);
            const size_t framingBytes = headerBytes + kAwdlDataHeaderBytes;
            if (request.ipv6Bytes > kMaxMpduWithFcs - kFcsBytes - framingBytes)
            {
                return Result::InvalidFrame;
            }
            if ((*request.ipv6 >> 4U) != kIpv6Version)
            {
                return Result::InvalidFrame;
            }
            const size_t declaredBytes =
                kIpv6HeaderBytes +
                (static_cast<size_t>(
                     *usbByteOffset(request.ipv6, kIpv6PayloadBytesOffset))
                 << kBitsPerByte) +
                static_cast<size_t>(
                    *usbByteOffset(request.ipv6, kIpv6PayloadBytesOffset + 1U));
            if (declaredBytes != request.ipv6Bytes)
            {
                return request.ipv6Bytes < declaredBytes ? Result::Truncated
                                                         : Result::InvalidFrame;
            }
            const size_t needed = framingBytes + request.ipv6Bytes;
            if (capacity < needed)
            {
                return Result::BufferTooSmall;
            }
            __builtin_memset(output, 0, framingBytes);
            *usbByteOffset(output, 0U) =
                request.qos ? kQosDataFrameControl : kDataFrameControl;
            __builtin_memcpy(usbByteOffset(output, kDestinationOffset),
                             &request.destination.bytes, kMacAddressBytes);
            __builtin_memcpy(usbByteOffset(output, kSourceOffset),
                             &request.source.bytes, kMacAddressBytes);
            __builtin_memcpy(usbByteOffset(output, kBssidOffset), &kAwdlBssid,
                             kMacAddressBytes);
            const auto sequenceControl =
                static_cast<uint16_t>(request.macSequence << kMacSequenceShift);
            *usbByteOffset(output, kMacSequenceOffset) =
                static_cast<uint8_t>(sequenceControl);
            *usbByteOffset(output, kMacSequenceOffset + 1U) =
                static_cast<uint8_t>(sequenceControl >> kBitsPerByte);
            uint8_t *const body = usbByteOffset(output, headerBytes);
            __builtin_memcpy(body, &kAwdlDataLlc, sizeof(kAwdlDataLlc));
            *usbByteOffset(body, kAwdlDataSequenceOffset) =
                static_cast<uint8_t>(request.awdlSequence);
            *usbByteOffset(body, kAwdlDataSequenceOffset + 1U) =
                static_cast<uint8_t>(request.awdlSequence >> kBitsPerByte);
            __builtin_memcpy(usbByteOffset(body, kAwdlDataTypeOffset),
                             &kIpv6EtherType, sizeof(kIpv6EtherType));
            __builtin_memcpy(usbByteOffset(output, framingBytes), request.ipv6,
                             request.ipv6Bytes);
            written = needed;
            return Result::Ok;
        }

        Result parseAwdlIpv6Data(const uint8_t *bytes, size_t length,
                                 AwdlIpv6Data &out)
        {
            if (overlaps(&out, sizeof(out), bytes, length))
            {
                return Result::OverlappingBuffers;
            }
            out = {};
            Frame header {};
            const Result parsed = parseFrame(bytes, length, header);
            if (parsed != Result::Ok)
            {
                return parsed;
            }
            if (header.type != FrameType::Data ||
                (header.subtype != 0U &&
                 header.subtype != kAwdlQosDataSubtype) ||
                header.toDs || header.fromDs || header.protectedFrame ||
                header.moreFragments || header.fragment != 0U ||
                !validStationMac(header.source) ||
                __builtin_memcmp(&header.bssid.bytes, &kAwdlBssid,
                                 sizeof(kAwdlBssid)) != 0)
            {
                return Result::UnsupportedFrame;
            }
            uint8_t aggregate = 0U;
            for (const uint8_t destinationByte : header.destination.bytes)
            {
                aggregate |= destinationByte;
            }
            if (aggregate == 0U)
            {
                return Result::InvalidAddress;
            }
            if (length - header.headerLength <
                kAwdlDataHeaderBytes + kIpv6HeaderBytes)
            {
                return Result::Truncated;
            }
            const uint8_t *body = usbByteOffset(bytes, header.headerLength);
            if (__builtin_memcmp(body, &kAwdlDataLlc, sizeof(kAwdlDataLlc)) !=
                    0 ||
                __builtin_memcmp(usbByteOffset(body, kAwdlDataTypeOffset),
                                 &kIpv6EtherType, sizeof(kIpv6EtherType)) != 0)
            {
                return Result::UnsupportedFrame;
            }
            uint8_t reserved[2] {};
            __builtin_memcpy(&reserved,
                             usbByteOffset(body, kAwdlDataReservedOffset),
                             sizeof(reserved));
            if (reserved[0] != 0U || reserved[1] != 0U)
            {
                return Result::InvalidFrame;
            }
            const size_t ipv6Offset =
                header.headerLength + kAwdlDataHeaderBytes;
            const uint8_t *ipv6 = usbByteOffset(bytes, ipv6Offset);
            if ((*ipv6 >> 4U) != kIpv6Version)
            {
                return Result::InvalidFrame;
            }
            const auto highLength = static_cast<uint32_t>(
                *usbByteOffset(ipv6, kIpv6PayloadBytesOffset));
            const auto lowLength = static_cast<uint32_t>(
                *usbByteOffset(ipv6, kIpv6PayloadBytesOffset + 1U));
            const auto payloadLength =
                static_cast<uint16_t>((highLength << kBitsPerByte) | lowLength);
            const size_t declaredBytes =
                kIpv6HeaderBytes + static_cast<size_t>(payloadLength);
            const size_t observedBytes = length - ipv6Offset;
            if (declaredBytes != observedBytes)
            {
                return observedBytes < declaredBytes ? Result::Truncated
                                                     : Result::InvalidFrame;
            }
            out = {
                header,
                readLittle16(usbByteOffset(body, kAwdlDataSequenceOffset)),
                ipv6Offset,
                declaredBytes,
            };
            return Result::Ok;
        }

        Result parseAwdlAction(const uint8_t *bytes, size_t length,
                               AwdlAction &out)
        {
            if (overlaps(&out, sizeof(out), bytes, length))
            {
                return Result::OverlappingBuffers;
            }
            out = {};
            Frame header {};
            const Result parsed = parseFrame(bytes, length, header);
            if (parsed != Result::Ok)
            {
                return parsed;
            }
            if (header.type != FrameType::Management ||
                header.subtype != kManagementActionSubtype ||
                header.protectedFrame || !validStationMac(header.source) ||
                __builtin_memcmp(&header.bssid.bytes, &kAwdlBssid,
                                 sizeof(kAwdlBssid)) != 0)
            {
                return Result::UnsupportedFrame;
            }
            if (length - header.headerLength < kActionBodyBytes)
            {
                return Result::Truncated;
            }
            UsbBytes<uint8_t, kActionBodyBytes> action {};
            __builtin_memcpy(action.data(),
                             usbByteOffset(bytes, header.headerLength),
                             kActionBodyBytes);
            if (__builtin_memcmp(action.data(), &kVendorPrefix,
                                 kVendorPrefixBytes) != 0 ||
                (action.at(kAwdlSubtypeOffset) != 0U &&
                 action.at(kAwdlSubtypeOffset) != kMasterIndicationSubtype))
            {
                return Result::UnsupportedFrame;
            }
            if (action.at(kReservedOffset) != 0U)
            {
                return Result::InvalidFrame;
            }
            const size_t tlvOffset = header.headerLength + kActionBodyBytes;
            AwdlTlvs tlvs(usbByteOffset(bytes, tlvOffset), length - tlvOffset);
            size_t count = 0U;
            AwdlTlv element {};
            for (;;)
            {
                const AwdlTlvStatus status = tlvs.next(element);
                if (status == AwdlTlvStatus::End)
                {
                    break;
                }
                if (status == AwdlTlvStatus::Truncated)
                {
                    return Result::InvalidElement;
                }
                ++count;
            }
            if (count == 0U)
            {
                return Result::InvalidElement;
            }
            out = {
                header,
                action.at(kVendorPrefixBytes - 1U),
                action.at(kAwdlSubtypeOffset),
                readLittle32(usbByteOffset(action.data(), kPhyTimeOffset)),
                readLittle32(usbByteOffset(action.data(), kTargetTimeOffset)),
                tlvOffset,
                count,
            };
            return Result::Ok;
        }
    } // namespace ieee80211
} // namespace simpleath
