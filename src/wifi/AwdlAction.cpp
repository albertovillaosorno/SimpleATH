// AWDL action-frame syntax described independently by Stute et al. (2018).
// No third-party implementation code is incorporated here.
#include "AwdlAction.hpp"
#include "Frames.hpp"
#include "bluetooth/UsbBytes.hpp"
#include <stddef.h>
#include <stdint.h>

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
            constexpr uint8_t kQosAmsduPresent = 0x80U;
            constexpr size_t kDataMacHeaderBytes = 24U;
            constexpr size_t kQosControlBytes = 2U;
            constexpr size_t kFcsBytes = 4U;
            constexpr size_t kMaxMpduWithFcs = 2346U;
            constexpr uint16_t kMacSequenceMax = 0x0fffU;
            constexpr uint16_t kMacSequenceHalfRange = 0x0800U;
            constexpr uint32_t kAwdlDataSequenceMask = 0xffffU;
            constexpr uint32_t kAwdlDataSequenceHalfRange = 0x8000U;
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
            // This parser handles one ordinary MSDU, not A-MSDU subframes
            // or an arbitrarily long aggregate. Match the FCS-free TX bound.
            if (length > kMaxMpduWithFcs - kFcsBytes)
            {
                return Result::InvalidFrame;
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
            // In a QoS Data header this flag changes the payload into an
            // A-MSDU subframe sequence, not an LLC/SNAP IPv6 MSDU.
            if (header.subtype == kAwdlQosDataSubtype &&
                (*usbByteOffset(bytes, kDataMacHeaderBytes) &
                 kQosAmsduPresent) != 0U)
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
            uint8_t destinationAggregate = 0U;
            for (const uint8_t octet : header.destination.bytes)
            {
                destinationAggregate |= octet;
            }
            if (destinationAggregate == 0U)
            {
                return Result::InvalidAddress;
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

        namespace
        {
            constexpr uint8_t kTlvSync = 4U;
            constexpr uint8_t kTlvChannel = 18U;
            constexpr uint8_t kTlvVersion = 21U;
            constexpr uint8_t kTlvElectionV2 = 24U;
            constexpr size_t kVersionBytes = 2U;
            constexpr size_t kSyncMinBytes = 31U;
            constexpr size_t kSyncDownCounter = 1U;
            constexpr size_t kSyncPeriod = 5U;
            constexpr size_t kSyncMaster = 21U;
            constexpr size_t kSyncAwSequence = 29U;
            constexpr size_t kElectionBytes = 40U;
            constexpr size_t kElectionMaster = 0U;
            constexpr size_t kElectionCounter = 12U;
            constexpr size_t kElectionMasterMetric = 20U;
            constexpr size_t kElectionOwnMetric = 24U;
            constexpr size_t kElectionOwnCounter = 36U;
            constexpr size_t kElectionReserved = 28U;
            constexpr size_t kElectionReservedBytes = 8U;
            constexpr size_t kChannelPrefix = 6U;
            constexpr size_t kChannelPadding = 3U;
            constexpr size_t kChannelCount = 16U;
            constexpr uint8_t kChannelSimple = 0U;
            constexpr uint8_t kChannelLegacy = 1U;
            constexpr uint8_t kChannelOpClass = 3U;
            constexpr uint8_t kOpClass24Ghz20Mhz = 81U;
            constexpr uint8_t kChannelSix = 6U;
            constexpr uint8_t kChannelSlotCount = 15U;
            constexpr uint8_t kChannelStepCount = 3U;
            constexpr uint16_t kAwdlPeriodTu = 16U;
            constexpr uint32_t kAwdlUsecPerTu = 1024U;
            constexpr uint32_t kAwdlUsecPerMs = 1000U;
            constexpr uint32_t kAwdlAwUsec = kAwdlUsecPerTu * kAwdlPeriodTu;
            constexpr uint32_t kAwdlAwPerChannelSlot = 4U;
            constexpr uint32_t kAwdlEawTu =
                kAwdlPeriodTu * kAwdlAwPerChannelSlot;
            constexpr uint32_t kAwdlEawUsec =
                kAwdlAwUsec * kAwdlAwPerChannelSlot;
            constexpr uint32_t kAwdlUnicastGuardUsec = kAwdlUsecPerTu * 3U;
            constexpr uint64_t kAwdlPeerExpiryUsec =
                AwdlNeighbors::kExpiryMs * kAwdlUsecPerMs;
            constexpr uint32_t kAwdlAwSequenceMask = 0xffffU;
            constexpr uint32_t kAwdlChannelSlotMask = 0x0fU;
            constexpr uint32_t kAwdlEawSequenceMask = 0xfffcU;
            constexpr uint16_t kChannelFill = 0xffffU;
            constexpr uint8_t kLocalAwdlVersion = 0x10U;
            constexpr uint8_t kLocalAwdlMacClass = 1U;
            constexpr size_t kMifChannelBytes =
                kChannelPrefix + kChannelCount + kChannelPadding;
            constexpr size_t kMifTlvBytes = (4U * kTlvHeaderBytes) +
                                            kSyncMinBytes + kMifChannelBytes +
                                            kElectionBytes + kVersionBytes;
            constexpr Mac kAwdlBroadcast {
                {0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU},
            };

            void writeLittle16(uint8_t *bytes, uint16_t value)
            {
                *usbByteOffset(bytes, 0U) = static_cast<uint8_t>(value);
                *usbByteOffset(bytes, 1U) =
                    static_cast<uint8_t>(value >> kBitsPerByte);
            }

            void writeLittle32(uint8_t *bytes, uint32_t value)
            {
                for (size_t index = 0U; index < sizeof(value); ++index)
                {
                    *usbByteOffset(bytes, index) =
                        static_cast<uint8_t>(value >> (index * kBitsPerByte));
                }
            }

            enum class MifTlvType : uint8_t
            {
                Sync = kTlvSync,
                Channel = kTlvChannel,
                Election = kTlvElectionV2,
                Version = kTlvVersion,
            };

            void writeTlvHeader(uint8_t *bytes, MifTlvType type,
                                uint16_t length)
            {
                *usbByteOffset(bytes, 0U) = static_cast<uint8_t>(type);
                writeLittle16(usbByteOffset(bytes, 1U), length);
            }

            bool validAt(uint64_t nowMs, uint64_t lastHeardMs)
            {
                return nowMs >= lastHeardMs &&
                       nowMs - lastHeardMs < AwdlNeighbors::kExpiryMs;
            }

            bool allZeros(const uint8_t *bytes, size_t length)
            {
                for (size_t offset = 0U; offset < length; ++offset)
                {
                    if (*usbByteOffset(bytes, offset) != 0U)
                    {
                        return false;
                    }
                }
                return true;
            }

            bool decodeChannelSixSlots(const AwdlTlv &tlv, uint16_t &slotMask)
            {
                slotMask = 0U;
                if (tlv.length < kChannelPrefix + kChannelPadding)
                {
                    return false;
                }
                const uint8_t *const data = tlv.data;
                const uint8_t encoding = *usbByteOffset(data, 1U);
                if (encoding != kChannelSimple && encoding != kChannelLegacy &&
                    encoding != kChannelOpClass)
                {
                    return false;
                }
                const size_t slotWidth = encoding == kChannelSimple ? 1U : 2U;
                const size_t slotsBytes = kChannelCount * slotWidth;
                const size_t expected =
                    kChannelPrefix + slotsBytes + kChannelPadding;
                if (tlv.length != expected ||
                    *usbByteOffset(data, 0U) != kChannelSlotCount ||
                    *usbByteOffset(data, 2U) != 0U ||
                    *usbByteOffset(data, 3U) != kChannelStepCount ||
                    readLittle16(usbByteOffset(data, 4U)) != kChannelFill ||
                    !allZeros(usbByteOffset(data, kChannelPrefix + slotsBytes),
                              kChannelPadding))
                {
                    return false;
                }
                for (size_t slot = 0U; slot < kChannelCount; ++slot)
                {
                    const size_t entry = kChannelPrefix + (slot * slotWidth);
                    const size_t channelOffset =
                        entry + (encoding == kChannelLegacy ? 1U : 0U);
                    // In opclass encoding the FIRST byte is the channel;
                    // legacy encoding stores it SECOND, after flags. Only
                    // 2.4-GHz class 81 can describe channel 6 for this NIC.
                    const bool allowedClass =
                        encoding != kChannelOpClass ||
                        *usbByteOffset(data, entry + 1U) == kOpClass24Ghz20Mhz;
                    if (allowedClass &&
                        *usbByteOffset(data, channelOffset) == kChannelSix)
                    {
                        slotMask |= static_cast<uint16_t>(1U << slot);
                    }
                }
                return true;
            }

            bool decodeVersion(const AwdlTlv &tlv, AwdlNeighbor &out)
            {
                if (tlv.length != kVersionBytes ||
                    *usbByteOffset(tlv.data, 0U) == 0U ||
                    *usbByteOffset(tlv.data, 1U) == 0U)
                {
                    return false;
                }
                out.version = *usbByteOffset(tlv.data, 0U);
                out.deviceClass = *usbByteOffset(tlv.data, 1U);
                return true;
            }

            bool decodeSync(const AwdlTlv &tlv, AwdlNeighbor &out)
            {
                const uint16_t downCounter =
                    tlv.length < kSyncMinBytes
                        ? 0U
                        : readLittle16(
                              usbByteOffset(tlv.data, kSyncDownCounter));
                if (tlv.length < kSyncMinBytes || downCounter == 0U ||
                    downCounter > kAwdlEawTu ||
                    readLittle16(usbByteOffset(tlv.data, kSyncPeriod)) !=
                        kAwdlPeriodTu)
                {
                    return false;
                }
                out.txDownCounterTu = downCounter;
                out.awPeriodTu = kAwdlPeriodTu;
                out.nextAwSequence =
                    readLittle16(usbByteOffset(tlv.data, kSyncAwSequence));
                __builtin_memcpy(&out.syncMaster.bytes,
                                 usbByteOffset(tlv.data, kSyncMaster),
                                 kMacAddressBytes);
                return true;
            }

            bool decodeElection(const AwdlTlv &tlv, AwdlNeighbor &out)
            {
                if (tlv.length != kElectionBytes ||
                    !allZeros(usbByteOffset(tlv.data, kElectionReserved),
                              kElectionReservedBytes))
                {
                    return false;
                }
                __builtin_memcpy(&out.electionMaster.bytes,
                                 usbByteOffset(tlv.data, kElectionMaster),
                                 kMacAddressBytes);
                out.masterCounter =
                    readLittle32(usbByteOffset(tlv.data, kElectionCounter));
                out.masterMetric = readLittle32(
                    usbByteOffset(tlv.data, kElectionMasterMetric));
                out.ownMetric =
                    readLittle32(usbByteOffset(tlv.data, kElectionOwnMetric));
                out.ownCounter =
                    readLittle32(usbByteOffset(tlv.data, kElectionOwnCounter));
                return true;
            }

            constexpr uint8_t kSeenVersion = 0x01U;
            constexpr uint8_t kSeenSync = 0x02U;
            constexpr uint8_t kSeenChannel = 0x04U;
            constexpr uint8_t kSeenElection = 0x08U;
            constexpr uint8_t kSeenAll = 0x0fU;

            bool absorbNeighborTlv(const AwdlTlv &tlv, AwdlNeighbor &neighbor,
                                   uint8_t &seen)
            {
                uint8_t bit = 0U;
                bool valid = true;
                switch (tlv.type)
                {
                    case kTlvVersion:
                        bit = kSeenVersion;
                        valid = decodeVersion(tlv, neighbor);
                        break;
                    case kTlvSync:
                        bit = kSeenSync;
                        valid = decodeSync(tlv, neighbor);
                        break;
                    case kTlvChannel:
                        bit = kSeenChannel;
                        valid = decodeChannelSixSlots(tlv,
                                                      neighbor.channelSixSlots);
                        break;
                    case kTlvElectionV2:
                        bit = kSeenElection;
                        valid = decodeElection(tlv, neighbor);
                        break;
                    default:
                        return true; // Unknown TLVs must be skipped by length.
                }
                if (!valid || (seen & bit) != 0U)
                {
                    return false;
                }
                seen |= bit;
                return true;
            }

            Result decodeNeighborMif(const uint8_t *frame, size_t bytes,
                                     AwdlNeighbor &out)
            {
                AwdlAction action {};
                const Result result = parseAwdlAction(frame, bytes, action);
                if (result != Result::Ok)
                {
                    return result;
                }
                if (action.subtype != kMasterIndicationSubtype)
                {
                    return Result::UnsupportedFrame;
                }
                AwdlNeighbor candidate {};
                candidate.source = action.header.source;
                candidate.macSequence = action.header.sequence;
                uint8_t seen = 0U;
                AwdlTlvs tlvs(usbByteOffset(frame, action.tlvOffset),
                              bytes - action.tlvOffset);
                AwdlTlv tlv {};
                for (;;)
                {
                    const AwdlTlvStatus status = tlvs.next(tlv);
                    if (status == AwdlTlvStatus::End)
                    {
                        break;
                    }
                    if (status != AwdlTlvStatus::Element)
                    {
                        return Result::InvalidElement;
                    }
                    if (!absorbNeighborTlv(tlv, candidate, seen))
                    {
                        return Result::InvalidElement;
                    }
                }
                if (seen != kSeenAll ||
                    !validStationMac(candidate.syncMaster) ||
                    !validStationMac(candidate.electionMaster))
                {
                    return Result::InvalidElement;
                }
                out = candidate;
                return Result::Ok;
            }
        } // namespace

        Result makeAwdlChannelSixMif(const AwdlLocalMifTx &request,
                                     uint8_t *output, size_t capacity,
                                     size_t &written)
        {
            if (overlaps(output, capacity, &request, sizeof(request)) ||
                overlaps(&written, sizeof(written), &request,
                         sizeof(request)) ||
                overlaps(output, capacity, &written, sizeof(written)))
            {
                return Result::OverlappingBuffers;
            }
            written = 0U;
            if (output == nullptr)
            {
                return Result::NullBuffer;
            }
            if (!validStationMac(request.source) ||
                !validStationMac(request.syncMaster) ||
                !validStationMac(request.electionMaster))
            {
                return Result::InvalidAddress;
            }
            if (request.macSequence > kMacSequenceMax ||
                request.txDownCounterTu == 0U ||
                request.txDownCounterTu > kAwdlEawTu ||
                request.channelSixSlots == 0U)
            {
                return Result::InvalidElement;
            }
            // This fixed local MIF conveys no unreviewed 5-GHz slots or
            // arbitrary election/synchronization padding. The native owner
            // must still derive these counters from live radio observations.
            UsbBytes<uint8_t, kMifTlvBytes> tlvs {};
            size_t position = 0U;
            uint8_t *header = usbByteOffset(tlvs.data(), position);
            writeTlvHeader(header, MifTlvType::Sync, kSyncMinBytes);
            uint8_t *sync = usbByteOffset(header, kTlvHeaderBytes);
            writeLittle16(usbByteOffset(sync, kSyncDownCounter),
                          request.txDownCounterTu);
            writeLittle16(usbByteOffset(sync, kSyncPeriod), kAwdlPeriodTu);
            __builtin_memcpy(usbByteOffset(sync, kSyncMaster),
                             &request.syncMaster.bytes, kMacAddressBytes);
            writeLittle16(usbByteOffset(sync, kSyncAwSequence),
                          request.nextAwSequence);
            position += kTlvHeaderBytes + kSyncMinBytes;

            header = usbByteOffset(tlvs.data(), position);
            writeTlvHeader(header, MifTlvType::Channel, kMifChannelBytes);
            uint8_t *channels = usbByteOffset(header, kTlvHeaderBytes);
            *usbByteOffset(channels, 0U) = kChannelSlotCount;
            *usbByteOffset(channels, 1U) = kChannelSimple;
            *usbByteOffset(channels, 3U) = kChannelStepCount;
            writeLittle16(usbByteOffset(channels, 4U), kChannelFill);
            for (size_t slot = 0U; slot < kChannelCount; ++slot)
            {
                if ((static_cast<uint32_t>(request.channelSixSlots) &
                     (uint32_t {1U} << slot)) != 0U)
                {
                    *usbByteOffset(channels, kChannelPrefix + slot) =
                        kChannelSix;
                }
            }
            position += kTlvHeaderBytes + kMifChannelBytes;

            header = usbByteOffset(tlvs.data(), position);
            writeTlvHeader(header, MifTlvType::Election, kElectionBytes);
            uint8_t *election = usbByteOffset(header, kTlvHeaderBytes);
            __builtin_memcpy(usbByteOffset(election, kElectionMaster),
                             &request.electionMaster.bytes, kMacAddressBytes);
            writeLittle32(usbByteOffset(election, kElectionCounter),
                          request.masterCounter);
            writeLittle32(usbByteOffset(election, kElectionMasterMetric),
                          request.masterMetric);
            writeLittle32(usbByteOffset(election, kElectionOwnMetric),
                          request.ownMetric);
            writeLittle32(usbByteOffset(election, kElectionOwnCounter),
                          request.ownCounter);
            position += kTlvHeaderBytes + kElectionBytes;

            header = usbByteOffset(tlvs.data(), position);
            writeTlvHeader(header, MifTlvType::Version, kVersionBytes);
            uint8_t *version = usbByteOffset(header, kTlvHeaderBytes);
            *usbByteOffset(version, 0U) = kLocalAwdlVersion;
            *usbByteOffset(version, 1U) = kLocalAwdlMacClass;
            position += kTlvHeaderBytes + kVersionBytes;
            if (position != kMifTlvBytes)
            {
                return Result::InvalidElement;
            }
            const AwdlActionTx action {
                request.source,
                kAwdlBroadcast,
                request.macSequence,
                kMasterIndicationSubtype,
                request.phyTransmitUsec,
                request.targetTransmitUsec,
                tlvs.data(),
                kMifTlvBytes,
            };
            return makeAwdlAction(action, output, capacity, written);
        }

        Result AwdlNeighbors::observeMif(uint64_t nowMs, const uint8_t *frame,
                                         size_t bytes)
        {
            if (overlaps(this, sizeof(*this), frame, bytes))
            {
                return Result::OverlappingBuffers;
            }
            if (clockInitialized_ && nowMs < lastClockMs_)
            {
                return Result::InvalidFrame;
            }
            AwdlNeighbor candidate {};
            const Result result = decodeNeighborMif(frame, bytes, candidate);
            if (result != Result::Ok)
            {
                return result;
            }
            candidate.lastHeardMs = nowMs;
            candidate.lastMifMs = nowMs;
            expire(nowMs);
            Entry *freeEntry = nullptr;
            for (size_t index = 0U; index < kCapacity; ++index)
            {
                Entry &entry = entries_.at(index);
                if (entry.occupied &&
                    sameMac(entry.neighbor.source, candidate.source))
                {
                    // 802.11 management sequence is 12-bit serial space.
                    // Require a strictly forward modular step less than
                    // half its space: duplicates and reordered/replayed
                    // MIFs must not invent a fresh clock synchronization.
                    const auto distance =
                        (static_cast<uint32_t>(candidate.macSequence) -
                         static_cast<uint32_t>(entry.neighbor.macSequence)) &
                        static_cast<uint32_t>(kMacSequenceMax);
                    if (distance == 0U || distance >= kMacSequenceHalfRange)
                    {
                        return Result::InvalidFrame;
                    }
                    entry.neighbor = candidate;
                    return Result::Ok;
                }
                if (!entry.occupied && freeEntry == nullptr)
                {
                    freeEntry = &entry;
                }
            }
            if (freeEntry == nullptr)
            {
                return Result::BufferTooSmall;
            }
            freeEntry->neighbor = candidate;
            freeEntry->occupied = true;
            return Result::Ok;
        }

        Result AwdlNeighbors::observeIpv6(uint64_t nowMs, const uint8_t *frame,
                                          size_t bytes)
        {
            if (overlaps(this, sizeof(*this), frame, bytes))
            {
                return Result::OverlappingBuffers;
            }
            if (clockInitialized_ && nowMs < lastClockMs_)
            {
                return Result::InvalidFrame;
            }
            AwdlIpv6Data data {};
            const Result result = parseAwdlIpv6Data(frame, bytes, data);
            if (result != Result::Ok)
            {
                return result;
            }
            expire(nowMs);
            for (size_t index = 0U; index < kCapacity; ++index)
            {
                Entry &entry = entries_.at(index);
                if (entry.occupied &&
                    sameMac(entry.neighbor.source, data.header.source) &&
                    validAt(nowMs, entry.neighbor.lastHeardMs))
                {
                    // AWDL data carries a separate 16-bit serial. Reject
                    // duplicates, reverse steps and half-range ambiguity:
                    // none may renew a neighbor via replayed IPv6 bytes.
                    // This is not authentication of unprotected data.
                    if (entry.ipv6SequenceSeen)
                    {
                        const uint32_t distance =
                            (static_cast<uint32_t>(data.sequence) -
                             static_cast<uint32_t>(entry.lastIpv6Sequence)) &
                            kAwdlDataSequenceMask;
                        if (distance == 0U ||
                            distance >= kAwdlDataSequenceHalfRange)
                        {
                            return Result::InvalidFrame;
                        }
                    }
                    entry.lastIpv6Sequence = data.sequence;
                    entry.ipv6SequenceSeen = true;
                    entry.neighbor.lastHeardMs = nowMs;
                    return Result::Ok;
                }
            }
            return Result::UnsupportedFrame;
        }

        Result AwdlNeighbors::observeIpv6ForLocal(uint64_t nowMs,
                                                  const Mac &local,
                                                  const uint8_t *frame,
                                                  size_t bytes)
        {
            if (overlaps(&local, sizeof(local), this, sizeof(*this)) ||
                overlaps(frame, bytes, this, sizeof(*this)))
            {
                return Result::OverlappingBuffers;
            }
            if (!validStationMac(local))
            {
                return Result::InvalidAddress;
            }
            AwdlIpv6Data data {};
            const Result parsed = parseAwdlIpv6Data(frame, bytes, data);
            if (parsed != Result::Ok)
            {
                return parsed;
            }
            if (sameMac(local, data.header.source))
            {
                return Result::InvalidAddress;
            }
            if (!sameMac(local, data.header.destination))
            {
                // Only 33:33 IPv6 multicast frames addressed to the
                // matching group may be observed in addition to our own
                // unicast destination (RFC 2464 section 7). A mismatch
                // cannot refresh a peer's clock or replay sequence.
                const uint8_t *const ipv6 =
                    usbByteOffset(frame, data.ipv6Offset);
                constexpr size_t kIpv6DestinationOffset = 24U;
                constexpr size_t kIpv6DestinationLastFour = 12U;
                const uint8_t *const destination =
                    usbByteOffset(ipv6, kIpv6DestinationOffset);
                constexpr uint8_t kMacIpv6MulticastPrefix = 0x33U;
                constexpr uint8_t kIpv6MulticastPrefix = 0xffU;
                constexpr size_t kMacGroupPrefixBytes = 2U;
                constexpr size_t kMulticastSuffixBytes = 4U;
                const auto *const mac = &data.header.destination.bytes[0];
                const uint8_t groupPrefix[kMacGroupPrefixBytes] {
                    kMacIpv6MulticastPrefix,
                    kMacIpv6MulticastPrefix,
                };
                if (__builtin_memcmp(mac, &groupPrefix, sizeof(groupPrefix)) !=
                        0 ||
                    *destination != kIpv6MulticastPrefix ||
                    __builtin_memcmp(
                        usbByteOffset(mac, kMacGroupPrefixBytes),
                        usbByteOffset(destination, kIpv6DestinationLastFour),
                        kMulticastSuffixBytes) != 0)
                {
                    return Result::UnsupportedFrame;
                }
            }
            return observeIpv6(nowMs, frame, bytes);
        }

        bool AwdlNeighbors::find(const Mac &source, uint64_t nowMs,
                                 AwdlNeighbor &out) const
        {
            if (overlaps(&out, sizeof(out), this, sizeof(*this)) ||
                overlaps(&source, sizeof(source), &out, sizeof(out)))
            {
                return false;
            }
            out = {};
            if (clockInitialized_ && nowMs < lastClockMs_)
            {
                return false;
            }
            for (size_t index = 0U; index < kCapacity; ++index)
            {
                const Entry &entry = entries_.at(index);
                if (entry.occupied && sameMac(entry.neighbor.source, source) &&
                    validAt(nowMs, entry.neighbor.lastHeardMs))
                {
                    out = entry.neighbor;
                    return true;
                }
            }
            return false;
        }

        bool AwdlNeighbors::strongestDirectMaster(const Mac &local,
                                                  uint64_t nowMs,
                                                  AwdlNeighbor &out) const
        {
            if (overlaps(&out, sizeof(out), this, sizeof(*this)) ||
                overlaps(&out, sizeof(out), &local, sizeof(local)))
            {
                return false;
            }
            out = {};
            if (!validStationMac(local) ||
                (clockInitialized_ && nowMs < lastClockMs_))
            {
                return false;
            }
            bool found = false;
            for (size_t index = 0U; index < kCapacity; ++index)
            {
                const Entry &entry = entries_.at(index);
                const AwdlNeighbor &peer = entry.neighbor;
                if (!entry.occupied || sameMac(peer.source, local) ||
                    !validAt(nowMs, peer.lastMifMs) ||
                    peer.channelSixSlots == 0U ||
                    !sameMac(peer.source, peer.syncMaster) ||
                    !sameMac(peer.source, peer.electionMaster) ||
                    peer.masterMetric == 0U ||
                    peer.masterMetric != peer.ownMetric ||
                    peer.masterCounter != peer.ownCounter)
                {
                    continue;
                }
                // Compare complete, copied MIF attributes. Never let a
                // non-root relay's claimed top-master score win election
                // without its synchronization-tree proof.
                const bool stronger =
                    !found || peer.masterMetric > out.masterMetric ||
                    (peer.masterMetric == out.masterMetric &&
                     peer.masterCounter > out.masterCounter) ||
                    (peer.masterMetric == out.masterMetric &&
                     peer.masterCounter == out.masterCounter &&
                     __builtin_memcmp(&peer.source.bytes, &out.source.bytes,
                                      kMacAddressBytes) > 0);
                if (stronger)
                {
                    out = peer;
                    found = true;
                }
            }
            return found;
        }

        void AwdlNeighbors::expire(uint64_t nowMs)
        {
            if (clockInitialized_ && nowMs < lastClockMs_)
            {
                return;
            }
            clockInitialized_ = true;
            lastClockMs_ = nowMs;
            for (size_t index = 0U; index < kCapacity; ++index)
            {
                Entry &entry = entries_.at(index);
                if (entry.occupied &&
                    !validAt(nowMs, entry.neighbor.lastHeardMs))
                {
                    entry = {};
                }
            }
        }

        AwdlRendezvousStatus
        planAwdlChannelSixRendezvous(const AwdlNeighbor &peer,
                                     const AwdlRendezvousRequest &request,
                                     AwdlRendezvousWindow &out)
        {
            if (overlaps(&out, sizeof(out), &peer, sizeof(peer)) ||
                overlaps(&out, sizeof(out), &request, sizeof(request)))
            {
                return AwdlRendezvousStatus::InvalidInput;
            }
            out = {};
            if (!validStationMac(peer.source) ||
                peer.awPeriodTu != kAwdlPeriodTu ||
                peer.txDownCounterTu == 0U ||
                peer.txDownCounterTu > kAwdlEawTu ||
                request.mifRxUsec / kAwdlUsecPerMs != peer.lastMifMs ||
                request.frameAirtimeUsec == 0U ||
                request.frameAirtimeUsec >
                    kAwdlEawUsec - (2U * kAwdlUnicastGuardUsec))
            {
                return AwdlRendezvousStatus::InvalidInput;
            }
            if (request.nowUsec < request.mifRxUsec)
            {
                return AwdlRendezvousStatus::StaleSync;
            }
            const uint64_t ageUsec = request.nowUsec - request.mifRxUsec;
            if (ageUsec >= kAwdlPeerExpiryUsec ||
                request.frameAirtimeUsec >= kAwdlPeerExpiryUsec - ageUsec ||
                request.frameAirtimeUsec > UINT64_MAX - request.nowUsec)
            {
                return AwdlRendezvousStatus::StaleSync;
            }
            // The advertised down-counter is to the next 64-TU extended
            // availability window (EAW), NOT to every 16-TU AW. Four AWs
            // share each channel-sequence slot. Derive the elapsed time from
            // the MIF's EAW epoch, then advance the 16-bit AW sequence.
            const uint32_t untilEawUsec = peer.txDownCounterTu * kAwdlUsecPerTu;
            const uint64_t elapsedUsec =
                (kAwdlEawUsec - untilEawUsec) + ageUsec;
            const uint64_t elapsedEawUsec = elapsedUsec % kAwdlEawUsec;
            const uint64_t advancedAw = elapsedUsec / kAwdlAwUsec;
            const auto awSequence = static_cast<uint32_t>(
                ((peer.nextAwSequence & kAwdlEawSequenceMask) + advancedAw) &
                kAwdlAwSequenceMask);
            const auto slot = static_cast<uint8_t>(
                (awSequence / kAwdlAwPerChannelSlot) & kAwdlChannelSlotMask);
            const uint32_t peerSlots = peer.channelSixSlots;
            if ((peerSlots & (uint32_t {1U} << slot)) == 0U)
            {
                return AwdlRendezvousStatus::PeerOffChannel;
            }
            if (elapsedEawUsec < kAwdlUnicastGuardUsec ||
                elapsedEawUsec + request.frameAirtimeUsec +
                        kAwdlUnicastGuardUsec >
                    kAwdlEawUsec)
            {
                return AwdlRendezvousStatus::GuardInterval;
            }
            out = {
                static_cast<uint16_t>(awSequence),
                slot,
                static_cast<uint32_t>(kAwdlEawUsec - elapsedEawUsec),
            };
            return AwdlRendezvousStatus::Candidate;
        }

        AwdlRendezvousStatus
        planNextAwdlChannelSixRendezvous(const AwdlNeighbor &peer,
                                         const AwdlRendezvousRequest &request,
                                         AwdlRendezvousWindow &out)
        {
            if (overlaps(&out, sizeof(out), &peer, sizeof(peer)) ||
                overlaps(&out, sizeof(out), &request, sizeof(request)))
            {
                return AwdlRendezvousStatus::InvalidInput;
            }
            out = {};
            if (!validStationMac(peer.source) ||
                peer.awPeriodTu != kAwdlPeriodTu ||
                peer.txDownCounterTu == 0U ||
                peer.txDownCounterTu > kAwdlEawTu ||
                request.mifRxUsec / kAwdlUsecPerMs != peer.lastMifMs ||
                request.frameAirtimeUsec == 0U ||
                request.frameAirtimeUsec >
                    kAwdlEawUsec - (2U * kAwdlUnicastGuardUsec))
            {
                return AwdlRendezvousStatus::InvalidInput;
            }
            if (request.nowUsec < request.mifRxUsec ||
                request.nowUsec - request.mifRxUsec >= kAwdlPeerExpiryUsec)
            {
                return AwdlRendezvousStatus::StaleSync;
            }
            if (peer.channelSixSlots == 0U)
            {
                return AwdlRendezvousStatus::PeerOffChannel;
            }
            const uint64_t ageUsec = request.nowUsec - request.mifRxUsec;
            const uint64_t syncRemaining = kAwdlPeerExpiryUsec - ageUsec;
            const uint32_t untilEawUsec = peer.txDownCounterTu * kAwdlUsecPerTu;
            const uint64_t elapsedUsec =
                (kAwdlEawUsec - untilEawUsec) + ageUsec;
            const uint64_t phaseUsec = elapsedUsec % kAwdlEawUsec;
            const uint64_t currentEaw = elapsedUsec / kAwdlEawUsec;
            const uint32_t baseAw = peer.nextAwSequence & kAwdlEawSequenceMask;

            // Include the currently open EAW and the return to its channel
            // after all 16 slots. Never infer a radio tune from this search.
            for (uint32_t advance = 0U; advance <= kAwdlChannelSlotMask + 1U;
                 ++advance)
            {
                const auto slot = static_cast<uint8_t>(
                    ((baseAw / kAwdlAwPerChannelSlot) + currentEaw + advance) &
                    kAwdlChannelSlotMask);
                if ((static_cast<uint32_t>(peer.channelSixSlots) &
                     (uint32_t {1U} << slot)) == 0U)
                {
                    continue;
                }
                const uint64_t eawDelay =
                    (static_cast<uint64_t>(advance) * kAwdlEawUsec);
                uint64_t waitUsec = 0U;
                if (advance == 0U)
                {
                    if (phaseUsec < kAwdlUnicastGuardUsec)
                    {
                        waitUsec = kAwdlUnicastGuardUsec - phaseUsec;
                    }
                }
                else
                {
                    waitUsec = eawDelay - phaseUsec + kAwdlUnicastGuardUsec;
                }
                const uint64_t untilEnd = (eawDelay + kAwdlEawUsec) - phaseUsec;
                // A current EAW already in its final guard has no usable
                // airtime. Never underflow that guard into a valid window.
                if (untilEnd <= kAwdlUnicastGuardUsec)
                {
                    continue;
                }
                const uint64_t usableUsec = untilEnd - kAwdlUnicastGuardUsec;
                if (waitUsec + request.frameAirtimeUsec > usableUsec)
                {
                    continue;
                }
                // The MIF phase is trusted only for the current five-second
                // anchor; do not schedule a frame finishing at its expiry.
                if (waitUsec + request.frameAirtimeUsec >= syncRemaining ||
                    request.nowUsec > UINT64_MAX - waitUsec ||
                    request.frameAirtimeUsec >
                        UINT64_MAX - request.nowUsec - waitUsec)
                {
                    return AwdlRendezvousStatus::StaleSync;
                }
                const uint64_t startElapsedUsec = elapsedUsec + waitUsec;
                out = {
                    static_cast<uint16_t>(
                        (baseAw + (startElapsedUsec / kAwdlAwUsec)) &
                        kAwdlAwSequenceMask),
                    slot,
                    static_cast<uint32_t>(kAwdlEawUsec -
                                          (startElapsedUsec % kAwdlEawUsec)),
                    static_cast<uint32_t>(waitUsec),
                };
                return AwdlRendezvousStatus::Candidate;
            }
            return AwdlRendezvousStatus::PeerOffChannel;
        }

        namespace
        {
            struct SharedCandidate
            {
                    uint64_t begin {};
                    uint64_t end {};
                    uint64_t next {};
            };

            // A candidate bounds the guarded channel-six intervals of BOTH
            // devices, without granting native airtime or radio ownership.
            AwdlRendezvousStatus
            nextSharedCandidate(const AwdlNeighbor &local,
                                const AwdlNeighbor &peer,
                                const AwdlSharedRendezvousRequest &request,
                                uint64_t cursor, SharedCandidate &candidate)
            {
                const AwdlRendezvousRequest localRequest {
                    request.localMifUsec,
                    cursor,
                    request.frameAirtimeUsec,
                };
                const AwdlRendezvousRequest peerRequest {
                    request.peerMifUsec,
                    cursor,
                    request.frameAirtimeUsec,
                };
                AwdlRendezvousWindow localWindow {};
                AwdlRendezvousWindow peerWindow {};
                const auto localStatus = planNextAwdlChannelSixRendezvous(
                    local, localRequest, localWindow);
                if (localStatus != AwdlRendezvousStatus::Candidate)
                {
                    return localStatus;
                }
                const auto peerStatus = planNextAwdlChannelSixRendezvous(
                    peer, peerRequest, peerWindow);
                if (peerStatus != AwdlRendezvousStatus::Candidate)
                {
                    return peerStatus;
                }
                // Both planners have checked that cursor+wait cannot wrap.
                const uint64_t localStart = cursor + localWindow.waitUsec;
                const uint64_t peerStart = cursor + peerWindow.waitUsec;
                const uint64_t localUsable =
                    localWindow.remainingEawUsec - kAwdlUnicastGuardUsec;
                const uint64_t peerUsable =
                    peerWindow.remainingEawUsec - kAwdlUnicastGuardUsec;
                if (localStart > UINT64_MAX - localUsable ||
                    peerStart > UINT64_MAX - peerUsable)
                {
                    return AwdlRendezvousStatus::StaleSync;
                }
                const uint64_t localEnd = localStart + localUsable;
                const uint64_t peerEnd = peerStart + peerUsable;
                candidate.begin =
                    localStart > peerStart ? localStart : peerStart;
                candidate.end = localEnd < peerEnd ? localEnd : peerEnd;
                candidate.next = localEnd < peerEnd ? localEnd : peerEnd;
                return AwdlRendezvousStatus::Candidate;
            }

            bool
            confirmSharedCandidate(const AwdlNeighbor &local,
                                   const AwdlNeighbor &peer,
                                   const AwdlSharedRendezvousRequest &request,
                                   const SharedCandidate &candidate,
                                   AwdlSharedRendezvousWindow &out)
            {
                const AwdlRendezvousRequest localAtStart {
                    request.localMifUsec,
                    candidate.begin,
                    request.frameAirtimeUsec,
                };
                const AwdlRendezvousRequest peerAtStart {
                    request.peerMifUsec,
                    candidate.begin,
                    request.frameAirtimeUsec,
                };
                AwdlRendezvousWindow observedLocal {};
                AwdlRendezvousWindow observedPeer {};
                if (planAwdlChannelSixRendezvous(local, localAtStart,
                                                 observedLocal) !=
                        AwdlRendezvousStatus::Candidate ||
                    planAwdlChannelSixRendezvous(peer, peerAtStart,
                                                 observedPeer) !=
                        AwdlRendezvousStatus::Candidate)
                {
                    return false;
                }
                // The shared guard may extend beyond an MIF's five-second
                // timestamp authority. Publish only time that is safe from
                // BOTH epoch expiries, excluding the expiry microsecond.
                const uint64_t localAge =
                    candidate.begin - request.localMifUsec;
                const uint64_t peerAge = candidate.begin - request.peerMifUsec;
                const uint64_t localFresh = kAwdlPeerExpiryUsec - localAge - 1U;
                const uint64_t peerFresh = kAwdlPeerExpiryUsec - peerAge - 1U;
                const uint64_t fresh =
                    localFresh < peerFresh ? localFresh : peerFresh;
                const uint64_t untilGuard = candidate.end - candidate.begin;
                const uint64_t usable = untilGuard < fresh ? untilGuard : fresh;
                out = {
                    observedLocal.awSequence,
                    observedPeer.awSequence,
                    observedLocal.channelSlot,
                    observedPeer.channelSlot,
                    static_cast<uint32_t>(candidate.begin - request.nowUsec),
                    static_cast<uint32_t>(usable),
                };
                return true;
            }

            bool beyondSharedAnchor(AwdlRendezvousStatus status)
            {
                return status == AwdlRendezvousStatus::StaleSync ||
                       status == AwdlRendezvousStatus::PeerOffChannel;
            }
        } // namespace

        AwdlRendezvousStatus planSharedAwdlChannelSixRendezvous(
            const AwdlNeighbor &local, const AwdlNeighbor &peer,
            const AwdlSharedRendezvousRequest &request,
            AwdlSharedRendezvousWindow &out)
        {
            if (overlaps(&out, sizeof(out), &local, sizeof(local)) ||
                overlaps(&out, sizeof(out), &peer, sizeof(peer)) ||
                overlaps(&out, sizeof(out), &request, sizeof(request)))
            {
                return AwdlRendezvousStatus::InvalidInput;
            }
            out = {};
            if (sameMac(local.source, peer.source) ||
                request.localMifUsec > request.nowUsec ||
                request.peerMifUsec > request.nowUsec)
            {
                return AwdlRendezvousStatus::InvalidInput;
            }
            // Each 5-second phase contains at most 77 EAWs per device.
            // Check no more than two per EAW; all loops are source-bounded.
            constexpr uint64_t kMaxChecks =
                2U * ((kAwdlPeerExpiryUsec / kAwdlEawUsec) + 2U);
            uint64_t cursor = request.nowUsec;
            for (uint64_t check = 0U; check < kMaxChecks; ++check)
            {
                SharedCandidate candidate {};
                const auto status = nextSharedCandidate(local, peer, request,
                                                        cursor, candidate);
                if (status != AwdlRendezvousStatus::Candidate)
                {
                    return check != 0U && beyondSharedAnchor(status)
                               ? AwdlRendezvousStatus::NoSharedWindow
                               : status;
                }
                if (candidate.end > candidate.begin &&
                    candidate.end - candidate.begin >= request.frameAirtimeUsec)
                {
                    return confirmSharedCandidate(local, peer, request,
                                                  candidate, out)
                               ? AwdlRendezvousStatus::Candidate
                               : AwdlRendezvousStatus::NoSharedWindow;
                }
                // Skip the earlier exhausted EAW rather than re-examine
                // either device's forbidden final guard.
                if (candidate.next <= cursor)
                {
                    return AwdlRendezvousStatus::NoSharedWindow;
                }
                cursor = candidate.next;
            }
            return AwdlRendezvousStatus::NoSharedWindow;
        }

        void AwdlNeighbors::clear()
        {
            for (size_t index = 0U; index < kCapacity; ++index)
            {
                entries_.at(index) = {};
            }
            clockInitialized_ = false;
            lastClockMs_ = 0U;
        }
    } // namespace ieee80211
} // namespace simpleath
