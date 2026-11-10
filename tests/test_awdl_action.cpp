// SPDX-License-Identifier: AGPL-3.0-only
// Synthetic AWDL action-frame syntax regression; no radio, OS or AirDrop.
#include "bluetooth/UsbBytes.hpp"
#include "wifi/AwdlAction.hpp"
#include "wifi/Frames.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace
{
    using namespace simpleath;
    using namespace simpleath::ieee80211;

    constexpr size_t kHeaderBytes = 24U;
    constexpr uint8_t kActionSubtype = 13U;
    constexpr size_t kActionBytes = 16U;
    constexpr size_t kFirstTlvBytes = 5U;
    constexpr size_t kSecondTlvBytes = 4U;
    constexpr size_t kPayloadStart = kHeaderBytes + kActionBytes;
    constexpr size_t kPacketBytes =
        kPayloadStart + kFirstTlvBytes + kSecondTlvBytes;
    constexpr size_t kSourceOffset = 10U;
    constexpr size_t kBssidOffset = 16U;
    constexpr size_t kFragmentOffset = 22U;
    constexpr size_t kVersionOffset = kHeaderBytes + 5U;
    constexpr size_t kSubtypeOffset = kVersionOffset + 1U;
    constexpr size_t kReservedOffset = kSubtypeOffset + 1U;
    constexpr size_t kVendorOuiOffset = kHeaderBytes + 1U;
    constexpr size_t kTlvLengthOffset = kPayloadStart + 1U;
    constexpr uint8_t kManagementAction = 0xd0U;
    constexpr uint8_t kBeaconFrame = 0x80U;
    constexpr uint8_t kPublicVendorVersion = 0x10U;
    constexpr uint8_t kOtherVersion = 0x20U;
    constexpr uint8_t kProtectedFlag = 0x40U;
    constexpr uint8_t kBroadcast = 0xffU;
    constexpr uint8_t kFirstTlvType = 0x04U;
    constexpr uint8_t kSecondTlvType = 0x99U;
    constexpr uint8_t kFirstTlvOctet = 0xabU;
    constexpr uint8_t kSecondTlvOctet = 0xcdU;
    constexpr uint8_t kThirdTlvOctet = 0x42U;
    constexpr uint32_t kPhyTime = 0x78563412U;
    constexpr uint32_t kTargetTime = 0x21436587U;
    constexpr uint8_t kMifSubtype = 3U;
    constexpr int kAwdlDataFailure = 5;
    using Packet = std::array<uint8_t, kPacketBytes>;

    template <typename Buffer, size_t Length>
    void copyField(Buffer &frame, size_t offset,
                   const std::array<uint8_t, Length> &field)
    {
        for (size_t index = 0U; index < field.size(); ++index)
        {
            frame.at(offset + index) = field.at(index);
        }
    }

    Packet makeAwdl()
    {
        Packet frame {};
        frame.at(0U) = kManagementAction;
        for (size_t index = 4U; index < kSourceOffset; ++index)
        {
            frame.at(index) = kBroadcast;
        }
        const std::array<uint8_t, kMacAddressBytes> station {
            0x02U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U,
        };
        const std::array<uint8_t, kMacAddressBytes> bssid {
            0x00U, 0x25U, 0x00U, 0xffU, 0x94U, 0x73U,
        };
        const std::array<uint8_t, kActionBytes> action {
            127U,  0x00U, 0x17U, 0xf2U, 0x08U, 0x10U, 0x00U, 0x00U,
            0x12U, 0x34U, 0x56U, 0x78U, 0x87U, 0x65U, 0x43U, 0x21U,
        };
        const std::array<uint8_t, kFirstTlvBytes + kSecondTlvBytes> tlvs {
            0x04U, 0x02U, 0x00U, 0xabU, 0xcdU, 0x99U, 0x01U, 0x00U, 0x42U,
        };
        copyField(frame, kSourceOffset, station);
        copyField(frame, kBssidOffset, bssid);
        copyField(frame, kHeaderBytes, action);
        copyField(frame, kPayloadStart, tlvs);
        return frame;
    }

    bool validActionAndIteration()
    {
        const Packet frame = makeAwdl();
        AwdlAction action {};
        if (parseAwdlAction(frame.data(), frame.size(), action) != Result::Ok ||
            action.header.subtype != kActionSubtype ||
            action.header.type != FrameType::Management ||
            action.tlvOffset != kPayloadStart || action.tlvCount != 2U ||
            action.version != kPublicVendorVersion || action.subtype != 0U ||
            action.phyTransmitUsec != kPhyTime ||
            action.targetTransmitUsec != kTargetTime)
        {
            return false;
        }
        AwdlTlvs tlvs(usbByteOffset(frame.data(), action.tlvOffset),
                      frame.size() - action.tlvOffset);
        AwdlTlv tlv {};
        uint8_t value[2] {};
        if (tlvs.next(tlv) != AwdlTlvStatus::Element ||
            tlv.type != kFirstTlvType || tlv.length != sizeof(value))
        {
            return false;
        }
        __builtin_memcpy(&value, tlv.data, sizeof(value));
        if (value[0] != kFirstTlvOctet || value[1] != kSecondTlvOctet)
        {
            return false;
        }
        if (tlvs.next(tlv) != AwdlTlvStatus::Element ||
            tlv.type != kSecondTlvType || tlv.length != 1U)
        {
            return false;
        }
        uint8_t single = 0U;
        __builtin_memcpy(&single, tlv.data, sizeof(single));
        return single == kThirdTlvOctet &&
               tlvs.next(tlv) == AwdlTlvStatus::End && tlv.data == nullptr &&
               tlv.length == 0U;
    }

    bool rejectNonAwdlAndFragments()
    {
        Packet frame = makeAwdl();
        AwdlAction action {};
        frame.at(0U) = kBeaconFrame;
        if (parseAwdlAction(frame.data(), frame.size(), action) !=
            Result::UnsupportedFrame)
        {
            return false;
        }
        frame = makeAwdl();
        frame.at(kBssidOffset + 1U) ^= 0x01U;
        if (parseAwdlAction(frame.data(), frame.size(), action) !=
            Result::UnsupportedFrame)
        {
            return false;
        }
        frame = makeAwdl();
        frame.at(kVendorOuiOffset) ^= 0x01U;
        if (parseAwdlAction(frame.data(), frame.size(), action) !=
            Result::UnsupportedFrame)
        {
            return false;
        }
        frame = makeAwdl();
        frame.at(kVersionOffset) = kOtherVersion;
        if (parseAwdlAction(frame.data(), frame.size(), action) !=
            Result::UnsupportedFrame)
        {
            return false;
        }
        frame = makeAwdl();
        frame.at(kSubtypeOffset) = kMifSubtype;
        if (parseAwdlAction(frame.data(), frame.size(), action) != Result::Ok ||
            action.subtype != kMifSubtype)
        {
            return false;
        }
        frame.at(kReservedOffset) = 1U;
        if (parseAwdlAction(frame.data(), frame.size(), action) !=
                Result::InvalidFrame ||
            action.tlvCount != 0U)
        {
            return false;
        }
        frame = makeAwdl();
        frame.at(kFragmentOffset) = 0x01U;
        if (parseAwdlAction(frame.data(), frame.size(), action) !=
            Result::UnsupportedFrame)
        {
            return false;
        }
        frame = makeAwdl();
        frame.at(1U) = kProtectedFlag;
        return parseAwdlAction(frame.data(), frame.size(), action) ==
               Result::UnsupportedFrame;
    }

    bool rejectTruncationAndAliasing()
    {
        Packet frame = makeAwdl();
        AwdlAction action {};
        if (parseAwdlAction(frame.data(), frame.size(), action) != Result::Ok)
        {
            return false;
        }
        if (parseAwdlAction(frame.data(), kPayloadStart - 1U, action) !=
                Result::Truncated ||
            action.tlvCount != 0U)
        {
            return false;
        }
        if (parseAwdlAction(frame.data(), kPayloadStart, action) !=
            Result::InvalidElement)
        {
            return false;
        }
        frame = makeAwdl();
        frame.at(kTlvLengthOffset) = kBroadcast;
        if (parseAwdlAction(frame.data(), frame.size(), action) !=
            Result::InvalidElement)
        {
            return false;
        }
        frame = makeAwdl();
        if (parseAwdlAction(frame.data(), frame.size() - 1U, action) !=
            Result::InvalidElement)
        {
            return false;
        }
        AwdlTlvs tlvs(usbByteOffset(frame.data(), kPayloadStart),
                      frame.size() - kPayloadStart - 1U);
        AwdlTlv tlv {};
        if (tlvs.next(tlv) != AwdlTlvStatus::Element ||
            tlvs.next(tlv) != AwdlTlvStatus::Truncated || tlv.data != nullptr ||
            tlv.length != 0U)
        {
            return false;
        }
        AwdlTlv alias {};
        const AwdlTlv original = alias;
        const void *address = &alias;
        const uint8_t *span = nullptr;
        static_assert(sizeof(span) == sizeof(address), "pointer width");
        __builtin_memcpy(static_cast<void *>(&span),
                         static_cast<const void *>(&address), sizeof(span));
        AwdlTlvs aliased(span, sizeof(alias));
        return aliased.next(alias) == AwdlTlvStatus::Truncated &&
               alias.type == original.type && alias.data == original.data &&
               alias.length == original.length;
    }

    bool acceptPadding()
    {
        Packet frame = makeAwdl();
        // The AWDL header permits exactly one or two trailing zero octets.
        for (size_t count = 1U; count <= 2U; ++count)
        {
            std::array<uint8_t, kPacketBytes + 2U> padded {};
            for (size_t index = 0U; index < frame.size(); ++index)
            {
                padded.at(index) = frame.at(index);
            }
            AwdlAction action {};
            if (parseAwdlAction(padded.data(), frame.size() + count, action) !=
                    Result::Ok ||
                action.tlvCount != 2U)
            {
                return false;
            }
            padded.at(frame.size()) = kBroadcast;
            if (parseAwdlAction(padded.data(), frame.size() + count, action) !=
                Result::InvalidElement)
            {
                return false;
            }
        }
        return true;
    }

    bool acceptAwdlIpv6Data()
    {
        constexpr size_t kAwdlDataBytes = 16U;
        constexpr size_t kIpv6LengthLowOffset = 5U;
        constexpr size_t kAwdlReservedLowOffset = 12U;
        constexpr size_t kAwdlEtherTypeHighOffset = 14U;
        constexpr uint8_t kIpv6HeaderVersion = 0x60U;
        constexpr uint8_t kInvalidIpv6HeaderVersion = 0x40U;
        constexpr uint8_t kQosFrameType = 0x88U;
        constexpr uint8_t kQosSubtype = 8U;
        constexpr size_t kIpv6Bytes = 40U;
        constexpr size_t kWholeFrameBytes =
            kHeaderBytes + kAwdlDataBytes + kIpv6Bytes;
        constexpr uint8_t kDataFrameType = 0x08U;
        constexpr uint16_t kSequenceNumber = 0x3412U;
        using DataPacket = std::array<uint8_t, kWholeFrameBytes>;
        DataPacket frame {};
        frame.at(0U) = kDataFrameType;
        const std::array<uint8_t, kMacAddressBytes> destination {
            0x33U, 0x33U, 0x00U, 0x00U, 0x00U, 0x01U,
        };
        const std::array<uint8_t, kMacAddressBytes> station {
            0x02U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U,
        };
        const std::array<uint8_t, kMacAddressBytes> bssid {
            0x00U, 0x25U, 0x00U, 0xffU, 0x94U, 0x73U,
        };
        const std::array<uint8_t, kAwdlDataBytes> awdlData {
            0xaaU, 0xaaU, 0x03U, 0x00U, 0x17U, 0xf2U, 0x08U, 0x00U,
            0x03U, 0x04U, 0x12U, 0x34U, 0x00U, 0x00U, 0x86U, 0xddU,
        };
        copyField(frame, 4U, destination);
        copyField(frame, kSourceOffset, station);
        copyField(frame, kBssidOffset, bssid);
        copyField(frame, kHeaderBytes, awdlData);
        const size_t ipv6Offset = kHeaderBytes + kAwdlDataBytes;
        frame.at(ipv6Offset) =
            kIpv6HeaderVersion; // IPv6 version; zero payload length.
        AwdlIpv6Data decoded {};
        if (parseAwdlIpv6Data(frame.data(), frame.size(), decoded) !=
                Result::Ok ||
            decoded.header.type != FrameType::Data ||
            decoded.ipv6Offset != ipv6Offset ||
            decoded.ipv6Bytes != kIpv6Bytes ||
            decoded.sequence != kSequenceNumber)
        {
            return false;
        }
        // QoS Data has a two-byte extra header; the SNAP header moves too.
        std::array<uint8_t, kWholeFrameBytes + 2U> qos {};
        for (size_t index = 0U; index < kHeaderBytes; ++index)
        {
            qos.at(index) = frame.at(index);
        }
        for (size_t index = kHeaderBytes; index < frame.size(); ++index)
        {
            qos.at(index + 2U) = frame.at(index);
        }
        qos.at(0U) = kQosFrameType; // QoS data subtype.
        if (parseAwdlIpv6Data(qos.data(), qos.size(), decoded) != Result::Ok ||
            decoded.header.subtype != kQosSubtype ||
            decoded.ipv6Offset != ipv6Offset + 2U)
        {
            return false;
        }
        qos.at(0U) = kDataFrameType;
        qos.at(1U) = 0x01U; // ToDS violates AWDL addressing.
        if (parseAwdlIpv6Data(qos.data(), qos.size(), decoded) !=
            Result::UnsupportedFrame)
        {
            return false;
        }
        frame.at(0U) = kDataFrameType;
        frame.at(kHeaderBytes + 4U) ^= 0x01U; // Wrong Apple OUI.
        if (parseAwdlIpv6Data(frame.data(), frame.size(), decoded) !=
            Result::UnsupportedFrame)
        {
            return false;
        }
        frame.at(kHeaderBytes + 4U) ^= 0x01U;
        frame.at(kHeaderBytes + kAwdlEtherTypeHighOffset) ^= 0x01U;
        if (parseAwdlIpv6Data(frame.data(), frame.size(), decoded) !=
            Result::UnsupportedFrame)
        {
            return false;
        }
        frame.at(kHeaderBytes + kAwdlEtherTypeHighOffset) ^= 0x01U;
        frame.at(kHeaderBytes + kAwdlReservedLowOffset) = 1U;
        if (parseAwdlIpv6Data(frame.data(), frame.size(), decoded) !=
            Result::InvalidFrame)
        {
            return false;
        }
        frame.at(kHeaderBytes + kAwdlReservedLowOffset) = 0U;
        frame.at(ipv6Offset) =
            kInvalidIpv6HeaderVersion; // IPv4-like version is forbidden.
        if (parseAwdlIpv6Data(frame.data(), frame.size(), decoded) !=
            Result::InvalidFrame)
        {
            return false;
        }
        frame.at(ipv6Offset) = kIpv6HeaderVersion;
        if (parseAwdlIpv6Data(frame.data(), frame.size() - 1U, decoded) !=
            Result::Truncated)
        {
            return false;
        }
        frame.at(ipv6Offset + kIpv6LengthLowOffset) =
            1U; // Declares one extra IPv6 byte.
        if (parseAwdlIpv6Data(frame.data(), frame.size(), decoded) !=
            Result::Truncated)
        {
            return false;
        }
        frame.at(ipv6Offset + kIpv6LengthLowOffset) = 0U;
        frame.at(4U) = 0U; // First multicast destination byte.
        for (size_t index = 4U; index < kSourceOffset; ++index)
        {
            frame.at(index) = 0U;
        }
        if (parseAwdlIpv6Data(frame.data(), frame.size(), decoded) !=
            Result::InvalidAddress)
        {
            return false;
        }
        copyField(frame, 4U, destination);
        frame.at(kFragmentOffset) = 1U; // Data fragment not reassembled.
        return parseAwdlIpv6Data(frame.data(), frame.size(), decoded) ==
               Result::UnsupportedFrame;
    }

    bool serializeAwdlIpv6Data()
    {
        constexpr size_t kIpv6Bytes = 45U;
        constexpr size_t kSerializedDataHeaderBytes = 16U;
        constexpr size_t kQosBytes = 2U;
        constexpr size_t kDataFrameBytes =
            kHeaderBytes + kSerializedDataHeaderBytes + kIpv6Bytes;
        constexpr uint8_t kIpv6Version = 0x60U;
        constexpr uint8_t kIpv6PayloadLength = 5U;
        constexpr uint16_t kMacSequence = 0x0456U;
        constexpr uint16_t kInnerSequence = 0x3412U;
        constexpr uint8_t kQosType = 0x88U;
        constexpr uint8_t kDataType = 0x08U;
        constexpr size_t kInvalidMacSequence = 0x1000U;
        constexpr size_t kMaxMpdu = 2346U;
        constexpr size_t kFcsBytes = 4U;
        constexpr size_t kIpv6LengthLowOffset = 5U;
        constexpr size_t kIpv6HeaderBytes = 40U;
        constexpr size_t kLastIpv6ByteOffset = 44U;
        constexpr size_t kShortIpv6Header = 39U;
        constexpr uint8_t kFirstIpv6DataByte = 0xabU;
        constexpr uint8_t kLastIpv6DataByte = 0xcdU;
        constexpr uint8_t kOutputSentinel = 0xa5U;
        constexpr uint8_t kWrongIpv6Version = 0x40U;
        constexpr size_t kCountSentinel = 123U;
        constexpr uint8_t kQosSubtype = 8U;
        std::array<uint8_t, kIpv6Bytes> ipv6 {};
        ipv6.at(0U) = kIpv6Version;
        ipv6.at(kIpv6LengthLowOffset) = kIpv6PayloadLength;
        ipv6.at(kIpv6HeaderBytes) = kFirstIpv6DataByte;
        ipv6.at(kLastIpv6ByteOffset) = kLastIpv6DataByte;
        const Mac source {{0x02U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U}};
        const Mac multicast {{0x33U, 0x33U, 0x00U, 0x00U, 0x00U, 0x01U}};
        AwdlIpv6Tx tx {
            source, multicast,   kMacSequence, kInnerSequence,
            false,  ipv6.data(), ipv6.size(),
        };
        std::array<uint8_t, kDataFrameBytes + kQosBytes + 1U> output {};
        output.fill(kOutputSentinel);
        size_t written = kCountSentinel;
        if (makeAwdlIpv6Data(tx, output.data(), output.size(), written) !=
                Result::Ok ||
            written != kDataFrameBytes || output.at(0U) != kDataType ||
            output.at(written) != kOutputSentinel ||
            output.at(kHeaderBytes + kSerializedDataHeaderBytes +
                      kIpv6HeaderBytes) != kFirstIpv6DataByte)
        {
            return false;
        }
        AwdlIpv6Data decoded {};
        if (parseAwdlIpv6Data(output.data(), written, decoded) != Result::Ok ||
            decoded.sequence != kInnerSequence ||
            decoded.header.sequence != kMacSequence ||
            !sameMac(decoded.header.source, source) ||
            !sameMac(decoded.header.destination, multicast) ||
            decoded.ipv6Bytes != ipv6.size() ||
            std::memcmp(usbByteOffset(output.data(), decoded.ipv6Offset),
                        ipv6.data(), ipv6.size()) != 0)
        {
            return false;
        }
        tx.qos = true;
        if (makeAwdlIpv6Data(tx, output.data(), output.size(), written) !=
                Result::Ok ||
            written != kDataFrameBytes + kQosBytes ||
            output.at(0U) != kQosType ||
            parseAwdlIpv6Data(output.data(), written, decoded) != Result::Ok ||
            decoded.header.subtype != kQosSubtype ||
            decoded.ipv6Offset !=
                kHeaderBytes + kSerializedDataHeaderBytes + kQosBytes)
        {
            return false;
        }
        output.fill(kOutputSentinel);
        if (makeAwdlIpv6Data(tx, output.data(), written - 1U, written) !=
                Result::BufferTooSmall ||
            written != 0U || output.at(0U) != kOutputSentinel)
        {
            return false;
        }
        tx.qos = false;
        tx.macSequence = kInvalidMacSequence;
        if (makeAwdlIpv6Data(tx, output.data(), output.size(), written) !=
            Result::InvalidFrame)
        {
            return false;
        }
        tx.macSequence = kMacSequence;
        tx.source.bytes[0U] = 0x03U;
        if (makeAwdlIpv6Data(tx, output.data(), output.size(), written) !=
            Result::InvalidAddress)
        {
            return false;
        }
        tx.source = source;
        tx.destination = {};
        if (makeAwdlIpv6Data(tx, output.data(), output.size(), written) !=
            Result::InvalidAddress)
        {
            return false;
        }
        tx.destination = multicast;
        ipv6.at(0U) = kWrongIpv6Version;
        if (makeAwdlIpv6Data(tx, output.data(), output.size(), written) !=
            Result::InvalidFrame)
        {
            return false;
        }
        ipv6.at(0U) = kIpv6Version;
        ipv6.at(kIpv6LengthLowOffset) = kIpv6PayloadLength + 1U;
        if (makeAwdlIpv6Data(tx, output.data(), output.size(), written) !=
            Result::Truncated)
        {
            return false;
        }
        ipv6.at(kIpv6LengthLowOffset) = kIpv6PayloadLength - 1U;
        if (makeAwdlIpv6Data(tx, output.data(), output.size(), written) !=
            Result::InvalidFrame)
        {
            return false;
        }
        ipv6.at(kIpv6LengthLowOffset) = kIpv6PayloadLength;
        tx.ipv6Bytes = kShortIpv6Header;
        if (makeAwdlIpv6Data(tx, output.data(), output.size(), written) !=
            Result::Truncated)
        {
            return false;
        }
        std::array<uint8_t, kMaxMpdu - kFcsBytes> oversizeIpv6 {};
        oversizeIpv6.at(0U) = kIpv6Version;
        tx.ipv6 = oversizeIpv6.data();
        tx.ipv6Bytes = oversizeIpv6.size();
        if (makeAwdlIpv6Data(tx, output.data(), output.size(), written) !=
            Result::InvalidFrame)
        {
            return false;
        }
        tx.ipv6Bytes = ipv6.size();
        tx.ipv6 = nullptr;
        if (makeAwdlIpv6Data(tx, output.data(), output.size(), written) !=
            Result::NullBuffer)
        {
            return false;
        }
        tx.ipv6 = ipv6.data();
        written = kCountSentinel;
        if (makeAwdlIpv6Data(tx, ipv6.data(), ipv6.size(), written) !=
                Result::OverlappingBuffers ||
            written != kCountSentinel || ipv6.at(0U) != kIpv6Version)
        {
            return false;
        }
        // Even a failed output-size check must not reset a length field
        // stored inside the caller's live request descriptor.
        const size_t originalLength = tx.ipv6Bytes;
        if (makeAwdlIpv6Data(tx, output.data(), output.size(), tx.ipv6Bytes) !=
                Result::OverlappingBuffers ||
            tx.ipv6Bytes != originalLength)
        {
            return false;
        }
        return output.at(0U) == kOutputSentinel;
    }

    bool serializeAwdlIpv6LengthBoundaries()
    {
        constexpr size_t kMpduWithFcsBytes = 2346U;
        constexpr size_t kFcsBytes = 4U;
        constexpr size_t kMacHeaderBytes = 24U;
        constexpr size_t kAwdlDataHeaderBytes = 16U;
        constexpr size_t kQosHeaderBytes = 2U;
        constexpr size_t kIpv6HeaderBytes = 40U;
        constexpr size_t kIpv6LengthHighOffset = 4U;
        constexpr size_t kIpv6LengthLowOffset = 5U;
        constexpr uint8_t kIpv6Version = 0x60U;
        constexpr uint8_t kIpv6PayloadLengthShift = 8U;
        constexpr size_t kMaxNormalIpv6 = kMpduWithFcsBytes - kFcsBytes -
                                          kMacHeaderBytes -
                                          kAwdlDataHeaderBytes;
        constexpr size_t kMaxQosIpv6 = kMaxNormalIpv6 - kQosHeaderBytes;
        std::array<uint8_t, kMaxNormalIpv6 + 1U> ipv6 {};
        ipv6.at(0U) = kIpv6Version;
        const Mac source {{0x02U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U}};
        const Mac destination {{0x02U, 0xaaU, 0xbbU, 0xccU, 0xddU, 0xeeU}};
        AwdlIpv6Tx request {
            source, destination, 0U, 0U, false, ipv6.data(), kMaxNormalIpv6,
        };
        std::array<uint8_t, kMpduWithFcsBytes> output {};
        const auto setIpv6Length = [&ipv6](size_t packetBytes)
        {
            const size_t payloadBytes = packetBytes - kIpv6HeaderBytes;
            ipv6.at(kIpv6LengthHighOffset) =
                static_cast<uint8_t>(payloadBytes >> kIpv6PayloadLengthShift);
            ipv6.at(kIpv6LengthLowOffset) = static_cast<uint8_t>(payloadBytes);
        };
        setIpv6Length(kMaxNormalIpv6);
        size_t written = 0U;
        AwdlIpv6Data parsed {};
        if (makeAwdlIpv6Data(request, output.data(), output.size(), written) !=
                Result::Ok ||
            written != kMpduWithFcsBytes - kFcsBytes ||
            parseAwdlIpv6Data(output.data(), written, parsed) != Result::Ok ||
            parsed.ipv6Bytes != kMaxNormalIpv6)
        {
            return false;
        }
        request.qos = true;
        if (makeAwdlIpv6Data(request, output.data(), output.size(), written) !=
            Result::InvalidFrame)
        {
            return false;
        }
        request.ipv6Bytes = kMaxQosIpv6;
        setIpv6Length(kMaxQosIpv6);
        if (makeAwdlIpv6Data(request, output.data(), output.size(), written) !=
                Result::Ok ||
            written != kMpduWithFcsBytes - kFcsBytes ||
            parseAwdlIpv6Data(output.data(), written, parsed) != Result::Ok ||
            parsed.ipv6Bytes != kMaxQosIpv6)
        {
            return false;
        }
        request.qos = false;
        request.ipv6Bytes = kMaxNormalIpv6 + 1U;
        setIpv6Length(request.ipv6Bytes);
        if (makeAwdlIpv6Data(request, output.data(), output.size(), written) !=
            Result::InvalidFrame)
        {
            return false;
        }
        // The written count must not be stored in a caller-owned output
        // span; even error-path clearing of such storage is disallowed.
        constexpr size_t kCountStorageWords = 64U;
        std::array<size_t, kCountStorageWords> words {};
        constexpr size_t kCountSentinel = 123U;
        words.at(0U) = kCountSentinel;
        uint8_t *wordBytes = nullptr;
        const void *wordsAddress = words.data();
        static_assert(sizeof(wordBytes) == sizeof(wordsAddress),
                      "pointer representation width");
        __builtin_memcpy(static_cast<void *>(&wordBytes),
                         static_cast<const void *>(&wordsAddress),
                         sizeof(wordBytes));
        request.ipv6Bytes = kMaxQosIpv6;
        setIpv6Length(kMaxQosIpv6);
        return makeAwdlIpv6Data(request, wordBytes, sizeof(words),
                                words.at(0U)) == Result::OverlappingBuffers &&
               words.at(0U) == kCountSentinel;
    }

    bool serializeAwdlAction()
    {
        constexpr uint16_t kNonzeroMacSequence = 0x0abcU;
        constexpr uint8_t kUnsupportedActionSubtype = 0x04U;
        constexpr uint8_t kInvalidSourceFirstOctet = 0x03U;
        constexpr uint8_t kBadTlvLength = 0xffU;
        constexpr uint8_t kUntouchedByte = 0xa5U;
        constexpr size_t kAdditionalSpace = 2U;
        constexpr size_t kActionTlvsBytes = kFirstTlvBytes + kSecondTlvBytes;
        const Packet expected = makeAwdl();
        const Mac source {{0x02U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U}};
        const Mac broadcast {{0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU}};
        std::array<uint8_t, kActionTlvsBytes> tlvs {};
        __builtin_memcpy(tlvs.data(),
                         usbByteOffset(expected.data(), kPayloadStart),
                         tlvs.size());
        AwdlActionTx tx {
            source,   broadcast,   0U,          0U,
            kPhyTime, kTargetTime, tlvs.data(), tlvs.size(),
        };
        std::array<uint8_t, kPacketBytes + kAdditionalSpace> output {};
        output.fill(kUntouchedByte);
        size_t written = 0U;
        if (makeAwdlAction(tx, output.data(), output.size(), written) !=
                Result::Ok ||
            written != expected.size() ||
            std::memcmp(output.data(), expected.data(), expected.size()) != 0 ||
            output.at(written) != kUntouchedByte)
        {
            return false;
        }
        tx.subtype = kMifSubtype;
        tx.macSequence = kNonzeroMacSequence;
        AwdlAction parsed {};
        if (makeAwdlAction(tx, output.data(), output.size(), written) !=
                Result::Ok ||
            parseAwdlAction(output.data(), written, parsed) != Result::Ok ||
            parsed.subtype != kMifSubtype ||
            parsed.header.sequence != kNonzeroMacSequence ||
            parsed.phyTransmitUsec != kPhyTime ||
            parsed.targetTransmitUsec != kTargetTime || parsed.tlvCount != 2U ||
            !sameMac(parsed.header.source, source) ||
            !sameMac(parsed.header.destination, broadcast))
        {
            return false;
        }
        output.fill(kUntouchedByte);
        if (makeAwdlAction(tx, output.data(), written - 1U, written) !=
                Result::BufferTooSmall ||
            written != 0U || output.at(0U) != kUntouchedByte)
        {
            return false;
        }
        tx.subtype = kUnsupportedActionSubtype;
        if (makeAwdlAction(tx, output.data(), output.size(), written) !=
            Result::UnsupportedFrame)
        {
            return false;
        }
        tx.subtype = kMifSubtype;
        tx.source.bytes[0U] = kInvalidSourceFirstOctet;
        if (makeAwdlAction(tx, output.data(), output.size(), written) !=
            Result::InvalidAddress)
        {
            return false;
        }
        tx.source = source;
        tx.destination = {};
        if (makeAwdlAction(tx, output.data(), output.size(), written) !=
            Result::InvalidAddress)
        {
            return false;
        }
        tx.destination = broadcast;
        tlvs.at(1U) = kBadTlvLength;
        if (makeAwdlAction(tx, output.data(), output.size(), written) !=
            Result::InvalidElement)
        {
            return false;
        }
        tlvs.at(1U) = kFirstTlvBytes - 3U;
        tx.tlvBytes = 0U;
        if (makeAwdlAction(tx, output.data(), output.size(), written) !=
            Result::InvalidElement)
        {
            return false;
        }
        tx.tlvBytes = tlvs.size();
        tx.tlvs = nullptr;
        if (makeAwdlAction(tx, output.data(), output.size(), written) !=
            Result::NullBuffer)
        {
            return false;
        }
        tx.tlvs = tlvs.data();
        constexpr size_t kAliasedCountSentinel = 123U;
        written = kAliasedCountSentinel;
        if (makeAwdlAction(tx, tlvs.data(), tlvs.size(), written) !=
                Result::OverlappingBuffers ||
            written != kAliasedCountSentinel || tlvs.at(0U) != kFirstTlvType)
        {
            return false;
        }
        const size_t originalTlvSize = tx.tlvBytes;
        return makeAwdlAction(tx, output.data(), output.size(), tx.tlvBytes) ==
                   Result::OverlappingBuffers &&
               tx.tlvBytes == originalTlvSize;
    }

} // namespace

int main()
{
    if (!validActionAndIteration())
    {
        return 1;
    }
    if (!rejectNonAwdlAndFragments())
    {
        return 2;
    }
    if (!rejectTruncationAndAliasing())
    {
        return 3;
    }
    if (!acceptPadding())
    {
        return 4;
    }
    if (!acceptAwdlIpv6Data())
    {
        return kAwdlDataFailure;
    }
    if (!serializeAwdlIpv6Data())
    {
        constexpr int kTxFailure = 6;
        return kTxFailure;
    }
    if (!serializeAwdlIpv6LengthBoundaries())
    {
        constexpr int kTxBoundaryFailure = 7;
        return kTxBoundaryFailure;
    }
    if (!serializeAwdlAction())
    {
        constexpr int kActionTxFailure = 8;
        return kActionTxFailure;
    }
    return 0;
}
