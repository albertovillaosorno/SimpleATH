// SPDX-License-Identifier: GPL-2.0-only
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
        // A zero destination cannot be delivered as a real AWDL MIF or
        // PSF, even if the source, BSSID and TLVs otherwise parse correctly.
        frame = makeAwdl();
        for (size_t index = 4U; index < kSourceOffset; ++index)
        {
            frame.at(index) = 0U;
        }
        if (parseAwdlAction(frame.data(), frame.size(), action) !=
                Result::InvalidAddress ||
            action.tlvCount != 0U)
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
        // QoS Control bit 7 declares an A-MSDU, whose subframe payload
        // cannot be interpreted as a directly encapsulated IPv6 MSDU.
        constexpr uint8_t kAmsduPresent = 0x80U;
        qos.at(kHeaderBytes) = kAmsduPresent;
        if (parseAwdlIpv6Data(qos.data(), qos.size(), decoded) !=
                Result::UnsupportedFrame ||
            decoded.ipv6Bytes != 0U)
        {
            return false;
        }
        qos.at(kHeaderBytes) = 0U;
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
        if (parseAwdlIpv6Data(frame.data(), frame.size(), decoded) !=
            Result::UnsupportedFrame)
        {
            return false;
        }
        // A single non-aggregated 802.11 MPDU must not bypass the same
        // FCS-including 2346-octet bound enforced by the TX serializer.
        constexpr size_t kMaxMpduWithoutFcs = 2342U;
        std::array<uint8_t, kMaxMpduWithoutFcs + 1U> oversized {};
        frame.at(kFragmentOffset) = 0U;
        for (size_t index = 0U; index < frame.size(); ++index)
        {
            oversized.at(index) = frame.at(index);
        }
        const size_t excessIpv6Payload =
            oversized.size() - ipv6Offset - kIpv6Bytes;
        constexpr uint8_t kByteShift = 8U;
        oversized.at(ipv6Offset + 4U) =
            static_cast<uint8_t>(excessIpv6Payload >> kByteShift);
        oversized.at(ipv6Offset + kIpv6LengthLowOffset) =
            static_cast<uint8_t>(excessIpv6Payload);
        return parseAwdlIpv6Data(oversized.data(), oversized.size(), decoded) ==
                   Result::InvalidFrame &&
               decoded.ipv6Bytes == 0U;
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

    constexpr size_t kNeighborFrameCapacity = 256U;
    constexpr size_t kNeighborTlvCapacity = 128U;
    constexpr size_t kNeighborSyncBytes = 31U;
    constexpr size_t kNeighborChannelBytes = 25U;
    constexpr size_t kNeighborElectionBytes = 40U;
    constexpr size_t kNeighborIpv6Bytes = 40U;
    constexpr size_t kNeighborDataBytes = 80U;
    constexpr size_t kNeighborMacLast = 5U;
    constexpr size_t kNeighborSyncPeriodOffset = 5U;
    constexpr size_t kNeighborSyncNextSeqLow = 29U;
    constexpr size_t kNeighborSyncNextSeqHigh = 30U;
    constexpr uint8_t kNeighborSeqLow = 0x34U;
    constexpr uint8_t kNeighborSeqHigh = 0x12U;
    constexpr uint16_t kNeighborNextAwSeq = 0x1234U;
    constexpr size_t kNeighborElectionMasterMetricOffset = 20U;
    constexpr size_t kNeighborElectionOwnMetricOffset = 24U;
    constexpr size_t kNeighborElectionOwnCounterOffset = 36U;
    constexpr size_t kNeighborElectionReservedOffset = 28U;
    constexpr size_t kNeighborSlotTen = 10U;
    constexpr size_t kNeighborSlotCount = 16U;
    constexpr size_t kNeighborTlvHeader = 3U;
    constexpr size_t kNeighborChannelOffset = 6U;
    constexpr size_t kNeighborSyncMacOffset = 21U;
    constexpr size_t kNeighborElectionMacOffset = 0U;
    constexpr size_t kNeighborSlotMask = (1U << 0U) | (1U << kNeighborSlotTen);
    constexpr uint64_t kNeighborFirstSeenMs = 1000U;
    constexpr uint64_t kNeighborJustAliveMs =
        kNeighborFirstSeenMs + AwdlNeighbors::kExpiryMs - 1U;
    constexpr uint64_t kNeighborExpiredMs =
        kNeighborFirstSeenMs + AwdlNeighbors::kExpiryMs;
    constexpr uint8_t kNeighborSourceLast = 0x55U;
    constexpr Mac kNeighborBaseSource {
        {
            0x02U,
            0x11U,
            0x22U,
            0x33U,
            0x44U,
            kNeighborSourceLast,
        },
    };
    constexpr uint8_t kNeighborVersion = 0x10U;
    constexpr uint8_t kNeighborClassMac = 1U;
    constexpr uint8_t kNeighborSocialChannel = 6U;
    constexpr uint8_t kNeighborOtherChannel = 149U;
    constexpr uint8_t kNeighborElectionMetric = 60U;
    constexpr uint8_t kNeighborElectionOwnMetric = 61U;
    constexpr uint8_t kNeighborElectionCounter = 7U;
    constexpr uint8_t kNeighborTlvVersion = 21U;
    constexpr uint8_t kNeighborTlvSync = 4U;
    constexpr uint8_t kNeighborTlvChannel = 18U;
    constexpr uint8_t kNeighborTlvElection = 24U;
    constexpr uint8_t kNeighborTlvUnknown = 250U;
    constexpr uint8_t kNeighborChannelStep = 3U;
    constexpr uint8_t kNeighborChannelSlotsMinusOne = 15U;
    enum class NeighborEncoding : uint8_t
    {
        Legacy = 1U,
        OperatingClass = 3U,
    };
    constexpr uint8_t kNeighborOpClass24Ghz = 81U;
    constexpr uint8_t kNeighborOpClass5Ghz = 124U;
    constexpr size_t kNeighborChannelEncodingOffset = 1U;
    constexpr size_t kNeighborExtraChannelBytes = 16U;
    constexpr uint8_t kNeighborIpv6Version = 0x60U;
    constexpr uint8_t kNeighborMif = 3U;
    constexpr uint8_t kNeighborPsf = 0U;
    using NeighborBytes = std::array<uint8_t, kNeighborFrameCapacity>;
    using NeighborTlvs = std::array<uint8_t, kNeighborTlvCapacity>;

    struct NeighborFixture
    {
            NeighborBytes frame {};
            size_t length {};
            size_t syncOffset {};
            size_t channelOffset {};
            size_t electionOffset {};
            size_t versionOffset {};
            size_t unknownOffset {};
            Mac source {};
    };

    template <size_t N>
    void appendNeighborTlv(NeighborTlvs &bytes, size_t &used, uint8_t type,
                           const std::array<uint8_t, N> &value,
                           size_t &valueOffset)
    {
        const size_t start = used;
        bytes.at(start) = type;
        bytes.at(start + 1U) = static_cast<uint8_t>(value.size());
        bytes.at(start + 2U) = 0U;
        used += kNeighborTlvHeader;
        valueOffset = used;
        for (size_t index = 0U; index < value.size(); ++index)
        {
            bytes.at(used + index) = value.at(index);
        }
        used += value.size();
    }

    NeighborFixture makeNeighborFixture(uint8_t lastOctet)
    {
        NeighborFixture result {};
        result.source = kNeighborBaseSource;
        result.source.bytes[kNeighborMacLast] = lastOctet;
        NeighborTlvs tlvs {};
        size_t used = 0U;
        std::array<uint8_t, kNeighborSyncBytes> sync {};
        sync.at(1U) = kNeighborChannelStep;
        sync.at(kNeighborSyncPeriodOffset) = kNeighborSlotCount;
        std::memcpy(&sync.at(kNeighborSyncMacOffset), &result.source.bytes,
                    kMacAddressBytes);
        sync.at(kNeighborSyncNextSeqLow) = kNeighborSeqLow;
        sync.at(kNeighborSyncNextSeqHigh) = kNeighborSeqHigh;
        appendNeighborTlv(tlvs, used, kNeighborTlvSync, sync,
                          result.syncOffset);

        std::array<uint8_t, kNeighborChannelBytes> channels {};
        channels.at(0U) = kNeighborChannelSlotsMinusOne;
        channels.at(3U) = kNeighborChannelStep;
        channels.at(4U) = kBroadcast;
        channels.at(kNeighborSyncPeriodOffset) = kBroadcast;
        for (size_t index = 0U; index < kNeighborSlotCount; ++index)
        {
            channels.at(kNeighborChannelOffset + index) =
                index == 0U || index == kNeighborSlotTen
                    ? kNeighborSocialChannel
                    : kNeighborOtherChannel;
        }
        appendNeighborTlv(tlvs, used, kNeighborTlvChannel, channels,
                          result.channelOffset);

        std::array<uint8_t, kNeighborElectionBytes> election {};
        std::memcpy(&election.at(kNeighborElectionMacOffset),
                    &result.source.bytes, kMacAddressBytes);
        election.at(kNeighborElectionMasterMetricOffset) =
            kNeighborElectionMetric;
        election.at(kNeighborElectionOwnMetricOffset) =
            kNeighborElectionOwnMetric;
        election.at(kNeighborElectionOwnCounterOffset) =
            kNeighborElectionCounter;
        appendNeighborTlv(tlvs, used, kNeighborTlvElection, election,
                          result.electionOffset);

        const std::array<uint8_t, 2U> version {
            kNeighborVersion,
            kNeighborClassMac,
        };
        appendNeighborTlv(tlvs, used, kNeighborTlvVersion, version,
                          result.versionOffset);
        const std::array<uint8_t, 2U> unknown {0xaaU, 0xbbU};
        appendNeighborTlv(tlvs, used, kNeighborTlvUnknown, unknown,
                          result.unknownOffset);
        const Mac multicast {{0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU}};
        const AwdlActionTx request {
            result.source, multicast, 0U, kNeighborMif, 0U, 0U,
            tlvs.data(),   used,
        };
        if (makeAwdlAction(request, result.frame.data(), result.frame.size(),
                           result.length) != Result::Ok)
        {
            result.length = 0U;
        }
        result.syncOffset += kPayloadStart;
        result.channelOffset += kPayloadStart;
        result.electionOffset += kPayloadStart;
        result.versionOffset += kPayloadStart;
        result.unknownOffset += kPayloadStart;
        return result;
    }

    // Promote a valid simple 16-slot TLV to a two-byte-per-slot encoding.
    // Shift subsequent TLVs before expanding backwards, preserving their
    // offsets and avoiding reserialization of the control frame under test.
    void expandNeighborChannels(NeighborFixture &fixture,
                                NeighborEncoding encoding, uint8_t opClass)
    {
        const size_t oldEnd = fixture.channelOffset + kNeighborChannelBytes;
        for (size_t cursor = fixture.length; cursor > oldEnd; --cursor)
        {
            fixture.frame.at(cursor + kNeighborExtraChannelBytes - 1U) =
                fixture.frame.at(cursor - 1U);
        }
        for (size_t slot = kNeighborSlotCount; slot > 0U; --slot)
        {
            const size_t index = slot - 1U;
            const uint8_t channel = fixture.frame.at(
                fixture.channelOffset + kNeighborChannelOffset + index);
            const size_t first =
                fixture.channelOffset + kNeighborChannelOffset + (2U * index);
            if (encoding == NeighborEncoding::Legacy)
            {
                fixture.frame.at(first) = 0U;
                fixture.frame.at(first + 1U) = channel;
            }
            else
            {
                fixture.frame.at(first) = channel;
                fixture.frame.at(first + 1U) = opClass;
            }
        }
        const size_t padding = fixture.channelOffset + kNeighborChannelOffset +
                               (2U * kNeighborSlotCount);
        for (size_t index = 0U; index < kNeighborTlvHeader; ++index)
        {
            fixture.frame.at(padding + index) = 0U;
        }
        fixture.frame.at(fixture.channelOffset - 2U) = static_cast<uint8_t>(
            kNeighborChannelBytes + kNeighborExtraChannelBytes);
        fixture.frame.at(fixture.channelOffset +
                         kNeighborChannelEncodingOffset) =
            static_cast<uint8_t>(encoding);
        fixture.electionOffset += kNeighborExtraChannelBytes;
        fixture.versionOffset += kNeighborExtraChannelBytes;
        fixture.unknownOffset += kNeighborExtraChannelBytes;
        fixture.length += kNeighborExtraChannelBytes;
    }

    bool serializeChannelSixMif()
    {
        constexpr uint16_t kLocalMacSequence = 0x123U;
        constexpr size_t kMifFourTlvs = 4U;
        constexpr size_t kLocalMifBytes =
            kHeaderBytes + kActionBytes + (kNeighborTlvHeader * kMifFourTlvs) +
            kNeighborSyncBytes + kNeighborChannelBytes +
            kNeighborElectionBytes + 2U;
        constexpr uint8_t kNonzeroSentinel = 0xa7U;
        constexpr uint16_t kTooLongDownCounter = 65U;
        const AwdlLocalMifTx valid {
            kNeighborBaseSource,
            kNeighborBaseSource,
            kNeighborBaseSource,
            kLocalMacSequence,
            kNeighborChannelStep,
            kNeighborNextAwSeq,
            kNeighborSlotMask,
            kPhyTime,
            kTargetTime,
            kNeighborElectionMetric,
            kNeighborElectionCounter,
            kNeighborElectionOwnMetric,
            kNeighborElectionCounter,
        };
        std::array<uint8_t, kLocalMifBytes> output {};
        size_t written = 0U;
        if (makeAwdlChannelSixMif(valid, output.data(), output.size(),
                                  written) != Result::Ok ||
            written != kLocalMifBytes)
        {
            return false;
        }
        AwdlAction parsed {};
        AwdlNeighbors neighbors {};
        AwdlNeighbor observed {};
        if (parseAwdlAction(output.data(), written, parsed) != Result::Ok ||
            parsed.tlvCount != kMifFourTlvs || parsed.subtype != kNeighborMif ||
            parsed.phyTransmitUsec != kPhyTime ||
            parsed.targetTransmitUsec != kTargetTime ||
            neighbors.observeMif(kNeighborFirstSeenMs, output.data(),
                                 written) != Result::Ok ||
            !neighbors.find(valid.source, kNeighborFirstSeenMs, observed) ||
            observed.channelSixSlots != kNeighborSlotMask ||
            observed.txDownCounterTu != kNeighborChannelStep ||
            observed.nextAwSequence != kNeighborNextAwSeq ||
            observed.masterMetric != kNeighborElectionMetric ||
            observed.ownMetric != kNeighborElectionOwnMetric ||
            observed.masterCounter != kNeighborElectionCounter ||
            observed.ownCounter != kNeighborElectionCounter ||
            !sameMac(observed.syncMaster, valid.syncMaster) ||
            !sameMac(observed.electionMaster, valid.electionMaster))
        {
            return false;
        }
        // Verify unselected channel slots are reserved-zero rather than
        // advertising an unimplemented 5-GHz AR9565 radio channel.
        AwdlTlvs tlvs(usbByteOffset(output.data(), parsed.tlvOffset),
                      written - parsed.tlvOffset);
        AwdlTlv element {};
        if (tlvs.next(element) != AwdlTlvStatus::Element ||
            element.type != kNeighborTlvSync ||
            tlvs.next(element) != AwdlTlvStatus::Element ||
            element.type != kNeighborTlvChannel)
        {
            return false;
        }
        for (size_t slot = 0U; slot < kNeighborSlotCount; ++slot)
        {
            const uint8_t expected =
                (kNeighborSlotMask & (uint32_t {1U} << slot)) != 0U
                    ? kNeighborSocialChannel
                    : 0U;
            if (*usbByteOffset(element.data, kNeighborChannelOffset + slot) !=
                expected)
            {
                return false;
            }
        }
        AwdlLocalMifTx invalid = valid;
        output.fill(kNonzeroSentinel);
        invalid.channelSixSlots = 0U;
        written = kLocalMifBytes;
        if (makeAwdlChannelSixMif(invalid, output.data(), output.size(),
                                  written) != Result::InvalidElement ||
            written != 0U || output.at(0U) != kNonzeroSentinel)
        {
            return false;
        }
        invalid = valid;
        invalid.txDownCounterTu = kTooLongDownCounter;
        if (makeAwdlChannelSixMif(invalid, output.data(), output.size(),
                                  written) != Result::InvalidElement ||
            written != 0U || output.at(0U) != kNonzeroSentinel)
        {
            return false;
        }
        invalid = valid;
        invalid.syncMaster = {};
        if (makeAwdlChannelSixMif(invalid, output.data(), output.size(),
                                  written) != Result::InvalidAddress ||
            written != 0U || output.at(0U) != kNonzeroSentinel)
        {
            return false;
        }
        return makeAwdlChannelSixMif(valid, output.data(), output.size() - 1U,
                                     written) == Result::BufferTooSmall &&
               written == 0U && output.at(0U) == kNonzeroSentinel;
    }

    bool rejectsOutOfRangeMifCountdown(AwdlNeighbors &peers,
                                       NeighborFixture fixture)
    {
        // A sync TLV's EAW countdown must fit 1..64 TU.
        constexpr uint8_t kTooLongDownCounterTu = 65U;
        constexpr uint8_t kMaxValidDownCounterTu = 64U;
        fixture.frame.at(fixture.syncOffset + 1U) = 0U;
        if (peers.observeMif(kNeighborFirstSeenMs + 1U, fixture.frame.data(),
                             fixture.length) != Result::InvalidElement)
        {
            return false;
        }
        fixture.frame.at(fixture.syncOffset + 1U) = kTooLongDownCounterTu;
        if (peers.observeMif(kNeighborFirstSeenMs + 1U, fixture.frame.data(),
                             fixture.length) != Result::InvalidElement)
        {
            return false;
        }
        fixture.frame.at(fixture.syncOffset + 1U) = kMaxValidDownCounterTu;
        return peers.observeMif(kNeighborFirstSeenMs + 1U, fixture.frame.data(),
                                fixture.length) == Result::Ok;
    }

    bool channelSixRendezvousCandidates()
    {
        constexpr uint64_t kUsecPerMs = 1000U;
        constexpr uint64_t kMifRxUsec = kNeighborFirstSeenMs * kUsecPerMs;
        constexpr uint64_t kTuUsec = 1024U;
        constexpr uint64_t kAwUsec = 16U * kTuUsec;
        constexpr uint64_t kEawUsec = 4U * kAwUsec;
        constexpr uint64_t kDownCounterUsec = kAwUsec;
        constexpr uint64_t kGuardUsec = 3U * kTuUsec;
        constexpr uint32_t kAirtimeUsec = 512U;
        constexpr uint16_t kFirstSlotBaseAw = 0U;
        constexpr uint16_t kOtherSlotBaseAw = 4U;
        constexpr uint16_t kTenthSlotBaseAw = 40U;
        constexpr uint16_t kTenthSlotLastAw = 43U;
        constexpr uint16_t kWrapBaseAw = 0xfffcU;
        constexpr uint16_t kWrapSlot = 15U;
        constexpr uint16_t kFullAwDownCounterTu = 16U;
        constexpr auto kOversizeAirtimeUsec =
            static_cast<uint32_t>(kEawUsec - (2U * kGuardUsec) + 1U);
        constexpr uint64_t kNearBoundaryUsec =
            kMifRxUsec + kDownCounterUsec - kGuardUsec - kAirtimeUsec;
        NeighborFixture fixture = makeNeighborFixture(kNeighborSourceLast);
        AwdlNeighbors peers {};
        AwdlNeighbor peer {};
        if (peers.observeMif(kNeighborFirstSeenMs, fixture.frame.data(),
                             fixture.length) != Result::Ok ||
            !peers.find(fixture.source, kNeighborFirstSeenMs, peer))
        {
            return false;
        }
        // A channel-sequence slot contains four AWs. The MIF countdown is
        // to the next *extended* AW (64 TU), not to the next 16-TU AW.
        peer.nextAwSequence = kFirstSlotBaseAw;
        peer.txDownCounterTu = kFullAwDownCounterTu;
        AwdlRendezvousRequest request {
            kMifRxUsec,
            kMifRxUsec + kGuardUsec,
            kAirtimeUsec,
        };
        AwdlRendezvousWindow window {};
        if (planAwdlChannelSixRendezvous(peer, request, window) !=
                AwdlRendezvousStatus::Candidate ||
            window.awSequence != 3U || window.channelSlot != 0U ||
            window.remainingEawUsec != kDownCounterUsec - kGuardUsec)
        {
            return false;
        }
        // A new EAW changes channel slot. Guard both sides and ensure that
        // the declared entire airtime leaves room for the final guard.
        peer.channelSixSlots =
            static_cast<uint16_t>(static_cast<uint32_t>(peer.channelSixSlots) |
                                  (uint32_t {1U} << 1U));
        request.nowUsec = kMifRxUsec + kDownCounterUsec;
        if (planAwdlChannelSixRendezvous(peer, request, window) !=
                AwdlRendezvousStatus::GuardInterval ||
            window.remainingEawUsec != 0U)
        {
            return false;
        }
        request.nowUsec += kGuardUsec - 1U;
        if (planAwdlChannelSixRendezvous(peer, request, window) !=
            AwdlRendezvousStatus::GuardInterval)
        {
            return false;
        }
        request.nowUsec = kMifRxUsec + kDownCounterUsec + kGuardUsec;
        if (planAwdlChannelSixRendezvous(peer, request, window) !=
                AwdlRendezvousStatus::Candidate ||
            window.awSequence != kOtherSlotBaseAw || window.channelSlot != 1U)
        {
            return false;
        }
        request.nowUsec = kNearBoundaryUsec;
        if (planAwdlChannelSixRendezvous(peer, request, window) !=
            AwdlRendezvousStatus::Candidate)
        {
            return false;
        }
        ++request.nowUsec;
        if (planAwdlChannelSixRendezvous(peer, request, window) !=
                AwdlRendezvousStatus::GuardInterval ||
            window.remainingEawUsec != 0U)
        {
            return false;
        }
        // A correctly phased but unadvertised peer cannot be scheduled.
        request.nowUsec = kMifRxUsec + kGuardUsec;
        peer.channelSixSlots = kNeighborSlotMask;
        peer.nextAwSequence = kOtherSlotBaseAw;
        if (planAwdlChannelSixRendezvous(peer, request, window) !=
            AwdlRendezvousStatus::PeerOffChannel)
        {
            return false;
        }
        peer.nextAwSequence = kTenthSlotBaseAw;
        if (planAwdlChannelSixRendezvous(peer, request, window) !=
                AwdlRendezvousStatus::Candidate ||
            window.channelSlot != kNeighborSlotTen ||
            window.awSequence != kTenthSlotLastAw)
        {
            return false;
        }
        peer.channelSixSlots = 0U;
        if (planAwdlChannelSixRendezvous(peer, request, window) !=
            AwdlRendezvousStatus::PeerOffChannel)
        {
            return false;
        }
        // End of the 16-bit AW sequence wraps on the next EAW boundary.
        peer.nextAwSequence = kWrapBaseAw;
        peer.channelSixSlots = 1U << kWrapSlot;
        if (planAwdlChannelSixRendezvous(peer, request, window) !=
                AwdlRendezvousStatus::Candidate ||
            window.awSequence != UINT16_MAX || window.channelSlot != kWrapSlot)
        {
            return false;
        }
        // IPv6 refresh preserves peer lifetime but cannot extend last MIF
        // timing or impersonate a new synchronization sample.
        peer.lastHeardMs = kNeighborFirstSeenMs + 1U;
        if (planAwdlChannelSixRendezvous(peer, request, window) !=
            AwdlRendezvousStatus::Candidate)
        {
            return false;
        }
        peer.lastMifMs = kNeighborFirstSeenMs + 1U;
        if (planAwdlChannelSixRendezvous(peer, request, window) !=
            AwdlRendezvousStatus::InvalidInput)
        {
            return false;
        }
        peer.lastMifMs = kNeighborFirstSeenMs;
        request.nowUsec = kMifRxUsec - 1U;
        if (planAwdlChannelSixRendezvous(peer, request, window) !=
            AwdlRendezvousStatus::StaleSync)
        {
            return false;
        }
        request.nowUsec = kMifRxUsec + (AwdlNeighbors::kExpiryMs * kUsecPerMs);
        if (planAwdlChannelSixRendezvous(peer, request, window) !=
            AwdlRendezvousStatus::StaleSync)
        {
            return false;
        }
        request.nowUsec = kMifRxUsec + kGuardUsec;
        request.frameAirtimeUsec = 0U;
        if (planAwdlChannelSixRendezvous(peer, request, window) !=
            AwdlRendezvousStatus::InvalidInput)
        {
            return false;
        }
        request.frameAirtimeUsec = kOversizeAirtimeUsec;
        if (planAwdlChannelSixRendezvous(peer, request, window) !=
            AwdlRendezvousStatus::InvalidInput)
        {
            return false;
        }
        return rejectsOutOfRangeMifCountdown(peers, fixture);
    }

    bool nextChannelSixRendezvousCandidates()
    {
        constexpr uint64_t kUsecPerMs = 1000U;
        constexpr uint64_t kMifUsec = kNeighborFirstSeenMs * kUsecPerMs;
        constexpr uint64_t kTuUsec = 1024U;
        constexpr uint64_t kGuardUsec = 3U * kTuUsec;
        constexpr uint64_t kEawUsec = 64U * kTuUsec;
        constexpr uint64_t kUntilEawUsec = 16U * kTuUsec;
        constexpr uint32_t kAirtimeUsec = 512U;
        constexpr uint32_t kLongAirtimeUsec = 4096U;
        constexpr uint32_t kFirstTwoChannels = 3U;
        constexpr uint32_t kFirstThreeChannels = 7U;
        constexpr uint16_t kDownCounterTu = 16U;
        constexpr uint16_t kWrapBaseAw = 0xfffcU;
        constexpr uint8_t kWrapSlot = 15U;
        constexpr uint16_t kTenthBaseAw = 40U;
        constexpr uint32_t kTenthEaw = 10U;
        constexpr uint8_t kNextSlot = 1U;
        constexpr uint8_t kTenthSlot = 10U;
        constexpr uint32_t kSlotTenMask = uint32_t {1U} << kTenthSlot;
        constexpr uint32_t kMifLastUsec = AwdlNeighbors::kExpiryMs * kUsecPerMs;
        NeighborFixture fixture = makeNeighborFixture(kNeighborSourceLast);
        AwdlNeighbors neighbors {};
        AwdlNeighbor peer {};
        if (neighbors.observeMif(kNeighborFirstSeenMs, fixture.frame.data(),
                                 fixture.length) != Result::Ok ||
            !neighbors.find(fixture.source, kNeighborFirstSeenMs, peer))
        {
            return false;
        }
        peer.nextAwSequence = 0U;
        peer.txDownCounterTu = kDownCounterTu;
        peer.channelSixSlots = kFirstTwoChannels;
        AwdlRendezvousRequest request {
            kMifUsec,
            kMifUsec + kUntilEawUsec,
            kAirtimeUsec,
        };
        AwdlRendezvousWindow window {};
        // The next EAW begins with a 3-TU guard. The planner returns the
        // first usable instant, not the forbidden channel-switch boundary.
        if (planNextAwdlChannelSixRendezvous(peer, request, window) !=
                AwdlRendezvousStatus::Candidate ||
            window.channelSlot != kNextSlot || window.awSequence != 4U ||
            window.waitUsec != kGuardUsec ||
            window.remainingEawUsec != kEawUsec - kGuardUsec)
        {
            return false;
        }
        request.nowUsec += kGuardUsec;
        if (planNextAwdlChannelSixRendezvous(peer, request, window) !=
                AwdlRendezvousStatus::Candidate ||
            window.waitUsec != 0U || window.channelSlot != kNextSlot)
        {
            return false;
        }
        // Near the current slot's final guard, declared airtime no longer
        // fits; skip to the following advertised channel-six EAW.
        request.nowUsec = kMifUsec + kUntilEawUsec - (2U * kGuardUsec);
        request.frameAirtimeUsec = kLongAirtimeUsec;
        if (planNextAwdlChannelSixRendezvous(peer, request, window) !=
                AwdlRendezvousStatus::Candidate ||
            window.channelSlot != kNextSlot ||
            window.waitUsec != 3U * kGuardUsec)
        {
            return false;
        }
        // At the final guard itself, skip the EAW even for tiny frames;
        // the next EAW's guard must be subtracted before admitting data.
        peer.channelSixSlots = kFirstThreeChannels;
        request.nowUsec = kMifUsec + kUntilEawUsec + kEawUsec - kGuardUsec + 1U;
        request.frameAirtimeUsec = kAirtimeUsec;
        if (planNextAwdlChannelSixRendezvous(peer, request, window) !=
                AwdlRendezvousStatus::Candidate ||
            window.channelSlot != 2U ||
            window.waitUsec != (2U * kGuardUsec) - 1U)
        {
            return false;
        }
        // Only slot 10 is valid: the search must cross off-channel EAWs
        // but cannot re-label them as channel-six radio availability.
        peer.channelSixSlots = kSlotTenMask;
        request.nowUsec = kMifUsec;
        request.frameAirtimeUsec = kAirtimeUsec;
        if (planNextAwdlChannelSixRendezvous(peer, request, window) !=
                AwdlRendezvousStatus::Candidate ||
            window.channelSlot != kTenthSlot ||
            window.awSequence != kTenthBaseAw ||
            window.waitUsec != (kTenthEaw * kEawUsec) -
                                   (kEawUsec - kUntilEawUsec) + kGuardUsec)
        {
            return false;
        }
        peer.channelSixSlots = 0U;
        if (planNextAwdlChannelSixRendezvous(peer, request, window) !=
                AwdlRendezvousStatus::PeerOffChannel ||
            window.waitUsec != 0U)
        {
            return false;
        }
        peer.channelSixSlots = uint16_t {1U} << kWrapSlot;
        peer.nextAwSequence = kWrapBaseAw;
        request.nowUsec += kGuardUsec;
        if (planNextAwdlChannelSixRendezvous(peer, request, window) !=
                AwdlRendezvousStatus::Candidate ||
            window.channelSlot != kWrapSlot ||
            window.awSequence != UINT16_MAX || window.waitUsec != 0U)
        {
            return false;
        }
        // Both the immediate and future planner reject TX finishing at
        // the five-second MIF boundary, even after a data-lifetime refresh.
        request.nowUsec = kMifUsec + kMifLastUsec - kAirtimeUsec;
        if (planNextAwdlChannelSixRendezvous(peer, request, window) !=
                AwdlRendezvousStatus::StaleSync ||
            planAwdlChannelSixRendezvous(peer, request, window) !=
                AwdlRendezvousStatus::StaleSync ||
            window.waitUsec != 0U)
        {
            return false;
        }
        request.nowUsec = kMifUsec + kGuardUsec;
        peer.lastMifMs = kNeighborFirstSeenMs + 1U;
        return planNextAwdlChannelSixRendezvous(peer, request, window) ==
               AwdlRendezvousStatus::InvalidInput;
    }

    bool sharedChannelSixOverlap()
    {
        constexpr uint64_t kUsecPerMs = 1000U;
        constexpr uint64_t kMifUsec = kNeighborFirstSeenMs * kUsecPerMs;
        constexpr uint64_t kTuUsec = 1024U;
        constexpr uint64_t kGuardUsec = 3U * kTuUsec;
        constexpr uint64_t kEawUsec = 64U * kTuUsec;
        constexpr uint64_t kUntilEawUsec = 16U * kTuUsec;
        constexpr uint32_t kAirtimeUsec = 512U;
        constexpr uint16_t kCountdownTu = 16U;
        constexpr uint16_t kFirstSlot = 0U;
        constexpr uint16_t kSecondSlot = 1U;
        constexpr uint8_t kLocalMacLast = 0x56U;
        const NeighborFixture fixture =
            makeNeighborFixture(kNeighborSourceLast);
        AwdlNeighbors peers {};
        AwdlNeighbor peer {};
        if (peers.observeMif(kNeighborFirstSeenMs, fixture.frame.data(),
                             fixture.length) != Result::Ok ||
            !peers.find(fixture.source, kNeighborFirstSeenMs, peer))
        {
            return false;
        }
        peer.nextAwSequence = 0U;
        peer.txDownCounterTu = kCountdownTu;
        peer.channelSixSlots = uint16_t {1U} << kFirstSlot;
        AwdlNeighbor local = peer;
        local.source.bytes[kNeighborMacLast] = kLocalMacLast;
        const AwdlSharedRendezvousRequest request {
            kMifUsec,
            kMifUsec,
            kMifUsec + kGuardUsec,
            kAirtimeUsec,
        };
        AwdlSharedRendezvousWindow window {};
        if (planSharedAwdlChannelSixRendezvous(local, peer, request, window) !=
                AwdlRendezvousStatus::Candidate ||
            window.waitUsec != 0U || window.localChannelSlot != kFirstSlot ||
            window.peerChannelSlot != kFirstSlot ||
            window.localAwSequence != 3U || window.peerAwSequence != 3U ||
            window.usableUsec != kUntilEawUsec - (2U * kGuardUsec))
        {
            return false;
        }
        // A peer-only channel-six candidate is insufficient: the LOCAL
        // window must overlap within both sides' radio-switch guards.
        peer.channelSixSlots = uint16_t {1U} << kSecondSlot;
        if (planSharedAwdlChannelSixRendezvous(local, peer, request, window) !=
                AwdlRendezvousStatus::NoSharedWindow ||
            window.waitUsec != 0U || window.usableUsec != 0U)
        {
            return false;
        }
        local.channelSixSlots =
            static_cast<uint16_t>(static_cast<uint32_t>(local.channelSixSlots) |
                                  (uint32_t {1U} << kSecondSlot));
        return planSharedAwdlChannelSixRendezvous(local, peer, request,
                                                  window) ==
                   AwdlRendezvousStatus::Candidate &&
               window.waitUsec == kUntilEawUsec &&
               window.localChannelSlot == kSecondSlot &&
               window.peerChannelSlot == kSecondSlot &&
               window.localAwSequence == 4U && window.peerAwSequence == 4U &&
               window.usableUsec == kEawUsec - (2U * kGuardUsec);
    }

    bool sharedWindowIndependentAnchors()
    {
        constexpr uint64_t kUsecPerMs = 1000U;
        constexpr uint64_t kMifUsec = kNeighborFirstSeenMs * kUsecPerMs;
        constexpr uint64_t kPeerDelayUsec = 2U * kUsecPerMs;
        constexpr uint64_t kGuardUsec = 3U * 1024ULL;
        constexpr uint64_t kUntilEawUsec = 16U * 1024ULL;
        constexpr uint32_t kAirtimeUsec = 512U;
        constexpr uint16_t kPeriodTu = 16U;
        constexpr uint8_t kLocalMacLast = 0x56U;
        AwdlNeighbor local {};
        local.source = kNeighborBaseSource;
        local.source.bytes[kNeighborMacLast] = kLocalMacLast;
        local.lastMifMs = kNeighborFirstSeenMs;
        local.awPeriodTu = kPeriodTu;
        local.txDownCounterTu = kPeriodTu;
        local.channelSixSlots = 1U;
        AwdlNeighbor peer = local;
        peer.source = kNeighborBaseSource;
        peer.lastMifMs += kPeerDelayUsec / kUsecPerMs;
        const AwdlSharedRendezvousRequest request {
            kMifUsec,
            kMifUsec + kPeerDelayUsec,
            kMifUsec + kPeerDelayUsec + kGuardUsec,
            kAirtimeUsec,
        };
        AwdlSharedRendezvousWindow window {};
        return planSharedAwdlChannelSixRendezvous(local, peer, request,
                                                  window) ==
                   AwdlRendezvousStatus::Candidate &&
               window.waitUsec == 0U &&
               window.usableUsec ==
                   kUntilEawUsec - kPeerDelayUsec - (2U * kGuardUsec) &&
               window.localChannelSlot == 0U && window.peerChannelSlot == 0U;
    }

    bool sharedWindowExpiresBeforeGuard()
    {
        constexpr uint64_t kUsecPerMs = 1000U;
        constexpr uint64_t kUsecPerTu = 1024U;
        constexpr uint64_t kEawTu = 64U;
        constexpr uint64_t kGuardTu = 3U;
        constexpr uint64_t kPastEaws = 76U;
        constexpr uint64_t kPastTu = kPastEaws * kEawTu;
        constexpr uint64_t kElapsedTu = kPastTu + kGuardTu;
        constexpr uint64_t kElapsedUsec = kElapsedTu * kUsecPerTu;
        constexpr uint64_t kMifUsec = kNeighborFirstSeenMs * kUsecPerMs;
        constexpr uint64_t kExpiryUsec = AwdlNeighbors::kExpiryMs * kUsecPerMs;
        constexpr uint32_t kAirtimeUsec = 512U;
        constexpr uint16_t kPeriodTu = 16U;
        constexpr uint16_t kAllSlots = UINT16_MAX;
        constexpr uint8_t kLocalMacLast = 0x56U;
        AwdlNeighbor local {};
        local.source = kNeighborBaseSource;
        local.source.bytes[kNeighborMacLast] = kLocalMacLast;
        local.lastMifMs = kNeighborFirstSeenMs;
        local.awPeriodTu = kPeriodTu;
        local.txDownCounterTu = static_cast<uint16_t>(kEawTu);
        local.channelSixSlots = kAllSlots;
        AwdlNeighbor peer = local;
        peer.source = kNeighborBaseSource;
        const AwdlSharedRendezvousRequest request {
            kMifUsec,
            kMifUsec,
            kMifUsec + kElapsedUsec,
            kAirtimeUsec,
        };
        AwdlSharedRendezvousWindow window {};
        const uint64_t remaining =
            kExpiryUsec - (request.nowUsec - request.localMifUsec);
        return planSharedAwdlChannelSixRendezvous(local, peer, request,
                                                  window) ==
                   AwdlRendezvousStatus::Candidate &&
               window.waitUsec == 0U && window.usableUsec == remaining - 1U;
    }

    bool rejectUnsafeSharedWindows()
    {
        constexpr uint64_t kUsecPerMs = 1000U;
        constexpr uint64_t kMifUsec = kNeighborFirstSeenMs * kUsecPerMs;
        constexpr uint64_t kGuardUsec = 3ULL * 1024U;
        constexpr uint32_t kAirtimeUsec = 512U;
        constexpr uint8_t kLocalMacLast = 0x56U;
        constexpr uint16_t kCountdownTu = 16U;
        AwdlNeighbor local {};
        local.source = kNeighborBaseSource;
        local.source.bytes[kNeighborMacLast] = kLocalMacLast;
        local.lastMifMs = kNeighborFirstSeenMs;
        local.awPeriodTu = kCountdownTu;
        local.txDownCounterTu = kCountdownTu;
        local.channelSixSlots = 1U;
        AwdlNeighbor peer = local;
        peer.source = kNeighborBaseSource;
        AwdlSharedRendezvousRequest request {
            kMifUsec,
            kMifUsec,
            kMifUsec + kGuardUsec,
            kAirtimeUsec,
        };
        AwdlSharedRendezvousWindow window {};
        if (planSharedAwdlChannelSixRendezvous(local, peer, request, window) !=
            AwdlRendezvousStatus::Candidate)
        {
            return false;
        }
        request.nowUsec = kMifUsec + (AwdlNeighbors::kExpiryMs * kUsecPerMs);
        if (planSharedAwdlChannelSixRendezvous(local, peer, request, window) !=
                AwdlRendezvousStatus::StaleSync ||
            window.waitUsec != 0U)
        {
            return false;
        }
        request.nowUsec = kMifUsec + kGuardUsec;
        request.frameAirtimeUsec = 0U;
        if (planSharedAwdlChannelSixRendezvous(local, peer, request, window) !=
            AwdlRendezvousStatus::InvalidInput)
        {
            return false;
        }
        request.frameAirtimeUsec = kAirtimeUsec;
        peer.source = local.source;
        if (planSharedAwdlChannelSixRendezvous(local, peer, request, window) !=
            AwdlRendezvousStatus::InvalidInput)
        {
            return false;
        }
        peer.source = kNeighborBaseSource;
        // An otherwise valid candidate near the monotonic counter ceiling
        // must not wrap its end time into an apparently earlier interval.
        constexpr uint64_t kNearOverflowMifUsec = UINT64_MAX - 4000U;
        constexpr uint64_t kNearOverflowNowOffset = kUsecPerMs;
        request.localMifUsec = kNearOverflowMifUsec;
        request.peerMifUsec = kNearOverflowMifUsec;
        request.nowUsec = UINT64_MAX - kNearOverflowNowOffset;
        local.lastMifMs = kNearOverflowMifUsec / kUsecPerMs;
        peer.lastMifMs = local.lastMifMs;
        if (planSharedAwdlChannelSixRendezvous(local, peer, request, window) !=
            AwdlRendezvousStatus::StaleSync)
        {
            return false;
        }
        request.localMifUsec = kMifUsec;
        request.peerMifUsec = kMifUsec;
        request.nowUsec = kMifUsec + kGuardUsec;
        local.lastMifMs = kNeighborFirstSeenMs;
        peer.lastMifMs = kNeighborFirstSeenMs;
        // A corrupted timestamp origin cannot grant a shared window.
        request.peerMifUsec += kUsecPerMs;
        return planSharedAwdlChannelSixRendezvous(local, peer, request,
                                                  window) ==
                   AwdlRendezvousStatus::InvalidInput &&
               window.usableUsec == 0U;
    }

    bool neighborChannelEncodings()
    {
        AwdlNeighbors peers {};
        AwdlNeighbor candidate {};
        NeighborFixture legacy = makeNeighborFixture(kNeighborSourceLast);
        expandNeighborChannels(legacy, NeighborEncoding::Legacy,
                               kNeighborOpClass24Ghz);
        if (peers.observeMif(kNeighborFirstSeenMs, legacy.frame.data(),
                             legacy.length) != Result::Ok ||
            !peers.find(legacy.source, kNeighborFirstSeenMs, candidate) ||
            candidate.channelSixSlots != kNeighborSlotMask)
        {
            return false;
        }
        peers.clear();
        NeighborFixture class24 = makeNeighborFixture(kNeighborSourceLast);
        expandNeighborChannels(class24, NeighborEncoding::OperatingClass,
                               kNeighborOpClass24Ghz);
        if (peers.observeMif(kNeighborFirstSeenMs, class24.frame.data(),
                             class24.length) != Result::Ok ||
            !peers.find(class24.source, kNeighborFirstSeenMs, candidate) ||
            candidate.channelSixSlots != kNeighborSlotMask)
        {
            return false;
        }
        peers.clear();
        NeighborFixture class5 = makeNeighborFixture(kNeighborSourceLast);
        expandNeighborChannels(class5, NeighborEncoding::OperatingClass,
                               kNeighborOpClass5Ghz);
        return peers.observeMif(kNeighborFirstSeenMs, class5.frame.data(),
                                class5.length) == Result::Ok &&
               peers.find(class5.source, kNeighborFirstSeenMs, candidate) &&
               candidate.channelSixSlots == 0U;
    }

    bool neighborElectionAndExpiry()
    {
        NeighborFixture fixture = makeNeighborFixture(kNeighborSourceLast);
        if (fixture.length == 0U)
        {
            return false;
        }
        AwdlNeighbors peers {};
        AwdlNeighbor neighbor {};
        if (peers.find(fixture.source, kNeighborFirstSeenMs, neighbor) ||
            peers.observeMif(kNeighborFirstSeenMs, fixture.frame.data(),
                             fixture.length) != Result::Ok ||
            !peers.find(fixture.source, kNeighborJustAliveMs, neighbor) ||
            neighbor.version != kNeighborVersion ||
            neighbor.deviceClass != kNeighborClassMac ||
            neighbor.awPeriodTu != kNeighborSlotCount ||
            neighbor.nextAwSequence != kNeighborNextAwSeq ||
            neighbor.txDownCounterTu != kNeighborChannelStep ||
            neighbor.channelSixSlots != kNeighborSlotMask ||
            neighbor.masterMetric != kNeighborElectionMetric ||
            neighbor.ownMetric != kNeighborElectionOwnMetric ||
            neighbor.ownCounter != kNeighborElectionCounter ||
            !sameMac(neighbor.syncMaster, fixture.source) ||
            !sameMac(neighbor.electionMaster, fixture.source) ||
            neighbor.lastHeardMs != kNeighborFirstSeenMs ||
            neighbor.lastMifMs != kNeighborFirstSeenMs)
        {
            return false;
        }
        if (peers.find(fixture.source, kNeighborExpiredMs, neighbor))
        {
            return false;
        }
        peers.expire(kNeighborExpiredMs);
        if (peers.find(fixture.source, kNeighborFirstSeenMs, neighbor))
        {
            return false;
        }
        if (peers.observeMif(kNeighborExpiredMs, fixture.frame.data(),
                             fixture.length) != Result::Ok)
        {
            return false;
        }
        peers.clear();
        return !peers.find(fixture.source, kNeighborExpiredMs, neighbor);
    }

    bool rejectIncompleteNeighbor()
    {
        NeighborFixture fixture = makeNeighborFixture(kNeighborSourceLast);
        AwdlNeighbors peers {};
        AwdlNeighbor neighbor {};
        fixture.frame.at(kSubtypeOffset) = kNeighborPsf;
        if (peers.observeMif(kNeighborFirstSeenMs, fixture.frame.data(),
                             fixture.length) != Result::UnsupportedFrame)
        {
            return false;
        }
        fixture = makeNeighborFixture(kNeighborSourceLast);
        fixture.frame.at(fixture.versionOffset) = 0U;
        if (peers.observeMif(kNeighborFirstSeenMs, fixture.frame.data(),
                             fixture.length) != Result::InvalidElement)
        {
            return false;
        }
        fixture = makeNeighborFixture(kNeighborSourceLast);
        fixture.frame.at(fixture.channelOffset + 3U) = 0U;
        if (peers.observeMif(kNeighborFirstSeenMs, fixture.frame.data(),
                             fixture.length) != Result::InvalidElement)
        {
            return false;
        }
        fixture = makeNeighborFixture(kNeighborSourceLast);
        fixture.frame.at(fixture.electionOffset +
                         kNeighborElectionReservedOffset) = 1U;
        if (peers.observeMif(kNeighborFirstSeenMs, fixture.frame.data(),
                             fixture.length) != Result::InvalidElement)
        {
            return false;
        }
        fixture = makeNeighborFixture(kNeighborSourceLast);
        fixture.frame.at(fixture.syncOffset + kNeighborSyncPeriodOffset) = 0U;
        if (peers.observeMif(kNeighborFirstSeenMs, fixture.frame.data(),
                             fixture.length) != Result::InvalidElement)
        {
            return false;
        }
        fixture = makeNeighborFixture(kNeighborSourceLast);
        fixture.frame.at(fixture.unknownOffset - kNeighborTlvHeader) =
            kNeighborTlvVersion;
        if (peers.observeMif(kNeighborFirstSeenMs, fixture.frame.data(),
                             fixture.length) != Result::InvalidElement ||
            peers.find(fixture.source, kNeighborFirstSeenMs, neighbor))
        {
            return false;
        }
        fixture = makeNeighborFixture(kNeighborSourceLast);
        fixture.frame.at(fixture.versionOffset - kNeighborTlvHeader) =
            kNeighborTlvUnknown;
        if (peers.observeMif(kNeighborFirstSeenMs, fixture.frame.data(),
                             fixture.length) != Result::InvalidElement)
        {
            return false;
        }
        fixture = makeNeighborFixture(kNeighborSourceLast);
        fixture.frame.at(fixture.channelOffset + kNeighborChannelOffset) =
            kNeighborOtherChannel;
        fixture.frame.at(fixture.channelOffset + kNeighborChannelOffset +
                         kNeighborSlotTen) = kNeighborOtherChannel;
        return peers.observeMif(kNeighborFirstSeenMs, fixture.frame.data(),
                                fixture.length) == Result::Ok &&
               peers.find(fixture.source, kNeighborFirstSeenMs, neighbor) &&
               neighbor.channelSixSlots == 0U;
    }

    bool boundedNeighborRetention()
    {
        AwdlNeighbors peers {};
        NeighborFixture fixture {};
        constexpr uint8_t kFirstPeerSuffix = 0x50U;
        for (size_t index = 0U; index < AwdlNeighbors::kCapacity; ++index)
        {
            fixture = makeNeighborFixture(
                static_cast<uint8_t>(kFirstPeerSuffix + index));
            if (peers.observeMif(kNeighborFirstSeenMs, fixture.frame.data(),
                                 fixture.length) != Result::Ok)
            {
                return false;
            }
        }
        fixture = makeNeighborFixture(
            static_cast<uint8_t>(kFirstPeerSuffix + AwdlNeighbors::kCapacity));
        if (peers.observeMif(kNeighborFirstSeenMs, fixture.frame.data(),
                             fixture.length) != Result::BufferTooSmall)
        {
            return false;
        }
        peers.expire(kNeighborExpiredMs);
        if (peers.observeMif(kNeighborExpiredMs, fixture.frame.data(),
                             fixture.length) != Result::Ok)
        {
            return false;
        }
        AwdlNeighbor neighbor {};
        if (!peers.find(fixture.source, kNeighborExpiredMs, neighbor))
        {
            return false;
        }
        // Earlier clocks cannot extend an existing peer or evict its slot.
        return peers.observeMif(kNeighborFirstSeenMs, fixture.frame.data(),
                                fixture.length) == Result::InvalidFrame &&
               peers.find(fixture.source, kNeighborExpiredMs, neighbor);
    }

    bool neighborIpv6Refresh()
    {
        NeighborFixture fixture = makeNeighborFixture(kNeighborSourceLast);
        AwdlNeighbors peers {};
        if (peers.observeMif(kNeighborFirstSeenMs, fixture.frame.data(),
                             fixture.length) != Result::Ok)
        {
            return false;
        }
        std::array<uint8_t, kNeighborIpv6Bytes> ipv6 {};
        ipv6.at(0U) = kNeighborIpv6Version;
        const Mac destination {{0x33U, 0x33U, 0U, 0U, 0U, 1U}};
        const AwdlIpv6Tx tx {
            fixture.source, destination, 0U,          0U,
            false,          ipv6.data(), ipv6.size(),
        };
        std::array<uint8_t, kNeighborDataBytes> output {};
        size_t written = 0U;
        if (makeAwdlIpv6Data(tx, output.data(), output.size(), written) !=
                Result::Ok ||
            written != output.size())
        {
            return false;
        }
        const uint64_t refreshedMs = kNeighborJustAliveMs;
        AwdlNeighbor neighbor {};
        if (peers.observeIpv6(refreshedMs, output.data(), written) !=
                Result::Ok ||
            peers.observeMif(kNeighborFirstSeenMs, fixture.frame.data(),
                             fixture.length) != Result::InvalidFrame ||
            !peers.find(fixture.source, kNeighborExpiredMs, neighbor) ||
            neighbor.lastHeardMs != refreshedMs ||
            neighbor.lastMifMs != kNeighborFirstSeenMs)
        {
            return false;
        }
        peers.clear();
        if (peers.observeIpv6(refreshedMs, output.data(), written) !=
            Result::UnsupportedFrame)
        {
            return false;
        }
        fixture = makeNeighborFixture(kNeighborSourceLast);
        if (peers.observeMif(refreshedMs, fixture.frame.data(),
                             fixture.length) != Result::Ok)
        {
            return false;
        }
        const uint64_t expiredAfterRefresh =
            refreshedMs + AwdlNeighbors::kExpiryMs;
        return peers.observeIpv6(expiredAfterRefresh, output.data(), written) ==
                   Result::UnsupportedFrame &&
               !peers.find(fixture.source, expiredAfterRefresh, neighbor);
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
    if (!neighborElectionAndExpiry())
    {
        constexpr int kNeighborFailure = 9;
        return kNeighborFailure;
    }
    if (!rejectIncompleteNeighbor())
    {
        constexpr int kIncompleteNeighborFailure = 10;
        return kIncompleteNeighborFailure;
    }
    if (!boundedNeighborRetention())
    {
        constexpr int kNeighborCapacityFailure = 11;
        return kNeighborCapacityFailure;
    }
    if (!neighborIpv6Refresh())
    {
        constexpr int kNeighborRefreshFailure = 12;
        return kNeighborRefreshFailure;
    }
    if (!neighborChannelEncodings())
    {
        constexpr int kNeighborChannelEncodingFailure = 13;
        return kNeighborChannelEncodingFailure;
    }
    if (!channelSixRendezvousCandidates())
    {
        constexpr int kRendezvousFailure = 14;
        return kRendezvousFailure;
    }
    if (!nextChannelSixRendezvousCandidates())
    {
        constexpr int kFutureRendezvousFailure = 15;
        return kFutureRendezvousFailure;
    }
    if (!sharedChannelSixOverlap())
    {
        constexpr int kSharedWindowFailure = 17;
        return kSharedWindowFailure;
    }
    if (!sharedWindowIndependentAnchors())
    {
        constexpr int kIndependentAnchorFailure = 19;
        return kIndependentAnchorFailure;
    }
    if (!sharedWindowExpiresBeforeGuard())
    {
        constexpr int kSharedExpiryFailure = 20;
        return kSharedExpiryFailure;
    }
    if (!rejectUnsafeSharedWindows())
    {
        constexpr int kUnsafeSharedWindowFailure = 18;
        return kUnsafeSharedWindowFailure;
    }
    if (!serializeChannelSixMif())
    {
        constexpr int kLocalMifFailure = 16;
        return kLocalMifFailure;
    }
    return 0;
}
