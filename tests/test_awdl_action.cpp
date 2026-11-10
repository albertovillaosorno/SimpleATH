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
    return 0;
}
