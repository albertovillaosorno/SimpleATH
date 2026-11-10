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
    using Packet = std::array<uint8_t, kPacketBytes>;

    template <size_t Length>
    void copyField(Packet &frame, size_t offset,
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
    return 0;
}
