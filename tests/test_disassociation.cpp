// SPDX-License-Identifier: GPL-2.0-only
// Source-only OS-native disassociation frame regression, no RF or IOKit.
#include "wifi/Frames.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace
{
    using namespace simpleath::ieee80211;
    constexpr Mac kStation {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
    constexpr Mac kAccessPoint {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
    constexpr uint16_t kLeaveReason = 8;
    constexpr uint16_t kSequence = 0x0123;
    constexpr size_t kFrameBytes = 26;
    constexpr size_t kTestCapacity = 32;
    constexpr uint8_t kDisassociationSubtype = 10;
    constexpr uint8_t kDisassociationFrameControl = 0xa0U;
    constexpr uint8_t kUntouched = 0xa5U;
    constexpr size_t kDestinationOffset = 4;
    constexpr size_t kSourceOffset = 10;
    constexpr size_t kBssidOffset = 16;
    constexpr size_t kSequenceLowOffset = 22;
    constexpr size_t kSequenceHighOffset = 23;
    constexpr size_t kReasonLowOffset = 24;
    constexpr size_t kReasonHighOffset = 25;
    constexpr unsigned int kFragmentBits = 4;
    constexpr unsigned int kByteBits = 8;

    bool matchesAddress(const std::array<uint8_t, kTestCapacity> &packet,
                        size_t offset, const Mac &address)
    {
        return std::memcmp(&packet.at(offset), &address.bytes[0],
                           sizeof(address.bytes)) == 0;
    }

    bool regression()
    {
        std::array<uint8_t, kTestCapacity> packet {};
        size_t written = 0;
        if (makeDisassociationRequest(kStation, kAccessPoint,
                                      {kLeaveReason, kSequence}, packet.data(),
                                      packet.size(), written) != Result::Ok ||
            written != kFrameBytes ||
            packet.at(0) != kDisassociationFrameControl ||
            packet.at(kSequenceLowOffset) !=
                static_cast<uint8_t>(kSequence << kFragmentBits) ||
            packet.at(kSequenceHighOffset) !=
                static_cast<uint8_t>(kSequence >>
                                     (kByteBits - kFragmentBits)) ||
            packet.at(kReasonLowOffset) != static_cast<uint8_t>(kLeaveReason) ||
            packet.at(kReasonHighOffset) != 0 ||
            !matchesAddress(packet, kDestinationOffset, kAccessPoint) ||
            !matchesAddress(packet, kSourceOffset, kStation) ||
            !matchesAddress(packet, kBssidOffset, kAccessPoint) ||
            packet.at(kFrameBytes) != 0)
        {
            return false;
        }
        Frame decoded {};
        if (parseFrame(packet.data(), written, decoded) != Result::Ok ||
            decoded.type != FrameType::Management ||
            decoded.subtype != kDisassociationSubtype ||
            !sameMac(decoded.source, kStation) ||
            !sameMac(decoded.bssid, kAccessPoint))
        {
            return false;
        }
        packet.fill(kUntouched);
        written = 1;
        if (makeDisassociationRequest(kStation, kAccessPoint, {0, kSequence},
                                      packet.data(), packet.size(),
                                      written) != Result::InvalidFrame ||
            written != 0 || packet.front() != kUntouched)
        {
            return false;
        }
        if (makeDisassociationRequest(kStation, kAccessPoint,
                                      {kLeaveReason, kSequence}, packet.data(),
                                      kFrameBytes - 1,
                                      written) != Result::BufferTooSmall ||
            written != 0 || packet.front() != kUntouched)
        {
            return false;
        }
        if (makeDisassociationRequest(
                kStation, kStation, {kLeaveReason, kSequence}, packet.data(),
                packet.size(), written) != Result::InvalidAddress ||
            written != 0 || packet.front() != kUntouched)
        {
            return false;
        }
        Mac aliased = kStation;
        const Mac before = aliased;
        if (makeDisassociationRequest(aliased, kAccessPoint,
                                      {kLeaveReason, kSequence},
                                      &aliased.bytes[0], sizeof(aliased.bytes),
                                      written) != Result::OverlappingBuffers ||
            !sameMac(aliased, before))
        {
            return false;
        }
        // The count may not alias the serialized destination. Inspecting the
        // same bytes through uint8_t is deliberate for this adversarial test.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        auto *aliasOfWritten = reinterpret_cast<uint8_t *>(&written);
        return makeDisassociationRequest(kStation, kAccessPoint,
                                         {kLeaveReason, kSequence},
                                         aliasOfWritten, sizeof(written),
                                         written) == Result::OverlappingBuffers;
    }
} // namespace

int main()
{
    return regression() ? 0 : 1;
}
