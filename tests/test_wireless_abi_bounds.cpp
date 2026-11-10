// Synthetic ABI size guards; never uses IOKit, real events, or hardware.
#include "WirelessABI.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace
{
    constexpr size_t kArenaBytes = 2048U;
    constexpr uint8_t kUntouchedByte = 0xA5U;
    constexpr size_t kOwnerOffset = 16U;
    constexpr size_t kRingAlignmentBytes = 8U;
    constexpr size_t kRingPayloadOffset = 100U;
    constexpr size_t kRingNameOffset = 200U;
    constexpr size_t kRingNameBytes = 4U;
    constexpr size_t kMalformedRingOffset = 1U;
    constexpr uint8_t kInvalidAssociateLayoutWireValue = 0xffU;

    bool intact(const std::array<uint8_t, kArenaBytes> &bytes)
    {
        return std::all_of(bytes.begin(), bytes.end(),
                           [](uint8_t byte)
                           {
                               return byte == kUntouchedByte;
                           });
    }

    bool rejectUndersizedLayouts()
    {
        std::array<uint8_t, kArenaBytes> arena {};
        std::array<uint8_t, ath::legacyDriverAvailableSize> source {};
        std::memset(arena.data(), kUntouchedByte, sizeof(arena));
        auto abi = ath::tahoeABI;
        abi.driverAvailableSize = 1;
        if (ath::copyEventPayload(ath::driverAvailableEvent, source.data(),
                                  sizeof(source), arena.data(), 1, abi) ||
            !intact(arena))
        {
            return false;
        }

        abi = ath::tahoeABI;
        abi.scanResultSize = 1;
        ath::Request request {};
        request.length = 1;
        if (ath::prepareScanResult(request, arena.data(), 1, abi) ||
            !intact(arena) || request.length != 1)
        {
            return false;
        }
        request.length = ath::legacyScanResultSize;
        if (ath::expandScanResult(request, arena.data(), 1, abi) ||
            !intact(arena) || request.length != ath::legacyScanResultSize)
        {
            return false;
        }

        abi = ath::tahoeABI;
        abi.capabilitySize = 1;
        request.length = ath::legacyCapabilitySize;
        if (ath::expandCapabilities(request, arena.data(), 1, abi, true) ||
            !intact(arena) || request.length != ath::legacyCapabilitySize)
        {
            return false;
        }

        abi = ath::tahoeABI;
        abi.scanMultipleSize = 1;
        request.length = 1;
        arena.front() = 1;
        if (ath::prepareScanMultiple(request, arena.data(), 1, abi) ||
            request.length != 1 || arena.front() != 1)
        {
            return false;
        }
        arena.front() = kUntouchedByte;
        if (!intact(arena))
        {
            return false;
        }

        abi = ath::tahoeABI;
        abi.driverAvailableSize = 1;
        std::array<uint8_t, ath::powerDataSize> power {};
        ath::writeUInt32(power.data(), 1);
        ath::writeUInt32(
            ath::wireByteAt(power.data(), ath::powerRadioCountOffset), 1);
        ath::writeUInt32(
            ath::wireByteAt(power.data(), ath::powerRadioStatusOffset), 1);
        if (ath::encodePowerAvailability(power.data(), sizeof(power),
                                         arena.data(), 1, abi) ||
            !intact(arena))
        {
            return false;
        }

        abi = ath::tahoeABI;
        abi.joinStatusSize = 1;
        if (ath::encodeJoinStatus(0, 0, nullptr, 0, arena.data(), 1, abi) ||
            !intact(arena))
        {
            return false;
        }

        abi = ath::tahoeABI;
        abi.associateSize = 1;
        request.length = 1;
        arena.at(ath::extendedAssociateFlagOffset) = 0;
        if (ath::prepareAssociate(request, arena.data(), 1, abi) ||
            request.length != 1)
        {
            return false;
        }
        arena.at(ath::extendedAssociateFlagOffset) = kUntouchedByte;
        abi = ath::tahoeABI;
        // Preserve the malformed on-wire enum test without an explicit
        // out-of-range enum cast (the kernel sees opaque bytes too).
        ath::AssociateLayout malformedLayout {};
        const auto rawLayout = kInvalidAssociateLayoutWireValue;
        static_assert(sizeof(malformedLayout) == sizeof(rawLayout),
                      "wire enum is a byte");
        std::memcpy(&malformedLayout, &rawLayout, sizeof(malformedLayout));
        abi.associateLayout = malformedLayout;
        request.length = static_cast<uint32_t>(abi.associateSize);
        if (ath::prepareAssociate(request, arena.data(), abi.associateSize,
                                  abi) ||
            request.length != abi.associateSize)
        {
            return false;
        }
        return intact(arena);
    }

    bool rejectEventRingAliases()
    {
        alignas(kRingAlignmentBytes)
            std::array<uint8_t,
                       ath::minimumEventRingBytes + kRingAlignmentBytes>
                storage {};
        std::array<uint8_t, sizeof(storage)> before {};
        auto *const ring = storage.data();
        uint32_t write = 0;
        uint16_t sequence = 0;
        ath::EventState state {};
        const auto append = [&](uint8_t *destination, ath::EventState *owner,
                                const char *name, const void *payload,
                                size_t length)
        {
            return ath::EventRing::append(
                destination, ath::minimumEventRingBytes, owner, write, sequence,
                name, 1U, payload, length, ath::EventTimestamp {0U, 0U});
        };
        std::memcpy(before.data(), storage.data(), sizeof(storage));
        if (append(ring, &state, "en0",
                   ath::wireByteAt(ring, kRingPayloadOffset),
                   4U) != ath::RingResult::Invalid ||
            std::memcmp(before.data(), storage.data(), sizeof(storage)) != 0 ||
            write != 0 || sequence != 0)
        {
            return false;
        }
        std::memcpy(ath::wireByteAt(ring, kRingNameOffset), "en0",
                    kRingNameBytes);
        std::memcpy(before.data(), storage.data(), sizeof(storage));
        if (append(ring, &state, ath::wireObjectAt<char>(ring, kRingNameOffset),
                   nullptr, 0U) != ath::RingResult::Invalid ||
            std::memcmp(before.data(), storage.data(), sizeof(storage)) != 0 ||
            write != 0 || sequence != 0)
        {
            return false;
        }
        auto *const aliasedState =
            ath::wireObjectAt<ath::EventState>(ring, kOwnerOffset);
        *aliasedState = {};
        std::memcpy(before.data(), storage.data(), sizeof(storage));
        if (append(ring, aliasedState, "en0", nullptr, 0U) !=
                ath::RingResult::Invalid ||
            std::memcmp(before.data(), storage.data(), sizeof(storage)) != 0 ||
            write != 0 || sequence != 0)
        {
            return false;
        }
        std::memcpy(before.data(), storage.data(), sizeof(storage));
        return append(ath::wireByteAt(ring, kMalformedRingOffset), &state,
                      "en0", nullptr, 0U) == ath::RingResult::Invalid &&
               std::memcmp(before.data(), storage.data(), sizeof(storage)) ==
                   0 &&
               write == 0U && sequence == 0U;
    }

    bool preserveSupportedLayouts()
    {
        auto abi = ath::tahoeABI;
        std::array<uint8_t, ath::legacyDriverAvailableSize> source {};
        std::array<uint8_t, ath::nativeDriverAvailableSize> destination {};
        if (!ath::copyEventPayload(ath::driverAvailableEvent, source.data(),
                                   sizeof(source), destination.data(),
                                   sizeof(destination), abi))
        {
            return false;
        }
        std::array<uint8_t, ath::powerDataSize> power {};
        ath::writeUInt32(power.data(), 1);
        ath::writeUInt32(
            ath::wireByteAt(power.data(), ath::powerRadioCountOffset), 1);
        ath::writeUInt32(
            ath::wireByteAt(power.data(), ath::powerRadioStatusOffset), 1);
        if (!ath::encodePowerAvailability(power.data(), sizeof(power),
                                          destination.data(),
                                          sizeof(destination), abi))
        {
            return false;
        }
        std::array<uint8_t, ath::tahoeABI.joinStatusSize> join {};
        if (!ath::encodeJoinStatus(0, 0, nullptr, 0, join.data(), sizeof(join),
                                   abi))
        {
            return false;
        }
        abi = ath::sequoiaABI;
        return ath::encodeJoinStatus(0, 0, nullptr, 0, join.data(),
                                     sizeof(join), abi);
    }
} // namespace

int main()
{
    assert(rejectUndersizedLayouts());
    assert(rejectEventRingAliases());
    assert(preserveSupportedLayouts());
    return 0;
}
