// SPDX-License-Identifier: AGPL-3.0-only
// Synthetic ABI size guards; never uses IOKit, real events, or hardware.
#include "WirelessABI.hpp"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace
{
    constexpr size_t kArenaBytes = 2048U;

    bool intact(const uint8_t (&bytes)[kArenaBytes])
    {
        for (uint8_t byte : bytes)
        {
            if (byte != 0xA5U)
            {
                return false;
            }
        }
        return true;
    }

    bool rejectUndersizedLayouts()
    {
        uint8_t arena[kArenaBytes];
        uint8_t source[ath::LegacyDriverAvailableSize] {};
        std::memset(arena, 0xA5, sizeof(arena));
        auto abi = ath::TahoeABI;
        abi.driverAvailableSize = 1;
        if (ath::copyEventPayload(ath::DriverAvailableEvent, source,
                                  sizeof(source), arena, 1, abi) ||
            !intact(arena))
        {
            return false;
        }

        abi = ath::TahoeABI;
        abi.scanResultSize = 1;
        ath::Request request {};
        request.length = 1;
        if (ath::prepareScanResult(request, arena, 1, abi) || !intact(arena) ||
            request.length != 1)
        {
            return false;
        }
        request.length = ath::LegacyScanResultSize;
        if (ath::expandScanResult(request, arena, 1, abi) || !intact(arena) ||
            request.length != ath::LegacyScanResultSize)
        {
            return false;
        }

        abi = ath::TahoeABI;
        abi.capabilitySize = 1;
        request.length = ath::LegacyCapabilitySize;
        if (ath::expandCapabilities(request, arena, 1, abi, true) ||
            !intact(arena) || request.length != ath::LegacyCapabilitySize)
        {
            return false;
        }

        abi = ath::TahoeABI;
        abi.scanMultipleSize = 1;
        request.length = 1;
        arena[0] = 1;
        if (ath::prepareScanMultiple(request, arena, 1, abi) ||
            request.length != 1 || arena[0] != 1)
        {
            return false;
        }
        arena[0] = 0xA5;
        if (!intact(arena))
        {
            return false;
        }

        abi = ath::TahoeABI;
        abi.driverAvailableSize = 1;
        uint8_t power[ath::PowerDataSize] {};
        ath::writeUInt32(power, 1);
        ath::writeUInt32(power + 4, 1);
        ath::writeUInt32(power + 8, 1);
        if (ath::encodePowerAvailability(power, sizeof(power), arena, 1, abi) ||
            !intact(arena))
        {
            return false;
        }

        abi = ath::TahoeABI;
        abi.joinStatusSize = 1;
        if (ath::encodeJoinStatus(0, 0, nullptr, 0, arena, 1, abi) ||
            !intact(arena))
        {
            return false;
        }

        abi = ath::TahoeABI;
        abi.associateSize = 1;
        request.length = 1;
        arena[0x206] = 0;
        if (ath::prepareAssociate(request, arena, 1, abi) ||
            request.length != 1)
        {
            return false;
        }
        arena[0x206] = 0xA5;
        abi = ath::TahoeABI;
        abi.associateLayout = static_cast<ath::AssociateLayout>(0xFFU);
        request.length = static_cast<uint32_t>(abi.associateSize);
        if (ath::prepareAssociate(request, arena, abi.associateSize, abi) ||
            request.length != abi.associateSize)
        {
            return false;
        }
        return intact(arena);
    }

    bool rejectEventRingAliases()
    {
        alignas(8) uint8_t storage[4096U + 8U] {};
        uint8_t before[sizeof(storage)];
        auto *const ring = storage;
        uint32_t write = 0;
        uint16_t sequence = 0;
        ath::EventState state {};
        const auto append = [&](uint8_t *destination, ath::EventState *owner,
                                const char *name, const void *payload,
                                size_t length)
        {
            return ath::EventRing::append(destination, 4096U, owner, write,
                                          sequence, name, 1U, payload, length,
                                          0U, 0U);
        };
        std::memcpy(before, storage, sizeof(storage));
        if (append(ring, &state, "en0", ring + 100, 4U) !=
                ath::RingResult::Invalid ||
            std::memcmp(before, storage, sizeof(storage)) != 0 || write != 0 ||
            sequence != 0)
        {
            return false;
        }
        std::memcpy(ring + 200, "en0", 4);
        std::memcpy(before, storage, sizeof(storage));
        if (append(ring, &state, reinterpret_cast<char *>(ring + 200), nullptr,
                   0U) != ath::RingResult::Invalid ||
            std::memcmp(before, storage, sizeof(storage)) != 0 || write != 0 ||
            sequence != 0)
        {
            return false;
        }
        auto *const aliasedState =
            reinterpret_cast<ath::EventState *>(ring + 16);
        *aliasedState = {};
        std::memcpy(before, storage, sizeof(storage));
        if (append(ring, aliasedState, "en0", nullptr, 0U) !=
                ath::RingResult::Invalid ||
            std::memcmp(before, storage, sizeof(storage)) != 0 || write != 0 ||
            sequence != 0)
        {
            return false;
        }
        std::memcpy(before, storage, sizeof(storage));
        if (append(ring + 1, &state, "en0", nullptr, 0U) !=
                ath::RingResult::Invalid ||
            std::memcmp(before, storage, sizeof(storage)) != 0 || write != 0 ||
            sequence != 0)
        {
            return false;
        }
        return true;
    }

    bool preserveSupportedLayouts()
    {
        auto abi = ath::TahoeABI;
        uint8_t source[ath::LegacyDriverAvailableSize] {};
        uint8_t destination[ath::NativeDriverAvailableSize] {};
        if (!ath::copyEventPayload(ath::DriverAvailableEvent, source,
                                   sizeof(source), destination,
                                   sizeof(destination), abi))
        {
            return false;
        }
        uint8_t power[ath::PowerDataSize] {};
        ath::writeUInt32(power, 1);
        ath::writeUInt32(power + 4, 1);
        ath::writeUInt32(power + 8, 1);
        if (!ath::encodePowerAvailability(power, sizeof(power), destination,
                                          sizeof(destination), abi))
        {
            return false;
        }
        uint8_t join[0x1D4] {};
        if (!ath::encodeJoinStatus(0, 0, nullptr, 0, join, sizeof(join), abi))
        {
            return false;
        }
        abi = ath::SequoiaABI;
        return ath::encodeJoinStatus(0, 0, nullptr, 0, join, sizeof(join), abi);
    }
} // namespace

int main()
{
    assert(rejectUndersizedLayouts());
    assert(rejectEventRingAliases());
    assert(preserveSupportedLayouts());
    return 0;
}
