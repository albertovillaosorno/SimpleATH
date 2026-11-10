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
    assert(preserveSupportedLayouts());
    return 0;
}
