// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Alberto Villa Osorno.
// Offline regression of real identity/invalid-output code; no PCI access.
#include "hardware/Ar9565Core.hpp"

int main()
{
    using namespace simpleath;
    if (!isSupportedPci(0x168c, 0x0036) || isSupportedPci(0x168c, 0x0030))
        return 1;
    for (uint32_t revision = 0; revision < 3; ++revision)
    {
        Silicon silicon {};
        const uint32_t srev =
            (static_cast<uint32_t>(kMacFamily) << 12) | (revision << 8) | 0xffu;
        if (decodeRevision(srev, silicon) != Result::Ok ||
            silicon.macRevision != revision || !silicon.usesPcie)
            return 2;
    }
    Silicon stale {};
    stale.rawSrev = 0x1234;
    if (decodeRevision(0xffffffffu, stale) == Result::Ok || stale.rawSrev)
        return 3;
    Channel channel {};
    if (mapChannel(14, channel) != Result::Ok || channel.centerMhz != 2484 ||
        !channel.requiresJapanAuthorization)
        return 4;
    if (mapChannel(0, channel) != Result::InvalidChannel || channel.number ||
        channel.centerMhz || channel.requiresJapanAuthorization)
        return 5;
    const uint16_t valid[3] = {0x0211, 0x2233, 0x4455};
    const uint8_t expected[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t mac[6] {};
    if (decodeEepromMac(valid, mac) != Result::Ok)
        return 6;
    for (size_t i = 0; i < sizeof(mac); ++i)
        if (mac[i] != expected[i])
            return 7;
    const uint16_t invalid[3] {};
    if (decodeEepromMac(invalid, mac) != Result::InvalidMacAddress)
        return 8;
    for (uint8_t octet : mac)
        if (octet)
            return 9;
    return 0;
}
