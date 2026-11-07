// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Alberto Villa Osorno.
// Offline regression of real identity/invalid-output code; no PCI access.
#include "hardware/Ar9565Core.hpp"

namespace
{
    using namespace simpleath;

    struct RevokingRead
    {
            Device *owner;
            RegisterBus bus;
            uint32_t revokeAt;
            unsigned reads;
            bool revoke;
            bool reattach;
            bool reattached;
    };

    bool syntheticRead32(void *opaque, uint32_t offset, uint32_t *value)
    {
        auto &context = *static_cast<RevokingRead *>(opaque);
        ++context.reads;
        if (context.revoke && offset == context.revokeAt)
        {
            context.revoke = false;
            // Model a native owner losing its mapping synchronously during
            // an MMIO callback. The callback may also reattach the SAME
            // function/context to a fresh owner generation before returning.
            context.owner->detach();
            if (context.reattach)
                context.reattached =
                    context.owner->matchPci(kPciVendor, kPciDevice, 0, 0) ==
                        Result::Ok &&
                    context.owner->attachReadOnlyBus(context.bus) == Result::Ok;
        }
        if (offset == kRevisionRegister)
            *value = (static_cast<uint32_t>(kMacFamily) << 12u) | 0xffu;
        else if (offset == kRtcStatusRegister)
            *value = kRtcOn;
        else if (offset == kEepromStatusRegister)
            *value = 0;
        else
            return false;
        return true;
    }

    bool rejectReentrantBusRevocation()
    {
        const uint32_t stages[] {kRevisionRegister, kRtcStatusRegister,
                                 kEepromStatusRegister};
        for (uint32_t revokedAt : stages)
        {
            Device device;
            RevokingRead context {};
            context.owner = &device;
            context.bus = {&context, syntheticRead32, nullptr, 0x7048};
            context.revokeAt = revokedAt;
            context.revoke = true;
            if (device.matchPci(kPciVendor, kPciDevice, 0, 0) != Result::Ok ||
                device.attachReadOnlyBus(context.bus) != Result::Ok ||
                device.inspect() != Result::WrongState ||
                device.status().stage != Stage::Detached ||
                device.status().silicon.rawSrev != 0 ||
                device.status().eepromAccessible ||
                context.reads != (revokedAt == kRevisionRegister    ? 1u
                                  : revokedAt == kRtcStatusRegister ? 2u
                                                                    : 3u))
                return false;

            // Even if a callback detach/reattach cycle restores the identical
            // bus pointers, a stale outer inspection must not publish success
            // or a failure into the replacement owner's state.
            context.revoke = true;
            context.reattach = true;
            context.reattached = false;
            if (device.matchPci(kPciVendor, kPciDevice, 0, 0) != Result::Ok ||
                device.attachReadOnlyBus(context.bus) != Result::Ok ||
                device.inspect() != Result::WrongState || !context.reattached ||
                device.status().stage != Stage::RegisterTransportReady ||
                device.status().lastResult != Result::Ok ||
                device.status().silicon.rawSrev != 0 ||
                device.status().eepromAccessible)
                return false;
            // The new attachment should remain usable on a fresh inspection.
            if (device.inspect() != Result::Ok ||
                device.status().stage != Stage::AwaitingResetAndCalibration ||
                !device.status().eepromAccessible)
                return false;
        }
        return true;
    }
} // namespace

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
    if (!rejectReentrantBusRevocation())
        return 10;
    return 0;
}
