// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Alberto Villa Osorno.
// Synthetic PCI callback contract only: no IOKit, PCI hardware or kext build.
#include "platform/Ar9565PciSession.hpp"

using namespace simpleath;

namespace
{
    struct FakePci
    {
            uint16_t command = 0;
            uint32_t barLength = kRtcStatusRegister + 4;
            bool powered = true;
            bool claimAllowed = true;
            bool claimed = false;
            bool mapped = false;
            bool mapAllowed = true;
            bool enableWriteFails = false;
            bool enableWriteTakesEffect = true;
            bool disableWriteFails = false;
            bool commandMutatedOnEnable = false;
            bool powerDropsOnReadback = false;
            bool registerReadFails = false;
            uint32_t eepromStatus = 0;
            unsigned claims = 0;
            unsigned releases = 0;
            unsigned maps = 0;
            unsigned unmaps = 0;
            unsigned writes = 0;
            unsigned reads = 0;

            static FakePci &get(void *context)
            {
                return *static_cast<FakePci *>(context);
            }

            static bool claim(void *context)
            {
                auto &self = get(context);
                ++self.claims;
                if (!self.claimAllowed || self.claimed)
                    return false;
                self.claimed = true;
                return true;
            }

            static void release(void *context)
            {
                auto &self = get(context);
                ++self.releases;
                self.claimed = false;
            }

            static bool inD0(void *context)
            {
                return get(context).powered;
            }

            static bool configRead(void *context, uint16_t offset,
                                   uint32_t *value)
            {
                auto &self = get(context);
                if (!self.claimed || !self.powered || !value)
                    return false;
                ++self.reads;
                switch (offset)
                {
                    case 0x00:
                        *value = 0x0036168cu; // Device 0036, Atheros 168c.
                        return true;
                    case 0x2c:
                        *value = 0x12345678u;
                        return true;
                    case 0x08:
                        *value = 0x02800001u; // Network/other, revision 1.
                        return true;
                    case 0x0c:
                        *value = 0; // Type-0 header.
                        return true;
                    case 0x04:
                        if (self.powerDropsOnReadback && (self.command & 2u))
                        {
                            // The provider disappears after decode enable.
                            self.powered = false;
                            return false;
                        }
                        *value = 0xa5a50000u | self.command; // Preserve status.
                        return true;
                    case 0x10:
                        *value = 0x80001000u; // Assigned 32-bit MMIO BAR.
                        return true;
                    default:
                        return false;
                }
            }

            static bool commandWrite(void *context, uint16_t value)
            {
                auto &self = get(context);
                ++self.writes;
                if (!self.claimed || !self.powered || (value & 4u))
                    return false; // No bus mastering, even in the fake.
                if (value & 2u)
                {
                    if (self.enableWriteTakesEffect)
                        self.command = static_cast<uint16_t>(
                            value |
                            (self.commandMutatedOnEnable ? 0x0100u : 0u));
                    return !self.enableWriteFails;
                }
                if (self.disableWriteFails)
                    return false;
                self.command = value;
                return true;
            }

            static bool map(void *context, uint32_t *length)
            {
                auto &self = get(context);
                ++self.maps;
                if (!self.claimed || !self.powered || !self.mapAllowed ||
                    !length || !(self.command & 2u))
                    return false;
                self.mapped = true;
                *length = self.barLength;
                return true;
            }

            static void unmap(void *context)
            {
                auto &self = get(context);
                ++self.unmaps;
                self.mapped = false;
            }

            static bool barRead(void *context, uint32_t offset, uint32_t *value)
            {
                auto &self = get(context);
                if (!self.claimed || !self.powered || !self.mapped ||
                    self.registerReadFails || !value || !(self.command & 2u))
                    return false;
                switch (offset)
                {
                    case kRevisionRegister:
                        *value =
                            (static_cast<uint32_t>(kMacFamily) << 12u) | 0xffu;
                        return true;
                    case kRtcStatusRegister:
                        *value = kRtcOn;
                        return true;
                    case kEepromStatusRegister:
                        *value = self.eepromStatus;
                        return true;
                    default:
                        return false;
                }
            }

            PciSessionBackend backend()
            {
                return {this,         claim, release, inD0,   configRead,
                        commandWrite, map,   unmap,   barRead};
            }
    };
} // namespace

int main()
{
    {
        FakePci fake {};
        PciReadOnlySession session;
        if (session.start(fake.backend()) != PciSessionResult::Ok ||
            !session.status().claimed || !session.status().mapped ||
            !session.status().readAccessReady ||
            !session.status().memoryDecodeChanged || fake.command != 2 ||
            fake.writes != 1 || fake.maps != 1)
            return 1;
        if (session.inspect() != PciSessionResult::Ok ||
            session.hardwareStatus().stage !=
                Stage::AwaitingResetAndCalibration ||
            !session.hardwareStatus().eepromAccessible ||
            session.status().coreInspectResult != Result::Ok)
            return 2;
        session.stop(ProviderAccess::Available);
        if (fake.claimed || fake.mapped || fake.command || fake.releases != 1 ||
            fake.unmaps != 1 || fake.writes != 2 ||
            session.status().memoryDecodeChanged ||
            session.status().cleanupResult != PciSessionResult::Ok ||
            session.status().readAccessReady)
            return 3;
    }
    {
        FakePci fake {};
        fake.command = 4; // Inherited bus master is never acceptable.
        PciReadOnlySession session;
        if (session.start(fake.backend()) !=
                PciSessionResult::InheritedBusMaster ||
            fake.releases != 1 || fake.maps || fake.writes || fake.command != 4)
            return 4;
    }
    {
        FakePci fake {};
        fake.mapAllowed = false;
        PciReadOnlySession session;
        if (session.start(fake.backend()) != PciSessionResult::MappingFailed ||
            fake.command || fake.releases != 1 || fake.maps != 1 ||
            fake.unmaps || fake.writes != 2 ||
            session.status().memoryDecodeChanged)
            return 5;
    }
    {
        FakePci fake {};
        fake.barLength = kRtcStatusRegister; // Too short for RTC word.
        PciReadOnlySession session;
        if (session.start(fake.backend()) != PciSessionResult::InvalidBar ||
            fake.command || fake.releases != 1 || fake.unmaps != 1 ||
            session.status().memoryDecodeChanged)
            return 6;
    }
    {
        FakePci fake {};
        fake.enableWriteFails = true;
        // Simulate a failed write that nevertheless reached device hardware.
        PciReadOnlySession session;
        if (session.start(fake.backend()) !=
                PciSessionResult::CommandWriteFailed ||
            fake.command || fake.writes != 2 || fake.releases != 1 ||
            session.status().cleanupResult != PciSessionResult::Ok ||
            session.status().memoryDecodeChanged)
            return 7;
    }
    {
        FakePci fake {};
        fake.commandMutatedOnEnable = true;
        PciReadOnlySession session;
        if (session.start(fake.backend()) !=
                PciSessionResult::CommandReadbackFailed ||
            fake.command != 0x0102 || fake.writes != 1 || fake.releases != 1 ||
            session.status().cleanupResult !=
                PciSessionResult::DecodeRestoreFailed ||
            !session.status().memoryDecodeChanged ||
            session.start(fake.backend()) != PciSessionResult::WrongState)
            return 8;
    }
    {
        FakePci fake {};
        PciReadOnlySession session;
        if (session.start(fake.backend()) != PciSessionResult::Ok)
            return 9;
        fake.disableWriteFails = true;
        session.stop(ProviderAccess::Available);
        if (fake.command != 2 || fake.writes != 2 || fake.releases != 1 ||
            fake.unmaps != 1 ||
            session.status().cleanupResult !=
                PciSessionResult::DecodeRestoreFailed ||
            !session.status().memoryDecodeChanged ||
            session.start(fake.backend()) != PciSessionResult::WrongState ||
            fake.claims != 1)
            return 10;
    }
    {
        FakePci fake {};
        PciReadOnlySession session;
        if (session.start(fake.backend()) != PciSessionResult::Ok)
            return 11;
        fake.powered = false;
        const unsigned reads = fake.reads;
        session.stop(ProviderAccess::Unavailable);
        if (fake.reads != reads || fake.writes != 1 || fake.unmaps != 1 ||
            fake.releases != 1 || fake.mapped ||
            session.status().cleanupResult !=
                PciSessionResult::ProviderUnavailable ||
            !session.status().memoryDecodeChanged ||
            session.start(fake.backend()) != PciSessionResult::WrongState)
            return 12;
    }
    {
        FakePci fake {};
        PciReadOnlySession session;
        if (session.start(fake.backend()) != PciSessionResult::Ok)
            return 13;
        fake.registerReadFails = true;
        if (session.inspect() != PciSessionResult::CoreRejected ||
            session.status().coreInspectResult != Result::RegisterReadFailed ||
            fake.claimed || fake.mapped || fake.command || fake.releases != 1 ||
            fake.unmaps != 1 || session.status().readAccessReady)
            return 14;
    }
    {
        FakePci fake {};
        fake.powered = false;
        PciReadOnlySession session;
        if (session.start(fake.backend()) != PciSessionResult::NotInD0 ||
            fake.releases != 1 || fake.maps || fake.writes || fake.claimed)
            return 15;
    }
    {
        FakePci fake {};
        fake.command = 2; // Preexisting memory decode belongs to prior owner.
        PciReadOnlySession session;
        if (session.start(fake.backend()) != PciSessionResult::Ok ||
            session.status().memoryDecodeChanged || fake.writes)
            return 16;
        session.stop(ProviderAccess::Available);
        if (fake.command != 2 || fake.writes || fake.releases != 1 ||
            fake.unmaps != 1)
            return 17;
    }
    {
        FakePci fake {};
        fake.enableWriteTakesEffect = false;
        PciReadOnlySession session;
        if (session.start(fake.backend()) !=
                PciSessionResult::CommandReadbackFailed ||
            fake.writes != 1 || fake.command || fake.releases != 1 ||
            session.status().cleanupResult != PciSessionResult::Ok ||
            session.status().memoryDecodeChanged)
            return 18;
    }
    {
        FakePci fake {};
        fake.claimAllowed = false;
        PciReadOnlySession session;
        if (session.start(fake.backend()) !=
                PciSessionResult::OwnershipDenied ||
            fake.claims != 1 || fake.releases || fake.maps || fake.writes)
            return 19;
    }
    {
        FakePci fake {};
        fake.powerDropsOnReadback = true;
        PciReadOnlySession session;
        if (session.start(fake.backend()) !=
                PciSessionResult::CommandReadbackFailed ||
            fake.powered || fake.command != 2 || fake.writes != 1 ||
            fake.releases != 1 || fake.maps || fake.unmaps ||
            session.status().cleanupResult !=
                PciSessionResult::ProviderUnavailable ||
            !session.status().memoryDecodeChanged ||
            session.start(fake.backend()) != PciSessionResult::WrongState)
            return 20;
    }
    {
        FakePci fake {};
        PciReadOnlySession session;
        if (session.start(fake.backend()) != PciSessionResult::Ok)
            return 21;
        fake.powered = false; // D0 lost between start and core register read.
        if (session.inspect() != PciSessionResult::CoreRejected ||
            session.status().coreInspectResult != Result::RegisterReadFailed ||
            session.status().cleanupResult !=
                PciSessionResult::ProviderUnavailable ||
            !session.status().memoryDecodeChanged || fake.writes != 1 ||
            fake.unmaps != 1 || fake.releases != 1 || fake.claimed)
            return 22;
        session.stop(ProviderAccess::Unavailable); // Idempotent late stop.
        if (fake.releases != 1 || fake.unmaps != 1 || fake.writes != 1 ||
            session.start(fake.backend()) != PciSessionResult::WrongState)
            return 23;
    }
    return 0;
}
