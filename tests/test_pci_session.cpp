// Copyright (c) 2026 Alberto Villa Osorno.
// Synthetic PCI callback contract only: no IOKit, PCI hardware or kext build.
#include "hardware/Ar9565Core.hpp"
#include "platform/Ar9565PciSession.hpp"
#include <cstdint>

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
            bool powerDropsAfterReadback = false;
            bool powerDropsDuringRollbackRead = false;
            bool powerDropsDuringRollbackVerification = false;
            bool powerDropsDuringMap = false;
            bool busMasterAppearsDuringMap = false;
            bool busMasterAppearsDuringInspection = false;
            bool powerDropsAfterMapOwnerCheck = false;
            bool mapPowerCheckReturned = false;
            bool powerDropsAfterFinalMmioCheck = false;
            bool finalEepromReadComplete = false;
            bool finalPowerCheckReturned = false;
            bool registerReadFails = false;
            uint32_t revokeAfterBarOffset = 0;
            uint32_t eepromStatus = 0;
            unsigned barReads = 0;
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
                {
                    return false;
                }
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
                auto &self = get(context);
                if (self.powerDropsAfterMapOwnerCheck && self.mapped &&
                    !self.mapPowerCheckReturned)
                {
                    // The post-map D0 preflight returns true just before
                    // software setup; a later publication check must see
                    // that ownership disappeared during that setup.
                    self.mapPowerCheckReturned = true;
                    self.powered = false;
                    return true;
                }
                if (self.powerDropsAfterFinalMmioCheck &&
                    self.finalEepromReadComplete &&
                    !self.finalPowerCheckReturned)
                {
                    // The final MMIO post-read D0 gate gets a true response
                    // before revocation. Parsing can then finish while D0 is
                    // gone; the PCI session must recheck before publishing.
                    self.finalPowerCheckReturned = true;
                    self.powered = false;
                    return true;
                }
                return self.powered;
            }

            static bool configRead(void *context, uint16_t offset,
                                   uint32_t *value)
            {
                auto &self = get(context);
                if (!self.claimed || !self.powered || (value == nullptr))
                {
                    return false;
                }
                ++self.reads;
                switch (offset)
                {
                    case 0x00:
                        *value = 0x0036168cU; // Device 0036, Atheros 168c.
                        return true;
                    case 0x2c:
                        *value = 0x12345678U;
                        return true;
                    case 0x08:
                        *value = 0x02800001U; // Network/other, revision 1.
                        return true;
                    case 0x0c:
                        *value = 0; // Type-0 header.
                        return true;
                    case 0x04:
                        if (self.powerDropsOnReadback &&
                            ((self.command & 2U) != 0U))
                        {
                            // The provider disappears after decode enable.
                            self.powered = false;
                            return false;
                        }
                        *value = 0xa5a50000U | self.command; // Preserve status.
                        if (((self.powerDropsAfterReadback ||
                              self.powerDropsDuringRollbackRead) &&
                             ((self.command & 2U) != 0U)) ||
                            (self.powerDropsDuringRollbackVerification &&
                             ((self.command & 2U) == 0U)))
                        {
                            self.powered = false;
                        }
                        return true;
                    case 0x10:
                        *value = 0x80001000U; // Assigned 32-bit MMIO BAR.
                        return true;
                    default:
                        return false;
                }
            }

            static bool commandWrite(void *context, uint16_t value)
            {
                auto &self = get(context);
                ++self.writes;
                if (!self.claimed || !self.powered || ((value & 4U) != 0U))
                {
                    return false; // No bus mastering, even in the fake.
                }
                if ((value & 2U) != 0U)
                {
                    if (self.enableWriteTakesEffect)
                    {
                        self.command = static_cast<uint16_t>(
                            value |
                            (self.commandMutatedOnEnable ? 0x0100U : 0U));
                    }
                    return !self.enableWriteFails;
                }
                if (self.disableWriteFails)
                {
                    return false;
                }
                self.command = value;
                return true;
            }

            static bool map(void *context, uint32_t *length)
            {
                auto &self = get(context);
                ++self.maps;
                if (!self.claimed || !self.powered || !self.mapAllowed ||
                    (length == nullptr) || ((self.command & 2U) == 0U))
                {
                    return false;
                }
                self.mapped = true;
                *length = self.barLength;
                if (self.busMasterAppearsDuringMap)
                {
                    self.command |= 4U;
                }
                if (self.powerDropsDuringMap)
                {
                    self.powered = false;
                }
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
                    self.registerReadFails || (value == nullptr) ||
                    ((self.command & 2U) == 0U))
                {
                    return false;
                }
                ++self.barReads;
                switch (offset)
                {
                    case kRevisionRegister:
                        *value =
                            (static_cast<uint32_t>(kMacFamily) << 12U) | 0xffU;
                        break;
                    case kRtcStatusRegister:
                        *value = kRtcOn;
                        break;
                    case kEepromStatusRegister:
                        *value = self.eepromStatus;
                        self.finalEepromReadComplete = true;
                        if (self.busMasterAppearsDuringInspection)
                        {
                            self.command |= 4U;
                        }
                        break;
                    default:
                        return false;
                }
                // Synthesize a provider disappearing precisely after a
                // successful MMIO sample, including the LAST EEPROM read.
                if (self.revokeAfterBarOffset == offset)
                {
                    self.powered = false;
                }
                return true;
            }

            PciSessionBackend backend()
            {
                return {
                    this,         claim, release, inD0,    configRead,
                    commandWrite, map,   unmap,   barRead,
                };
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
        {
            return 1;
        }
        if (session.inspect() != PciSessionResult::Ok ||
            session.hardwareStatus().stage !=
                Stage::AwaitingResetAndCalibration ||
            !session.hardwareStatus().eepromAccessible ||
            session.status().coreInspectResult != Result::Ok)
        {
            return 2;
        }
        session.stop(ProviderAccess::Available);
        if (fake.claimed || fake.mapped || (fake.command != 0U) ||
            fake.releases != 1 || fake.unmaps != 1 || fake.writes != 2 ||
            session.status().memoryDecodeChanged ||
            session.status().cleanupResult != PciSessionResult::Ok ||
            session.status().readAccessReady)
        {
            return 3;
        }
    }
    {
        FakePci fake {};
        fake.command = 4; // Inherited bus master is never acceptable.
        PciReadOnlySession session;
        if (session.start(fake.backend()) !=
                PciSessionResult::InheritedBusMaster ||
            fake.releases != 1 || (fake.maps != 0U) || (fake.writes != 0U) ||
            fake.command != 4)
        {
            return 4;
        }
    }
    {
        FakePci fake {};
        fake.mapAllowed = false;
        PciReadOnlySession session;
        if (session.start(fake.backend()) != PciSessionResult::MappingFailed ||
            (fake.command != 0U) || fake.releases != 1 || fake.maps != 1 ||
            (fake.unmaps != 0U) || fake.writes != 2 ||
            session.status().memoryDecodeChanged)
        {
            return 5;
        }
    }
    {
        FakePci fake {};
        fake.barLength = kRtcStatusRegister; // Too short for RTC word.
        PciReadOnlySession session;
        if (session.start(fake.backend()) != PciSessionResult::InvalidBar ||
            (fake.command != 0U) || fake.releases != 1 || fake.unmaps != 1 ||
            session.status().memoryDecodeChanged)
        {
            return 6;
        }
    }
    {
        FakePci fake {};
        fake.enableWriteFails = true;
        // Simulate a failed write that nevertheless reached device hardware.
        PciReadOnlySession session;
        if (session.start(fake.backend()) !=
                PciSessionResult::CommandWriteFailed ||
            (fake.command != 0U) || fake.writes != 2 || fake.releases != 1 ||
            session.status().cleanupResult != PciSessionResult::Ok ||
            session.status().memoryDecodeChanged)
        {
            return 7;
        }
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
        {
            return 8;
        }
    }
    {
        FakePci fake {};
        PciReadOnlySession session;
        if (session.start(fake.backend()) != PciSessionResult::Ok)
        {
            return 9;
        }
        fake.disableWriteFails = true;
        session.stop(ProviderAccess::Available);
        if (fake.command != 2 || fake.writes != 2 || fake.releases != 1 ||
            fake.unmaps != 1 ||
            session.status().cleanupResult !=
                PciSessionResult::DecodeRestoreFailed ||
            !session.status().memoryDecodeChanged ||
            session.start(fake.backend()) != PciSessionResult::WrongState ||
            fake.claims != 1)
        {
            return 10;
        }
    }
    {
        FakePci fake {};
        PciReadOnlySession session;
        if (session.start(fake.backend()) != PciSessionResult::Ok)
        {
            return 11;
        }
        fake.powered = false;
        const unsigned reads = fake.reads;
        session.stop(ProviderAccess::Unavailable);
        if (fake.reads != reads || fake.writes != 1 || fake.unmaps != 1 ||
            fake.releases != 1 || fake.mapped ||
            session.status().cleanupResult !=
                PciSessionResult::ProviderUnavailable ||
            !session.status().memoryDecodeChanged ||
            session.start(fake.backend()) != PciSessionResult::WrongState)
        {
            return 12;
        }
    }
    {
        FakePci fake {};
        PciReadOnlySession session;
        if (session.start(fake.backend()) != PciSessionResult::Ok)
        {
            return 13;
        }
        fake.registerReadFails = true;
        if (session.inspect() != PciSessionResult::CoreRejected ||
            session.status().coreInspectResult != Result::RegisterReadFailed ||
            fake.claimed || fake.mapped || (fake.command != 0U) ||
            fake.releases != 1 || fake.unmaps != 1 ||
            session.status().readAccessReady)
        {
            return 14;
        }
    }
    {
        FakePci fake {};
        fake.powered = false;
        PciReadOnlySession session;
        if (session.start(fake.backend()) != PciSessionResult::NotInD0 ||
            fake.releases != 1 || (fake.maps != 0U) || (fake.writes != 0U) ||
            fake.claimed)
        {
            return 15;
        }
    }
    {
        FakePci fake {};
        fake.command = 2; // Preexisting memory decode belongs to prior owner.
        PciReadOnlySession session;
        if (session.start(fake.backend()) != PciSessionResult::Ok ||
            session.status().memoryDecodeChanged || (fake.writes != 0U))
        {
            return 16;
        }
        session.stop(ProviderAccess::Available);
        if (fake.command != 2 || (fake.writes != 0U) || fake.releases != 1 ||
            fake.unmaps != 1)
        {
            return 17;
        }
    }
    {
        FakePci fake {};
        fake.enableWriteTakesEffect = false;
        PciReadOnlySession session;
        if (session.start(fake.backend()) !=
                PciSessionResult::CommandReadbackFailed ||
            fake.writes != 1 || (fake.command != 0U) || fake.releases != 1 ||
            session.status().cleanupResult != PciSessionResult::Ok ||
            session.status().memoryDecodeChanged)
        {
            return 18;
        }
    }
    {
        FakePci fake {};
        fake.claimAllowed = false;
        PciReadOnlySession session;
        if (session.start(fake.backend()) !=
                PciSessionResult::OwnershipDenied ||
            fake.claims != 1 || (fake.releases != 0U) || (fake.maps != 0U) ||
            (fake.writes != 0U))
        {
            return 19;
        }
    }
    {
        FakePci fake {};
        fake.powerDropsOnReadback = true;
        PciReadOnlySession session;
        if (session.start(fake.backend()) !=
                PciSessionResult::CommandReadbackFailed ||
            fake.powered || fake.command != 2 || fake.writes != 1 ||
            fake.releases != 1 || (fake.maps != 0U) || (fake.unmaps != 0U) ||
            session.status().cleanupResult !=
                PciSessionResult::ProviderUnavailable ||
            !session.status().memoryDecodeChanged ||
            session.start(fake.backend()) != PciSessionResult::WrongState)
        {
            return 20;
        }
    }
    {
        FakePci fake {};
        PciReadOnlySession session;
        if (session.start(fake.backend()) != PciSessionResult::Ok)
        {
            return 21;
        }
        fake.powered = false; // D0 lost between start and core register read.
        if (session.inspect() != PciSessionResult::CoreRejected ||
            session.status().coreInspectResult != Result::RegisterReadFailed ||
            session.status().cleanupResult !=
                PciSessionResult::ProviderUnavailable ||
            !session.status().memoryDecodeChanged || fake.writes != 1 ||
            fake.unmaps != 1 || fake.releases != 1 || fake.claimed)
        {
            return 22;
        }
        session.stop(ProviderAccess::Unavailable); // Idempotent late stop.
        if (fake.releases != 1 || fake.unmaps != 1 || fake.writes != 1 ||
            session.start(fake.backend()) != PciSessionResult::WrongState)
        {
            return 23;
        }
    }
    {
        // A callback context forged from our retained session storage must
        // not reach even claim(), because the fake callback treats it as a
        // FakePci and would overwrite object/function-pointer state.
        FakePci fake {};
        PciReadOnlySession session;
        auto backend = fake.backend();
        backend.context = &session;
        if (session.start(backend) != PciSessionResult::MissingBackend ||
            (fake.claims != 0U) || (fake.writes != 0U) || (fake.maps != 0U) ||
            session.status().claimed || session.status().mapped)
        {
            return 24;
        }
        backend.context = &backend;
        if (session.start(backend) != PciSessionResult::MissingBackend ||
            (fake.claims != 0U) || (fake.writes != 0U) || (fake.maps != 0U) ||
            session.status().claimed || session.status().mapped)
        {
            return 25;
        }
        // A rejected malicious context does not poison a later legitimate
        // claim with the same already initialized session object.
        backend.context = &fake;
        if (session.start(backend) != PciSessionResult::Ok ||
            !session.status().readAccessReady || fake.claims != 1)
        {
            return 26;
        }
        session.stop(ProviderAccess::Available);
        if (fake.claimed || fake.mapped || (fake.command != 0U) ||
            fake.releases != 1)
        {
            return 27;
        }
    }
    {
        // Readback succeeds just as D0 is revoked. Mapping may use a provider
        // context that is no longer valid, so do not call mapBar0 at all.
        FakePci fake {};
        fake.powerDropsAfterReadback = true;
        PciReadOnlySession session;
        if (session.start(fake.backend()) != PciSessionResult::NotInD0 ||
            fake.powered || (fake.maps != 0U) || (fake.unmaps != 0U) ||
            fake.writes != 1 || fake.releases != 1 || fake.claimed ||
            session.status().cleanupResult !=
                PciSessionResult::ProviderUnavailable ||
            !session.status().memoryDecodeChanged ||
            session.start(fake.backend()) != PciSessionResult::WrongState)
        {
            return 28;
        }
    }
    {
        // BAR mapping can succeed just before provider access is revoked.
        // A successful map is not a license to publish a ready session.
        FakePci fake {};
        fake.powerDropsDuringMap = true;
        PciReadOnlySession session;
        if (session.start(fake.backend()) != PciSessionResult::NotInD0 ||
            fake.powered || fake.maps != 1 || fake.unmaps != 1 ||
            fake.writes != 1 || fake.releases != 1 || fake.mapped ||
            fake.claimed || session.status().readAccessReady ||
            session.status().cleanupResult !=
                PciSessionResult::ProviderUnavailable ||
            !session.status().memoryDecodeChanged)
        {
            return 29;
        }
    }
    {
        // D0 may vanish while readBar0 itself is completing. In particular,
        // the last EEPROM read must not declare the old session inspected.
        const uint32_t revokeOffsets[] {
            kRevisionRegister,
            kEepromStatusRegister,
        };
        for (uint32_t revokedAt : revokeOffsets)
        {
            FakePci fake {};
            PciReadOnlySession session;
            if (session.start(fake.backend()) != PciSessionResult::Ok)
            {
                return 30;
            }
            fake.revokeAfterBarOffset = revokedAt;
            if (session.inspect() != PciSessionResult::CoreRejected ||
                session.status().coreInspectResult !=
                    Result::RegisterReadFailed ||
                session.status().cleanupResult !=
                    PciSessionResult::ProviderUnavailable ||
                session.status().readAccessReady ||
                !session.status().memoryDecodeChanged || fake.powered ||
                fake.claimed || fake.mapped || fake.releases != 1 ||
                fake.unmaps != 1 || fake.writes != 1 ||
                fake.barReads != (revokedAt == kRevisionRegister ? 1U : 3U))
            {
                return 31;
            }
        }
    }
    {
        // A successful PCI command read during rollback may itself revoke
        // the provider's D0 authorization. No subsequent command write may
        // use the stale readback, even to restore memory decode.
        FakePci fake {};
        PciReadOnlySession session;
        if (session.start(fake.backend()) != PciSessionResult::Ok)
        {
            return 32;
        }
        const unsigned readsBeforeStop = fake.reads;
        fake.powerDropsDuringRollbackRead = true;
        session.stop(ProviderAccess::Available);
        if (fake.powered || fake.command != 2 || fake.writes != 1 ||
            fake.reads != readsBeforeStop + 1 || fake.releases != 1 ||
            fake.unmaps != 1 || fake.claimed || fake.mapped ||
            session.status().cleanupResult !=
                PciSessionResult::ProviderUnavailable ||
            !session.status().memoryDecodeChanged ||
            session.start(fake.backend()) != PciSessionResult::WrongState)
        {
            return 33;
        }
    }
    {
        // Revocation may also occur on the *verification* read after a
        // successful memory-decode restore. Without rechecking D0, a stale
        // readback could incorrectly certify rollback as complete.
        FakePci fake {};
        PciReadOnlySession session;
        if (session.start(fake.backend()) != PciSessionResult::Ok)
        {
            return 34;
        }
        const unsigned readsBeforeStop = fake.reads;
        fake.powerDropsDuringRollbackVerification = true;
        session.stop(ProviderAccess::Available);
        if (fake.powered || (fake.command != 0U) || fake.writes != 2 ||
            fake.reads != readsBeforeStop + 2 || fake.releases != 1 ||
            fake.unmaps != 1 || fake.claimed || fake.mapped ||
            session.status().cleanupResult !=
                PciSessionResult::ProviderUnavailable ||
            !session.status().memoryDecodeChanged ||
            session.start(fake.backend()) != PciSessionResult::WrongState)
        {
            return 35;
        }
    }
    {
        // The final MMIO read can finish with a valid sample before the
        // provider revokes D0 during post-read parsing. Successful core
        // inspection alone cannot publish a still-ready PCI session.
        FakePci fake {};
        PciReadOnlySession session;
        if (session.start(fake.backend()) != PciSessionResult::Ok)
        {
            return 36;
        }
        fake.powerDropsAfterFinalMmioCheck = true;
        if (session.inspect() != PciSessionResult::NotInD0 || fake.powered ||
            !fake.finalPowerCheckReturned || fake.barReads != 3 ||
            session.status().coreInspectResult != Result::Ok ||
            session.status().readAccessReady || fake.claimed || fake.mapped ||
            fake.releases != 1 || fake.unmaps != 1 || fake.writes != 1 ||
            session.status().cleanupResult !=
                PciSessionResult::ProviderUnavailable ||
            !session.status().memoryDecodeChanged ||
            session.start(fake.backend()) != PciSessionResult::WrongState)
        {
            return 37;
        }
    }
    {
        // A successful post-map D0 gate cannot authorize publication after
        // software-only PCI/core setup if power disappears in the meantime.
        FakePci fake {};
        fake.powerDropsAfterMapOwnerCheck = true;
        PciReadOnlySession session;
        if (session.start(fake.backend()) != PciSessionResult::NotInD0 ||
            fake.powered || !fake.mapPowerCheckReturned || fake.maps != 1 ||
            fake.unmaps != 1 || fake.releases != 1 || fake.writes != 1 ||
            fake.claimed || fake.mapped || session.status().readAccessReady ||
            session.status().cleanupResult !=
                PciSessionResult::ProviderUnavailable ||
            !session.status().memoryDecodeChanged ||
            session.start(fake.backend()) != PciSessionResult::WrongState)
        {
            return 39;
        }
    }
    {
        // A BAR mapping callback can succeed while PCI command acquires
        // bus-master enable. Its earlier readback cannot authorize a session
        // after that drift, even if provider D0 remains confirmed.
        FakePci fake {};
        fake.busMasterAppearsDuringMap = true;
        PciReadOnlySession session;
        if (session.start(fake.backend()) !=
                PciSessionResult::CommandReadbackFailed ||
            fake.command != 6U || fake.maps != 1 || fake.unmaps != 1 ||
            fake.releases != 1 || fake.claimed || fake.mapped ||
            session.status().readAccessReady ||
            session.status().cleanupResult !=
                PciSessionResult::DecodeRestoreFailed ||
            !session.status().memoryDecodeChanged ||
            session.start(fake.backend()) != PciSessionResult::WrongState)
        {
            return 40;
        }
    }
    {
        // Read-only MMIO callbacks must not turn a post-scan command change
        // into an apparently valid inspected session with bus mastering on.
        FakePci fake {};
        fake.busMasterAppearsDuringInspection = true;
        PciReadOnlySession session;
        if (session.start(fake.backend()) != PciSessionResult::Ok ||
            session.inspect() != PciSessionResult::CommandReadbackFailed ||
            fake.command != 6U || fake.barReads != 3 || fake.releases != 1 ||
            fake.unmaps != 1 || fake.claimed || fake.mapped ||
            session.status().readAccessReady ||
            session.status().coreInspectResult != Result::Ok ||
            session.status().cleanupResult !=
                PciSessionResult::DecodeRestoreFailed ||
            !session.status().memoryDecodeChanged ||
            session.start(fake.backend()) != PciSessionResult::WrongState)
        {
            return 41;
        }
    }
    return 0;
}
