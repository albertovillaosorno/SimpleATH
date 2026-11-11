// Copyright:
//   - Copyright © 2026 Alberto Villa Osorno
// SPDX-License-Identifier:
//   - MIT
// Confidential:
//   - false
// License-File:
//   - LICENSE-MIT
// Provenance:
//   - SimpleATH original; independently developed or locally authored
//
// Boundary-Contract:
// - Owns:
//   - Offline regression cases for pci session.
// - Must-Not:
//   - Require physical hardware, mutate installed drivers, or suppress
//     failures.
// - Allows:
//   - Inputs: isolated fixtures and reproducible source-under-test inputs.
//   - Outputs: assertions and observable regression verdicts.
//   - Side effects: test-local temporary files and bounded subprocesses only.
// - Split-When:
//   - A separate protocol stage needs independent validation and ownership.
// - Merge-When:
//   - The caller directly owns this narrow contract without reuse.
// - Summary:
//   - Offline regression cases for pci session.
// - Description:
//   - Implements or verifies the test_pci_session source boundary.
// - Usage:
//   - Executed by offline host test discovery or the native test harness.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Offline regression cases for pci session.
// Synthetic PCI callback contract only: no IOKit, PCI hardware or kext build.
#include "hardware/Ar9565Core.hpp"
#include "platform/Ar9565PciSession.hpp"
#include <array>
#include <cstdint>

using namespace simpleath;

namespace
{
    // Exact PCI config-space wire layout and synthetic device identity.
    constexpr uint16_t kPciSubsystemIdOffset = 0x2cU;
    constexpr uint16_t kPciClassRevisionOffset = 0x08U;
    constexpr uint16_t kPciHeaderTypeOffset = 0x0cU;
    constexpr uint16_t kPciBar0Offset = 0x10U;
    constexpr uint32_t kAtherosVendorDevice = 0x0036168cU;
    constexpr uint32_t kSyntheticSubsystem = 0x12345678U;
    constexpr uint32_t kNetworkControllerRevision = 0x02800001U;
    constexpr uint32_t kPciStatusUpperWord = 0xa5a50000U;
    constexpr uint32_t kSyntheticMappedBar = 0x80001000U;
    constexpr uint16_t kUnexpectedCommandBit = 0x0100U;
    constexpr uint16_t kUnexpectedCommandReadback = 0x0102U;
    constexpr uint16_t kUnsafeMemoryDecodeAndBusMaster = 0x0006U;
    constexpr uint32_t kRevisionWordShift = 12U;
    constexpr uint32_t kRevisionLowByteMask = 0xffU;

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
    };

    // Keep the simulated PCI registers as an ordinary aggregate. Its I/O
    // callbacks belong to a separate adapter, not to the mutable test state.
    struct FakePciCallbacks
    {
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
                        *value =
                            kAtherosVendorDevice; // Device 0036, Atheros 168c.
                        return true;
                    case kPciSubsystemIdOffset:
                        *value = kSyntheticSubsystem;
                        return true;
                    case kPciClassRevisionOffset:
                        *value = kNetworkControllerRevision; // Network/other,
                                                             // revision 1.
                        return true;
                    case kPciHeaderTypeOffset:
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
                        *value = kPciStatusUpperWord |
                                 self.command; // Preserve status.
                        if (((self.powerDropsAfterReadback ||
                              self.powerDropsDuringRollbackRead) &&
                             ((self.command & 2U) != 0U)) ||
                            (self.powerDropsDuringRollbackVerification &&
                             ((self.command & 2U) == 0U)))
                        {
                            self.powered = false;
                        }
                        return true;
                    case kPciBar0Offset:
                        *value =
                            kSyntheticMappedBar; // Assigned 32-bit MMIO BAR.
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
                            (self.commandMutatedOnEnable ? kUnexpectedCommandBit
                                                         : 0U));
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
                        *value = (static_cast<uint32_t>(kMacFamily)
                                  << kRevisionWordShift) |
                                 kRevisionLowByteMask;
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
    };

    PciSessionBackend backend(FakePci &fake)
    {
        return {
            &fake,
            FakePciCallbacks::claim,
            FakePciCallbacks::release,
            FakePciCallbacks::inD0,
            FakePciCallbacks::configRead,
            FakePciCallbacks::commandWrite,
            FakePciCallbacks::map,
            FakePciCallbacks::unmap,
            FakePciCallbacks::barRead,
        };
    }

    // Preserve stable error codes for the standalone PCI session fixture.
    constexpr int kPciFailureCode1 = 1;
    constexpr int kPciFailureCode2 = 2;
    constexpr int kPciFailureCode3 = 3;
    constexpr int kPciFailureCode4 = 4;
    constexpr int kPciFailureCode5 = 5;
    constexpr int kPciFailureCode6 = 6;
    constexpr int kPciFailureCode7 = 7;
    constexpr int kPciFailureCode8 = 8;
    constexpr int kPciFailureCode9 = 9;
    constexpr int kPciFailureCode10 = 10;
    constexpr int kPciFailureCode11 = 11;
    constexpr int kPciFailureCode12 = 12;
    constexpr int kPciFailureCode13 = 13;
    constexpr int kPciFailureCode14 = 14;
    constexpr int kPciFailureCode15 = 15;
    constexpr int kPciFailureCode16 = 16;
    constexpr int kPciFailureCode17 = 17;
    constexpr int kPciFailureCode18 = 18;
    constexpr int kPciFailureCode19 = 19;
    constexpr int kPciFailureCode20 = 20;
    constexpr int kPciFailureCode21 = 21;
    constexpr int kPciFailureCode22 = 22;
    constexpr int kPciFailureCode23 = 23;
    constexpr int kPciFailureCode24 = 24;
    constexpr int kPciFailureCode25 = 25;
    constexpr int kPciFailureCode26 = 26;
    constexpr int kPciFailureCode27 = 27;
    constexpr int kPciFailureCode28 = 28;
    constexpr int kPciFailureCode29 = 29;
    constexpr int kPciFailureCode30 = 30;
    constexpr int kPciFailureCode31 = 31;
    constexpr int kPciFailureCode32 = 32;
    constexpr int kPciFailureCode33 = 33;
    constexpr int kPciFailureCode34 = 34;
    constexpr int kPciFailureCode35 = 35;
    constexpr int kPciFailureCode36 = 36;
    constexpr int kPciFailureCode37 = 37;
    constexpr int kPciFailureCode39 = 39;
    constexpr int kPciFailureCode40 = 40;
    constexpr int kPciFailureCode41 = 41;

    int checkPciSessionScenario1()
    {
        {
            FakePci fake {};
            PciReadOnlySession session;
            if (session.start(backend(fake)) != PciSessionResult::Ok ||
                !session.status().claimed || !session.status().mapped ||
                !session.status().readAccessReady ||
                !session.status().memoryDecodeChanged || fake.command != 2 ||
                fake.writes != 1 || fake.maps != 1)
            {
                return kPciFailureCode1;
            }
            if (session.inspect() != PciSessionResult::Ok ||
                session.hardwareStatus().stage !=
                    Stage::AwaitingResetAndCalibration ||
                !session.hardwareStatus().eepromAccessible ||
                session.status().coreInspectResult != Result::Ok)
            {
                return kPciFailureCode2;
            }
            session.stop(ProviderAccess::Available);
            if (fake.claimed || fake.mapped || (fake.command != 0U) ||
                fake.releases != 1 || fake.unmaps != 1 || fake.writes != 2 ||
                session.status().memoryDecodeChanged ||
                session.status().cleanupResult != PciSessionResult::Ok ||
                session.status().readAccessReady)
            {
                return kPciFailureCode3;
            }
        }
        return 0;
    }

    int checkPciSessionScenario2()
    {
        {
            FakePci fake {};
            fake.command = 4; // Inherited bus master is never acceptable.
            PciReadOnlySession session;
            if (session.start(backend(fake)) !=
                    PciSessionResult::InheritedBusMaster ||
                fake.releases != 1 || (fake.maps != 0U) ||
                (fake.writes != 0U) || fake.command != 4)
            {
                return kPciFailureCode4;
            }
        }
        return 0;
    }

    int checkPciSessionScenario3()
    {
        {
            FakePci fake {};
            fake.mapAllowed = false;
            PciReadOnlySession session;
            if (session.start(backend(fake)) !=
                    PciSessionResult::MappingFailed ||
                (fake.command != 0U) || fake.releases != 1 || fake.maps != 1 ||
                (fake.unmaps != 0U) || fake.writes != 2 ||
                session.status().memoryDecodeChanged)
            {
                return kPciFailureCode5;
            }
        }
        return 0;
    }

    int checkPciSessionScenario4()
    {
        {
            FakePci fake {};
            fake.barLength = kRtcStatusRegister; // Too short for RTC word.
            PciReadOnlySession session;
            if (session.start(backend(fake)) != PciSessionResult::InvalidBar ||
                (fake.command != 0U) || fake.releases != 1 ||
                fake.unmaps != 1 || session.status().memoryDecodeChanged)
            {
                return kPciFailureCode6;
            }
        }
        return 0;
    }

    int checkPciSessionScenario5()
    {
        {
            FakePci fake {};
            fake.enableWriteFails = true;
            // Simulate a failed write that nevertheless reached device
            // hardware.
            PciReadOnlySession session;
            if (session.start(backend(fake)) !=
                    PciSessionResult::CommandWriteFailed ||
                (fake.command != 0U) || fake.writes != 2 ||
                fake.releases != 1 ||
                session.status().cleanupResult != PciSessionResult::Ok ||
                session.status().memoryDecodeChanged)
            {
                return kPciFailureCode7;
            }
        }
        return 0;
    }

    int checkPciSessionScenario6()
    {
        {
            FakePci fake {};
            fake.commandMutatedOnEnable = true;
            PciReadOnlySession session;
            if (session.start(backend(fake)) !=
                    PciSessionResult::CommandReadbackFailed ||
                fake.command != kUnexpectedCommandReadback ||
                fake.writes != 1 || fake.releases != 1 ||
                session.status().cleanupResult !=
                    PciSessionResult::DecodeRestoreFailed ||
                !session.status().memoryDecodeChanged ||
                session.start(backend(fake)) != PciSessionResult::WrongState)
            {
                return kPciFailureCode8;
            }
        }
        return 0;
    }

    int checkPciSessionScenario7()
    {
        {
            FakePci fake {};
            PciReadOnlySession session;
            if (session.start(backend(fake)) != PciSessionResult::Ok)
            {
                return kPciFailureCode9;
            }
            fake.disableWriteFails = true;
            session.stop(ProviderAccess::Available);
            if (fake.command != 2 || fake.writes != 2 || fake.releases != 1 ||
                fake.unmaps != 1 ||
                session.status().cleanupResult !=
                    PciSessionResult::DecodeRestoreFailed ||
                !session.status().memoryDecodeChanged ||
                session.start(backend(fake)) != PciSessionResult::WrongState ||
                fake.claims != 1)
            {
                return kPciFailureCode10;
            }
        }
        return 0;
    }

    int checkPciSessionScenario8()
    {
        {
            FakePci fake {};
            PciReadOnlySession session;
            if (session.start(backend(fake)) != PciSessionResult::Ok)
            {
                return kPciFailureCode11;
            }
            fake.powered = false;
            const unsigned reads = fake.reads;
            session.stop(ProviderAccess::Unavailable);
            if (fake.reads != reads || fake.writes != 1 || fake.unmaps != 1 ||
                fake.releases != 1 || fake.mapped ||
                session.status().cleanupResult !=
                    PciSessionResult::ProviderUnavailable ||
                !session.status().memoryDecodeChanged ||
                session.start(backend(fake)) != PciSessionResult::WrongState)
            {
                return kPciFailureCode12;
            }
        }
        return 0;
    }

    int checkPciSessionScenario9()
    {
        {
            FakePci fake {};
            PciReadOnlySession session;
            if (session.start(backend(fake)) != PciSessionResult::Ok)
            {
                return kPciFailureCode13;
            }
            fake.registerReadFails = true;
            if (session.inspect() != PciSessionResult::CoreRejected ||
                session.status().coreInspectResult !=
                    Result::RegisterReadFailed ||
                fake.claimed || fake.mapped || (fake.command != 0U) ||
                fake.releases != 1 || fake.unmaps != 1 ||
                session.status().readAccessReady)
            {
                return kPciFailureCode14;
            }
        }
        return 0;
    }

    int checkPciSessionScenario10()
    {
        {
            FakePci fake {};
            fake.powered = false;
            PciReadOnlySession session;
            if (session.start(backend(fake)) != PciSessionResult::NotInD0 ||
                fake.releases != 1 || (fake.maps != 0U) ||
                (fake.writes != 0U) || fake.claimed)
            {
                return kPciFailureCode15;
            }
        }
        return 0;
    }

    int checkPciSessionScenario11()
    {
        {
            FakePci fake {};
            fake.command =
                2; // Preexisting memory decode belongs to prior owner.
            PciReadOnlySession session;
            if (session.start(backend(fake)) != PciSessionResult::Ok ||
                session.status().memoryDecodeChanged || (fake.writes != 0U))
            {
                return kPciFailureCode16;
            }
            session.stop(ProviderAccess::Available);
            if (fake.command != 2 || (fake.writes != 0U) ||
                fake.releases != 1 || fake.unmaps != 1)
            {
                return kPciFailureCode17;
            }
        }
        return 0;
    }

    int checkPciSessionScenario12()
    {
        {
            FakePci fake {};
            fake.enableWriteTakesEffect = false;
            PciReadOnlySession session;
            if (session.start(backend(fake)) !=
                    PciSessionResult::CommandReadbackFailed ||
                fake.writes != 1 || (fake.command != 0U) ||
                fake.releases != 1 ||
                session.status().cleanupResult != PciSessionResult::Ok ||
                session.status().memoryDecodeChanged)
            {
                return kPciFailureCode18;
            }
        }
        return 0;
    }

    int checkPciSessionScenario13()
    {
        {
            FakePci fake {};
            fake.claimAllowed = false;
            PciReadOnlySession session;
            if (session.start(backend(fake)) !=
                    PciSessionResult::OwnershipDenied ||
                fake.claims != 1 || (fake.releases != 0U) ||
                (fake.maps != 0U) || (fake.writes != 0U))
            {
                return kPciFailureCode19;
            }
        }
        return 0;
    }

    int checkPciSessionScenario14()
    {
        {
            FakePci fake {};
            fake.powerDropsOnReadback = true;
            PciReadOnlySession session;
            if (session.start(backend(fake)) !=
                    PciSessionResult::CommandReadbackFailed ||
                fake.powered || fake.command != 2 || fake.writes != 1 ||
                fake.releases != 1 || (fake.maps != 0U) ||
                (fake.unmaps != 0U) ||
                session.status().cleanupResult !=
                    PciSessionResult::ProviderUnavailable ||
                !session.status().memoryDecodeChanged ||
                session.start(backend(fake)) != PciSessionResult::WrongState)
            {
                return kPciFailureCode20;
            }
        }
        return 0;
    }

    int checkPciSessionScenario15()
    {
        {
            FakePci fake {};
            PciReadOnlySession session;
            if (session.start(backend(fake)) != PciSessionResult::Ok)
            {
                return kPciFailureCode21;
            }
            fake.powered =
                false; // D0 lost between start and core register read.
            if (session.inspect() != PciSessionResult::CoreRejected ||
                session.status().coreInspectResult !=
                    Result::RegisterReadFailed ||
                session.status().cleanupResult !=
                    PciSessionResult::ProviderUnavailable ||
                !session.status().memoryDecodeChanged || fake.writes != 1 ||
                fake.unmaps != 1 || fake.releases != 1 || fake.claimed)
            {
                return kPciFailureCode22;
            }
            session.stop(ProviderAccess::Unavailable); // Idempotent late stop.
            if (fake.releases != 1 || fake.unmaps != 1 || fake.writes != 1 ||
                session.start(backend(fake)) != PciSessionResult::WrongState)
            {
                return kPciFailureCode23;
            }
        }
        return 0;
    }

    int checkPciSessionScenario16()
    {
        {
            // A callback context forged from our retained session storage must
            // not reach even claim(), because the fake callback treats it as a
            // FakePci and would overwrite object/function-pointer state.
            FakePci fake {};
            PciReadOnlySession session;
            auto forgedBackend = backend(fake);
            forgedBackend.context = &session;
            if (session.start(forgedBackend) !=
                    PciSessionResult::MissingBackend ||
                (fake.claims != 0U) || (fake.writes != 0U) ||
                (fake.maps != 0U) || session.status().claimed ||
                session.status().mapped)
            {
                return kPciFailureCode24;
            }
            forgedBackend.context = &forgedBackend;
            if (session.start(forgedBackend) !=
                    PciSessionResult::MissingBackend ||
                (fake.claims != 0U) || (fake.writes != 0U) ||
                (fake.maps != 0U) || session.status().claimed ||
                session.status().mapped)
            {
                return kPciFailureCode25;
            }
            // A rejected malicious context does not poison a later legitimate
            // claim with the same already initialized session object.
            forgedBackend.context = &fake;
            if (session.start(forgedBackend) != PciSessionResult::Ok ||
                !session.status().readAccessReady || fake.claims != 1)
            {
                return kPciFailureCode26;
            }
            session.stop(ProviderAccess::Available);
            if (fake.claimed || fake.mapped || (fake.command != 0U) ||
                fake.releases != 1)
            {
                return kPciFailureCode27;
            }
        }
        return 0;
    }

    int checkPciSessionScenario17()
    {
        {
            // Readback succeeds just as D0 is revoked. Mapping may use a
            // provider context that is no longer valid, so do not call mapBar0
            // at all.
            FakePci fake {};
            fake.powerDropsAfterReadback = true;
            PciReadOnlySession session;
            if (session.start(backend(fake)) != PciSessionResult::NotInD0 ||
                fake.powered || (fake.maps != 0U) || (fake.unmaps != 0U) ||
                fake.writes != 1 || fake.releases != 1 || fake.claimed ||
                session.status().cleanupResult !=
                    PciSessionResult::ProviderUnavailable ||
                !session.status().memoryDecodeChanged ||
                session.start(backend(fake)) != PciSessionResult::WrongState)
            {
                return kPciFailureCode28;
            }
        }
        return 0;
    }

    int checkPciSessionScenario18()
    {
        {
            // BAR mapping can succeed just before provider access is revoked.
            // A successful map is not a license to publish a ready session.
            FakePci fake {};
            fake.powerDropsDuringMap = true;
            PciReadOnlySession session;
            if (session.start(backend(fake)) != PciSessionResult::NotInD0 ||
                fake.powered || fake.maps != 1 || fake.unmaps != 1 ||
                fake.writes != 1 || fake.releases != 1 || fake.mapped ||
                fake.claimed || session.status().readAccessReady ||
                session.status().cleanupResult !=
                    PciSessionResult::ProviderUnavailable ||
                !session.status().memoryDecodeChanged)
            {
                return kPciFailureCode29;
            }
        }
        return 0;
    }

    int checkPciSessionScenario19()
    {
        {
            // D0 may vanish while readBar0 itself is completing. In particular,
            // the last EEPROM read must not declare the old session inspected.
            const uint32_t revokeOffsets[] {
                kRevisionRegister,
                kEepromStatusRegister,
            };
            for (const uint32_t revokedAt : revokeOffsets)
            {
                FakePci fake {};
                PciReadOnlySession session;
                if (session.start(backend(fake)) != PciSessionResult::Ok)
                {
                    return kPciFailureCode30;
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
                    return kPciFailureCode31;
                }
            }
        }
        return 0;
    }

    int checkPciSessionScenario20()
    {
        {
            // A successful PCI command read during rollback may itself revoke
            // the provider's D0 authorization. No subsequent command write may
            // use the stale readback, even to restore memory decode.
            FakePci fake {};
            PciReadOnlySession session;
            if (session.start(backend(fake)) != PciSessionResult::Ok)
            {
                return kPciFailureCode32;
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
                session.start(backend(fake)) != PciSessionResult::WrongState)
            {
                return kPciFailureCode33;
            }
        }
        return 0;
    }

    int checkPciSessionScenario21()
    {
        {
            // Revocation may also occur on the *verification* read after a
            // successful memory-decode restore. Without rechecking D0, a stale
            // readback could incorrectly certify rollback as complete.
            FakePci fake {};
            PciReadOnlySession session;
            if (session.start(backend(fake)) != PciSessionResult::Ok)
            {
                return kPciFailureCode34;
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
                session.start(backend(fake)) != PciSessionResult::WrongState)
            {
                return kPciFailureCode35;
            }
        }
        return 0;
    }

    int checkPciSessionScenario22()
    {
        {
            // The final MMIO read can finish with a valid sample before the
            // provider revokes D0 during post-read parsing. Successful core
            // inspection alone cannot publish a still-ready PCI session.
            FakePci fake {};
            PciReadOnlySession session;
            if (session.start(backend(fake)) != PciSessionResult::Ok)
            {
                return kPciFailureCode36;
            }
            fake.powerDropsAfterFinalMmioCheck = true;
            if (session.inspect() != PciSessionResult::NotInD0 ||
                fake.powered || !fake.finalPowerCheckReturned ||
                fake.barReads != 3 ||
                session.status().coreInspectResult != Result::Ok ||
                session.status().readAccessReady || fake.claimed ||
                fake.mapped || fake.releases != 1 || fake.unmaps != 1 ||
                fake.writes != 1 ||
                session.status().cleanupResult !=
                    PciSessionResult::ProviderUnavailable ||
                !session.status().memoryDecodeChanged ||
                session.start(backend(fake)) != PciSessionResult::WrongState)
            {
                return kPciFailureCode37;
            }
        }
        return 0;
    }

    int checkPciSessionScenario23()
    {
        {
            // A successful post-map D0 gate cannot authorize publication after
            // software-only PCI/core setup if power disappears in the meantime.
            FakePci fake {};
            fake.powerDropsAfterMapOwnerCheck = true;
            PciReadOnlySession session;
            if (session.start(backend(fake)) != PciSessionResult::NotInD0 ||
                fake.powered || !fake.mapPowerCheckReturned || fake.maps != 1 ||
                fake.unmaps != 1 || fake.releases != 1 || fake.writes != 1 ||
                fake.claimed || fake.mapped ||
                session.status().readAccessReady ||
                session.status().cleanupResult !=
                    PciSessionResult::ProviderUnavailable ||
                !session.status().memoryDecodeChanged ||
                session.start(backend(fake)) != PciSessionResult::WrongState)
            {
                return kPciFailureCode39;
            }
        }
        return 0;
    }

    int checkPciSessionScenario24()
    {
        {
            // A BAR mapping callback can succeed while PCI command acquires
            // bus-master enable. Its earlier readback cannot authorize a
            // session after that drift, even if provider D0 remains confirmed.
            FakePci fake {};
            fake.busMasterAppearsDuringMap = true;
            PciReadOnlySession session;
            if (session.start(backend(fake)) !=
                    PciSessionResult::CommandReadbackFailed ||
                fake.command != kUnsafeMemoryDecodeAndBusMaster ||
                fake.maps != 1 || fake.unmaps != 1 || fake.releases != 1 ||
                fake.claimed || fake.mapped ||
                session.status().readAccessReady ||
                session.status().cleanupResult !=
                    PciSessionResult::DecodeRestoreFailed ||
                !session.status().memoryDecodeChanged ||
                session.start(backend(fake)) != PciSessionResult::WrongState)
            {
                return kPciFailureCode40;
            }
        }
        return 0;
    }

    int checkPciSessionScenario25()
    {
        {
            // Read-only MMIO callbacks must not turn a post-scan command change
            // into an apparently valid inspected session with bus mastering on.
            FakePci fake {};
            fake.busMasterAppearsDuringInspection = true;
            PciReadOnlySession session;
            if (session.start(backend(fake)) != PciSessionResult::Ok ||
                session.inspect() != PciSessionResult::CommandReadbackFailed ||
                fake.command != kUnsafeMemoryDecodeAndBusMaster ||
                fake.barReads != 3 || fake.releases != 1 || fake.unmaps != 1 ||
                fake.claimed || fake.mapped ||
                session.status().readAccessReady ||
                session.status().coreInspectResult != Result::Ok ||
                session.status().cleanupResult !=
                    PciSessionResult::DecodeRestoreFailed ||
                !session.status().memoryDecodeChanged ||
                session.start(backend(fake)) != PciSessionResult::WrongState)
            {
                return kPciFailureCode41;
            }
        }
        return 0;
    }
} // namespace

int main()
{
    // Stop on the first failed independent synthetic PCI scenario.
    constexpr std::array<int (*)(), 25U> cases {
        checkPciSessionScenario1,  checkPciSessionScenario2,
        checkPciSessionScenario3,  checkPciSessionScenario4,
        checkPciSessionScenario5,  checkPciSessionScenario6,
        checkPciSessionScenario7,  checkPciSessionScenario8,
        checkPciSessionScenario9,  checkPciSessionScenario10,
        checkPciSessionScenario11, checkPciSessionScenario12,
        checkPciSessionScenario13, checkPciSessionScenario14,
        checkPciSessionScenario15, checkPciSessionScenario16,
        checkPciSessionScenario17, checkPciSessionScenario18,
        checkPciSessionScenario19, checkPciSessionScenario20,
        checkPciSessionScenario21, checkPciSessionScenario22,
        checkPciSessionScenario23, checkPciSessionScenario24,
        checkPciSessionScenario25,
    };
    for (const auto scenario : cases)
    {
        const int result = scenario();
        if (result != 0)
        {
            return result;
        }
    }
    return 0;
}
