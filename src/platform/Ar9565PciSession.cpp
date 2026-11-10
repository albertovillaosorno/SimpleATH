// SPDX-License-Identifier: AGPL-3.0-only
#include "Ar9565PciSession.hpp"
#include "hardware/Ar9565Core.hpp"
#include <cstddef>
#include <cstdint>

namespace simpleath
{
    namespace
    {
        constexpr uint16_t kMemoryDecode = 0x0002;
        constexpr uint16_t kBusMaster = 0x0004;
        constexpr uint32_t kMinimumInspectionBar = kRtcStatusRegister + 4;
        constexpr uint16_t kPciCommandOffset = 0x04U;
        constexpr uint16_t kPciClassRevisionOffset = 0x08U;
        constexpr uint16_t kPciHeaderOffset = 0x0cU;
        constexpr uint16_t kPciBar0Offset = 0x10U;
        constexpr uint16_t kPciBar0HighOffset = 0x14U;
        constexpr uint16_t kPciSubsystemOffset = 0x2cU;
        constexpr uint16_t kPciConfigMaxOffset = 0xfcU;
        constexpr uint32_t kInvalidConfigRead = UINT32_MAX;
        constexpr uint32_t kPciWordHighShift = 16U;
        constexpr uint32_t kPciHeaderTypeMask = 0x7fU;
        constexpr uint32_t kPciWirelessClass = 0x0280U;
        constexpr uint32_t kPciBarReservedMask = 0x09U;
        constexpr uint32_t kPciBarAddressMask = 0xfffffff0U;
        constexpr uint32_t kPciMemoryBarTypeShift = 1U;
        constexpr uint32_t kPciOtherCommandBits = 0xffffU ^ kMemoryDecode;

        bool overlaps(const void *a, size_t aBytes, const void *b,
                      size_t bBytes)
        {
            if ((a == nullptr) || (b == nullptr) || (aBytes == 0U) ||
                (bBytes == 0U))
            {
                return false;
            }
            uintptr_t first = 0;
            uintptr_t second = 0;
            static_assert(sizeof(uintptr_t) == sizeof(a),
                          "portable PCI pointers must fit uintptr_t");
            __builtin_memcpy(&first, static_cast<const void *>(&a), sizeof(a));
            __builtin_memcpy(&second, static_cast<const void *>(&b), sizeof(b));
            return first <= second ? second - first < aBytes
                                   : first - second < bBytes;
        }

        bool validBackend(const PciSessionBackend &backend)
        {
            return backend.context != nullptr && backend.claim != nullptr &&
                   backend.release != nullptr && backend.inD0 != nullptr &&
                   backend.configRead32 != nullptr &&
                   backend.commandWrite16 != nullptr &&
                   backend.mapBar0 != nullptr && backend.unmapBar0 != nullptr &&
                   backend.readBar0 != nullptr;
        }

        bool validPciWirelessFunction(uint32_t id, uint32_t header,
                                      uint32_t classRevision)
        {
            return isSupportedPci(
                       static_cast<uint16_t>(id),
                       static_cast<uint16_t>(id >> kPciWordHighShift)) &&
                   ((header >> kPciWordHighShift) & kPciHeaderTypeMask) == 0U &&
                   (classRevision >> kPciWordHighShift) == kPciWirelessClass;
        }

        bool validPciBarType(uint32_t bar, uint32_t kind)
        {
            return (bar & kPciBarReservedMask) == 0U &&
                   (kind == 0U || kind == 2U);
        }

        // If anything except memory decode changes, ownership is no longer
        // proven. Never restore a stale PCI command word over those changes.
        bool commandBitsChanged(uint32_t observed, uint16_t original)
        {
            return ((static_cast<uint32_t>(static_cast<uint16_t>(observed)) ^
                     static_cast<uint32_t>(original)) &
                    kPciOtherCommandBits) != 0U;
        }
    } // namespace

    PciReadOnlySession::PciReadOnlySession() : backend_ {}, status_ {}
    {
    }

    PciReadOnlySession::~PciReadOnlySession()
    {
        // Normal teardown must happen explicitly before the owner destroys the
        // backend context. Never assume powered/config-accessible in a
        // destructor.
        stop(ProviderAccess::Unavailable);
    }

    bool PciReadOnlySession::readConfig(uint16_t offset, uint32_t &value) const
    {
        return status_.claimed && backend_.inD0(backend_.context) &&
               (offset & 3U) == 0 && offset <= kPciConfigMaxOffset &&
               backend_.configRead32(backend_.context, offset, &value) &&
               value != kInvalidConfigRead;
    }

    PciSessionResult PciReadOnlySession::start(const PciSessionBackend &backend)
    {
        // An opaque callback context cannot be the session or the supplied
        // callback table. Otherwise a first claim callback can overwrite our
        // ownership state or future function pointers. Check before clearing
        // any state; an alias error is signaled only by its return value.
        if (overlaps(&backend, sizeof(backend), this, sizeof(*this)) ||
            overlaps(backend.context, 1, this, sizeof(*this)) ||
            overlaps(backend.context, 1, &backend, sizeof(backend)))
        {
            return PciSessionResult::MissingBackend;
        }
        if (status_.claimed || status_.mapped || status_.memoryDecodeChanged)
        {
            return status_.lastResult = PciSessionResult::WrongState;
        }
        device_.detach();
        status_ = {};
        if (!validBackend(backend))
        {
            return status_.lastResult = PciSessionResult::MissingBackend;
        }
        backend_ = backend;
        if (!backend_.claim(backend_.context))
        {
            backend_ = {};
            return status_.lastResult = PciSessionResult::OwnershipDenied;
        }
        status_.claimed = true;
        if (!backend_.inD0(backend_.context))
        {
            return failStart(PciSessionResult::NotInD0);
        }

        uint32_t id = 0;
        uint32_t subsystem = 0;
        uint32_t classRevision = 0;
        uint32_t header = 0;
        uint32_t command = 0;
        if (!readConfig(0x00, id) ||
            !readConfig(kPciSubsystemOffset, subsystem) ||
            !readConfig(kPciClassRevisionOffset, classRevision) ||
            !readConfig(kPciHeaderOffset, header) ||
            !readConfig(kPciCommandOffset, command))
        {
            return failStart(PciSessionResult::ConfigReadFailed);
        }
        // AR9565 is a type-0 PCI wireless network function (class 0x0280).
        if (!validPciWirelessFunction(id, header, classRevision))
        {
            return failStart(PciSessionResult::UnsupportedFunction);
        }
        status_.originalCommand = static_cast<uint16_t>(command);
        if ((command & kBusMaster) != 0U)
        {
            return failStart(PciSessionResult::InheritedBusMaster);
        }

        return finishStartAfterConfig(PciStartSnapshot {
            id,
            subsystem,
            command,
        });
    }

    PciSessionResult
    PciReadOnlySession::finishStartAfterConfig(const PciStartSnapshot &snapshot)
    {
        const uint32_t id = snapshot.id;
        const uint32_t subsystem = snapshot.subsystem;
        uint32_t command = snapshot.command;
        uint32_t bar = 0;
        if (!readConfig(kPciBar0Offset, bar))
        {
            return failStart(PciSessionResult::ConfigReadFailed);
        }
        // Only assigned, non-prefetchable 32-bit or 64-bit memory BARs.
        const uint32_t kind = (bar >> kPciMemoryBarTypeShift) & 3U;
        if (!validPciBarType(bar, kind))
        {
            return failStart(PciSessionResult::InvalidBar);
        }
        uint32_t upper = 0;
        if (kind == 2 && !readConfig(kPciBar0HighOffset, upper))
        {
            return failStart(PciSessionResult::ConfigReadFailed);
        }
        if (((bar & kPciBarAddressMask) == 0U) && (upper == 0U))
        {
            return failStart(PciSessionResult::InvalidBar);
        }

        if ((command & kMemoryDecode) == 0U)
        {
            // A failed write can still reach the device. Record the obligation
            // before attempting it, then unwind conservatively on any error.
            status_.memoryDecodeChanged = true;
            if (!backend_.inD0(backend_.context) ||
                !backend_.commandWrite16(
                    backend_.context,
                    static_cast<uint16_t>(command | kMemoryDecode)))
            {
                return failStart(PciSessionResult::CommandWriteFailed);
            }
        }
        if (!readConfig(kPciCommandOffset, command) ||
            ((command & kMemoryDecode) == 0U) ||
            ((command & kBusMaster) != 0U) ||
            commandBitsChanged(command, status_.originalCommand))
        {
            return failStart(PciSessionResult::CommandReadbackFailed);
        }
        // A configuration-read callback may revoke D0 after returning
        // success. BAR mapping must not run against a revoked provider.
        if (!backend_.inD0(backend_.context))
        {
            return failStart(PciSessionResult::NotInD0);
        }
        if (!backend_.mapBar0(backend_.context, &status_.barLengthBytes))
        {
            return failStart(PciSessionResult::MappingFailed);
        }
        status_.mapped = true;
        // A successful map can also coincide with provider revocation.
        // Do not publish a read-ready session after losing ownership.
        if (!backend_.inD0(backend_.context))
        {
            return failStart(PciSessionResult::NotInD0);
        }
        if (status_.barLengthBytes < kMinimumInspectionBar)
        {
            return failStart(PciSessionResult::InvalidBar);
        }
        // Mapping may complete after an unrelated PCI command change. The
        // pre-map readback alone cannot authorize read-ready publication.
        const bool commandReadOk = readConfig(kPciCommandOffset, command);
        if (!backend_.inD0(backend_.context))
        {
            return failStart(PciSessionResult::NotInD0);
        }
        if (!commandReadOk || ((command & kMemoryDecode) == 0U) ||
            ((command & kBusMaster) != 0U) ||
            commandBitsChanged(command, status_.originalCommand))
        {
            return failStart(PciSessionResult::CommandReadbackFailed);
        }

        if (device_.matchPci(static_cast<uint16_t>(id),
                             static_cast<uint16_t>(id >> kPciWordHighShift),
                             static_cast<uint16_t>(subsystem),
                             static_cast<uint16_t>(
                                 subsystem >> kPciWordHighShift)) != Result::Ok)
        {
            return failStart(PciSessionResult::CoreRejected);
        }
        status_.readAccessReady = true;
        const RegisterBus bus {
            this,
            readRegister,
            nullptr,
            status_.barLengthBytes,
        };
        if (device_.attachReadOnlyBus(bus) != Result::Ok)
        {
            return failStart(PciSessionResult::CoreRejected);
        }
        // Core setup does not touch PCI, but D0 can vanish after the last
        // post-map preflight. Never publish a ready session from stale power
        // authorization after this software-only work.
        if (!backend_.inD0(backend_.context))
        {
            return failStart(PciSessionResult::NotInD0);
        }
        return status_.lastResult = PciSessionResult::Ok;
    }

    bool PciReadOnlySession::readRegister(void *context, uint32_t offset,
                                          uint32_t *value)
    {
        const auto &self = *static_cast<PciReadOnlySession *>(context);
        if ((value == nullptr) || !self.status_.readAccessReady ||
            !self.status_.mapped || !self.status_.claimed ||
            !self.backend_.inD0(self.backend_.context) ||
            (offset != kRevisionRegister && offset != kRtcStatusRegister &&
             offset != kEepromStatusRegister) ||
            offset > self.status_.barLengthBytes ||
            self.status_.barLengthBytes - offset < sizeof(uint32_t))
        {
            return false;
        }
        // An MMIO callback can complete just as the provider loses D0.
        // Recheck powered ownership before reporting a valid register sample,
        // especially the final EEPROM word used to authorize inspection.
        return self.backend_.readBar0(self.backend_.context, offset, value) &&
               *value != kInvalidConfigRead &&
               self.backend_.inD0(self.backend_.context);
    }

    PciSessionResult PciReadOnlySession::inspect()
    {
        if (!status_.readAccessReady)
        {
            return status_.lastResult = PciSessionResult::WrongState;
        }
        const Result coreResult = device_.inspect();
        status_.coreInspectResult = coreResult;
        if (coreResult != Result::Ok)
        {
            // Never leave a failed inspection holding a BAR or newly enabled
            // memory decode until an unspecified future stop callback. Save
            // the precise core reason before detach clears its live status.
            unwind(ProviderAccess::Available);
            return status_.lastResult = PciSessionResult::CoreRejected;
        }
        // Neither the last register sample nor its D0 check can certify
        // command bits after inspection has finished. Refuse newly enabled
        // bus mastering or unrelated changes before publishing success.
        uint32_t command = 0;
        const bool commandReadOk = readConfig(kPciCommandOffset, command);
        if (!backend_.inD0(backend_.context))
        {
            unwind(ProviderAccess::Unavailable);
            return status_.lastResult = PciSessionResult::NotInD0;
        }
        if (!commandReadOk || ((command & kMemoryDecode) == 0U) ||
            ((command & kBusMaster) != 0U) ||
            commandBitsChanged(command, status_.originalCommand))
        {
            unwind(ProviderAccess::Available);
            return status_.lastResult = PciSessionResult::CommandReadbackFailed;
        }
        return status_.lastResult = PciSessionResult::Ok;
    }

    PciSessionResult PciReadOnlySession::failStart(PciSessionResult result)
    {
        unwind(ProviderAccess::Available);
        return status_.lastResult = result;
    }

    void PciReadOnlySession::unwind(ProviderAccess access)
    {
        status_.readAccessReady = false;
        device_.detach();
        if (status_.mapped)
        {
            backend_.unmapBar0(backend_.context);
            status_.mapped = false;
        }
        if (status_.claimed && status_.memoryDecodeChanged)
        {
            status_.cleanupResult = PciSessionResult::ProviderUnavailable;
            if (access == ProviderAccess::Available &&
                backend_.inD0(backend_.context))
            {
                uint32_t command = 0;
                // Refuse rollback on unexpected changes to PCI command.
                // If failed enable never reached the device, decode is already
                // off and no further configuration write is necessary.
                // A successful config read can revoke D0 in its own
                // callback. Neither the saved command nor a previous D0
                // check authorizes a subsequent PCI command write.
                if (readConfig(kPciCommandOffset, command) &&
                    backend_.inD0(backend_.context) &&
                    ((command & kBusMaster) == 0U) &&
                    !commandBitsChanged(command, status_.originalCommand) &&
                    (((command & kMemoryDecode) == 0U) ||
                     (backend_.commandWrite16(
                          backend_.context,
                          static_cast<uint16_t>(command &
                                                kPciOtherCommandBits)) &&
                      readConfig(kPciCommandOffset, command) &&
                      backend_.inD0(backend_.context) &&
                      ((command & (static_cast<uint32_t>(kMemoryDecode) |
                                   static_cast<uint32_t>(kBusMaster))) == 0U) &&
                      !commandBitsChanged(command, status_.originalCommand))))
                {
                    status_.memoryDecodeChanged = false;
                    status_.cleanupResult = PciSessionResult::Ok;
                }
                else if (backend_.inD0(backend_.context))
                {
                    status_.cleanupResult =
                        PciSessionResult::DecodeRestoreFailed;
                }
            }
        }
        if (status_.claimed)
        {
            backend_.release(backend_.context);
            status_.claimed = false;
        }
        backend_ = {};
    }

    void PciReadOnlySession::stop(ProviderAccess access)
    {
        unwind(access);
    }

} // namespace simpleath
