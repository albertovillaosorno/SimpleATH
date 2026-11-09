// SPDX-License-Identifier: AGPL-3.0-only
#include "Ar9565PciSession.hpp"

namespace simpleath
{
    namespace
    {
        constexpr uint16_t kMemoryDecode = 0x0002;
        constexpr uint16_t kBusMaster = 0x0004;
        constexpr uint32_t kMinimumInspectionBar = kRtcStatusRegister + 4;

        bool overlaps(const void *a, size_t aBytes, const void *b,
                      size_t bBytes)
        {
            if (!a || !b || !aBytes || !bBytes)
                return false;
            const auto first = reinterpret_cast<uintptr_t>(a);
            const auto second = reinterpret_cast<uintptr_t>(b);
            return first <= second ? second - first < aBytes
                                   : first - second < bBytes;
        }

        // If anything except memory decode changes, ownership is no longer
        // proven. Never restore a stale PCI command word over those changes.
        bool commandBitsChanged(uint32_t observed, uint16_t original)
        {
            return ((static_cast<uint16_t>(observed) ^ original) &
                    static_cast<uint16_t>(~kMemoryDecode)) != 0;
        }
    } // namespace

    PciReadOnlySession::PciReadOnlySession()
        : device_ {}, backend_ {}, status_ {}
    {
    }

    PciReadOnlySession::~PciReadOnlySession()
    {
        // Normal teardown must happen explicitly before the owner destroys the
        // backend context. Never assume powered/config-accessible in a
        // destructor.
        stop(ProviderAccess::Unavailable);
    }

    bool PciReadOnlySession::readConfig(uint16_t offset, uint32_t &value)
    {
        return status_.claimed && backend_.inD0(backend_.context) &&
               (offset & 3u) == 0 && offset <= 0xfcu &&
               backend_.configRead32(backend_.context, offset, &value) &&
               value != 0xffffffffu;
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
            return PciSessionResult::MissingBackend;
        if (status_.claimed || status_.mapped || status_.memoryDecodeChanged)
            return status_.lastResult = PciSessionResult::WrongState;
        device_.detach();
        status_ = {};
        if (!backend.context || !backend.claim || !backend.release ||
            !backend.inD0 || !backend.configRead32 || !backend.commandWrite16 ||
            !backend.mapBar0 || !backend.unmapBar0 || !backend.readBar0)
            return status_.lastResult = PciSessionResult::MissingBackend;
        backend_ = backend;
        if (!backend_.claim(backend_.context))
        {
            backend_ = {};
            return status_.lastResult = PciSessionResult::OwnershipDenied;
        }
        status_.claimed = true;
        if (!backend_.inD0(backend_.context))
            return failStart(PciSessionResult::NotInD0);

        uint32_t id = 0, subsystem = 0, classRevision = 0, header = 0,
                 command = 0;
        if (!readConfig(0x00, id) || !readConfig(0x2c, subsystem) ||
            !readConfig(0x08, classRevision) || !readConfig(0x0c, header) ||
            !readConfig(0x04, command))
            return failStart(PciSessionResult::ConfigReadFailed);
        // AR9565 is a type-0 PCI wireless network function (class 0x0280).
        if (!isSupportedPci(static_cast<uint16_t>(id),
                            static_cast<uint16_t>(id >> 16)) ||
            ((header >> 16) & 0x7fu) != 0 || (classRevision >> 16) != 0x0280u)
            return failStart(PciSessionResult::UnsupportedFunction);
        status_.originalCommand = static_cast<uint16_t>(command);
        if (command & kBusMaster)
            return failStart(PciSessionResult::InheritedBusMaster);

        uint32_t bar = 0;
        if (!readConfig(0x10, bar))
            return failStart(PciSessionResult::ConfigReadFailed);
        // Only assigned, non-prefetchable 32-bit or 64-bit memory BARs.
        const uint32_t kind = (bar >> 1) & 3u;
        if ((bar & 0x09u) || (kind != 0 && kind != 2))
            return failStart(PciSessionResult::InvalidBar);
        uint32_t upper = 0;
        if (kind == 2 && !readConfig(0x14, upper))
            return failStart(PciSessionResult::ConfigReadFailed);
        if (!(bar & 0xfffffff0u) && !upper)
            return failStart(PciSessionResult::InvalidBar);

        if (!(command & kMemoryDecode))
        {
            // A failed write can still reach the device. Record the obligation
            // before attempting it, then unwind conservatively on any error.
            status_.memoryDecodeChanged = true;
            if (!backend_.inD0(backend_.context) ||
                !backend_.commandWrite16(
                    backend_.context,
                    static_cast<uint16_t>(command | kMemoryDecode)))
                return failStart(PciSessionResult::CommandWriteFailed);
        }
        if (!readConfig(0x04, command) || !(command & kMemoryDecode) ||
            (command & kBusMaster) ||
            commandBitsChanged(command, status_.originalCommand))
            return failStart(PciSessionResult::CommandReadbackFailed);
        // A configuration-read callback may revoke D0 after returning
        // success. BAR mapping must not run against a revoked provider.
        if (!backend_.inD0(backend_.context))
            return failStart(PciSessionResult::NotInD0);
        if (!backend_.mapBar0(backend_.context, &status_.barLengthBytes))
            return failStart(PciSessionResult::MappingFailed);
        status_.mapped = true;
        // A successful map can also coincide with provider revocation.
        // Do not publish a read-ready session after losing ownership.
        if (!backend_.inD0(backend_.context))
            return failStart(PciSessionResult::NotInD0);
        if (status_.barLengthBytes < kMinimumInspectionBar)
            return failStart(PciSessionResult::InvalidBar);
        // Mapping may complete after an unrelated PCI command change. The
        // pre-map readback alone cannot authorize read-ready publication.
        const bool commandReadOk = readConfig(0x04, command);
        if (!backend_.inD0(backend_.context))
            return failStart(PciSessionResult::NotInD0);
        if (!commandReadOk || !(command & kMemoryDecode) ||
            (command & kBusMaster) ||
            commandBitsChanged(command, status_.originalCommand))
            return failStart(PciSessionResult::CommandReadbackFailed);

        if (device_.matchPci(
                static_cast<uint16_t>(id), static_cast<uint16_t>(id >> 16),
                static_cast<uint16_t>(subsystem),
                static_cast<uint16_t>(subsystem >> 16)) != Result::Ok)
            return failStart(PciSessionResult::CoreRejected);
        status_.readAccessReady = true;
        const RegisterBus bus {this, readRegister, nullptr,
                               status_.barLengthBytes};
        if (device_.attachReadOnlyBus(bus) != Result::Ok)
            return failStart(PciSessionResult::CoreRejected);
        // Core setup does not touch PCI, but D0 can vanish after the last
        // post-map preflight. Never publish a ready session from stale power
        // authorization after this software-only work.
        if (!backend_.inD0(backend_.context))
            return failStart(PciSessionResult::NotInD0);
        return status_.lastResult = PciSessionResult::Ok;
    }

    bool PciReadOnlySession::readRegister(void *context, uint32_t offset,
                                          uint32_t *value)
    {
        auto &self = *static_cast<PciReadOnlySession *>(context);
        if (!value || !self.status_.readAccessReady || !self.status_.mapped ||
            !self.status_.claimed ||
            !self.backend_.inD0(self.backend_.context) ||
            (offset != kRevisionRegister && offset != kRtcStatusRegister &&
             offset != kEepromStatusRegister) ||
            offset > self.status_.barLengthBytes ||
            self.status_.barLengthBytes - offset < sizeof(uint32_t))
            return false;
        // An MMIO callback can complete just as the provider loses D0.
        // Recheck powered ownership before reporting a valid register sample,
        // especially the final EEPROM word used to authorize inspection.
        return self.backend_.readBar0(self.backend_.context, offset, value) &&
               *value != 0xffffffffu &&
               self.backend_.inD0(self.backend_.context);
    }

    PciSessionResult PciReadOnlySession::inspect()
    {
        if (!status_.readAccessReady)
            return status_.lastResult = PciSessionResult::WrongState;
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
        const bool commandReadOk = readConfig(0x04, command);
        if (!backend_.inD0(backend_.context))
        {
            unwind(ProviderAccess::Unavailable);
            return status_.lastResult = PciSessionResult::NotInD0;
        }
        if (!commandReadOk || !(command & kMemoryDecode) ||
            (command & kBusMaster) ||
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
                if (readConfig(0x04, command) &&
                    backend_.inD0(backend_.context) &&
                    !(command & kBusMaster) &&
                    !commandBitsChanged(command, status_.originalCommand) &&
                    (!(command & kMemoryDecode) ||
                     (backend_.commandWrite16(
                          backend_.context,
                          static_cast<uint16_t>(command & ~kMemoryDecode)) &&
                      readConfig(0x04, command) &&
                      backend_.inD0(backend_.context) &&
                      !(command & (kMemoryDecode | kBusMaster)) &&
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
