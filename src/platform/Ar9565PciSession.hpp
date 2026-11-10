// SPDX-License-Identifier: AGPL-3.0-only
#ifndef SIMPLEATH_AR9565_PCI_SESSION_HPP
#define SIMPLEATH_AR9565_PCI_SESSION_HPP

#include "../hardware/Ar9565Core.hpp"

namespace simpleath
{

    enum class PciSessionResult : uint8_t
    {
        Ok,
        WrongState,
        MissingBackend,
        OwnershipDenied,
        NotInD0,
        ConfigReadFailed,
        UnsupportedFunction,
        InheritedBusMaster,
        InvalidBar,
        CommandWriteFailed,
        CommandReadbackFailed,
        MappingFailed,
        CoreRejected,
        ProviderUnavailable,
        DecodeRestoreFailed,
    };

    enum class ProviderAccess : uint8_t
    {
        Available,
        Unavailable,
    };

    // Callback contract supplied by NativePciBackend to the native owner.
    // All calls, including power/termination, MUST run under one serialization
    // gate. Context outlives the session. No callback may reenter the session.
    struct PciSessionBackend
    {
            void *context;
            // Retain the PCI provider and exclusively open it for the
            // controlling service. Failure must leave no ownership or retained
            // resources behind.
            bool (*claim)(void *context);
            // Release the successful claim/retain, tolerating provider
            // disappearance. Must not issue driver MMIO/config accesses.
            void (*release)(void *context);
            // Consult the provider power contract, not AR_RTC_STATUS or a
            // property.
            bool (*inD0)(void *context);
            // Read live config, never OpenCore-injected registry properties.
            bool (*configRead32)(void *context, uint16_t offset,
                                 uint32_t *value);
            // Write ONLY the 16-bit PCI command word at 0x04, never PCI status.
            // Re-read live command and refuse any changes except memory decode.
            bool (*commandWrite16)(void *context, uint16_t value);
            // Map the assigned BAR0 range by config register 0x10, cache
            // inhibited. On failure leave no map; on success own it until
            // unmapBar0. The length must come from the PCI provider, never from
            // write-all-ones sizing.
            bool (*mapBar0)(void *context, uint32_t *lengthBytes);
            void (*unmapBar0)(void *context);
            // Ordered little-endian 32-bit access; validate mapping bounds
            // again.
            bool (*readBar0)(void *context, uint32_t offset, uint32_t *value);
    };

    struct PciSessionStatus
    {
            PciSessionResult lastResult;
            PciSessionResult cleanupResult;
            // Preserved when inspection failure revokes callbacks and detaches
            // the hardware core before restoring PCI memory decode.
            Result coreInspectResult;
            uint16_t originalCommand;
            uint32_t barLengthBytes;
            bool claimed;
            bool mapped;
            bool readAccessReady;
            // Recorded before an uncertain enable write; unresolved rollback
            // blocks subsequent session start, including after provider loss.
            bool memoryDecodeChanged;
    };

    // Read-only silicon inspection session. Owns its core so callbacks cannot
    // escape into a detached/reused Device. There are no TX/DMA/interrupt APIs.
    // stop(Available) is required while in D0 on sleep/normal stop. If the
    // device disappeared, use Unavailable: callbacks are revoked before
    // map/claim release and no configuration restoration is attempted. Resume
    // starts a fresh session.
    class PciReadOnlySession final
    {
        public:
            PciReadOnlySession();
            ~PciReadOnlySession();
            PciReadOnlySession(const PciReadOnlySession &) = delete;
            PciReadOnlySession &operator=(const PciReadOnlySession &) = delete;
            PciReadOnlySession(PciReadOnlySession &&) = delete;
            PciReadOnlySession &operator=(PciReadOnlySession &&) = delete;
            PciSessionResult start(const PciSessionBackend &backend);
            // On core inspection failure, immediately revoke callbacks,
            // unmap, and conservatively restore memory decode if possible.
            // status().coreInspectResult retains the core diagnostic.
            PciSessionResult inspect();
            void stop(ProviderAccess access);

            const PciSessionStatus &status() const
            {
                return status_;
            }

            const Status &hardwareStatus() const
            {
                return device_.status();
            }

        private:
            static bool readRegister(void *context, uint32_t offset,
                                     uint32_t *value);
            bool readConfig(uint16_t offset, uint32_t &value);
            PciSessionResult failStart(PciSessionResult result);
            void unwind(ProviderAccess access);
            Device device_;
            PciSessionBackend backend_;
            PciSessionStatus status_;
    };

} // namespace simpleath
#endif
