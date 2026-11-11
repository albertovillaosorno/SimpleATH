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
//   - Native driver contracts and implementation for ar9565 native pci.
// - Must-Not:
//   - Invent hardware readiness, weaken buffer bounds, or assume ABI
//     compatibility.
// - Allows:
//   - Inputs: validated register, protocol, platform, or device state from
//     callers.
//   - Outputs: bounded native transitions, messages, or explicit errors.
//   - Side effects: only the device and kernel operations owned by this module.
// - Split-When:
//   - A separate protocol stage needs independent validation and ownership.
// - Merge-When:
//   - The caller directly owns this narrow contract without reuse.
// - Summary:
//   - Native driver contracts and implementation for ar9565 native pci.
// - Description:
//   - Implements or verifies the Ar9565NativePci source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for ar9565 native pci.

// Native IOPCIFamily ownership and register transport.
#ifndef SIMPLEATH_SRC_PLATFORM_AR9565NATIVEPCI_HPP
#define SIMPLEATH_SRC_PLATFORM_AR9565NATIVEPCI_HPP

#include "Ar9565PciSession.hpp"
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOService.h>
#include <IOKit/pci/IOPCIDevice.h>

namespace simpleath
{
    struct NativePciPowerGate
    {
            void *context;
            bool (*isConfirmedD0)(void *context);
    };

    // Owner serializes callbacks under an IOCommandGate; session.stop()
    // precedes service termination. D0 must come from actual PCI power
    // management state.
    class NativePciBackend final
    {
        public:
            NativePciBackend();
            ~NativePciBackend();
            NativePciBackend(const NativePciBackend &) = delete;
            NativePciBackend &operator=(const NativePciBackend &) = delete;
            NativePciBackend(NativePciBackend &&) = delete;
            NativePciBackend &operator=(NativePciBackend &&) = delete;
            // Retains both objects. Explicit clear() after session.stop()
            // breaks these references. The power context must outlive that
            // entire configured lifetime.
            bool configure(IOService *owner, IOPCIDevice *pci,
                           const NativePciPowerGate &power);
            PciSessionBackend callbacks();
            bool clear();
            // Separate active capability for the serialized reset/NVM owner.
            // Inspection callbacks retain their three-register allowlist.
            RegisterBus activeRegisters();
            // Only the serialized queue owner may enable this, after all
            // descriptors and receive buffers are mapped and published.
            bool setBusMasterGated(bool enabled);

        private:
            static bool claim(void *context);
            static void release(void *context);
            static bool inD0(void *context);
            static bool configRead32(void *context, uint16_t offset,
                                     uint32_t *value);
            static bool commandWrite16(void *context, uint16_t value);
            static bool mapBar0(void *context, uint32_t *lengthBytes);
            static void unmapBar0(void *context);
            static bool readBar0(void *context, uint32_t offset,
                                 uint32_t *value);
            static bool readActive(void *context, uint32_t offset,
                                   uint32_t *value);
            static bool writeActive(void *context, uint32_t offset,
                                    uint32_t value);
            IOService *owner_ {nullptr};
            IOPCIDevice *pci_ {nullptr};
            IOMemoryMap *bar_ {nullptr};
            NativePciPowerGate power_ {nullptr, nullptr};
            uint32_t length_ {0U};
            uint8_t powerCapability_ {0U};
            bool configured_ {false};
            bool claimed_ {false};
            bool dmaEnabled_ {false};
    };
} // namespace simpleath
#endif
