// SPDX-License-Identifier: AGPL-3.0-only
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

        private:
            static bool claim(void *);
            static void release(void *);
            static bool inD0(void *);
            static bool configRead32(void *, uint16_t, uint32_t *);
            static bool commandWrite16(void *, uint16_t);
            static bool mapBar0(void *, uint32_t *);
            static void unmapBar0(void *);
            static bool readBar0(void *, uint32_t, uint32_t *);
            static bool readActive(void *, uint32_t, uint32_t *);
            static bool writeActive(void *, uint32_t, uint32_t);
            IOService *owner_;
            IOPCIDevice *pci_;
            IOMemoryMap *bar_;
            NativePciPowerGate power_;
            uint32_t length_;
            uint8_t powerCapability_;
            bool configured_;
            bool claimed_;
    };
} // namespace simpleath
#endif
