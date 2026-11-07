// SPDX-License-Identifier: AGPL-3.0-only
// SimpleATH: boot-safe QCA9565 discovery on macOS Tahoe.
// This code deliberately does not enable bus mastering, allocate DMA buffers,
// request interrupts, write RF registers, or register a networking interface.
// Actual AR9565 Wi-Fi operation requires a separately validated backend.
#include "hardware/Ar9565Core.hpp"
#include <IOKit/IOLib.h>
#include <IOKit/IOService.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSMetaClass.h>
#include <mach/kmod.h>
#include <pexpert/pexpert.h>

namespace
{
    constexpr UInt16 kAtherosVendor = 0x168c;
    constexpr UInt16 kAr9565Device = 0x0036;
    bool gSimpleATHEnabled = true;

    // These values describe the matched registry node only. OpenCore can
    // replace them. They are never passed to Device::matchPci or used to
    // authorize MMIO.
    void publishRegistryId(IOService *service, IOService *provider,
                           const char *key, const char *diagnosticKey)
    {
        OSObject *property = provider->copyProperty(key);
        auto data = OSDynamicCast(OSData, property);
        if (data && data->getLength() == sizeof(uint32_t))
        {
            const auto bytes =
                static_cast<const uint8_t *>(data->getBytesNoCopy());
            // Registry properties are diagnostics, not trusted identity.
            // Even a length-valid OSData must not be dereferenced if it has
            // no accessible backing bytes.
            if (bytes)
            {
                const uint32_t value = static_cast<uint32_t>(bytes[0]) |
                                       (static_cast<uint32_t>(bytes[1]) << 8) |
                                       (static_cast<uint32_t>(bytes[2]) << 16) |
                                       (static_cast<uint32_t>(bytes[3]) << 24);
                service->setProperty(diagnosticKey, value, 32);
            }
        }
        if (property)
            property->release();
    }
} // namespace

// An IOResources service proves that this kernel extension started without
// requiring the Skywalk, IO80211, Broadcom, or obsolete AirPort ABI.
class SimpleATH final : public IOService
{
    OSDeclareDefaultStructors(SimpleATH) public
        : IOService *probe(IOService *provider, SInt32 *score) override
        {
            return gSimpleATHEnabled ? IOService::probe(provider, score)
                                     : nullptr;
        }

        bool start(IOService *provider) override
        {
            if (!gSimpleATHEnabled || !IOService::start(provider))
                return false;
            setProperty("SimpleATHMode", "PassiveQCA9565Discovery");
            setProperty("SimpleATHDriverReady", false);
            setProperty("SimpleATHVendorID", kAtherosVendor, 32);
            setProperty("SimpleATHDeviceID", kAr9565Device, 32);
            setProperty("SimpleATHSkywalkBridgeReady", false);
            registerService();
            IOLog("SimpleATH: bootstrap started without legacy wireless "
                  "dependencies\n");
            return true;
        }
};

OSDefineMetaClassAndStructors(SimpleATH, IOService)

    // IOKit matches this service to the AR9565 using IOPCIPrimaryMatch in
    // Info.plist. No direct calls to IOPCIDevice: the old artifact failed to
    // resolve its metaclass/extendedConfigRead16. Exact Tahoe PCI exports
    // remain unverified; that error does not establish that the APIs are
    // unavailable. All hardware remains untouched. The service is a diagnostic
    // marker only.
    class SimpleATHPciProbe final : public IOService
{
    OSDeclareDefaultStructors(SimpleATHPciProbe) public
        : IOService *probe(IOService *provider, SInt32 *score) override
        {
            return gSimpleATHEnabled ? IOService::probe(provider, score)
                                     : nullptr;
        }

        bool start(IOService *provider) override
        {
            if (!gSimpleATHEnabled || !IOService::start(provider))
                return false;
            setProperty("SimpleATHMode", "IOKitMatchedPCIProbe");
            setProperty("SimpleATHVendorID", kAtherosVendor, 32);
            setProperty("SimpleATHMatchedDeviceIDs",
                        "0036 / 0030 (IOPCIPrimaryMatch)");
            setProperty("SimpleATHDriverReady", false);
            // The PCI identity comes from IOKit's IOPCIPrimaryMatch. We must
            // not claim that we have accessed hardware until a real mapped PCI
            // bus transport is installed. Keep the complete Wi-Fi path
            // disabled.
            setProperty("SimpleATHRadioInitialized", false);
            // A portable C++ core is present in source, but the runtime has
            // neither authenticated PCI identity nor instantiated its hardware
            // transport. Never report a detected physical core from matching.
            setProperty("SimpleATHPortableCoreSourcePresent", true);
            setProperty("SimpleATHHardwareCorePresent", false);
            setProperty("SimpleATHMmioTransportReady", false);
            setProperty("SimpleATHEepromValidated", false);
            setProperty("SimpleATHRegulatoryReady", false);
            setProperty("SimpleATHNetworkInterfaceReady", false);
            setProperty("SimpleATHIdentitySource",
                        "IORegistryPropertiesMayBeSpoofed");
            setProperty("SimpleATHPhysicalIdentityVerified", false);
            setProperty("SimpleATHPciExclusiveOwner", false);
            setProperty("SimpleATHSrevState", "NotRead");
            setProperty("SimpleATHEepromState", "NotRead");
            setProperty("SimpleATHRegulatoryState", "TransmitProhibited");
            setProperty("SimpleATHAssociationState", "NotImplemented");
            setProperty("SimpleATHTrafficState", "NotImplemented");
            setProperty("SimpleATHNativeWirelessAbiState", "Unverified");
            publishRegistryId(this, provider, "vendor-id",
                              "SimpleATHRegistryVendorID");
            publishRegistryId(this, provider, "device-id",
                              "SimpleATHRegistryDeviceID");
            publishRegistryId(this, provider, "subsystem-vendor-id",
                              "SimpleATHRegistrySubsystemVendorID");
            publishRegistryId(this, provider, "subsystem-id",
                              "SimpleATHRegistrySubsystemDeviceID");
            registerService();
            IOLog("SimpleATH: IOKit matched the Atheros PCI device; radio "
                  "inactive\n");
            return true;
        }

        void stop(IOService *provider) override
        {
            // This passive service owns no PCI mapping, DMA or interrupt
            // source. A future controlling backend must quiesce those before
            // super::stop.
            setProperty("SimpleATHMode", "PassivePCIStopped");
            setProperty("SimpleATHDriverReady", false);
            IOService::stop(provider);
        }
};

OSDefineMetaClassAndStructors(SimpleATHPciProbe, IOService)

    extern "C" kern_return_t SimpleATH_kern_start(kmod_info_t *, void *)
{
    int ignored = 0;
    // Disable matching by adding -simpleathoff to boot-args if necessary.
    gSimpleATHEnabled =
        !PE_parse_boot_argn("-simpleathoff", &ignored, sizeof(ignored));
    return KERN_SUCCESS;
}

extern "C" kern_return_t SimpleATH_kern_stop(kmod_info_t *, void *)
{
    return KERN_SUCCESS;
}
