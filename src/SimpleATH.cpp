// SPDX-License-Identifier: AGPL-3.0-only
// SimpleATH: boot-safe QCA9565 discovery on macOS Tahoe.
// This code deliberately does not enable bus mastering, allocate DMA buffers,
// request interrupts, write RF registers, or register a networking interface.
// Actual AR9565 Wi-Fi operation requires a separately validated backend.
#include <IOKit/IOLib.h>
#include <IOKit/IOService.h>
#include <libkern/c++/OSMetaClass.h>
#include <mach/kmod.h>
#include <pexpert/pexpert.h>

namespace {
constexpr UInt16 kAtherosVendor = 0x168c;
constexpr UInt16 kAr9565Device = 0x0036;
bool gSimpleATHEnabled = true;
}

// An IOResources service proves that this kernel extension started without
// requiring the Skywalk, IO80211, Broadcom, or obsolete AirPort ABI.
class SimpleATH final : public IOService {
    OSDeclareDefaultStructors(SimpleATH)
public:
    IOService *probe(IOService *provider, SInt32 *score) override {
        return gSimpleATHEnabled ? IOService::probe(provider, score) : nullptr;
    }

    bool start(IOService *provider) override {
        if (!gSimpleATHEnabled || !IOService::start(provider)) return false;
        setProperty("SimpleATHMode", "PassiveQCA9565Discovery");
        setProperty("SimpleATHDriverReady", false);
        setProperty("SimpleATHVendorID", kAtherosVendor, 32);
        setProperty("SimpleATHDeviceID", kAr9565Device, 32);
        setProperty("SimpleATHSkywalkBridgeReady", false);
        registerService();
        IOLog("SimpleATH: bootstrap started without legacy wireless dependencies\n");
        return true;
    }
};
OSDefineMetaClassAndStructors(SimpleATH, IOService)

// IOKit matches this service to the AR9565 using IOPCIPrimaryMatch in
// Info.plist. No direct calls to IOPCIDevice: its class metaclass and
// extendedConfigRead16 symbol were unresolved in Tahoe's boot cache.
// All hardware remains untouched. The service is a diagnostic marker only.
class SimpleATHPciProbe final : public IOService {
    OSDeclareDefaultStructors(SimpleATHPciProbe)
public:
    IOService *probe(IOService *provider, SInt32 *score) override {
        return gSimpleATHEnabled ? IOService::probe(provider, score) : nullptr;
    }

    bool start(IOService *provider) override {
        if (!gSimpleATHEnabled || !IOService::start(provider)) return false;
        setProperty("SimpleATHMode", "IOKitMatchedPCIProbe");
        setProperty("SimpleATHVendorID", kAtherosVendor, 32);
        setProperty("SimpleATHMatchedDeviceIDs", "0036 / 0030 (IOPCIPrimaryMatch)");
        setProperty("SimpleATHDriverReady", false);
        setProperty("SimpleATHRadioInitialized", false);
        registerService();
        IOLog("SimpleATH: IOKit matched the Atheros PCI device; radio inactive\n");
        return true;
    }
};
OSDefineMetaClassAndStructors(SimpleATHPciProbe, IOService)

extern "C" kern_return_t SimpleATH_kern_start(kmod_info_t *, void *) {
    int ignored = 0;
    // Disable matching by adding -simpleathoff to boot-args if necessary.
    gSimpleATHEnabled = !PE_parse_boot_argn("-simpleathoff", &ignored,
                                            sizeof(ignored));
    return KERN_SUCCESS;
}

extern "C" kern_return_t SimpleATH_kern_stop(kmod_info_t *, void *) {
    return KERN_SUCCESS;
}
