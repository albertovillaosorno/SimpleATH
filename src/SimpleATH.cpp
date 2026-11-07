// SPDX-License-Identifier: AGPL-3.0-only
// SimpleATH: boot-safe QCA9565 discovery on macOS Tahoe.
// This code deliberately does not enable bus mastering, allocate DMA buffers,
// request interrupts, write RF registers, or register a networking interface.
// Actual AR9565 Wi-Fi operation requires a separately validated backend.
#include <IOKit/IOLib.h>
#include <IOKit/IOService.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <libkern/c++/OSMetaClass.h>
#include <mach/kmod.h>
#include <pexpert/pexpert.h>

namespace {
constexpr UInt16 kAtherosVendor = 0x168c;
constexpr UInt16 kAr9565Device = 0x0036;
constexpr UInt16 kLegacyCompatibleDevice = 0x0030;
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

// The separate PCI service makes no changes to the hardware. It reads the
// identification registers only, and recognizes an OpenCore device-id spoof
// without interpreting the spoof as the physical silicon revision.
class SimpleATHPciProbe final : public IOService {
    OSDeclareDefaultStructors(SimpleATHPciProbe)
public:
    IOService *probe(IOService *provider, SInt32 *score) override {
        if (!gSimpleATHEnabled || OSDynamicCast(IOPCIDevice, provider) == nullptr)
            return nullptr;
        return IOService::probe(provider, score);
    }

    bool start(IOService *provider) override {
        auto *pci = OSDynamicCast(IOPCIDevice, provider);
        if (!gSimpleATHEnabled || pci == nullptr || !IOService::start(provider))
            return false;
        UInt16 vendor = pci->configRead16(0x00);
        UInt16 device = pci->configRead16(0x02);
        if (vendor != kAtherosVendor ||
            (device != kAr9565Device && device != kLegacyCompatibleDevice)) {
            IOService::stop(provider);
            return false;
        }
        setProperty("SimpleATHMode", "PassivePCIProbe");
        setProperty("SimpleATHVendorID", vendor, 32);
        setProperty("SimpleATHObservedPCIDeviceID", device, 32);
        setProperty("SimpleATHDriverReady", false);
        setProperty("SimpleATHRadioInitialized", false);
        registerService();
        IOLog("SimpleATH: AR9565 PCI detected %04x:%04x; radio inactive\n",
              static_cast<unsigned>(vendor), static_cast<unsigned>(device));
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
