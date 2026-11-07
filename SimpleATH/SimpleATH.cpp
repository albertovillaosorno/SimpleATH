//
// SimpleATH – first-stage kernel service for Qualcomm Atheros AR9565.
// Based on the architecture of SimpleBCM by laobamac; NOTICE.md retained.
// Original Broadcom bridge code is retained in the repository but not linked.
//
#include <IOKit/IOService.h>
#include <IOKit/IOLib.h>
#include <libkern/c++/OSMetaClass.h>
#include <pexpert/pexpert.h>
#include <mach/kmod.h>

static bool simpleATHEnabled = true;

// An IOResources service, with no Broadcom firmware or Skywalk calls.
class SimpleATH final : public IOService {
    OSDeclareDefaultStructors(SimpleATH)
public:
    IOService *probe(IOService *provider, SInt32 *score) override {
        if (!simpleATHEnabled) return nullptr;
        return IOService::probe(provider, score);
    }

    bool start(IOService *provider) override {
        if (!simpleATHEnabled) return false;
        if (!IOService::start(provider)) return false;
        setProperty("SimpleATHMode", "MinimalKernelBootstrap");
        setProperty("SimpleATHDriverReady", false);
        setProperty("SimpleATHVendorID", 0x168c, 32);
        setProperty("SimpleATHDeviceID", 0x0036, 32);
        setProperty("SimpleATHBroadcomDisabled", true);
        setProperty("SimpleATHNativeSkywalkActive", false);
        IOLog("SimpleATH: minimal kernel service registered, Wi-Fi backend inactive\n");
        registerService();
        return true;
    }

    void stop(IOService *provider) override {
        IOService::stop(provider);
    }
};

OSDefineMetaClassAndStructors(SimpleATH, IOService)

extern "C" kern_return_t SimpleATH_kern_start(kmod_info_t *, void *) {
    int disabled = 0;
    // -simpleathoff prevents driver matching as a boot recovery option.
    simpleATHEnabled = !PE_parse_boot_argn("-simpleathoff", &disabled, sizeof(disabled));
    return KERN_SUCCESS;
}

extern "C" kern_return_t SimpleATH_kern_stop(kmod_info_t *, void *) {
    return KERN_SUCCESS;
}
