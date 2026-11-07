//
//  SimpleATH.cpp
//  SimpleATH
//
//  Created by laobamac on 2026/11/1.
//  Copyright © 2026 laobamac. All rights reserved.
//

#include "Bridge.hpp"
#include "Loader.hpp"
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOWorkLoop.h>
#include <pexpert/pexpert.h>
#include <mach/kmod.h>

bool simpleATHDebug;
static bool enabled;
static bool initialized;
static bool payloadOptIn;

class SimpleATH final : public IOService {
    OSDeclareDefaultStructors(SimpleATH)
public:
    IOService *probe(IOService *provider, SInt32 *score) override {
        return enabled ? IOService::probe(provider, score) : nullptr;
    }
    bool start(IOService *provider) override {
        if (!IOService::start(provider))
            return false;
        if (payloadOptIn) {
            bcm::startPayloads();
        } else {
            setProperty("SimpleATHMode", "AtherosProbeOnly");
            setProperty("SimpleATHDriverReady", false);
            setProperty("SimpleATHVendorID", 0x168c, 32);
            setProperty("SimpleATHDeviceID", 0x0036, 32);
            setProperty("SimpleATHNativePayloadActive", false);
        }
        loop = IOWorkLoop::workLoop();
        timer = IOTimerEventSource::timerEventSource(this, tick);
        update();
        if (loop && timer && loop->addEventSource(timer) == kIOReturnSuccess)
            timer->setTimeoutMS(1000);
        else
            SYSLOG("loader", "periodic diagnostics unavailable");
        registerService();
        return true;
    }
    void stop(IOService *provider) override {
        if (timer) {
            timer->cancelTimeout();
            if (loop)
                loop->removeEventSource(timer);
        }
        IOService::stop(provider);
    }
    void free() override {
        if (timer)
            timer->release();
        if (loop)
            loop->release();
        IOService::free();
    }
private:
    IOWorkLoop *loop {nullptr};
    IOTimerEventSource *timer {nullptr};
    void update() {
        bcm::Bridge::publish(this);
        bcm::publishLoader(this);
    }
    static void tick(OSObject *owner, IOTimerEventSource *source) {
        static_cast<SimpleATH *>(owner)->update();
        source->setTimeoutMS(1000);
    }
};

OSDefineMetaClassAndStructors(SimpleATH, IOService)

extern "C" kern_return_t SimpleATH_kern_start(kmod_info_t *, void *) {
    int value = 0;
    enabled = !PE_parse_boot_argn("-simpleathoff", &value, sizeof(value));
#ifdef DEBUG
    simpleATHDebug = true;
#else
    simpleATHDebug = PE_parse_boot_argn("-simpleathdbg", &value, sizeof(value));
#endif
    // Probe-only by default. Original Broadcom payload is incompatible with AR9565.
    payloadOptIn = PE_parse_boot_argn("-simpleathpayload", &value, sizeof(value));
    if (enabled) {
        initialized = true;
        if (payloadOptIn) bcm::preparePayloads();
    }
    return KERN_SUCCESS;
}

extern "C" kern_return_t SimpleATH_kern_stop(kmod_info_t *, void *) {
    return initialized ? KERN_FAILURE : KERN_SUCCESS;
}
