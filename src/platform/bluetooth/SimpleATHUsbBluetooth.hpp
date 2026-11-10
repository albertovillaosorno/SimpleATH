// Independent USB function owner for the QCA9565-family AR3012 bootstrap.
#ifndef SIMPLEATH_USB_BLUETOOTH_SERVICE_HPP
#define SIMPLEATH_USB_BLUETOOTH_SERVICE_HPP

#include "NativeAth3kIo.hpp"
#include <IOKit/IOService.h>
#include <IOKit/usb/IOUSBHostInterface.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSMetaClass.h>
#include <stdint.h>

// The WLAN PCI owner never owns this IOUSBHostInterface. Firmware loading
// requires exact, licensed AR3012 resources supplied by the kext personality;
// no generic or built-in firmware fallback is permitted.
class SimpleATHUsbBluetooth final : public IOService
{
        // Mirror the MacKernelSDK OSDeclareDefaultStructors expansion with an
        // explicit metaclass constructor. This retains the exact IOKit RTTI ABI
        // while preventing unintended pointer-to-service conversion.
    private:
        static constexpr const OSMetaClass *superClass = &IOService::gMetaClass;

    public:
        static const OSMetaClass *const metaClass;

        static class MetaClass : public OSMetaClass
        {
            public:
                MetaClass() noexcept;
                OSObject *alloc() const APPLE_KEXT_OVERRIDE;
        } gMetaClass;
        friend class SimpleATHUsbBluetooth::MetaClass;
        const OSMetaClass *getMetaClass() const APPLE_KEXT_OVERRIDE;

    protected:
        explicit SimpleATHUsbBluetooth(const OSMetaClass *meta);
        ~SimpleATHUsbBluetooth() APPLE_KEXT_OVERRIDE;

    public:
        SimpleATHUsbBluetooth();

        SimpleATHUsbBluetooth(const SimpleATHUsbBluetooth &) = delete;
        SimpleATHUsbBluetooth &
        operator=(const SimpleATHUsbBluetooth &) = delete;
        SimpleATHUsbBluetooth(SimpleATHUsbBluetooth &&) = delete;
        SimpleATHUsbBluetooth &operator=(SimpleATHUsbBluetooth &&) = delete;
        IOService *probe(IOService *provider, SInt32 *score) override;
        bool start(IOService *provider) override;
        bool willTerminate(IOService *provider, IOOptionBits options) override;
        void stop(IOService *provider) override;
        void free() override;

    private:
        static bool permitted(void *context, uint64_t epoch);
        static bool resetAllowed(void *context);
        void cancelDeferredReset();
        static bool firmware(void *context, const char *name,
                             simpleath::Ath3kFirmwareImage *image);
        void revoke();

        simpleath::NativeAth3kIo usb_ {};
        OSDictionary *images_ {nullptr};
        IOUSBHostInterface *interface_ {nullptr};
        uint64_t epoch_ {0};
        bool stopping_ {false};
        // Atomically claim a queued reset vs. external shutdown. Internal
        // start-failure cleanup deliberately does not cancel recovery.
        uint8_t resetState_ {0U};
};

#endif
