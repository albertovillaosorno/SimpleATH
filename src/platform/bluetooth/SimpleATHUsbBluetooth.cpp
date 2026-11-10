#include "SimpleATHUsbBluetooth.hpp"
#include "NativeAth3kIo.hpp"
#include "bluetooth/Ath3kUsb.hpp"
#include <IOKit/IOLib.h>
#include <IOKit/IOService.h>
#include <IOKit/IOTypes.h>
#include <IOKit/usb/AppleUSBDefinitions.h>
#include <IOKit/usb/IOUSBHostDevice.h>
#include <IOKit/usb/StandardUSB.h>
#include <kern/thread_call.h>
#include <libkern/OSTypes.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSMetaClass.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Equivalent to OSDefineMetaClassWithInit + OSDefineDefaultStructors,
// except the SDK's MetaClass constructor is explicitly nonthrowing.
SimpleATHUsbBluetooth::MetaClass SimpleATHUsbBluetooth::gMetaClass;
const OSMetaClass *const SimpleATHUsbBluetooth::metaClass =
    &SimpleATHUsbBluetooth::gMetaClass;
constexpr const OSMetaClass *SimpleATHUsbBluetooth::superClass;

SimpleATHUsbBluetooth::SimpleATHUsbBluetooth(const OSMetaClass *meta)
    : IOService(meta)
{
}

SimpleATHUsbBluetooth::~SimpleATHUsbBluetooth() = default;

const OSMetaClass *SimpleATHUsbBluetooth::getMetaClass() const
{
    return &gMetaClass;
}

SimpleATHUsbBluetooth::MetaClass::MetaClass() noexcept
    : OSMetaClass("SimpleATHUsbBluetooth", SimpleATHUsbBluetooth::superClass,
                  sizeof(SimpleATHUsbBluetooth))
{
}

OSDefineDefaultStructors(SimpleATHUsbBluetooth, IOService)

    namespace
{
    constexpr size_t kMaxFirmwareName = 48;
    constexpr size_t kMaxFirmwareBytes = size_t {1024U} * 1024U;
    constexpr unsigned int kRegistryPropertyBits = 32U;

    // The device lease belongs to this independent thread call. The USB
    // service itself can terminate without leaving a callback to freed
    // service state or running reset from the USB port workloop.
    struct ResetRequest
    {
            IOUSBHostDevice *device;
            IOService *owner;
            simpleath::Ath3kUsbIdentity identity;
            thread_call_t call;
    };

    const auto resetAfterBootstrap =
        [](thread_call_param_t requestContext, void *const unusedContext)
    {
        static_cast<void>(unusedContext);
        auto *request = static_cast<ResetRequest *>(requestContext);
        IOUSBHostDevice *const device = request->device;
        const auto *descriptor =
            device->isInactive() ? nullptr : device->getDeviceDescriptor();
        // If the controller already switched product/revision, a reset of
        // the old retained provider would disrupt a new Bluetooth host.
        if (descriptor != nullptr &&
            USBToHost16(descriptor->idVendor) == request->identity.vendorId &&
            USBToHost16(descriptor->idProduct) == request->identity.productId &&
            USBToHost16(descriptor->bcdDevice) ==
                request->identity.deviceRevision)
        {
            (void)device->reset();
        }
        device->release();
        (void)thread_call_free(request->call);
        const IOService *const owner = request->owner;
        IOFree(request, sizeof(ResetRequest));
        // The service reference also pins the kext's asynchronous code
        // until the device handoff has finished.
        owner->release();
    };

    bool requestReenumeration(IOUSBHostDevice * device, IOService * owner,
                              const simpleath::Ath3kUsbIdentity &identity)
    {
        if (device == nullptr)
        {
            return false;
        }
        auto *request =
            static_cast<ResetRequest *>(IOMalloc(sizeof(ResetRequest)));
        if (request == nullptr)
        {
            device->release();
            return false;
        }
        request->device = device;
        request->owner = owner;
        request->identity = identity;
        owner->retain();
        request->call = thread_call_allocate_with_priority(
            resetAfterBootstrap, request, THREAD_CALL_PRIORITY_KERNEL);
        if (request->call == nullptr)
        {
            owner->release();
            device->release();
            IOFree(request, sizeof(ResetRequest));
            return false;
        }
        (void)thread_call_enter(request->call);
        return true;
    }

    bool physicalIdentity(IOUSBHostInterface * interface,
                          simpleath::Ath3kUsbIdentity & out)
    {
        out = {};
        if (interface == nullptr || interface->isInactive())
        {
            return false;
        }
        const auto *descriptor = interface->getInterfaceDescriptor();
        auto *device = interface->getDevice();
        const auto *deviceDescriptor =
            device == nullptr ? nullptr : device->getDeviceDescriptor();
        if (descriptor == nullptr || deviceDescriptor == nullptr)
        {
            return false;
        }
        out = {
            USBToHost16(deviceDescriptor->idVendor),
            USBToHost16(deviceDescriptor->idProduct),
            USBToHost16(deviceDescriptor->bcdDevice),
            descriptor->bInterfaceNumber,
        };
        return simpleath::isSupportedAth3kUsbIdentity(out);
    }
}

IOService *SimpleATHUsbBluetooth::probe(IOService *provider, SInt32 *score)
{
    auto *usb = OSDynamicCast(IOUSBHostInterface, provider);
    simpleath::Ath3kUsbIdentity identity {};
    if (!physicalIdentity(usb, identity) || identity.deviceRevision > 1U ||
        OSDynamicCast(OSDictionary, getProperty("SimpleATHAth3kFirmware")) ==
            nullptr)
    {
        return nullptr;
    }
    return IOService::probe(provider, score);
}

bool SimpleATHUsbBluetooth::permitted(void *context, uint64_t epoch)
{
    const auto &self = *static_cast<SimpleATHUsbBluetooth *>(context);
    return epoch != 0 && epoch == self.epoch_ && !self.stopping_ &&
           self.interface_ != nullptr && !self.interface_->isInactive();
}

bool SimpleATHUsbBluetooth::firmware(void *context, const char *name,
                                     simpleath::Ath3kFirmwareImage *image)
{
    if (image == nullptr)
    {
        return false;
    }
    *image = {};
    const auto &self = *static_cast<SimpleATHUsbBluetooth *>(context);
    if (!permitted(context, self.epoch_) || self.images_ == nullptr ||
        name == nullptr)
    {
        return false;
    }
    // The exact ROM/clock filename comes from the device's USB version
    // response, not a guessed Dell USB ID. Restrict all key lookups to a
    // bounded, terminated path before touching a supplied firmware object.
    const size_t length = strnlen(name, kMaxFirmwareName);
    if (length == 0 || length == kMaxFirmwareName)
    {
        return false;
    }
    const auto *data = OSDynamicCast(OSData, self.images_->getObject(name));
    if (data == nullptr || data->getLength() == 0 ||
        data->getLength() > kMaxFirmwareBytes ||
        data->getBytesNoCopy() == nullptr)
    {
        return false;
    }
    image->data = static_cast<const uint8_t *>(data->getBytesNoCopy());
    image->size = data->getLength();
    return permitted(context, self.epoch_);
}

bool SimpleATHUsbBluetooth::start(IOService *provider)
{
    if (!IOService::start(provider))
    {
        return false;
    }
    interface_ = OSDynamicCast(IOUSBHostInterface, provider);
    simpleath::Ath3kUsbIdentity identity {};
    if (!physicalIdentity(interface_, identity))
    {
        revoke();
        return false;
    }
    // An already switched HCI interface must be owned by a real Bluetooth
    // host controller, not held hostage by a firmware-loader personality.
    if (identity.deviceRevision > 1U)
    {
        revoke();
        return false;
    }
    auto *providedImages =
        OSDynamicCast(OSDictionary, getProperty("SimpleATHAth3kFirmware"));
    if (providedImages != nullptr)
    {
        providedImages->retain();
        images_ = providedImages;
    }
    if (images_ == nullptr)
    {
        setProperty("SimpleATHBluetoothBootstrapResult",
                    static_cast<uint32_t>(
                        simpleath::Ath3kBootResult::FirmwareUnavailable),
                    kRegistryPropertyBits);
        revoke();
        return false;
    }
    ++epoch_;
    if (epoch_ == 0 ||
        !simpleath::openNativeAth3kIo(usb_, this, interface_, this, epoch_,
                                      permitted, firmware))
    {
        setProperty(
            "SimpleATHBluetoothBootstrapError",
            static_cast<uint32_t>(simpleath::Ath3kBootResult::InvalidBackend),
            kRegistryPropertyBits);
        revoke();
        return false;
    }
    const simpleath::Ath3kBootProgress status =
        simpleath::bootstrapNativeAth3kIo(usb_);
    setProperty("SimpleATHBluetoothBootstrapPhase",
                static_cast<uint32_t>(status.phase), kRegistryPropertyBits);
    setProperty("SimpleATHBluetoothBootstrapResult",
                static_cast<uint32_t>(status.result), kRegistryPropertyBits);
    setProperty("SimpleATHBluetoothUsbResetRequired", status.requiresUsbReset);
    // The switch-identity control transfer alone does not prove a new
    // IOUSBHostDevice instance exists. Release the interface before asking
    // the USB host to reset/re-enumerate. On a failed partial upload this
    // also prevents another client inheriting ambiguous controller state.
    const bool mayReset =
        simpleath::shouldReenumerateAth3k(status, permitted(this, epoch_));
    IOUSBHostDevice *device =
        mayReset && interface_ != nullptr ? interface_->getDevice() : nullptr;
    if (device != nullptr)
    {
        device->retain();
    }
    simpleath::closeNativeAth3kIo(usb_);
    if (status.result != simpleath::Ath3kBootResult::AwaitReenumeration)
    {
        revoke();
        (void)requestReenumeration(device, this, identity);
        return false;
    }
    setProperty("SimpleATHBluetoothAwaitReenumeration", true);
    registerService();
    // The kernel scheduler (rather than this USB port callback) now owns
    // the retained device. Reset failure is never reported as HCI ready.
    (void)requestReenumeration(device, this, identity);
    return true;
}

void SimpleATHUsbBluetooth::revoke()
{
    stopping_ = true;
    ++epoch_;
    simpleath::closeNativeAth3kIo(usb_);
    if (images_ != nullptr)
    {
        images_->release();
        images_ = nullptr;
    }
    interface_ = nullptr;
    setProperty("SimpleATHBluetoothAwaitReenumeration", false);
}

bool SimpleATHUsbBluetooth::willTerminate(IOService *provider,
                                          IOOptionBits options)
{
    // Close before provider revocation; IOUSBHostInterface may block USB
    // re-enumeration until every client's open session has closed.
    revoke();
    return IOService::willTerminate(provider, options);
}

void SimpleATHUsbBluetooth::stop(IOService *provider)
{
    revoke();
    IOService::stop(provider);
}

void SimpleATHUsbBluetooth::free()
{
    revoke();
    IOService::free();
}
