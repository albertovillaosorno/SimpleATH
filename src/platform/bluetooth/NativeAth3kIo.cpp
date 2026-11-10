// SPDX-License-Identifier: AGPL-3.0-only
#include "NativeAth3kIo.hpp"
#include "bluetooth/Ath3kUsb.hpp"
#include "bluetooth/UsbBytes.hpp"
#include "bluetooth/UsbHci.hpp"
#include "bluetooth/UsbHciEndpointSelector.hpp"

#include <cstddef>
#include <cstdint>

#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOReturn.h>
#include <IOKit/IOService.h>
#include <IOKit/usb/AppleUSBDefinitions.h>
#include <IOKit/usb/IOUSBHostDevice.h>
#include <IOKit/usb/IOUSBHostInterface.h>
#include <IOKit/usb/IOUSBHostPipe.h>
#include <IOKit/usb/StandardUSB.h>

namespace simpleath
{
    namespace
    {
        constexpr uint8_t kVendorIn = 0xc0U;
        constexpr uint8_t kVendorOut = 0x40U;
        constexpr uint8_t kHciClassOut = 0x20U;
        constexpr uint8_t kBluetoothUsbClass = 0xe0U;
        constexpr uint8_t kHciRequest = 0U;
        constexpr uint8_t kFirmwareEndpoint = 0x02U;
        constexpr uint8_t kEndpointTypeMask = 0x03U;
        constexpr uint16_t kUsbMaxControl = UINT16_MAX;
        constexpr uint32_t kUsbTimeoutMs = 5000U;
        constexpr size_t kHciReadChunkBytes = 512U;
        constexpr size_t kHciMaxEndpoints = 32U;
        constexpr uint8_t kUsbEndpointMinSize = 7U;

        bool discoverHciEndpoints(IOUSBHostInterface *interface,
                                  UsbHciEndpoints &endpoints)
        {
            if (interface == nullptr)
            {
                return false;
            }
            const auto *interfaceDescriptor =
                interface->getInterfaceDescriptor();
            const auto *configuration = interface->getConfigurationDescriptor();
            if (interfaceDescriptor == nullptr || configuration == nullptr ||
                interfaceDescriptor->bNumEndpoints < 3U ||
                interfaceDescriptor->bNumEndpoints > kHciMaxEndpoints)
            {
                return false;
            }
            UsbBytes<UsbHciEndpointDescriptor, kHciMaxEndpoints> found {};
            const StandardUSB::Descriptor *cursor = nullptr;
            size_t count = 0U;
            while (true)
            {
                const auto *candidate = StandardUSB::getNextEndpointDescriptor(
                    configuration, interfaceDescriptor, cursor);
                if (candidate == nullptr)
                {
                    break;
                }
                if (candidate->bLength < kUsbEndpointMinSize ||
                    count >= kHciMaxEndpoints)
                {
                    return false;
                }
                found.at(count) = {
                    candidate->bEndpointAddress,
                    static_cast<uint8_t>(candidate->bmAttributes &
                                         kEndpointTypeMask),
                };
                ++count;
                cursor = candidate;
            }
            // Reject inconsistent bNumEndpoints and truncated alternate
            // descriptors rather than borrowing a pipe from another setting.
            return count == interfaceDescriptor->bNumEndpoints &&
                   selectUsbHciEndpoints(found.data(), count, endpoints) ==
                       UsbHciEndpointResult::Ok;
        }

        bool validPipe(IOUSBHostPipe *pipe, uint8_t address, uint8_t type)
        {
            if (pipe == nullptr)
            {
                return false;
            }
            const auto *descriptor = pipe->getEndpointDescriptor();
            return descriptor != nullptr &&
                   descriptor->bEndpointAddress == address &&
                   (descriptor->bmAttributes & kEndpointTypeMask) == type;
        }

        // All platform callbacks are called only while the owning USB
        // service's workloop serializes against stop/willTerminate/power loss.
        bool ownerPermit(void *context, uint64_t epoch)
        {
            const auto &native = *static_cast<NativeAth3kIo *>(context);
            return native.opened && native.epoch == epoch &&
                   native.permit != nullptr &&
                   native.permit(native.policyContext, epoch);
        }

        bool controlTransfer(IOUSBHostInterface *interface, uint8_t requestType,
                             uint8_t request, void *buffer, size_t bytes)
        {
            if (interface == nullptr || bytes > kUsbMaxControl)
            {
                return false;
            }
            StandardUSB::DeviceRequest setup {
                requestType, request, 0U, 0U, static_cast<uint16_t>(bytes),
            };
            uint32_t transferred = 0;
            const IOReturn status = interface->deviceRequest(
                setup, buffer, transferred, kUsbTimeoutMs);
            return status == kIOReturnSuccess && transferred == bytes;
        }

        bool vendorRead(void *context, Ath3kControl command, uint8_t *buffer,
                        size_t bytes)
        {
            const auto &native = *static_cast<NativeAth3kIo *>(context);
            return ownerPermit(context, native.epoch) &&
                   command.requestType == kVendorIn &&
                   controlTransfer(native.interface, command.requestType,
                                   command.request, buffer, bytes);
        }

        bool vendorWrite(void *context, Ath3kControl command,
                         const uint8_t *buffer, size_t bytes)
        {
            const auto &native = *static_cast<NativeAth3kIo *>(context);
            // A vendor control OUT operation only reads the supplied bytes.
            // Kernel IOKit has a mutable buffer API; do not mutate firmware.
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
            auto *usbBuffer = const_cast<uint8_t *>(buffer);
            return ownerPermit(context, native.epoch) &&
                   command.requestType == kVendorOut &&
                   controlTransfer(native.interface, command.requestType,
                                   command.request, usbBuffer, bytes);
        }

        bool writePipe(IOUSBHostPipe *pipe, const uint8_t *buffer, size_t bytes,
                       size_t *transferred)
        {
            if (pipe == nullptr || buffer == nullptr ||
                transferred == nullptr || bytes == 0U || bytes > UINT32_MAX)
            {
                return false;
            }
            // IOMemoryDescriptor is used only as an I/O source, never written.
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
            auto *usbBuffer = const_cast<uint8_t *>(buffer);
            IOMemoryDescriptor *descriptor = IOMemoryDescriptor::withAddress(
                usbBuffer, bytes, kIODirectionOut);
            if (descriptor == nullptr)
            {
                return false;
            }
            const IOReturn prepared = descriptor->prepare();
            uint32_t actual = 0U;
            IOReturn status = kIOReturnError;
            if (prepared == kIOReturnSuccess)
            {
                status = pipe->io(descriptor, static_cast<uint32_t>(bytes),
                                  actual, kUsbTimeoutMs);
                (void)descriptor->complete();
            }
            descriptor->release();
            *transferred = actual;
            return status == kIOReturnSuccess && actual == bytes;
        }

        bool firmwareBulkOut(void *context, uint8_t endpoint,
                             const uint8_t *buffer, size_t bytes,
                             size_t *transferred)
        {
            const auto &native = *static_cast<NativeAth3kIo *>(context);
            return ownerPermit(context, native.epoch) &&
                   endpoint == kFirmwareEndpoint &&
                   writePipe(native.firmwareBulkOut, buffer, bytes,
                             transferred);
        }

        bool getFirmware(void *context, const char *filename,
                         Ath3kFirmwareImage *image)
        {
            const auto &native = *static_cast<NativeAth3kIo *>(context);
            return ownerPermit(context, native.epoch) &&
                   native.firmware != nullptr &&
                   native.firmware(native.policyContext, filename, image);
        }

        void waitMicroseconds(void * /*unused*/, uint32_t delay)
        {
            IODelay(delay);
        }

        bool hciPermit(void *context, uint64_t epoch)
        {
            const auto &native = *static_cast<NativeUsbHciIo *>(context);
            return native.opened && native.epoch == epoch &&
                   native.permit != nullptr &&
                   native.permit(native.policyContext, epoch);
        }

        bool hciCommand(void *context, const uint8_t *buffer, size_t bytes)
        {
            const auto &native = *static_cast<NativeUsbHciIo *>(context);
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
            auto *usbBuffer = const_cast<uint8_t *>(buffer);
            return hciPermit(context, native.epoch) &&
                   controlTransfer(native.interface, kHciClassOut, kHciRequest,
                                   usbBuffer, bytes);
        }

        bool hciAclOut(void *context, uint8_t endpoint, const uint8_t *buffer,
                       size_t bytes, size_t *transferred)
        {
            const auto &native = *static_cast<NativeUsbHciIo *>(context);
            return hciPermit(context, native.epoch) &&
                   endpoint == native.stream.endpoints.aclBulkOut &&
                   writePipe(native.aclOut, buffer, bytes, transferred);
        }

        bool hciDeliver(void *context, UsbHciPacketKind kind,
                        const uint8_t *packet, size_t bytes)
        {
            const auto &native = *static_cast<NativeUsbHciIo *>(context);
            return hciPermit(context, native.epoch) &&
                   native.deliver != nullptr &&
                   native.deliver(native.policyContext, kind, packet, bytes);
        }

        UsbHciHostCallbacks hciCallbacks(NativeUsbHciIo &native)
        {
            return {
                &native,    native.epoch, hciPermit,
                hciCommand, hciAclOut,    hciDeliver,
            };
        }

        UsbHciStatus pump(NativeUsbHciIo &native, UsbHciPacketKind kind)
        {
            if (!hciPermit(&native, native.epoch))
            {
                return UsbHciStatus::OwnershipLost;
            }
            IOUSBHostPipe *pipe =
                kind == UsbHciPacketKind::Event ? native.eventIn : native.aclIn;
            if (pipe == nullptr)
            {
                return UsbHciStatus::NotAttached;
            }
            uint8_t buffer[kHciReadChunkBytes] {};
            IOMemoryDescriptor *descriptor = IOMemoryDescriptor::withAddress(
                &buffer[0U], sizeof(buffer), kIODirectionIn);
            if (descriptor == nullptr)
            {
                native.stream.faulted = true;
                return UsbHciStatus::TransferFailed;
            }
            const IOReturn prepared = descriptor->prepare();
            IOReturn status = kIOReturnError;
            uint32_t transferred = 0U;
            if (prepared == kIOReturnSuccess)
            {
                status = pipe->io(descriptor, sizeof(buffer), transferred,
                                  kUsbTimeoutMs);
                (void)descriptor->complete();
            }
            descriptor->release();
            // An IN poll may outlive device removal or a host-controller
            // reset. Never parse borrowed USB bytes once the owning epoch
            // has been revoked, even when the transfer returned success.
            // Interrupt IN can be silent for an arbitrary period. A finite
            // timeout makes shutdown bounded, while partial/ambiguous I/O
            // failures still require a fresh controller transport session.
            const UsbHciStatus read = classifyUsbHciRead(
                hciPermit(&native, native.epoch), status == kIOReturnSuccess,
                status == kIOReturnTimeout, transferred, sizeof(buffer));
            if (read == UsbHciStatus::TransferFailed)
            {
                native.stream.faulted = true;
            }
            if (read != UsbHciStatus::Ok)
            {
                return read;
            }
            if (kind == UsbHciPacketKind::Event)
            {
                return receiveUsbHciEvent(native.stream, hciCallbacks(native),
                                          &buffer[0U], transferred);
            }
            return receiveUsbHciAcl(native.stream, hciCallbacks(native),
                                    &buffer[0U], transferred);
        }
    } // namespace

    bool openNativeAth3kIo(NativeAth3kIo &native, IOService *owner,
                           IOUSBHostInterface *interface, void *context,
                           uint64_t epoch, bool (*permit)(void *, uint64_t),
                           bool (*firmware)(void *, const char *,
                                            Ath3kFirmwareImage *))
    {
        if (native.opened || owner == nullptr || interface == nullptr ||
            context == nullptr || permit == nullptr || firmware == nullptr ||
            !permit(context, epoch))
        {
            return false;
        }
        const auto *descriptor = interface->getInterfaceDescriptor();
        if (descriptor == nullptr || descriptor->bInterfaceNumber != 0U ||
            !interface->open(owner))
        {
            return false;
        }
        IOUSBHostPipe *firmwarePipe = interface->copyPipe(kFirmwareEndpoint);
        if (!validPipe(firmwarePipe, kFirmwareEndpoint,
                       StandardUSB::kEndpointDescriptorTransferTypeBulk))
        {
            if (firmwarePipe != nullptr)
            {
                firmwarePipe->release();
            }
            interface->close(owner);
            return false;
        }
        native.owner = owner;
        native.interface = interface;
        native.firmwareBulkOut = firmwarePipe;
        native.policyContext = context;
        native.epoch = epoch;
        native.permit = permit;
        native.firmware = firmware;
        native.opened = true;
        return true;
    }

    void closeNativeAth3kIo(NativeAth3kIo &native)
    {
        if (native.firmwareBulkOut != nullptr)
        {
            native.firmwareBulkOut->release();
        }
        if (native.opened && native.interface != nullptr &&
            native.owner != nullptr)
        {
            native.interface->close(native.owner);
        }
        native = {};
    }

    Ath3kBootProgress bootstrapNativeAth3kIo(NativeAth3kIo &native)
    {
        if (!ownerPermit(&native, native.epoch) || native.interface == nullptr)
        {
            return {
                Ath3kBootResult::IdentityLost,
                Ath3kBootPhase::Probe,
                0U,
                false,
            };
        }
        IOUSBHostDevice *device = native.interface->getDevice();
        const auto *descriptor =
            device == nullptr ? nullptr : device->getDeviceDescriptor();
        if (descriptor == nullptr)
        {
            return {
                Ath3kBootResult::UnsupportedDevice,
                Ath3kBootPhase::Probe,
                0U,
                false,
            };
        }
        const Ath3kUsbIdentity identity {
            USBToHost16(descriptor->idVendor),
            USBToHost16(descriptor->idProduct),
            USBToHost16(descriptor->bcdDevice),
            0U,
        };
        const Ath3kIo io {
            &native,     native.epoch,    ownerPermit, vendorRead,
            vendorWrite, firmwareBulkOut, getFirmware, waitMicroseconds,
        };
        return bootstrapAth3kUsb(identity, io);
    }

    bool openNativeUsbHciIo(NativeUsbHciIo &native,
                            IOUSBHostInterface *interface, void *context,
                            uint64_t epoch, bool (*permit)(void *, uint64_t),
                            bool (*deliver)(void *, UsbHciPacketKind,
                                            const uint8_t *, size_t))
    {
        if (native.opened || interface == nullptr || context == nullptr ||
            permit == nullptr || deliver == nullptr || !permit(context, epoch))
        {
            return false;
        }
        const auto *descriptor = interface->getInterfaceDescriptor();
        // Bluetooth HCI is a separate USB function. Refuse an unrelated
        // interface even when it exposes similarly numbered endpoints.
        if (descriptor == nullptr || descriptor->bInterfaceNumber != 0U ||
            descriptor->bInterfaceClass != kBluetoothUsbClass ||
            descriptor->bInterfaceSubClass != 0x01U ||
            descriptor->bInterfaceProtocol != 0x01U)
        {
            return false;
        }
        // HCI-class endpoint topology alone is NOT device identity: do not
        // claim an unrelated Intel/Broadcom/Qualcomm Bluetooth USB adapter.
        // Read the physical USB DEVICE descriptor, never a registry hint or
        // the AR9565 WLAN PCI identity, and refuse pre-firmware boot mode.
        IOUSBHostDevice *device = interface->getDevice();
        const auto *deviceDescriptor =
            device == nullptr ? nullptr : device->getDeviceDescriptor();
        if (deviceDescriptor == nullptr || interface->isInactive() ||
            !isSupportedAth3kHciIdentity({
                USBToHost16(deviceDescriptor->idVendor),
                USBToHost16(deviceDescriptor->idProduct),
                USBToHost16(deviceDescriptor->bcdDevice),
                descriptor->bInterfaceNumber,
            }))
        {
            return false;
        }
        UsbHciEndpoints endpoints {};
        if (!discoverHciEndpoints(interface, endpoints))
        {
            return false;
        }
        IOUSBHostPipe *eventPipe =
            interface->copyPipe(endpoints.eventInterruptIn);
        IOUSBHostPipe *aclRead = interface->copyPipe(endpoints.aclBulkIn);
        IOUSBHostPipe *aclWrite = interface->copyPipe(endpoints.aclBulkOut);
        const bool endpointsValid =
            validPipe(eventPipe, endpoints.eventInterruptIn,
                      StandardUSB::kEndpointDescriptorTransferTypeInterrupt) &&
            validPipe(aclRead, endpoints.aclBulkIn,
                      StandardUSB::kEndpointDescriptorTransferTypeBulk) &&
            validPipe(aclWrite, endpoints.aclBulkOut,
                      StandardUSB::kEndpointDescriptorTransferTypeBulk);
        if (!endpointsValid)
        {
            if (eventPipe != nullptr)
            {
                eventPipe->release();
            }
            if (aclRead != nullptr)
            {
                aclRead->release();
            }
            if (aclWrite != nullptr)
            {
                aclWrite->release();
            }
            return false;
        }
        native.interface = interface;
        native.eventIn = eventPipe;
        native.aclIn = aclRead;
        native.aclOut = aclWrite;
        native.policyContext = context;
        native.epoch = epoch;
        native.permit = permit;
        native.deliver = deliver;
        native.opened = true;
        if (attachUsbHci(native.stream, endpoints, hciCallbacks(native)) !=
            UsbHciStatus::Ok)
        {
            closeNativeUsbHciIo(native);
            return false;
        }
        return true;
    }

    void closeNativeUsbHciIo(NativeUsbHciIo &native)
    {
        detachUsbHci(native.stream);
        if (native.eventIn != nullptr)
        {
            native.eventIn->release();
        }
        if (native.aclIn != nullptr)
        {
            native.aclIn->release();
        }
        if (native.aclOut != nullptr)
        {
            native.aclOut->release();
        }
        native = {};
    }

    UsbHciStatus sendNativeUsbHciCommand(NativeUsbHciIo &native,
                                         const uint8_t *command, size_t bytes)
    {
        return sendUsbHciCommand(native.stream, hciCallbacks(native), command,
                                 bytes);
    }

    UsbHciStatus sendNativeUsbHciAcl(NativeUsbHciIo &native,
                                     const uint8_t *packet, size_t bytes)
    {
        return sendUsbHciAcl(native.stream, hciCallbacks(native), packet,
                             bytes);
    }

    UsbHciStatus pumpNativeUsbHciEvent(NativeUsbHciIo &native)
    {
        return pump(native, UsbHciPacketKind::Event);
    }

    UsbHciStatus pumpNativeUsbHciAcl(NativeUsbHciIo &native)
    {
        return pump(native, UsbHciPacketKind::Acl);
    }
} // namespace simpleath
