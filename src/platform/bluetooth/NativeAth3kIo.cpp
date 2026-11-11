#include "NativeAth3kIo.hpp"
#include "bluetooth/Ath3kUsb.hpp"
#include "bluetooth/UsbBytes.hpp"
#include "bluetooth/UsbHci.hpp"
#include "bluetooth/UsbHciEndpointSelector.hpp"

#include <stddef.h>
#include <stdint.h>

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

        // The firmware bootstrap entrypoint can also be called directly.
        // Matching a personality in the USB service is not proof that an
        // arbitrary interface passed here still belongs to the same AR3012
        // boot device. Never send DFU bytes to an unrelated USB function.
        bool bootInterfaceIdentity(IOUSBHostInterface *interface,
                                   Ath3kUsbIdentity &identity)
        {
            identity = {};
            if (interface == nullptr || interface->isInactive())
            {
                return false;
            }
            const auto *interfaceDescriptor =
                interface->getInterfaceDescriptor();
            IOUSBHostDevice *device = interface->getDevice();
            const auto *deviceDescriptor =
                device == nullptr ? nullptr : device->getDeviceDescriptor();
            if (interfaceDescriptor == nullptr || deviceDescriptor == nullptr ||
                device->isInactive())
            {
                return false;
            }
            identity = {
                USBToHost16(deviceDescriptor->idVendor),
                USBToHost16(deviceDescriptor->idProduct),
                USBToHost16(deviceDescriptor->bcdDevice),
                interfaceDescriptor->bInterfaceNumber,
            };
            return identity.interfaceNumber == 0U &&
                   identity.deviceRevision <= 1U &&
                   isSupportedAth3kUsbIdentity(identity);
        }

        bool sameIdentity(const Ath3kUsbIdentity &left,
                          const Ath3kUsbIdentity &right)
        {
            return left.vendorId == right.vendorId &&
                   left.productId == right.productId &&
                   left.deviceRevision == right.deviceRevision &&
                   left.interfaceNumber == right.interfaceNumber;
        }

        bool liveHciIdentity(IOUSBHostInterface *interface,
                             Ath3kUsbIdentity &identity)
        {
            identity = {};
            if (interface == nullptr || interface->isInactive())
            {
                return false;
            }
            const auto *descriptor = interface->getInterfaceDescriptor();
            IOUSBHostDevice *device = interface->getDevice();
            const auto *usb =
                device == nullptr ? nullptr : device->getDeviceDescriptor();
            if (descriptor == nullptr || usb == nullptr ||
                device->isInactive() || descriptor->bInterfaceNumber != 0U ||
                descriptor->bInterfaceClass != kBluetoothUsbClass ||
                descriptor->bInterfaceSubClass != 0x01U ||
                descriptor->bInterfaceProtocol != 0x01U)
            {
                return false;
            }
            identity = {
                USBToHost16(usb->idVendor),
                USBToHost16(usb->idProduct),
                USBToHost16(usb->bcdDevice),
                descriptor->bInterfaceNumber,
            };
            return isSupportedAth3kHciIdentity(identity);
        }

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

        bool hciTopology(IOUSBHostInterface *interface,
                         UsbHciInterfaceTopology &topology)
        {
            topology = {};
            if (interface == nullptr)
            {
                return false;
            }
            const auto *config = interface->getConfigurationDescriptor();
            const auto *alternate = interface->getInterfaceDescriptor();
            if (config == nullptr || alternate == nullptr ||
                config->bConfigurationValue == 0U)
            {
                return false;
            }
            const uint8_t configurationValue = config->bConfigurationValue;
            const uint8_t alternateSetting = alternate->bAlternateSetting;
            if (!discoverHciEndpoints(interface, topology.endpoints))
            {
                return false;
            }
            // A descriptor lookup may invoke provider code while the active
            // alternate changes. Bind only a stable descriptor snapshot.
            config = interface->getConfigurationDescriptor();
            alternate = interface->getInterfaceDescriptor();
            if (config == nullptr || alternate == nullptr ||
                config->bConfigurationValue != configurationValue ||
                alternate->bAlternateSetting != alternateSetting)
            {
                return false;
            }
            topology.configurationValue = configurationValue;
            topology.alternateSetting = alternateSetting;
            return true;
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
            if (!native.opened || native.epoch != epoch ||
                native.permit == nullptr || native.interface == nullptr ||
                native.device == nullptr)
            {
                return false;
            }
            IOUSBHostInterface *const interface = native.interface;
            const IOUSBHostDevice *const device = native.device;
            if (!native.permit(native.policyContext, epoch) || !native.opened ||
                native.epoch != epoch || native.interface != interface ||
                native.device != device || interface->getDevice() != device)
            {
                return false;
            }
            Ath3kUsbIdentity current {};
            return bootInterfaceIdentity(interface, current) &&
                   sameIdentity(native.identity, current);
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
            if (!native.opened || native.epoch != epoch ||
                native.permit == nullptr || native.interface == nullptr ||
                native.device == nullptr)
            {
                return false;
            }
            // Capture the complete borrowed USB lease. A native policy or
            // descriptor method can synchronously close and reopen this same
            // storage with the SAME owner epoch and endpoint addresses.
            // Checking only before the final provider calls would authorize
            // the old stack frame to send on that successor's pipes.
            const UsbHciOwnerLease issued {
                epoch,
                native.stream.generation,
                native.topology,
                true,
            };
            const Ath3kUsbIdentity identity = native.identity;
            IOUSBHostInterface *const interface = native.interface;
            const IOUSBHostDevice *const device = native.device;
            IOUSBHostPipe *const eventPipe = native.eventIn;
            IOUSBHostPipe *const aclRead = native.aclIn;
            IOUSBHostPipe *const aclWrite = native.aclOut;
            void *const policyContext = native.policyContext;
            const auto permit = native.permit;
            const auto deliver = native.deliver;
            const auto stillOwned = [&native, &issued, interface, device,
                                     eventPipe, aclRead, aclWrite,
                                     policyContext, permit, deliver, &identity]
            {
                const UsbHciOwnerLease current {
                    native.epoch,
                    native.stream.generation,
                    native.topology,
                    native.opened,
                };
                return sameUsbHciOwnerLease(issued, current) &&
                       native.interface == interface &&
                       native.device == device &&
                       sameIdentity(native.identity, identity) &&
                       native.eventIn == eventPipe && native.aclIn == aclRead &&
                       native.aclOut == aclWrite &&
                       native.policyContext == policyContext &&
                       native.permit == permit && native.deliver == deliver;
            };
            if (!permit(policyContext, epoch) || !stillOwned())
            {
                return false;
            }
            if (interface->getDevice() != device || !stillOwned())
            {
                return false;
            }
            Ath3kUsbIdentity current {};
            if (!liveHciIdentity(interface, current) || !stillOwned() ||
                !sameIdentity(identity, current))
            {
                return false;
            }
            UsbHciInterfaceTopology topology {};
            if (!hciTopology(interface, topology) || !stillOwned() ||
                !sameUsbHciInterfaceTopology(issued.topology, topology))
            {
                return false;
            }
            // Recheck after EACH borrowed pipe descriptor query. If one
            // reenters owner shutdown, do not dereference any later pipe.
            if (!validPipe(
                    eventPipe, issued.topology.endpoints.eventInterruptIn,
                    StandardUSB::kEndpointDescriptorTransferTypeInterrupt) ||
                !stillOwned())
            {
                return false;
            }
            if (!validPipe(aclRead, issued.topology.endpoints.aclBulkIn,
                           StandardUSB::kEndpointDescriptorTransferTypeBulk) ||
                !stillOwned())
            {
                return false;
            }
            return validPipe(
                       aclWrite, issued.topology.endpoints.aclBulkOut,
                       StandardUSB::kEndpointDescriptorTransferTypeBulk) &&
                   stillOwned();
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
            // Once a USB fault has invalidated the stream, no further bus
            // reads may be issued until the physical owner reattaches.
            if (native.stream.faulted)
            {
                return UsbHciStatus::Faulted;
            }
            if (!native.stream.attached)
            {
                return UsbHciStatus::NotAttached;
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
            const bool partialFrame = kind == UsbHciPacketKind::Event
                                          ? native.stream.events.used != 0U
                                          : native.stream.acl.used != 0U;
            const UsbHciStatus read = classifyUsbHciRead(
                hciPermit(&native, native.epoch), status == kIOReturnSuccess,
                status == kIOReturnTimeout, transferred, sizeof(buffer),
                partialFrame);
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
            epoch == 0U || !permit(context, epoch) || native.opened)
        {
            return false;
        }
        Ath3kUsbIdentity initialIdentity {};
        if (!bootInterfaceIdentity(interface, initialIdentity))
        {
            return false;
        }
        IOUSBHostDevice *const device = interface->getDevice();
        if (device == nullptr || !interface->open(owner))
        {
            return false;
        }
        IOUSBHostPipe *firmwarePipe = interface->copyPipe(kFirmwareEndpoint);
        Ath3kUsbIdentity currentIdentity {};
        if (!validPipe(firmwarePipe, kFirmwareEndpoint,
                       StandardUSB::kEndpointDescriptorTransferTypeBulk) ||
            !permit(context, epoch) || native.opened ||
            interface->getDevice() != device ||
            !bootInterfaceIdentity(interface, currentIdentity) ||
            !sameIdentity(initialIdentity, currentIdentity))
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
        native.device = device;
        native.firmwareBulkOut = firmwarePipe;
        native.identity = initialIdentity;
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
        Ath3kUsbIdentity identity {};
        if (!bootInterfaceIdentity(native.interface, identity) ||
            !sameIdentity(native.identity, identity) ||
            !ownerPermit(&native, native.epoch))
        {
            // A revoked or re-enumerated provider cannot be given a DFU
            // transfer by reconstructing an interface number from its USB
            // device descriptor. The physical interface must still match
            // the one exclusively opened for this firmware epoch.
            return {
                Ath3kBootResult::IdentityLost,
                Ath3kBootPhase::Probe,
                0U,
                false,
            };
        }
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
            permit == nullptr || deliver == nullptr || epoch == 0U ||
            !permit(context, epoch) || native.opened)
        {
            return false;
        }
        // The real USB HCI function must be both class-correct and one of
        // the published, post-firmware ATH3012 physical identities. Never
        // derive this from a property on the WLAN PCI function.
        Ath3kUsbIdentity initialIdentity {};
        if (!liveHciIdentity(interface, initialIdentity))
        {
            return false;
        }
        IOUSBHostDevice *const device = interface->getDevice();
        UsbHciInterfaceTopology openingTopology {};
        if (!hciTopology(interface, openingTopology))
        {
            return false;
        }
        const UsbHciEndpoints &endpoints = openingTopology.endpoints;
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
        // copyPipe may trigger synchronous USB/provider callbacks. A grant
        // obtained before pipe discovery is not sufficient to publish an
        // adapter after detach or replacement. Release all local pipes and
        // leave a possible successor's state untouched on lease loss.
        // External permission may synchronously switch the interface's
        // alternate setting. Re-evaluate topology *after* that callback;
        // otherwise the pre-permit snapshot could authorize stale pipes.
        const bool permitted = permit(context, epoch);
        Ath3kUsbIdentity currentIdentity {};
        const IOUSBHostDevice *const currentDevice = interface->getDevice();
        UsbHciInterfaceTopology currentTopology {};
        const bool sameEndpoints =
            hciTopology(interface, currentTopology) &&
            sameUsbHciInterfaceTopology(openingTopology, currentTopology);
        const bool stillHci = currentDevice == device &&
                              interface->getDevice() == device &&
                              liveHciIdentity(interface, currentIdentity) &&
                              sameIdentity(initialIdentity, currentIdentity);
        if (!endpointsValid || !sameEndpoints || !permitted || native.opened ||
            interface->isInactive() || !stillHci)
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
        native.device = device;
        native.identity = initialIdentity;
        native.topology = openingTopology;
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
        // Preserve the stream generation across native close/reset. A USB
        // callback may tear down and reopen the same storage before an old
        // HCI call returns, even if the physical owner reuses its epoch.
        const uint64_t detachedGeneration = native.stream.generation;
        native = {};
        native.stream.generation = detachedGeneration;
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
