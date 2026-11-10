#ifndef SIMPLEATH_NATIVE_ATH3K_IO_HPP
#define SIMPLEATH_NATIVE_ATH3K_IO_HPP

#include "bluetooth/Ath3kUsb.hpp"
#include "bluetooth/UsbHci.hpp"

#include <IOKit/IOService.h>
#include <IOKit/usb/IOUSBHostInterface.h>
#include <IOKit/usb/IOUSBHostPipe.h>

namespace simpleath
{
    struct NativeAth3kIo
    {
            IOService *owner {};
            IOUSBHostInterface *interface {};
            IOUSBHostPipe *firmwareBulkOut {};
            void *policyContext {};
            uint64_t epoch {};
            bool (*permit)(void *, uint64_t) {};
            bool (*firmware)(void *, const char *, Ath3kFirmwareImage *) {};
            bool opened {};
    };

    // Native IOUSBHostInterface must already have matched as USB interface 0.
    // The IOService owner is the USB driver, not the WLAN PCI driver. Acquires
    // the interface session and the real DFU bulk-out pipe with verified type.
    bool openNativeAth3kIo(NativeAth3kIo &native, IOService *owner,
                           IOUSBHostInterface *interface, void *context,
                           uint64_t epoch, bool (*permit)(void *, uint64_t),
                           bool (*firmware)(void *, const char *,
                                            Ath3kFirmwareImage *));
    void closeNativeAth3kIo(NativeAth3kIo &native);

    // Derive physical ID from USB descriptors, not PCI, and run the synchronous
    // bootstrap callbacks. No USB-device or OS availability is fabricated.
    Ath3kBootProgress bootstrapNativeAth3kIo(NativeAth3kIo &native);

    // Borrowed native USB HCI pipes from an ALREADY OPEN USB interface;
    // openNativeUsbHciIo consumes real endpoint
    // descriptors and leaves the physical controller's HCI registration to the
    // OS's native Bluetooth stack, not to this packet-transport adapter.
    struct NativeUsbHciIo
    {
            IOUSBHostInterface *interface {};
            IOUSBHostPipe *eventIn {};
            IOUSBHostPipe *aclIn {};
            IOUSBHostPipe *aclOut {};
            UsbHciState stream {};
            void *policyContext {};
            uint64_t epoch {};
            bool (*permit)(void *, uint64_t) {};
            bool (*deliver)(void *, UsbHciPacketKind, const uint8_t *,
                            size_t) {};
            bool opened {};
    };

    // The caller holds the OPEN USB interface under exclusive, serialized
    // ownership. Endpoints are discovered from its active descriptors;
    // callers must not guess addresses. closeNativeUsbHciIo releases pipes,
    // not the caller's open interface session.
    bool openNativeUsbHciIo(NativeUsbHciIo &native,
                            IOUSBHostInterface *interface, void *context,
                            uint64_t epoch, bool (*permit)(void *, uint64_t),
                            bool (*deliver)(void *, UsbHciPacketKind,
                                            const uint8_t *, size_t));
    void closeNativeUsbHciIo(NativeUsbHciIo &native);

    UsbHciStatus sendNativeUsbHciCommand(NativeUsbHciIo &native,
                                         const uint8_t *command, size_t bytes);
    UsbHciStatus sendNativeUsbHciAcl(NativeUsbHciIo &native,
                                     const uint8_t *packet, size_t bytes);
    // These calls synchronously read at most one USB transfer, with a
    // bounded timeout. UsbHciStatus::Idle means a zero-byte timeout, not a
    // fault; OwnershipLost means the epoch changed during the I/O. NEVER
    // call these blocking operations on the lifecycle workloop/gate; the
    // native USB service must use an independent, cancellable USB I/O context.
    UsbHciStatus pumpNativeUsbHciEvent(NativeUsbHciIo &native);
    UsbHciStatus pumpNativeUsbHciAcl(NativeUsbHciIo &native);
} // namespace simpleath
#endif
