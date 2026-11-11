// Copyright:
//   - Copyright © 2026 Alberto Villa Osorno
// SPDX-License-Identifier:
//   - MIT
// Confidential:
//   - false
// License-File:
//   - LICENSE-MIT
// Provenance:
//   - SimpleATH original; independently developed or locally authored
//
// Boundary-Contract:
// - Owns:
//   - Native driver contracts and implementation for native ath3k io.
// - Must-Not:
//   - Invent hardware readiness, weaken buffer bounds, or assume ABI
//     compatibility.
// - Allows:
//   - Inputs: validated register, protocol, platform, or device state from
//     callers.
//   - Outputs: bounded native transitions, messages, or explicit errors.
//   - Side effects: only the device and kernel operations owned by this module.
// - Split-When:
//   - A separate protocol stage needs independent validation and ownership.
// - Merge-When:
//   - The caller directly owns this narrow contract without reuse.
// - Summary:
//   - Native driver contracts and implementation for native ath3k io.
// - Description:
//   - Implements or verifies the NativeAth3kIo source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for native ath3k io.

#ifndef SIMPLEATH_NATIVE_ATH3K_IO_HPP
#define SIMPLEATH_NATIVE_ATH3K_IO_HPP

#include "bluetooth/Ath3kUsb.hpp"
#include "bluetooth/UsbHci.hpp"
#include "bluetooth/UsbHciEndpointSelector.hpp"

#include <IOKit/IOService.h>
#include <IOKit/usb/IOUSBHostInterface.h>
#include <IOKit/usb/IOUSBHostPipe.h>

namespace simpleath
{
    struct NativeAth3kIo
    {
            IOService *owner {};
            IOUSBHostInterface *interface {};
            // Borrowed while this service exclusively owns the boot interface.
            IOUSBHostDevice *device {};
            IOUSBHostPipe *firmwareBulkOut {};
            // Exact physical USB identity captured while opening the DFU
            // session. A later bootstrap must verify the same interface.
            Ath3kUsbIdentity identity {};
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
            // Borrowed under the caller's exclusively opened USB interface.
            // A swapped device object is NOT the same controller even when
            // USB VID/PID/revision and the owner's epoch happen to match.
            IOUSBHostDevice *device {};
            Ath3kUsbIdentity identity {};
            // Initial configuration/alternate descriptor and required HCI
            // endpoints. A same-device setting switch invalidates this lease.
            UsbHciInterfaceTopology topology {};
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
    // ownership. Endpoints are discovered from its active descriptors; the
    // physical USB device and interface identity are checked again before
    // each native HCI operation and after external permission callbacks.
    // Callers must not guess addresses. closeNativeUsbHciIo releases pipes,
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
