// SPDX-License-Identifier: AGPL-3.0-only
#ifndef SIMPLEATH_USB_HCI_HPP
#define SIMPLEATH_USB_HCI_HPP

#include "UsbBytes.hpp"
#include <cstddef>
#include <cstdint>

namespace simpleath
{
    constexpr size_t kUsbHciMaxEventBytes = 257U;
    constexpr size_t kUsbHciMaxAclBytes = 4096U;
    constexpr size_t kUsbHciMaxCommandBytes = 258U;

    enum class UsbHciPacketKind : uint8_t
    {
        Event,
        Acl,
    };

    enum class UsbHciStatus : uint8_t
    {
        Ok,
        InvalidArgument,
        InvalidEndpoint,
        NotAttached,
        OwnershipLost,
        MalformedPacket,
        FrameTooLarge,
        CallbackFailed,
        TransferFailed,
        Faulted,
    };

    struct UsbHciEndpoints
    {
            uint8_t eventInterruptIn;
            uint8_t aclBulkIn;
            uint8_t aclBulkOut;
    };

    struct UsbHciHostCallbacks
    {
            void *context;
            uint64_t ownerEpoch;
            bool (*permit)(void *context, uint64_t epoch);
            bool (*commandControlOut)(void *context, const uint8_t *packet,
                                      size_t bytes);
            bool (*aclBulkOut)(void *context, uint8_t endpoint,
                               const uint8_t *packet, size_t bytes,
                               size_t *transferred);
            // Called with an entire HCI event/ACL frame. The borrowed packet
            // bytes are valid ONLY during the callback. The macOS HCI host
            // stack must copy/consume data before returning.
            bool (*deliver)(void *context, UsbHciPacketKind kind,
                            const uint8_t *packet, size_t bytes);
    };

    struct UsbHciStream
    {
            UsbBytes<uint8_t, kUsbHciMaxAclBytes> packet {};
            size_t used {};
            size_t expected {};
    };

    struct UsbHciState
    {
            UsbHciStream events {};
            UsbHciStream acl {};
            UsbHciEndpoints endpoints {};
            uint64_t epoch {};
            bool attached {};
            bool faulted {};
    };

    // A dedicated native USB service must discover real endpoint types and
    // addresses, own the USB interface and arrange serialized callbacks.
    // Do not attach HCI to the WLAN PCI owner. Successful attach only enables
    // HCI transport; BLE readiness belongs to the real macOS host stack.
    UsbHciStatus attachUsbHci(UsbHciState &state,
                              const UsbHciEndpoints &endpoints,
                              const UsbHciHostCallbacks &host);
    void detachUsbHci(UsbHciState &state);

    // Host-issued HCI commands use USB class control transfer (0x20, req 0)
    // at interface 0. The native callback supplies that exact USB setup.
    UsbHciStatus sendUsbHciCommand(UsbHciState &state,
                                   const UsbHciHostCallbacks &host,
                                   const uint8_t *command, size_t bytes);
    UsbHciStatus sendUsbHciAcl(UsbHciState &state,
                               const UsbHciHostCallbacks &host,
                               const uint8_t *packet, size_t bytes);

    // USB interrupt/event and bulk/ACL transfers may split or coalesce HCI
    // frames. These functions reassemble exact lengths and detect overflows.
    // On a malformed stream the transport latches a fault until detach.
    UsbHciStatus receiveUsbHciEvent(UsbHciState &state,
                                    const UsbHciHostCallbacks &host,
                                    const uint8_t *transfer, size_t bytes);
    UsbHciStatus receiveUsbHciAcl(UsbHciState &state,
                                  const UsbHciHostCallbacks &host,
                                  const uint8_t *transfer, size_t bytes);
} // namespace simpleath
#endif
