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
    constexpr size_t kUsbHciTrackedAclHandles = 16U;

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
        FlowControlUnavailable,
        NoControllerCredits,
        NoCommandCredits,
        TooManyConnections,
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

    struct UsbHciAclHandle
    {
            uint16_t handle {};
            uint16_t outstanding {};
            bool active {};
            bool le {};
            bool classified {};
            bool connected {};
            bool retired {};
    };

    struct UsbHciAclCredits
    {
            uint16_t packetBytes {};
            uint16_t totalCredits {};
            uint16_t availableCredits {};
            bool readBufferPending {};
            bool configured {};
    };

    struct UsbHciAclWindow : UsbHciAclCredits
    {
            UsbBytes<UsbHciAclHandle, kUsbHciTrackedAclHandles> connections {};
            bool resetPending {};
    };

    struct UsbHciLeAclWindow : UsbHciAclCredits
    {
    };

    // A dedicated HCI host owns command serialization. The USB controller
    // initially permits one command; Command Complete/Status replaces that
    // budget with Num_HCI_Command_Packets (not a cumulative credit grant).
    // This adapter allows one pending command at a time, even if a controller
    // reports a larger window, to avoid ambiguous opcode completions.
    struct UsbHciCommandWindow
    {
            uint16_t pendingOpcode {};
            uint8_t credits {1U};
            bool pending {};
    };

    struct UsbHciState
    {
            UsbHciStream events {};
            UsbHciStream acl {};
            UsbHciAclWindow aclWindow {};
            UsbHciLeAclWindow leAclWindow {};
            UsbHciCommandWindow commandWindow {};
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
    // No new command can overtake a pending Command Complete/Status, exceed
    // Num_HCI_Command_Packets, or bypass a pending controller Reset/ACL pool
    // negotiation. The USB owner must serialize send/event/lifecycle calls.
    UsbHciStatus sendUsbHciCommand(UsbHciState &state,
                                   const UsbHciHostCallbacks &host,
                                   const uint8_t *command, size_t bytes);
    // Controller ACL credits are learned ONLY from a matching successful
    // HCI Read Buffer Size (0x1005) command-complete event. No bulk ACL TX
    // is accepted before that handshake. The owner must serialize these
    // operations and its HCI event callbacks under one USB epoch.
    //
    // BR/EDR Read Buffer Size and LE Read Buffer Size (0x2002) report
    // separate buffer pools. A successful physical LE Connection Complete
    // classifies an LE handle. LE credits stay segregated when advertised;
    // a zero-sized dedicated LE pool instead shares BR/EDR credits as the
    // HCI spec requires. Unclassified handles are not accepted once LE pool
    // negotiation has begun. Controller Number Of Completed Packets events
    // retire exact per-handle outstanding packets from the correct pool;
    // false or duplicate credits latch a fault instead of allowing overflow.
    // A disconnect event alone does NOT confirm buffer completion; all
    // outstanding slots require controller completion or transport reset.
    // HCI Reset invalidates all credits immediately and blocks renegotiation
    // until its successful Command Complete; USB transfer ACK is not enough.
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
