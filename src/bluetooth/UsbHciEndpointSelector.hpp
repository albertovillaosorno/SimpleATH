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
//   - Native driver contracts and implementation for usb hci endpoint selector.
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
//   - Native driver contracts and implementation for usb hci endpoint selector.
// - Description:
//   - Implements or verifies the UsbHciEndpointSelector source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: usb hci endpoint selector.

#ifndef SIMPLEATH_USB_HCI_ENDPOINT_SELECTOR_HPP
#define SIMPLEATH_USB_HCI_ENDPOINT_SELECTOR_HPP

#include "UsbHci.hpp"
#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    struct UsbHciEndpointDescriptor
    {
            uint8_t address;
            uint8_t transferType;
    };

    enum class UsbHciEndpointResult : uint8_t
    {
        Ok,
        InvalidArgument,
        InvalidDescriptor,
        MissingRequired,
        Ambiguous,
    };

    // A borrowed pipe belongs to a particular active USB configuration and
    // alternate interface setting, not just an endpoint address. Switching
    // either can invalidate the borrowed pipe even if the three HCI endpoint
    // addresses remain identical. Compare this snapshot before every I/O.
    struct UsbHciInterfaceTopology
    {
            uint8_t configurationValue;
            uint8_t alternateSetting;
            UsbHciEndpoints endpoints;
    };

    bool sameUsbHciInterfaceTopology(const UsbHciInterfaceTopology &opened,
                                     const UsbHciInterfaceTopology &current);

    // The native HCI owner can be torn down and rebound inside a borrowed
    // USB/provider callback, even to the same epoch and endpoint topology.
    // A local transport generation is the final discriminator. During the
    // initial attach it may still be zero; only the native owner is open then.
    struct UsbHciOwnerLease
    {
            uint64_t epoch {};
            uint64_t generation {};
            UsbHciInterfaceTopology topology {};
            bool opened {};
    };

    inline bool sameUsbHciOwnerLease(const UsbHciOwnerLease &issued,
                                     const UsbHciOwnerLease &current)
    {
        return issued.opened && current.opened && issued.epoch != 0U &&
               issued.epoch == current.epoch &&
               issued.generation == current.generation &&
               sameUsbHciInterfaceTopology(issued.topology, current.topology);
    }

    // Classify a completed USB IN poll against the exact session that issued
    // the read, not the session which happens to occupy the same native
    // storage when the USB/provider callback returns. A stale read is never
    // allowed to fault the replacement controller's HCI stream.
    inline UsbHciStatus
    classifyUsbHciReadForLease(const UsbHciOwnerLease &issued,
                               const UsbHciOwnerLease &current, bool completed,
                               bool timedOut, size_t transferred,
                               size_t capacity, bool partialFrame = false)
    {
        return classifyUsbHciRead(sameUsbHciOwnerLease(issued, current),
                                  completed, timedOut, transferred, capacity,
                                  partialFrame);
    }

    // The USB owner extracts endpoint address and transfer type from the
    // ACTIVE interface's real descriptors, including alternate setting.
    // Transfer type follows USB bmAttributes bits 1:0 (bulk=2, interrupt=3).
    // Select exactly one HCI interrupt IN, ACL bulk IN and ACL bulk OUT.
    // Reject duplicate addresses and ambiguous alternate pipes instead of
    // inventing conventional endpoint addresses (e.g. 0x81/0x82/0x02).
    // Ignore unrelated isochronous SCO endpoints; no SCO support implied.
    // Overlapping output/descriptor storage fails without mutation.
    UsbHciEndpointResult
    selectUsbHciEndpoints(const UsbHciEndpointDescriptor *descriptors,
                          size_t count, UsbHciEndpoints &endpoints);
} // namespace simpleath
#endif
