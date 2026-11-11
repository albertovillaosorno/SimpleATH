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

#include "UsbHciEndpointSelector.hpp"
#include "UsbBytes.hpp"
#include "UsbHci.hpp"

#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    namespace
    {
        constexpr uint8_t kUsbIn = 0x80U;
        constexpr uint8_t kUsbEndpointNumber = 0x0fU;
        constexpr uint8_t kUsbEndpointReserved = 0x70U;
        constexpr uint8_t kUsbBulk = 0x02U;
        constexpr uint8_t kUsbInterrupt = 0x03U;
        constexpr uint8_t kUsbTransferTypeMask = 0x03U;
        constexpr size_t kUsbMaxEndpoints = 32U;
        constexpr size_t kUsbAddressSlots = 256U;

        bool chooseOne(uint8_t address, uint8_t &selected)
        {
            if (selected != 0U)
            {
                return false;
            }
            selected = address;
            return true;
        }

        bool validAddress(uint8_t address)
        {
            return (address & kUsbEndpointNumber) != 0U &&
                   (address & kUsbEndpointReserved) == 0U;
        }

        bool overlaps(const void *const firstBuffer, size_t firstBytes,
                      const void *const secondBuffer, size_t secondBytes)
        {
            uintptr_t first = 0U;
            uintptr_t second = 0U;
            static_assert(sizeof(first) == sizeof(firstBuffer),
                          "pointer addresses must fit uintptr_t");
            __builtin_memcpy(static_cast<void *>(&first),
                             static_cast<const void *>(&firstBuffer),
                             sizeof(first));
            __builtin_memcpy(static_cast<void *>(&second),
                             static_cast<const void *>(&secondBuffer),
                             sizeof(second));
            return first <= second ? second - first < firstBytes
                                   : first - second < secondBytes;
        }
    } // namespace

    bool sameUsbHciInterfaceTopology(const UsbHciInterfaceTopology &opened,
                                     const UsbHciInterfaceTopology &current)
    {
        return opened.configurationValue != 0U &&
               current.configurationValue == opened.configurationValue &&
               current.alternateSetting == opened.alternateSetting &&
               opened.endpoints.eventInterruptIn != 0U &&
               opened.endpoints.aclBulkIn != 0U &&
               opened.endpoints.aclBulkOut != 0U &&
               current.endpoints.eventInterruptIn ==
                   opened.endpoints.eventInterruptIn &&
               current.endpoints.aclBulkIn == opened.endpoints.aclBulkIn &&
               current.endpoints.aclBulkOut == opened.endpoints.aclBulkOut;
    }

    UsbHciEndpointResult
    selectUsbHciEndpoints(const UsbHciEndpointDescriptor *descriptors,
                          size_t count, UsbHciEndpoints &endpoints)
    {
        // The output must not invalidate borrowed endpoint descriptors,
        // including when it overlays only a later descriptor in the array.
        // Check the full declared input span before clearing any output.
        if (descriptors != nullptr && count != 0U &&
            (count > SIZE_MAX / sizeof(*descriptors) ||
             overlaps(descriptors, count * sizeof(*descriptors), &endpoints,
                      sizeof(endpoints))))
        {
            return UsbHciEndpointResult::InvalidArgument;
        }
        endpoints = {};
        if (descriptors == nullptr || count == 0U || count > kUsbMaxEndpoints)
        {
            return UsbHciEndpointResult::InvalidArgument;
        }
        UsbHciEndpoints found {};
        // 7-bit endpoint address space, two directions. A descriptor may
        // not reuse an address in the same active interface setting.
        UsbBytes<bool, kUsbAddressSlots> seen {};
        for (size_t index = 0U; index < count; ++index)
        {
            const auto &descriptor = *usbByteOffset(descriptors, index);
            const uint8_t address = descriptor.address;
            if (!validAddress(address) ||
                descriptor.transferType > kUsbTransferTypeMask)
            {
                return UsbHciEndpointResult::InvalidDescriptor;
            }
            if (seen.at(address))
            {
                return UsbHciEndpointResult::Ambiguous;
            }
            seen.at(address) = true;
            const bool isIn = (address & kUsbIn) != 0U;
            if (descriptor.transferType == kUsbInterrupt && isIn &&
                !chooseOne(address, found.eventInterruptIn))
            {
                return UsbHciEndpointResult::Ambiguous;
            }
            if (descriptor.transferType == kUsbBulk && isIn &&
                !chooseOne(address, found.aclBulkIn))
            {
                return UsbHciEndpointResult::Ambiguous;
            }
            if (descriptor.transferType == kUsbBulk && !isIn &&
                !chooseOne(address, found.aclBulkOut))
            {
                return UsbHciEndpointResult::Ambiguous;
            }
        }
        if (found.eventInterruptIn == 0U || found.aclBulkIn == 0U ||
            found.aclBulkOut == 0U)
        {
            return UsbHciEndpointResult::MissingRequired;
        }
        endpoints = found;
        return UsbHciEndpointResult::Ok;
    }
} // namespace simpleath
