// SPDX-License-Identifier: AGPL-3.0-only
#include "UsbHciEndpointSelector.hpp"
#include "UsbBytes.hpp"
#include "UsbHci.hpp"

#include <cstddef>
#include <cstdint>

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
    } // namespace

    UsbHciEndpointResult
    selectUsbHciEndpoints(const UsbHciEndpointDescriptor *descriptors,
                          size_t count, UsbHciEndpoints &endpoints)
    {
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
