#ifndef SIMPLEATH_USB_HCI_ENDPOINT_SELECTOR_HPP
#define SIMPLEATH_USB_HCI_ENDPOINT_SELECTOR_HPP

#include "UsbHci.hpp"
#include <cstddef>
#include <cstdint>

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
