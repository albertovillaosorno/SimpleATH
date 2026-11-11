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
