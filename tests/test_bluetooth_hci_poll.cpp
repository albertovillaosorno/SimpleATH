// Synthetic USB IN results: no Apple USB provider or physical controller.
#include "bluetooth/UsbHci.hpp"
#include "bluetooth/UsbHciEndpointSelector.hpp"

#include <cstddef>

namespace
{
    using simpleath::UsbHciStatus;

    struct Sample
    {
            size_t transferred;
            size_t capacity;
            bool current;
            bool completed;
            bool timeout;
            UsbHciStatus expected;
    };

    constexpr size_t kTransferCapacity = 512U;
    constexpr size_t kShortTransfer = 7U;
    constexpr size_t kOversized = kTransferCapacity + 1U;
    constexpr Sample kCases[] {
        {
            kTransferCapacity,
            kTransferCapacity,
            true,
            true,
            false,
            UsbHciStatus::Ok,
        },
        {
            kShortTransfer,
            kTransferCapacity,
            true,
            true,
            false,
            UsbHciStatus::Ok,
        },
        {
            0U,
            kTransferCapacity,
            true,
            false,
            true,
            UsbHciStatus::Idle,
        },
        {
            kShortTransfer,
            kTransferCapacity,
            true,
            false,
            true,
            UsbHciStatus::TransferFailed,
        },
        {
            0U,
            kTransferCapacity,
            true,
            true,
            false,
            UsbHciStatus::TransferFailed,
        },
        {
            kOversized,
            kTransferCapacity,
            true,
            true,
            false,
            UsbHciStatus::TransferFailed,
        },
        {
            0U,
            kTransferCapacity,
            true,
            false,
            false,
            UsbHciStatus::TransferFailed,
        },
        {
            0U,
            kTransferCapacity,
            true,
            true,
            true,
            UsbHciStatus::TransferFailed,
        },
        {
            kShortTransfer,
            0U,
            true,
            true,
            false,
            UsbHciStatus::TransferFailed,
        },
        {
            kShortTransfer,
            kTransferCapacity,
            false,
            true,
            false,
            UsbHciStatus::OwnershipLost,
        },
        {
            0U,
            kTransferCapacity,
            false,
            false,
            true,
            UsbHciStatus::OwnershipLost,
        },
        {
            kOversized,
            kTransferCapacity,
            false,
            false,
            false,
            UsbHciStatus::OwnershipLost,
        },
    };
} // namespace

int main()
{
    using simpleath::sameUsbHciOwnerLease;
    using simpleath::UsbHciOwnerLease;
    // A native HCI service can call its own detach/reopen from a borrowed
    // authorization callback. The successor can reuse the physical USB ID,
    // owner epoch, and exact endpoint topology; only generation separates it.
    const UsbHciOwnerLease issued {
        17U,
        8U,
        {1U, 0U, {0x81U, 0x82U, 0x02U}},
        true,
    };
    UsbHciOwnerLease current = issued;
    if (!sameUsbHciOwnerLease(issued, current))
    {
        return 10;
    }
    current.generation = 10U; // Synchronous revoke + reattach, same epoch.
    if (sameUsbHciOwnerLease(issued, current))
    {
        return 11;
    }
    current = issued;
    current.epoch = 18U;
    if (sameUsbHciOwnerLease(issued, current))
    {
        return 12;
    }
    current = issued;
    current.topology.alternateSetting = 1U;
    if (sameUsbHciOwnerLease(issued, current))
    {
        return 13;
    }
    current = issued;
    current.topology.endpoints.aclBulkOut = 0x03U;
    if (sameUsbHciOwnerLease(issued, current))
    {
        return 14;
    }
    current = issued;
    current.opened = false;
    if (sameUsbHciOwnerLease(issued, current))
    {
        return 15;
    }
    // attachUsbHci calls the native permit before assigning generation 1.
    current = issued;
    current.generation = 0U;
    const UsbHciOwnerLease initial = current;
    if (!sameUsbHciOwnerLease(initial, current))
    {
        return 16;
    }
    current.generation = 1U;
    if (sameUsbHciOwnerLease(initial, current))
    {
        return 17;
    }
    for (const auto &sample : kCases)
    {
        if (simpleath::classifyUsbHciRead(sample.current, sample.completed,
                                          sample.timeout, sample.transferred,
                                          sample.capacity) != sample.expected)
        {
            return 1;
        }
    }
    // Both Event and ACL reassembly can span multiple successful USB reads.
    // A full native poll timeout with an unfinished frame must poison that
    // stream; otherwise stale prefix bytes can be spliced to a later frame.
    if (simpleath::classifyUsbHciRead(true, false, true, 0U, kTransferCapacity,
                                      true) != UsbHciStatus::TransferFailed ||
        simpleath::classifyUsbHciRead(true, true, false, kShortTransfer,
                                      kTransferCapacity,
                                      true) != UsbHciStatus::Ok ||
        simpleath::classifyUsbHciRead(false, false, true, 0U, kTransferCapacity,
                                      true) != UsbHciStatus::OwnershipLost ||
        simpleath::classifyUsbHciRead(true, false, true, kShortTransfer,
                                      kTransferCapacity,
                                      true) != UsbHciStatus::TransferFailed ||
        simpleath::classifyUsbHciRead(true, false, true, 0U,
                                      kTransferCapacity) != UsbHciStatus::Idle)
    {
        return 18;
    }
    return 0;
}
