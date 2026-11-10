// Synthetic USB IN results: no Apple USB provider or physical controller.
#include "bluetooth/UsbHci.hpp"

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
    for (const auto &sample : kCases)
    {
        if (simpleath::classifyUsbHciRead(sample.current, sample.completed,
                                          sample.timeout, sample.transferred,
                                          sample.capacity) != sample.expected)
        {
            return 1;
        }
    }
    return 0;
}
