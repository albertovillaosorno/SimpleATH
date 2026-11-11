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
//   - Native driver contracts and implementation for usb bytes.
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
//   - Native driver contracts and implementation for usb bytes.
// - Description:
//   - Implements or verifies the UsbBytes source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for usb bytes.

#ifndef SIMPLEATH_USB_BYTES_HPP
#define SIMPLEATH_USB_BYTES_HPP

#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    // Fixed-size freestanding packet storage for a target without userspace
    // STL headers. Every variable index is checked before the array access.
    template <typename Value, size_t Capacity> class UsbBytes
    {
        private:
            Value storage_[Capacity] {};

        public:
            Value *data()
            {
                return &storage_[0U];
            }

            const Value *data() const
            {
                return &storage_[0U];
            }

            static constexpr size_t size()
            {
                return Capacity;
            }

            Value &at(size_t index)
            {
                if (index >= Capacity)
                {
                    __builtin_trap();
                }
                // NOLINTNEXTLINE(*bounds-constant-array-index)
                return storage_[index];
            }

            const Value &at(size_t index) const
            {
                if (index >= Capacity)
                {
                    __builtin_trap();
                }
                // NOLINTNEXTLINE(*bounds-constant-array-index)
                return storage_[index];
            }

            void fill(Value value)
            {
                for (size_t index = 0U; index < Capacity; ++index)
                {
                    at(index) = value;
                }
            }
    };

    template <typename Value> Value *usbByteOffset(Value *data, size_t index)
    {
        // The caller checks packet length and index before using the address.
        // NOLINTNEXTLINE(*bounds-pointer-arithmetic)
        return &data[index];
    }
} // namespace simpleath
#endif
