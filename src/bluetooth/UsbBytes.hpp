// SPDX-License-Identifier: GPL-2.0-only
#ifndef SIMPLEATH_USB_BYTES_HPP
#define SIMPLEATH_USB_BYTES_HPP

#include <cstddef>
#include <cstdint>

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
                // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
                return storage_[index];
            }

            const Value &at(size_t index) const
            {
                if (index >= Capacity)
                {
                    __builtin_trap();
                }
                // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
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
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        return &data[index];
    }
} // namespace simpleath
#endif
