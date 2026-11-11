// Copyright:
//   - Copyright © 2026 laobamac. All rights reserved.
// SPDX-License-Identifier:
//   - LicenseRef-SimpleBCM-All-Rights-Reserved
// Confidential:
//   - false
// License-File:
//   - LICENSE-SIMPLEBCM
// Provenance:
//   - SimpleBCM v1.2.0, by laobamac; no public license grant identified
//   - Originally authored by laobamac on 2026/11/1.
//
// Boundary-Contract:
// - Owns:
//   - Native driver contracts and implementation for hardware identity.
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
//   - Native driver contracts and implementation for hardware identity.
// - Description:
//   - Implements or verifies the HardwareIdentity source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for hardware identity.

#ifndef SIMPLEATH_HARDWARE_IDENTITY_HPP
#define SIMPLEATH_HARDWARE_IDENTITY_HPP

#include <stddef.h>
#include <stdint.h>

namespace ath
{

    struct HardwareIdentity
    {
            uint32_t vendor;
            uint32_t device;
            uint32_t chip;
            uint32_t board;
            uint32_t boardVendor;
    };

    namespace detail
    {
        constexpr size_t kHardwareIdentityMaxBytes = 2048U;
        constexpr unsigned kHardwareHexDigits = 8U;
        constexpr unsigned kHardwareNibbleShift = 4U;
        constexpr int kHexAlphabetOffset = 10;
        constexpr uint32_t kBroadcomVendorId = 0x14e4U;

        // The native kernel source uses C++14 without std::span. Use a
        // checked byte load rather than unchecked caller-span arithmetic.
        inline bool identityReadChar(const char *data, size_t length,
                                     size_t index, char &character)
        {
            if (data == nullptr || index >= length)
            {
                return false;
            }
            uintptr_t address = 0U;
            static_assert(sizeof(address) == sizeof(data),
                          "native pointer address width must match uintptr_t");
            __builtin_memcpy(&address, static_cast<const void *>(&data),
                             sizeof(address));
            if (index > UINTPTR_MAX - address)
            {
                return false;
            }
            address += index;
            const char *location = nullptr;
            __builtin_memcpy(static_cast<void *>(&location), &address,
                             sizeof(location));
            __builtin_memcpy(&character, location, sizeof(character));
            return true;
        }

        inline int identityHexDigit(char character)
        {
            if (character >= '0' && character <= '9')
            {
                return character - '0';
            }
            if (character >= 'a' && character <= 'f')
            {
                return character - 'a' + kHexAlphabetOffset;
            }
            if (character >= 'A' && character <= 'F')
            {
                return character - 'A' + kHexAlphabetOffset;
            }
            return -1;
        }

        inline bool identityMatchKey(const char *text, size_t length,
                                     size_t offset, const char *key,
                                     size_t keyLength)
        {
            if (offset > length || keyLength > length - offset)
            {
                return false;
            }
            for (size_t index = 0U; index < keyLength; ++index)
            {
                char source = 0;
                char wanted = 0;
                if (!identityReadChar(text, length, offset + index, source) ||
                    !identityReadChar(key, keyLength, index, wanted) ||
                    source != wanted)
                {
                    return false;
                }
            }
            return true;
        }

        inline bool identityParseHex(const char *text, size_t start,
                                     uint32_t &value, size_t length)
        {
            uint32_t result = 0U;
            unsigned digits = 0U;
            for (size_t cursor = start; cursor < length; ++cursor)
            {
                char character = 0;
                if (!identityReadChar(text, length, cursor, character))
                {
                    return false;
                }
                if (character == '\n' || character == '\r' || character == 0)
                {
                    break;
                }
                const int digit = identityHexDigit(character);
                if (digit < 0 || digits >= kHardwareHexDigits)
                {
                    return false;
                }
                ++digits;
                result = (result << kHardwareNibbleShift) |
                         static_cast<uint32_t>(digit);
            }
            if (digits == 0U)
            {
                return false;
            }
            value = result;
            return true;
        }
    } // namespace detail

    inline bool hardwareValue(const char *text, size_t length, const char *key,
                              uint32_t &value)
    {
        if (text == nullptr || key == nullptr ||
            length > detail::kHardwareIdentityMaxBytes)
        {
            return false;
        }
        const size_t keyLength = __builtin_strlen(key);
        if (keyLength == 0U || keyLength > length)
        {
            return false;
        }
        for (size_t offset = 0U; offset <= length - keyLength; ++offset)
        {
            char before = 0;
            if (offset != 0U &&
                (!detail::identityReadChar(text, length, offset - 1U, before) ||
                 before != '\n'))
            {
                continue;
            }
            if (detail::identityMatchKey(text, length, offset, key, keyLength))
            {
                return detail::identityParseHex(text, offset + keyLength, value,
                                                length);
            }
        }
        return false;
    }

    inline bool decodeHardwareIdentity(const char *text, size_t length,
                                       HardwareIdentity &identity)
    {
        HardwareIdentity result {};
        if (text == nullptr || length > detail::kHardwareIdentityMaxBytes ||
            !hardwareValue(text, length, "vendorid: 0x", result.vendor) ||
            !hardwareValue(text, length, "deviceid: 0x", result.device) ||
            !hardwareValue(text, length, "chipnum: 0x", result.chip) ||
            !hardwareValue(text, length, "boardid: 0x", result.board) ||
            !hardwareValue(text, length, "boardvendor: 0x",
                           result.boardVendor) ||
            result.vendor != detail::kBroadcomVendorId || result.device == 0U ||
            result.chip == 0U || result.board == 0U)
        {
            return false;
        }
        identity = result;
        return true;
    }

} // namespace ath

#endif
