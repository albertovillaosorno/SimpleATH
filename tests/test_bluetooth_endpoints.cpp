// SPDX-License-Identifier: AGPL-3.0-only
// Synthetic USB endpoint topology tests; no real USB device or kext loaded.
#include "bluetooth/UsbHci.hpp"
#include "bluetooth/UsbHciEndpointSelector.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

using namespace simpleath;

namespace
{
    constexpr int kDiagnosticModulo = 250;
    constexpr uint8_t kInterrupt = 3U;
    constexpr uint8_t kBulk = 2U;
    constexpr uint8_t kIso = 1U;
    constexpr uint8_t kControl = 0U;
    constexpr uint8_t kEvent = 0x85U;
    constexpr uint8_t kAclIn = 0x87U;
    constexpr uint8_t kAclOut = 0x04U;
    constexpr uint8_t kScoIn = 0x83U;
    constexpr uint8_t kScoOut = 0x03U;
    constexpr uint8_t kAdditionalOut = 0x05U;
    constexpr uint8_t kInvalidAddress = 0xf1U;
    constexpr uint8_t kInvalidType = 5U;
    constexpr size_t kLimit = 32U;
    constexpr size_t kOverLimit = 33U;
    constexpr std::array<UsbHciEndpointDescriptor, 5U> kDescriptors {
        {
            {kAclOut, kBulk},
            {kScoIn, kIso},
            {kEvent, kInterrupt},
            {kAdditionalOut, kInterrupt},
            {kAclIn, kBulk},
        },
    };

    bool expected(const UsbHciEndpointDescriptor *data, size_t count,
                  UsbHciEndpointResult result, bool populated)
    {
        UsbHciEndpoints selected {kEvent, kAclIn, kAclOut};
        const auto actual = selectUsbHciEndpoints(data, count, selected);
        if (actual != result)
        {
            return false;
        }
        if (populated)
        {
            return selected.eventInterruptIn == kEvent &&
                   selected.aclBulkIn == kAclIn &&
                   selected.aclBulkOut == kAclOut;
        }
        return selected.eventInterruptIn == 0U && selected.aclBulkIn == 0U &&
               selected.aclBulkOut == 0U;
    }

    int acceptPhysicalEndpoints()
    {
        if (!expected(kDescriptors.data(), kDescriptors.size(),
                      UsbHciEndpointResult::Ok, true))
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        // USB endpoint numbers are NOT fixed to the conventional Linux
        // btusb addresses; this catches guessed 0x81/0x82/0x02 wiring.
        constexpr std::array<UsbHciEndpointDescriptor, 3U> kAlternate {
            {
                {kEvent, kInterrupt},
                {kAclOut, kBulk},
                {kAclIn, kBulk},
            },
        };
        if (!expected(kAlternate.data(), kAlternate.size(),
                      UsbHciEndpointResult::Ok, true))
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        return 0;
    }

    int rejectAmbiguous()
    {
        auto duplicates = kDescriptors;
        duplicates.at(1U).address = kAclOut;
        if (!expected(duplicates.data(), duplicates.size(),
                      UsbHciEndpointResult::Ambiguous, false))
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        auto secondInterrupt = kDescriptors;
        secondInterrupt.at(1U) = {kScoIn, kInterrupt};
        if (!expected(secondInterrupt.data(), secondInterrupt.size(),
                      UsbHciEndpointResult::Ambiguous, false))
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        auto secondBulkOut = kDescriptors;
        secondBulkOut.at(1U) = {kScoOut, kBulk};
        if (!expected(secondBulkOut.data(), secondBulkOut.size(),
                      UsbHciEndpointResult::Ambiguous, false))
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        return 0;
    }

    int rejectMalformed()
    {
        auto invalidAddress = kDescriptors;
        invalidAddress.at(0U).address = 0U;
        if (!expected(invalidAddress.data(), invalidAddress.size(),
                      UsbHciEndpointResult::InvalidDescriptor, false))
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        invalidAddress.at(0U).address = kInvalidAddress;
        if (!expected(invalidAddress.data(), invalidAddress.size(),
                      UsbHciEndpointResult::InvalidDescriptor, false))
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        auto invalidType = kDescriptors;
        invalidType.at(0U).transferType = kInvalidType;
        if (!expected(invalidType.data(), invalidType.size(),
                      UsbHciEndpointResult::InvalidDescriptor, false))
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        auto missing = kDescriptors;
        missing.at(0U).transferType = kControl;
        if (!expected(missing.data(), missing.size(),
                      UsbHciEndpointResult::MissingRequired, false))
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        if (!expected(nullptr, kDescriptors.size(),
                      UsbHciEndpointResult::InvalidArgument, false) ||
            !expected(kDescriptors.data(), 0U,
                      UsbHciEndpointResult::InvalidArgument, false) ||
            !expected(kDescriptors.data(), kOverLimit,
                      UsbHciEndpointResult::InvalidArgument, false))
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        // 32 descriptors are accepted only if every selected HCI role is
        // unique. Duplicates must fail without reading past the input.
        std::array<UsbHciEndpointDescriptor, kLimit> many {};
        for (auto &item : many)
        {
            item = {kAclIn, kBulk};
        }
        if (!expected(many.data(), many.size(), UsbHciEndpointResult::Ambiguous,
                      false))
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        return 0;
    }
} // namespace

int main()
{
    if (const int result = acceptPhysicalEndpoints())
    {
        return result;
    }
    if (const int result = rejectAmbiguous())
    {
        return result;
    }
    return rejectMalformed();
}
