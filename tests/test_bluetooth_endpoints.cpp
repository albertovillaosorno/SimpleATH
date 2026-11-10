// Synthetic USB endpoint topology tests; no real USB device or kext loaded.
#include "bluetooth/Ath3kUsb.hpp"
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
    constexpr uint8_t kChangedEvent = 0x81U;
    constexpr uint8_t kChangedAclIn = 0x82U;
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

    int rejectAliasedOutputAt(size_t offset)
    {
        // Deliberately invalid caller: the result points into borrowed USB
        // descriptor storage. The selector must reject it before any access
        // through the output reference, keeping every descriptor unchanged.
        auto descriptors = kDescriptors;
        const auto *const borrowed = &descriptors.at(offset);
        UsbHciEndpoints *output = nullptr;
        static_assert(sizeof(UsbHciEndpoints *) ==
                          sizeof(const UsbHciEndpointDescriptor *),
                      "USB fixture pointers must share an address width");
        __builtin_memcpy(static_cast<void *>(&output),
                         static_cast<const void *>(&borrowed),
                         sizeof(UsbHciEndpoints *));
        if (selectUsbHciEndpoints(descriptors.data(), descriptors.size(),
                                  *output) !=
            UsbHciEndpointResult::InvalidArgument)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        for (size_t index = 0U; index < descriptors.size(); ++index)
        {
            if (descriptors.at(index).address !=
                    kDescriptors.at(index).address ||
                descriptors.at(index).transferType !=
                    kDescriptors.at(index).transferType)
            {
                return (__LINE__ % kDiagnosticModulo) + 1;
            }
        }
        return 0;
    }

    int verifyPhysicalHciIdentity()
    {
        // All matching is based on USB VID/PID/bcdDevice and interface
        // number, never on the WLAN function's independent PCI 168c:0036.
        constexpr Ath3kUsbIdentity kAr3012 {0x0cf3U, 0x0036U, 2U, 0U};
        constexpr Ath3kUsbIdentity kAdditional {0x0489U, 0xe04dU, 3U, 0U};
        constexpr Ath3kUsbIdentity kLatestAdditional {0x13d3U, 0x3487U, 2U, 0U};
        if (!isSupportedAth3kHciIdentity(kAr3012) ||
            !isSupportedAth3kHciIdentity(kAdditional) ||
            !isSupportedAth3kHciIdentity(kLatestAdditional))
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        // The same VID/PID still in ATH3K bootstrap mode must not become an
        // HCI owner; unrelated controllers and nonzero interfaces fail too.
        constexpr Ath3kUsbIdentity kBoot {0x0cf3U, 0x0036U, 1U, 0U};
        constexpr Ath3kUsbIdentity kUnrelated {0x8087U, 0x0026U, 2U, 0U};
        constexpr Ath3kUsbIdentity kWrongInterface {0x0cf3U, 0x0036U, 2U, 1U};
        constexpr Ath3kUsbIdentity kLegacy3011 {0x0cf3U, 0x3000U, 2U, 0U};
        constexpr Ath3kUsbIdentity kIgnoredAtheros {0x0489U, 0xe02cU, 2U, 0U};
        if (isSupportedAth3kHciIdentity(kBoot) ||
            isSupportedAth3kHciIdentity(kUnrelated) ||
            isSupportedAth3kHciIdentity(kWrongInterface) ||
            isSupportedAth3kHciIdentity(kLegacy3011) ||
            isSupportedAth3kHciIdentity(kIgnoredAtheros))
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        return 0;
    }

    int rejectChangedActiveSetting()
    {
        constexpr UsbHciInterfaceTopology kOpened {
            1U,
            0U,
            {kEvent, kAclIn, kAclOut},
        };
        if (!sameUsbHciInterfaceTopology(kOpened, kOpened))
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        // Alternate setting changes invalidate existing IOUSBHostPipe
        // leases even when the new setting reuses identical endpoints.
        auto changed = kOpened;
        changed.alternateSetting = 1U;
        if (sameUsbHciInterfaceTopology(kOpened, changed))
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        changed = kOpened;
        changed.configurationValue = 2U;
        if (sameUsbHciInterfaceTopology(kOpened, changed))
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        changed = kOpened;
        changed.endpoints.eventInterruptIn = kChangedEvent;
        if (sameUsbHciInterfaceTopology(kOpened, changed))
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        changed = kOpened;
        changed.endpoints.aclBulkIn = kChangedAclIn;
        if (sameUsbHciInterfaceTopology(kOpened, changed))
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        changed = kOpened;
        changed.endpoints.aclBulkOut = 0x02U;
        if (sameUsbHciInterfaceTopology(kOpened, changed))
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        changed = kOpened;
        changed.configurationValue = 0U;
        if (sameUsbHciInterfaceTopology(changed, changed))
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        changed = kOpened;
        changed.endpoints.aclBulkOut = 0U;
        if (sameUsbHciInterfaceTopology(changed, changed))
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
    if (const int result = rejectMalformed())
    {
        return result;
    }
    if (const int result = rejectAliasedOutputAt(0U))
    {
        return result;
    }
    if (const int result = rejectAliasedOutputAt(2U))
    {
        return result;
    }
    if (const int result = rejectChangedActiveSetting())
    {
        return result;
    }
    return verifyPhysicalHciIdentity();
}
