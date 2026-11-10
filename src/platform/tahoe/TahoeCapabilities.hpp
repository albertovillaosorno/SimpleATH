// Native 25G332 card inventory, independent of RF readiness and country policy.
#ifndef SIMPLEATH_TAHOE_CAPABILITIES_HPP
#define SIMPLEATH_TAHOE_CAPABILITIES_HPP

#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    namespace tahoe
    {
        constexpr size_t kNativeCapabilityBytes = 21U;
        constexpr size_t kNativeCapabilityEnvelopeBytes = 0x1cU;

        // WCLDeviceConfiguration::setCardCapbilities copies 0x1c bytes. The
        // compatibility SDK's legacy 11-byte bitmap is not this native ABI.
        struct NativeCapabilities
        {
                uint32_t version;
                uint8_t capabilities[kNativeCapabilityBytes];
                uint8_t reserved[3];
        };

        static_assert(sizeof(NativeCapabilities) ==
                          kNativeCapabilityEnvelopeBytes,
                      "25G332 capability envelope");
        static_assert(offsetof(NativeCapabilities, capabilities) == 4U,
                      "25G332 capability bitmap offset");

        inline NativeCapabilities ar9565Capabilities()
        {
            NativeCapabilities result {};
            result.version = 1;
            // These are API capability positions, not an assertion that the
            // radio is initialized or its controlled data port is open.
            constexpr uint32_t ccmp = 1U << 3U;
            constexpr uint32_t shortSlot = 1U << 1U;
            constexpr uint32_t shortPreamble = 1U << 2U;
            constexpr uint32_t wpa2 = 1U << 6U;
            constexpr uint8_t asynchronousScan = 1U << 6U;
            constexpr uint8_t scanCompletion = 1U << 6U;
            result.capabilities[0] = ccmp;
            result.capabilities[1] = shortSlot | shortPreamble | wpa2;
            result.capabilities[2] = asynchronousScan;
            constexpr size_t scanCompletionByte = 5U;
            result.capabilities[scanCompletionByte] = scanCompletion;
            // WEP/TKIP/WPA1, 5/6 GHz, VHT/HE/EHT, SAE, offloads, and a native
            // AWDL service are not supplied by this inventory. Required AWDL
            // integration remains an open implementation task, never inferred
            // from ordinary station traffic or the presence of a combo chip.
            return result;
        }
    } // namespace tahoe
} // namespace simpleath
#endif
