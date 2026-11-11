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
//   - Native driver contracts and implementation for tahoe apple80211 values.
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
//   - Native driver contracts and implementation for tahoe apple80211 values.
// - Description:
//   - Implements or verifies the TahoeApple80211Values source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: tahoe apple80211 values.

// Minimal value layouts for selected Tahoe IO80211/WCL controller requests.
// Apple omits its private apple80211_{var,ioctl}.h headers from the native
// macOS SDK. These independent declarations describe only the fixed request
// payloads actually consumed here; they do not import a legacy controller,
// ioctl dispatch table, or any downloaded research header into a kext.
// Layouts/values were checked against the pinned historical Apple80211 ABI
// reference and must still be verified against the exact Tahoe binary ABI.
#ifndef SIMPLEATH_TAHOE_APPLE80211_VALUES_HPP
#define SIMPLEATH_TAHOE_APPLE80211_VALUES_HPP

#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    namespace tahoe
    {
        constexpr uint32_t kApple80211Version = 1U;
        constexpr uint32_t kApple80211PowerOff = 0U;
        constexpr uint32_t kApple80211PowerOn = 1U;
        constexpr uint32_t kApple80211StationMode = 1U;
        constexpr uint32_t kApple80211StateInit = 0U;
        constexpr uint32_t kApple80211StateRun = 4U;
        constexpr uint32_t kApple80211Channel20Mhz = 0x02U;
        constexpr uint32_t kApple80211Channel2Ghz = 0x08U;
        constexpr uint32_t kApple80211RssiDbm = 0U;
        constexpr uint32_t kApple80211PowerSaveDisabled = 0U;

        constexpr size_t kApple80211MaxRadioChains = 4U;
        constexpr size_t kApple80211MaxVersionBytes = 256U;
        constexpr size_t kApple80211CountryCodeBytes = 3U;

        struct NativeApple80211Version
        {
                uint32_t version;
                uint16_t stringLength;
                char string[kApple80211MaxVersionBytes];
        };

        struct NativeApple80211Power
        {
                uint32_t version;
                uint32_t numRadios;
                uint32_t powerState[kApple80211MaxRadioChains];
        };

        struct NativeApple80211Country
        {
                uint32_t version;
                uint8_t countryCode[kApple80211CountryCodeBytes];
        };

        struct NativeApple80211ChannelInfo
        {
                uint32_t version;
                uint32_t channel;
                uint32_t flags;
        };

        struct NativeApple80211Channel
        {
                uint32_t version;
                NativeApple80211ChannelInfo channel;
        };

        struct NativeApple80211StationMode
        {
                uint32_t version;
                uint32_t mode;
        };

        struct NativeApple80211Rssi
        {
                uint32_t version;
                uint32_t numRadios;
                uint32_t unit;
                int32_t radio[kApple80211MaxRadioChains];
                int32_t aggregate;
                int32_t extension[kApple80211MaxRadioChains];
                int32_t aggregateExtension;
        };

        struct NativeApple80211PowerSave
        {
                uint32_t version;
                uint32_t level;
        };

        struct NativeApple80211Nss
        {
                uint32_t version;
                uint8_t streams;
                uint8_t reserved[3];
        };

        static_assert(sizeof(NativeApple80211Version) == 264U &&
                          offsetof(NativeApple80211Version, string) == 6U,
                      "native Apple80211 version request ABI");
        static_assert(sizeof(NativeApple80211Power) == 24U &&
                          offsetof(NativeApple80211Power, powerState) == 8U,
                      "native Apple80211 power request ABI");
        static_assert(sizeof(NativeApple80211Country) == 8U &&
                          offsetof(NativeApple80211Country, countryCode) == 4U,
                      "native Apple80211 country request ABI");
        static_assert(sizeof(NativeApple80211Channel) == 16U &&
                          offsetof(NativeApple80211Channel, channel) == 4U,
                      "native Apple80211 channel request ABI");
        static_assert(sizeof(NativeApple80211StationMode) == 8U &&
                          sizeof(NativeApple80211PowerSave) == 8U &&
                          sizeof(NativeApple80211Nss) == 8U,
                      "native Apple80211 fixed scalar request ABI");
        static_assert(sizeof(NativeApple80211Rssi) == 52U &&
                          offsetof(NativeApple80211Rssi, aggregate) == 28U &&
                          offsetof(NativeApple80211Rssi, aggregateExtension) ==
                              48U,
                      "native Apple80211 RSSI request ABI");
    } // namespace tahoe
} // namespace simpleath
#endif
