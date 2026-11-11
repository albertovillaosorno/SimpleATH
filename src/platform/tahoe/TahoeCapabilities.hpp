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
//   - Native driver contracts and implementation for tahoe capabilities.
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
//   - Native driver contracts and implementation for tahoe capabilities.
// - Description:
//   - Implements or verifies the TahoeCapabilities source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for tahoe capabilities.

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
        constexpr size_t kNativeStationStatusBytes = 8U;

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

        // Exact compatibility-SDK envelopes for GET POWERSAVE (0x0eb0)
        // and NSS (0x0fe0). The modern Tahoe slots consume these same
        // fixed-sized fields; the native source asserts both SDK layouts.
        // A disabled power-save mode describes actual unimplemented chipset
        // sleep scheduling, NOT the independently controlled radio power.
        struct NativePowerSaveStatus
        {
                uint32_t version;
                uint32_t powersaveLevel;
        };

        struct NativeNssStatus
        {
                uint32_t version;
                uint8_t streams;
                uint8_t reserved[3];
        };

        static_assert(sizeof(NativePowerSaveStatus) ==
                          kNativeStationStatusBytes,
                      "native power-save status size");
        static_assert(sizeof(NativeNssStatus) == kNativeStationStatusBytes,
                      "native NSS status size");
        static_assert(offsetof(NativeNssStatus, streams) == 4U,
                      "native NSS field offset");

        inline NativePowerSaveStatus ar9565PowerSaveStatus()
        {
            // APPLE80211_POWERSAVE_MODE_DISABLED == 0. The current driver
            // does not implement AP TIM/DTIM listen/sleep transitions.
            return {1U, 0U};
        }

        inline NativeNssStatus ar9565NssStatus()
        {
            // AR9565 PCI 168c:0036 has one transmit and one receive chain;
            // neither a powered-down radio nor an unassociated station is a
            // second spatial stream.
            return {1U, 1U, {0U, 0U, 0U}};
        }

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
