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
//   - Native driver contracts and implementation for native port security
//     admission.
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
//   - Native driver contracts and implementation for native port security
//     admission.
// - Description:
//   - Implements or verifies the NativePortSecurityAdmission source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: native port security admission.

// Native controlled-port security policy. Physical RF/DMA, exact join, AP
// beacon and country/TPC authorization are independent mandatory gates.
#ifndef SIMPLEATH_WIFI_NATIVE_PORT_SECURITY_ADMISSION_HPP
#define SIMPLEATH_WIFI_NATIVE_PORT_SECURITY_ADMISSION_HPP

#include "Station.hpp"

namespace simpleath
{
    namespace ieee80211
    {
        struct NativePortSecurityEvidence
        {
                Security selectedSecurity {Security::UnsupportedRsn};
                StationState station {StationState::Inactive};
                bool osSupplicantOwnsWpa2 {};
                bool hardwareKeyOwnerMatches {};
                bool hardwareKeyRequiresReset {};
                bool hardwarePairwiseInstalled {};
                bool hardwareGroupInstalled {};
                bool softwarePairwiseTxInstalled {};
                bool softwarePairwiseRxInstalled {};
                bool softwareGroupRxInstalled {};
                bool pairwiseKeyRevoked {};
                bool m4TransmitConfirmed {};
                bool authenticatedProtectedRxObserved {};
        };

        struct NativeM4CompletionEvidence
        {
                uint64_t completedToken {};
                uint64_t pendingToken {};
                uint64_t joinEpoch {};
                uint64_t radioEpoch {};
                uint64_t hardwareKeyEpoch {};
                StationState station {StationState::Inactive};
                bool frameTransmitOk {};
                bool excessiveRetries {};
                bool filtered {};
        };

        // TX completion identity must survive a different packet, a new join
        // or a PCI/key epoch change. TX success alone never proves a WPA2
        // link: controlled-port policy also requires CCMP-verified RX.
        inline bool
        nativeM4TransmitCompleted(const NativeM4CompletionEvidence &evidence)
        {
            return evidence.completedToken != 0 &&
                   evidence.completedToken == evidence.pendingToken &&
                   evidence.radioEpoch != 0 &&
                   evidence.joinEpoch == evidence.radioEpoch &&
                   evidence.hardwareKeyEpoch == evidence.radioEpoch &&
                   evidence.station == StationState::HardwareKeysInstalled &&
                   evidence.frameTransmitOk && !evidence.excessiveRetries &&
                   !evidence.filtered;
        }

        // A key install or WPA2 association alone cannot open the data port.
        // Native connect selects the driver-owned PSK supplicant; an unrelated
        // OS-owned key callback must never satisfy that security lifetime.
        // The owner must ALSO verify an actual same-epoch radio, authorized
        // channel, post-association AP beacon and strict transmit policy.
        inline bool nativeControlledPortSecurityReady(
            const NativePortSecurityEvidence &evidence)
        {
            if (evidence.pairwiseKeyRevoked ||
                evidence.hardwareKeyRequiresReset ||
                evidence.osSupplicantOwnsWpa2 ||
                !evidence.hardwareKeyOwnerMatches)
            {
                return false;
            }
            if (evidence.selectedSecurity == Security::Open)
            {
                return evidence.station == StationState::AssociatedOpen &&
                       !evidence.hardwarePairwiseInstalled &&
                       !evidence.hardwareGroupInstalled &&
                       !evidence.softwarePairwiseTxInstalled &&
                       !evidence.softwarePairwiseRxInstalled &&
                       !evidence.softwareGroupRxInstalled;
            }
            if (evidence.selectedSecurity == Security::Wpa2Personal)
            {
                return evidence.station ==
                           StationState::HardwareKeysInstalled &&
                       evidence.hardwarePairwiseInstalled &&
                       evidence.hardwareGroupInstalled &&
                       evidence.softwarePairwiseTxInstalled &&
                       evidence.softwarePairwiseRxInstalled &&
                       evidence.softwareGroupRxInstalled &&
                       evidence.m4TransmitConfirmed &&
                       evidence.authenticatedProtectedRxObserved;
            }
            return false;
        }
    } // namespace ieee80211
} // namespace simpleath

#endif
