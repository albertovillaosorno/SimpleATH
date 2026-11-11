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
//   - Native driver contracts and implementation for station.
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
//   - Native driver contracts and implementation for station.
// - Description:
//   - Implements or verifies the Station source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for station.

// Software association state machine. No transport or WPA2 crypto installed.
#ifndef SIMPLEATH_WIFI_STATION_HPP
#define SIMPLEATH_WIFI_STATION_HPP

#include "ScanCache.hpp"

namespace simpleath
{
    namespace ieee80211
    {

        enum class StationState : uint8_t
        {
            Inactive,
            Scanning,
            CandidateSelected,
            AuthenticationFramePrepared,
            Authenticated,
            AssociationFramePrepared,
            AssociatedOpen,
            WaitingForWpa2Keys,
            HardwareKeysInstalled,
            Failed,
        };

        enum class StationResult : uint8_t
        {
            Ok,
            InvalidState,
            HardwareNotReady,
            RegulatoryNotReady,
            UnsupportedNetwork,
            FrameRejected,
            AssociationRejected,
            Wpa2CryptoNotImplemented,
            NetworkInterfaceNotImplemented,
        };

        class Wpa2Supplicant;

        class Station
        {
            public:
                Station();
                void reset();
                StationResult enterScanning(bool radioInitialized,
                                            bool countryChannelAllowed);
                // Reject nonviable or inconsistent BSS snapshots even when
                // called without ScanCache as the source of candidates.
                StationResult select(const Mac &station, const Bss &candidate);
                // These only serialize bytes. The future radio backend must
                // safely send them after obtaining the right channel and owning
                // TX buffers.
                Result authenticationRequest(uint16_t sequence, uint8_t *out,
                                             size_t capacity, size_t &written);
                StationResult onAuthenticationResponse(const uint8_t *bytes,
                                                       size_t length);
                Result associationRequest(uint16_t sequence, uint8_t *out,
                                          size_t capacity, size_t &written);
                StationResult onAssociationResponse(const uint8_t *bytes,
                                                    size_t length);
                // A separately verified EAPOL supplicant must install both PTK
                // and GTK before the link enters its keys-installed (NOT
                // network-ready) phase.
                StationResult
                recordInstalledWpa2Keys(const Wpa2Supplicant &supplicant);

                StationState state() const
                {
                    return state_;
                }

                uint16_t associationId() const
                {
                    return associationId_;
                }

                const Bss &candidate() const
                {
                    return chosen_;
                }

                // No crypto engine or macOS network interface is present: do
                // not expose a "connected" success state.
                static bool hasFunctionalWifi()
                {
                    return false;
                }

            private:
                StationState state_ {StationState::Inactive};
                Bss chosen_ {};
                Mac stationMac_ {};
                uint16_t associationId_ {0};
        };

    } // namespace ieee80211
} // namespace simpleath
#endif
