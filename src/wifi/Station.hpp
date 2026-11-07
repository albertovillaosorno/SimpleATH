// SPDX-License-Identifier: AGPL-3.0-only
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
            Failed
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
            NetworkInterfaceNotImplemented
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
                bool hasFunctionalWifi() const
                {
                    return false;
                }

            private:
                StationState state_;
                Bss chosen_;
                Mac stationMac_;
                uint16_t associationId_;
        };

    } // namespace ieee80211
} // namespace simpleath
#endif
