// SPDX-License-Identifier: AGPL-3.0-only
// Bounded, allocation-free 802.11 BSS discovery cache.
#ifndef SIMPLEATH_WIFI_SCAN_CACHE_HPP
#define SIMPLEATH_WIFI_SCAN_CACHE_HPP

#include "Frames.hpp"

namespace simpleath
{
    namespace ieee80211
    {

        struct Bss
        {
                Beacon beacon;
                int8_t rssiDbm;
                uint64_t lastSeenMs;
                bool occupied;
        };

        // Keep the observation measurements and candidate-selection policy
        // together so callers cannot accidentally swap convertible scalars.
        struct ScanObservation
        {
                size_t frameBytes;
                int8_t rssiDbm;
                uint64_t nowMs;
        };

        struct ScanSelection
        {
                size_t ssidLength;
                uint8_t channel;
                bool permitOpen;
                bool permitWpa2;
        };

        class ScanCache
        {
            public:
                enum : size_t
                {
                    kCapacity = 48,
                };

                ScanCache();
                void clear();
                // Caller must have verified RX descriptor CRC and DMA bounds
                // first. RX frame storage must not overlap this cache.
                Result observe(const uint8_t *frame,
                               const ScanObservation &observation);
                void expire(uint64_t nowMs, uint64_t ttlMs);
                size_t size() const;
                // Returns a defensive copy of the Nth occupied BSS for native
                // scan enumeration. Caller must serialize with
                // observe()/expire()/clear(). Failed lookups clear out,
                // except malformed output aliases with the retained cache.
                bool snapshot(size_t ordinal, Bss &out) const;

                // Only allows Open or WPA2/CCMP PSK, with a visible SSID
                // and 2.4GHz channel. If both security types are permitted,
                // prefer WPA2/CCMP PSK over Open before comparing signal.
                // Invalid/unmeasured RSSI never beats a measured value.
                // Candidates must also share local legacy association rates
                // and must not require an unsupported basic PHY rate.
                // This does NOT check country-specific regulatory policy.
                // A copy of the BSS is returned; no invalidatable pointers.
                // The output cannot overlap the input SSID or this cache.
                bool strongest(const uint8_t *ssid,
                               const ScanSelection &selection, Bss &out) const;
                // Select the exact OS-requested BSSID, not merely the
                // strongest matching SSID. Apply identical security, rate,
                // channel and visible-SSID admission to strongest(). A
                // failed lookup clears out unless output aliases any input
                // or cache storage; no borrowed BSS pointer escapes.
                bool matchingBssid(const Mac &bssid, const uint8_t *ssid,
                                   const ScanSelection &selection,
                                   Bss &out) const;

            private:
                Bss entries_[kCapacity] {};
        };

    } // namespace ieee80211
} // namespace simpleath
#endif
