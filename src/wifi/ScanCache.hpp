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

        class ScanCache
        {
            public:
                enum : size_t
                {
                    kCapacity = 48
                };

                ScanCache();
                void clear();
                // Caller must have verified RX descriptor CRC and DMA bounds
                // first. RX frame storage must not overlap this cache.
                Result observe(const uint8_t *frame, size_t length,
                               int8_t rssiDbm, uint64_t nowMs);
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
                bool strongest(const uint8_t *ssid, size_t ssidLength,
                               uint8_t channel, bool permitOpen,
                               bool permitWpa2, Bss &out) const;

            private:
                Bss entries_[kCapacity];
        };

    } // namespace ieee80211
} // namespace simpleath
#endif
