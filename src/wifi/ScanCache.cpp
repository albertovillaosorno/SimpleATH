// SPDX-License-Identifier: AGPL-3.0-only
#include "ScanCache.hpp"

namespace simpleath
{
    namespace ieee80211
    {

        ScanCache::ScanCache() : entries_ {}
        {
        }

        void ScanCache::clear()
        {
            for (size_t i = 0; i < kCapacity; ++i)
                entries_[i] = {};
        }

        Result ScanCache::observe(const uint8_t *frame, size_t length,
                                  int8_t rssiDbm, uint64_t nowMs)
        {
            Beacon beacon {};
            const Result result = parseBeacon(frame, length, beacon);
            if (result != Result::Ok)
                return result;
            if (!beacon.infrastructure || beacon.intervalTu == 0)
                return Result::InvalidFrame;

            size_t slot = kCapacity;
            size_t freeSlot = kCapacity;
            size_t oldestSlot = kCapacity;
            uint64_t oldest = 0;
            for (size_t i = 0; i < kCapacity; ++i)
            {
                if (!entries_[i].occupied)
                {
                    if (freeSlot == kCapacity)
                        freeSlot = i;
                    continue;
                }
                if (sameMac(entries_[i].beacon.bssid, beacon.bssid))
                {
                    slot = i;
                    break;
                }
                const uint64_t age = nowMs >= entries_[i].lastSeenMs
                                         ? nowMs - entries_[i].lastSeenMs
                                         : 0;
                if (oldestSlot == kCapacity || age > oldest)
                {
                    oldestSlot = i;
                    oldest = age;
                }
            }
            if (slot == kCapacity)
                slot = freeSlot != kCapacity ? freeSlot : oldestSlot;
            if (slot == kCapacity)
                return Result::InvalidFrame;

            // Hidden beacon SSIDs must not erase a previously observed visible
            // probe-response name for the same BSSID.
            if (entries_[slot].occupied && beacon.hiddenSsid &&
                !entries_[slot].beacon.hiddenSsid)
            {
                beacon.ssidLength = entries_[slot].beacon.ssidLength;
                beacon.hiddenSsid = false;
                for (size_t i = 0; i < beacon.ssidLength; ++i)
                    beacon.ssid[i] = entries_[slot].beacon.ssid[i];
            }
            entries_[slot].beacon = beacon;
            entries_[slot].rssiDbm = rssiDbm;
            entries_[slot].lastSeenMs = nowMs;
            entries_[slot].occupied = true;
            return Result::Ok;
        }

        void ScanCache::expire(uint64_t nowMs, uint64_t ttlMs)
        {
            for (size_t i = 0; i < kCapacity; ++i)
            {
                if (!entries_[i].occupied)
                    continue;
                if (nowMs < entries_[i].lastSeenMs ||
                    nowMs - entries_[i].lastSeenMs > ttlMs)
                    entries_[i] = {};
            }
        }

        size_t ScanCache::size() const
        {
            size_t count = 0;
            for (size_t i = 0; i < kCapacity; ++i)
                if (entries_[i].occupied)
                    ++count;
            return count;
        }

        bool ScanCache::snapshot(size_t ordinal, Bss &out) const
        {
            if (ordinal >= kCapacity)
                return false;
            size_t occupied = 0;
            for (size_t i = 0; i < kCapacity; ++i)
            {
                if (!entries_[i].occupied)
                    continue;
                if (occupied == ordinal)
                {
                    out = entries_[i];
                    return true;
                }
                ++occupied;
            }
            return false;
        }

        bool ScanCache::strongest(const uint8_t *ssid, size_t ssidLength,
                                  uint8_t channel, bool permitOpen,
                                  bool permitWpa2, Bss &out) const
        {
            if (ssidLength > 32 || (ssidLength != 0 && !ssid))
                return false;
            bool found = false;
            Bss best {};
            for (size_t i = 0; i < kCapacity; ++i)
            {
                const Bss &candidate = entries_[i];
                if (!candidate.occupied || candidate.beacon.hiddenSsid ||
                    candidate.beacon.channel == 0 ||
                    (channel != 0 && candidate.beacon.channel != channel))
                    continue;
                const Security security = candidate.beacon.rsn.security;
                if (security == Security::Open && !permitOpen)
                    continue;
                if (security == Security::Wpa2Personal &&
                    (!permitWpa2 || !candidate.beacon.rsn.groupCcmp))
                    continue;
                if (security != Security::Open &&
                    security != Security::Wpa2Personal)
                    continue;
                if (ssidLength != 0)
                {
                    if (candidate.beacon.ssidLength != ssidLength)
                        continue;
                    uint8_t difference = 0;
                    for (size_t j = 0; j < ssidLength; ++j)
                        difference |= candidate.beacon.ssid[j] ^ ssid[j];
                    if (difference != 0)
                        continue;
                }
                // Never prefer a stronger Open BSS over compatible WPA2
                // solely because both policies were explicitly allowed.
                // RSSI is only the tiebreaker within a security class.
                const bool secureCandidate = security == Security::Wpa2Personal;
                const bool secureBest =
                    found && best.beacon.rsn.security == Security::Wpa2Personal;
                if (!found || (secureCandidate && !secureBest) ||
                    (secureCandidate == secureBest &&
                     candidate.rssiDbm > best.rssiDbm))
                {
                    found = true;
                    best = candidate;
                }
            }
            if (found)
                out = best;
            return found;
        }

    } // namespace ieee80211
} // namespace simpleath
