// SPDX-License-Identifier: AGPL-3.0-only
#include "ScanCache.hpp"

namespace simpleath
{
    namespace ieee80211
    {
        namespace
        {
            bool overlaps(const void *a, size_t aBytes, const void *b,
                          size_t bBytes)
            {
                if (!a || !b || !aBytes || !bBytes)
                    return false;
                const auto first = reinterpret_cast<uintptr_t>(a);
                const auto second = reinterpret_cast<uintptr_t>(b);
                return first <= second ? second - first < aBytes
                                       : first - second < bBytes;
            }

            bool sameSecurityAdvertisement(const Beacon &left,
                                           const Beacon &right)
            {
                if (left.channel != right.channel ||
                    left.rsn.security != right.rsn.security ||
                    ((left.capabilities ^ right.capabilities) & 0x0010u) != 0 ||
                    left.rsnIeLength != right.rsnIeLength ||
                    left.rsnIeLength > sizeof(left.rsnIe))
                    return false;
                for (size_t i = 0; i < left.rsnIeLength; ++i)
                    if (left.rsnIe[i] != right.rsnIe[i])
                        return false;
                return true;
            }

            bool measuredRssi(int8_t rssiDbm)
            {
                return rssiDbm < 0 && rssiDbm >= -127;
            }
        } // namespace

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
            // RX bytes must be borrowed from a disjoint DMA/frame allocation;
            // a forged source within the cache could change while updating it.
            if (overlaps(frame, length, this, sizeof(*this)))
                return Result::InvalidFrame;
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
                // A delayed RX callback must not rewind any cached clock or
                // evict a newer BSSID on the strength of an older sample.
                // Check all occupied entries, including those after a match.
                if (nowMs < entries_[i].lastSeenMs)
                    return Result::InvalidFrame;
                if (sameMac(entries_[i].beacon.bssid, beacon.bssid))
                {
                    slot = i;
                    continue;
                }
                const uint64_t age = nowMs - entries_[i].lastSeenMs;
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

            // Retain a previously visible probe-response name only when the
            // exact same BSSID advertises a hidden SSID with unchanged channel
            // and security. A full-cache eviction may reuse an occupied slot
            // for a different BSSID, which must never inherit the old SSID.
            if (entries_[slot].occupied && beacon.hiddenSsid &&
                sameMac(entries_[slot].beacon.bssid, beacon.bssid) &&
                !entries_[slot].beacon.hiddenSsid &&
                sameSecurityAdvertisement(beacon, entries_[slot].beacon))
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
            // Failed lookups normally clear stale output, but an alias to an
            // owned cache entry must not erase its live BSS first.
            if (overlaps(&out, sizeof(out), this, sizeof(*this)))
                return false;
            out = {};
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
            // Caller-owned output cannot alias the search SSID or the live
            // cache. Even an invalid lookup must not erase borrowed bytes.
            if (overlaps(&out, sizeof(out), this, sizeof(*this)) ||
                overlaps(&out, sizeof(out), ssid, ssidLength) ||
                overlaps(ssid, ssidLength, this, sizeof(*this)))
                return false;
            if (ssidLength > 32 || (ssidLength != 0 && !ssid))
            {
                out = {};
                return false;
            }
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
                const bool candidateMeasured = measuredRssi(candidate.rssiDbm);
                const bool bestMeasured = measuredRssi(best.rssiDbm);
                // Unknown/invalid RSSI must not outrank an actual measured
                // signal. Both unmeasured: retain deterministic first entry.
                const bool betterSignal =
                    (candidateMeasured && !bestMeasured) ||
                    (candidateMeasured && bestMeasured &&
                     candidate.rssiDbm > best.rssiDbm);
                if (!found || (secureCandidate && !secureBest) ||
                    (secureCandidate == secureBest && betterSignal))
                {
                    found = true;
                    best = candidate;
                }
            }
            if (found)
                out = best;
            else
                out = {};
            return found;
        }

    } // namespace ieee80211
} // namespace simpleath
