#include "ScanCache.hpp"
#include "wifi/Frames.hpp"
#include <cstddef>
#include <cstdint>

namespace simpleath
{
    namespace ieee80211
    {
        namespace
        {
            constexpr uint16_t kPrivacyCapabilityMask = 0x0010U;
            constexpr int8_t kLowestMeasuredRssiDbm = -127;

            template <typename T, size_t N>
            T &boundedElement(T (&items)[N], size_t index)
            {
                for (T &element : items)
                {
                    if (index == 0)
                    {
                        return element;
                    }
                    --index;
                }
                __builtin_trap();
            }

            uintptr_t pointerAddress(const void *pointer)
            {
                static_assert(sizeof(uintptr_t) == sizeof(pointer),
                              "cache host pointer width must fit uintptr_t");
                uintptr_t address = 0;
                __builtin_memcpy(&address, static_cast<const void *>(&pointer),
                                 sizeof(pointer));
                return address;
            }

            bool overlaps(const void *a, size_t aBytes, const void *b,
                          size_t bBytes)
            {
                if ((a == nullptr) || (b == nullptr) || (aBytes == 0U) ||
                    (bBytes == 0U))
                {
                    return false;
                }
                const auto first = pointerAddress(a);
                const auto second = pointerAddress(b);
                return first <= second ? second - first < aBytes
                                       : first - second < bBytes;
            }

            bool sameSecurityAdvertisement(const Beacon &left,
                                           const Beacon &right)
            {
                if (left.channel != right.channel ||
                    left.rsn.security != right.rsn.security ||
                    ((static_cast<uint32_t>(left.capabilities) ^
                      static_cast<uint32_t>(right.capabilities)) &
                     kPrivacyCapabilityMask) != 0 ||
                    left.rsnIeLength != right.rsnIeLength ||
                    left.rsnIeLength > sizeof(left.rsnIe))
                {
                    return false;
                }
                return __builtin_memcmp(&left.rsnIe[0], &right.rsnIe[0],
                                        left.rsnIeLength) == 0;
            }

            bool measuredRssi(int8_t rssiDbm)
            {
                return rssiDbm < 0 && rssiDbm >= kLowestMeasuredRssiDbm;
            }
        } // namespace

        ScanCache::ScanCache() = default;

        void ScanCache::clear()
        {
            for (auto &entrie : entries_)
            {
                entrie = {};
            }
        }

        Result ScanCache::observe(const uint8_t *frame,
                                  const ScanObservation &observation)
        {
            const size_t length = observation.frameBytes;
            const int8_t rssiDbm = observation.rssiDbm;
            const uint64_t nowMs = observation.nowMs;
            // RX bytes must be borrowed from a disjoint DMA/frame allocation;
            // a forged source within the cache could change while updating it.
            if (overlaps(frame, length, this, sizeof(*this)))
            {
                return Result::InvalidFrame;
            }
            Beacon beacon {};
            const Result result = parseBeacon(frame, length, beacon);
            if (result != Result::Ok)
            {
                return result;
            }
            if (!beacon.infrastructure || beacon.intervalTu == 0)
            {
                return Result::InvalidFrame;
            }

            size_t slot = kCapacity;
            size_t freeSlot = kCapacity;
            size_t oldestSlot = kCapacity;
            uint64_t oldest = 0;
            size_t nextIndex = 0;
            for (const Bss &entry : entries_)
            {
                const size_t i = nextIndex++;
                if (!entry.occupied)
                {
                    if (freeSlot == kCapacity)
                    {
                        freeSlot = i;
                    }
                    continue;
                }
                // A delayed RX callback must not rewind any cached clock or
                // evict a newer BSSID on the strength of an older sample.
                // Check all occupied entries, including those after a match.
                if (nowMs < entry.lastSeenMs)
                {
                    return Result::InvalidFrame;
                }
                if (sameMac(entry.beacon.bssid, beacon.bssid))
                {
                    slot = i;
                    continue;
                }
                const uint64_t age = nowMs - entry.lastSeenMs;
                if (oldestSlot == kCapacity || age > oldest)
                {
                    oldestSlot = i;
                    oldest = age;
                }
            }
            if (slot == kCapacity)
            {
                slot = freeSlot != kCapacity ? freeSlot : oldestSlot;
            }
            if (slot == kCapacity)
            {
                return Result::InvalidFrame;
            }

            // Retain a previously visible probe-response name only when the
            // exact same BSSID advertises a hidden SSID with unchanged channel
            // and security. A full-cache eviction may reuse an occupied slot
            // for a different BSSID, which must never inherit the old SSID.
            Bss &destination = boundedElement(entries_, slot);
            if (destination.occupied && beacon.hiddenSsid &&
                sameMac(destination.beacon.bssid, beacon.bssid) &&
                !destination.beacon.hiddenSsid &&
                sameSecurityAdvertisement(beacon, destination.beacon))
            {
                beacon.ssidLength = destination.beacon.ssidLength;
                beacon.hiddenSsid = false;
                __builtin_memcpy(&beacon.ssid[0], &destination.beacon.ssid[0],
                                 beacon.ssidLength);
            }
            destination.beacon = beacon;
            destination.rssiDbm = rssiDbm;
            destination.lastSeenMs = nowMs;
            destination.occupied = true;
            return Result::Ok;
        }

        void ScanCache::expire(uint64_t nowMs, uint64_t ttlMs)
        {
            for (auto &entrie : entries_)
            {
                if (!entrie.occupied)
                {
                    continue;
                }
                if (nowMs < entrie.lastSeenMs ||
                    nowMs - entrie.lastSeenMs > ttlMs)
                {
                    entrie = {};
                }
            }
        }

        size_t ScanCache::size() const
        {
            size_t count = 0;
            for (const auto &entrie : entries_)
            {
                if (entrie.occupied)
                {
                    ++count;
                }
            }
            return count;
        }

        bool ScanCache::snapshot(size_t ordinal, Bss &out) const
        {
            // Failed lookups normally clear stale output, but an alias to an
            // owned cache entry must not erase its live BSS first.
            if (overlaps(&out, sizeof(out), this, sizeof(*this)))
            {
                return false;
            }
            out = {};
            if (ordinal >= kCapacity)
            {
                return false;
            }
            size_t occupied = 0;
            for (const auto &entrie : entries_)
            {
                if (!entrie.occupied)
                {
                    continue;
                }
                if (occupied == ordinal)
                {
                    out = entrie;
                    return true;
                }
                ++occupied;
            }
            return false;
        }

        static bool eligibleForSelection(const Bss &candidate,
                                         const uint8_t *ssid,
                                         const ScanSelection &selection)
        {
            const size_t ssidLength = selection.ssidLength;
            if (!candidate.occupied || candidate.beacon.hiddenSsid ||
                candidate.beacon.channel == 0 ||
                (selection.channel != 0 &&
                 candidate.beacon.channel != selection.channel))
            {
                return false;
            }
            const Security security = candidate.beacon.rsn.security;
            if (security == Security::Open && !selection.permitOpen)
            {
                return false;
            }
            if (security == Security::Wpa2Personal &&
                (!selection.permitWpa2 || !candidate.beacon.rsn.groupCcmp))
            {
                return false;
            }
            if (security != Security::Open &&
                security != Security::Wpa2Personal)
            {
                return false;
            }
            // Rank only BSSes whose mandatory basic rates this PHY can
            // honor and which have at least one common association rate.
            // Otherwise a stronger unjoinable BSSID can mask a weaker
            // compatible AP with the same SSID and security policy.
            if (associationRequestLength(candidate.beacon) == 0)
            {
                return false;
            }
            if (ssidLength != 0)
            {
                if (candidate.beacon.ssidLength != ssidLength)
                {
                    return false;
                }
                if (__builtin_memcmp(&candidate.beacon.ssid[0], ssid,
                                     ssidLength) != 0)
                {
                    return false;
                }
            }
            return true;
        }

        bool ScanCache::matchingBssid(const Mac &bssid, const uint8_t *ssid,
                                      const ScanSelection &selection,
                                      Bss &out) const
        {
            const size_t ssidLength = selection.ssidLength;
            if (overlaps(&out, sizeof(out), this, sizeof(*this)) ||
                overlaps(&out, sizeof(out), &bssid, sizeof(bssid)) ||
                overlaps(&out, sizeof(out), ssid, ssidLength) ||
                overlaps(&bssid, sizeof(bssid), this, sizeof(*this)) ||
                overlaps(ssid, ssidLength, this, sizeof(*this)))
            {
                return false;
            }
            if (!validStationMac(bssid) || ssidLength == 0 ||
                ssidLength > kMaxSsidBytes || ssid == nullptr)
            {
                out = {};
                return false;
            }
            for (const Bss &candidate : entries_)
            {
                if (sameMac(candidate.beacon.bssid, bssid) &&
                    eligibleForSelection(candidate, ssid, selection))
                {
                    out = candidate;
                    return true;
                }
            }
            out = {};
            return false;
        }

        bool ScanCache::strongest(const uint8_t *ssid,
                                  const ScanSelection &selection,
                                  Bss &out) const
        {
            const size_t ssidLength = selection.ssidLength;
            // Caller-owned output cannot alias the search SSID or the live
            // cache. Even an invalid lookup must not erase borrowed bytes.
            if (overlaps(&out, sizeof(out), this, sizeof(*this)) ||
                overlaps(&out, sizeof(out), ssid, ssidLength) ||
                overlaps(ssid, ssidLength, this, sizeof(*this)))
            {
                return false;
            }
            if (ssidLength > kMaxSsidBytes ||
                (ssidLength != 0 && (ssid == nullptr)))
            {
                out = {};
                return false;
            }
            bool found = false;
            Bss best {};
            for (const auto &candidate : entries_)
            {
                if (!eligibleForSelection(candidate, ssid, selection))
                {
                    continue;
                }
                const Security security = candidate.beacon.rsn.security;
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
            {
                out = best;
            }
            else
            {
                out = {};
            }
            return found;
        }

    } // namespace ieee80211
} // namespace simpleath
