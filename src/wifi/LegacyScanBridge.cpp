// SPDX-License-Identifier: AGPL-3.0-only
#include "LegacyScanBridge.hpp"
#include "Frames.hpp"
#include "ScanCache.hpp"

#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    namespace ieee80211
    {
        namespace
        {
            constexpr uint8_t kHighest2GhzChannel = 14;
            constexpr int8_t kMinMeasuredRssiDbm = -127;

            template <size_t DestinationSize, size_t SourceSize>
            void copyBytes(uint8_t (&dest)[DestinationSize],
                           const uint8_t (&src)[SourceSize], size_t size)
            {
                // The caller validates the BSS lengths before copying.
                for (size_t i = 0;
                     i < size && i < DestinationSize && i < SourceSize; ++i)
                {
                    dest[i] = src[i];
                }
            }

            bool overlapsStorage(const void *a, size_t aBytes, const void *b,
                                 size_t bBytes)
            {
                const auto first = reinterpret_cast<uintptr_t>(a);
                const auto second = reinterpret_cast<uintptr_t>(b);
                return aBytes != 0 && bBytes != 0 &&
                       (first >= second ? first - second < bBytes
                                        : second - first < aBytes);
            }

            bool accepted(const Bss &bss)
            {
                const Beacon &beacon = bss.beacon;
                if (!bss.occupied || !validStationMac(beacon.bssid) ||
                    beacon.hiddenSsid || beacon.ssidLength == 0 ||
                    beacon.ssidLength > sizeof(beacon.ssid) ||
                    beacon.channel == 0 ||
                    beacon.channel > kHighest2GhzChannel ||
                    !beacon.infrastructure || beacon.intervalTu == 0)
                {
                    return false;
                }
                if (beacon.rateCount > sizeof(beacon.rates) ||
                    beacon.rsnIeLength > sizeof(beacon.rsnIe))
                {
                    return false;
                }
                return true;
            }

            NativeBssSnapshot copyBss(const Bss &bss)
            {
                const Beacon &beacon = bss.beacon;
                NativeBssSnapshot out {};
                out.bssid = beacon.bssid;
                out.ssidLength = beacon.ssidLength;
                copyBytes(out.ssid, beacon.ssid, out.ssidLength);
                out.channel = beacon.channel;
                out.capabilities = beacon.capabilities;
                out.beaconIntervalTu = beacon.intervalTu;
                out.rateCount = beacon.rateCount;
                copyBytes(out.rates, beacon.rates, out.rateCount);
                out.rsnIeLength = beacon.rsnIeLength;
                copyBytes(out.rsnInformationElement, beacon.rsnIe,
                          out.rsnIeLength);
                out.signalMeasured =
                    bss.rssiDbm < 0 && bss.rssiDbm >= kMinMeasuredRssiDbm;
                out.rssiDbm = out.signalMeasured ? bss.rssiDbm : 0;
                out.htSupported = beacon.htSupported;
                out.ht40Allowed = beacon.ht40Allowed;
                out.security = beacon.rsn.security;
                return out;
            }
        } // namespace

        LegacyScanBridge::LegacyScanBridge() = default;

        void LegacyScanBridge::clear()
        {
            for (auto &entry : completed_)
            {
                entry = {};
            }
            state_ = {};
        }

        ScanBridgeResult LegacyScanBridge::beginScan(uint32_t serial,
                                                     ScanBridgeTicket &ticket)
        {
            // A caller may not smuggle an output reference into this large
            // owner object and overwrite its generation or result storage.
            if (overlapsStorage(&ticket, sizeof(ticket), this, sizeof(*this)))
            {
                return ScanBridgeResult::InvalidArgument;
            }
            // A failed request must leave an in-flight or just-completed
            // caller ticket intact; it is still needed for completion and
            // result enumeration. Mint an output only after all guards pass.
            if (serial == 0)
            {
                return ScanBridgeResult::InvalidArgument;
            }
            if (state_.radioScanRunning)
            {
                return ScanBridgeResult::ScanInProgress;
            }
            if (state_.completionEventPending)
            {
                return ScanBridgeResult::EventPending;
            }
            if (serial <= state_.requestSerial)
            {
                return ScanBridgeResult::InvalidArgument;
            }
            // No wraparound/reuse is possible within this object's lifetime.
            if (lastGeneration_ == UINT64_MAX)
            {
                return ScanBridgeResult::InvalidState;
            }
            ticket = {};
            ++lastGeneration_;
            state_.requestSerial = serial;
            state_.activeGeneration = lastGeneration_;
            state_.radioScanRunning = true;
            ticket.generation = lastGeneration_;
            ticket.serial = serial;
            // Rewind the last complete snapshot so synchronous SCAN_RESULT
            // calls still see valid results until the newly requested scan
            // finishes.
            state_.nextResult = 0;
            // Preserve the previous completed scan until the actual radio
            // reports a new completed scan. Never advertise unfinished results
            // as fresh.
            return ScanBridgeResult::Ok;
        }

        ScanBridgeResult
        LegacyScanBridge::completeScan(const ScanCache &cache,
                                       const ScanBridgeTicket &ticket,
                                       bool succeeded)
        {
            if (!state_.radioScanRunning || ticket.generation == 0 ||
                ticket.generation != state_.activeGeneration ||
                ticket.serial != state_.requestSerial ||
                overlapsStorage(&cache, sizeof(cache), this, sizeof(*this)) ||
                overlapsStorage(&ticket, sizeof(ticket), this, sizeof(*this)))
            {
                return ScanBridgeResult::InvalidState;
            }
            state_.radioScanRunning = false;
            state_.finishedGeneration = ticket.generation;
            state_.finishedSerial = ticket.serial;
            state_.lastScanSucceeded = false;
            state_.completionEventPending = true;
            if (!succeeded)
            {
                return ScanBridgeResult::InvalidState;
            }

            // Validate source availability first; preserve prior snapshot if
            // the source cache is inconsistent. Never allocate 48 full BSS
            // records on a small kernel stack. All access must be serialized by
            // the caller.
            const size_t available = cache.size();
            if (available > ScanCache::kCapacity)
            {
                return ScanBridgeResult::InvalidState;
            }
            for (size_t i = 0; i < available; ++i)
            {
                Bss candidate {};
                if (!cache.snapshot(i, candidate))
                {
                    return ScanBridgeResult::InvalidState;
                }
            }
            size_t count = 0;
            uint32_t rejected = 0;
            for (size_t i = 0; i < available; ++i)
            {
                Bss bss {};
                // The native owner promises a serialized cache. If it is
                // nevertheless inconsistent, never expose a snapshot that
                // mixes the prior completion with partially copied new BSSes.
                if (!cache.snapshot(i, bss))
                {
                    for (auto &entry : completed_)
                    {
                        entry = {};
                    }
                    state_.resultCount = 0;
                    state_.nextResult = 0;
                    state_.completedSerial = 0;
                    state_.completedGeneration = 0;
                    state_.rejectedEntries = 0;
                    state_.completeSnapshotAvailable = false;
                    return ScanBridgeResult::InvalidState;
                }
                if (!accepted(bss))
                {
                    ++rejected;
                    continue;
                }
                completed_[count++] = copyBss(bss);
            }
            for (size_t i = count; i < ScanCache::kCapacity; ++i)
            {
                completed_[i] = {};
            }
            state_.resultCount = count;
            state_.rejectedEntries = rejected;
            state_.nextResult = 0;
            state_.completedSerial = ticket.serial;
            state_.completedGeneration = ticket.generation;
            state_.completeSnapshotAvailable = true;
            state_.lastScanSucceeded = true;
            if (state_.completedScans < UINT32_MAX)
            {
                ++state_.completedScans;
            }
            return ScanBridgeResult::Ok;
        }

        ScanBridgeResult
        LegacyScanBridge::completion(ScanBridgeCompletion &out) const
        {
            if (overlapsStorage(&out, sizeof(out), this, sizeof(*this)))
            {
                return ScanBridgeResult::InvalidArgument;
            }
            out = {};
            if (!state_.completionEventPending)
            {
                return ScanBridgeResult::NoResult;
            }
            out.ticket = {state_.finishedGeneration, state_.finishedSerial};
            out.succeeded = state_.lastScanSucceeded;
            out.resultCount = out.succeeded ? state_.resultCount : 0;
            return ScanBridgeResult::Ok;
        }

        ScanBridgeResult
        LegacyScanBridge::acknowledgeCompletion(const ScanBridgeTicket &ticket)
        {
            if (!state_.completionEventPending ||
                ticket.generation != state_.finishedGeneration ||
                ticket.serial != state_.finishedSerial)
            {
                return ScanBridgeResult::InvalidState;
            }
            state_.completionEventPending = false;
            return ScanBridgeResult::Ok;
        }

        ScanBridgeResult LegacyScanBridge::next(const ScanBridgeTicket &ticket,
                                                NativeBssSnapshot &out)
        {
            if (overlapsStorage(&out, sizeof(out), this, sizeof(*this)) ||
                overlapsStorage(&out, sizeof(out), &ticket, sizeof(ticket)))
            {
                return ScanBridgeResult::InvalidArgument;
            }
            // An exhausted or invalidated iterator cannot return a stale
            // BSS from the previous successful call.
            out = {};
            if (!state_.completeSnapshotAvailable)
            {
                return state_.radioScanRunning &&
                               ticket.generation == state_.activeGeneration &&
                               ticket.serial == state_.requestSerial
                           ? ScanBridgeResult::ScanInProgress
                           : ScanBridgeResult::NoResult;
            }
            if (ticket.generation != state_.completedGeneration ||
                ticket.serial != state_.completedSerial)
            {
                return ScanBridgeResult::InvalidState;
            }
            if (state_.nextResult >= state_.resultCount)
            {
                return ScanBridgeResult::NoResult;
            }
            out = completed_[state_.nextResult++];
            if (state_.returnedResults < UINT32_MAX)
            {
                ++state_.returnedResults;
            }
            return ScanBridgeResult::Ok;
        }

        ScanBridgeResult
        LegacyScanBridge::rewind(const ScanBridgeTicket &ticket)
        {
            if (!state_.completeSnapshotAvailable ||
                ticket.generation != state_.completedGeneration ||
                ticket.serial != state_.completedSerial)
            {
                return ScanBridgeResult::InvalidState;
            }
            state_.nextResult = 0;
            return ScanBridgeResult::Ok;
        }

    } // namespace ieee80211
} // namespace simpleath
