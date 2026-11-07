// SPDX-License-Identifier: AGPL-3.0-only
// Platform-neutral snapshot of completed radio scan results for a future
// native IO80211FamilyLegacy adapter. No Apple private ABI is linked here.
#ifndef SIMPLEATH_WIFI_LEGACY_SCAN_BRIDGE_HPP
#define SIMPLEATH_WIFI_LEGACY_SCAN_BRIDGE_HPP

#include "ScanCache.hpp"

namespace simpleath
{
    namespace ieee80211
    {

        enum class ScanBridgeResult : uint8_t
        {
            Ok,
            NoResult,
            ScanInProgress,
            InvalidState,
            InvalidArgument,
            EventPending
        };

        struct NativeBssSnapshot
        {
                Mac bssid;
                uint8_t ssid[32];
                uint8_t ssidLength;
                uint8_t channel;
                uint16_t capabilities;
                uint16_t beaconIntervalTu;
                uint8_t rates[32];
                uint8_t rateCount;
                uint8_t rsnInformationElement[257];
                uint16_t rsnIeLength;
                int8_t rssiDbm;
                bool signalMeasured;
                bool htSupported;
                bool ht40Allowed;
                Security security;
        };

        // Minted by this bridge, never by an Apple80211 request or a synthetic
        // registry property. An owner must retain the ticket until actual RF
        // work completes, then return the identical ticket under its gate.
        struct ScanBridgeTicket
        {
                uint64_t generation;
                uint32_t serial;
        };

        struct ScanBridgeCompletion
        {
                ScanBridgeTicket ticket;
                size_t resultCount;
                bool succeeded;
        };

        struct ScanBridgeStatus
        {
                uint64_t activeGeneration;
                uint64_t finishedGeneration;
                uint64_t completedGeneration;
                uint32_t finishedSerial;
                uint32_t requestSerial;
                uint32_t completedSerial;
                uint32_t completedScans;
                uint32_t returnedResults;
                uint32_t rejectedEntries;
                size_t resultCount;
                size_t nextResult;
                bool radioScanRunning;
                bool completeSnapshotAvailable;
                bool completionEventPending;
                bool lastScanSucceeded;
        };

        // A completed snapshot is a *value copy*, stable while the live BSS
        // cache changes. Apple80211 SCAN_RESULT requests are an iterator; do
        // not return mutable pointers to the WifiEngine's live cache or a
        // DMA-owned packet.
        //
        // Allocate this large object persistently (not on a kernel stack).
        // Every method must run under the future native controller's serial
        // gate.
        class LegacyScanBridge
        {
            public:
                LegacyScanBridge();
                // Clear on stop/termination. The generation counter is never
                // reset, so stale completions cannot match a later scan after
                // a fresh start reuses the same request serial.
                void clear();
                ScanBridgeResult beginScan(uint32_t serial,
                                           ScanBridgeTicket &ticket);
                // The native owner MUST call this only after genuine channel
                // dwell work and RX have finished. The ticket is checked
                // before consuming source cache or changing the result set.
                ScanBridgeResult completeScan(const ScanCache &cache,
                                              const ScanBridgeTicket &ticket,
                                              bool succeeded);
                // The owner posts SCAN_DONE/its failure equivalent only after
                // reading this pending completion, and acknowledges ONLY after
                // the native client accepted its event. Pending completions
                // block a new beginScan; neither method emits an OS event.
                ScanBridgeResult completion(ScanBridgeCompletion &out) const;
                ScanBridgeResult
                acknowledgeCompletion(const ScanBridgeTicket &ticket);
                // Only the last successful completion ticket can read or
                // rewind its value snapshot; late callbacks from a retired
                // owner may not affect a newer cursor or leak newer results.
                // A completed ticket can still enumerate while a new scan
                // runs. On ordinary failure, out is cleared.
                ScanBridgeResult next(const ScanBridgeTicket &ticket,
                                      NativeBssSnapshot &out);
                ScanBridgeResult rewind(const ScanBridgeTicket &ticket);

                const ScanBridgeStatus &status() const
                {
                    return state_;
                }

            private:
                NativeBssSnapshot completed_[ScanCache::kCapacity];
                ScanBridgeStatus state_;
                uint64_t lastGeneration_;
        };

    } // namespace ieee80211
} // namespace simpleath
#endif
