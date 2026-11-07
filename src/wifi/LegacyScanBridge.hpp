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
            InvalidArgument
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

        struct ScanBridgeStatus
        {
                uint32_t requestSerial;
                uint32_t completedSerial;
                uint32_t completedScans;
                uint32_t returnedResults;
                uint32_t rejectedEntries;
                size_t resultCount;
                size_t nextResult;
                bool radioScanRunning;
                bool completeSnapshotAvailable;
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
                void clear();
                ScanBridgeResult beginScan(uint32_t serial);
                // The radio backend MUST call this only after genuine channel
                // dwell work and RX have finished. This class cannot claim that
                // radio did scan.
                ScanBridgeResult completeScan(const ScanCache &cache,
                                              uint32_t serial, bool succeeded);
                // Reads results from last completed snapshot, including while a
                // new scan is in progress. This avoids disappearing results in
                // native UI. On NoResult/ScanInProgress, out is cleared.
                ScanBridgeResult next(NativeBssSnapshot &out);
                void rewind();

                const ScanBridgeStatus &status() const
                {
                    return state_;
                }

            private:
                NativeBssSnapshot completed_[ScanCache::kCapacity];
                ScanBridgeStatus state_;
        };

    } // namespace ieee80211
} // namespace simpleath
#endif
