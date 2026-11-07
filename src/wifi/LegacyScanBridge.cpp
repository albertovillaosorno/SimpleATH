// SPDX-License-Identifier: AGPL-3.0-only
#include "LegacyScanBridge.hpp"

namespace simpleath {
namespace ieee80211 {
namespace {
void copyBytes(uint8_t *dest, const uint8_t *src, size_t size) {
    for (size_t i = 0; i < size; ++i) dest[i] = src[i];
}

bool accepted(const Bss &bss) {
    const Beacon &beacon = bss.beacon;
    if (!bss.occupied || beacon.hiddenSsid ||
        beacon.ssidLength == 0 || beacon.ssidLength > 32 ||
        beacon.channel == 0 || beacon.channel > 14 ||
        !beacon.infrastructure || beacon.intervalTu == 0)
        return false;
    if (beacon.rateCount > sizeof(beacon.rates) ||
        beacon.rsnIeLength > sizeof(beacon.rsnIe))
        return false;
    return true;
}

NativeBssSnapshot copyBss(const Bss &bss) {
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
    out.signalMeasured = bss.rssiDbm < 0 && bss.rssiDbm >= -127;
    out.rssiDbm = out.signalMeasured ? bss.rssiDbm : 0;
    out.htSupported = beacon.htSupported;
    out.ht40Allowed = beacon.ht40Allowed;
    out.security = beacon.rsn.security;
    return out;
}
}

LegacyScanBridge::LegacyScanBridge() : completed_ {}, state_ {} {}

void LegacyScanBridge::clear() {
    for (size_t i = 0; i < ScanCache::kCapacity; ++i)
        completed_[i] = {};
    state_ = {};
}

ScanBridgeResult LegacyScanBridge::beginScan(uint32_t serial) {
    if (serial == 0) return ScanBridgeResult::InvalidArgument;
    if (state_.radioScanRunning)
        return ScanBridgeResult::ScanInProgress;
    if (serial <= state_.requestSerial)
        return ScanBridgeResult::InvalidArgument;
    state_.requestSerial = serial;
    state_.radioScanRunning = true;
    // Rewind the last complete snapshot so synchronous SCAN_RESULT calls
    // still see valid results until the newly requested scan finishes.
    state_.nextResult = 0;
    // Preserve the previous completed scan until the actual radio reports
    // a new completed scan. Never advertise unfinished results as fresh.
    return ScanBridgeResult::Ok;
}

ScanBridgeResult LegacyScanBridge::completeScan(
    const ScanCache &cache, uint32_t serial, bool succeeded) {
    if (!state_.radioScanRunning || serial != state_.requestSerial)
        return ScanBridgeResult::InvalidState;
    state_.radioScanRunning = false;
    if (!succeeded)
        return ScanBridgeResult::InvalidState;

    // Validate source availability first; preserve prior snapshot if the
    // source cache is inconsistent. Never allocate 48 full BSS records on
    // a small kernel stack. All access must be serialized by the caller.
    const size_t available = cache.size();
    if (available > ScanCache::kCapacity)
        return ScanBridgeResult::InvalidState;
    for (size_t i = 0; i < available; ++i) {
        Bss candidate {};
        if (!cache.snapshot(i, candidate))
            return ScanBridgeResult::InvalidState;
    }
    size_t count = 0;
    uint32_t rejected = 0;
    for (size_t i = 0; i < available; ++i) {
        Bss bss {};
        // The synchronized source cannot have changed since preflight.
        if (!cache.snapshot(i, bss))
            return ScanBridgeResult::InvalidState;
        if (!accepted(bss)) {
            ++rejected;
            continue;
        }
        completed_[count++] = copyBss(bss);
    }
    for (size_t i = count; i < ScanCache::kCapacity; ++i)
        completed_[i] = {};
    state_.resultCount = count;
    state_.rejectedEntries = rejected;
    state_.nextResult = 0;
    state_.completedSerial = serial;
    state_.completeSnapshotAvailable = true;
    if (state_.completedScans < 0xffffffffu)
        ++state_.completedScans;
    return ScanBridgeResult::Ok;
}

ScanBridgeResult LegacyScanBridge::next(NativeBssSnapshot &out) {
    if (!state_.completeSnapshotAvailable)
        return state_.radioScanRunning
            ? ScanBridgeResult::ScanInProgress : ScanBridgeResult::NoResult;
    if (state_.nextResult >= state_.resultCount)
        return ScanBridgeResult::NoResult;
    out = completed_[state_.nextResult++];
    if (state_.returnedResults < 0xffffffffu)
        ++state_.returnedResults;
    return ScanBridgeResult::Ok;
}

void LegacyScanBridge::rewind() {
    state_.nextResult = 0;
}

} // namespace ieee80211
} // namespace simpleath
