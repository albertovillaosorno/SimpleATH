// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Alberto Villa Osorno.
// Offline portable scan pipeline; this is NOT Apple80211, RF or device I/O.
#include "wifi/LegacyScanBridge.hpp"
#include "wifi/WifiEngine.hpp"

namespace
{
    constexpr size_t kBeaconBytes = 49;

    void makeBeacon(uint8_t frame[kBeaconBytes], uint8_t channel)
    {
        for (size_t index = 0; index < kBeaconBytes; ++index)
            frame[index] = 0;
        frame[0] = 0x80; // Beacon management subtype.
        for (size_t index = 4; index < 10; ++index)
            frame[index] = 0xff;      // Broadcast receiver.
        frame[10] = frame[16] = 0x02; // Source/BSSID unicast and identical.
        frame[11] = frame[17] = 0x11;
        frame[12] = frame[18] = 0x22;
        frame[13] = frame[19] = 0x33;
        frame[14] = frame[20] = 0x44;
        frame[15] = frame[21] = 0x55;
        frame[32] = 100;  // Beacon interval, little-endian TU.
        frame[34] = 0x01; // Infrastructure capability, open BSS.
        frame[36] = 0;    // SSID element.
        frame[37] = 4;
        frame[38] = 'T';
        frame[39] = 'e';
        frame[40] = 's';
        frame[41] = 't';
        frame[42] = 1; // Supported rates.
        frame[43] = 2;
        frame[44] = 0x82;
        frame[45] = 0x84;
        frame[46] = 3; // DS channel parameter.
        frame[47] = 1;
        frame[48] = channel;
    }

    bool isTestBss(const simpleath::ieee80211::NativeBssSnapshot &entry,
                   uint8_t channel)
    {
        using namespace simpleath::ieee80211;
        return entry.ssidLength == 4 && entry.ssid[0] == 'T' &&
               entry.ssid[1] == 'e' && entry.ssid[2] == 's' &&
               entry.ssid[3] == 't' && entry.bssid.bytes[0] == 0x02 &&
               entry.bssid.bytes[5] == 0x55 && entry.channel == channel &&
               entry.beaconIntervalTu == 100 && entry.rateCount == 2 &&
               entry.rates[0] == 0x82 && entry.rates[1] == 0x84 &&
               entry.security == Security::Open;
    }
} // namespace

int main()
{
    using namespace simpleath::ieee80211;
    // Persistent owner-style allocations, no OS driver or bus interactions.
    static ScanCache cache;
    static LegacyScanBridge bridge;
    // A forged borrowed RX source from inside the cache must not be parsed
    // as a real air frame or erase cached BSS metadata.
    const auto *cacheBytes = reinterpret_cast<const uint8_t *>(&cache);
    if (cache.observe(cacheBytes, kBeaconBytes, -41, 1) !=
            Result::InvalidFrame ||
        cache.size() != 0)
        return 18;
    // Ordinary missing-SSID lookups clear a stale output, but a caller
    // accidentally pointing its SSID into that output must leave it intact.
    Bss aliasedResult {};
    aliasedResult.rssiDbm = 37;
    const auto *badSsid = reinterpret_cast<const uint8_t *>(&aliasedResult);
    if (cache.strongest(badSsid, 4, 6, true, true, aliasedResult) ||
        aliasedResult.rssiDbm != 37 || cache.size() != 0)
        return 19;
    uint8_t beacon[kBeaconBytes] {};
    makeBeacon(beacon, 6);
    NativeBssSnapshot entry {};
    ScanBridgeTicket ticket {};
    ScanBridgeTicket completedTicket {};
    ScanBridgeTicket ignored {};
    ScanBridgeCompletion completed {};
    if (bridge.next(ticket, entry) != ScanBridgeResult::NoResult ||
        bridge.beginScan(0, ticket) != ScanBridgeResult::InvalidArgument ||
        bridge.completeScan(cache, ticket, true) !=
            ScanBridgeResult::InvalidState)
        return 1;
    if (bridge.beginScan(1, ticket) != ScanBridgeResult::Ok ||
        ticket.serial != 1 || ticket.generation == 0 ||
        bridge.beginScan(2, ignored) != ScanBridgeResult::ScanInProgress ||
        bridge.next(ticket, entry) != ScanBridgeResult::ScanInProgress)
        return 2;
    if (cache.observe(beacon, sizeof(beacon), -41, 1000) != Result::Ok ||
        bridge.completeScan(cache, {ticket.generation, 2}, true) !=
            ScanBridgeResult::InvalidState ||
        bridge.completeScan(cache, ticket, true) != ScanBridgeResult::Ok ||
        bridge.beginScan(2, ignored) != ScanBridgeResult::EventPending ||
        bridge.completion(completed) != ScanBridgeResult::Ok ||
        completed.ticket.generation != ticket.generation ||
        completed.ticket.serial != ticket.serial || !completed.succeeded ||
        completed.resultCount != 1 ||
        bridge.acknowledgeCompletion(ticket) != ScanBridgeResult::Ok)
        return 3;
    completedTicket = ticket;
    if (bridge.next(completedTicket, entry) != ScanBridgeResult::Ok ||
        !isTestBss(entry, 6) || !entry.signalMeasured || entry.rssiDbm != -41 ||
        bridge.next(completedTicket, entry) != ScanBridgeResult::NoResult ||
        entry.ssidLength)
        return 4;

    // The native UI-facing snapshot is a value copy: neither clearing a live
    // cache nor starting a new radio operation can invent new scan results.
    cache.clear();
    if (bridge.rewind(completedTicket) != ScanBridgeResult::Ok ||
        bridge.beginScan(2, ticket) != ScanBridgeResult::Ok ||
        bridge.next(completedTicket, entry) != ScanBridgeResult::Ok ||
        !isTestBss(entry, 6))
        return 5;
    if (bridge.completeScan(cache, ticket, false) !=
            ScanBridgeResult::InvalidState ||
        bridge.completion(completed) != ScanBridgeResult::Ok ||
        completed.succeeded || completed.resultCount != 0 ||
        bridge.acknowledgeCompletion(ticket) != ScanBridgeResult::Ok)
        return 6;
    if (bridge.rewind(completedTicket) != ScanBridgeResult::Ok ||
        bridge.next(completedTicket, entry) != ScanBridgeResult::Ok ||
        !isTestBss(entry, 6) ||
        bridge.beginScan(2, ignored) != ScanBridgeResult::InvalidArgument)
        return 7;

    // An invalid channel never becomes a new accepted BSS. A genuinely
    // completed empty scan revokes the previous snapshot, unlike a failure.
    makeBeacon(beacon, 15);
    if (cache.observe(beacon, sizeof(beacon), -30, 1100) !=
            Result::InvalidElement ||
        bridge.beginScan(3, ticket) != ScanBridgeResult::Ok ||
        bridge.completeScan(cache, ticket, true) != ScanBridgeResult::Ok ||
        bridge.acknowledgeCompletion(ticket) != ScanBridgeResult::Ok ||
        bridge.next(ticket, entry) != ScanBridgeResult::NoResult ||
        entry.ssidLength || bridge.status().resultCount != 0 ||
        !bridge.status().completeSnapshotAvailable ||
        bridge.next(completedTicket, entry) != ScanBridgeResult::InvalidState ||
        entry.ssidLength)
        return 8;

    // The next completed scan contains actual validated frame data, but is
    // still not proof that a native Apple80211 interface or radio exists.
    makeBeacon(beacon, 11);
    if (cache.observe(beacon, sizeof(beacon), 18, 1200) != Result::Ok ||
        bridge.beginScan(4, ticket) != ScanBridgeResult::Ok ||
        bridge.completeScan(cache, ticket, true) != ScanBridgeResult::Ok ||
        bridge.acknowledgeCompletion(ticket) != ScanBridgeResult::Ok ||
        bridge.next(ticket, entry) != ScanBridgeResult::Ok ||
        !isTestBss(entry, 11) || entry.signalMeasured || entry.rssiDbm != 0)
        return 9;

    // Finally exercise the higher portable integration boundary, rather than
    // feeding the scan cache directly: a synthetic RX trust report must first
    // pass WifiEngine admission and produce an explicit cache-update action.
    // These booleans are test doubles; no real PCI/DMA/FCS authority exists.
    static WifiEngine engine;
    EngineAction action {};
    const InputTrust untrusted {true, true, false, false};
    const InputTrust syntheticVerifiedRx {true, true, true, false};

    // A caller cannot pass the engine's own persistent crypto/station bytes
    // as borrowed RX/DMA input, even if they accidentally resemble a frame.
    // Reject before clearing the caller's action or entering the parser.
    action.kind = ActionKind::LinkLost;
    action.bytes = 17;
    const auto *aliasedOwnerFrame = reinterpret_cast<const uint8_t *>(&engine);
    if (engine.acceptRx(aliasedOwnerFrame, kBeaconBytes, -40, 1290,
                        syntheticVerifiedRx, nullptr, 0,
                        action) != EngineResult::InvalidInput ||
        action.kind != ActionKind::LinkLost || action.bytes != 17 ||
        engine.scan().size() != 0)
        return 16;
    if (engine.encodeOutgoingEthernet(aliasedOwnerFrame, kBeaconBytes, 1,
                                      syntheticVerifiedRx, nullptr, 0,
                                      action) != EngineResult::InvalidInput ||
        action.kind != ActionKind::LinkLost || action.bytes != 17 ||
        engine.scan().size() != 0)
        return 17;
    action = {};

    // Caller mistakes must not zero a DMA frame before its FCS/state is
    // checked. An EngineAction occupying the same allocation is rejected
    // untouched, as is a TX response buffer inside the incoming RX frame.
    struct AliasedActionFrame
    {
            EngineAction action;
            uint8_t trailer[kBeaconBytes];
    } aliased {};

    auto *aliasedFrame = reinterpret_cast<uint8_t *>(&aliased);
    makeBeacon(aliasedFrame, 11);
    uint8_t preserved[kBeaconBytes] {};
    for (size_t i = 0; i < kBeaconBytes; ++i)
        preserved[i] = aliasedFrame[i];
    if (engine.acceptRx(aliasedFrame, kBeaconBytes, -45, 1300,
                        syntheticVerifiedRx, nullptr, 0,
                        aliased.action) != EngineResult::InvalidInput ||
        engine.scan().size() != 0)
        return 10;
    for (size_t i = 0; i < kBeaconBytes; ++i)
        if (aliasedFrame[i] != preserved[i])
            return 10;
    if (engine.acceptRx(beacon, sizeof(beacon), -45, 1300, syntheticVerifiedRx,
                        beacon, sizeof(beacon),
                        action) != EngineResult::InvalidInput ||
        engine.scan().size() != 0)
        return 10;
    if (engine.startScan(false, true) != EngineResult::RadioNotReady ||
        engine.startScan(true, true) != EngineResult::Ok ||
        engine.acceptRx(beacon, sizeof(beacon), -45, 1300, untrusted, nullptr,
                        0, action) != EngineResult::InvalidInput ||
        action.kind != ActionKind::None || engine.scan().size() != 0)
        return 10;
    if (engine.acceptRx(beacon, sizeof(beacon), -45, 1300, syntheticVerifiedRx,
                        nullptr, 0, action) != EngineResult::Ok ||
        action.kind != ActionKind::ScanCacheUpdated ||
        action.nativeInterfaceUsable || engine.scan().size() != 1)
        return 11;
    if (bridge.beginScan(5, ticket) != ScanBridgeResult::Ok ||
        bridge.completeScan(engine.scan(), ticket, true) !=
            ScanBridgeResult::Ok ||
        bridge.acknowledgeCompletion(ticket) != ScanBridgeResult::Ok ||
        bridge.next(ticket, entry) != ScanBridgeResult::Ok ||
        !isTestBss(entry, 11) || !entry.signalMeasured || entry.rssiDbm != -45)
        return 12;
    engine.radioStopped(1301, true);
    if (bridge.rewind(ticket) != ScanBridgeResult::Ok ||
        engine.scan().size() != 0 ||
        bridge.next(ticket, entry) != ScanBridgeResult::Ok ||
        !isTestBss(entry, 11))
        return 13;
    // A fresh controller lifetime can reuse an OS-request serial, not a
    // generation. A retired owner may not complete or expose its last BSS.
    bridge.clear();
    if (bridge.rewind(ticket) != ScanBridgeResult::InvalidState ||
        bridge.next(ticket, entry) != ScanBridgeResult::NoResult ||
        entry.ssidLength)
        return 14;
    ScanBridgeTicket newLifetime {};
    if (bridge.beginScan(5, newLifetime) != ScanBridgeResult::Ok ||
        newLifetime.generation == ticket.generation ||
        bridge.completeScan(cache, ticket, true) !=
            ScanBridgeResult::InvalidState ||
        !bridge.status().radioScanRunning ||
        bridge.next(ticket, entry) != ScanBridgeResult::NoResult ||
        entry.ssidLength)
        return 15;

    // A full cache may evict a different BSSID whose channel and RSN match.
    // The newcomer's hidden beacon must never inherit that older BSSID's SSID.
    static ScanCache recycledCache;
    uint8_t visible[kBeaconBytes] {};
    for (size_t i = 0; i < ScanCache::kCapacity; ++i)
    {
        makeBeacon(visible, 6);
        visible[15] = visible[21] = static_cast<uint8_t>(i + 1);
        if (recycledCache.observe(visible, sizeof(visible), -40, i + 10) !=
            Result::Ok)
            return 20;
    }
    makeBeacon(visible, 6);
    visible[15] = visible[21] = 0xfe;
    uint8_t hidden[45] {};
    for (size_t i = 0; i < 38; ++i)
        hidden[i] = visible[i];
    hidden[37] = 0; // Zero-length hidden SSID element.
    for (size_t i = 0; i < 7; ++i)
        hidden[38 + i] = visible[42 + i];
    if (recycledCache.observe(hidden, sizeof(hidden), -35, 1000) !=
            Result::Ok ||
        recycledCache.size() != ScanCache::kCapacity)
        return 21;
    bool foundNewBssid = false;
    Bss recycled {};
    for (size_t i = 0; i < ScanCache::kCapacity; ++i)
    {
        if (!recycledCache.snapshot(i, recycled))
            return 22;
        if (recycled.beacon.bssid.bytes[5] == 0xfe)
        {
            foundNewBssid = true;
            if (!recycled.beacon.hiddenSsid || recycled.beacon.ssidLength)
                return 23;
        }
    }
    if (!foundNewBssid)
        return 24;

    // An actual visible SSID from the *same* BSSID may still be retained
    // when its subsequent advertisement hides the name.
    if (recycledCache.observe(visible, sizeof(visible), -35, 1001) !=
            Result::Ok ||
        recycledCache.observe(hidden, sizeof(hidden), -35, 1002) != Result::Ok)
        return 25;
    bool preservedSameBssid = false;
    for (size_t i = 0; i < ScanCache::kCapacity; ++i)
    {
        if (!recycledCache.snapshot(i, recycled))
            return 26;
        if (recycled.beacon.bssid.bytes[5] == 0xfe)
        {
            preservedSameBssid = !recycled.beacon.hiddenSsid &&
                                 recycled.beacon.ssidLength == 4 &&
                                 recycled.beacon.ssid[0] == 'T';
        }
    }
    if (!preservedSameBssid)
        return 27;

    // RX callbacks can arrive with a timestamp older than an already cached
    // observation. Such a delayed frame must not replace a newer BSSID's
    // security/channel/SSID metadata or roll its expiration clock backwards.
    static ScanCache chronologicalCache;
    uint8_t ordered[kBeaconBytes] {};
    makeBeacon(ordered, 6);
    if (chronologicalCache.observe(ordered, sizeof(ordered), -40, 2000) !=
        Result::Ok)
        return 28;
    makeBeacon(ordered, 11);
    if (chronologicalCache.observe(ordered, sizeof(ordered), -25, 1999) !=
            Result::InvalidFrame ||
        !chronologicalCache.snapshot(0, recycled) ||
        recycled.lastSeenMs != 2000 || recycled.beacon.channel != 6 ||
        recycled.rssiDbm != -40)
        return 28;

    // With the cache full, a frame older than the newest observation must
    // not displace any BSSID just because another cached entry is older.
    for (size_t i = 0; i < ScanCache::kCapacity - 1; ++i)
    {
        makeBeacon(ordered, 6);
        ordered[15] = ordered[21] = static_cast<uint8_t>(i + 1);
        if (chronologicalCache.observe(ordered, sizeof(ordered), -40,
                                       2001 + i) != Result::Ok)
            return 29;
    }
    makeBeacon(ordered, 6);
    ordered[15] = ordered[21] = 0xfdu;
    if (chronologicalCache.size() != ScanCache::kCapacity ||
        chronologicalCache.observe(ordered, sizeof(ordered), -20, 2030) !=
            Result::InvalidFrame ||
        chronologicalCache.size() != ScanCache::kCapacity)
        return 29;
    for (size_t i = 0; i < ScanCache::kCapacity; ++i)
    {
        if (!chronologicalCache.snapshot(i, recycled) ||
            recycled.beacon.bssid.bytes[5] == 0xfdu)
            return 29;
    }
    return 0;
}
