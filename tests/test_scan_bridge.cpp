// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Alberto Villa Osorno.
// Offline portable scan pipeline; this is NOT Apple80211, RF or device I/O.
#include "wifi/Frames.hpp"
#include "wifi/LegacyScanBridge.hpp"
#include "wifi/ScanCache.hpp"
#include "wifi/WifiEngine.hpp"
#include "wifi/crypto/Wpa2CryptoAdapter.hpp"
#include <cstddef>
#include <cstdint>

namespace
{
    constexpr size_t kBeaconBytes = 49;

    void makeBeacon(uint8_t frame[kBeaconBytes], uint8_t channel)
    {
        for (size_t index = 0; index < kBeaconBytes; ++index)
        {
            frame[index] = 0;
        }
        frame[0] = 0x80; // Beacon management subtype.
        for (size_t index = 4; index < 10; ++index)
        {
            frame[index] = 0xff; // Broadcast receiver.
        }
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

    bool scheduledPassiveScanRequiresVerifiedTune()
    {
        using namespace simpleath::ieee80211;
        static WifiEngine engine;
        const ScanChannelDwell bad[] {{6, 20}, {6, 40}};
        const ScanChannelDwell invalidChannel[] {{15, 20}};
        const ScanChannelDwell invalidDwell[] {{6, 0}};
        const ScanChannelDwell channels[] {{6, 20}, {11, 30}};
        uint64_t generation = 0;
        if (engine.beginChannelScan({invalidChannel, 1, 100, true, true},
                                    generation) != EngineResult::InvalidInput ||
            engine.beginChannelScan({invalidDwell, 1, 100, true, true},
                                    generation) != EngineResult::InvalidInput ||
            engine.beginChannelScan({bad, 2, 100, true, true}, generation) !=
                EngineResult::InvalidInput ||
            engine.beginChannelScan({channels, 2, 100, false, true},
                                    generation) !=
                EngineResult::RadioNotReady ||
            engine.beginChannelScan({channels, 2, 100, true, true},
                                    generation) != EngineResult::Ok ||
            generation == 0)
        {
            return false;
        }
        ScanProgress step {};
        EngineAction action {};
        const InputTrust verified {true, true, true, false};
        uint8_t frame[kBeaconBytes] {};
        makeBeacon(frame, 6);
        if (engine.pollChannelScan(100, step) != EngineResult::Ok ||
            step.kind != ScanProgressKind::TuneRequired || step.channel != 6 ||
            step.generation != generation ||
            engine.beginChannelScan({channels, 2, 101, true, true},
                                    generation) != EngineResult::InvalidState ||
            engine.acknowledgeChannelTune({generation, 6, 100, false}) !=
                EngineResult::RadioNotReady ||
            engine.acceptRx(frame, sizeof(frame), verified, {-30, 100}, nullptr,
                            0, action) != EngineResult::NoAction ||
            engine.scan().size() != 0 ||
            engine.acknowledgeChannelTune({generation + 1, 6, 100, true}) !=
                EngineResult::InvalidState ||
            engine.acknowledgeChannelTune({generation, 11, 100, true}) !=
                EngineResult::InvalidState ||
            engine.acknowledgeChannelTune({generation, 6, 100, true}) !=
                EngineResult::Ok)
        {
            return false;
        }
        makeBeacon(frame, 11);
        if (engine.acceptRx(frame, sizeof(frame), verified, {-30, 110}, nullptr,
                            0, action) != EngineResult::NoAction ||
            engine.pollChannelScan(119, step) != EngineResult::Ok ||
            step.kind != ScanProgressKind::Dwelling || step.deadlineMs != 120 ||
            engine.scan().size() != 0)
        {
            return false;
        }
        makeBeacon(frame, 6);
        if (engine.acceptRx(frame, sizeof(frame), verified, {-30, 110}, nullptr,
                            0, action) != EngineResult::NoAction ||
            engine.scan().size() != 0)
        {
            return false;
        }
        const Mac station {{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}};
        const uint8_t ssid[] {'T', 'e', 's', 't'};
        if (engine.acceptRx(frame, sizeof(frame), verified, {-30, 119}, nullptr,
                            0, action) != EngineResult::Ok ||
            action.kind != ActionKind::ScanCacheUpdated ||
            engine.scan().size() != 1 ||
            engine.chooseNetwork(station, ssid, sizeof(ssid), 6, true, false,
                                 nullptr) != EngineResult::InvalidState ||
            engine.pollChannelScan(120, step) != EngineResult::Ok ||
            step.kind != ScanProgressKind::TuneRequired || step.channel != 11 ||
            engine.acceptRx(frame, sizeof(frame), verified, {-30, 120}, nullptr,
                            0, action) != EngineResult::NoAction ||
            engine.acknowledgeChannelTune({generation, 11, 119, true}) !=
                EngineResult::InvalidInput ||
            engine.acknowledgeChannelTune({generation, 11, 120, true}) !=
                EngineResult::Ok)
        {
            return false;
        }
        makeBeacon(frame, 11);
        if (engine.acceptRx(frame, sizeof(frame), verified, {-30, 150}, nullptr,
                            0, action) != EngineResult::NoAction ||
            engine.pollChannelScan(150, step) != EngineResult::Ok ||
            step.kind != ScanProgressKind::Complete ||
            step.generation != generation ||
            engine.pollChannelScan(151, step) != EngineResult::NoAction ||
            engine.chooseNetwork(station, ssid, sizeof(ssid), 6, true, false,
                                 nullptr) != EngineResult::Ok ||
            engine.cancelChannelScan(generation) != EngineResult::InvalidState)
        {
            return false;
        }
        engine.radioStopped(151, true);
        uint64_t second = 0;
        if (engine.beginChannelScan({channels, 2, 200, true, true}, second) !=
                EngineResult::Ok ||
            second == generation ||
            engine.acknowledgeChannelTune({generation, 6, 200, true}) !=
                EngineResult::InvalidState ||
            engine.cancelChannelScan(second) != EngineResult::Ok ||
            engine.pollChannelScan(201, step) != EngineResult::NoAction ||
            engine.cancelChannelScan(second) != EngineResult::InvalidState ||
            engine.chooseNetwork(station, ssid, sizeof(ssid), 6, true, false,
                                 nullptr) != EngineResult::InvalidState)
        {
            return false;
        }
        if (engine.beginChannelScan({channels, 2, UINT64_MAX - 4, true, true},
                                    second) != EngineResult::Ok ||
            engine.pollChannelScan(UINT64_MAX - 4, step) != EngineResult::Ok ||
            engine.acknowledgeChannelTune({second, 6, UINT64_MAX - 4, true}) !=
                EngineResult::InvalidInput)
        {
            return false;
        }
        engine.radioStopped(UINT64_MAX - 4, false);
        return true;
    }

    bool osOwnedWpa2SelectsExactObservedBssid()
    {
        using namespace simpleath::ieee80211;
        constexpr size_t kAuthenticationResponseBytes = 30U;
        constexpr uint8_t kAuthenticationResponseControl = 0xb0U;
        constexpr uint8_t kTestChannel = 6U;
        constexpr int8_t kLateResponseRssi = -20;
        constexpr int8_t kStrongerRssi = -21;
        constexpr uint64_t kLateResponseMs = 203U;
        constexpr uint64_t kFreshBeaconMs = 204U;
        constexpr uint64_t kStoppedMs = 205U;
        constexpr uint8_t rsnIe[22] {
            48,   20,   1, 0, 0, 0x0f, 0xac, 4,    1, 0, 0,
            0x0f, 0xac, 4, 1, 0, 0,    0x0f, 0xac, 2, 0, 0,
        };
        uint8_t advertisement[kBeaconBytes + sizeof(rsnIe)] {};
        makeBeacon(advertisement, 6);
        advertisement[34] |= 0x10; // RSN privacy capability.
        for (size_t i = 0; i < sizeof(rsnIe); ++i)
        {
            advertisement[kBeaconBytes + i] = rsnIe[i];
        }
        const Mac weaker {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        const Mac stronger {{0x02, 0x11, 0x22, 0x33, 0x44, 0x66}};
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        const uint8_t ssid[] {'T', 'e', 's', 't'};
        const ScanSelection allowed {sizeof(ssid), 6, false, true};
        ScanCache cache;
        Bss result {};
        if (cache.observe(advertisement, {sizeof(advertisement), -68, 100}) !=
            Result::Ok)
        {
            return false;
        }
        advertisement[15] = advertisement[21] = stronger.bytes[5];
        if (cache.observe(advertisement, {sizeof(advertisement), -21, 101}) !=
                Result::Ok ||
            !cache.strongest(ssid, allowed, result) ||
            !sameMac(result.beacon.bssid, stronger) ||
            !cache.matchingBssid(weaker, ssid, allowed, result) ||
            !sameMac(result.beacon.bssid, weaker))
        {
            return false;
        }
        result.rssiDbm = 12;
        const Mac unknown {{0x02, 0x11, 0x22, 0x33, 0x44, 0x77}};
        if (cache.matchingBssid(unknown, ssid, allowed, result) ||
            result.occupied || result.rssiDbm != 0 ||
            cache.matchingBssid(weaker, ssid, {sizeof(ssid), 11, false, true},
                                result) ||
            cache.matchingBssid(weaker, ssid, {sizeof(ssid), 6, true, false},
                                result))
        {
            return false;
        }
        // Reject aliased output without corrupting the caller's BSSID.
        Bss aliased {};
        aliased.beacon.bssid = weaker;
        if (cache.matchingBssid(aliased.beacon.bssid, ssid, allowed, aliased) ||
            !sameMac(aliased.beacon.bssid, weaker))
        {
            return false;
        }

        static WifiEngine native;
        if (native.startScan(true, true) != EngineResult::Ok)
        {
            return false;
        }
        EngineAction action {};
        const InputTrust verified {true, true, true, false};
        // The OS selected the *weaker* observed BSSID; never silently join
        // the stronger neighbor with the same SSID and advertised RSNE.
        advertisement[15] = advertisement[21] = weaker.bytes[5];
        if (native.acceptRx(advertisement, sizeof(advertisement), verified,
                            {-68, 200}, nullptr, 0, action) != EngineResult::Ok)
        {
            return false;
        }
        advertisement[15] = advertisement[21] = stronger.bytes[5];
        if (native.acceptRx(advertisement, sizeof(advertisement), verified,
                            {-21, 201}, nullptr, 0,
                            action) != EngineResult::Ok ||
            native.chooseNetworkForOsSupplicant(station, unknown, ssid,
                                                sizeof(ssid), 6, true) !=
                EngineResult::NoMatchingBss ||
            native.chooseNetworkForOsSupplicant(station, weaker, ssid,
                                                sizeof(ssid), 6, false) !=
                EngineResult::NoMatchingBss ||
            native.chooseNetworkForOsSupplicant(weaker, weaker, ssid,
                                                sizeof(ssid), 6, true) !=
                EngineResult::InvalidInput ||
            native.chooseNetwork(station, ssid, sizeof(ssid), 6, false, true,
                                 nullptr) != EngineResult::CryptoUnavailable ||
            native.chooseNetworkForOsSupplicant(station, weaker, ssid,
                                                sizeof(ssid), 6,
                                                true) != EngineResult::Ok ||
            !native.osSupplicantOwnsWpa2() ||
            native.stationState() != StationState::CandidateSelected ||
            native.chooseNetworkForOsSupplicant(station, stronger, ssid,
                                                sizeof(ssid), 6, true) !=
                EngineResult::InvalidState)
        {
            return false;
        }
        uint8_t outbound[256] {};
        if (native.requestAuthentication(7, outbound, sizeof(outbound),
                                         action) != EngineResult::Ok ||
            action.kind != ActionKind::TransmitAuthentication ||
            action.bytes < 24 || outbound[4] != weaker.bytes[0] ||
            outbound[9] != weaker.bytes[5])
        {
            return false;
        }
        // A native leave during authentication must NOT construct a
        // disassociation for a link which has never associated. The owner
        // first drains any pending physical management TX, then cancels only
        // the selected candidate. A late AP response is no longer applicable.
        if (native.cancelPendingJoin() != EngineResult::Ok ||
            native.cancelPendingJoin() != EngineResult::InvalidState ||
            native.osSupplicantOwnsWpa2() ||
            native.stationState() != StationState::Inactive ||
            native.startScan(true, true) != EngineResult::Ok)
        {
            return false;
        }
        uint8_t staleAuth[kAuthenticationResponseBytes] {};
        staleAuth[0] = kAuthenticationResponseControl;
        if (native.acceptRx(&staleAuth[0], sizeof(staleAuth), verified,
                            {kLateResponseRssi, kLateResponseMs}, nullptr, 0,
                            action) != EngineResult::NoAction ||
            action.kind != ActionKind::None ||
            native.stationState() != StationState::Scanning)
        {
            return false;
        }
        if (native.acceptRx(&advertisement[0], sizeof(advertisement), verified,
                            {kStrongerRssi, kFreshBeaconMs}, nullptr, 0,
                            action) != EngineResult::Ok ||
            native.chooseNetworkForOsSupplicant(station, stronger, &ssid[0],
                                                sizeof(ssid), kTestChannel,
                                                true) != EngineResult::Ok ||
            native.stationState() != StationState::CandidateSelected ||
            native.cancelPendingJoin() != EngineResult::Ok ||
            native.startScan(true, true) != EngineResult::Ok)
        {
            return false;
        }
        native.radioStopped(kStoppedMs, true);
        return !native.osSupplicantOwnsWpa2() &&
               native.stationState() == StationState::Inactive;
    }

    bool preferCompatibleAssociationRates()
    {
        using namespace simpleath::ieee80211;
        ScanCache cache;
        uint8_t advertised[kBeaconBytes] {};
        makeBeacon(advertised, 6);
        if (cache.observe(advertised, ScanObservation {sizeof(advertised), -60,
                                                       1}) != Result::Ok)
        {
            return false;
        }

        // A stronger AP with the same SSID requires an unknown mandatory
        // basic rate, even though another rate overlaps local capabilities.
        advertised[15] = advertised[21] = 0x66;
        advertised[44] = 0xff;
        advertised[45] = 0x82;
        if (cache.observe(advertised, ScanObservation {sizeof(advertised), -25,
                                                       2}) != Result::Ok)
        {
            return false;
        }
        const uint8_t ssid[] {'T', 'e', 's', 't'};
        Bss choice {};
        if (!cache.strongest(ssid, ScanSelection {sizeof(ssid), 6, true, false},
                             choice) ||
            choice.beacon.bssid.bytes[5] != 0x55)
        {
            return false;
        }

        // Unknown optional rates do not prevent joining when a compatible
        // rate remains; a stronger compatible AP should still win.
        advertised[44] = 0x7f;
        if (cache.observe(advertised, ScanObservation {sizeof(advertised), -25,
                                                       3}) != Result::Ok ||
            !cache.strongest(ssid, ScanSelection {sizeof(ssid), 6, true, false},
                             choice) ||
            choice.beacon.bssid.bytes[5] != 0x66)
        {
            return false;
        }

        // Optional rates alone are insufficient without any common rate.
        advertised[45] = 0x7e;
        return cache.observe(advertised,
                             ScanObservation {sizeof(advertised), -20, 4}) ==
                   Result::Ok &&
               cache.strongest(ssid,
                               ScanSelection {sizeof(ssid), 6, true, false},
                               choice) &&
               choice.beacon.bssid.bytes[5] == 0x55;
    }
} // namespace

int main()
{
    using namespace simpleath::ieee80211;
    if (!osOwnedWpa2SelectsExactObservedBssid())
    {
        return 37;
    }
    if (!scheduledPassiveScanRequiresVerifiedTune())
    {
        return 36;
    }
    if (!preferCompatibleAssociationRates())
    {
        return 35;
    }
    // Persistent owner-style allocations, no OS driver or bus interactions.
    static ScanCache cache;
    static LegacyScanBridge bridge;
    // A forged borrowed RX source from inside the cache must not be parsed
    // as a real air frame or erase cached BSS metadata.
    const auto *cacheBytes = reinterpret_cast<const uint8_t *>(&cache);
    if (cache.observe(cacheBytes, ScanObservation {kBeaconBytes, -41, 1}) !=
            Result::InvalidFrame ||
        cache.size() != 0)
    {
        return 18;
    }
    // Ordinary missing-SSID lookups clear a stale output, but a caller
    // accidentally pointing its SSID into that output must leave it intact.
    Bss aliasedResult {};
    aliasedResult.rssiDbm = 37;
    const auto *badSsid = reinterpret_cast<const uint8_t *>(&aliasedResult);
    if (cache.strongest(badSsid, ScanSelection {4, 6, true, true},
                        aliasedResult) ||
        aliasedResult.rssiDbm != 37 || cache.size() != 0)
    {
        return 19;
    }
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
    {
        return 1;
    }
    if (bridge.beginScan(1, ticket) != ScanBridgeResult::Ok ||
        ticket.serial != 1 || ticket.generation == 0 ||
        bridge.beginScan(2, ignored) != ScanBridgeResult::ScanInProgress ||
        bridge.next(ticket, entry) != ScanBridgeResult::ScanInProgress)
    {
        return 2;
    }
    // A rejected duplicate scan request must not destroy the caller's live
    // ticket. Otherwise a status poll can orphan the active scan and prevent
    // its valid completion without any radio failure.
    const ScanBridgeTicket liveTicket = ticket;
    if (bridge.beginScan(2, ticket) != ScanBridgeResult::ScanInProgress ||
        ticket.generation != liveTicket.generation ||
        ticket.serial != liveTicket.serial)
    {
        return 32;
    }
    if (cache.observe(beacon, ScanObservation {sizeof(beacon), -41, 1000}) !=
            Result::Ok ||
        bridge.completeScan(cache, {ticket.generation, 2}, true) !=
            ScanBridgeResult::InvalidState ||
        bridge.completeScan(cache, ticket, true) != ScanBridgeResult::Ok ||
        bridge.beginScan(2, ignored) != ScanBridgeResult::EventPending ||
        bridge.completion(completed) != ScanBridgeResult::Ok ||
        completed.ticket.generation != ticket.generation ||
        completed.ticket.serial != ticket.serial || !completed.succeeded ||
        completed.resultCount != 1)
    {
        return 3;
    }
    // Another request while SCAN_DONE is pending must preserve the ticket
    // needed to acknowledge the pending completion and read its results.
    if (bridge.beginScan(2, ticket) != ScanBridgeResult::EventPending ||
        ticket.generation != liveTicket.generation ||
        ticket.serial != liveTicket.serial)
    {
        return 33;
    }
    if (bridge.acknowledgeCompletion(ticket) != ScanBridgeResult::Ok)
    {
        return 3;
    }
    // A duplicate request serial must likewise preserve a completed ticket.
    if (bridge.beginScan(1, ticket) != ScanBridgeResult::InvalidArgument ||
        ticket.generation != liveTicket.generation ||
        ticket.serial != liveTicket.serial)
    {
        return 34;
    }
    completedTicket = ticket;
    if (bridge.next(completedTicket, entry) != ScanBridgeResult::Ok ||
        !isTestBss(entry, 6) || !entry.signalMeasured || entry.rssiDbm != -41 ||
        bridge.next(completedTicket, entry) != ScanBridgeResult::NoResult ||
        (entry.ssidLength != 0U))
    {
        return 4;
    }

    // The native UI-facing snapshot is a value copy: neither clearing a live
    // cache nor starting a new radio operation can invent new scan results.
    cache.clear();
    if (bridge.rewind(completedTicket) != ScanBridgeResult::Ok ||
        bridge.beginScan(2, ticket) != ScanBridgeResult::Ok ||
        bridge.next(completedTicket, entry) != ScanBridgeResult::Ok ||
        !isTestBss(entry, 6))
    {
        return 5;
    }
    if (bridge.completeScan(cache, ticket, false) !=
            ScanBridgeResult::InvalidState ||
        bridge.completion(completed) != ScanBridgeResult::Ok ||
        completed.succeeded || completed.resultCount != 0 ||
        bridge.acknowledgeCompletion(ticket) != ScanBridgeResult::Ok)
    {
        return 6;
    }
    if (bridge.rewind(completedTicket) != ScanBridgeResult::Ok ||
        bridge.next(completedTicket, entry) != ScanBridgeResult::Ok ||
        !isTestBss(entry, 6) ||
        bridge.beginScan(2, ignored) != ScanBridgeResult::InvalidArgument)
    {
        return 7;
    }

    // An invalid channel never becomes a new accepted BSS. A genuinely
    // completed empty scan revokes the previous snapshot, unlike a failure.
    makeBeacon(beacon, 15);
    if (cache.observe(beacon, ScanObservation {sizeof(beacon), -30, 1100}) !=
            Result::InvalidElement ||
        bridge.beginScan(3, ticket) != ScanBridgeResult::Ok ||
        bridge.completeScan(cache, ticket, true) != ScanBridgeResult::Ok ||
        bridge.acknowledgeCompletion(ticket) != ScanBridgeResult::Ok ||
        bridge.next(ticket, entry) != ScanBridgeResult::NoResult ||
        (entry.ssidLength != 0U) || bridge.status().resultCount != 0 ||
        !bridge.status().completeSnapshotAvailable ||
        bridge.next(completedTicket, entry) != ScanBridgeResult::InvalidState ||
        (entry.ssidLength != 0U))
    {
        return 8;
    }

    // The next completed scan contains actual validated frame data, but is
    // still not proof that a native Apple80211 interface or radio exists.
    makeBeacon(beacon, 11);
    if (cache.observe(beacon, ScanObservation {sizeof(beacon), 18, 1200}) !=
            Result::Ok ||
        bridge.beginScan(4, ticket) != ScanBridgeResult::Ok ||
        bridge.completeScan(cache, ticket, true) != ScanBridgeResult::Ok ||
        bridge.acknowledgeCompletion(ticket) != ScanBridgeResult::Ok ||
        bridge.next(ticket, entry) != ScanBridgeResult::Ok ||
        !isTestBss(entry, 11) || entry.signalMeasured || entry.rssiDbm != 0)
    {
        return 9;
    }

    // Finally exercise the higher portable integration boundary, rather than
    // feeding the scan cache directly: a synthetic RX trust report must first
    // pass WifiEngine admission and produce an explicit cache-update action.
    // These booleans are test doubles; no real PCI/DMA/FCS authority exists.
    static WifiEngine engine;
    // The crypto provider owns writable context memory. It must not be
    // borrowed from any part of the engine, even outside Adapter itself:
    // a future random/keycache callback could overwrite live link state.
    crypto::KeyHardware borrowedHardware {};
    borrowedHardware.context = &engine;
    borrowedHardware.secureRandom = +[](void *, uint8_t *, size_t) -> bool
    {
        return true;
    };
    borrowedHardware.installPairwise =
        +[](void *, const Mac &, const uint8_t *) -> bool
    {
        return true;
    };
    borrowedHardware.installGroup =
        +[](void *, uint8_t, const uint8_t *, const uint8_t *) -> bool
    {
        return true;
    };
    borrowedHardware.removeKeys = +[](void *)
    {
    };
    if (engine.configureKeys(borrowedHardware))
    {
        return 30;
    }
    EngineAction action {};
    const InputTrust untrusted {true, true, false, false};
    const InputTrust syntheticVerifiedRx {true, true, true, false};

    // A caller cannot pass the engine's own persistent crypto/station bytes
    // as borrowed RX/DMA input, even if they accidentally resemble a frame.
    // Reject before clearing the caller's action or entering the parser.
    action.kind = ActionKind::LinkLost;
    action.bytes = 17;
    const auto *aliasedOwnerFrame = reinterpret_cast<const uint8_t *>(&engine);
    if (engine.acceptRx(aliasedOwnerFrame, kBeaconBytes, syntheticVerifiedRx,
                        {-40, 1290}, nullptr, 0,
                        action) != EngineResult::InvalidInput ||
        action.kind != ActionKind::LinkLost || action.bytes != 17 ||
        engine.scan().size() != 0)
    {
        return 16;
    }
    if (engine.encodeOutgoingEthernet(aliasedOwnerFrame, kBeaconBytes, 1,
                                      syntheticVerifiedRx, nullptr, 0,
                                      action) != EngineResult::InvalidInput ||
        action.kind != ActionKind::LinkLost || action.bytes != 17 ||
        engine.scan().size() != 0)
    {
        return 17;
    }
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
    {
        preserved[i] = aliasedFrame[i];
    }
    if (engine.acceptRx(aliasedFrame, kBeaconBytes, syntheticVerifiedRx,
                        {-45, 1300}, nullptr, 0,
                        aliased.action) != EngineResult::InvalidInput ||
        engine.scan().size() != 0)
    {
        return 10;
    }
    for (size_t i = 0; i < kBeaconBytes; ++i)
    {
        if (aliasedFrame[i] != preserved[i])
        {
            return 10;
        }
    }
    if (engine.acceptRx(beacon, sizeof(beacon), syntheticVerifiedRx,
                        {-45, 1300}, beacon, sizeof(beacon),
                        action) != EngineResult::InvalidInput ||
        engine.scan().size() != 0)
    {
        return 10;
    }
    if (engine.startScan(false, true) != EngineResult::RadioNotReady ||
        engine.startScan(true, true) != EngineResult::Ok ||
        engine.acceptRx(beacon, sizeof(beacon), untrusted, {-45, 1300}, nullptr,
                        0, action) != EngineResult::InvalidInput ||
        action.kind != ActionKind::None || engine.scan().size() != 0)
    {
        return 10;
    }
    if (engine.acceptRx(beacon, sizeof(beacon), syntheticVerifiedRx,
                        {-45, 1300}, nullptr, 0, action) != EngineResult::Ok ||
        action.kind != ActionKind::ScanCacheUpdated ||
        action.nativeInterfaceUsable || engine.scan().size() != 1)
    {
        return 11;
    }
    if (bridge.beginScan(5, ticket) != ScanBridgeResult::Ok ||
        bridge.completeScan(engine.scan(), ticket, true) !=
            ScanBridgeResult::Ok ||
        bridge.acknowledgeCompletion(ticket) != ScanBridgeResult::Ok ||
        bridge.next(ticket, entry) != ScanBridgeResult::Ok ||
        !isTestBss(entry, 11) || !entry.signalMeasured || entry.rssiDbm != -45)
    {
        return 12;
    }
    engine.radioStopped(1301, true);
    if (bridge.rewind(ticket) != ScanBridgeResult::Ok ||
        engine.scan().size() != 0 ||
        bridge.next(ticket, entry) != ScanBridgeResult::Ok ||
        !isTestBss(entry, 11))
    {
        return 13;
    }
    // A fresh controller lifetime can reuse an OS-request serial, not a
    // generation. A retired owner may not complete or expose its last BSS.
    bridge.clear();
    if (bridge.rewind(ticket) != ScanBridgeResult::InvalidState ||
        bridge.next(ticket, entry) != ScanBridgeResult::NoResult ||
        (entry.ssidLength != 0U))
    {
        return 14;
    }
    ScanBridgeTicket newLifetime {};
    if (bridge.beginScan(5, newLifetime) != ScanBridgeResult::Ok ||
        newLifetime.generation == ticket.generation ||
        bridge.completeScan(cache, ticket, true) !=
            ScanBridgeResult::InvalidState ||
        !bridge.status().radioScanRunning ||
        bridge.next(ticket, entry) != ScanBridgeResult::NoResult ||
        (entry.ssidLength != 0U))
    {
        return 15;
    }

    // A full cache may evict a different BSSID whose channel and RSN match.
    // The newcomer's hidden beacon must never inherit that older BSSID's SSID.
    static ScanCache recycledCache;
    uint8_t visible[kBeaconBytes] {};
    for (size_t i = 0; i < ScanCache::kCapacity; ++i)
    {
        makeBeacon(visible, 6);
        visible[15] = visible[21] = static_cast<uint8_t>(i + 1);
        if (recycledCache.observe(
                visible, ScanObservation {sizeof(visible), -40, i + 10}) !=
            Result::Ok)
        {
            return 20;
        }
    }
    makeBeacon(visible, 6);
    visible[15] = visible[21] = 0xfe;
    uint8_t hidden[45] {};
    for (size_t i = 0; i < 38; ++i)
    {
        hidden[i] = visible[i];
    }
    hidden[37] = 0; // Zero-length hidden SSID element.
    for (size_t i = 0; i < 7; ++i)
    {
        hidden[38 + i] = visible[42 + i];
    }
    if (recycledCache.observe(hidden, ScanObservation {sizeof(hidden), -35,
                                                       1000}) != Result::Ok ||
        recycledCache.size() != ScanCache::kCapacity)
    {
        return 21;
    }
    bool foundNewBssid = false;
    Bss recycled {};
    for (size_t i = 0; i < ScanCache::kCapacity; ++i)
    {
        if (!recycledCache.snapshot(i, recycled))
        {
            return 22;
        }
        if (recycled.beacon.bssid.bytes[5] == 0xfe)
        {
            foundNewBssid = true;
            if (!recycled.beacon.hiddenSsid ||
                (recycled.beacon.ssidLength != 0U))
            {
                return 23;
            }
        }
    }
    if (!foundNewBssid)
    {
        return 24;
    }

    // An actual visible SSID from the *same* BSSID may still be retained
    // when its subsequent advertisement hides the name.
    if (recycledCache.observe(visible, ScanObservation {sizeof(visible), -35,
                                                        1001}) != Result::Ok ||
        recycledCache.observe(
            hidden, ScanObservation {sizeof(hidden), -35, 1002}) != Result::Ok)
    {
        return 25;
    }
    bool preservedSameBssid = false;
    for (size_t i = 0; i < ScanCache::kCapacity; ++i)
    {
        if (!recycledCache.snapshot(i, recycled))
        {
            return 26;
        }
        if (recycled.beacon.bssid.bytes[5] == 0xfe)
        {
            preservedSameBssid = !recycled.beacon.hiddenSsid &&
                                 recycled.beacon.ssidLength == 4 &&
                                 recycled.beacon.ssid[0] == 'T';
        }
    }
    if (!preservedSameBssid)
    {
        return 27;
    }

    // RX callbacks can arrive with a timestamp older than an already cached
    // observation. Such a delayed frame must not replace a newer BSSID's
    // security/channel/SSID metadata or roll its expiration clock backwards.
    static ScanCache chronologicalCache;
    uint8_t ordered[kBeaconBytes] {};
    makeBeacon(ordered, 6);
    if (chronologicalCache.observe(
            ordered, ScanObservation {sizeof(ordered), -40, 2000}) !=
        Result::Ok)
    {
        return 28;
    }
    makeBeacon(ordered, 11);
    if (chronologicalCache.observe(
            ordered, ScanObservation {sizeof(ordered), -25, 1999}) !=
            Result::InvalidFrame ||
        !chronologicalCache.snapshot(0, recycled) ||
        recycled.lastSeenMs != 2000 || recycled.beacon.channel != 6 ||
        recycled.rssiDbm != -40)
    {
        return 28;
    }

    // With the cache full, a frame older than the newest observation must
    // not displace any BSSID just because another cached entry is older.
    for (size_t i = 0; i < ScanCache::kCapacity - 1; ++i)
    {
        makeBeacon(ordered, 6);
        ordered[15] = ordered[21] = static_cast<uint8_t>(i + 1);
        if (chronologicalCache.observe(
                ordered, ScanObservation {sizeof(ordered), -40, 2001 + i}) !=
            Result::Ok)
        {
            return 29;
        }
    }
    makeBeacon(ordered, 6);
    ordered[15] = ordered[21] = 0xfdU;
    if (chronologicalCache.size() != ScanCache::kCapacity ||
        chronologicalCache.observe(
            ordered, ScanObservation {sizeof(ordered), -20, 2030}) !=
            Result::InvalidFrame ||
        chronologicalCache.size() != ScanCache::kCapacity)
    {
        return 29;
    }
    for (size_t i = 0; i < ScanCache::kCapacity; ++i)
    {
        if (!chronologicalCache.snapshot(i, recycled) ||
            recycled.beacon.bssid.bytes[5] == 0xfdU)
        {
            return 29;
        }
    }
    // Hidden beacons also use nonempty, all-zero SSID IEs. These are not
    // visible four-byte NUL network names and must never be selectable or
    // exposed to the native scan-results iterator.
    uint8_t zeroNamed[kBeaconBytes] {};
    makeBeacon(zeroNamed, 6);
    for (size_t i = 38; i < 42; ++i)
    {
        zeroNamed[i] = 0;
    }
    Beacon zeroParsed {};
    static ScanCache zeroNameCache;
    const uint8_t nullName[4] {};
    Bss zeroSelected {};
    static LegacyScanBridge zeroNameBridge;
    ScanBridgeTicket zeroNameTicket {};
    if (parseBeacon(zeroNamed, sizeof(zeroNamed), zeroParsed) != Result::Ok ||
        !zeroParsed.hiddenSsid || zeroParsed.ssidLength != 4 ||
        zeroNameCache.observe(zeroNamed,
                              ScanObservation {sizeof(zeroNamed), -38, 3000}) !=
            Result::Ok ||
        zeroNameCache.strongest(nullName,
                                ScanSelection {sizeof(nullName), 6, true, true},
                                zeroSelected) ||
        zeroNameCache.strongest(nullptr, ScanSelection {0, 6, true, true},
                                zeroSelected) ||
        zeroNameBridge.beginScan(1, zeroNameTicket) != ScanBridgeResult::Ok ||
        zeroNameBridge.completeScan(zeroNameCache, zeroNameTicket, true) !=
            ScanBridgeResult::Ok ||
        zeroNameBridge.status().resultCount != 0 ||
        zeroNameBridge.status().rejectedEntries != 1)
    {
        return 31;
    }
    return 0;
}
