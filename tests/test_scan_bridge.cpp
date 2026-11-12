// Copyright:
//   - Copyright © 2026 Alberto Villa Osorno
// SPDX-License-Identifier:
//   - MIT
// Confidential:
//   - false
// License-File:
//   - LICENSE-MIT
// Provenance:
//   - SimpleATH original; independently developed or locally authored
//
// Boundary-Contract:
// - Owns:
//   - Offline regression cases for scan bridge.
// - Must-Not:
//   - Require physical hardware, mutate installed drivers, or suppress
//     failures.
// - Allows:
//   - Inputs: isolated fixtures and reproducible source-under-test inputs.
//   - Outputs: assertions and observable regression verdicts.
//   - Side effects: test-local temporary files and bounded subprocesses only.
// - Split-When:
//   - A separate protocol stage needs independent validation and ownership.
// - Merge-When:
//   - The caller directly owns this narrow contract without reuse.
// - Summary:
//   - Offline regression cases for scan bridge.
// - Description:
//   - Implements or verifies the test_scan_bridge source boundary.
// - Usage:
//   - Executed by offline host test discovery or the native test harness.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Offline regression cases for scan bridge.
// Offline portable scan pipeline; this is NOT Apple80211, RF or device I/O.
#include "wifi/Frames.hpp"
#include "wifi/LegacyScanBridge.hpp"
#include "wifi/ScanCache.hpp"
#include "wifi/Station.hpp"
#include "wifi/WifiEngine.hpp"
#include "wifi/crypto/Wpa2CryptoAdapter.hpp"
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace
{
    // Named scanner-fixture values keep synthetic channel, timestamp and
    // malformed-frame bytes explicit at their use sites.
    constexpr auto kFixtureInt5 = 5;
    constexpr auto kFixtureInt6 = 6;
    constexpr auto kFixtureInt7 = 7;
    constexpr auto kFixtureInt8 = 8;
    constexpr auto kFixtureInt9 = 9;
    constexpr auto kFixtureInt10 = 10;
    constexpr auto kFixtureInt11 = 11;
    constexpr auto kFixtureInt12 = 12;
    constexpr auto kFixtureInt13 = 13;
    constexpr auto kFixtureInt14 = 14;
    constexpr auto kFixtureInt15 = 15;
    constexpr auto kFixtureHex10 = 0x10;
    constexpr auto kFixtureInt16 = 16;
    constexpr auto kFixtureHex11 = 0x11;
    constexpr auto kFixtureInt17 = 17;
    constexpr auto kFixtureInt18 = 18;
    constexpr auto kFixtureInt19 = 19;
    constexpr auto kFixtureInt20 = 20;
    constexpr auto kFixtureInt21 = 21;
    constexpr auto kFixtureInt22 = 22;
    constexpr auto kFixtureInt23 = 23;
    constexpr auto kFixtureInt24 = 24;
    constexpr auto kFixtureInt25 = 25;
    constexpr auto kFixtureInt26 = 26;
    constexpr auto kFixtureInt27 = 27;
    constexpr auto kFixtureInt28 = 28;
    constexpr auto kFixtureInt29 = 29;
    constexpr auto kFixtureInt30 = 30;
    constexpr auto kFixtureInt31 = 31;
    constexpr auto kFixtureInt32 = 32;
    constexpr auto kFixtureInt33 = 33;
    constexpr auto kFixtureHex22 = 0x22;
    constexpr auto kFixtureInt34 = 34;
    constexpr auto kFixtureInt35 = 35;
    constexpr auto kFixtureInt36 = 36;
    constexpr auto kFixtureInt37 = 37;
    constexpr auto kFixtureInt38 = 38;
    constexpr auto kFixtureInt39 = 39;
    constexpr auto kFixtureInt40 = 40;
    constexpr auto kFixtureInt41 = 41;
    constexpr auto kFixtureInt42 = 42;
    constexpr auto kFixtureInt43 = 43;
    constexpr auto kFixtureInt44 = 44;
    constexpr auto kFixtureInt45 = 45;
    constexpr auto kFixtureInt46 = 46;
    constexpr auto kFixtureInt47 = 47;
    constexpr auto kFixtureInt48 = 48;
    constexpr auto kFixtureHex33 = 0x33;
    constexpr auto kFixtureInt60 = 60;
    constexpr auto kFixtureHex44 = 0x44;
    constexpr auto kFixtureInt68 = 68;
    constexpr auto kFixtureHex55 = 0x55;
    constexpr auto kFixtureInt100 = 100;
    constexpr auto kFixtureInt101 = 101;
    constexpr auto kFixtureHex66 = 0x66;
    constexpr auto kFixtureInt110 = 110;
    constexpr auto kFixtureInt119 = 119;
    constexpr auto kFixtureInt120 = 120;
    constexpr auto kFixtureHex7e = 0x7e;
    constexpr auto kFixtureHex7f = 0x7f;
    constexpr auto kFixtureHex80 = 0x80;
    constexpr auto kFixtureHex82 = 0x82;
    constexpr auto kFixtureHex84 = 0x84;
    constexpr auto kFixtureInt150 = 150;
    constexpr auto kFixtureInt151 = 151;
    constexpr auto kFixtureInt200 = 200;
    constexpr auto kFixtureInt201 = 201;
    constexpr auto kFixtureHexfe = 0xfe;
    constexpr auto kFixtureHexff = 0xff;
    constexpr auto kFixtureInt256 = 256;
    constexpr auto kFixtureInt1000 = 1000;
    constexpr auto kFixtureInt1001 = 1001;
    constexpr auto kFixtureInt1002 = 1002;
    constexpr auto kFixtureInt1100 = 1100;
    constexpr auto kFixtureInt1200 = 1200;
    constexpr auto kFixtureInt1290 = 1290;
    constexpr auto kFixtureInt1300 = 1300;
    constexpr auto kFixtureInt1301 = 1301;
    constexpr auto kFixtureInt1999 = 1999;
    constexpr auto kFixtureInt2000 = 2000;
    constexpr auto kFixtureInt2001 = 2001;
    constexpr auto kFixtureInt2030 = 2030;
    constexpr auto kFixtureInt3000 = 3000;

    template <typename T, size_t N> T *arrayData(T (&array)[N])
    {
        return &array[0U];
    }

    constexpr size_t kBeaconBytes = 49;
    constexpr uint8_t kSyntheticRecycledBssid = 0xfdU;

    template <typename T, size_t N> T &arrayAt(T (&array)[N], size_t index)
    {
        for (T &entry : array)
        {
            if (index == 0U)
            {
                return entry;
            }
            --index;
        }
        __builtin_trap();
    }

    template <typename T> const uint8_t *byteView(const T &object)
    {
        const T *const original = &object;
        const uint8_t *result = nullptr;
        static_assert(sizeof(const T *) == sizeof(const uint8_t *),
                      "The fixture needs native host pointer width");
        std::memcpy(static_cast<void *>(&result),
                    static_cast<const void *>(&original), sizeof(result));
        return result;
    }

    template <typename T> uint8_t *byteView(T &object)
    {
        const T *const original = &object;
        uint8_t *result = nullptr;
        static_assert(sizeof(T *) == sizeof(uint8_t *),
                      "The fixture needs native host pointer width");
        std::memcpy(static_cast<void *>(&result),
                    static_cast<const void *>(&original), sizeof(result));
        return result;
    }

    template <size_t N> void makeBeacon(uint8_t (&frame)[N], uint8_t channel)
    {
        static_assert(N >= kBeaconBytes, "Beacon fixture capacity");
        for (size_t index = 0; index < kBeaconBytes; ++index)
        {
            arrayAt(frame, index) = 0;
        }
        arrayAt(frame, 0) = kFixtureHex80; // Beacon management subtype.
        for (size_t index = 4; index < kFixtureInt10; ++index)
        {
            arrayAt(frame, index) = kFixtureHexff; // Broadcast receiver.
        }
        arrayAt(frame, kFixtureInt10) = arrayAt(frame, kFixtureInt16) =
            0x02; // Source/BSSID unicast and identical.
        arrayAt(frame, kFixtureInt11) = arrayAt(frame, kFixtureInt17) =
            kFixtureHex11;
        arrayAt(frame, kFixtureInt12) = arrayAt(frame, kFixtureInt18) =
            kFixtureHex22;
        arrayAt(frame, kFixtureInt13) = arrayAt(frame, kFixtureInt19) =
            kFixtureHex33;
        arrayAt(frame, kFixtureInt14) = arrayAt(frame, kFixtureInt20) =
            kFixtureHex44;
        arrayAt(frame, kFixtureInt15) = arrayAt(frame, kFixtureInt21) =
            kFixtureHex55;
        arrayAt(frame, kFixtureInt32) =
            kFixtureInt100; // Beacon interval, little-endian TU.
        arrayAt(frame, kFixtureInt34) =
            0x01; // Infrastructure capability, open BSS.
        arrayAt(frame, kFixtureInt36) = 0; // SSID element.
        arrayAt(frame, kFixtureInt37) = 4;
        arrayAt(frame, kFixtureInt38) = 'T';
        arrayAt(frame, kFixtureInt39) = 'e';
        arrayAt(frame, kFixtureInt40) = 's';
        arrayAt(frame, kFixtureInt41) = 't';
        arrayAt(frame, kFixtureInt42) = 1; // Supported rates.
        arrayAt(frame, kFixtureInt43) = 2;
        arrayAt(frame, kFixtureInt44) = kFixtureHex82;
        arrayAt(frame, kFixtureInt45) = kFixtureHex84;
        arrayAt(frame, kFixtureInt46) = 3; // DS channel parameter.
        arrayAt(frame, kFixtureInt47) = 1;
        arrayAt(frame, kFixtureInt48) = channel;
    }

    bool isTestBss(const simpleath::ieee80211::NativeBssSnapshot &entry,
                   uint8_t channel)
    {
        using namespace simpleath::ieee80211;
        return entry.ssidLength == 4 && entry.ssid[0] == 'T' &&
               entry.ssid[1] == 'e' && entry.ssid[2] == 's' &&
               entry.ssid[3] == 't' && entry.bssid.bytes[0] == 0x02 &&
               entry.bssid.bytes[kFixtureInt5] == kFixtureHex55 &&
               entry.channel == channel &&
               entry.beaconIntervalTu == kFixtureInt100 &&
               entry.rateCount == 2 && entry.rates[0] == kFixtureHex82 &&
               entry.rates[1] == kFixtureHex84 &&
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
        if (engine.beginChannelScan(
                {arrayData(invalidChannel), 1, kFixtureInt100, true, true},
                generation) != EngineResult::InvalidInput ||
            engine.beginChannelScan(
                {arrayData(invalidDwell), 1, kFixtureInt100, true, true},
                generation) != EngineResult::InvalidInput ||
            engine.beginChannelScan(
                {arrayData(bad), 2, kFixtureInt100, true, true}, generation) !=
                EngineResult::InvalidInput ||
            engine.beginChannelScan(
                {arrayData(channels), 2, kFixtureInt100, false, true},
                generation) != EngineResult::RadioNotReady ||
            engine.beginChannelScan(
                {arrayData(channels), 2, kFixtureInt100, true, true},
                generation) != EngineResult::Ok ||
            generation == 0)
        {
            return false;
        }
        ScanProgress step {};
        EngineAction action {};
        const InputTrust verified {true, true, true, false};
        uint8_t frame[kBeaconBytes] {};
        makeBeacon(frame, kFixtureInt6);
        if (engine.pollChannelScan(kFixtureInt100, step) != EngineResult::Ok ||
            step.kind != ScanProgressKind::TuneRequired ||
            step.channel != kFixtureInt6 || step.generation != generation ||
            engine.beginChannelScan(
                {arrayData(channels), 2, kFixtureInt101, true, true},
                generation) != EngineResult::InvalidState ||
            engine.acknowledgeChannelTune(
                {generation, kFixtureInt6, kFixtureInt100, false}) !=
                EngineResult::RadioNotReady ||
            engine.acceptRx(arrayData(frame), sizeof(frame), verified,
                            {-kFixtureInt30, kFixtureInt100}, nullptr, 0,
                            action) != EngineResult::NoAction ||
            engine.scan().size() != 0 ||
            engine.acknowledgeChannelTune(
                {generation + 1, kFixtureInt6, kFixtureInt100, true}) !=
                EngineResult::InvalidState ||
            engine.acknowledgeChannelTune(
                {generation, kFixtureInt11, kFixtureInt100, true}) !=
                EngineResult::InvalidState ||
            engine.acknowledgeChannelTune(
                {generation, kFixtureInt6, kFixtureInt100, true}) !=
                EngineResult::Ok)
        {
            return false;
        }
        makeBeacon(frame, kFixtureInt11);
        if (engine.acceptRx(arrayData(frame), sizeof(frame), verified,
                            {-kFixtureInt30, kFixtureInt110}, nullptr, 0,
                            action) != EngineResult::NoAction ||
            engine.pollChannelScan(kFixtureInt119, step) != EngineResult::Ok ||
            step.kind != ScanProgressKind::Dwelling ||
            step.deadlineMs != kFixtureInt120 || engine.scan().size() != 0)
        {
            return false;
        }
        makeBeacon(frame, kFixtureInt6);
        if (engine.acceptRx(arrayData(frame), sizeof(frame), verified,
                            {-kFixtureInt30, kFixtureInt110}, nullptr, 0,
                            action) != EngineResult::NoAction ||
            engine.scan().size() != 0)
        {
            return false;
        }
        const Mac station {{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}};
        const uint8_t ssid[] {'T', 'e', 's', 't'};
        if (engine.acceptRx(arrayData(frame), sizeof(frame), verified,
                            {-kFixtureInt30, kFixtureInt119}, nullptr, 0,
                            action) != EngineResult::Ok ||
            action.kind != ActionKind::ScanCacheUpdated ||
            engine.scan().size() != 1 ||
            engine.chooseNetwork(station, arrayData(ssid), sizeof(ssid),
                                 kFixtureInt6, true, false,
                                 nullptr) != EngineResult::InvalidState ||
            engine.pollChannelScan(kFixtureInt120, step) != EngineResult::Ok ||
            step.kind != ScanProgressKind::TuneRequired ||
            step.channel != kFixtureInt11 ||
            engine.acceptRx(arrayData(frame), sizeof(frame), verified,
                            {-kFixtureInt30, kFixtureInt120}, nullptr, 0,
                            action) != EngineResult::NoAction ||
            engine.acknowledgeChannelTune(
                {generation, kFixtureInt11, kFixtureInt119, true}) !=
                EngineResult::InvalidInput ||
            engine.acknowledgeChannelTune(
                {generation, kFixtureInt11, kFixtureInt120, true}) !=
                EngineResult::Ok)
        {
            return false;
        }
        makeBeacon(frame, kFixtureInt11);
        if (engine.acceptRx(arrayData(frame), sizeof(frame), verified,
                            {-kFixtureInt30, kFixtureInt150}, nullptr, 0,
                            action) != EngineResult::NoAction ||
            engine.pollChannelScan(kFixtureInt150, step) != EngineResult::Ok ||
            step.kind != ScanProgressKind::Complete ||
            step.generation != generation ||
            engine.pollChannelScan(kFixtureInt151, step) !=
                EngineResult::NoAction ||
            engine.chooseNetwork(station, arrayData(ssid), sizeof(ssid),
                                 kFixtureInt6, true, false,
                                 nullptr) != EngineResult::Ok ||
            engine.cancelChannelScan(generation) != EngineResult::InvalidState)
        {
            return false;
        }
        engine.radioStopped(kFixtureInt151, true);
        uint64_t second = 0;
        if (engine.beginChannelScan(
                {arrayData(channels), 2, kFixtureInt200, true, true}, second) !=
                EngineResult::Ok ||
            second == generation ||
            engine.acknowledgeChannelTune(
                {generation, kFixtureInt6, kFixtureInt200, true}) !=
                EngineResult::InvalidState ||
            engine.cancelChannelScan(second) != EngineResult::Ok ||
            engine.pollChannelScan(kFixtureInt201, step) !=
                EngineResult::NoAction ||
            engine.cancelChannelScan(second) != EngineResult::InvalidState ||
            engine.chooseNetwork(station, arrayData(ssid), sizeof(ssid),
                                 kFixtureInt6, true, false,
                                 nullptr) != EngineResult::InvalidState)
        {
            return false;
        }
        if (engine.beginChannelScan(
                {arrayData(channels), 2, UINT64_MAX - 4, true, true}, second) !=
                EngineResult::Ok ||
            engine.pollChannelScan(UINT64_MAX - 4, step) != EngineResult::Ok ||
            engine.acknowledgeChannelTune({
                second,
                kFixtureInt6,
                UINT64_MAX - 4,
                true,
            }) != EngineResult::InvalidInput)
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
        makeBeacon(advertisement, kFixtureInt6);
        advertisement[kFixtureInt34] = static_cast<uint8_t>(
            static_cast<unsigned>(advertisement[kFixtureInt34]) |
            static_cast<unsigned>(kFixtureHex10)); // RSN privacy capability.
        for (size_t i = 0; i < sizeof(rsnIe); ++i)
        {
            arrayAt(advertisement, kBeaconBytes + i) = arrayAt(rsnIe, i);
        }
        const Mac weaker {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        const Mac stronger {{0x02, 0x11, 0x22, 0x33, 0x44, 0x66}};
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        const uint8_t ssid[] {'T', 'e', 's', 't'};
        const ScanSelection allowed {sizeof(ssid), 6, false, true};
        ScanCache cache;
        Bss result {};
        if (cache.observe(arrayData(advertisement), {
                                                        sizeof(advertisement),
                                                        -kFixtureInt68,
                                                        kFixtureInt100,
                                                    }) != Result::Ok)
        {
            return false;
        }
        advertisement[kFixtureInt15] = advertisement[kFixtureInt21] =
            stronger.bytes[kFixtureInt5];
        if (cache.observe(arrayData(advertisement),
                          {
                              sizeof(advertisement),
                              -kFixtureInt21,
                              kFixtureInt101,
                          }) != Result::Ok ||
            !cache.strongest(arrayData(ssid), allowed, result) ||
            !sameMac(result.beacon.bssid, stronger) ||
            !cache.matchingBssid(weaker, arrayData(ssid), allowed, result) ||
            !sameMac(result.beacon.bssid, weaker))
        {
            return false;
        }
        result.rssiDbm = kFixtureInt12;
        const Mac unknown {{0x02, 0x11, 0x22, 0x33, 0x44, 0x77}};
        if (cache.matchingBssid(unknown, arrayData(ssid), allowed, result) ||
            result.occupied || result.rssiDbm != 0 ||
            cache.matchingBssid(weaker, arrayData(ssid),
                                {sizeof(ssid), kFixtureInt11, false, true},
                                result) ||
            cache.matchingBssid(weaker, arrayData(ssid),
                                {sizeof(ssid), kFixtureInt6, true, false},
                                result))
        {
            return false;
        }
        // Reject aliased output without corrupting the caller's BSSID.
        Bss aliased {};
        aliased.beacon.bssid = weaker;
        if (cache.matchingBssid(aliased.beacon.bssid, arrayData(ssid), allowed,
                                aliased) ||
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
        advertisement[kFixtureInt15] = advertisement[kFixtureInt21] =
            weaker.bytes[kFixtureInt5];
        if (native.acceptRx(arrayData(advertisement), sizeof(advertisement),
                            verified, {-kFixtureInt68, kFixtureInt200}, nullptr,
                            0, action) != EngineResult::Ok)
        {
            return false;
        }
        advertisement[kFixtureInt15] = advertisement[kFixtureInt21] =
            stronger.bytes[kFixtureInt5];
        if (native.acceptRx(arrayData(advertisement), sizeof(advertisement),
                            verified, {-kFixtureInt21, kFixtureInt201}, nullptr,
                            0, action) != EngineResult::Ok ||
            native.chooseNetworkForOsSupplicant(
                station, unknown, arrayData(ssid), sizeof(ssid), kFixtureInt6,
                true) != EngineResult::NoMatchingBss ||
            native.chooseNetworkForOsSupplicant(
                station, weaker, arrayData(ssid), sizeof(ssid), kFixtureInt6,
                false) != EngineResult::NoMatchingBss ||
            native.chooseNetworkForOsSupplicant(
                weaker, weaker, arrayData(ssid), sizeof(ssid), kFixtureInt6,
                true) != EngineResult::InvalidInput ||
            native.chooseNetwork(station, arrayData(ssid), sizeof(ssid),
                                 kFixtureInt6, false, true,
                                 nullptr) != EngineResult::CryptoUnavailable ||
            native.chooseNetworkForOsSupplicant(
                station, weaker, arrayData(ssid), sizeof(ssid), kFixtureInt6,
                true) != EngineResult::Ok ||
            !native.osSupplicantOwnsWpa2() ||
            native.stationState() != StationState::CandidateSelected ||
            native.chooseNetworkForOsSupplicant(
                station, stronger, arrayData(ssid), sizeof(ssid), kFixtureInt6,
                true) != EngineResult::InvalidState)
        {
            return false;
        }
        uint8_t outbound[kFixtureInt256] {};
        if (native.requestAuthentication(kFixtureInt7, arrayData(outbound),
                                         sizeof(outbound),
                                         action) != EngineResult::Ok ||
            action.kind != ActionKind::TransmitAuthentication ||
            action.bytes < kFixtureInt24 || outbound[4] != weaker.bytes[0] ||
            outbound[kFixtureInt9] != weaker.bytes[kFixtureInt5])
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
        makeBeacon(advertised, kFixtureInt6);
        if (cache.observe(arrayData(advertised), ScanObservation {
                                                     sizeof(advertised),
                                                     -kFixtureInt60,
                                                     1,
                                                 }) != Result::Ok)
        {
            return false;
        }

        // A stronger AP with the same SSID requires an unknown mandatory
        // basic rate, even though another rate overlaps local capabilities.
        advertised[kFixtureInt15] = advertised[kFixtureInt21] = kFixtureHex66;
        advertised[kFixtureInt44] = kFixtureHexff;
        advertised[kFixtureInt45] = kFixtureHex82;
        if (cache.observe(arrayData(advertised), ScanObservation {
                                                     sizeof(advertised),
                                                     -kFixtureInt25,
                                                     2,
                                                 }) != Result::Ok)
        {
            return false;
        }
        const uint8_t ssid[] {'T', 'e', 's', 't'};
        Bss choice {};
        if (!cache.strongest(
                arrayData(ssid),
                ScanSelection {sizeof(ssid), kFixtureInt6, true, false},
                choice) ||
            choice.beacon.bssid.bytes[kFixtureInt5] != kFixtureHex55)
        {
            return false;
        }

        // Unknown optional rates do not prevent joining when a compatible
        // rate remains; a stronger compatible AP should still win.
        advertised[kFixtureInt44] = kFixtureHex7f;
        if (cache.observe(arrayData(advertised),
                          ScanObservation {
                              sizeof(advertised),
                              -kFixtureInt25,
                              3,
                          }) != Result::Ok ||
            !cache.strongest(
                arrayData(ssid),
                ScanSelection {sizeof(ssid), kFixtureInt6, true, false},
                choice) ||
            choice.beacon.bssid.bytes[kFixtureInt5] != kFixtureHex66)
        {
            return false;
        }

        // Optional rates alone are insufficient without any common rate.
        advertised[kFixtureInt45] = kFixtureHex7e;
        return cache.observe(
                   arrayData(advertised),
                   ScanObservation {sizeof(advertised), -kFixtureInt20, 4}) ==
                   Result::Ok &&
               cache.strongest(
                   arrayData(ssid),
                   ScanSelection {sizeof(ssid), kFixtureInt6, true, false},
                   choice) &&
               choice.beacon.bssid.bytes[kFixtureInt5] == kFixtureHex55;
    }
} // namespace

namespace
{
    // One synthetic owner shared across the sequential phases. Retain the
    // same persistent cache and bridge while resetting only local test data.
    struct ScanHarness
    {
            simpleath::ieee80211::ScanCache cache;
            simpleath::ieee80211::LegacyScanBridge bridge;
            uint8_t beacon[kBeaconBytes] {};
            simpleath::ieee80211::NativeBssSnapshot entry {};
            simpleath::ieee80211::ScanBridgeTicket ticket {};
            simpleath::ieee80211::Bss recycled {};
            simpleath::ieee80211::ScanBridgeTicket completedTicket {};
            simpleath::ieee80211::ScanBridgeTicket ignored {};
            simpleath::ieee80211::ScanBridgeCompletion completed {};
            simpleath::ieee80211::ScanCache recycledCache;
            uint8_t visible[kBeaconBytes] {};
            uint8_t hidden[kFixtureInt45] {};
    };

    int checkScanLifecycleStart(ScanHarness &fixture)
    {
        using namespace simpleath::ieee80211;
        auto &cache = fixture.cache;
        auto &bridge = fixture.bridge;
        auto &beacon = fixture.beacon;
        auto &entry = fixture.entry;
        auto &ticket = fixture.ticket;
        auto &completedTicket = fixture.completedTicket;
        auto &ignored = fixture.ignored;
        auto &completed = fixture.completed;

        // Persistent owner-style allocations, no OS driver or bus interactions.
        // A forged borrowed RX source from inside the cache must not be parsed
        // as a real air frame or erase cached BSS metadata.
        const auto *cacheBytes = byteView(cache);
        if (cache.observe(cacheBytes,
                          ScanObservation {kBeaconBytes, -kFixtureInt41, 1}) !=
                Result::InvalidFrame ||
            cache.size() != 0)
        {
            return kFixtureInt18;
        }
        // Ordinary missing-SSID lookups clear a stale output, but a caller
        // accidentally pointing its SSID into that output must leave it intact.
        Bss aliasedResult {};
        aliasedResult.rssiDbm = kFixtureInt37;
        const auto *badSsid = byteView(aliasedResult);
        if (cache.strongest(badSsid,
                            ScanSelection {4, kFixtureInt6, true, true},
                            aliasedResult) ||
            aliasedResult.rssiDbm != kFixtureInt37 || cache.size() != 0)
        {
            return kFixtureInt19;
        }
        makeBeacon(beacon, kFixtureInt6);
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
        // ticket. Otherwise a status poll can orphan the active scan and
        // prevent its valid completion without any radio failure.
        const ScanBridgeTicket liveTicket = ticket;
        if (bridge.beginScan(2, ticket) != ScanBridgeResult::ScanInProgress ||
            ticket.generation != liveTicket.generation ||
            ticket.serial != liveTicket.serial)
        {
            return kFixtureInt32;
        }
        if (cache.observe(arrayData(beacon),
                          ScanObservation {
                              sizeof(beacon),
                              -kFixtureInt41,
                              kFixtureInt1000,
                          }) != Result::Ok ||
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
            return kFixtureInt33;
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
            return kFixtureInt34;
        }
        completedTicket = ticket;
        if (bridge.next(completedTicket, entry) != ScanBridgeResult::Ok ||
            !isTestBss(entry, kFixtureInt6) || !entry.signalMeasured ||
            entry.rssiDbm != -kFixtureInt41 ||
            bridge.next(completedTicket, entry) != ScanBridgeResult::NoResult ||
            (entry.ssidLength != 0U))
        {
            return 4;
        }

        return 0;
    }

    int checkScanLifecycleFinish(ScanHarness &fixture)
    {
        using namespace simpleath::ieee80211;
        auto &cache = fixture.cache;
        auto &bridge = fixture.bridge;
        auto &beacon = fixture.beacon;
        auto &entry = fixture.entry;
        auto &ticket = fixture.ticket;
        const auto &completedTicket = fixture.completedTicket;
        auto &ignored = fixture.ignored;
        auto &completed = fixture.completed;

        // The native UI-facing snapshot is a value copy: neither clearing a
        // live cache nor starting a new radio operation can invent new scan
        // results.
        cache.clear();
        if (bridge.rewind(completedTicket) != ScanBridgeResult::Ok ||
            bridge.beginScan(2, ticket) != ScanBridgeResult::Ok ||
            bridge.next(completedTicket, entry) != ScanBridgeResult::Ok ||
            !isTestBss(entry, kFixtureInt6))
        {
            return kFixtureInt5;
        }
        if (bridge.completeScan(cache, ticket, false) !=
                ScanBridgeResult::InvalidState ||
            bridge.completion(completed) != ScanBridgeResult::Ok ||
            completed.succeeded || completed.resultCount != 0 ||
            // An RF interruption keeps its failure intent until the native
            // SCAN_DONE handoff is acknowledged. The old snapshot cannot
            // acknowledge it or make a successor physical scan start early.
            bridge.beginScan(3, ignored) != ScanBridgeResult::EventPending ||
            bridge.acknowledgeCompletion(completedTicket) !=
                ScanBridgeResult::InvalidState ||
            bridge.beginScan(3, ignored) != ScanBridgeResult::EventPending ||
            bridge.acknowledgeCompletion(ticket) != ScanBridgeResult::Ok)
        {
            return kFixtureInt6;
        }
        if (bridge.rewind(completedTicket) != ScanBridgeResult::Ok ||
            bridge.next(completedTicket, entry) != ScanBridgeResult::Ok ||
            !isTestBss(entry, kFixtureInt6) ||
            bridge.beginScan(2, ignored) != ScanBridgeResult::InvalidArgument)
        {
            return kFixtureInt7;
        }

        // An invalid channel never becomes a new accepted BSS. A genuinely
        // completed empty scan revokes the previous snapshot, unlike a failure.
        makeBeacon(beacon, kFixtureInt15);
        if (cache.observe(arrayData(beacon),
                          ScanObservation {
                              sizeof(beacon),
                              -kFixtureInt30,
                              kFixtureInt1100,
                          }) != Result::InvalidElement ||
            bridge.beginScan(3, ticket) != ScanBridgeResult::Ok ||
            bridge.completeScan(cache, ticket, true) != ScanBridgeResult::Ok ||
            bridge.acknowledgeCompletion(ticket) != ScanBridgeResult::Ok ||
            bridge.next(ticket, entry) != ScanBridgeResult::NoResult ||
            (entry.ssidLength != 0U) || bridge.status().resultCount != 0 ||
            !bridge.status().completeSnapshotAvailable ||
            bridge.next(completedTicket, entry) !=
                ScanBridgeResult::InvalidState ||
            (entry.ssidLength != 0U))
        {
            return kFixtureInt8;
        }

        // The next completed scan contains actual validated frame data, but is
        // still not proof that a native Apple80211 interface or radio exists.
        makeBeacon(beacon, kFixtureInt11);
        if (cache.observe(arrayData(beacon),
                          ScanObservation {
                              sizeof(beacon),
                              kFixtureInt18,
                              kFixtureInt1200,
                          }) != Result::Ok ||
            bridge.beginScan(4, ticket) != ScanBridgeResult::Ok ||
            bridge.completeScan(cache, ticket, true) != ScanBridgeResult::Ok ||
            bridge.acknowledgeCompletion(ticket) != ScanBridgeResult::Ok ||
            bridge.next(ticket, entry) != ScanBridgeResult::Ok ||
            !isTestBss(entry, kFixtureInt11) || entry.signalMeasured ||
            entry.rssiDbm != 0)
        {
            return kFixtureInt9;
        }

        return 0;
    }

    int checkWifiEngineAdmission(ScanHarness &fixture)
    {
        using namespace simpleath::ieee80211;
        auto &bridge = fixture.bridge;
        auto &beacon = fixture.beacon;
        auto &entry = fixture.entry;
        auto &ticket = fixture.ticket;

        // Finally exercise the higher portable integration boundary, rather
        // than feeding the scan cache directly: a synthetic RX trust report
        // must first pass WifiEngine admission and produce an explicit
        // cache-update action. These booleans are test doubles; no real
        // PCI/DMA/FCS authority exists.
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
            return kFixtureInt30;
        }
        EngineAction action {};
        const InputTrust untrusted {true, true, false, false};
        const InputTrust syntheticVerifiedRx {true, true, true, false};

        // A caller cannot pass the engine's own persistent crypto/station bytes
        // as borrowed RX/DMA input, even if they accidentally resemble a frame.
        // Reject before clearing the caller's action or entering the parser.
        action.kind = ActionKind::LinkLost;
        action.bytes = kFixtureInt17;
        const auto *aliasedOwnerFrame = byteView(engine);
        if (engine.acceptRx(aliasedOwnerFrame, kBeaconBytes,
                            syntheticVerifiedRx,
                            {-kFixtureInt40, kFixtureInt1290}, nullptr, 0,
                            action) != EngineResult::InvalidInput ||
            action.kind != ActionKind::LinkLost ||
            action.bytes != kFixtureInt17 || engine.scan().size() != 0)
        {
            return kFixtureInt16;
        }
        if (engine.encodeOutgoingEthernet(
                aliasedOwnerFrame, kBeaconBytes, 1, syntheticVerifiedRx,
                nullptr, 0, action) != EngineResult::InvalidInput ||
            action.kind != ActionKind::LinkLost ||
            action.bytes != kFixtureInt17 || engine.scan().size() != 0)
        {
            return kFixtureInt17;
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

        auto *aliasedFrame = byteView(aliased);
        uint8_t malformedBeacon[kBeaconBytes] {};
        makeBeacon(malformedBeacon, kFixtureInt11);
        std::memcpy(static_cast<void *>(aliasedFrame),
                    static_cast<const void *>(arrayData(malformedBeacon)),
                    sizeof(malformedBeacon));
        uint8_t preserved[kBeaconBytes] {};
        std::memcpy(static_cast<void *>(arrayData(preserved)),
                    static_cast<const void *>(aliasedFrame), sizeof(preserved));
        if (engine.acceptRx(aliasedFrame, kBeaconBytes, syntheticVerifiedRx,
                            {-kFixtureInt45, kFixtureInt1300}, nullptr, 0,
                            aliased.action) != EngineResult::InvalidInput ||
            engine.scan().size() != 0)
        {
            return kFixtureInt10;
        }
        if (std::memcmp(static_cast<const void *>(aliasedFrame),
                        static_cast<const void *>(arrayData(preserved)),
                        sizeof(preserved)) != 0)
        {
            return kFixtureInt10;
        }
        if (engine.acceptRx(
                arrayData(beacon), sizeof(beacon), syntheticVerifiedRx,
                {-kFixtureInt45, kFixtureInt1300}, arrayData(beacon),
                sizeof(beacon), action) != EngineResult::InvalidInput ||
            engine.scan().size() != 0)
        {
            return kFixtureInt10;
        }
        if (engine.startScan(false, true) != EngineResult::RadioNotReady ||
            engine.startScan(true, true) != EngineResult::Ok ||
            engine.acceptRx(arrayData(beacon), sizeof(beacon), untrusted,
                            {-kFixtureInt45, kFixtureInt1300}, nullptr, 0,
                            action) != EngineResult::InvalidInput ||
            action.kind != ActionKind::None || engine.scan().size() != 0)
        {
            return kFixtureInt10;
        }
        if (engine.acceptRx(arrayData(beacon), sizeof(beacon),
                            syntheticVerifiedRx,
                            {-kFixtureInt45, kFixtureInt1300}, nullptr, 0,
                            action) != EngineResult::Ok ||
            action.kind != ActionKind::ScanCacheUpdated ||
            action.nativeInterfaceUsable || engine.scan().size() != 1)
        {
            return kFixtureInt11;
        }
        if (bridge.beginScan(kFixtureInt5, ticket) != ScanBridgeResult::Ok ||
            bridge.completeScan(engine.scan(), ticket, true) !=
                ScanBridgeResult::Ok ||
            bridge.acknowledgeCompletion(ticket) != ScanBridgeResult::Ok ||
            bridge.next(ticket, entry) != ScanBridgeResult::Ok ||
            !isTestBss(entry, kFixtureInt11) || !entry.signalMeasured ||
            entry.rssiDbm != -kFixtureInt45)
        {
            return kFixtureInt12;
        }
        engine.radioStopped(kFixtureInt1301, true);
        if (bridge.rewind(ticket) != ScanBridgeResult::Ok ||
            engine.scan().size() != 0 ||
            bridge.next(ticket, entry) != ScanBridgeResult::Ok ||
            !isTestBss(entry, kFixtureInt11))
        {
            return kFixtureInt13;
        }
        return 0;
    }

    int checkBssRecyclingStart(ScanHarness &fixture)
    {
        using namespace simpleath::ieee80211;
        const auto &cache = fixture.cache;
        auto &bridge = fixture.bridge;
        auto &entry = fixture.entry;
        const auto &ticket = fixture.ticket;
        auto &recycled = fixture.recycled;
        auto &recycledCache = fixture.recycledCache;
        auto &visible = fixture.visible;
        auto &hidden = fixture.hidden;

        // A fresh controller lifetime can reuse an OS-request serial, not a
        // generation. A retired owner may not complete or expose its last BSS.
        bridge.clear();
        if (bridge.rewind(ticket) != ScanBridgeResult::InvalidState ||
            bridge.next(ticket, entry) != ScanBridgeResult::NoResult ||
            (entry.ssidLength != 0U))
        {
            return kFixtureInt14;
        }
        ScanBridgeTicket newLifetime {};
        if (bridge.beginScan(kFixtureInt5, newLifetime) !=
                ScanBridgeResult::Ok ||
            newLifetime.generation == ticket.generation ||
            bridge.completeScan(cache, ticket, true) !=
                ScanBridgeResult::InvalidState ||
            !bridge.status().radioScanRunning ||
            bridge.next(ticket, entry) != ScanBridgeResult::NoResult ||
            (entry.ssidLength != 0U))
        {
            return kFixtureInt15;
        }

        // A full cache may evict a different BSSID whose channel and RSN match.
        // The newcomer's hidden beacon must never inherit that older BSSID's
        // SSID.
        for (size_t i = 0; i < ScanCache::kCapacity; ++i)
        {
            makeBeacon(visible, kFixtureInt6);
            visible[kFixtureInt15] = visible[kFixtureInt21] =
                static_cast<uint8_t>(i + 1);
            if (recycledCache.observe(arrayData(visible), ScanObservation {
                                                              sizeof(visible),
                                                              -kFixtureInt40,
                                                              i + kFixtureInt10,
                                                          }) != Result::Ok)
            {
                return kFixtureInt20;
            }
        }
        makeBeacon(visible, kFixtureInt6);
        visible[kFixtureInt15] = visible[kFixtureInt21] = kFixtureHexfe;
        for (size_t i = 0; i < kFixtureInt38; ++i)
        {
            arrayAt(hidden, i) = arrayAt(visible, i);
        }
        hidden[kFixtureInt37] = 0; // Zero-length hidden SSID element.
        for (size_t i = 0; i < kFixtureInt7; ++i)
        {
            arrayAt(hidden, kFixtureInt38 + i) =
                arrayAt(visible, kFixtureInt42 + i);
        }
        if (recycledCache.observe(arrayData(hidden),
                                  ScanObservation {
                                      sizeof(hidden),
                                      -kFixtureInt35,
                                      kFixtureInt1000,
                                  }) != Result::Ok ||
            recycledCache.size() != ScanCache::kCapacity)
        {
            return kFixtureInt21;
        }
        bool foundNewBssid = false;
        for (size_t i = 0; i < ScanCache::kCapacity; ++i)
        {
            if (!recycledCache.snapshot(i, recycled))
            {
                return kFixtureInt22;
            }
            if (recycled.beacon.bssid.bytes[kFixtureInt5] == kFixtureHexfe)
            {
                foundNewBssid = true;
                if (!recycled.beacon.hiddenSsid ||
                    (recycled.beacon.ssidLength != 0U))
                {
                    return kFixtureInt23;
                }
            }
        }
        if (!foundNewBssid)
        {
            return kFixtureInt24;
        }

        return 0;
    }

    int checkBssRecyclingFinish(ScanHarness &fixture)
    {
        using namespace simpleath::ieee80211;
        auto &recycled = fixture.recycled;
        auto &recycledCache = fixture.recycledCache;
        auto &visible = fixture.visible;
        auto &hidden = fixture.hidden;

        // An actual visible SSID from the *same* BSSID may still be retained
        // when its subsequent advertisement hides the name.
        if (recycledCache.observe(arrayData(visible),
                                  ScanObservation {
                                      sizeof(visible),
                                      -kFixtureInt35,
                                      kFixtureInt1001,
                                  }) != Result::Ok ||
            recycledCache.observe(arrayData(hidden), ScanObservation {
                                                         sizeof(hidden),
                                                         -kFixtureInt35,
                                                         kFixtureInt1002,
                                                     }) != Result::Ok)
        {
            return kFixtureInt25;
        }
        bool preservedSameBssid = false;
        for (size_t i = 0; i < ScanCache::kCapacity; ++i)
        {
            if (!recycledCache.snapshot(i, recycled))
            {
                return kFixtureInt26;
            }
            if (recycled.beacon.bssid.bytes[kFixtureInt5] == kFixtureHexfe)
            {
                preservedSameBssid = !recycled.beacon.hiddenSsid &&
                                     recycled.beacon.ssidLength == 4 &&
                                     recycled.beacon.ssid[0] == 'T';
            }
        }
        if (!preservedSameBssid)
        {
            return kFixtureInt27;
        }

        return 0;
    }

    int checkChronologicalExpiry(ScanHarness &fixture)
    {
        using namespace simpleath::ieee80211;
        auto &recycled = fixture.recycled;

        // RX callbacks can arrive with a timestamp older than an already cached
        // observation. Such a delayed frame must not replace a newer BSSID's
        // security/channel/SSID metadata or roll its expiration clock
        // backwards.
        static ScanCache chronologicalCache;
        uint8_t ordered[kBeaconBytes] {};
        makeBeacon(ordered, kFixtureInt6);
        if (chronologicalCache.observe(arrayData(ordered), ScanObservation {
                                                               sizeof(ordered),
                                                               -kFixtureInt40,
                                                               kFixtureInt2000,
                                                           }) != Result::Ok)
        {
            return kFixtureInt28;
        }
        makeBeacon(ordered, kFixtureInt11);
        if (chronologicalCache.observe(arrayData(ordered),
                                       ScanObservation {
                                           sizeof(ordered),
                                           -kFixtureInt25,
                                           kFixtureInt1999,
                                       }) != Result::InvalidFrame ||
            !chronologicalCache.snapshot(0, recycled) ||
            recycled.lastSeenMs != kFixtureInt2000 ||
            recycled.beacon.channel != kFixtureInt6 ||
            recycled.rssiDbm != -kFixtureInt40)
        {
            return kFixtureInt28;
        }

        // With the cache full, a frame older than the newest observation must
        // not displace any BSSID just because another cached entry is older.
        for (size_t i = 0; i < ScanCache::kCapacity - 1; ++i)
        {
            makeBeacon(ordered, kFixtureInt6);
            ordered[kFixtureInt15] = ordered[kFixtureInt21] =
                static_cast<uint8_t>(i + 1);
            if (chronologicalCache.observe(arrayData(ordered),
                                           ScanObservation {
                                               sizeof(ordered),
                                               -kFixtureInt40,
                                               kFixtureInt2001 + i,
                                           }) != Result::Ok)
            {
                return kFixtureInt29;
            }
        }
        makeBeacon(ordered, kFixtureInt6);
        ordered[kFixtureInt15] = ordered[kFixtureInt21] =
            kSyntheticRecycledBssid;
        if (chronologicalCache.size() != ScanCache::kCapacity ||
            chronologicalCache.observe(arrayData(ordered),
                                       ScanObservation {
                                           sizeof(ordered),
                                           -kFixtureInt20,
                                           kFixtureInt2030,
                                       }) != Result::InvalidFrame ||
            chronologicalCache.size() != ScanCache::kCapacity)
        {
            return kFixtureInt29;
        }
        for (size_t i = 0; i < ScanCache::kCapacity; ++i)
        {
            if (!chronologicalCache.snapshot(i, recycled) ||
                recycled.beacon.bssid.bytes[kFixtureInt5] ==
                    kSyntheticRecycledBssid)
            {
                return kFixtureInt29;
            }
        }
        // Hidden beacons also use nonempty, all-zero SSID IEs. These are not
        // visible four-byte NUL network names and must never be selectable or
        // exposed to the native scan-results iterator.
        uint8_t zeroNamed[kBeaconBytes] {};
        makeBeacon(zeroNamed, kFixtureInt6);
        for (size_t i = kFixtureInt38; i < kFixtureInt42; ++i)
        {
            arrayAt(zeroNamed, i) = 0;
        }
        Beacon zeroParsed {};
        static ScanCache zeroNameCache;
        const uint8_t nullName[4] {};
        Bss zeroSelected {};
        static LegacyScanBridge zeroNameBridge;
        ScanBridgeTicket zeroNameTicket {};
        if (parseBeacon(arrayData(zeroNamed), sizeof(zeroNamed), zeroParsed) !=
                Result::Ok ||
            !zeroParsed.hiddenSsid || zeroParsed.ssidLength != 4 ||
            zeroNameCache.observe(arrayData(zeroNamed),
                                  ScanObservation {
                                      sizeof(zeroNamed),
                                      -kFixtureInt38,
                                      kFixtureInt3000,
                                  }) != Result::Ok ||
            zeroNameCache.strongest(
                arrayData(nullName),
                ScanSelection {sizeof(nullName), kFixtureInt6, true, true},
                zeroSelected) ||
            zeroNameCache.strongest(nullptr,
                                    ScanSelection {0, kFixtureInt6, true, true},
                                    zeroSelected) ||
            zeroNameBridge.beginScan(1, zeroNameTicket) !=
                ScanBridgeResult::Ok ||
            zeroNameBridge.completeScan(zeroNameCache, zeroNameTicket, true) !=
                ScanBridgeResult::Ok ||
            zeroNameBridge.status().resultCount != 0 ||
            zeroNameBridge.status().rejectedEntries != 1)
        {
            return kFixtureInt31;
        }
        return 0;
    }

} // namespace

int main()
{
    using namespace simpleath::ieee80211;
    if (!osOwnedWpa2SelectsExactObservedBssid())
    {
        return kFixtureInt37;
    }
    if (!scheduledPassiveScanRequiresVerifiedTune())
    {
        return kFixtureInt36;
    }
    if (!preferCompatibleAssociationRates())
    {
        return kFixtureInt35;
    }
    static ScanHarness fixture;
    const int checkScanLifecycleStartResult = checkScanLifecycleStart(fixture);
    if (checkScanLifecycleStartResult != 0)
    {
        return checkScanLifecycleStartResult;
    }
    const int checkScanLifecycleFinishResult =
        checkScanLifecycleFinish(fixture);
    if (checkScanLifecycleFinishResult != 0)
    {
        return checkScanLifecycleFinishResult;
    }
    const int checkWifiEngineAdmissionResult =
        checkWifiEngineAdmission(fixture);
    if (checkWifiEngineAdmissionResult != 0)
    {
        return checkWifiEngineAdmissionResult;
    }
    const int checkBssRecyclingStartResult = checkBssRecyclingStart(fixture);
    if (checkBssRecyclingStartResult != 0)
    {
        return checkBssRecyclingStartResult;
    }
    const int checkBssRecyclingFinishResult = checkBssRecyclingFinish(fixture);
    if (checkBssRecyclingFinishResult != 0)
    {
        return checkBssRecyclingFinishResult;
    }
    const int checkChronologicalExpiryResult =
        checkChronologicalExpiry(fixture);
    if (checkChronologicalExpiryResult != 0)
    {
        return checkChronologicalExpiryResult;
    }
    return 0;
}
