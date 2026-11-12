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
//   - Offline regression cases for open station pipeline.
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
//   - Offline regression cases for open station pipeline.
// - Description:
//   - Implements or verifies the test_open_station_pipeline source boundary.
// - Usage:
//   - Executed by offline host test discovery or the native test harness.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Offline regression cases for open station pipeline.
// Portable synthetic open-BSS association; NO native Wi-Fi, RF, PCI or OS I/O.
#include "wifi/DataFrames.hpp"
#include "wifi/DataPath.hpp"
#include "wifi/Eapol.hpp"
#include "wifi/Frames.hpp"
#include "wifi/LinkMonitor.hpp"
#include "wifi/ScanCache.hpp"
#include "wifi/Station.hpp"
#include "wifi/WifiEngine.hpp"
#include "wifi/Wpa2Supplicant.hpp"
#include "wifi/crypto/Ccmp.hpp"
#include "wifi/crypto/Wpa2CryptoAdapter.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <iterator>

namespace
{
    using namespace simpleath::ieee80211;

    constexpr uint8_t kAp[6] {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    constexpr uint8_t kStation[6] {0x02, 0x66, 0x77, 0x88, 0x99, 0xaa};
    constexpr int kAssociatedBssSnapshotFailure = 77;
    constexpr uint8_t kAssociatedBssTestChannel = 6U;

    // These deliberately nonfunctional providers are never invoked; they
    // validate only the adapter's offline callback storage contract.
    bool fakeRandom(void * /*unused*/, uint8_t * /*unused*/, size_t /*unused*/)
    {
        return false;
    }

    bool fakePairwise(void * /*unused*/, const Mac & /*unused*/,
                      const uint8_t /*unused*/[16])
    {
        return false;
    }

    bool fakeGroup(void * /*unused*/, uint8_t /*unused*/,
                   const uint8_t /*unused*/[16], const uint8_t /*unused*/[8])
    {
        return false;
    }

    void fakeRemove(void * /*unused*/)
    {
    }

    bool observingRandom(void *context, uint8_t * /*unused*/, size_t /*unused*/)
    {
        // Synthetic only: let tests detect a forbidden provider invocation.
        ++*static_cast<size_t *>(context);
        return true;
    }

    void addresses(uint8_t *frame, const uint8_t *destination)
    {
        std::memcpy(frame + 4, destination, 6);
        std::memcpy(frame + 10, kAp, 6);
        std::memcpy(frame + 16, kAp, 6);
    }

    void beacon(uint8_t frame[49])
    {
        std::memset(frame, 0, 49);
        frame[0] = 0x80;
        std::memset(frame + 4, 0xff, 6);
        std::memcpy(frame + 10, kAp, 6);
        std::memcpy(frame + 16, kAp, 6);
        frame[32] = 100;
        frame[34] = 1;
        frame[36] = 0;
        frame[37] = 4;
        std::memcpy(frame + 38, "Test", 4);
        frame[42] = 1;
        frame[43] = 2;
        frame[44] = 0x82;
        frame[45] = 0x84;
        frame[46] = 3;
        frame[47] = 1;
        frame[48] = 6;
    }

    void authenticationResponse(uint8_t frame[30])
    {
        std::memset(frame, 0, 30);
        frame[0] = 0xb0;
        addresses(frame, kStation);
        frame[26] = 2; // Open-system auth response transaction 2.
    }

    void associationResponse(uint8_t frame[34])
    {
        std::memset(frame, 0, 34);
        frame[0] = 0x10;
        addresses(frame, kStation);
        frame[24] = 1;
        frame[28] = 1;
        frame[29] = 0xc0; // AID 1.
        frame[30] = 1;
        frame[31] = 2;
        frame[32] = 0x82;
        frame[33] = 0x84;
    }

    bool rejectDisjointAssociationRates()
    {
        // A successful response cannot replace the selected BSS rate set
        // with an entirely disjoint one, then claim a usable association.
        uint8_t advertisement[49] {};
        beacon(advertisement);
        Bss candidate {};
        if (parseBeacon(advertisement, sizeof(advertisement),
                        candidate.beacon) != Result::Ok)
        {
            return false;
        }
        // The AP may advertise an optional rate the station hardware lacks.
        // Association TX correctly omits it, so an Association Response
        // containing ONLY that rate cannot establish a common PHY rate.
        candidate.beacon.rates[1] = 0x04; // 2 Mbps is optional in this BSS.
        candidate.beacon.rates[2] = 0x7f;
        candidate.beacon.rateCount = 3;
        candidate.occupied = true;
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        Station owner;
        uint8_t tx[128] {};
        size_t written = 0;
        if (owner.enterScanning(true, true) != StationResult::Ok ||
            owner.select(station, candidate) != StationResult::Ok ||
            owner.authenticationRequest(1, tx, sizeof(tx), written) !=
                Result::Ok)
        {
            return false;
        }
        uint8_t authentication[30] {};
        authenticationResponse(authentication);
        if (owner.onAuthenticationResponse(
                authentication, sizeof(authentication)) != StationResult::Ok ||
            owner.associationRequest(2, tx, sizeof(tx), written) != Result::Ok)
        {
            return false;
        }

        // One matching rate cannot mask a newly mandatory, unsupported AP
        // basic rate. Retain the retryable association state for a rescan.
        uint8_t newBasic[34] {};
        associationResponse(newBasic);
        newBasic[33] = 0xff; // Basic 63.5 Mbps; selected BSS had only 1/2.
        if (owner.onAssociationResponse(newBasic, sizeof(newBasic)) !=
                StationResult::FrameRejected ||
            owner.state() != StationState::AssociationFramePrepared ||
            owner.associationId() != 0)
        {
            return false;
        }

        uint8_t unnegotiated[34] {};
        associationResponse(unnegotiated);
        unnegotiated[31] = 1;
        unnegotiated[32] = 0x7f; // Advertised by AP but NOT by this station.
        if (owner.onAssociationResponse(unnegotiated, sizeof(unnegotiated)) !=
                StationResult::FrameRejected ||
            owner.state() != StationState::AssociationFramePrepared ||
            owner.associationId() != 0)
        {
            return false;
        }

        uint8_t response[36] {};
        associationResponse(response);
        response[31] = 1;    // One base Supported Rate.
        response[32] = 0x96; // 11 Mbps, not in the selected 1/2 Mbps BSS.
        response[33] = 50;   // Extended Supported Rates.
        response[34] = 1;
        response[35] = 0x0c; // 6 Mbps, also absent from the selected BSS.
        if (owner.onAssociationResponse(response, sizeof(response)) !=
                StationResult::FrameRejected ||
            owner.state() != StationState::AssociationFramePrepared ||
            owner.associationId() != 0)
        {
            return false;
        }
        // Extended Supported Rates also cannot add a new mandatory basic
        // rate, even if base Supported Rates retains a matching rate.
        response[32] = 0x82; // Matching 1 Mbps basic rate.
        response[35] = 0xff; // Unsupported basic rate in extended IE.
        if (owner.onAssociationResponse(response, sizeof(response)) !=
                StationResult::FrameRejected ||
            owner.state() != StationState::AssociationFramePrepared ||
            owner.associationId() != 0)
        {
            return false;
        }
        // The AP cannot upgrade a selected optional rate to a new mandatory
        // basic rate in its response without forcing a rescan. This local PHY
        // rate is supported, but was not advertised as a required BSS rate.
        response[35] = 0x84; // 2 Mbps basic; selected BSS offered 0x04.
        if (owner.onAssociationResponse(response, sizeof(response)) !=
                StationResult::FrameRejected ||
            owner.state() != StationState::AssociationFramePrepared ||
            owner.associationId() != 0)
        {
            return false;
        }
        // Nonbasic AP additions are allowed when a selected rate is shared.
        response[35] = 0x7f; // Unrecognized, but not mandatory.
        return owner.onAssociationResponse(response, sizeof(response)) ==
                   StationResult::NetworkInterfaceNotImplemented &&
               owner.state() == StationState::AssociatedOpen &&
               owner.associationId() == 1;
    }

    bool associationUsesSelectedRates()
    {
        uint8_t advertisement[49] {};
        beacon(advertisement);
        Beacon network {};
        if (parseBeacon(advertisement, sizeof(advertisement), network) !=
                Result::Ok ||
            network.rateCount != 2)
        {
            return false;
        }
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        uint8_t request[128] {};
        size_t written = 0;
        // The AP offers only 1/2 Mbps. A station must not invent 10 more
        // association rates or claim 5.5/11 Mbps as AP basic requirements.
        if (makeAssociationRequest(station, network, 1, request,
                                   sizeof(request), written) != Result::Ok ||
            written != 38 || request[34] != 1 || request[35] != 2 ||
            request[36] != 0x82 || request[37] != 0x84)
        {
            return false;
        }
        // Supported Rates holds at most eight entries. A ninth compatible
        // AP rate belongs in Extended Supported Rates. An unknown optional
        // rate must not be falsely advertised as a local capability.
        const uint8_t offered[] {
            0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24, 0x30, 0x7f,
        };
        network.rateCount = sizeof(offered);
        std::memcpy(network.rates, offered, sizeof(offered));
        if (makeAssociationRequest(station, network, 2, request,
                                   sizeof(request), written) != Result::Ok ||
            written != 47 || request[34] != 1 || request[35] != 8 ||
            request[44] != 50 || request[45] != 1 || request[46] != 0x30)
        {
            return false;
        }
        // The same PHY rate may occur twice with different basic flags.
        // Deduplication must retain the mandatory bit, not drop it.
        network.rateCount = 3;
        network.rates[0] = 0x02;
        network.rates[1] = 0x82;
        network.rates[2] = 0x84;
        if (makeAssociationRequest(station, network, 3, request,
                                   sizeof(request), written) != Result::Ok ||
            written != 38 || request[36] != 0x82 || request[37] != 0x84)
        {
            return false;
        }
        network.rateCount = sizeof(offered);
        std::memcpy(network.rates, offered, sizeof(offered));
        // A new mandatory basic rate unknown to this hardware is never
        // negotiated, even if many optional rates overlap.
        network.rates[9] = 0xff;
        std::memset(request, 0xa5, sizeof(request));
        written = 777;
        if (makeAssociationRequest(station, network, 3, request,
                                   sizeof(request),
                                   written) != Result::InvalidElement ||
            written != 0 || request[0] != 0xa5)
        {
            return false;
        }
        return true;
    }

    bool rejectInvalidFromDsSource()
    {
        // FromDS address 3 is the originating Ethernet SA. An all-zero or
        // multicast source is never a valid individual Ethernet sender, even
        // when the AP BSSID and our receiver address are otherwise valid.
        uint8_t frame[33] {};
        frame[0] = 0x08; // Data.
        frame[1] = 0x02; // From DS.
        addresses(frame, kStation);
        std::memcpy(frame + 16, kAp, 6); // Valid Ethernet source.
        frame[24] = frame[25] = 0xaa;
        frame[26] = 3;
        frame[30] = 0x08;
        frame[31] = 0x00;
        frame[32] = 0x45;
        LinkContext link {};
        link.station = {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        link.bssid = {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        link.security = LinkSecurity::Open;
        link.associated = true;
        link.rfReady = true;
        link.channelPermitted = true;
        Msdu result {};
        if (inspectStationRx(link, frame, sizeof(frame), false, true, false,
                             result) != DataPathResult::Ok ||
            result.payload != frame + 32)
        {
            return false;
        }
        // Broadcast source (multicast bit set), zero source, and another
        // multicast source must all fail without borrowing stale RX bytes.
        frame[16] = 0xff;
        if (inspectStationRx(link, frame, sizeof(frame), false, true, false,
                             result) != DataPathResult::InvalidAddress ||
            (result.payload != nullptr))
        {
            return false;
        }
        std::memset(frame + 16, 0, 6);
        if (inspectStationRx(link, frame, sizeof(frame), false, true, false,
                             result) != DataPathResult::InvalidAddress ||
            (result.payload != nullptr))
        {
            return false;
        }
        frame[16] = 0x01;
        if (inspectStationRx(link, frame, sizeof(frame), false, true, false,
                             result) != DataPathResult::InvalidAddress ||
            (result.payload != nullptr))
        {
            return false;
        }
        return true;
    }

    bool rejectIdenticalLinkIdentities()
    {
        // A public LinkContext is not proof of an association. A station
        // cannot be its own AP/BSSID, even when both MACs are unicast.
        LinkContext link {};
        link.station = {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        link.bssid = link.station;
        link.security = LinkSecurity::Open;
        link.associated = true;
        link.rfReady = true;
        link.channelPermitted = true;

        uint8_t ethernet[17] {};
        std::memcpy(ethernet, kAp, 6);
        std::memcpy(ethernet + 6, kStation, 6);
        ethernet[12] = 0x08;
        ethernet[13] = 0x00;
        ethernet[14] = 0x45;
        uint8_t tx[64] {};
        std::memset(tx, 0xa5, sizeof(tx));
        SerializedData txResult {};
        txResult.frameBytes = 77;
        if (prepareStationTx(link, ethernet, sizeof(ethernet), 1, tx,
                             sizeof(tx),
                             txResult) != DataPathResult::InvalidAddress ||
            txResult.frameBytes != 77 || tx[0] != 0xa5)
        {
            return false;
        }

        uint8_t frame[33] {};
        frame[0] = 0x08;
        frame[1] = 0x02; // FromDS.
        addresses(frame, kStation);
        std::memcpy(frame + 10, kStation, 6); // Forged self-BSSID.
        std::memcpy(frame + 16, kAp, 6);      // Distinct valid Ethernet source.
        frame[24] = frame[25] = 0xaa;
        frame[26] = 3;
        frame[30] = 0x08;
        frame[31] = 0x00;
        frame[32] = 0x45;
        Msdu rxResult {};
        rxResult.payload = frame;
        rxResult.payloadLength = 1;
        if (inspectStationRx(link, frame, sizeof(frame), false, true, false,
                             rxResult) != DataPathResult::InvalidAddress ||
            (rxResult.payload != nullptr) || (rxResult.payloadLength != 0U))
        {
            return false;
        }

        // Both directions still accept a genuinely distinct valid AP.
        std::memcpy(link.bssid.bytes, kAp, 6);
        std::memcpy(frame + 10, kAp, 6);
        return prepareStationTx(link, ethernet, sizeof(ethernet), 2, tx,
                                sizeof(tx), txResult) == DataPathResult::Ok &&
               inspectStationRx(link, frame, sizeof(frame), false, true, false,
                                rxResult) == DataPathResult::Ok &&
               rxResult.payload == frame + 32;
    }

    bool rejectOpenLinkWithInstalledWpa2Keys()
    {
        // A forged public LinkContext cannot announce a fresh open
        // association while carrying an old WPA2 pairwise/group key claim.
        LinkContext link {};
        link.station = {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        link.bssid = {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        link.security = LinkSecurity::Open;
        link.associated = true;
        link.rfReady = true;
        link.channelPermitted = true;
        link.pairwiseAndGroupKeysInstalled = true;

        uint8_t ethernet[17] {};
        std::memcpy(ethernet, kAp, 6);
        std::memcpy(ethernet + 6, kStation, 6);
        ethernet[12] = 0x08;
        ethernet[13] = 0x00;
        ethernet[14] = 0x45;
        uint8_t tx[64] {};
        std::memset(tx, 0xa5, sizeof(tx));
        SerializedData prepared {};
        prepared.frameBytes = 77;
        if (prepareStationTx(link, ethernet, sizeof(ethernet), 1, tx,
                             sizeof(tx), prepared) !=
                DataPathResult::InvalidSecurityState ||
            tx[0] != 0xa5 || prepared.frameBytes != 77)
        {
            return false;
        }

        uint8_t frame[33] {};
        frame[0] = 0x08;
        frame[1] = 0x02;
        addresses(frame, kStation);
        frame[24] = frame[25] = 0xaa;
        frame[26] = 3;
        frame[30] = 0x08;
        frame[31] = 0x00;
        frame[32] = 0x45;
        Msdu decoded {};
        decoded.payload = frame;
        decoded.payloadLength = sizeof(frame);
        if (inspectStationRx(link, frame, sizeof(frame), false, true, false,
                             decoded) != DataPathResult::InvalidSecurityState ||
            (decoded.payload != nullptr) || (decoded.payloadLength != 0U))
        {
            return false;
        }

        // A legitimate open link still admits cleartext TX and RX.
        link.pairwiseAndGroupKeysInstalled = false;
        return prepareStationTx(link, ethernet, sizeof(ethernet), 1, tx,
                                sizeof(tx), prepared) == DataPathResult::Ok &&
               prepared.frameBytes == 35 &&
               inspectStationRx(link, frame, sizeof(frame), false, true, false,
                                decoded) == DataPathResult::Ok &&
               decoded.payload == frame + 32;
    }

    bool rejectOpenAssociationEapolTx()
    {
        // This portable station supports Open data and WPA2-PSK M2/M4 only.
        // An Open LinkContext must not smuggle an unchecked 802.1X/EAPOL
        // payload into a cleartext data frame or native TX action.
        LinkContext link {};
        link.station = {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        link.bssid = {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        link.security = LinkSecurity::Open;
        link.associated = true;
        link.rfReady = true;
        link.channelPermitted = true;
        uint8_t ethernet[17] {};
        std::memcpy(ethernet, kAp, 6);
        std::memcpy(ethernet + 6, kStation, 6);
        ethernet[12] = 0x88;
        ethernet[13] = 0x8e;
        ethernet[14] = 2;
        uint8_t tx[64] {};
        std::memset(tx, 0xa5, sizeof(tx));
        SerializedData prepared {};
        prepared.frameBytes = 99;
        if (prepareStationTx(link, ethernet, sizeof(ethernet), 1, tx,
                             sizeof(tx), prepared) !=
                DataPathResult::InvalidEthernetFrame ||
            tx[0] != 0xa5 || prepared.frameBytes != 99)
        {
            return false;
        }
        // Ordinary Open IPv4 data remains permitted under the same link.
        ethernet[12] = 0x08;
        ethernet[13] = 0x00;
        return prepareStationTx(link, ethernet, sizeof(ethernet), 1, tx,
                                sizeof(tx), prepared) == DataPathResult::Ok &&
               !prepared.isEapol && prepared.etherType == 0x0800;
    }

    bool rejectForeignWpa2Authenticator()
    {
        // The WPA2 4-way handshake for the selected BSSID must never accept
        // an EAPOL-Key frame bridged through the AP from another transmitter.
        // Ordinary encrypted data may still originate behind the AP.
        uint8_t frame[131] {};
        frame[0] = 0x08; // FromDS data to this station.
        frame[1] = 0x02;
        addresses(frame, kStation);
        frame[24] = frame[25] = 0xaa;
        frame[26] = 3;
        frame[30] = 0x88;
        frame[31] = 0x8e;
        frame[32] = 2; // Valid AP M1 as the only pre-key EAPOL exception.
        frame[33] = 3;
        frame[35] = 95;
        frame[36] = 2;
        frame[38] = 0x8a;
        frame[40] = 16;
        frame[48] = 1;
        frame[49] = 7;
        LinkContext link {};
        link.station = {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        link.bssid = {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        link.security = LinkSecurity::Wpa2Ccmp;
        link.associated = true;
        link.rfReady = true;
        link.channelPermitted = true;
        Msdu msdu {};
        if (inspectStationRx(link, frame, sizeof(frame), false, true, false,
                             msdu) != DataPathResult::Ok ||
            msdu.etherType != 0x888e)
        {
            return false;
        }
        frame[21] ^= 1U; // Different valid unicast source, same AP/BSSID.
        if (inspectStationRx(link, frame, sizeof(frame), false, true, false,
                             msdu) !=
                DataPathResult::NotFromAssociatedAccessPoint ||
            (msdu.payload != nullptr) || (msdu.payloadLength != 0U))
        {
            return false;
        }
        // Do not accidentally ban other unicast Ethernet sources behind the
        // AP for actual protected data with validated integrity and keys.
        frame[1] |= 0x40;
        frame[30] = 0x08;
        frame[31] = 0x00;
        link.pairwiseAndGroupKeysInstalled = true;
        return inspectStationRx(link, frame, sizeof(frame), false, true, true,
                                msdu) == DataPathResult::Ok &&
               msdu.payload == frame + 32 && msdu.etherType == 0x0800;
    }

    bool rejectMalformedWpa2RxEapol()
    {
        // The public RX admission gate must not publish arbitrary bytes as
        // an authenticated AP-side WPA2 M1/M3. Only complete pairwise M1/M3
        // can cross the cleartext pre-key exception. No post-key rekey path
        // exists in this portable engine.
        LinkContext link {};
        link.station = {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        link.bssid = {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        link.security = LinkSecurity::Wpa2Ccmp;
        link.associated = true;
        link.rfReady = true;
        link.channelPermitted = true;
        uint8_t frame[132] {};
        frame[0] = 0x08;
        frame[1] = 0x02; // AP FromDS unprotected Data.
        addresses(frame, kStation);
        frame[24] = frame[25] = 0xaa;
        frame[26] = 3;
        frame[30] = 0x88;
        frame[31] = 0x8e; // EAPOL EtherType.
        frame[32] = 2;    // A one-byte truncated EAPOL frame.
        Msdu result {};
        result.payload = frame;
        result.payloadLength = 10;
        if (inspectStationRx(link, frame, 33, false, true, false, result) !=
                DataPathResult::UnsupportedFrame ||
            (result.payload != nullptr) || (result.payloadLength != 0U))
        {
            return false;
        }

        uint8_t *const eapol = frame + 32;
        eapol[1] = 3;    // EAPOL-Key.
        eapol[3] = 95;   // Complete fixed-length RSN EAPOL-Key body.
        eapol[4] = 2;    // RSN descriptor.
        eapol[6] = 0x8a; // M1: version 2, pairwise, ACK.
        eapol[8] = 16;   // AP key length.
        eapol[16] = 1;   // Replay counter.
        eapol[17] = 7;   // ANonce.
        if (inspectStationRx(link, frame, 131, false, true, false, result) !=
                DataPathResult::Ok ||
            result.payload != eapol || result.payloadLength != 99)
        {
            return false;
        }
        frame[131] = 0xa5; // Not part of the declared EAPOL packet.
        if (inspectStationRx(link, frame, sizeof(frame), false, true, false,
                             result) != DataPathResult::UnsupportedFrame ||
            (result.payload != nullptr))
        {
            return false;
        }

        eapol[5] = 1;
        eapol[6] = 0x0a; // M2: a supplicant reply, never AP-side RX.
        eapol[8] = 0;
        eapol[81] = 0x55; // MIC present.
        if (inspectStationRx(link, frame, 131, false, true, false, result) !=
                DataPathResult::UnsupportedFrame ||
            (result.payload != nullptr))
        {
            return false;
        }

        eapol[5] = 0x13;
        eapol[6] = 0xca; // M3: AP install/MIC/secure/encrypted flags.
        eapol[8] = 16;
        if (inspectStationRx(link, frame, 131, false, true, false, result) !=
                DataPathResult::Ok ||
            result.payload != eapol)
        {
            return false;
        }
        link.pairwiseAndGroupKeysInstalled = true;
        frame[1] = 0x42; // Protected AP EAPOL after initial key install.
        if (inspectStationRx(link, frame, 131, false, true, true, result) !=
                DataPathResult::UnsupportedFrame ||
            (result.payload != nullptr))
        {
            return false;
        }
        // An open link must not inherit a prior WPA2 session's key-installed
        // claim; that contradiction cannot authorize plaintext receive.
        link.security = LinkSecurity::Open;
        frame[1] = 0x02;
        if (inspectStationRx(link, frame, 33, false, true, false, result) !=
                DataPathResult::InvalidSecurityState ||
            (result.payload != nullptr))
        {
            return false;
        }
        // Open networks retain generic Ethernet-II EAPOL pass-through only
        // after the previous security state has been fully revoked.
        link.pairwiseAndGroupKeysInstalled = false;
        return inspectStationRx(link, frame, 33, false, true, false, result) ==
                   DataPathResult::Ok &&
               result.payload == frame + 32;
    }

    // Synthetic wire-format literals and fixed-size packet buffers are
    // intentional in this regression fixture; production uses the checked
    // parser/serializer and bound CCMP key owner.
    // NOLINTBEGIN(*avoid-magic-numbers,readability-magic-numbers)
    // NOLINTBEGIN(*bounds-pointer-arithmetic)
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
    // NOLINTBEGIN(readability-function-cognitive-complexity)
    bool protectedWpa2Transmit()
    {
        // The MIC here is synthetic; only Wpa2Supplicant may authenticate
        // and supply a Group2 reply to the native owner in production.
        constexpr uint64_t kEpoch = 1234U;
        constexpr size_t kEthernetHeader = 14U;
        constexpr size_t kGroup2Bytes = 99U;
        constexpr size_t kPlainMpduBytes = 32U + kGroup2Bytes;
        constexpr size_t kEncryptedMpduBytes = kPlainMpduBytes + 16U;
        const uint8_t tk[16] {0x11U, 0x22U, 0x33U, 0x44U};
        LinkContext link {};
        link.station = {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        link.bssid = {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        link.security = LinkSecurity::Wpa2Ccmp;
        link.associated = true;
        link.rfReady = true;
        link.channelPermitted = true;
        link.pairwiseAndGroupKeysInstalled = true;
        uint8_t ethernet[kEthernetHeader + kGroup2Bytes] {};
        std::memcpy(ethernet, kAp, 6U);
        std::memcpy(ethernet + 6U, kStation, 6U);
        ethernet[12U] = 0x88U;
        ethernet[13U] = 0x8eU;
        uint8_t *const eapol = ethernet + kEthernetHeader;
        eapol[0U] = 2U; // EAPOL v2 / EAPOL-Key, 95-byte body.
        eapol[1U] = 3U;
        eapol[3U] = 95U;
        eapol[4U] = 2U; // RSN descriptor type.
        eapol[5U] = 3U;
        eapol[6U] = 2U; // Group2: MIC + Secure; no ACK/Pairwise.
        eapol[16U] = 9U;
        eapol[81U] = 0x5aU;
        KeyFrame parsed {};
        if (parseEapolKey(eapol, kGroup2Bytes, parsed) != EapolResult::Ok ||
            parsed.message != KeyMessage::Group2)
        {
            return false;
        }
        crypto::CcmpSession tx {};
        crypto::CcmpSession rx {};
        if (tx.install(tk, kStation, 0U, kEpoch, 0U, 0U) !=
                crypto::CcmpResult::Ok ||
            rx.install(tk, kStation, 0U, kEpoch, 0U, 0U) !=
                crypto::CcmpResult::Ok)
        {
            return false;
        }
        uint8_t scratch[256] {};
        uint8_t protectedFrame[256] {};
        std::memset(protectedFrame, 0xa5, sizeof(protectedFrame));
        SerializedData result {};
        result.frameBytes = 777U;
        // Public cleartext serializer must never hand out Group2.
        if (prepareStationTx(link, ethernet, sizeof(ethernet), 3U,
                             protectedFrame, sizeof(protectedFrame),
                             result) != DataPathResult::InvalidEthernetFrame ||
            protectedFrame[0U] != 0xa5U || result.frameBytes != 777U)
        {
            return false;
        }
        if (prepareProtectedStationTx(link, ethernet, sizeof(ethernet), 3U, tx,
                                      kEpoch, scratch, sizeof(scratch),
                                      protectedFrame, sizeof(protectedFrame),
                                      result) != DataPathResult::Ok ||
            result.frameBytes != kEncryptedMpduBytes ||
            result.onAirLengthIncludingFcs != kEncryptedMpduBytes + 4U ||
            result.needsCcmp || !result.isEapol ||
            result.etherType != 0x888eU || protectedFrame[1U] != 0x41U ||
            protectedFrame[24U] != 1U || tx.lastTransmittedPn() != 1U)
        {
            return false;
        }
        for (const uint8_t byte : scratch)
        {
            if (byte != 0U)
            {
                return false;
            }
        }
        uint8_t recovered[256] {};
        size_t restoredBytes = 0U;
        if (rx.unprotect(kEpoch, protectedFrame, result.frameBytes, recovered,
                         sizeof(recovered),
                         restoredBytes) != crypto::CcmpResult::Ok ||
            restoredBytes != kPlainMpduBytes ||
            std::memcmp(recovered + 32U, eapol, kGroup2Bytes) != 0 ||
            std::memcmp(recovered + 4U, kAp, 6U) != 0 ||
            std::memcmp(recovered + 10U, kStation, 6U) != 0 ||
            rx.unprotect(kEpoch, protectedFrame, result.frameBytes, recovered,
                         sizeof(recovered),
                         restoredBytes) != crypto::CcmpResult::ReplayDetected)
        {
            return false;
        }
        // No key consumption, output mutation, or leaked scratch plaintext
        // on invalid group-rekey replies or a stale protection epoch.
        const uint64_t committedPn = tx.lastTransmittedPn();
        const size_t committedBytes = result.frameBytes;
        eapol[8U] = 16U; // A forged Group2 with a nonzero key length.
        if (prepareProtectedStationTx(
                link, ethernet, sizeof(ethernet), 3U, tx, kEpoch, scratch,
                sizeof(scratch), protectedFrame, sizeof(protectedFrame),
                result) != DataPathResult::InvalidEthernetFrame ||
            tx.lastTransmittedPn() != committedPn)
        {
            return false;
        }
        eapol[8U] = 0U;
        eapol[6U] = 0x0aU; // M4, not a protected group response.
        if (prepareProtectedStationTx(
                link, ethernet, sizeof(ethernet), 3U, tx, kEpoch, scratch,
                sizeof(scratch), protectedFrame, sizeof(protectedFrame),
                result) != DataPathResult::InvalidEthernetFrame ||
            result.frameBytes != committedBytes ||
            tx.lastTransmittedPn() != committedPn)
        {
            return false;
        }
        eapol[6U] = 2U;
        if (prepareProtectedStationTx(
                link, ethernet, sizeof(ethernet), 3U, tx, kEpoch + 1U, scratch,
                sizeof(scratch), protectedFrame, sizeof(protectedFrame),
                result) != DataPathResult::EncryptionFailed ||
            result.frameBytes != committedBytes ||
            tx.lastTransmittedPn() != committedPn)
        {
            return false;
        }
        for (const uint8_t byte : scratch)
        {
            if (byte != 0U)
            {
                return false;
            }
        }
        // An aliased caller scratch cannot erase the input Ethernet frame
        // while preparing an authenticated packet.
        const uint8_t savedEtherType = ethernet[12U];
        if (prepareProtectedStationTx(
                link, ethernet, sizeof(ethernet), 3U, tx, kEpoch, ethernet,
                sizeof(ethernet), protectedFrame, sizeof(protectedFrame),
                result) != DataPathResult::OverlappingBuffers ||
            ethernet[12U] != savedEtherType ||
            tx.lastTransmittedPn() != committedPn)
        {
            return false;
        }
        // Normal WPA2 data must also be encrypted, never returned as an
        // unprotected MPDU or transmitted with a fabricated security flag.
        uint8_t data[19] {};
        std::memcpy(data, kAp, 6U);
        std::memcpy(data + 6U, kStation, 6U);
        data[12U] = 0x08U;
        data[13U] = 0U;
        data[14U] = 0x45U;
        data[15U] = 0x67U;
        return prepareStationTx(link, data, sizeof(data), 4U, protectedFrame,
                                sizeof(protectedFrame), result) ==
                   DataPathResult::NeedsCcmpEncryption &&
               prepareProtectedStationTx(link, data, sizeof(data), 4U, tx,
                                         kEpoch, scratch, sizeof(scratch),
                                         protectedFrame, sizeof(protectedFrame),
                                         result) == DataPathResult::Ok &&
               result.frameBytes == 32U + 5U + 16U &&
               tx.lastTransmittedPn() == 2U;
    }

    // NOLINTEND(readability-function-cognitive-complexity)
    // NOLINTEND(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
    // NOLINTEND(*bounds-pointer-arithmetic)
    // NOLINTEND(*avoid-magic-numbers,readability-magic-numbers)

    // A synthetic authenticated AP MPDU must cross CCMP and the ordinary
    // station receiver together. No DMA or native network stack is involved.
    // NOLINTBEGIN(*avoid-magic-numbers,readability-magic-numbers)
    // NOLINTBEGIN(*bounds-pointer-arithmetic)
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
    // NOLINTBEGIN(readability-function-cognitive-complexity)
    bool protectedWpa2Receive()
    {
        constexpr uint64_t kEpoch = 992U;
        const uint8_t key[16] {0x11U, 0x22U, 0x33U, 0x44U};
        uint8_t clear[35] {};
        clear[0] = 0x08U;
        clear[1] = 0x02U;
        addresses(clear, kStation);
        clear[24] = clear[25] = 0xaaU;
        clear[26] = 3U;
        clear[30] = 0x08U;
        clear[31] = 0x00U;
        clear[32] = 0x45U;
        clear[33] = 0x67U;
        clear[34] = 0x89U;
        LinkContext link {};
        link.station = {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        link.bssid = {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        link.security = LinkSecurity::Wpa2Ccmp;
        link.associated = true;
        link.rfReady = true;
        link.channelPermitted = true;
        link.pairwiseAndGroupKeysInstalled = true;
        crypto::CcmpSession tx {};
        crypto::CcmpSession rx {};
        if (tx.install(key, kAp, 0U, kEpoch, 0U, 0U) !=
                crypto::CcmpResult::Ok ||
            rx.install(key, kAp, 0U, kEpoch, 0U, 0U) != crypto::CcmpResult::Ok)
        {
            return false;
        }
        uint8_t wire[128] {};
        size_t wireBytes = 0U;
        if (tx.protect(kEpoch, clear, sizeof(clear), wire, sizeof(wire),
                       wireBytes) != crypto::CcmpResult::Ok ||
            wireBytes != sizeof(clear) + 16U)
        {
            return false;
        }
        uint8_t scratch[128] {};
        Msdu delivered {};
        delivered.payload = clear;
        delivered.payloadLength = sizeof(clear);
        if (inspectProtectedStationRx(link, wire, wireBytes, false, false, rx,
                                      kEpoch, scratch, sizeof(scratch),
                                      delivered) !=
                DataPathResult::InvalidRxStatus ||
            delivered.payload != nullptr || rx.receiveFloor() != 0U)
        {
            return false;
        }
        // No unauthorized plaintext may be published by a stale key epoch.
        if (inspectProtectedStationRx(link, wire, wireBytes, false, true, rx,
                                      kEpoch + 1U, scratch, sizeof(scratch),
                                      delivered) !=
                DataPathResult::UnverifiedDecryption ||
            rx.receiveFloor() != 0U)
        {
            return false;
        }
        // Reject a mutation before accepting a correct authenticated PN.
        constexpr size_t kMicLastByte = sizeof(clear) + 16U - 1U;
        wire[kMicLastByte] ^= 1U;
        if (inspectProtectedStationRx(link, wire, wireBytes, false, true, rx,
                                      kEpoch, scratch, sizeof(scratch),
                                      delivered) !=
                DataPathResult::UnverifiedDecryption ||
            rx.receiveFloor() != 0U || delivered.payload != nullptr)
        {
            return false;
        }
        wire[kMicLastByte] ^= 1U;
        // A scratch alias must not destroy ciphertext, the link, or keys.
        const uint8_t encryptedFirst = wire[0U];
        if (inspectProtectedStationRx(link, wire, wireBytes, false, true, rx,
                                      kEpoch, wire, sizeof(wire), delivered) !=
                DataPathResult::OverlappingBuffers ||
            wire[0U] != encryptedFirst || rx.receiveFloor() != 0U)
        {
            return false;
        }
        // Group destinations must not ride on the pairwise key ID zero.
        wire[4U] |= 1U;
        if (inspectProtectedStationRx(link, wire, wireBytes, false, true, rx,
                                      kEpoch, scratch, sizeof(scratch),
                                      delivered) !=
                DataPathResult::UnverifiedDecryption ||
            rx.receiveFloor() != 0U)
        {
            return false;
        }
        wire[4U] &= static_cast<uint8_t>(~1U);
        // The FCS is supplied out of band after the native RX descriptor has
        // authenticated it. AES-CCM must not process the four FCS bytes.
        std::memset(wire + wireBytes, 0xaaU, 4U);
        if (inspectProtectedStationRx(link, wire, wireBytes + 4U, true, true,
                                      rx, kEpoch, scratch, sizeof(scratch),
                                      delivered) != DataPathResult::Ok ||
            delivered.payload != scratch + 32U ||
            delivered.payloadLength != 3U || delivered.etherType != 0x0800U ||
            !delivered.protectedFrame || delivered.payload[0] != 0x45U ||
            delivered.payload[2] != 0x89U || (scratch[1U] & 0x40U) == 0U ||
            rx.receiveFloor() != 1U)
        {
            return false;
        }
        // A replay cannot borrow the previously delivered plaintext again.
        if (inspectProtectedStationRx(link, wire, wireBytes, false, true, rx,
                                      kEpoch, scratch, sizeof(scratch),
                                      delivered) !=
                DataPathResult::UnverifiedDecryption ||
            delivered.payload != nullptr || rx.receiveFloor() != 1U)
        {
            return false;
        }
        // Owner erases accepted plaintext after synchronous delivery.
        std::memset(scratch, 0, sizeof(scratch));
        return true;
    }

    bool protectedGroup1Decrypt()
    {
        constexpr uint64_t kEpoch = 993U;
        constexpr size_t kGroup1Bytes = 139U;
        constexpr size_t kDataHeaderBytes = 32U;
        const uint8_t key[16] {0x11U, 0x22U, 0x33U, 0x44U};
        uint8_t clear[kDataHeaderBytes + kGroup1Bytes] {};
        clear[0U] = 0x08U;
        clear[1U] = 0x02U;
        addresses(clear, kStation);
        clear[24U] = clear[25U] = 0xaaU;
        clear[26U] = 3U;
        clear[30U] = 0x88U;
        clear[31U] = 0x8eU;
        uint8_t *const eapol = clear + kDataHeaderBytes;
        eapol[0U] = 2U;
        eapol[1U] = 3U;
        eapol[3U] = 135U;
        eapol[4U] = 2U;
        eapol[5U] = 0x13U;
        eapol[6U] = 0x82U;
        eapol[8U] = 16U;
        eapol[16U] = 7U;
        eapol[65U] = 2U;
        eapol[81U] = 0x5aU;
        eapol[98U] = 40U;
        for (size_t index = 99U; index < kGroup1Bytes; ++index)
        {
            eapol[index] = static_cast<uint8_t>(index);
        }
        LinkContext link {};
        link.station = {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        link.bssid = {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        link.security = LinkSecurity::Wpa2Ccmp;
        link.associated = true;
        link.rfReady = true;
        link.channelPermitted = true;
        link.pairwiseAndGroupKeysInstalled = true;
        crypto::CcmpSession tx {};
        crypto::CcmpSession rx {};
        if (tx.install(key, kAp, 0U, kEpoch, 0U, 0U) !=
                crypto::CcmpResult::Ok ||
            rx.install(key, kAp, 0U, kEpoch, 0U, 0U) != crypto::CcmpResult::Ok)
        {
            return false;
        }
        uint8_t wire[256] {};
        uint8_t scratch[256] {};
        size_t wireBytes = 0U;
        Msdu delivered {};
        if (tx.protect(kEpoch, clear, sizeof(clear), wire, sizeof(wire),
                       wireBytes) != crypto::CcmpResult::Ok ||
            inspectProtectedStationRx(link, wire, wireBytes, false, true, rx,
                                      kEpoch, scratch, sizeof(scratch),
                                      delivered) != DataPathResult::Ok ||
            delivered.etherType != 0x888eU || !delivered.protectedFrame ||
            delivered.payloadLength != kGroup1Bytes ||
            std::memcmp(delivered.payload, eapol, kGroup1Bytes) != 0 ||
            rx.receiveFloor() != 1U)
        {
            return false;
        }
        // A fully MIC-verified packet that is not authenticator Group1 still
        // must be discarded after decrypt, with the borrowed plaintext wiped.
        eapol[6U] = 0x0aU;
        if (tx.protect(kEpoch, clear, sizeof(clear), wire, sizeof(wire),
                       wireBytes) != crypto::CcmpResult::Ok ||
            inspectProtectedStationRx(link, wire, wireBytes, false, true, rx,
                                      kEpoch, scratch, sizeof(scratch),
                                      delivered) !=
                DataPathResult::UnsupportedFrame ||
            delivered.payload != nullptr || rx.receiveFloor() != 2U)
        {
            return false;
        }
        uint8_t zero[sizeof(scratch)] {};
        return std::memcmp(scratch, zero, sizeof(scratch)) == 0;
    }

    // NOLINTEND(readability-function-cognitive-complexity)
    // NOLINTEND(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
    // NOLINTEND(*bounds-pointer-arithmetic)
    // NOLINTEND(*avoid-magic-numbers,readability-magic-numbers)

    // Regression against independently generated OpenSSL AES-CCM group
    // ciphertext/MIC (same vector as standalone test_ccmp.cpp). Exercise
    // both CCMP and native-bound LLC/MSDU admission, not just decryption.
    // NOLINTBEGIN(*avoid-magic-numbers,readability-magic-numbers)
    // NOLINTBEGIN(*bounds-pointer-arithmetic)
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
    // NOLINTBEGIN(readability-function-cognitive-complexity)
    bool protectedGtkMulticastReceive()
    {
        constexpr uint64_t kEpoch = 995U;
        const uint8_t key[16] {
            0U, 1U, 2U,  3U,  4U,  5U,  6U,  7U,
            8U, 9U, 10U, 11U, 12U, 13U, 14U, 15U,
        };
        const uint8_t wire[] {
            0x08U, 0x42U, 0x00U, 0x00U, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
            0xffU, 0x02U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x02U, 0x33U,
            0x44U, 0x55U, 0x66U, 0x77U, 0x00U, 0x00U, 0x01U, 0x00U, 0x00U,
            0x60U, 0x00U, 0x00U, 0x00U, 0x00U, 0x61U, 0xd6U, 0xd3U, 0x3dU,
            0x81U, 0xdfU, 0x62U, 0x96U, 0x66U, 0x08U, 0x65U, 0x56U, 0x6eU,
            0xe5U, 0x95U, 0xf7U, 0xc6U, 0xd1U, 0xfbU, 0x3bU, 0x1dU, 0xc5U,
            0x47U, 0x1eU, 0x46U, 0xc0U, 0x3cU,
        };
        LinkContext link {};
        link.station = {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        link.bssid = {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        link.security = LinkSecurity::Wpa2Ccmp;
        link.associated = true;
        link.rfReady = true;
        link.channelPermitted = true;
        link.pairwiseAndGroupKeysInstalled = true;
        crypto::CcmpSession group {};
        crypto::CcmpSession pairwise {};
        if (group.install(key, kAp, 1U, kEpoch, 0U, 0U) !=
                crypto::CcmpResult::Ok ||
            pairwise.install(key, kAp, 0U, kEpoch, 0U, 0U) !=
                crypto::CcmpResult::Ok)
        {
            return false;
        }
        uint8_t scratch[128] {};
        Msdu parsed {};
        if (inspectProtectedStationRx(link, wire, sizeof(wire), false, true,
                                      pairwise, kEpoch, scratch,
                                      sizeof(scratch), parsed) !=
                DataPathResult::UnverifiedDecryption ||
            pairwise.receiveFloor() != 0U || parsed.payload != nullptr)
        {
            return false;
        }
        if (inspectProtectedStationRx(link, wire, sizeof(wire), false, true,
                                      group, kEpoch, scratch, sizeof(scratch),
                                      parsed) != DataPathResult::Ok ||
            parsed.etherType != 0x0800U ||
            parsed.payloadLength != sizeof("hello world") - 1U ||
            !parsed.protectedFrame || parsed.destination.bytes[0U] != 0xffU ||
            std::memcmp(parsed.payload, "hello world",
                        sizeof("hello world") - 1U) != 0 ||
            group.receiveFloor() != 1U)
        {
            return false;
        }
        if (inspectProtectedStationRx(link, wire, sizeof(wire), false, true,
                                      group, kEpoch, scratch, sizeof(scratch),
                                      parsed) !=
                DataPathResult::UnverifiedDecryption ||
            parsed.payload != nullptr || group.receiveFloor() != 1U)
        {
            return false;
        }
        std::memset(scratch, 0, sizeof(scratch));
        return true;
    }

    // NOLINTEND(readability-function-cognitive-complexity)
    // NOLINTEND(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
    // NOLINTEND(*bounds-pointer-arithmetic)
    // NOLINTEND(*avoid-magic-numbers,readability-magic-numbers)

    // The native owner must have already verified CCMP MIC/PN and stripped
    // ExtIV/MIC; the fixture feeds the resulting plaintext MPDU with its
    // protected-frame bit preserved. This does not prove hardware RX.
    // NOLINTBEGIN(*avoid-magic-numbers,readability-magic-numbers)
    // NOLINTBEGIN(*bounds-pointer-arithmetic)
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
    // NOLINTBEGIN(readability-function-cognitive-complexity)
    bool protectedGroup1RxAdmission()
    {
        constexpr size_t kGroup1Bytes = 139U;
        constexpr size_t kDataHeaderBytes = 32U;
        uint8_t frame[kDataHeaderBytes + kGroup1Bytes] {};
        frame[0U] = 0x08U;
        frame[1U] = 0x42U; // FromDS, Protected bit.
        addresses(frame, kStation);
        frame[24U] = frame[25U] = 0xaaU;
        frame[26U] = 3U;
        frame[30U] = 0x88U;
        frame[31U] = 0x8eU;
        uint8_t *const eapol = frame + kDataHeaderBytes;
        eapol[0U] = 2U;
        eapol[1U] = 3U;
        eapol[3U] = 135U;
        eapol[4U] = 2U;
        eapol[5U] = 0x13U;
        eapol[6U] = 0x82U; // Group1 MIC+Secure+ACK+wrapped data.
        eapol[8U] = 16U;
        eapol[16U] = 3U;
        eapol[65U] = 7U; // CCMP group RSC.
        eapol[81U] = 0x5aU;
        eapol[98U] = 40U;
        for (size_t index = 99U; index < kGroup1Bytes; ++index)
        {
            eapol[index] = static_cast<uint8_t>(index);
        }
        LinkContext link {};
        link.station = {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        link.bssid = {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        link.security = LinkSecurity::Wpa2Ccmp;
        link.associated = true;
        link.rfReady = true;
        link.channelPermitted = true;
        link.pairwiseAndGroupKeysInstalled = true;
        Msdu parsed {};
        if (inspectStationRx(link, frame, sizeof(frame), false, true, true,
                             parsed) != DataPathResult::Ok ||
            parsed.etherType != 0x888eU || parsed.payload != eapol ||
            parsed.payloadLength != kGroup1Bytes)
        {
            return false;
        }
        // CCMP trust, Protected flag and installed keys are ALL required.
        if (inspectStationRx(link, frame, sizeof(frame), false, true, false,
                             parsed) != DataPathResult::UnverifiedDecryption ||
            parsed.payload != nullptr)
        {
            return false;
        }
        frame[1U] = 0x02U; // Plaintext post-install EAPOL forbidden.
        if (inspectStationRx(link, frame, sizeof(frame), false, true, true,
                             parsed) != DataPathResult::UnverifiedDecryption ||
            parsed.payload != nullptr)
        {
            return false;
        }
        frame[1U] = 0x42U;
        link.pairwiseAndGroupKeysInstalled = false;
        if (inspectStationRx(link, frame, sizeof(frame), false, true, true,
                             parsed) != DataPathResult::UnverifiedDecryption ||
            parsed.payload != nullptr)
        {
            return false;
        }
        link.pairwiseAndGroupKeysInstalled = true;
        eapol[6U] = 0x0aU; // Forged station M4, not authenticator Group1.
        if (inspectStationRx(link, frame, sizeof(frame), false, true, true,
                             parsed) != DataPathResult::UnsupportedFrame ||
            parsed.payload != nullptr)
        {
            return false;
        }
        eapol[6U] = 0x82U;
        eapol[98U] = 0U; // Group1 cannot lack wrapped GTK data.
        if (inspectStationRx(link, frame, sizeof(frame), false, true, true,
                             parsed) != DataPathResult::UnsupportedFrame ||
            parsed.payload != nullptr)
        {
            return false;
        }
        eapol[98U] = 40U;
        frame[15U] ^= 1U; // Foreign BSSID, despite valid MIC flag.
        return inspectStationRx(link, frame, sizeof(frame), false, true, true,
                                parsed) ==
                   DataPathResult::NotFromAssociatedAccessPoint &&
               parsed.payload == nullptr;
    }

    // NOLINTEND(readability-function-cognitive-complexity)
    // NOLINTEND(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
    // NOLINTEND(*bounds-pointer-arithmetic)
    // NOLINTEND(*avoid-magic-numbers,readability-magic-numbers)

    bool rejectUnboundWpa2Eapol()
    {
        // This limited WPA2-PSK station may send only parsed pairwise M2
        // before keys and M4 after keys, both to its selected authenticator.
        // Generic EAPOL or a forged AP-side M1/M3 must not get a TX frame.
        LinkContext link {};
        link.station = {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        link.bssid = {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        link.security = LinkSecurity::Wpa2Ccmp;
        link.associated = true;
        link.rfReady = true;
        link.channelPermitted = true;
        constexpr size_t kM2EthernetBytes = 14U + 121U;
        uint8_t ethernet[kM2EthernetBytes + 1U] {};
        std::memcpy(ethernet, kAp, 6);
        std::memcpy(ethernet + 6, kStation, 6);
        ethernet[12] = 0x88;
        ethernet[13] = 0x8e;
        uint8_t *eapol = ethernet + 14;
        eapol[0] = 2;
        eapol[1] = 3;
        eapol[3] = 117; // Fixed RSN descriptor plus 22-byte RSNE.
        eapol[4] = 2;
        eapol[5] = 1;
        eapol[6] = 0x0a;  // Supplicant M2 key info.
        eapol[16] = 1;    // Replay counter.
        eapol[17] = 7;    // SNonce.
        eapol[81] = 0x55; // Synthetic nonzero MIC.
        eapol[98] = 22;
        const uint8_t rsne[22] {
            48,   20,   1, 0, 0, 0x0f, 0xac, 4,    1, 0, 0,
            0x0f, 0xac, 4, 1, 0, 0,    0x0f, 0xac, 2, 0, 0,
        };
        std::memcpy(eapol + 99, rsne, sizeof(rsne));
        uint8_t tx[192] {};
        std::memset(tx, 0xa5, sizeof(tx));
        SerializedData prepared {};
        prepared.frameBytes = 91;
        std::memset(ethernet, 0xff, 6);
        if (prepareStationTx(link, ethernet, kM2EthernetBytes, 1, tx,
                             sizeof(tx),
                             prepared) != DataPathResult::InvalidAddress ||
            tx[0] != 0xa5 || prepared.frameBytes != 91)
        {
            return false;
        }
        std::memcpy(ethernet, kStation, 6);
        ethernet[5] ^= 1U; // Valid foreign unicast destination.
        if (prepareStationTx(link, ethernet, kM2EthernetBytes, 1, tx,
                             sizeof(tx),
                             prepared) != DataPathResult::InvalidAddress ||
            tx[0] != 0xa5 || prepared.frameBytes != 91)
        {
            return false;
        }
        std::memcpy(ethernet, kAp, 6);
        // An arbitrary 1-byte EAPOL body is not an authorized key response.
        if (prepareStationTx(link, ethernet, 15, 1, tx, sizeof(tx), prepared) !=
                DataPathResult::InvalidEthernetFrame ||
            tx[0] != 0xa5 || prepared.frameBytes != 91)
        {
            return false;
        }
        // A syntactically valid incoming M1 must not be transmitted from the
        // station through the public EAPOL serializer.
        eapol[5] = 0;
        eapol[6] = 0x8a;
        eapol[8] = 16;
        eapol[81] = 0;
        if (prepareStationTx(link, ethernet, kM2EthernetBytes, 1, tx,
                             sizeof(tx), prepared) !=
                DataPathResult::InvalidEthernetFrame ||
            tx[0] != 0xa5 || prepared.frameBytes != 91)
        {
            return false;
        }
        eapol[5] = 1;
        eapol[6] = 0x0a;
        eapol[8] = 0;
        eapol[81] = 0x55;
        if (prepareStationTx(link, ethernet, kM2EthernetBytes, 1, tx,
                             sizeof(tx), prepared) != DataPathResult::Ok ||
            !prepared.isEapol || prepared.frameBytes != 153)
        {
            return false;
        }
        // M2 cannot be sent in the clear after pairwise/group installation.
        link.pairwiseAndGroupKeysInstalled = true;
        std::memset(tx, 0xa5, sizeof(tx));
        if (prepareStationTx(link, ethernet, kM2EthernetBytes, 1, tx,
                             sizeof(tx),
                             prepared) != DataPathResult::NeedsCcmpEncryption ||
            tx[0] != 0xa5 || prepared.frameBytes != 153)
        {
            return false;
        }
        // M4 carries no SNonce/key data and is the final cleartext 4-way
        // handshake response after M3 has installed the PTK/GTK.
        eapol[3] = 95;
        eapol[5] = 3;
        eapol[6] = 0x0a;
        eapol[17] = 0;
        eapol[98] = 0;
        constexpr size_t kM4EthernetBytes = 14U + 99U;
        if (prepareStationTx(link, ethernet, kM4EthernetBytes, 1, tx,
                             sizeof(tx), prepared) != DataPathResult::Ok ||
            !prepared.isEapol || prepared.frameBytes != 131)
        {
            return false;
        }
        link.pairwiseAndGroupKeysInstalled = false;
        std::memset(tx, 0xa5, sizeof(tx));
        if (prepareStationTx(link, ethernet, kM4EthernetBytes, 1, tx,
                             sizeof(tx),
                             prepared) != DataPathResult::MissingKeys ||
            tx[0] != 0xa5 || prepared.frameBytes != 131)
        {
            return false;
        }
        // A valid EAPOL payload cannot conceal an extra trailing byte.
        eapol[5] = 1;
        eapol[3] = 117;
        eapol[6] = 0x0a;
        eapol[17] = 7;
        eapol[98] = 22;
        eapol[121] = 0xa5; // Outside the 121 bytes declared by EAPOL.
        if (prepareStationTx(link, ethernet, sizeof(ethernet), 1, tx,
                             sizeof(tx), prepared) !=
                DataPathResult::InvalidEthernetFrame ||
            tx[0] != 0xa5 || prepared.frameBytes != 131)
        {
            return false;
        }

        // A forged verified-decryption flag cannot make protected EAPOL
        // admissible before the selected link reports installed keys.
        uint8_t frame[131] {};
        frame[0] = 0x08;
        frame[1] = 0x42; // FromDS + protected.
        addresses(frame, kStation);
        frame[24] = frame[25] = 0xaa;
        frame[26] = 3;
        frame[30] = 0x88;
        frame[31] = 0x8e;
        frame[32] = 2; // Valid incoming pairwise M1.
        frame[33] = 3;
        frame[35] = 95;
        frame[36] = 2;
        frame[38] = 0x8a;
        frame[40] = 16;
        frame[48] = 1;
        frame[49] = 7;
        Msdu decoded {};
        decoded.payload = frame;
        decoded.payloadLength = 1;
        if (inspectStationRx(link, frame, sizeof(frame), false, true, true,
                             decoded) != DataPathResult::UnverifiedDecryption ||
            (decoded.payload != nullptr) || (decoded.payloadLength != 0U))
        {
            return false;
        }
        link.pairwiseAndGroupKeysInstalled = true;
        if (inspectStationRx(link, frame, sizeof(frame), false, true, true,
                             decoded) != DataPathResult::UnsupportedFrame ||
            (decoded.payload != nullptr) || (decoded.payloadLength != 0U))
        {
            return false;
        }
        frame[1] = 0x02; // Post-key cleartext EAPOL cannot bypass CCMP.
        if (inspectStationRx(link, frame, sizeof(frame), false, true, true,
                             decoded) != DataPathResult::UnverifiedDecryption ||
            (decoded.payload != nullptr) || (decoded.payloadLength != 0U))
        {
            return false;
        }
        link.pairwiseAndGroupKeysInstalled = false;
        // Before installation, unprotected M1/M3 is still permissible.
        return inspectStationRx(link, frame, sizeof(frame), false, true, false,
                                decoded) == DataPathResult::Ok &&
               decoded.payload == frame + 32;
    }

    bool rejectCryptoProviderContextAliases()
    {
        // The adapter's opaque hardware owner is writable callback state.
        // Reject a crypto result whose buffer or length reference can erase
        // even the first byte of that owner, before invoking any callback.
        struct ProviderContext
        {
                size_t calls = 0x1234U;
                uint8_t storage[128] {};
        } providerContext {};

        crypto::Adapter adapter;
        const crypto::KeyHardware hw {
            &providerContext.calls,
            observingRandom,
            fakePairwise,
            fakeGroup,
            fakeRemove,
        };
        if (!adapter.configure(hw))
        {
            return false;
        }
        const Wpa2Crypto callbacks = adapter.callbacks();
        uint8_t kek[16] {};
        uint8_t wrapped[24] {};
        uint8_t output[32] {};
        if (callbacks.unwrapGtk(callbacks.context, kek, wrapped,
                                sizeof(wrapped), output, sizeof(output),
                                &providerContext.calls) ||
            providerContext.calls != 0x1234U)
        {
            return false;
        }
        if (callbacks.generateNonce(
                callbacks.context,
                reinterpret_cast<uint8_t *>(&providerContext.calls)) ||
            providerContext.calls != 0x1234U)
        {
            return false;
        }
        const Mac ap {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        uint8_t pmk[32] {};
        uint8_t nonce[32] {};
        if (callbacks.derivePtk(
                callbacks.context, pmk, ap, station, nonce, nonce,
                reinterpret_cast<uint8_t *>(&providerContext)) ||
            providerContext.calls != 0x1234U)
        {
            return false;
        }
        uint8_t eapol[99] {};
        if (callbacks.micSha1(callbacks.context, pmk, eapol, sizeof(eapol),
                              reinterpret_cast<uint8_t *>(&providerContext)) ||
            providerContext.calls != 0x1234U)
        {
            return false;
        }
        size_t length = 123;
        if (callbacks.unwrapGtk(callbacks.context, kek, wrapped,
                                sizeof(wrapped),
                                reinterpret_cast<uint8_t *>(&providerContext),
                                sizeof(providerContext), &length) ||
            length != 123 || providerContext.calls != 0x1234U)
        {
            return false;
        }
        // Disjoint outputs still reach the configured provider. This fake
        // only counts invocations: it supplies no entropy, so the adapter
        // must not accept or publish a nonce from the no-op callback.
        uint8_t independentNonce[32] {};
        return !callbacks.generateNonce(callbacks.context, independentNonce) &&
               providerContext.calls == 0x1235U && independentNonce[0] == 0;
    }

    bool rejectForgedVisibleZeroName()
    {
        uint8_t advertisement[49] {};
        beacon(advertisement);
        Bss candidate {};
        if (parseBeacon(advertisement, sizeof(advertisement),
                        candidate.beacon) != Result::Ok)
        {
            return false;
        }
        candidate.occupied = true;
        std::memset(candidate.beacon.ssid, 0, sizeof(candidate.beacon.ssid));
        candidate.beacon.hiddenSsid = false;
        Station owner;
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        if (owner.enterScanning(true, true) != StationResult::Ok)
        {
            return false;
        }
        // A forged scan snapshot must not reach authentication if its SSID
        // has no actual visible octet, regardless of its hidden flag.
        if (owner.select(station, candidate) !=
                StationResult::UnsupportedNetwork ||
            owner.state() != StationState::Scanning ||
            owner.candidate().occupied)
        {
            return false;
        }
        beacon(advertisement);
        return parseBeacon(advertisement, sizeof(advertisement),
                           candidate.beacon) == Result::Ok &&
               owner.select(station, candidate) == StationResult::Ok &&
               owner.state() == StationState::CandidateSelected;
    }

    bool rejectForgedInfrastructureCapability()
    {
        uint8_t advertisement[49] {};
        beacon(advertisement);
        Bss candidate {};
        if (parseBeacon(advertisement, sizeof(advertisement),
                        candidate.beacon) != Result::Ok)
        {
            return false;
        }
        candidate.occupied = true;
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        Station owner;
        if (owner.enterScanning(true, true) != StationResult::Ok)
        {
            return false;
        }

        // The public selection API must not trust a caller-forged
        // infrastructure flag when the 802.11 capabilities say otherwise.
        // Neither ESS nor IBSS, IBSS only, and both bits are all invalid.
        const uint16_t invalidModes[] {0U, 2U, 3U};
        for (const uint16_t mode : invalidModes)
        {
            candidate.beacon.capabilities = mode;
            if (owner.select(station, candidate) !=
                    StationResult::UnsupportedNetwork ||
                owner.state() != StationState::Scanning ||
                owner.candidate().occupied)
            {
                return false;
            }
        }
        // A genuine infrastructure advertisement is still selectable.
        candidate.beacon.capabilities = 1U;
        return owner.select(station, candidate) == StationResult::Ok &&
               owner.state() == StationState::CandidateSelected;
    }

    bool rejectEngineSelfBssidBeforeCrypto()
    {
        // A forged local station address equal to the selected WPA2 AP must
        // be rejected before handing identity and credentials to WPA2.
        constexpr uint8_t rsnIe[22] {
            48,   20,   1, 0, 0, 0x0f, 0xac, 4,    1, 0, 0,
            0x0f, 0xac, 4, 1, 0, 0,    0x0f, 0xac, 2, 0, 0,
        };
        uint8_t advertisement[49 + sizeof(rsnIe)] {};
        beacon(advertisement);
        advertisement[34] |= 0x10; // WPA2 privacy capability.
        std::memcpy(advertisement + 49, rsnIe, sizeof(rsnIe));

        WifiEngine engine;
        uint32_t providerContext = 1;
        const crypto::KeyHardware hardware {
            &providerContext, fakeRandom, fakePairwise, fakeGroup, fakeRemove,
        };
        if (!engine.configureKeys(hardware) ||
            engine.startScan(true, true) != EngineResult::Ok)
        {
            return false;
        }
        uint8_t output[256] {};
        EngineAction action {};
        const InputTrust verifiedRx {true, true, true, false};
        if (engine.acceptRx(advertisement, sizeof(advertisement), verifiedRx,
                            {-40, 1000}, output, sizeof(output),
                            action) != EngineResult::Ok ||
            engine.scan().size() != 1)
        {
            return false;
        }
        const Mac ap {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        const uint8_t ssid[] {'T', 'e', 's', 't'};
        uint8_t pmk[32] {1};
        if (engine.chooseNetwork(ap, ssid, sizeof(ssid), 6, false, true, pmk) !=
                EngineResult::InvalidInput ||
            engine.stationState() != StationState::Scanning)
        {
            return false;
        }
        // Rejecting the identity cannot consume a valid candidate or make a
        // subsequent independently addressed WPA2 selection impossible.
        return engine.chooseNetwork(station, ssid, sizeof(ssid), 6, false, true,
                                    pmk) == EngineResult::Ok &&
               engine.stationState() == StationState::CandidateSelected;
    }

    bool selectExactDriverOwnedWpa2Bssid()
    {
        constexpr size_t kBeaconBytes = 49U;
        constexpr size_t kPrivacyOffset = 34U;
        constexpr uint8_t kWpa2InfrastructureCapabilities = 0x11U;
        constexpr size_t kSourceLastByte = 15U;
        constexpr size_t kBssidLastByte = 21U;
        constexpr uint8_t kSecondApLastByte = 0x56U;
        constexpr uint8_t kTestChannel = 6U;
        constexpr int8_t kWeakerRssi = -75;
        constexpr int8_t kStrongerRssi = -25;
        constexpr int8_t kUnconfiguredRssi = -50;
        constexpr uint64_t kFirstObservationMs = 1000U;
        constexpr uint64_t kSecondObservationMs = 1001U;
        constexpr uint64_t kThirdObservationMs = 1002U;
        constexpr size_t kTestTxCapacity = 256U;
        constexpr size_t kDestinationOffset = 4U;
        constexpr std::array<uint8_t, 22> rsnIe {
            {
                48,   20,   1, 0, 0, 0x0f, 0xac, 4,    1, 0, 0,
                0x0f, 0xac, 4, 1, 0, 0,    0x0f, 0xac, 2, 0, 0,
            },
        };
        std::array<uint8_t, kBeaconBytes + rsnIe.size()> weaker {};
        beacon(weaker.data());
        weaker.at(kPrivacyOffset) = kWpa2InfrastructureCapabilities;
        std::copy(rsnIe.begin(), rsnIe.end(),
                  std::next(weaker.begin(), kBeaconBytes));
        auto stronger = weaker;
        stronger.at(kSourceLastByte) = kSecondApLastByte;
        stronger.at(kBssidLastByte) = kSecondApLastByte;
        const Mac own {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        const Mac requested {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        const Mac unknown {{0x02, 0x11, 0x22, 0x33, 0x44, 0x57}};
        const std::array<uint8_t, 4> ssid {{'T', 'e', 's', 't'}};
        std::array<uint8_t, kWpa2PmkBytes> pmk {{1}};
        std::array<uint8_t, kWpa2PmkBytes> emptyPmk {};
        const InputTrust verifiedRx {true, true, true, false};
        std::array<uint8_t, kTestTxCapacity> tx {};
        EngineAction action {};
        uint32_t context = 1;
        const crypto::KeyHardware hw {
            &context, fakeRandom, fakePairwise, fakeGroup, fakeRemove,
        };
        WifiEngine engine;
        if (!engine.configureKeys(hw) ||
            engine.startScan(true, true) != EngineResult::Ok ||
            engine.acceptRx(weaker.data(), weaker.size(), verifiedRx,
                            {kWeakerRssi, kFirstObservationMs}, tx.data(),
                            tx.size(), action) != EngineResult::Ok ||
            engine.acceptRx(stronger.data(), stronger.size(), verifiedRx,
                            {kStrongerRssi, kSecondObservationMs}, tx.data(),
                            tx.size(), action) != EngineResult::Ok ||
            engine.scan().size() != 2)
        {
            return false;
        }
        // Exact OS-requested BSSID must win over a stronger AP with the same
        // SSID; bad inputs must not consume the valid WPA2 candidate.
        if (engine.chooseNetworkForDriverSupplicant(
                own, unknown, ssid.data(), ssid.size(), kTestChannel,
                pmk.data()) != EngineResult::NoMatchingBss ||
            engine.chooseNetworkForDriverSupplicant(
                requested, requested, ssid.data(), ssid.size(), kTestChannel,
                pmk.data()) != EngineResult::InvalidInput ||
            engine.chooseNetworkForDriverSupplicant(
                own, requested, ssid.data(), ssid.size(), kTestChannel,
                emptyPmk.data()) != EngineResult::CryptoFailure ||
            engine.stationState() != StationState::Scanning ||
            engine.chooseNetworkForDriverSupplicant(
                own, requested, ssid.data(), ssid.size(), kTestChannel,
                pmk.data()) != EngineResult::Ok ||
            engine.osSupplicantOwnsWpa2() ||
            engine.stationState() != StationState::CandidateSelected ||
            engine.requestAuthentication(3, tx.data(), tx.size(), action) !=
                EngineResult::Ok ||
            action.kind != ActionKind::TransmitAuthentication ||
            std::memcmp(&tx.at(kDestinationOffset), &requested.bytes[0],
                        sizeof(requested.bytes)) != 0)
        {
            return false;
        }
        WifiEngine unconfigured;
        return unconfigured.startScan(true, true) == EngineResult::Ok &&
               unconfigured.acceptRx(weaker.data(), weaker.size(), verifiedRx,
                                     {kUnconfiguredRssi, kThirdObservationMs},
                                     tx.data(), tx.size(),
                                     action) == EngineResult::Ok &&
               unconfigured.chooseNetworkForDriverSupplicant(
                   own, requested, ssid.data(), ssid.size(), kTestChannel,
                   pmk.data()) == EngineResult::CryptoUnavailable &&
               unconfigured.stationState() == StationState::Scanning;
    }

    bool rejectStationManagementTxAlias()
    {
        uint8_t advertisement[49] {};
        beacon(advertisement);
        Bss candidate {};
        if (parseBeacon(advertisement, sizeof(advertisement),
                        candidate.beacon) != Result::Ok)
        {
            return false;
        }
        candidate.occupied = true;
        const Mac ownMac {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        Station owner;
        if (owner.enterScanning(true, true) != StationResult::Ok ||
            owner.select(ownMac, candidate) != StationResult::Ok)
        {
            return false;
        }

        struct TxBuffer
        {
                size_t written;
                uint8_t storage[128];
        } tx {};

        tx.written = 123;
        std::memset(tx.storage, 0xa5, sizeof(tx.storage));
        uint8_t previousTx[sizeof(tx)] {};
        std::memcpy(previousTx, &tx, sizeof(tx));
        if (owner.authenticationRequest(1, reinterpret_cast<uint8_t *>(&tx),
                                        sizeof(tx), tx.written) !=
                Result::OverlappingBuffers ||
            std::memcmp(&tx, previousTx, sizeof(tx)) != 0 ||
            owner.state() != StationState::CandidateSelected)
        {
            return false;
        }

        // A byte pointer into owner storage must not overwrite association
        // state even if the output-length reference is kept elsewhere.
        uint8_t previousOwner[sizeof(owner)] {};
        std::memcpy(previousOwner, &owner, sizeof(owner));
        size_t written = 777;
        if (owner.authenticationRequest(1, reinterpret_cast<uint8_t *>(&owner),
                                        sizeof(owner), written) !=
                Result::OverlappingBuffers ||
            written != 777 ||
            std::memcmp(&owner, previousOwner, sizeof(owner)) != 0)
        {
            return false;
        }
        uint8_t frame[128] {};
        if (owner.authenticationRequest(1, frame, sizeof(frame), written) !=
                Result::Ok ||
            written != 30)
        {
            return false;
        }
        uint8_t response[30] {};
        authenticationResponse(response);
        if (owner.onAuthenticationResponse(response, sizeof(response)) !=
            StationResult::Ok)
        {
            return false;
        }
        tx.written = 234;
        std::memcpy(previousTx, &tx, sizeof(tx));
        if (owner.associationRequest(2, reinterpret_cast<uint8_t *>(&tx),
                                     sizeof(tx), tx.written) !=
                Result::OverlappingBuffers ||
            std::memcmp(&tx, previousTx, sizeof(tx)) != 0 ||
            owner.state() != StationState::Authenticated)
        {
            return false;
        }
        std::memcpy(previousOwner, &owner, sizeof(owner));
        written = 888;
        if (owner.associationRequest(2, reinterpret_cast<uint8_t *>(&owner),
                                     sizeof(owner),
                                     written) != Result::OverlappingBuffers ||
            written != 888 ||
            std::memcmp(&owner, previousOwner, sizeof(owner)) != 0)
        {
            return false;
        }
        return owner.associationRequest(2, frame, sizeof(frame), written) ==
                   Result::Ok &&
               written > 30 &&
               owner.state() == StationState::AssociationFramePrepared;
    }

    bool rejectMalformedLinkLossIes()
    {
        // Deauth/disassoc may carry optional well-formed IEs. A truncated
        // suffix must not tear down a running link just because the first
        // 26 bytes contain a valid AP identity and nonzero reason code.
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        const Mac ap {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        uint8_t frame[31] {};
        addresses(frame, kStation);
        frame[24] = 7;   // Valid, nonzero reason code.
        frame[26] = 221; // Vendor-specific IE.
        frame[27] = 3;
        frame[28] = 0x12;
        frame[29] = 0x34;
        frame[30] = 0x56;
        const uint8_t subtypes[] {0xc0, 0xa0};
        for (uint8_t subtype : subtypes)
        {
            LinkMonitor monitor;
            if (monitor.started(station, ap,
                                LinkStartConfig {
                                    100,
                                    1000,
                                    false,
                                    false,
                                }) != LinkMonitorResult::Ok)
            {
                return false;
            }
            frame[0] = subtype;
            if (monitor.observeManagement(frame, 27, 1500, true, false) !=
                    LinkMonitorResult::InvalidFrame ||
                monitor.status().state != LinkState::Associated ||
                monitor.status().lastBeaconMs != 1000 ||
                monitor.observeManagement(frame, 30, 1510, true, false) !=
                    LinkMonitorResult::InvalidFrame ||
                monitor.status().state != LinkState::Associated ||
                monitor.status().lastBeaconMs != 1000)
            {
                return false;
            }
            // Optional complete IEs remain permitted, including on a
            // correctly formed disassociation frame.
            if (monitor.observeManagement(frame, sizeof(frame), 1520, true,
                                          false) != LinkMonitorResult::Ok ||
                monitor.status().state != LinkState::ReconnectPending)
            {
                return false;
            }
        }
        return true;
    }

    bool rejectExpiredBeaconRefresh()
    {
        // A delayed watchdog callback cannot let a beacon arriving AFTER
        // ten missed beacon intervals renew an already expired link lease.
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        const Mac ap {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        uint8_t advertisement[49] {};
        beacon(advertisement);
        const LinkStartConfig session {100, 1000, false, false};
        LinkMonitor boundary;
        if (boundary.started(station, ap, session) != LinkMonitorResult::Ok ||
            boundary.observeManagement(advertisement, sizeof(advertisement),
                                       2200, true,
                                       false) != LinkMonitorResult::Ok ||
            boundary.status().state != LinkState::Associated ||
            boundary.status().lastBeaconMs != 2200 ||
            boundary.status().acceptedBeacons != 1)
        {
            return false;
        }
        LinkMonitor expired;
        if (expired.started(station, ap, session) != LinkMonitorResult::Ok ||
            expired.observeManagement(advertisement, sizeof(advertisement),
                                      2201, true,
                                      false) != LinkMonitorResult::Ok ||
            expired.status().state != LinkState::ReconnectPending ||
            expired.status().reason != LinkLoss::BeaconTimeout ||
            expired.status().lastBeaconMs != 1000 ||
            expired.status().acceptedBeacons != 0 ||
            expired.reconnectDue(2700) || !expired.reconnectDue(2701) ||
            expired.observeManagement(advertisement, sizeof(advertisement),
                                      2202, true, false) !=
                LinkMonitorResult::NotAssociated)
        {
            return false;
        }
        // A foreign AP cannot force expiry by offering spoofed liveness.
        LinkMonitor foreign;
        if (foreign.started(station, ap, session) != LinkMonitorResult::Ok)
        {
            return false;
        }
        advertisement[10] ^= 0x02U;
        const auto rejected = foreign.observeManagement(
            advertisement, sizeof(advertisement), 2201, true, false);
        advertisement[10] ^= 0x02U;
        return rejected == LinkMonitorResult::ForeignAccessPoint &&
               foreign.status().state == LinkState::Associated &&
               foreign.status().lastBeaconMs == 1000 &&
               foreign.observeManagement(advertisement, sizeof(advertisement),
                                         2201, true,
                                         false) == LinkMonitorResult::Ok &&
               foreign.status().state == LinkState::ReconnectPending;
    }

    bool rejectNullLinkManagementRx()
    {
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        const Mac ap {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        LinkMonitor monitor;
        if (monitor.started(station, ap,
                            LinkStartConfig {
                                100,
                                1000,
                                false,
                                false,
                            }) != LinkMonitorResult::Ok)
        {
            return false;
        }
        if (monitor.observeManagement(nullptr, 26, 1500, true, false) !=
                LinkMonitorResult::InvalidFrame ||
            monitor.observeManagement(nullptr, 0, 1510, true, false) !=
                LinkMonitorResult::InvalidFrame ||
            monitor.observeManagement(nullptr, 26, 1520, false, false) !=
                LinkMonitorResult::UnverifiedFrame)
        {
            return false;
        }
        return monitor.status().state == LinkState::Associated &&
               monitor.status().lastBeaconMs == 1000 &&
               monitor.status().acceptedBeacons == 0 &&
               !monitor.reconnectDue(1600);
    }

    bool rejectUnexpectedProtectedLinkManagementRx()
    {
        // A Protected bit with a caller-supplied true MIC/PN assertion cannot
        // authenticate robust management when PMF was never negotiated.
        // Neither forged deauth nor disassoc may revoke an Open association.
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        const Mac ap {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        uint8_t forged[26] {};
        addresses(forged, kStation);
        forged[1] = 0x40; // Protected management frame.
        forged[24] = 7;   // Nonzero reason code.
        const uint8_t subtypes[] = {0xc0, 0xa0};
        for (uint8_t subtype : subtypes)
        {
            LinkMonitor open;
            if (open.started(station, ap,
                             LinkStartConfig {
                                 100,
                                 1000,
                                 false,
                                 false,
                             }) != LinkMonitorResult::Ok)
            {
                return false;
            }
            forged[0] = subtype;
            if (open.observeManagement(forged, sizeof(forged), 1500, true,
                                       true) !=
                    LinkMonitorResult::InvalidFrame ||
                open.status().state != LinkState::Associated)
            {
                return false;
            }
        }
        // A genuinely PMF-negotiated session still honors a verified robust
        // management frame from its associated AP.
        LinkMonitor pmf;
        if (pmf.started(station, ap,
                        LinkStartConfig {
                            100,
                            1000,
                            true,
                            false,
                        }) != LinkMonitorResult::Ok)
        {
            return false;
        }
        forged[0] = 0xc0;
        return pmf.observeManagement(forged, sizeof(forged), 1500, true,
                                     true) == LinkMonitorResult::Ok &&
               pmf.status().state == LinkState::ReconnectPending;
    }

    bool rejectAliasedLinkManagementRx()
    {
        // A callback may accidentally borrow a link monitor's live snapshot
        // as RX storage. A valid deauth would otherwise overwrite its own
        // borrowed source bytes when transitioning to reconnect-pending.
        LinkMonitor monitor;
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        const Mac ap {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        if (monitor.started(station, ap,
                            LinkStartConfig {
                                100,
                                1000,
                                false,
                                false,
                            }) != LinkMonitorResult::Ok)
        {
            return false;
        }
        constexpr size_t kDeauthBytes = 26;
        const auto *const start =
            reinterpret_cast<const uint8_t *>(&monitor.status());
        const auto *const tail =
            reinterpret_cast<const uint8_t *>(&monitor.status().lastBeaconMs);
        if (sizeof(LinkSnapshot) - static_cast<size_t>(tail - start) <
            kDeauthBytes)
        {
            return false;
        }
        auto *const borrowed = const_cast<uint8_t *>(tail);
        std::memset(borrowed, 0, kDeauthBytes);
        borrowed[0] = 0xc0; // Deauthentication management subtype.
        addresses(borrowed, kStation);
        borrowed[24] = 7; // Valid nonzero reason code.
        uint8_t original[kDeauthBytes] {};
        std::memcpy(original, borrowed, sizeof(original));
        if (monitor.observeManagement(borrowed, kDeauthBytes, ~uint64_t(0),
                                      true, false) !=
                LinkMonitorResult::InvalidArgument ||
            monitor.status().state != LinkState::Associated ||
            std::memcmp(borrowed, original, sizeof(original)) != 0)
        {
            return false;
        }
        // Independent, FCS-verified AP deauth continues to revoke a link.
        LinkMonitor independent;
        if (independent.started(station, ap,
                                LinkStartConfig {
                                    100,
                                    1000,
                                    false,
                                    false,
                                }) != LinkMonitorResult::Ok)
        {
            return false;
        }
        return independent.observeManagement(original, sizeof(original), 1500,
                                             true,
                                             false) == LinkMonitorResult::Ok &&
               independent.status().state == LinkState::ReconnectPending &&
               independent.status().reason == LinkLoss::Deauthentication;
    }

    bool rejectAuthenticationWithoutTxBuffer()
    {
        // A rejected AP authentication does not need an association TX
        // buffer. A missing buffer must never conceal the rejection and
        // strand the candidate in AuthenticationFramePrepared.
        static WifiEngine engine;
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        const InputTrust trusted {true, true, true, false};
        uint8_t advertisement[49] {};
        beacon(advertisement);
        uint8_t tx[128] {};
        EngineAction action {};
        if (engine.startScan(true, true) != EngineResult::Ok ||
            engine.acceptRx(advertisement, sizeof(advertisement), trusted,
                            {-40, 1000}, tx, sizeof(tx),
                            action) != EngineResult::Ok ||
            engine.chooseNetwork(station,
                                 reinterpret_cast<const uint8_t *>("Test"), 4,
                                 6, true, false, nullptr) != EngineResult::Ok ||
            engine.requestAuthentication(1, tx, sizeof(tx), action) !=
                EngineResult::Ok)
        {
            return false;
        }

        uint8_t response[30] {};
        authenticationResponse(response);
        response[28] = 13; // AP rejected Open System authentication.
        if (engine.acceptRx(response, sizeof(response), trusted, {0, 1010},
                            nullptr, 0,
                            action) != EngineResult::AccessPointRejected ||
            engine.stationState() != StationState::Inactive ||
            action.kind != ActionKind::None)
        {
            return false;
        }

        // A malformed response also must not request TX buffer capacity.
        if (engine.startScan(true, true) != EngineResult::Ok ||
            engine.acceptRx(advertisement, sizeof(advertisement), trusted,
                            {-40, 2000}, tx, sizeof(tx),
                            action) != EngineResult::Ok ||
            engine.chooseNetwork(station,
                                 reinterpret_cast<const uint8_t *>("Test"), 4,
                                 6, true, false, nullptr) != EngineResult::Ok ||
            engine.requestAuthentication(2, tx, sizeof(tx), action) !=
                EngineResult::Ok)
        {
            return false;
        }
        authenticationResponse(response);
        response[26] = 3; // Not transaction 2.
        if (engine.acceptRx(response, sizeof(response), trusted, {0, 2010},
                            nullptr, 0,
                            action) != EngineResult::InvalidReceivedFrame ||
            engine.stationState() !=
                StationState::AuthenticationFramePrepared ||
            action.kind != ActionKind::None)
        {
            return false;
        }
        authenticationResponse(response);
        if (engine.acceptRx(response, sizeof(response), trusted, {0, 2010},
                            nullptr, 0,
                            action) != EngineResult::BufferTooSmall ||
            engine.stationState() != StationState::AuthenticationFramePrepared)
        {
            return false;
        }
        // A valid retry still emits the association body after an output
        // allocation is supplied, and never reports native Wi-Fi success.
        return engine.acceptRx(response, sizeof(response), trusted, {0, 2010},
                               tx, sizeof(tx), action) == EngineResult::Ok &&
               action.kind == ActionKind::TransmitAssociation &&
               engine.stationState() == StationState::AssociationFramePrepared;
    }

} // namespace

int main()
{
    using namespace simpleath::ieee80211;
    if (!rejectMalformedLinkLossIes())
    {
        return 51;
    }
    if (!rejectExpiredBeaconRefresh())
    {
        return 71;
    }
    if (!rejectNullLinkManagementRx())
    {
        return 55;
    }
    if (!rejectUnexpectedProtectedLinkManagementRx())
    {
        return 49;
    }
    if (!rejectAliasedLinkManagementRx())
    {
        return 47;
    }
    if (!associationUsesSelectedRates())
    {
        return 44;
    }
    if (!rejectDisjointAssociationRates())
    {
        return 32;
    }
    if (!selectExactDriverOwnedWpa2Bssid())
    {
        return 68;
    }
    if (!rejectEngineSelfBssidBeforeCrypto())
    {
        return 25;
    }
    if (!rejectStationManagementTxAlias())
    {
        return 19;
    }
    if (!rejectForgedVisibleZeroName())
    {
        return 23;
    }
    if (!rejectForgedInfrastructureCapability())
    {
        return 26;
    }
    if (!rejectInvalidFromDsSource())
    {
        return 20;
    }
    if (!rejectIdenticalLinkIdentities())
    {
        return 24;
    }
    if (!rejectOpenLinkWithInstalledWpa2Keys())
    {
        return 45;
    }
    if (!rejectOpenAssociationEapolTx())
    {
        return 48;
    }
    if (!rejectForeignWpa2Authenticator())
    {
        return 21;
    }
    if (!protectedWpa2Receive())
    {
        return 59;
    }
    if (!protectedGroup1Decrypt())
    {
        return 60;
    }
    if (!protectedGtkMulticastReceive())
    {
        return 61;
    }
    if (!protectedGroup1RxAdmission())
    {
        return 58;
    }
    if (!protectedWpa2Transmit())
    {
        return 57;
    }
    if (!rejectUnboundWpa2Eapol())
    {
        return 31;
    }
    if (!rejectMalformedWpa2RxEapol())
    {
        return 43;
    }
    if (!rejectCryptoProviderContextAliases())
    {
        return 22;
    }
    if (!rejectAuthenticationWithoutTxBuffer())
    {
        return 50;
    }
    // Native lifecycle must allocate/serialize persistent owner storage.
    // This static host fixture has no controlling radio or OS interface.
    static WifiEngine engine;
    const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
    const InputTrust syntheticTrust {true, true, true, false};
    const InputTrust verifiedRxWithFcs {true, true, true, false, true};
    const InputTrust unverifiedFrame {true, true, false, false};
    uint8_t tx[512] {};
    uint8_t probe[49] {};
    beacon(probe);
    EngineAction action {};
    if (engine.startScan(true, true) != EngineResult::Ok ||
        engine.hasNativeWifiInterface())
    {
        return 1;
    }
    // Default construction must fail closed even without `{}` value-init.
    // A caller that forgets to populate trust cannot assert RF or DMA proof.
    InputTrust defaultTrust;
    if (defaultTrust.radioReady || defaultTrust.channelAuthorized ||
        defaultTrust.dmaAndFcsVerified ||
        defaultTrust.ccmpMicAndReplayVerified ||
        defaultTrust.rxFrameIncludesFcs)
    {
        return 55;
    }
    if (engine.acceptRx(probe, sizeof(probe), defaultTrust, {-42, 1000}, tx,
                        sizeof(tx), action) != EngineResult::InvalidInput ||
        action.kind != ActionKind::None)
    {
        return 56;
    }
    if (engine.acceptRx(probe, sizeof(probe), unverifiedFrame, {-42, 1000}, tx,
                        sizeof(tx), action) != EngineResult::InvalidInput ||
        action.kind != ActionKind::None)
    {
        return 2;
    }
    // An inconsistent FCS layout cannot underflow the MAC frame length.
    const uint8_t truncatedFcs[3] {0x08, 0x02, 0xff};
    if (engine.acceptRx(truncatedFcs, sizeof(truncatedFcs), verifiedRxWithFcs,
                        {-42, 999}, tx, sizeof(tx),
                        action) != EngineResult::InvalidReceivedFrame ||
        action.kind != ActionKind::None)
    {
        return 54;
    }
    // A verified DMA buffer can still contain the trailing FCS. Those four
    // bytes are NOT management information elements. The same parser must
    // accept the BSS as a stripped frame, without corrupting scan admission.
    uint8_t probeWithFcs[sizeof(probe) + 4] {};
    std::memcpy(probeWithFcs, probe, sizeof(probe));
    probeWithFcs[sizeof(probe)] = 0xfe;
    probeWithFcs[sizeof(probe) + 1] = 0xff;
    if (engine.acceptRx(probeWithFcs, sizeof(probeWithFcs), verifiedRxWithFcs,
                        {-42, 999}, tx, sizeof(tx),
                        action) != EngineResult::Ok ||
        action.kind != ActionKind::ScanCacheUpdated ||
        engine.scan().size() != 1)
    {
        return 52;
    }
    if (engine.acceptRx(probe, sizeof(probe), syntheticTrust, {-42, 1000}, tx,
                        sizeof(tx), action) != EngineResult::Ok ||
        action.kind != ActionKind::ScanCacheUpdated ||
        action.nativeInterfaceUsable || engine.scan().size() != 1)
    {
        return 3;
    }
    if (engine.chooseNetwork(station, reinterpret_cast<const uint8_t *>("Test"),
                             4, 6, true, false, nullptr) != EngineResult::Ok ||
        engine.startScan(true, true) != EngineResult::InvalidState)
    {
        return 4;
    }
    if (engine.requestAuthentication(10, tx, sizeof(tx), action) !=
            EngineResult::Ok ||
        action.kind != ActionKind::TransmitAuthentication ||
        action.bytes != 30 || action.nativeInterfaceUsable)
    {
        return 5;
    }
    // The native controller may not expose a selected (but unassociated)
    // BSS as an OS-visible connection. Failed output is cleared.
    Bss associatedBss {};
    associatedBss.occupied = true;
    if (engine.copyAssociatedBss(associatedBss) || associatedBss.occupied)
    {
        return kAssociatedBssSnapshotFailure;
    }
    uint8_t auth[30] {};
    authenticationResponse(auth);
    // Exact selected-rate capacity must work before authentication is
    // consumed; the former fixed 12-rate estimate rejected this 38-byte TX.
    if (engine.acceptRx(auth, sizeof(auth), syntheticTrust, {0, 1010}, tx, 38,
                        action) != EngineResult::Ok ||
        action.kind != ActionKind::TransmitAssociation || action.bytes != 38 ||
        action.nativeInterfaceUsable)
    {
        return 6;
    }
    uint8_t assoc[34] {};
    associationResponse(assoc);
    // A changed AP privacy capability cannot silently turn our selected
    // Open BSS into a protected association; retain retryable TX state.
    assoc[24] |= 0x10U;
    if (engine.acceptRx(assoc, sizeof(assoc), syntheticTrust, {0, 1020}, tx,
                        sizeof(tx),
                        action) != EngineResult::InvalidReceivedFrame ||
        engine.stationState() != StationState::AssociationFramePrepared ||
        action.kind != ActionKind::None)
    {
        return 27;
    }
    assoc[24] &= static_cast<uint8_t>(~0x10U);
    if (engine.acceptRx(assoc, sizeof(assoc), syntheticTrust, {0, 1020}, tx,
                        sizeof(tx), action) != EngineResult::Ok ||
        action.kind != ActionKind::OpenAssociationEstablished ||
        engine.stationState() != StationState::AssociatedOpen ||
        action.nativeInterfaceUsable || engine.hasNativeWifiInterface())
    {
        return 7;
    }

    if (!engine.copyAssociatedBss(associatedBss) || !associatedBss.occupied ||
        associatedBss.beacon.channel != kAssociatedBssTestChannel ||
        associatedBss.beacon.ssidLength != 4U ||
        associatedBss.beacon.ssid[0] != 'T' ||
        associatedBss.beacon.ssid[3] != 't' ||
        std::memcmp(&associatedBss.beacon.bssid.bytes[0], &kAp[0],
                    sizeof(kAp)) != 0)
    {
        return kAssociatedBssSnapshotFailure;
    }

    // On RX, a verified but retained FCS is not Ethernet payload. The
    // caller-provided layout bit must strip it before LLC/SNAP delivery.
    uint8_t incoming[24 + 8 + 3 + 4] {};
    incoming[0] = 0x08; // Data subtype.
    incoming[1] = 0x02; // FromDS, not ToDS.
    std::memcpy(incoming + 4, kStation, 6);
    std::memcpy(incoming + 10, kAp, 6);
    std::memcpy(incoming + 16, kAp, 6);
    incoming[24] = incoming[25] = 0xaa;
    incoming[26] = 3;
    incoming[30] = 0x08; // IPv4 Ethertype.
    incoming[32] = 0x45;
    incoming[33] = 0x01;
    incoming[34] = 0x02;
    incoming[35] = 0xfa; // FCS is verified externally, not decoded here.
    incoming[36] = 0xfb;
    incoming[37] = 0xfc;
    incoming[38] = 0xfd;
    if (engine.acceptRx(incoming, sizeof(incoming), verifiedRxWithFcs,
                        {-42, 1030}, tx, sizeof(tx),
                        action) != EngineResult::Ok ||
        action.kind != ActionKind::ReceivedPayload ||
        action.receivedPayload != incoming + 32 ||
        action.receivedPayloadBytes != 3 || action.etherType != 0x0800)
    {
        return 53;
    }

    // A verified, associated MPDU must never be delivered twice, even when
    // its retry flag is missing. The filter runs after security validation.
    incoming[1] |= 0x08U;
    if (engine.acceptRx(incoming, sizeof(incoming), verifiedRxWithFcs,
                        {-42, 1031}, tx, sizeof(tx),
                        action) != EngineResult::NoAction ||
        action.kind != ActionKind::None)
    {
        return 57;
    }
    incoming[1] &= static_cast<uint8_t>(~0x08U);
    if (engine.acceptRx(incoming, sizeof(incoming), verifiedRxWithFcs,
                        {-42, 1032}, tx, sizeof(tx),
                        action) != EngineResult::NoAction ||
        action.kind != ActionKind::None)
    {
        return 58;
    }
    incoming[22] = 0x20;  // Sequence 2, fragment 0.
    incoming[1] |= 0x40U; // Unsupported protected Open-link payload.
    if (engine.acceptRx(incoming, sizeof(incoming), verifiedRxWithFcs,
                        {-42, 1033}, tx, sizeof(tx),
                        action) != EngineResult::InvalidReceivedFrame ||
        action.kind != ActionKind::None)
    {
        return 59;
    }
    incoming[1] &= static_cast<uint8_t>(~0x40U);
    if (engine.acceptRx(incoming, sizeof(incoming), verifiedRxWithFcs,
                        {-42, 1034}, tx, sizeof(tx),
                        action) != EngineResult::Ok ||
        action.kind != ActionKind::ReceivedPayload)
    {
        return 60;
    }
    incoming[22] = 0; // Old sequence 0 remains in the receive window.
    if (engine.acceptRx(incoming, sizeof(incoming), verifiedRxWithFcs,
                        {-42, 1035}, tx, sizeof(tx),
                        action) != EngineResult::NoAction ||
        action.kind != ActionKind::None)
    {
        return 61;
    }

    // The hardware may interleave independent QoS traffic identifiers.
    // A repeated sequence within one TID is a duplicate, but the same
    // sequence in another TID is not a duplicate. Sequence 4095 wraps to 0.
    uint8_t qos[26 + 8 + 3] {};
    qos[0] = 0x88; // QoS data, FromDS.
    qos[1] = 0x02;
    std::memcpy(qos + 4, kStation, 6);
    std::memcpy(qos + 10, kAp, 6);
    std::memcpy(qos + 16, kAp, 6);
    std::memcpy(qos + 26, incoming + 24, 11);
    qos[22] = 0x40; // Sequence 4.
    qos[24] = 0;    // TID 0, no A-MSDU.
    if (engine.acceptRx(qos, sizeof(qos), syntheticTrust, {-42, 1036}, tx,
                        sizeof(tx), action) != EngineResult::Ok ||
        action.kind != ActionKind::ReceivedPayload)
    {
        return 62;
    }
    qos[24] = 1; // TID 1 retains a different sequence window.
    if (engine.acceptRx(qos, sizeof(qos), syntheticTrust, {-42, 1037}, tx,
                        sizeof(tx), action) != EngineResult::Ok ||
        action.kind != ActionKind::ReceivedPayload)
    {
        return 63;
    }
    if (engine.acceptRx(qos, sizeof(qos), syntheticTrust, {-42, 1038}, tx,
                        sizeof(tx), action) != EngineResult::NoAction ||
        action.kind != ActionKind::None)
    {
        return 64;
    }
    // Group-addressed QoS traffic may use a distinct AP sequence counter.
    // It must not be discarded due to an identical unicast TID and SN.
    std::memset(qos + 4, 0xff, 6);
    if (engine.acceptRx(qos, sizeof(qos), syntheticTrust, {-42, 1038}, tx,
                        sizeof(tx), action) != EngineResult::Ok ||
        action.kind != ActionKind::ReceivedPayload)
    {
        return 68;
    }
    std::memcpy(qos + 4, kStation, 6);
    qos[24] = 2;
    qos[22] = 0xf0;
    qos[23] = 0xff; // 12-bit sequence 4095.
    if (engine.acceptRx(qos, sizeof(qos), syntheticTrust, {-42, 1039}, tx,
                        sizeof(tx), action) != EngineResult::Ok ||
        action.kind != ActionKind::ReceivedPayload)
    {
        return 65;
    }
    qos[22] = qos[23] = 0; // Wrap to sequence 0.
    if (engine.acceptRx(qos, sizeof(qos), syntheticTrust, {-42, 1040}, tx,
                        sizeof(tx), action) != EngineResult::Ok ||
        action.kind != ActionKind::ReceivedPayload)
    {
        return 66;
    }
    qos[22] = 0xf0;
    qos[23] = 0xff;
    if (engine.acceptRx(qos, sizeof(qos), syntheticTrust, {-42, 1041}, tx,
                        sizeof(tx), action) != EngineResult::NoAction ||
        action.kind != ActionKind::None)
    {
        return 67;
    }

    // An OPEN A-MSDU shares the same per-TID sequence ledger as ordinary
    // QoS MPDUs. It is all-or-nothing and cannot be delivered twice.
    uint8_t aggregate[26U + 23U + 1U + 23U] {};
    std::memcpy(aggregate, qos, 26U);
    aggregate[22U] = 0x10U; // Sequence 1 on TID 2.
    aggregate[23U] = 0U;
    aggregate[24U] = 0x82U;
    for (size_t index = 0; index < 2U; ++index)
    {
        uint8_t *const subframe = aggregate + (index == 0U ? 26U : 50U);
        if (index == 0U)
        {
            std::memcpy(subframe, kStation, 6U);
        }
        else
        {
            std::memset(subframe, 0xff, 6U);
        }
        std::memcpy(subframe + 6U, kAp, 6U);
        subframe[13U] = 9U;
        subframe[14U] = 0xaaU;
        subframe[15U] = 0xaaU;
        subframe[16U] = 3U;
        subframe[20U] = 0x08U;
        subframe[22U] = static_cast<uint8_t>('A' + index);
    }
    AmsduPayload aggregates {};
    if (engine.acceptOpenAmsduRx(aggregate, sizeof(aggregate), syntheticTrust,
                                 aggregates) != EngineResult::Ok ||
        aggregates.count != 2U || aggregates.subframes[0].payload[0] != 'A' ||
        aggregates.subframes[1].payload[0] != 'B' ||
        engine.acceptOpenAmsduRx(aggregate, sizeof(aggregate), syntheticTrust,
                                 aggregates) != EngineResult::NoAction ||
        aggregates.count != 0U)
    {
        return 69;
    }
    aggregate[22U] = 0x20U; // New sequence, invalid foreign recipient.
    // A unicast DA which differs from the associated station must fail.
    aggregate[50U] = 0x02U;
    aggregate[50U + 1U] = 0xeeU;
    if (engine.acceptOpenAmsduRx(aggregate, sizeof(aggregate), syntheticTrust,
                                 aggregates) !=
            EngineResult::InvalidReceivedFrame ||
        aggregates.count != 0U)
    {
        return 70;
    }

    uint8_t ethernet[17] {};
    std::memcpy(ethernet, kAp, 6);
    std::memcpy(ethernet + 6, kStation, 6);
    ethernet[12] = 0x08;
    ethernet[13] = 0x00;
    ethernet[14] = 0x45;
    if (engine.encodeOutgoingEthernet(ethernet, sizeof(ethernet), 12,
                                      syntheticTrust, tx, sizeof(tx),
                                      action) != EngineResult::Ok ||
        action.kind != ActionKind::TransmitData || action.bytes == 0 ||
        action.nativeInterfaceUsable)
    {
        return 8;
    }
    // A DATA callback may precede an overdue beacon watchdog. It must
    // expire the missed-beacon lease before accepting new Ethernet payload.
    // No new sequence or verified FCS may extend AP beacon liveness.
    incoming[22] = 0x30U; // New data sequence, beyond previous RX history.
    if (engine.acceptRx(incoming, sizeof(incoming), verifiedRxWithFcs,
                        {-42, 2220}, tx, sizeof(tx),
                        action) != EngineResult::Ok ||
        action.kind != ActionKind::ReceivedPayload)
    {
        return 72;
    }
    incoming[22] = 0x40U;
    if (engine.acceptRx(incoming, sizeof(incoming), verifiedRxWithFcs,
                        {-42, 2221}, tx, sizeof(tx),
                        action) != EngineResult::Ok ||
        action.kind != ActionKind::LinkLost ||
        engine.linkStatus().state != LinkState::ReconnectPending ||
        engine.linkStatus().reason != LinkLoss::BeaconTimeout ||
        engine.checkBeaconTimeout(2222, action) != EngineResult::NoAction)
    {
        return 73;
    }
    if (engine.acceptRx(incoming, sizeof(incoming), verifiedRxWithFcs,
                        {-42, 2222}, tx, sizeof(tx),
                        action) != EngineResult::InvalidState ||
        action.kind != ActionKind::None)
    {
        return 74;
    }
    engine.radioStopped(2300, false);
    if (engine.copyAssociatedBss(associatedBss) || associatedBss.occupied)
    {
        return kAssociatedBssSnapshotFailure;
    }
    if (engine.encodeOutgoingEthernet(ethernet, sizeof(ethernet), 13,
                                      syntheticTrust, tx, sizeof(tx),
                                      action) != EngineResult::InvalidState ||
        action.kind != ActionKind::None ||
        engine.stationState() == StationState::AssociatedOpen ||
        engine.hasNativeWifiInterface())
    {
        return 9;
    }

    // Borrowed identities from a previous link are not independent inputs to
    // started(): resetting the snapshot would otherwise erase both MACs
    // before they are copied, yet report the link Associated.
    LinkMonitor monitor;
    const Mac accessPoint {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
    if (monitor.started(station, accessPoint,
                        LinkStartConfig {
                            100,
                            1000,
                            false,
                            false,
                        }) != LinkMonitorResult::Ok ||
        monitor.observeTimeout(3000) != LinkMonitorResult::Ok ||
        monitor.status().state != LinkState::ReconnectPending)
    {
        return 10;
    }
    const LinkSnapshot beforeRestart = monitor.status();
    if (monitor.started(monitor.status().station, monitor.status().bssid,
                        LinkStartConfig {
                            100,
                            3000,
                            false,
                            false,
                        }) != LinkMonitorResult::InvalidArgument ||
        monitor.status().state != LinkState::ReconnectPending ||
        !sameMac(monitor.status().station, beforeRestart.station) ||
        !sameMac(monitor.status().bssid, beforeRestart.bssid) ||
        monitor.status().nextReconnectAtMs != beforeRestart.nextReconnectAtMs)
    {
        return 11;
    }
    if (monitor.started(station, monitor.status().bssid,
                        LinkStartConfig {
                            100,
                            3000,
                            false,
                            false,
                        }) != LinkMonitorResult::InvalidArgument ||
        monitor.started(monitor.status().station, accessPoint,
                        LinkStartConfig {
                            100,
                            3000,
                            false,
                            false,
                        }) != LinkMonitorResult::InvalidArgument ||
        monitor.status().state != LinkState::ReconnectPending)
    {
        return 12;
    }
    if (monitor.started(station, accessPoint,
                        LinkStartConfig {
                            100,
                            3000,
                            false,
                            false,
                        }) != LinkMonitorResult::Ok ||
        !sameMac(monitor.status().station, station) ||
        !sameMac(monitor.status().bssid, accessPoint))
    {
        return 13;
    }

    // A provider may write to its opaque context. It cannot be allowed to
    // modify the adapter's callbacks or the borrowed callback table itself.
    crypto::Adapter adapter;
    crypto::KeyHardware provider {
        nullptr, fakeRandom, fakePairwise, fakeGroup, fakeRemove,
    };
    provider.context = &adapter;
    if (adapter.configure(provider) || (adapter.callbacks().context != nullptr))
    {
        return 14;
    }
    provider.context = &provider;
    if (adapter.configure(provider) || (adapter.callbacks().context != nullptr))
    {
        return 15;
    }
    provider.context = reinterpret_cast<uint8_t *>(&adapter) + 1;
    if (adapter.configure(provider) || (adapter.callbacks().context != nullptr))
    {
        return 16;
    }
    uint32_t independentOwner = 1;
    provider.context = &independentOwner;
    if (!adapter.configure(provider) || adapter.callbacks().context != &adapter)
    {
        return 17;
    }
    adapter.clear();
    if (adapter.callbacks().context != nullptr)
    {
        return 18;
    }
    return 0;
}
