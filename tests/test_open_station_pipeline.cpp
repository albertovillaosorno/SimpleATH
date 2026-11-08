// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Alberto Villa Osorno.
// Portable synthetic open-BSS association; NO native Wi-Fi, RF, PCI or OS I/O.
#include "wifi/WifiEngine.hpp"
#include "wifi/crypto/Wpa2CryptoAdapter.hpp"
#include <cstring>

namespace
{
    using namespace simpleath::ieee80211;

    constexpr uint8_t kAp[6] {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    constexpr uint8_t kStation[6] {0x02, 0x66, 0x77, 0x88, 0x99, 0xaa};

    // These deliberately nonfunctional providers are never invoked; they
    // validate only the adapter's offline callback storage contract.
    bool fakeRandom(void *, uint8_t *, size_t)
    {
        return false;
    }

    bool fakePairwise(void *, const Mac &, const uint8_t[16])
    {
        return false;
    }

    bool fakeGroup(void *, uint8_t, const uint8_t[16], const uint8_t[8])
    {
        return false;
    }

    void fakeRemove(void *)
    {
    }

    bool observingRandom(void *context, uint8_t *, size_t)
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
            return false;
        // Broadcast source (multicast bit set), zero source, and another
        // multicast source must all fail without borrowing stale RX bytes.
        frame[16] = 0xff;
        if (inspectStationRx(link, frame, sizeof(frame), false, true, false,
                             result) != DataPathResult::InvalidAddress ||
            result.payload)
            return false;
        std::memset(frame + 16, 0, 6);
        if (inspectStationRx(link, frame, sizeof(frame), false, true, false,
                             result) != DataPathResult::InvalidAddress ||
            result.payload)
            return false;
        frame[16] = 0x01;
        if (inspectStationRx(link, frame, sizeof(frame), false, true, false,
                             result) != DataPathResult::InvalidAddress ||
            result.payload)
            return false;
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
            return false;

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
            rxResult.payload || rxResult.payloadLength)
            return false;

        // Both directions still accept a genuinely distinct valid AP.
        std::memcpy(link.bssid.bytes, kAp, 6);
        std::memcpy(frame + 10, kAp, 6);
        return prepareStationTx(link, ethernet, sizeof(ethernet), 2, tx,
                                sizeof(tx), txResult) == DataPathResult::Ok &&
               inspectStationRx(link, frame, sizeof(frame), false, true, false,
                                rxResult) == DataPathResult::Ok &&
               rxResult.payload == frame + 32;
    }

    bool rejectForeignWpa2Authenticator()
    {
        // The WPA2 4-way handshake for the selected BSSID must never accept
        // an EAPOL-Key frame bridged through the AP from another transmitter.
        // Ordinary encrypted data may still originate behind the AP.
        uint8_t frame[33] {};
        frame[0] = 0x08; // FromDS data to this station.
        frame[1] = 0x02;
        addresses(frame, kStation);
        frame[24] = frame[25] = 0xaa;
        frame[26] = 3;
        frame[30] = 0x88;
        frame[31] = 0x8e;
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
            return false;
        frame[21] ^= 1u; // Different valid unicast source, same AP/BSSID.
        if (inspectStationRx(link, frame, sizeof(frame), false, true, false,
                             msdu) !=
                DataPathResult::NotFromAssociatedAccessPoint ||
            msdu.payload || msdu.payloadLength)
            return false;
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

    bool rejectUnboundWpa2Eapol()
    {
        // This limited WPA2-PSK station may send M2/M4 only to its selected
        // authenticator. A public link context cannot authorize broadcast or
        // third-party EAPOL transmissions before key installation.
        LinkContext link {};
        link.station = {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        link.bssid = {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        link.security = LinkSecurity::Wpa2Ccmp;
        link.associated = true;
        link.rfReady = true;
        link.channelPermitted = true;
        uint8_t ethernet[15] {};
        std::memcpy(ethernet, kAp, 6);
        std::memcpy(ethernet + 6, kStation, 6);
        ethernet[12] = 0x88;
        ethernet[13] = 0x8e;
        ethernet[14] = 1;
        uint8_t tx[64] {};
        std::memset(tx, 0xa5, sizeof(tx));
        SerializedData prepared {};
        prepared.frameBytes = 91;
        std::memset(ethernet, 0xff, 6);
        if (prepareStationTx(link, ethernet, sizeof(ethernet), 1, tx,
                             sizeof(tx),
                             prepared) != DataPathResult::InvalidAddress ||
            tx[0] != 0xa5 || prepared.frameBytes != 91)
            return false;
        std::memcpy(ethernet, kStation, 6);
        ethernet[5] ^= 1u; // Valid foreign unicast destination.
        if (prepareStationTx(link, ethernet, sizeof(ethernet), 1, tx,
                             sizeof(tx),
                             prepared) != DataPathResult::InvalidAddress ||
            tx[0] != 0xa5 || prepared.frameBytes != 91)
            return false;
        std::memcpy(ethernet, kAp, 6);
        if (prepareStationTx(link, ethernet, sizeof(ethernet), 1, tx,
                             sizeof(tx), prepared) != DataPathResult::Ok ||
            !prepared.isEapol || prepared.frameBytes != 33)
            return false;

        // A forged verified-decryption flag cannot make protected EAPOL
        // admissible before the selected link reports installed keys.
        uint8_t frame[33] {};
        frame[0] = 0x08;
        frame[1] = 0x42; // FromDS + protected.
        addresses(frame, kStation);
        frame[24] = frame[25] = 0xaa;
        frame[26] = 3;
        frame[30] = 0x88;
        frame[31] = 0x8e;
        frame[32] = 1;
        Msdu decoded {};
        decoded.payload = frame;
        decoded.payloadLength = 1;
        if (inspectStationRx(link, frame, sizeof(frame), false, true, true,
                             decoded) != DataPathResult::UnverifiedDecryption ||
            decoded.payload || decoded.payloadLength)
            return false;
        link.pairwiseAndGroupKeysInstalled = true;
        if (inspectStationRx(link, frame, sizeof(frame), false, true, true,
                             decoded) != DataPathResult::Ok ||
            decoded.payload != frame + 32)
            return false;
        link.pairwiseAndGroupKeysInstalled = false;
        frame[1] = 0x02; // Cleartext M1/M3 may still arrive before install.
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
                size_t calls = 0x1234u;
                uint8_t storage[128] {};
        } providerContext {};

        crypto::Adapter adapter;
        const crypto::KeyHardware hw {&providerContext.calls, observingRandom,
                                      fakePairwise, fakeGroup, fakeRemove};
        if (!adapter.configure(hw))
            return false;
        const Wpa2Crypto callbacks = adapter.callbacks();
        uint8_t kek[16] {};
        uint8_t wrapped[24] {};
        uint8_t output[32] {};
        if (callbacks.unwrapGtk(callbacks.context, kek, wrapped,
                                sizeof(wrapped), output, sizeof(output),
                                &providerContext.calls) ||
            providerContext.calls != 0x1234u)
            return false;
        if (callbacks.generateNonce(
                callbacks.context,
                reinterpret_cast<uint8_t *>(&providerContext.calls)) ||
            providerContext.calls != 0x1234u)
            return false;
        const Mac ap {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        uint8_t pmk[32] {};
        uint8_t nonce[32] {};
        if (callbacks.derivePtk(
                callbacks.context, pmk, ap, station, nonce, nonce,
                reinterpret_cast<uint8_t *>(&providerContext)) ||
            providerContext.calls != 0x1234u)
            return false;
        uint8_t eapol[99] {};
        if (callbacks.micSha1(callbacks.context, pmk, eapol, sizeof(eapol),
                              reinterpret_cast<uint8_t *>(&providerContext)) ||
            providerContext.calls != 0x1234u)
            return false;
        size_t length = 123;
        if (callbacks.unwrapGtk(callbacks.context, kek, wrapped,
                                sizeof(wrapped),
                                reinterpret_cast<uint8_t *>(&providerContext),
                                sizeof(providerContext), &length) ||
            length != 123 || providerContext.calls != 0x1234u)
            return false;
        // Disjoint outputs are still passed to a real configured provider.
        // This host callback only counts invocations, not random bytes.
        uint8_t independentNonce[32] {};
        return callbacks.generateNonce(callbacks.context, independentNonce) &&
               providerContext.calls == 0x1235u;
    }

    bool rejectForgedVisibleZeroName()
    {
        uint8_t advertisement[49] {};
        beacon(advertisement);
        Bss candidate {};
        if (parseBeacon(advertisement, sizeof(advertisement),
                        candidate.beacon) != Result::Ok)
            return false;
        candidate.occupied = true;
        std::memset(candidate.beacon.ssid, 0, sizeof(candidate.beacon.ssid));
        candidate.beacon.hiddenSsid = false;
        Station owner;
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        if (owner.enterScanning(true, true) != StationResult::Ok)
            return false;
        // A forged scan snapshot must not reach authentication if its SSID
        // has no actual visible octet, regardless of its hidden flag.
        if (owner.select(station, candidate) !=
                StationResult::UnsupportedNetwork ||
            owner.state() != StationState::Scanning ||
            owner.candidate().occupied)
            return false;
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
            return false;
        candidate.occupied = true;
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        Station owner;
        if (owner.enterScanning(true, true) != StationResult::Ok)
            return false;

        // The public selection API must not trust a caller-forged
        // infrastructure flag when the 802.11 capabilities say otherwise.
        // Neither ESS nor IBSS, IBSS only, and both bits are all invalid.
        const uint16_t invalidModes[] {0u, 2u, 3u};
        for (const uint16_t mode : invalidModes)
        {
            candidate.beacon.capabilities = mode;
            if (owner.select(station, candidate) !=
                    StationResult::UnsupportedNetwork ||
                owner.state() != StationState::Scanning ||
                owner.candidate().occupied)
                return false;
        }
        // A genuine infrastructure advertisement is still selectable.
        candidate.beacon.capabilities = 1u;
        return owner.select(station, candidate) == StationResult::Ok &&
               owner.state() == StationState::CandidateSelected;
    }

    bool rejectEngineSelfBssidBeforeCrypto()
    {
        // A forged local station address equal to the selected WPA2 AP must
        // be rejected before handing identity and credentials to WPA2.
        constexpr uint8_t rsnIe[22] {48, 20,   1,    0,    0,    0x0f, 0xac, 4,
                                     1,  0,    0,    0x0f, 0xac, 4,    1,    0,
                                     0,  0x0f, 0xac, 2,    0,    0};
        uint8_t advertisement[49 + sizeof(rsnIe)] {};
        beacon(advertisement);
        advertisement[34] |= 0x10; // WPA2 privacy capability.
        std::memcpy(advertisement + 49, rsnIe, sizeof(rsnIe));

        WifiEngine engine;
        uint32_t providerContext = 1;
        const crypto::KeyHardware hardware {
            &providerContext, fakeRandom, fakePairwise, fakeGroup, fakeRemove};
        if (!engine.configureKeys(hardware) ||
            engine.startScan(true, true) != EngineResult::Ok)
            return false;
        uint8_t output[256] {};
        EngineAction action {};
        const InputTrust verifiedRx {true, true, true, false};
        if (engine.acceptRx(advertisement, sizeof(advertisement), -40, 1000,
                            verifiedRx, output, sizeof(output),
                            action) != EngineResult::Ok ||
            engine.scan().size() != 1)
            return false;
        const Mac ap {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        const uint8_t ssid[] {'T', 'e', 's', 't'};
        uint8_t pmk[32] {1};
        if (engine.chooseNetwork(ap, ssid, sizeof(ssid), 6, false, true, pmk) !=
                EngineResult::InvalidInput ||
            engine.stationState() != StationState::Scanning)
            return false;
        // Rejecting the identity cannot consume a valid candidate or make a
        // subsequent independently addressed WPA2 selection impossible.
        return engine.chooseNetwork(station, ssid, sizeof(ssid), 6, false, true,
                                    pmk) == EngineResult::Ok &&
               engine.stationState() == StationState::CandidateSelected;
    }

    bool rejectStationManagementTxAlias()
    {
        uint8_t advertisement[49] {};
        beacon(advertisement);
        Bss candidate {};
        if (parseBeacon(advertisement, sizeof(advertisement),
                        candidate.beacon) != Result::Ok)
            return false;
        candidate.occupied = true;
        const Mac ownMac {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        Station owner;
        if (owner.enterScanning(true, true) != StationResult::Ok ||
            owner.select(ownMac, candidate) != StationResult::Ok)
            return false;

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
            return false;

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
            return false;
        uint8_t frame[128] {};
        if (owner.authenticationRequest(1, frame, sizeof(frame), written) !=
                Result::Ok ||
            written != 30)
            return false;
        uint8_t response[30] {};
        authenticationResponse(response);
        if (owner.onAuthenticationResponse(response, sizeof(response)) !=
            StationResult::Ok)
            return false;
        tx.written = 234;
        std::memcpy(previousTx, &tx, sizeof(tx));
        if (owner.associationRequest(2, reinterpret_cast<uint8_t *>(&tx),
                                     sizeof(tx), tx.written) !=
                Result::OverlappingBuffers ||
            std::memcmp(&tx, previousTx, sizeof(tx)) != 0 ||
            owner.state() != StationState::Authenticated)
            return false;
        std::memcpy(previousOwner, &owner, sizeof(owner));
        written = 888;
        if (owner.associationRequest(2, reinterpret_cast<uint8_t *>(&owner),
                                     sizeof(owner),
                                     written) != Result::OverlappingBuffers ||
            written != 888 ||
            std::memcmp(&owner, previousOwner, sizeof(owner)) != 0)
            return false;
        return owner.associationRequest(2, frame, sizeof(frame), written) ==
                   Result::Ok &&
               written > 30 &&
               owner.state() == StationState::AssociationFramePrepared;
    }
} // namespace

int main()
{
    using namespace simpleath::ieee80211;
    if (!rejectEngineSelfBssidBeforeCrypto())
        return 25;
    if (!rejectStationManagementTxAlias())
        return 19;
    if (!rejectForgedVisibleZeroName())
        return 23;
    if (!rejectForgedInfrastructureCapability())
        return 26;
    if (!rejectInvalidFromDsSource())
        return 20;
    if (!rejectIdenticalLinkIdentities())
        return 24;
    if (!rejectForeignWpa2Authenticator())
        return 21;
    if (!rejectUnboundWpa2Eapol())
        return 31;
    if (!rejectCryptoProviderContextAliases())
        return 22;
    // Native lifecycle must allocate/serialize persistent owner storage.
    // This static host fixture has no controlling radio or OS interface.
    static WifiEngine engine;
    const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
    const InputTrust syntheticTrust {true, true, true, false};
    const InputTrust unverifiedFrame {true, true, false, false};
    uint8_t tx[512] {};
    uint8_t probe[49] {};
    beacon(probe);
    EngineAction action {};
    if (engine.startScan(true, true) != EngineResult::Ok ||
        engine.hasNativeWifiInterface())
        return 1;
    if (engine.acceptRx(probe, sizeof(probe), -42, 1000, unverifiedFrame, tx,
                        sizeof(tx), action) != EngineResult::InvalidInput ||
        action.kind != ActionKind::None)
        return 2;
    if (engine.acceptRx(probe, sizeof(probe), -42, 1000, syntheticTrust, tx,
                        sizeof(tx), action) != EngineResult::Ok ||
        action.kind != ActionKind::ScanCacheUpdated ||
        action.nativeInterfaceUsable || engine.scan().size() != 1)
        return 3;
    if (engine.chooseNetwork(station, reinterpret_cast<const uint8_t *>("Test"),
                             4, 6, true, false, nullptr) != EngineResult::Ok ||
        engine.startScan(true, true) != EngineResult::InvalidState)
        return 4;
    if (engine.requestAuthentication(10, tx, sizeof(tx), action) !=
            EngineResult::Ok ||
        action.kind != ActionKind::TransmitAuthentication ||
        action.bytes != 30 || action.nativeInterfaceUsable)
        return 5;
    uint8_t auth[30] {};
    authenticationResponse(auth);
    if (engine.acceptRx(auth, sizeof(auth), 0, 1010, syntheticTrust, tx,
                        sizeof(tx), action) != EngineResult::Ok ||
        action.kind != ActionKind::TransmitAssociation || action.bytes == 0 ||
        action.nativeInterfaceUsable)
        return 6;
    uint8_t assoc[34] {};
    associationResponse(assoc);
    // A changed AP privacy capability cannot silently turn our selected
    // Open BSS into a protected association; retain retryable TX state.
    assoc[24] |= 0x10u;
    if (engine.acceptRx(assoc, sizeof(assoc), 0, 1020, syntheticTrust, tx,
                        sizeof(tx),
                        action) != EngineResult::InvalidReceivedFrame ||
        engine.stationState() != StationState::AssociationFramePrepared ||
        action.kind != ActionKind::None)
        return 27;
    assoc[24] &= static_cast<uint8_t>(~0x10u);
    if (engine.acceptRx(assoc, sizeof(assoc), 0, 1020, syntheticTrust, tx,
                        sizeof(tx), action) != EngineResult::Ok ||
        action.kind != ActionKind::OpenAssociationEstablished ||
        engine.stationState() != StationState::AssociatedOpen ||
        action.nativeInterfaceUsable || engine.hasNativeWifiInterface())
        return 7;

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
        return 8;
    engine.radioStopped(2000, false);
    if (engine.encodeOutgoingEthernet(ethernet, sizeof(ethernet), 13,
                                      syntheticTrust, tx, sizeof(tx),
                                      action) != EngineResult::InvalidState ||
        action.kind != ActionKind::None ||
        engine.stationState() == StationState::AssociatedOpen ||
        engine.hasNativeWifiInterface())
        return 9;

    // Borrowed identities from a previous link are not independent inputs to
    // started(): resetting the snapshot would otherwise erase both MACs
    // before they are copied, yet report the link Associated.
    LinkMonitor monitor;
    const Mac accessPoint {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
    if (monitor.started(station, accessPoint, 100, 1000, false, false) !=
            LinkMonitorResult::Ok ||
        monitor.observeTimeout(3000) != LinkMonitorResult::Ok ||
        monitor.status().state != LinkState::ReconnectPending)
        return 10;
    const LinkSnapshot beforeRestart = monitor.status();
    if (monitor.started(monitor.status().station, monitor.status().bssid, 100,
                        3000, false,
                        false) != LinkMonitorResult::InvalidArgument ||
        monitor.status().state != LinkState::ReconnectPending ||
        !sameMac(monitor.status().station, beforeRestart.station) ||
        !sameMac(monitor.status().bssid, beforeRestart.bssid) ||
        monitor.status().nextReconnectAtMs != beforeRestart.nextReconnectAtMs)
        return 11;
    if (monitor.started(station, monitor.status().bssid, 100, 3000, false,
                        false) != LinkMonitorResult::InvalidArgument ||
        monitor.started(monitor.status().station, accessPoint, 100, 3000, false,
                        false) != LinkMonitorResult::InvalidArgument ||
        monitor.status().state != LinkState::ReconnectPending)
        return 12;
    if (monitor.started(station, accessPoint, 100, 3000, false, false) !=
            LinkMonitorResult::Ok ||
        !sameMac(monitor.status().station, station) ||
        !sameMac(monitor.status().bssid, accessPoint))
        return 13;

    // A provider may write to its opaque context. It cannot be allowed to
    // modify the adapter's callbacks or the borrowed callback table itself.
    crypto::Adapter adapter;
    crypto::KeyHardware provider {nullptr, fakeRandom, fakePairwise, fakeGroup,
                                  fakeRemove};
    provider.context = &adapter;
    if (adapter.configure(provider) || adapter.callbacks().context)
        return 14;
    provider.context = &provider;
    if (adapter.configure(provider) || adapter.callbacks().context)
        return 15;
    provider.context = reinterpret_cast<uint8_t *>(&adapter) + 1;
    if (adapter.configure(provider) || adapter.callbacks().context)
        return 16;
    uint32_t independentOwner = 1;
    provider.context = &independentOwner;
    if (!adapter.configure(provider) || adapter.callbacks().context != &adapter)
        return 17;
    adapter.clear();
    if (adapter.callbacks().context)
        return 18;
    return 0;
}
