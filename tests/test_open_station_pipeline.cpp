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
    if (!rejectStationManagementTxAlias())
        return 19;
    if (!rejectInvalidFromDsSource())
        return 20;
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
