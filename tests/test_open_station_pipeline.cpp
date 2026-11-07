// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Alberto Villa Osorno.
// Portable synthetic open-BSS association; NO native Wi-Fi, RF, PCI or OS I/O.
#include "wifi/WifiEngine.hpp"
#include <cstring>

namespace
{
    using namespace simpleath::ieee80211;

    constexpr uint8_t kAp[6] {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    constexpr uint8_t kStation[6] {0x02, 0x66, 0x77, 0x88, 0x99, 0xaa};

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
} // namespace

int main()
{
    using namespace simpleath::ieee80211;
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
    return 0;
}
