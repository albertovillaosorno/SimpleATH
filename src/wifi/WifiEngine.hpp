// SPDX-License-Identifier: AGPL-3.0-only
// Coordinates portable 802.11 scan, association, EAPOL and data parsing.
// NO native macOS Wi-Fi interface, physical PCI, RF, DMA, OS event loop,
// packet allocator or hardware TX is implemented by this engine.
#ifndef SIMPLEATH_WIFI_ENGINE_HPP
#define SIMPLEATH_WIFI_ENGINE_HPP

#include "ScanCache.hpp"
#include "Station.hpp"
#include "LinkMonitor.hpp"
#include "DataPath.hpp"
#include "Wpa2Supplicant.hpp"
#include "crypto/Wpa2CryptoAdapter.hpp"

namespace simpleath {
namespace ieee80211 {

enum class EngineResult : uint8_t {
    Ok,
    InvalidState,
    InvalidInput,
    RadioNotReady,
    CountryNotAuthorized,
    NoMatchingBss,
    UnsupportedSecurity,
    CryptoUnavailable,
    CryptoFailure,
    BufferTooSmall,
    InvalidReceivedFrame,
    NoAction
};

enum class ActionKind : uint8_t {
    None,
    ScanCacheUpdated,
    TransmitAuthentication,
    TransmitAssociation,
    TransmitEapol,
    TransmitData,
    AssociatedAwaitingKeys,
    HardwareKeysInstalled,
    OpenAssociationEstablished,
    ReceivedPayload,
    LinkLost
};

struct EngineAction {
    ActionKind kind;
    size_t bytes;
    uint16_t etherType;
    const uint8_t *receivedPayload; // Borrowed, only valid during callback.
    size_t receivedPayloadBytes;
    bool nativeInterfaceUsable; // Always false until actual OS integration.
};

struct InputTrust {
    // The real PCI/EDMA owner must verify all of these BEFORE calling into
    // this layer, using its live DMA ownership, queue and cryptographic state.
    bool radioReady;
    bool channelAuthorized;
    bool dmaAndFcsVerified;
    bool ccmpMicAndReplayVerified;
};

// Caller allocates this relatively large object on a persistent OS-owned heap,
// not the small kernel interrupt stack. All access must be serialized by the
// future native adapter's work loop. No callbacks or timers are installed here.
class WifiEngine {
public:
    WifiEngine();
    ~WifiEngine();
    WifiEngine(const WifiEngine &) = delete;
    WifiEngine &operator=(const WifiEngine &) = delete;

    void clear();
    bool configureKeys(const crypto::KeyHardware &hardware);
    EngineResult startScan(bool radioInitialized, bool countryChannelAllowed);
    // requestedChannel MUST be the explicitly permitted primary channel;
    // 0 (wildcard) is refused. The caller's country policy must authorize
    // the exact selected channel and bandwidth before submitting any TX.
    EngineResult chooseNetwork(const Mac &station,
                               const uint8_t *ssid, size_t ssidLength,
                               uint8_t requestedChannel,
                               bool allowOpen, bool allowWpa2,
                               const uint8_t pmk[32]);

    // Caller submits returned frame only after full RF/calibration/DMA policy.
    EngineResult requestAuthentication(uint16_t sequence, uint8_t *out,
                                       size_t capacity, EngineAction &action);
    EngineResult acceptRx(const uint8_t *frame, size_t length,
                          int8_t rssi, uint64_t nowMs,
                          const InputTrust &trust,
                          uint8_t *out, size_t capacity,
                          EngineAction &action);

    EngineResult checkBeaconTimeout(uint64_t nowMs, EngineAction &action);
    void radioStopped(uint64_t nowMs, bool suspended);
    EngineResult encodeOutgoingEthernet(const uint8_t *ethernet,
                                        size_t length, uint16_t sequence,
                                        const InputTrust &trust,
                                        uint8_t *out, size_t capacity,
                                        EngineAction &action);

    const ScanCache &scan() const { return cache_; }
    StationState stationState() const { return station_.state(); }
    const LinkSnapshot &linkStatus() const { return link_.status(); }
    bool hasNativeWifiInterface() const { return false; }

private:
    static EngineResult emitPrepared(ActionKind kind, size_t written,
                                     EngineAction &action);
    EngineResult handleManagement(const uint8_t *frame, size_t length,
                                  uint64_t nowMs, uint8_t *out,
                                  size_t capacity, EngineAction &action);
    EngineResult handleData(const uint8_t *frame, size_t length,
                            const InputTrust &trust, uint8_t *out,
                            size_t capacity, EngineAction &action);
    EngineResult packageEapol(const uint8_t *message, size_t messageBytes,
                              uint8_t *out, size_t capacity,
                              EngineAction &action);

    ScanCache cache_;
    Station station_;
    LinkMonitor link_;
    Wpa2Supplicant supplicant_;
    crypto::Adapter crypto_;
    Mac stationAddress_;
    uint16_t nextSequence_;
    bool selected_;
    bool keysConfigured_;
    bool channelAuthorized_;
};

} // namespace ieee80211
} // namespace simpleath
#endif
