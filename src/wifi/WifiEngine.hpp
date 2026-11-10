// Coordinates portable 802.11 scan, association, EAPOL and data parsing.
// NO native macOS Wi-Fi interface, physical PCI, RF, DMA, OS event loop,
// packet allocator or hardware TX is implemented by this engine.
#ifndef SIMPLEATH_WIFI_ENGINE_HPP
#define SIMPLEATH_WIFI_ENGINE_HPP

#include "DataPath.hpp"
#include "LinkMonitor.hpp"
#include "ScanCache.hpp"
#include "Station.hpp"
#include "Wpa2Supplicant.hpp"
#include "crypto/Wpa2CryptoAdapter.hpp"

namespace simpleath
{
    namespace ieee80211
    {

        enum class EngineResult : uint8_t
        {
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
            NoAction,
            AccessPointRejected,
        };

        enum class ActionKind : uint8_t
        {
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
            LinkLost,
        };

        // Borrowed RX payloads are valid only for the successful call.
        // Every public action-producing call clears the action at entry on
        // ordinary failures. Output and action storage must not overlap the
        // engine state, inputs, each other or trusted callback metadata;
        // malformed aliases return InvalidInput before any write or transition.
        struct EngineAction
        {
                ActionKind kind;
                size_t bytes;
                uint16_t etherType;
                const uint8_t
                    *receivedPayload; // Borrowed, only valid during callback.
                size_t receivedPayloadBytes;
                bool nativeInterfaceUsable; // Always false until actual OS
                                            // integration.
        };

        struct InputTrust
        {
                // The real PCI/EDMA owner must verify all of these BEFORE
                // calling into this layer, using its live DMA ownership, queue
                // and cryptographic state.
                bool radioReady = false;
                bool channelAuthorized = false;
                bool dmaAndFcsVerified = false;
                bool ccmpMicAndReplayVerified = false;
                // Verified RX buffer may retain its four-byte trailing FCS.
                // This describes byte layout, not FCS validation itself.
                // TX callers leave false; historical stripped RX is default.
                bool rxFrameIncludesFcs = false;
        };

        // A scheduled passive scan is a sequence of authorized RX channels.
        // The native owner must tune and verify the channel before
        // acknowledging a hop; no probe frames, RF writes or timer are issued
        // by this layer.
        struct ScanChannelDwell
        {
                uint8_t channel;
                uint16_t dwellMs;
        };

        struct ScanScheduleRequest
        {
                const ScanChannelDwell *channels;
                size_t count;
                uint64_t nowMs;
                bool radioReady;
                bool countryApproved;
        };

        struct ScanTuneConfirmation
        {
                uint64_t generation;
                uint8_t channel;
                uint64_t nowMs;
                bool hardwareConfirmed;
        };

        enum class ScanProgressKind : uint8_t
        {
            TuneRequired,
            Dwelling,
            Complete,
        };

        struct ScanProgress
        {
                ScanProgressKind kind;
                uint64_t generation;
                uint8_t channel;
                uint64_t deadlineMs;
        };

        // RX metadata arrives as one verified observation; callers cannot
        // accidentally exchange RSSI and the event timestamp.
        struct EngineRxObservation
        {
                int8_t rssiDbm;
                uint64_t nowMs;
        };

        // Caller allocates this relatively large object on a persistent
        // OS-owned heap, not the small kernel interrupt stack. All access must
        // be serialized by the future native adapter's work loop. No callbacks
        // or timers are installed here.
        class WifiEngine
        {
            public:
                WifiEngine();
                ~WifiEngine();
                WifiEngine(const WifiEngine &) = delete;
                WifiEngine &operator=(const WifiEngine &) = delete;
                WifiEngine(WifiEngine &&) = delete;
                WifiEngine &operator=(WifiEngine &&) = delete;

                void clear();
                bool configureKeys(const crypto::KeyHardware &hardware);
                EngineResult startScan(bool radioInitialized,
                                       bool countryChannelAllowed);
                // An explicit passive dwell itinerary is required for real
                // multi-channel scanning. Only channels independently approved
                // by the board, country and RF owner may appear here. The
                // generation is invalidated by restart, cancel and radio stop;
                // the native owner must ALSO validate its PCI/IRQ epoch.
                EngineResult
                beginChannelScan(const ScanScheduleRequest &request,
                                 uint64_t &generation);
                // Poll on the serialized owner work loop. TuneRequired is a
                // REQUEST, never proof that hardware has changed channels.
                EngineResult pollChannelScan(uint64_t nowMs,
                                             ScanProgress &progress);
                EngineResult acknowledgeChannelTune(
                    const ScanTuneConfirmation &confirmation);
                EngineResult cancelChannelScan(uint64_t generation);
                // requestedChannel MUST be the explicitly permitted primary
                // channel; 0 (wildcard) is refused. An explicit nonempty SSID
                // is also mandatory: no wildcard association. Country policy
                // must authorize channel and bandwidth before any TX.
                EngineResult chooseNetwork(const Mac &station,
                                           const uint8_t *ssid,
                                           size_t ssidLength,
                                           uint8_t requestedChannel,
                                           bool allowOpen, bool allowWpa2,
                                           const uint8_t pmk[kWpa2PmkBytes]);
                // The OS supplied an independently authorized 32-byte PMK
                // for one exact, RX-observed BSSID. Unlike the OS-owned key
                // path, the portable supplicant owns M1-M4, GTK and key
                // installation through a configured real native backend.
                // A successful selection never authorizes radio TX or the
                // controlled data port by itself. The PMK is copied into
                // private supplicant state, not retained by reference.
                EngineResult chooseNetworkForDriverSupplicant(
                    const Mac &station, const Mac &bssid, const uint8_t *ssid,
                    size_t ssidLength, uint8_t requestedChannel,
                    const uint8_t pmk[kWpa2PmkBytes]);
                // Driver-owned open joins must target the exact RX-observed
                // BSSID, even when a WPA2 key backend is configured for
                // another attempt. This never authorizes a usable port.
                EngineResult chooseNetworkForDriverOpen(
                    const Mac &station, const Mac &bssid, const uint8_t *ssid,
                    size_t ssidLength, uint8_t requestedChannel);
                // Native macOS owns PSK derivation/EAPOL/CCMP on this path.
                // Select only the exact observed BSSID and security type;
                // never start the portable supplicant or accept a PMK here.
                // All scan, radio and country checks still apply. This
                // selects a candidate, NOT an association or usable port.
                EngineResult chooseNetworkForOsSupplicant(
                    const Mac &station, const Mac &bssid, const uint8_t *ssid,
                    size_t ssidLength, uint8_t requestedChannel,
                    bool wpa2Personal);
                // An OS-initiated leave before an authenticated association
                // must retire its candidate without emitting a disassociation
                // frame or pretending RF stopped. The native caller must first
                // ensure any queued authentication/association TX is drained.
                // A fully associated link requires the normal leave path.
                EngineResult cancelPendingJoin();

                bool osSupplicantOwnsWpa2() const
                {
                    return osSupplicantOwned_;
                }

                // Caller submits returned frame only after full
                // RF/calibration/DMA policy.
                EngineResult requestAuthentication(uint16_t sequence,
                                                   uint8_t *out,
                                                   size_t capacity,
                                                   EngineAction &action);
                // Authentication RX that requires an association reply first
                // checks TX capacity before consuming the station transition.
                // Data payloads are rejected when LinkMonitor has moved to
                // ReconnectPending, even before native key/DMA teardown.
                EngineResult acceptRx(const uint8_t *frame, size_t length,
                                      const InputTrust &trust,
                                      const EngineRxObservation &observation,
                                      uint8_t *out, size_t capacity,
                                      EngineAction &action);

                EngineResult checkBeaconTimeout(uint64_t nowMs,
                                                EngineAction &action);
                // Caller must quiesce hardware before invalidating its key
                // backend. This resets security callbacks and channel policy;
                // a resumed radio must reconfigure its provider and rescan.
                void radioStopped(uint64_t nowMs, bool suspended);
                // Generic Ethernet-II transmission only. This never sends
                // cleartext EAPOL after WPA2 key install; the private M2/M4
                // handshake serializer is the only cleartext exception. A
                // lost link also blocks TX until native owner cleanup.
                EngineResult
                encodeOutgoingEthernet(const uint8_t *ethernet, size_t length,
                                       uint16_t sequence,
                                       const InputTrust &trust, uint8_t *out,
                                       size_t capacity, EngineAction &action);

                // Copy only the BSS of a genuinely accepted association,
                // never a provisional candidate or a mutable scan-cache
                // entry. The native owner independently validates RF/queue
                // authority before presenting the resulting OS snapshot.
                // An output overlapping this engine is refused untouched.
                bool copyAssociatedBss(Bss &out) const;

                const ScanCache &scan() const
                {
                    return cache_;
                }

                StationState stationState() const
                {
                    return station_.state();
                }

                const LinkSnapshot &linkStatus() const
                {
                    return link_.status();
                }

                static bool hasNativeWifiInterface()
                {
                    return false;
                }

            private:
                static EngineResult emitPrepared(ActionKind kind,
                                                 size_t written,
                                                 EngineAction &action);
                EngineResult handleAuthenticationResponse(const uint8_t *frame,
                                                          size_t length,
                                                          uint8_t *out,
                                                          size_t capacity,
                                                          EngineAction &action);
                EngineResult handleAssociationResponse(const uint8_t *frame,
                                                       size_t length,
                                                       EngineAction &action,
                                                       uint64_t nowMs);
                EngineResult observeScanFrame(const uint8_t *frame,
                                              size_t macBytes, int8_t rssi,
                                              uint64_t nowMs,
                                              EngineAction &action);
                EngineResult handleManagement(const uint8_t *frame,
                                              size_t length, uint64_t nowMs,
                                              uint8_t *out, size_t capacity,
                                              EngineAction &action);
                EngineResult handleData(const uint8_t *frame, size_t length,
                                        const InputTrust &trust, uint8_t *out,
                                        size_t capacity, EngineAction &action);
                EngineResult packageEapol(const uint8_t *message,
                                          size_t messageBytes, uint8_t *out,
                                          size_t capacity,
                                          EngineAction &action);
                const ScanChannelDwell &currentScanChannel() const;
                // A 64-sequence bitmap for each QoS TID (plus legacy),
                // independently for unicast and group addressed MPDUs,
                // prevents duplicate/stale data from being delivered twice.
                // It is valid only for the current association; the caller
                // must have verified DMA/FCS, addresses and CCMP replay first.
                static constexpr size_t kRxTrafficClasses = 34;

                struct RxSequenceWindow
                {
                        uint64_t seen {0};
                        uint16_t newest {0};
                        bool initialized {false};
                };

                bool acceptDataSequence(const uint8_t *frame, bool qosFrame);
                void resetDataSequences();
                RxSequenceWindow rxSequences_[kRxTrafficClasses] {};
                // Rejecting an auth/association response is recoverable only
                // after forgetting the rejected candidate and supplicant.
                void abandonCandidate();

                ScanCache cache_;
                Station station_;
                LinkMonitor link_;
                Wpa2Supplicant supplicant_;
                crypto::Adapter crypto_;
                Mac stationAddress_ {};
                uint16_t nextSequence_ {0};
                bool selected_ {false};
                bool keysConfigured_ {false};
                bool osSupplicantOwned_ {false};
                bool channelAuthorized_ {false};
                static constexpr size_t kMaximumScanChannels = 14;
                ScanChannelDwell scanChannels_[kMaximumScanChannels] {};
                size_t scanCount_ {0};
                size_t scanIndex_ {0};
                uint64_t scanGeneration_ {0};
                uint64_t scanLastClockMs_ {0};
                uint64_t scanTuneStartMs_ {0};
                uint64_t scanDeadlineMs_ {0};
                bool scanConfigured_ {false};
                bool scanOnChannel_ {false};
                bool scanComplete_ {false};
        };

    } // namespace ieee80211
} // namespace simpleath
#endif
