// SPDX-License-Identifier: AGPL-3.0-only
#include "WifiEngine.hpp"

namespace simpleath
{
    namespace ieee80211
    {
        namespace
        {

            constexpr uint16_t kEtherTypeEapol = 0x888eu;
            constexpr size_t kEthernetHeader = 14u;
            constexpr size_t kMaximumEapolReply = 256u;
            // WPA2 M2 is 121 bytes EAPOL plus 802.11 header and 8-byte
            // LLC/SNAP.
            constexpr size_t kMinimumEapolTxFrameCapacity = 24u + 8u + 121u;

            bool overlaps(const void *a, size_t aBytes, const void *b,
                          size_t bBytes)
            {
                if (!a || !b || !aBytes || !bBytes)
                    return false;
                const auto first = reinterpret_cast<uintptr_t>(a);
                const auto second = reinterpret_cast<uintptr_t>(b);
                return first <= second ? second - first < aBytes
                                       : first - second < bBytes;
            }

            // EngineAction is a caller-owned output, but the RX frame can be
            // borrowed from DMA and the engine stores keys and station state.
            // An overlap must be refused BEFORE action={} or a TX response.
            bool aliasesEngineIo(const WifiEngine *engine,
                                 const EngineAction &action, const void *input,
                                 size_t inputBytes, const void *trust,
                                 size_t trustBytes, const uint8_t *out,
                                 size_t capacity)
            {
                return overlaps(&action, sizeof(action), engine,
                                sizeof(*engine)) ||
                       overlaps(&action, sizeof(action), input, inputBytes) ||
                       overlaps(&action, sizeof(action), trust, trustBytes) ||
                       overlaps(&action, sizeof(action), out, capacity) ||
                       overlaps(out, capacity, engine, sizeof(*engine)) ||
                       overlaps(out, capacity, input, inputBytes) ||
                       overlaps(out, capacity, trust, trustBytes);
            }

            void copyBytes(uint8_t *dest, const uint8_t *src, size_t count)
            {
                for (size_t i = 0; i < count; ++i)
                    dest[i] = src[i];
            }

            EngineResult mapPrepared(Result value)
            {
                if (value == Result::BufferTooSmall)
                    return EngineResult::BufferTooSmall;
                return value == Result::Ok ? EngineResult::Ok
                                           : EngineResult::InvalidInput;
            }

        } // namespace

        WifiEngine::WifiEngine()
            : cache_ {}, station_ {}, link_ {}, supplicant_ {}, crypto_ {},
              stationAddress_ {}, nextSequence_(0), selected_(false),
              keysConfigured_(false), channelAuthorized_(false)
        {
        }

        WifiEngine::~WifiEngine()
        {
            // Owner MUST stop hardware and call clear() before destroying
            // crypto backend context. This destructor only wipes local
            // supplicant secrets.
        }

        void WifiEngine::clear()
        {
            // The supplicant must remove installed keys while the PCI backend
            // is still alive. Revoke adapter callbacks only AFTER that removal.
            supplicant_.reset();
            crypto_.clear();
            station_.reset();
            link_.clear();
            cache_.clear();
            stationAddress_ = {};
            selected_ = false;
            keysConfigured_ = false;
            channelAuthorized_ = false;
            nextSequence_ = 0;
        }

        bool WifiEngine::configureKeys(const crypto::KeyHardware &hardware)
        {
            if (keysConfigured_ || selected_)
                return false;
            keysConfigured_ = crypto_.configure(hardware);
            return keysConfigured_;
        }

        EngineResult WifiEngine::startScan(bool radioInitialized,
                                           bool countryChannelAllowed)
        {
            if (selected_)
                return EngineResult::InvalidState;
            if (!radioInitialized)
                return EngineResult::RadioNotReady;
            if (!countryChannelAllowed)
                return EngineResult::CountryNotAuthorized;
            if (station_.enterScanning(radioInitialized,
                                       countryChannelAllowed) !=
                StationResult::Ok)
                return EngineResult::InvalidState;
            cache_.clear();
            channelAuthorized_ = countryChannelAllowed;
            return EngineResult::Ok;
        }

        EngineResult WifiEngine::chooseNetwork(const Mac &station,
                                               const uint8_t *ssid,
                                               size_t ssidLength,
                                               uint8_t requestedChannel,
                                               bool allowOpen, bool allowWpa2,
                                               const uint8_t pmk[32])
        {
            if (selected_ || station_.state() != StationState::Scanning)
                return EngineResult::InvalidState;
            if (!channelAuthorized_ || requestedChannel < 1u ||
                requestedChannel > 14u)
                return EngineResult::CountryNotAuthorized;
            if (!validStationMac(station) || !ssid || ssidLength == 0 ||
                ssidLength > 32)
                return EngineResult::InvalidInput;
            // An explicit SSID is mandatory for association. A wildcard
            // scan result is never authorization to join an arbitrary BSS.
            Bss candidate {};
            if (!cache_.strongest(ssid, ssidLength, requestedChannel, allowOpen,
                                  allowWpa2, candidate))
                return EngineResult::NoMatchingBss;
            if (candidate.beacon.channel != requestedChannel)
                return EngineResult::CountryNotAuthorized;
            const Security security = candidate.beacon.rsn.security;
            if (security == Security::Wpa2Personal)
            {
                if (!keysConfigured_ || !pmk)
                    return EngineResult::CryptoUnavailable;
                const Wpa2Crypto callbacks = crypto_.callbacks();
                if (!callbacks.context ||
                    supplicant_.begin(
                        callbacks, station, candidate.beacon.bssid, pmk,
                        candidate.beacon.rsnIe,
                        candidate.beacon.rsnIeLength) != Wpa2Result::Ok)
                    return EngineResult::CryptoFailure;
            }
            else if (security != Security::Open)
            {
                return EngineResult::UnsupportedSecurity;
            }
            if (station_.select(station, candidate) != StationResult::Ok)
            {
                supplicant_.reset();
                return EngineResult::InvalidInput;
            }
            selected_ = true;
            stationAddress_ = station;
            return EngineResult::Ok;
        }

        void WifiEngine::abandonCandidate()
        {
            // AP rejection can occur on a still-running radio. Forget only
            // the association attempt; keep the verified crypto provider
            // configured so a subsequent explicit scan can select a new BSS.
            supplicant_.reset();
            station_.reset();
            link_.clear();
            stationAddress_ = {};
            selected_ = false;
        }

        EngineResult WifiEngine::emitPrepared(ActionKind kind, size_t written,
                                              EngineAction &action)
        {
            EngineAction result {};
            result.kind = kind;
            result.bytes = written;
            result.nativeInterfaceUsable = false;
            action = result;
            return EngineResult::Ok;
        }

        EngineResult WifiEngine::requestAuthentication(uint16_t sequence,
                                                       uint8_t *out,
                                                       size_t capacity,
                                                       EngineAction &action)
        {
            if (aliasesEngineIo(this, action, nullptr, 0, nullptr, 0, out,
                                capacity))
                return EngineResult::InvalidInput;
            action = {};
            if (!selected_)
                return EngineResult::InvalidState;
            size_t written = 0;
            Result result = station_.authenticationRequest(sequence, out,
                                                           capacity, written);
            if (result != Result::Ok)
                return mapPrepared(result);
            nextSequence_ = static_cast<uint16_t>((sequence + 1u) & 0xfffu);
            return emitPrepared(ActionKind::TransmitAuthentication, written,
                                action);
        }

        EngineResult WifiEngine::handleManagement(const uint8_t *frame,
                                                  size_t length, uint64_t nowMs,
                                                  uint8_t *out, size_t capacity,
                                                  EngineAction &action)
        {
            Frame header {};
            if (parseFrame(frame, length, header) != Result::Ok)
                return EngineResult::InvalidReceivedFrame;
            const StationState state = station_.state();
            if (state == StationState::AuthenticationFramePrepared &&
                header.subtype == 11)
            {
                // Station::onAuthenticationResponse consumes the pending
                // authentication state. Provision the exact association TX
                // body first so a small or absent buffer cannot strand the
                // station in Authenticated with no retryable response path.
                const Beacon &network = station_.candidate().beacon;
                const size_t associationBytes =
                    28u + 2u + network.ssidLength + 10u + 6u +
                    (network.rsn.security == Security::Wpa2Personal ? 22u : 0u);
                if (!out || capacity < associationBytes)
                    return EngineResult::BufferTooSmall;
                const StationResult authenticated =
                    station_.onAuthenticationResponse(frame, length);
                if (authenticated == StationResult::AssociationRejected)
                {
                    abandonCandidate();
                    return EngineResult::AccessPointRejected;
                }
                if (authenticated != StationResult::Ok)
                    return EngineResult::InvalidReceivedFrame;
                size_t written = 0;
                const Result prepared = station_.associationRequest(
                    nextSequence_, out, capacity, written);
                if (prepared != Result::Ok)
                    return mapPrepared(prepared);
                nextSequence_ =
                    static_cast<uint16_t>((nextSequence_ + 1u) & 0xfffu);
                return emitPrepared(ActionKind::TransmitAssociation, written,
                                    action);
            }
            if (state == StationState::AssociationFramePrepared &&
                header.subtype == 1)
            {
                const StationResult response =
                    station_.onAssociationResponse(frame, length);
                if (response == StationResult::AssociationRejected)
                {
                    abandonCandidate();
                    return EngineResult::AccessPointRejected;
                }
                if (response != StationResult::Wpa2CryptoNotImplemented &&
                    response != StationResult::NetworkInterfaceNotImplemented)
                    return EngineResult::InvalidReceivedFrame;
                const Bss &candidate = station_.candidate();
                if (link_.started(stationAddress_, candidate.beacon.bssid,
                                  candidate.beacon.intervalTu, nowMs, false,
                                  false) != LinkMonitorResult::Ok)
                    return EngineResult::InvalidState;
                if (response == StationResult::Wpa2CryptoNotImplemented)
                    return emitPrepared(ActionKind::AssociatedAwaitingKeys, 0,
                                        action);
                return emitPrepared(ActionKind::OpenAssociationEstablished, 0,
                                    action);
            }
            if (link_.status().state == LinkState::Associated)
            {
                const LinkMonitorResult updated =
                    link_.observeManagement(frame, length, nowMs, true, false);
                if (updated == LinkMonitorResult::Ok &&
                    link_.status().state == LinkState::ReconnectPending)
                {
                    // Caller must stop traffic and actually begin a new scan.
                    return emitPrepared(ActionKind::LinkLost, 0, action);
                }
            }
            return EngineResult::NoAction;
        }

        EngineResult WifiEngine::packageEapol(const uint8_t *message,
                                              size_t messageBytes, uint8_t *out,
                                              size_t capacity,
                                              EngineAction &action)
        {
            if (!message || messageBytes > kMaximumEapolReply)
                return EngineResult::InvalidInput;
            // WPA2 EAPOL is cleartext at the 802.11 data layer until PTK
            // install. Keep source and destination distinct when encoding
            // LLC/SNAP.
            uint8_t ethernet[kEthernetHeader + kMaximumEapolReply] {};
            const Mac &ap = station_.candidate().beacon.bssid;
            copyBytes(ethernet, ap.bytes, 6);
            copyBytes(ethernet + 6, stationAddress_.bytes, 6);
            ethernet[12] = static_cast<uint8_t>(kEtherTypeEapol >> 8u);
            ethernet[13] = static_cast<uint8_t>(kEtherTypeEapol);
            copyBytes(ethernet + kEthernetHeader, message, messageBytes);
            LinkContext link {};
            link.station = stationAddress_;
            link.bssid = ap;
            link.security = LinkSecurity::Wpa2Ccmp;
            link.associated = true;
            link.rfReady =
                true; // Still gated by caller's trusted RX/PHY state.
            link.channelPermitted = channelAuthorized_;
            link.pairwiseAndGroupKeysInstalled = supplicant_.keysInstalled();
            SerializedData packet {};
            const DataPathResult encoded =
                prepareStationTx(link, ethernet, kEthernetHeader + messageBytes,
                                 nextSequence_, out, capacity, packet);
            if (encoded != DataPathResult::Ok)
                return encoded == DataPathResult::BufferTooSmall
                           ? EngineResult::BufferTooSmall
                           : EngineResult::InvalidState;
            nextSequence_ =
                static_cast<uint16_t>((nextSequence_ + 1u) & 0xfffu);
            return emitPrepared(ActionKind::TransmitEapol, packet.frameBytes,
                                action);
        }

        EngineResult WifiEngine::handleData(const uint8_t *frame, size_t length,
                                            const InputTrust &trust,
                                            uint8_t *out, size_t capacity,
                                            EngineAction &action)
        {
            const StationState state = station_.state();
            const bool associated =
                state == StationState::AssociatedOpen ||
                state == StationState::WaitingForWpa2Keys ||
                state == StationState::HardwareKeysInstalled;
            // A lost link remains in the Station state until the native owner
            // has quiesced DMA and removed keys. No payload may pass through
            // that gap, even if the station still remembers the association.
            if (!associated || link_.status().state != LinkState::Associated)
                return EngineResult::InvalidState;
            const Bss &candidate = station_.candidate();
            LinkContext link {};
            link.station = stationAddress_;
            link.bssid = candidate.beacon.bssid;
            link.security =
                candidate.beacon.rsn.security == Security::Wpa2Personal
                    ? LinkSecurity::Wpa2Ccmp
                    : LinkSecurity::Open;
            link.associated = associated;
            link.rfReady = trust.radioReady;
            link.channelPermitted = trust.channelAuthorized;
            link.pairwiseAndGroupKeysInstalled = supplicant_.keysInstalled();
            Msdu msdu {};
            if (inspectStationRx(
                    link, frame, length, false, trust.dmaAndFcsVerified,
                    trust.ccmpMicAndReplayVerified, msdu) != DataPathResult::Ok)
                return EngineResult::InvalidReceivedFrame;
            if (msdu.etherType != kEtherTypeEapol)
            {
                if (link.security == LinkSecurity::Wpa2Ccmp &&
                    !supplicant_.keysInstalled())
                    return EngineResult::CryptoUnavailable;
                EngineAction result {};
                result.kind = ActionKind::ReceivedPayload;
                result.etherType = msdu.etherType;
                result.receivedPayload = msdu.payload;
                result.receivedPayloadBytes = msdu.payloadLength;
                result.nativeInterfaceUsable = false;
                action = result;
                return EngineResult::Ok;
            }
            if (link.security != LinkSecurity::Wpa2Ccmp ||
                state != StationState::WaitingForWpa2Keys)
                return EngineResult::NoAction;
            KeyFrame key {};
            if (parseEapolKey(msdu.payload, msdu.payloadLength, key) !=
                EapolResult::Ok)
                return EngineResult::InvalidReceivedFrame;
            // Refuse too-small output BEFORE changing supplicant
            // replay/nonce/key state; the caller can provision enough room and
            // retry the same input.
            if (!out || capacity < kMinimumEapolTxFrameCapacity)
                return EngineResult::BufferTooSmall;
            uint8_t reply[kMaximumEapolReply] {};
            size_t written = 0;
            Wpa2Result security = Wpa2Result::InvalidState;
            if (key.message == KeyMessage::Pairwise1)
                security =
                    supplicant_.onMessage1(msdu.payload, msdu.payloadLength,
                                           reply, sizeof(reply), written);
            else if (key.message == KeyMessage::Pairwise3)
                security =
                    supplicant_.onMessage3(msdu.payload, msdu.payloadLength,
                                           reply, sizeof(reply), written);
            else
                return EngineResult::NoAction;
            if (security != Wpa2Result::Ok)
                return EngineResult::CryptoFailure;
            if (key.message == KeyMessage::Pairwise3 &&
                station_.recordInstalledWpa2Keys(supplicant_) !=
                    StationResult::NetworkInterfaceNotImplemented)
                return EngineResult::CryptoFailure;
            return packageEapol(reply, written, out, capacity, action);
        }

        EngineResult WifiEngine::acceptRx(const uint8_t *frame, size_t length,
                                          int8_t rssi, uint64_t nowMs,
                                          const InputTrust &trust, uint8_t *out,
                                          size_t capacity, EngineAction &action)
        {
            if (aliasesEngineIo(this, action, frame, length, &trust,
                                sizeof(trust), out, capacity))
                return EngineResult::InvalidInput;
            action = {};
            if (!frame || !trust.radioReady || !trust.channelAuthorized ||
                !trust.dmaAndFcsVerified)
                return EngineResult::InvalidInput;
            Frame header {};
            if (parseFrame(frame, length, header) != Result::Ok)
                return EngineResult::InvalidReceivedFrame;

            if (header.type == FrameType::Management)
            {
                if (header.subtype == 8 || header.subtype == 5)
                {
                    if (station_.state() == StationState::Scanning)
                    {
                        if (cache_.observe(frame, length, rssi, nowMs) ==
                            Result::Ok)
                            return emitPrepared(ActionKind::ScanCacheUpdated, 0,
                                                action);
                    }
                }
                return handleManagement(frame, length, nowMs, out, capacity,
                                        action);
            }
            if (header.type == FrameType::Data)
                return handleData(frame, length, trust, out, capacity, action);
            return EngineResult::NoAction;
        }

        EngineResult WifiEngine::checkBeaconTimeout(uint64_t nowMs,
                                                    EngineAction &action)
        {
            if (aliasesEngineIo(this, action, nullptr, 0, nullptr, 0, nullptr,
                                0))
                return EngineResult::InvalidInput;
            action = {};
            if (link_.observeTimeout(nowMs) != LinkMonitorResult::Ok)
                return EngineResult::NoAction;
            // OS / radio owner must quiesce DMA, clear keycache and reconnect.
            return emitPrepared(ActionKind::LinkLost, 0, action);
        }

        void WifiEngine::radioStopped(uint64_t nowMs, bool suspended)
        {
            link_.radioUnavailable(nowMs, suspended);
            // Fail closed: wipe cryptographic state. The owner must quiesce
            // hardware and remain able to remove keys before it releases the
            // backend.
            supplicant_.reset();
            // Callback context may be freed after the owner has quiesced the
            // device and removeInstalledKeys has returned. Do not retain a
            // borrowed native provider across suspend or surprise removal.
            crypto_.clear();
            station_.reset();
            cache_.clear();
            stationAddress_ = {};
            nextSequence_ = 0;
            selected_ = false;
            keysConfigured_ = false;
            channelAuthorized_ = false;
        }

        EngineResult WifiEngine::encodeOutgoingEthernet(
            const uint8_t *ethernet, size_t length, uint16_t sequence,
            const InputTrust &trust, uint8_t *out, size_t capacity,
            EngineAction &action)
        {
            if (aliasesEngineIo(this, action, ethernet, length, &trust,
                                sizeof(trust), out, capacity))
                return EngineResult::InvalidInput;
            action = {};
            const StationState state = station_.state();
            if ((state != StationState::AssociatedOpen &&
                 state != StationState::HardwareKeysInstalled) ||
                link_.status().state != LinkState::Associated)
                return EngineResult::InvalidState;
            const Bss &bss = station_.candidate();
            LinkContext context {};
            context.station = stationAddress_;
            context.bssid = bss.beacon.bssid;
            context.security = bss.beacon.rsn.security == Security::Wpa2Personal
                                   ? LinkSecurity::Wpa2Ccmp
                                   : LinkSecurity::Open;
            context.associated = true;
            context.rfReady = trust.radioReady;
            context.channelPermitted = trust.channelAuthorized;
            context.pairwiseAndGroupKeysInstalled = supplicant_.keysInstalled();
            // Only packageEapol() may emit cleartext M2/M4 during the 4-way
            // handshake. Generic outbound EAPOL after key installation needs
            // a separately reviewed, policy-checked rekey transport, not the
            // unprotected Ethernet-II serializer.
            if (context.security == LinkSecurity::Wpa2Ccmp && ethernet &&
                length >= kEthernetHeader && ethernet[12] == 0x88u &&
                ethernet[13] == 0x8eu)
                return EngineResult::CryptoUnavailable;
            SerializedData serialized {};
            const DataPathResult result = prepareStationTx(
                context, ethernet, length, sequence, out, capacity, serialized);
            if (result == DataPathResult::NeedsCcmpEncryption)
                return EngineResult::CryptoUnavailable;
            if (result != DataPathResult::Ok)
                return result == DataPathResult::BufferTooSmall
                           ? EngineResult::BufferTooSmall
                           : EngineResult::InvalidInput;
            // No transport here: output contains only bytes for the future PCI
            // and native wireless backend; never report IP connectivity.
            return emitPrepared(serialized.isEapol ? ActionKind::TransmitEapol
                                                   : ActionKind::TransmitData,
                                serialized.frameBytes, action);
        }

    } // namespace ieee80211
} // namespace simpleath
