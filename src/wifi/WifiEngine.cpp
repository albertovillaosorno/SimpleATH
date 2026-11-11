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
//   - Native driver contracts and implementation for wifi engine.
// - Must-Not:
//   - Invent hardware readiness, weaken buffer bounds, or assume ABI
//     compatibility.
// - Allows:
//   - Inputs: validated register, protocol, platform, or device state from
//     callers.
//   - Outputs: bounded native transitions, messages, or explicit errors.
//   - Side effects: only the device and kernel operations owned by this module.
// - Split-When:
//   - A separate protocol stage needs independent validation and ownership.
// - Merge-When:
//   - The caller directly owns this narrow contract without reuse.
// - Summary:
//   - Native driver contracts and implementation for wifi engine.
// - Description:
//   - Implements or verifies the WifiEngine source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for wifi engine.

#include "WifiEngine.hpp"
#include "wifi/DataFrames.hpp"
#include "wifi/DataPath.hpp"
#include "wifi/DataReassembly.hpp"
#include "wifi/Eapol.hpp"
#include "wifi/Frames.hpp"
#include "wifi/LinkMonitor.hpp"
#include "wifi/ManagementReassembly.hpp"
#include "wifi/ScanCache.hpp"
#include "wifi/Station.hpp"
#include "wifi/Wpa2Supplicant.hpp"
#include "wifi/crypto/Ccmp.hpp"
#include "wifi/crypto/Wpa2CryptoAdapter.hpp"
#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    namespace ieee80211
    {
        namespace
        {

            constexpr uint16_t kEtherTypeEapol = 0x888eU;
            constexpr uint8_t kMaximum2GhzChannel = 14;
            constexpr uint8_t kAuthResponseSubtype = 11;
            constexpr uint8_t kAssociationResponseSubtype = 1;
            constexpr uint8_t kBeaconSubtype = 8;
            constexpr uint8_t kProbeResponseSubtype = 5;
            constexpr size_t kEtherTypeHighOffset = 12;
            constexpr size_t kEtherTypeLowOffset = 13;
            constexpr uint8_t kEtherTypeHighEapol = 0x88U;
            constexpr uint8_t kEtherTypeLowEapol = 0x8eU;
            constexpr uint8_t kEtherTypeShift = 8U;
            constexpr uint16_t kSequenceMask = 0xfffU;
            constexpr uint16_t kSequenceModulus = 4096U;
            constexpr uint16_t kSequenceHalfRange = kSequenceModulus / 2U;
            constexpr uint16_t kRxSequenceHistory = 64U;
            constexpr size_t kRxLegacyTid = 16U;
            constexpr size_t kRxPerDestinationClasses = 17U;
            constexpr size_t kRxCopiedHeaderBytes = 26U;
            constexpr size_t kRxQosControlOffset = 24U;
            constexpr uint8_t kRxTidMask = 0x0fU;
            constexpr uint8_t kManagementVersionTypeMask = 0x0fU;
            constexpr uint8_t kDataVersionType = 0x08U;
            constexpr uint8_t kFragmentedMoreBit = 0x04U;
            constexpr uint8_t kFragmentSequenceMask = 0x0fU;
            constexpr size_t kDataFragmentHeaderBytes = 24U;
            constexpr uint16_t kMinimumPassiveDwellMs = 10;
            constexpr uint16_t kMaximumPassiveDwellMs = 1000;
            constexpr size_t kEthernetHeader = 14U;
            constexpr size_t kMaximumEapolReply = 256U;
            // WPA2 M2 is 121 bytes EAPOL plus 802.11 header and 8-byte
            // LLC/SNAP.
            constexpr size_t kMinimumEapolTxFrameCapacity = 24U + 8U + 121U;
            constexpr size_t kDataHeaderBytes = 24U;
            constexpr size_t kSnapHeaderBytes = 8U;
            constexpr size_t kGroup2ReplyBytes = 99U;
            constexpr size_t kCcmpOverheadBytes = 16U;

            bool overlaps(const void *a, size_t aBytes, const void *b,
                          size_t bBytes)
            {
                if ((a == nullptr) || (b == nullptr) || (aBytes == 0U) ||
                    (bBytes == 0U))
                {
                    return false;
                }
                uintptr_t first = 0;
                uintptr_t second = 0;
                static_assert(sizeof(first) == sizeof(a),
                              "pointer and uintptr_t must have equal width");
                __builtin_memcpy(&first, static_cast<const void *>(&a),
                                 sizeof(first));
                __builtin_memcpy(&second, static_cast<const void *>(&b),
                                 sizeof(second));
                return first <= second ? second - first < aBytes
                                       : first - second < bBytes;
            }

            struct MemoryRange
            {
                    const void *data;
                    size_t bytes;
            };

            template <size_t Count>
            bool disjointRanges(const MemoryRange (&ranges)[Count])
            {
                for (size_t i = 0; i < Count; ++i)
                {
                    for (size_t j = i + 1U; j < Count; ++j)
                    {
                        if (overlaps(ranges[i].data, ranges[i].bytes,
                                     ranges[j].data, ranges[j].bytes))
                        {
                            return false;
                        }
                    }
                }
                return true;
            }

            class ScopedFrameClear final
            {
                public:
                    ScopedFrameClear(uint8_t *buffer, size_t bytes)
                        : buffer_(buffer), bytes_(bytes)
                    {
                    }

                    ~ScopedFrameClear()
                    {
                        volatile uint8_t *const bytes = buffer_;
                        for (size_t i = 0; i < bytes_; ++i)
                        {
                            // NOLINTNEXTLINE(*bounds-pointer-arithmetic)
                            bytes[i] = 0U;
                        }
                    }

                    ScopedFrameClear(const ScopedFrameClear &) = delete;
                    ScopedFrameClear &
                    operator=(const ScopedFrameClear &) = delete;
                    ScopedFrameClear(ScopedFrameClear &&) = delete;
                    ScopedFrameClear &operator=(ScopedFrameClear &&) = delete;

                private:
                    uint8_t *buffer_;
                    size_t bytes_;
            };

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
                       overlaps(input, inputBytes, engine, sizeof(*engine)) ||
                       overlaps(trust, trustBytes, engine, sizeof(*engine)) ||
                       overlaps(&action, sizeof(action), input, inputBytes) ||
                       overlaps(&action, sizeof(action), trust, trustBytes) ||
                       overlaps(&action, sizeof(action), out, capacity) ||
                       overlaps(out, capacity, engine, sizeof(*engine)) ||
                       overlaps(out, capacity, input, inputBytes) ||
                       overlaps(out, capacity, trust, trustBytes);
            }

            void copyBytes(uint8_t *dest, const uint8_t *src, size_t count)
            {
                __builtin_memmove(dest, src, count);
            }

            EngineResult mapPrepared(Result value)
            {
                if (value == Result::BufferTooSmall)
                {
                    return EngineResult::BufferTooSmall;
                }
                return value == Result::Ok ? EngineResult::Ok
                                           : EngineResult::InvalidInput;
            }

        } // namespace

        WifiEngine::WifiEngine() = default;

        WifiEngine::~WifiEngine() = default;

        void WifiEngine::resetDataSequences()
        {
            for (RxSequenceWindow &window : rxSequences_)
            {
                window = {};
            }
        }

        bool WifiEngine::acceptDataSequence(const uint8_t *frame, bool qosFrame)
        {
            // inspectStationRx has already accepted a complete, single-DS,
            // unfragmented data MPDU; the sequence and QoS bytes are within
            // its validated span. Copy a fixed-size header so no raw pointer
            // indexing crosses a DMA-backed buffer boundary.
            uint8_t header[kRxCopiedHeaderBytes] {};
            __builtin_memcpy(&header[0], frame, sizeof(header));
            size_t tid = qosFrame
                             ? static_cast<size_t>(header[kRxQosControlOffset] &
                                                   kRxTidMask)
                             : kRxLegacyTid;
            // A QoS AP can maintain separate sequence spaces for a station
            // receiver and group-addressed traffic. Do not suppress a valid
            // group MPDU because unicast used the same sequence number.
            if ((header[4] & 1U) != 0)
            {
                tid += kRxPerDestinationClasses;
            }
            RxSequenceWindow *window = nullptr;
            for (RxSequenceWindow &entry : rxSequences_)
            {
                if (tid == 0)
                {
                    window = &entry;
                    break;
                }
                --tid;
            }
            if (window == nullptr)
            {
                return false; // Validated TID must fit the destination table.
            }
            const auto sequence = static_cast<uint16_t>(
                ((static_cast<uint32_t>(header[23]) << 8U) |
                 static_cast<uint32_t>(header[22])) >>
                4U);
            if (!window->initialized)
            {
                *window = {1U, sequence, true};
                return true;
            }
            const auto forward =
                static_cast<uint16_t>((static_cast<uint32_t>(sequence) +
                                       kSequenceModulus - window->newest) &
                                      kSequenceMask);
            if (forward == 0)
            {
                // Even a peer omitting Retry cannot deliver a second copy.
                return false;
            }
            if (forward < kSequenceHalfRange)
            {
                window->seen = forward >= kRxSequenceHistory
                                   ? 1U
                                   : (window->seen << forward) | 1U;
                window->newest = sequence;
                return true;
            }
            const uint16_t behind = kSequenceModulus - forward;
            if (behind >= kRxSequenceHistory)
            {
                // With no block-ack reorder contract, an MPDU outside the
                // bounded history is too old to safely deliver.
                return false;
            }
            const uint64_t bit = uint64_t {1} << behind;
            if ((window->seen & bit) != 0)
            {
                return false;
            }
            window->seen |= bit;
            return true;
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
            osSupplicantOwned_ = false;
            channelAuthorized_ = false;
            nextSequence_ = 0;
            resetDataSequences();
            management_.clear();
            dataFragments_.clear();
            scanConfigured_ = false;
            scanOnChannel_ = false;
            scanComplete_ = false;
            scanCount_ = 0;
            scanIndex_ = 0;
            scanDeadlineMs_ = 0;
        }

        bool WifiEngine::copyAssociatedBss(Bss &out) const
        {
            if (overlaps(&out, sizeof(out), this, sizeof(*this)))
            {
                return false;
            }
            out = {};
            const StationState state = station_.state();
            if (!selected_ ||
                (state != StationState::AssociatedOpen &&
                 state != StationState::WaitingForWpa2Keys &&
                 state != StationState::HardwareKeysInstalled) ||
                link_.status().state != LinkState::Associated)
            {
                return false;
            }
            const Bss &candidate = station_.candidate();
            if (!candidate.occupied ||
                !sameMac(candidate.beacon.bssid, link_.status().bssid) ||
                candidate.beacon.ssidLength == 0 ||
                candidate.beacon.ssidLength > sizeof(candidate.beacon.ssid) ||
                candidate.beacon.channel == 0 ||
                candidate.beacon.channel > kMaximum2GhzChannel)
            {
                return false;
            }
            out = candidate;
            return true;
        }

        bool WifiEngine::configureKeys(const crypto::KeyHardware &hardware)
        {
            // The adapter checks its own storage, but the provider's opaque
            // writable context could point into this engine's station/link
            // state instead. Reject the entire owner, not just the adapter,
            // before retaining callbacks that may mutate that context.
            if (overlaps(hardware.context, 1, this, sizeof(*this)) ||
                overlaps(&hardware, sizeof(hardware), this, sizeof(*this)) ||
                keysConfigured_ || selected_)
            {
                return false;
            }
            keysConfigured_ = crypto_.configure(hardware);
            return keysConfigured_;
        }

        EngineResult WifiEngine::startScan(bool radioInitialized,
                                           bool countryChannelAllowed)
        {
            if (selected_ || (scanConfigured_ && !scanComplete_))
            {
                return EngineResult::InvalidState;
            }
            if (!radioInitialized)
            {
                return EngineResult::RadioNotReady;
            }
            if (!countryChannelAllowed)
            {
                return EngineResult::CountryNotAuthorized;
            }
            if (station_.enterScanning(radioInitialized,
                                       countryChannelAllowed) !=
                StationResult::Ok)
            {
                return EngineResult::InvalidState;
            }
            cache_.clear();
            management_.clear();
            dataFragments_.clear();
            channelAuthorized_ = countryChannelAllowed;
            scanConfigured_ = false;
            scanOnChannel_ = false;
            scanComplete_ = false;
            scanCount_ = 0;
            scanIndex_ = 0;
            return EngineResult::Ok;
        }

        EngineResult
        WifiEngine::beginChannelScan(const ScanScheduleRequest &request,
                                     uint64_t &generation)
        {
            if (request.count == 0 || request.count > kMaximumScanChannels ||
                request.channels == nullptr ||
                overlaps(request.channels,
                         request.count * sizeof(*request.channels), this,
                         sizeof(*this)) ||
                overlaps(&request, sizeof(request), this, sizeof(*this)) ||
                overlaps(&generation, sizeof(generation), this,
                         sizeof(*this)) ||
                overlaps(&generation, sizeof(generation), request.channels,
                         request.count * sizeof(*request.channels)) ||
                overlaps(&generation, sizeof(generation), &request,
                         sizeof(request)))
            {
                return EngineResult::InvalidInput;
            }
            if (scanGeneration_ == UINT64_MAX)
            {
                return EngineResult::InvalidState;
            }
            ScanChannelDwell copy[kMaximumScanChannels] {};
            __builtin_memcpy(&copy[0], request.channels,
                             request.count * sizeof(*request.channels));
            uint16_t seenChannels = 0;
            size_t checked = 0;
            for (const ScanChannelDwell &entry : copy)
            {
                if (checked++ == request.count)
                {
                    break;
                }
                // Passive-only: regulatory authority belongs to the native
                // channel policy. Refuse duplicates and unbounded dwells.
                if (entry.channel == 0 || entry.channel > kMaximum2GhzChannel ||
                    entry.dwellMs < kMinimumPassiveDwellMs ||
                    entry.dwellMs > kMaximumPassiveDwellMs)
                {
                    return EngineResult::InvalidInput;
                }
                const auto bit = static_cast<uint16_t>(1U << entry.channel);
                if ((seenChannels & bit) != 0)
                {
                    return EngineResult::InvalidInput;
                }
                seenChannels = static_cast<uint16_t>(seenChannels | bit);
            }
            const EngineResult started =
                startScan(request.radioReady, request.countryApproved);
            if (started != EngineResult::Ok)
            {
                return started;
            }
            __builtin_memcpy(&scanChannels_[0], &copy[0],
                             request.count * sizeof(*request.channels));
            scanCount_ = request.count;
            scanIndex_ = 0;
            scanLastClockMs_ = request.nowMs;
            scanTuneStartMs_ = 0;
            scanDeadlineMs_ = 0;
            scanOnChannel_ = false;
            scanComplete_ = false;
            scanConfigured_ = true;
            generation = ++scanGeneration_;
            return EngineResult::Ok;
        }

        const ScanChannelDwell &WifiEngine::currentScanChannel() const
        {
            size_t index = 0;
            for (const ScanChannelDwell &entry : scanChannels_)
            {
                if (index++ == scanIndex_)
                {
                    return entry;
                }
            }
            // scanIndex_ is bounded by validated plan length and checked
            // before every access; any violation is an internal logic fault.
            __builtin_trap();
        }

        EngineResult WifiEngine::pollChannelScan(uint64_t nowMs,
                                                 ScanProgress &progress)
        {
            if (overlaps(&progress, sizeof(progress), this, sizeof(*this)))
            {
                return EngineResult::InvalidInput;
            }
            progress = {};
            if (!scanConfigured_ || scanComplete_ ||
                station_.state() != StationState::Scanning)
            {
                return EngineResult::NoAction;
            }
            if (nowMs < scanLastClockMs_)
            {
                return EngineResult::InvalidInput;
            }
            scanLastClockMs_ = nowMs;
            if (scanOnChannel_ && nowMs >= scanDeadlineMs_)
            {
                scanOnChannel_ = false;
                ++scanIndex_;
                if (scanIndex_ == scanCount_)
                {
                    scanComplete_ = true;
                    progress.kind = ScanProgressKind::Complete;
                    progress.generation = scanGeneration_;
                    return EngineResult::Ok;
                }
            }
            progress.kind = scanOnChannel_ ? ScanProgressKind::Dwelling
                                           : ScanProgressKind::TuneRequired;
            progress.generation = scanGeneration_;
            progress.channel = currentScanChannel().channel;
            progress.deadlineMs = scanOnChannel_ ? scanDeadlineMs_ : 0;
            return EngineResult::Ok;
        }

        EngineResult WifiEngine::acknowledgeChannelTune(
            const ScanTuneConfirmation &confirmation)
        {
            if (overlaps(&confirmation, sizeof(confirmation), this,
                         sizeof(*this)))
            {
                return EngineResult::InvalidInput;
            }
            if (!scanConfigured_ || scanComplete_ || scanOnChannel_ ||
                station_.state() != StationState::Scanning ||
                confirmation.generation != scanGeneration_ ||
                confirmation.channel != currentScanChannel().channel)
            {
                return EngineResult::InvalidState;
            }
            if (!confirmation.hardwareConfirmed)
            {
                return EngineResult::RadioNotReady;
            }
            const uint64_t dwell = currentScanChannel().dwellMs;
            if (confirmation.nowMs < scanLastClockMs_ ||
                confirmation.nowMs > UINT64_MAX - dwell)
            {
                return EngineResult::InvalidInput;
            }
            scanLastClockMs_ = confirmation.nowMs;
            scanTuneStartMs_ = confirmation.nowMs;
            scanDeadlineMs_ = confirmation.nowMs + dwell;
            scanOnChannel_ = true;
            return EngineResult::Ok;
        }

        EngineResult WifiEngine::cancelChannelScan(uint64_t generation)
        {
            if (!scanConfigured_ || scanComplete_ ||
                generation != scanGeneration_)
            {
                return EngineResult::InvalidState;
            }
            scanConfigured_ = false;
            scanOnChannel_ = false;
            scanComplete_ = false;
            scanCount_ = 0;
            scanIndex_ = 0;
            cache_.clear();
            station_.reset();
            management_.clear();
            dataFragments_.clear();
            channelAuthorized_ = false;
            return EngineResult::Ok;
        }

        EngineResult WifiEngine::chooseNetwork(const Mac &station,
                                               const uint8_t *ssid,
                                               size_t ssidLength,
                                               uint8_t requestedChannel,
                                               bool allowOpen, bool allowWpa2,
                                               const uint8_t pmk[kWpa2PmkBytes])
        {
            if (selected_ || station_.state() != StationState::Scanning ||
                (scanConfigured_ && !scanComplete_))
            {
                return EngineResult::InvalidState;
            }
            if (!channelAuthorized_ || requestedChannel < 1U ||
                requestedChannel > kMaximum2GhzChannel)
            {
                return EngineResult::CountryNotAuthorized;
            }
            if (!validStationMac(station) || (ssid == nullptr) ||
                ssidLength == 0 || ssidLength > kMaxSsidBytes)
            {
                return EngineResult::InvalidInput;
            }
            // An explicit SSID is mandatory for association. A wildcard
            // scan result is never authorization to join an arbitrary BSS.
            Bss candidate {};
            if (!cache_.strongest(ssid,
                                  ScanSelection {
                                      ssidLength,
                                      requestedChannel,
                                      allowOpen,
                                      allowWpa2,
                                  },
                                  candidate))
            {
                return EngineResult::NoMatchingBss;
            }
            if (candidate.beacon.channel != requestedChannel)
            {
                return EngineResult::CountryNotAuthorized;
            }
            // Reject a forged local/AP identity before the WPA2 supplicant
            // sees credentials. Station::select also checks this, but runs
            // only after the optional security setup below.
            if (sameMac(station, candidate.beacon.bssid))
            {
                return EngineResult::InvalidInput;
            }
            const Security security = candidate.beacon.rsn.security;
            if (security == Security::Wpa2Personal)
            {
                if (!keysConfigured_ || (pmk == nullptr))
                {
                    return EngineResult::CryptoUnavailable;
                }
                const Wpa2Crypto callbacks = crypto_.callbacks();
                if ((callbacks.context == nullptr) ||
                    supplicant_.begin(
                        callbacks, station, candidate.beacon.bssid, pmk,
                        &candidate.beacon.rsnIe[0],
                        candidate.beacon.rsnIeLength) != Wpa2Result::Ok)
                {
                    return EngineResult::CryptoFailure;
                }
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
            osSupplicantOwned_ = false;
            resetDataSequences();
            management_.clear();
            dataFragments_.clear();
            stationAddress_ = station;
            return EngineResult::Ok;
        }

        EngineResult WifiEngine::chooseNetworkForDriverSupplicant(
            const Mac &station, const Mac &bssid, const uint8_t *ssid,
            size_t ssidLength, uint8_t requestedChannel,
            const uint8_t pmk[kWpa2PmkBytes])
        {
            if (selected_ || station_.state() != StationState::Scanning ||
                (scanConfigured_ && !scanComplete_))
            {
                return EngineResult::InvalidState;
            }
            if (!channelAuthorized_ || requestedChannel < 1U ||
                requestedChannel > kMaximum2GhzChannel)
            {
                return EngineResult::CountryNotAuthorized;
            }
            if (!validStationMac(station) || !validStationMac(bssid) ||
                sameMac(station, bssid) || ssid == nullptr || ssidLength == 0 ||
                ssidLength > kMaxSsidBytes ||
                overlaps(ssid, ssidLength, this, sizeof(*this)) ||
                overlaps(&station, sizeof(station), this, sizeof(*this)) ||
                overlaps(&bssid, sizeof(bssid), this, sizeof(*this)) ||
                overlaps(pmk, kWpa2PmkBytes, this, sizeof(*this)))
            {
                return EngineResult::InvalidInput;
            }
            if (!keysConfigured_ || pmk == nullptr)
            {
                return EngineResult::CryptoUnavailable;
            }
            Bss candidate {};
            if (!cache_.matchingBssid(bssid, ssid,
                                      ScanSelection {
                                          ssidLength,
                                          requestedChannel,
                                          false,
                                          true,
                                      },
                                      candidate))
            {
                return EngineResult::NoMatchingBss;
            }
            if (candidate.beacon.channel != requestedChannel ||
                candidate.beacon.rsn.security != Security::Wpa2Personal)
            {
                return EngineResult::UnsupportedSecurity;
            }
            const Wpa2Crypto callbacks = crypto_.callbacks();
            if (callbacks.context == nullptr ||
                supplicant_.begin(
                    callbacks, station, bssid, pmk, &candidate.beacon.rsnIe[0],
                    candidate.beacon.rsnIeLength) != Wpa2Result::Ok)
            {
                return EngineResult::CryptoFailure;
            }
            if (station_.select(station, candidate) != StationResult::Ok)
            {
                supplicant_.reset();
                return EngineResult::InvalidInput;
            }
            selected_ = true;
            osSupplicantOwned_ = false;
            resetDataSequences();
            management_.clear();
            dataFragments_.clear();
            stationAddress_ = station;
            return EngineResult::Ok;
        }

        EngineResult WifiEngine::chooseNetworkForDriverOpen(
            const Mac &station, const Mac &bssid, const uint8_t *ssid,
            size_t ssidLength, uint8_t requestedChannel)
        {
            if (selected_ || station_.state() != StationState::Scanning ||
                (scanConfigured_ && !scanComplete_))
            {
                return EngineResult::InvalidState;
            }
            if (!channelAuthorized_ || requestedChannel < 1U ||
                requestedChannel > kMaximum2GhzChannel)
            {
                return EngineResult::CountryNotAuthorized;
            }
            if (!validStationMac(station) || !validStationMac(bssid) ||
                sameMac(station, bssid) || ssid == nullptr || ssidLength == 0 ||
                ssidLength > kMaxSsidBytes ||
                overlaps(ssid, ssidLength, this, sizeof(*this)) ||
                overlaps(&station, sizeof(station), this, sizeof(*this)) ||
                overlaps(&bssid, sizeof(bssid), this, sizeof(*this)))
            {
                return EngineResult::InvalidInput;
            }
            Bss candidate {};
            if (!cache_.matchingBssid(bssid, ssid,
                                      ScanSelection {
                                          ssidLength,
                                          requestedChannel,
                                          true,
                                          false,
                                      },
                                      candidate))
            {
                return EngineResult::NoMatchingBss;
            }
            if (candidate.beacon.channel != requestedChannel ||
                candidate.beacon.rsn.security != Security::Open)
            {
                return EngineResult::UnsupportedSecurity;
            }
            if (station_.select(station, candidate) != StationResult::Ok)
            {
                return EngineResult::InvalidInput;
            }
            selected_ = true;
            osSupplicantOwned_ = false;
            resetDataSequences();
            management_.clear();
            dataFragments_.clear();
            stationAddress_ = station;
            return EngineResult::Ok;
        }

        EngineResult WifiEngine::chooseNetworkForOsSupplicant(
            const Mac &station, const Mac &bssid, const uint8_t *ssid,
            size_t ssidLength, uint8_t requestedChannel, bool wpa2Personal)
        {
            // An already configured internal key provider must never share
            // EAPOL, nonce or key ownership with the native OS supplicant.
            if (selected_ || keysConfigured_ ||
                station_.state() != StationState::Scanning ||
                (scanConfigured_ && !scanComplete_))
            {
                return EngineResult::InvalidState;
            }
            if (!channelAuthorized_ || requestedChannel < 1U ||
                requestedChannel > kMaximum2GhzChannel)
            {
                return EngineResult::CountryNotAuthorized;
            }
            if (!validStationMac(station) || !validStationMac(bssid) ||
                sameMac(station, bssid) || ssid == nullptr || ssidLength == 0 ||
                ssidLength > kMaxSsidBytes ||
                overlaps(ssid, ssidLength, this, sizeof(*this)) ||
                overlaps(&station, sizeof(station), this, sizeof(*this)) ||
                overlaps(&bssid, sizeof(bssid), this, sizeof(*this)))
            {
                return EngineResult::InvalidInput;
            }
            Bss candidate {};
            if (!cache_.matchingBssid(bssid, ssid,
                                      ScanSelection {
                                          ssidLength,
                                          requestedChannel,
                                          !wpa2Personal,
                                          wpa2Personal,
                                      },
                                      candidate))
            {
                return EngineResult::NoMatchingBss;
            }
            if (station_.select(station, candidate) != StationResult::Ok)
            {
                return EngineResult::InvalidInput;
            }
            selected_ = true;
            osSupplicantOwned_ = wpa2Personal;
            resetDataSequences();
            management_.clear();
            dataFragments_.clear();
            stationAddress_ = station;
            return EngineResult::Ok;
        }

        EngineResult WifiEngine::cancelPendingJoin()
        {
            const StationState state = station_.state();
            if (!selected_ ||
                (state != StationState::CandidateSelected &&
                 state != StationState::AuthenticationFramePrepared &&
                 state != StationState::Authenticated &&
                 state != StationState::AssociationFramePrepared))
            {
                return EngineResult::InvalidState;
            }
            // Do not invalidate the physical channel or retained, verified
            // scan results. A later scan request explicitly clears the cache.
            // A delayed AP response after cancellation cannot match the
            // station state because the candidate and security owner are gone.
            abandonCandidate();
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
            resetDataSequences();
            management_.clear();
            dataFragments_.clear();
            selected_ = false;
            osSupplicantOwned_ = false;
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
            {
                return EngineResult::InvalidInput;
            }
            action = {};
            if (!selected_)
            {
                return EngineResult::InvalidState;
            }
            size_t written = 0;
            const Result result = station_.authenticationRequest(
                sequence, out, capacity, written);
            if (result != Result::Ok)
            {
                return mapPrepared(result);
            }
            nextSequence_ =
                static_cast<uint16_t>((sequence + 1U) & kSequenceMask);
            return emitPrepared(ActionKind::TransmitAuthentication, written,
                                action);
        }

        EngineResult WifiEngine::handleAuthenticationResponse(
            const uint8_t *frame, size_t length, uint8_t *out, size_t capacity,
            EngineAction &action)
        {
            // First validate the AP response without changing station
            // state. A rejection or malformed RX requires no association
            // TX buffer; checking capacity first would mask the AP's
            // refusal and leave a rejected candidate active indefinitely.
            const Beacon &network = station_.candidate().beacon;
            uint16_t statusCode = UINT16_MAX;
            if (parseAuthenticationResponse(frame, length, stationAddress_,
                                            network.bssid,
                                            statusCode) != Result::Ok)
            {
                return EngineResult::InvalidReceivedFrame;
            }
            if (statusCode != 0)
            {
                abandonCandidate();
                return EngineResult::AccessPointRejected;
            }
            // Successful authentication needs a serialized association
            // request. Reserve its exact capacity before consuming the
            // state transition so the caller can retry a small buffer.
            const size_t associationBytes = associationRequestLength(network);
            if (associationBytes == 0)
            {
                return EngineResult::InvalidState;
            }
            if ((out == nullptr) || capacity < associationBytes)
            {
                return EngineResult::BufferTooSmall;
            }
            const StationResult authenticated =
                station_.onAuthenticationResponse(frame, length);
            if (authenticated == StationResult::AssociationRejected)
            {
                abandonCandidate();
                return EngineResult::AccessPointRejected;
            }
            if (authenticated != StationResult::Ok)
            {
                return EngineResult::InvalidReceivedFrame;
            }
            size_t written = 0;
            const Result prepared = station_.associationRequest(
                nextSequence_, out, capacity, written);
            if (prepared != Result::Ok)
            {
                return mapPrepared(prepared);
            }
            nextSequence_ =
                static_cast<uint16_t>((nextSequence_ + 1U) & kSequenceMask);
            return emitPrepared(ActionKind::TransmitAssociation, written,
                                action);
        }

        EngineResult WifiEngine::handleAssociationResponse(const uint8_t *frame,
                                                           size_t length,
                                                           EngineAction &action,
                                                           uint64_t nowMs)
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
            {
                return EngineResult::InvalidReceivedFrame;
            }
            const Bss &candidate = station_.candidate();
            if (link_.started(stationAddress_, candidate.beacon.bssid,
                              LinkStartConfig {
                                  candidate.beacon.intervalTu,
                                  nowMs,
                                  false,
                                  false,
                              }) != LinkMonitorResult::Ok)
            {
                return EngineResult::InvalidState;
            }
            if (response == StationResult::Wpa2CryptoNotImplemented)
            {
                return emitPrepared(ActionKind::AssociatedAwaitingKeys, 0,
                                    action);
            }
            return emitPrepared(ActionKind::OpenAssociationEstablished, 0,
                                action);
        }

        EngineResult WifiEngine::handleManagement(const uint8_t *frame,
                                                  size_t length, uint64_t nowMs,
                                                  uint8_t *out, size_t capacity,
                                                  EngineAction &action)
        {
            Frame header {};
            if (parseFrame(frame, length, header) != Result::Ok)
            {
                return EngineResult::InvalidReceivedFrame;
            }
            const StationState state = station_.state();
            if (state == StationState::AuthenticationFramePrepared &&
                header.subtype == kAuthResponseSubtype)
            {
                return handleAuthenticationResponse(frame, length, out,
                                                    capacity, action);
            }
            if (state == StationState::AssociationFramePrepared &&
                header.subtype == kAssociationResponseSubtype)
            {
                return handleAssociationResponse(frame, length, action, nowMs);
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
            if ((message == nullptr) || messageBytes > kMaximumEapolReply)
            {
                return EngineResult::InvalidInput;
            }
            // WPA2 EAPOL is cleartext at the 802.11 data layer until PTK
            // install. Keep source and destination distinct when encoding
            // LLC/SNAP.
            uint8_t ethernet[kEthernetHeader + kMaximumEapolReply] {};
            const Mac &ap = station_.candidate().beacon.bssid;
            copyBytes(&ethernet[0], &ap.bytes[0], kMacAddressBytes);
            copyBytes(&ethernet[kMacAddressBytes], &stationAddress_.bytes[0],
                      kMacAddressBytes);
            ethernet[kEtherTypeHighOffset] =
                static_cast<uint8_t>(kEtherTypeEapol >> kEtherTypeShift);
            ethernet[kEtherTypeLowOffset] =
                static_cast<uint8_t>(kEtherTypeEapol);
            copyBytes(&ethernet[kEthernetHeader], message, messageBytes);
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
            const DataPathResult encoded = prepareStationTx(
                link, &ethernet[0], kEthernetHeader + messageBytes,
                nextSequence_, out, capacity, packet);
            if (encoded != DataPathResult::Ok)
            {
                return encoded == DataPathResult::BufferTooSmall
                           ? EngineResult::BufferTooSmall
                           : EngineResult::InvalidState;
            }
            nextSequence_ =
                static_cast<uint16_t>((nextSequence_ + 1U) & kSequenceMask);
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
            {
                return EngineResult::InvalidState;
            }
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
            {
                return EngineResult::InvalidReceivedFrame;
            }
            if (msdu.etherType != kEtherTypeEapol)
            {
                if (link.security == LinkSecurity::Wpa2Ccmp &&
                    !supplicant_.keysInstalled())
                {
                    return EngineResult::CryptoUnavailable;
                }
                // Only an RX that passed the entire address, FCS, MAC and
                // security contract is allowed to advance duplicate state.
                // Suppress both Retry-marked retransmissions and malformed
                // second deliveries lacking Retry; keep QoS TIDs separate.
                if (!acceptDataSequence(frame, msdu.qosFrame))
                {
                    return EngineResult::NoAction;
                }
                EngineAction result {};
                result.kind = ActionKind::ReceivedPayload;
                result.etherType = msdu.etherType;
                result.receivedPayload = msdu.payload;
                result.receivedPayloadBytes = msdu.payloadLength;
                result.nativeInterfaceUsable = false;
                action = result;
                return EngineResult::Ok;
            }
            // The native OS-owned EAPOL path is separately admitted by the
            // physical EDMA owner and forwarded to one OS supplicant. Never
            // run the portable PMK/nonce/handshake callbacks for that link.
            if (osSupplicantOwned_)
            {
                return EngineResult::NoAction;
            }
            if (link.security != LinkSecurity::Wpa2Ccmp ||
                state != StationState::WaitingForWpa2Keys)
            {
                return EngineResult::NoAction;
            }
            KeyFrame key {};
            if (parseEapolKey(msdu.payload, msdu.payloadLength, key) !=
                EapolResult::Ok)
            {
                return EngineResult::InvalidReceivedFrame;
            }
            // Refuse too-small output BEFORE changing supplicant
            // replay/nonce/key state; the caller can provision enough room and
            // retry the same input.
            if ((out == nullptr) || capacity < kMinimumEapolTxFrameCapacity)
            {
                return EngineResult::BufferTooSmall;
            }
            uint8_t reply[kMaximumEapolReply] {};
            size_t written = 0;
            Wpa2Result security = Wpa2Result::InvalidState;
            if (key.message == KeyMessage::Pairwise1)
            {
                security =
                    supplicant_.onMessage1(msdu.payload, msdu.payloadLength,
                                           &reply[0], sizeof(reply), written);
            }
            else if (key.message == KeyMessage::Pairwise3)
            {
                security =
                    supplicant_.onMessage3(msdu.payload, msdu.payloadLength,
                                           &reply[0], sizeof(reply), written);
            }
            else
            {
                return EngineResult::NoAction;
            }
            if (security != Wpa2Result::Ok)
            {
                return EngineResult::CryptoFailure;
            }
            if (key.message == KeyMessage::Pairwise3 &&
                station_.recordInstalledWpa2Keys(supplicant_) !=
                    StationResult::NetworkInterfaceNotImplemented)
            {
                return EngineResult::CryptoFailure;
            }
            return packageEapol(&reply[0], written, out, capacity, action);
        }

        EngineResult WifiEngine::observeScanFrame(const uint8_t *frame,
                                                  size_t macBytes, int8_t rssi,
                                                  uint64_t nowMs,
                                                  EngineAction &action)
        {
            if (scanConfigured_)
            {
                // Only the confirmed, still-dwelling RF channel may
                // contribute BSS records. A frame from a prior hop cannot
                // contaminate the next scan channel.
                if (!scanOnChannel_ || nowMs < scanTuneStartMs_ ||
                    nowMs < scanLastClockMs_ || nowMs >= scanDeadlineMs_)
                {
                    return EngineResult::NoAction;
                }
                Beacon advertised {};
                if (parseBeacon(frame, macBytes, advertised) != Result::Ok ||
                    advertised.channel != currentScanChannel().channel)
                {
                    return EngineResult::NoAction;
                }
            }
            if (cache_.observe(frame, ScanObservation {
                                          macBytes,
                                          rssi,
                                          nowMs,
                                      }) == Result::Ok)
            {
                return emitPrepared(ActionKind::ScanCacheUpdated, 0, action);
            }
            return EngineResult::NoAction;
        }

        EngineResult WifiEngine::prepareRxFrame(const uint8_t *frame,
                                                size_t macBytes, uint64_t nowMs,
                                                DataFrameView &complete)
        {
            complete = {frame, macBytes};
            if (macBytes < 2U)
            {
                return EngineResult::Ok;
            }
            uint8_t frameControl = 0U;
            __builtin_memcpy(&frameControl, frame, sizeof(frameControl));
            if ((frameControl & kManagementVersionTypeMask) == 0U)
            {
                ManagementFrameView view {};
                const auto assembly =
                    management_.ingest(frame, macBytes, nowMs, view);
                if (assembly == ManagementFragmentResult::Rejected)
                {
                    return EngineResult::InvalidReceivedFrame;
                }
                if (assembly == ManagementFragmentResult::Pending)
                {
                    return EngineResult::NoAction;
                }
                complete = {view.bytes, view.length};
                return EngineResult::Ok;
            }
            if (macBytes < kDataFragmentHeaderBytes ||
                (frameControl & kManagementVersionTypeMask) != kDataVersionType)
            {
                return EngineResult::Ok;
            }
            uint8_t initial[kDataFragmentHeaderBytes] {};
            __builtin_memcpy(&initial[0], frame, sizeof(initial));
            const bool fragmented = (initial[1] & kFragmentedMoreBit) != 0U ||
                                    (initial[22] & kFragmentSequenceMask) != 0U;
            if (!fragmented)
            {
                return EngineResult::Ok;
            }
            // Per-fragment CCMP PN/MIC ownership is unavailable. A fragment
            // stream must never cross a station association or security mode.
            if (station_.state() != StationState::AssociatedOpen ||
                link_.status().state != LinkState::Associated)
            {
                dataFragments_.clear();
                return EngineResult::InvalidReceivedFrame;
            }
            DataFrameView view {};
            const auto assembly =
                dataFragments_.ingest(frame, macBytes, nowMs, view);
            if (assembly == DataFragmentResult::Rejected)
            {
                return EngineResult::InvalidReceivedFrame;
            }
            if (assembly == DataFragmentResult::Pending)
            {
                return EngineResult::NoAction;
            }
            complete = view;
            return EngineResult::Ok;
        }

        EngineResult WifiEngine::acceptRx(
            const uint8_t *frame, size_t length, const InputTrust &trust,
            const EngineRxObservation &observation, uint8_t *out,
            size_t capacity, EngineAction &action)
        {
            if (aliasesEngineIo(this, action, frame, length, &trust,
                                sizeof(trust), out, capacity) ||
                overlaps(&observation, sizeof(observation), this,
                         sizeof(*this)) ||
                overlaps(&observation, sizeof(observation), frame, length) ||
                overlaps(&observation, sizeof(observation), &trust,
                         sizeof(trust)) ||
                overlaps(&observation, sizeof(observation), out, capacity) ||
                overlaps(&observation, sizeof(observation), &action,
                         sizeof(action)))
            {
                return EngineResult::InvalidInput;
            }
            action = {};
            const auto rssi = observation.rssiDbm;
            const auto nowMs = observation.nowMs;
            if ((frame == nullptr) || !trust.radioReady ||
                !trust.channelAuthorized || !trust.dmaAndFcsVerified)
            {
                // An unverified or revoked RX must not leave an earlier
                // fragment eligible for completion after radio recovery.
                management_.clear();
                dataFragments_.clear();
                return EngineResult::InvalidInput;
            }
            // The trusted DMA owner must state whether the verified FCS was
            // stripped. A retained FCS is neither a management IE tail nor
            // Ethernet payload. Bounds/alias checks above cover the original
            // allocation; all parsers below see only the on-air MAC body.
            if (trust.rxFrameIncludesFcs && length < 4U)
            {
                management_.clear();
                dataFragments_.clear();
                return EngineResult::InvalidReceivedFrame;
            }
            const size_t macBytes =
                length - (trust.rxFrameIncludesFcs ? 4U : 0U);
            DataFrameView complete {};
            const auto preparation =
                prepareRxFrame(frame, macBytes, nowMs, complete);
            if (preparation != EngineResult::Ok)
            {
                return preparation;
            }
            Frame header {};
            if (parseFrame(complete.bytes, complete.length, header) !=
                Result::Ok)
            {
                return EngineResult::InvalidReceivedFrame;
            }

            if (header.type == FrameType::Management)
            {
                if (station_.state() == StationState::Scanning &&
                    (header.subtype == kBeaconSubtype ||
                     header.subtype == kProbeResponseSubtype))
                {
                    const EngineResult scanResult = observeScanFrame(
                        complete.bytes, complete.length, rssi, nowMs, action);
                    if (scanResult == EngineResult::Ok || scanConfigured_)
                    {
                        return scanResult;
                    }
                }
                return handleManagement(complete.bytes, complete.length, nowMs,
                                        out, capacity, action);
            }
            if (header.type == FrameType::Data)
            {
                return handleData(complete.bytes, complete.length, trust, out,
                                  capacity, action);
            }
            return EngineResult::NoAction;
        }

        EngineResult WifiEngine::acceptOpenAmsduRx(const uint8_t *frame,
                                                   size_t length,
                                                   const InputTrust &trust,
                                                   AmsduPayload &out)
        {
            if (overlaps(&out, sizeof(out), this, sizeof(*this)) ||
                overlaps(&out, sizeof(out), frame, length) ||
                overlaps(&out, sizeof(out), &trust, sizeof(trust)) ||
                overlaps(frame, length, this, sizeof(*this)) ||
                overlaps(frame, length, &trust, sizeof(trust)))
            {
                return EngineResult::InvalidInput;
            }
            out = {};
            if (frame == nullptr || !trust.radioReady ||
                !trust.channelAuthorized || !trust.dmaAndFcsVerified ||
                station_.state() != StationState::AssociatedOpen ||
                link_.status().state != LinkState::Associated)
            {
                return EngineResult::InvalidState;
            }
            LinkContext link {};
            link.station = stationAddress_;
            link.bssid = station_.candidate().beacon.bssid;
            link.security = LinkSecurity::Open;
            link.associated = true;
            link.rfReady = trust.radioReady;
            link.channelPermitted = trust.channelAuthorized;
            link.pairwiseAndGroupKeysInstalled = false;
            AmsduPayload accepted {};
            if (inspectStationAmsduRx(link, frame, length,
                                      trust.rxFrameIncludesFcs,
                                      trust.dmaAndFcsVerified, false,
                                      accepted) != DataPathResult::Ok)
            {
                return EngineResult::InvalidReceivedFrame;
            }
            // The *whole* aggregate consumes one 802.11 QoS sequence number.
            // Never publish a subframe before this shared duplicate gate.
            if (!acceptDataSequence(frame, true))
            {
                return EngineResult::NoAction;
            }
            out = accepted;
            return EngineResult::Ok;
        }

        EngineResult WifiEngine::acceptProtectedGroupRekey(
            const uint8_t *encrypted, size_t encryptedBytes, bool includesFcs,
            const InputTrust &trust, crypto::CcmpSession &receive,
            crypto::CcmpSession &transmit, uint64_t epoch,
            uint8_t *receiveScratch, size_t receiveScratchBytes,
            uint8_t *transmitScratch, size_t transmitScratchBytes, uint8_t *out,
            size_t capacity, EngineAction &action)
        {
            // A forged alias must not clear a live key/session, an RX DMA
            // input, a trusted metadata report or the caller's action.
            const MemoryRange ranges[] {
                {this, sizeof(*this)},
                {encrypted, encryptedBytes},
                {&trust, sizeof(trust)},
                {&receive, sizeof(receive)},
                {&transmit, sizeof(transmit)},
                {receiveScratch, receiveScratchBytes},
                {transmitScratch, transmitScratchBytes},
                {out, capacity},
                {&action, sizeof(action)},
            };
            if (!disjointRanges(ranges))
            {
                return EngineResult::InvalidInput;
            }
            action = {};
            if (encrypted == nullptr || out == nullptr ||
                receiveScratch == nullptr || transmitScratch == nullptr)
            {
                return EngineResult::InvalidInput;
            }
            constexpr size_t kGroup2PlainMpduBytes =
                kDataHeaderBytes + kSnapHeaderBytes + kGroup2ReplyBytes;
            constexpr size_t kProtectedGroup2Bytes =
                kGroup2PlainMpduBytes + kCcmpOverheadBytes;
            if (capacity < kProtectedGroup2Bytes ||
                transmitScratchBytes < kGroup2PlainMpduBytes)
            {
                return EngineResult::BufferTooSmall;
            }
            if (encryptedBytes > crypto::kCcmpMaximumMpduBytes + 4U ||
                encryptedBytes < kDataHeaderBytes + kCcmpOverheadBytes +
                                     (includesFcs ? 4U : 0U))
            {
                return EngineResult::InvalidReceivedFrame;
            }
            if (osSupplicantOwned_ || !keysConfigured_ ||
                station_.state() != StationState::HardwareKeysInstalled ||
                link_.status().state != LinkState::Associated ||
                !supplicant_.keysInstalledFor(
                    stationAddress_, station_.candidate().beacon.bssid))
            {
                return EngineResult::InvalidState;
            }
            if (!trust.radioReady || !trust.channelAuthorized ||
                !trust.dmaAndFcsVerified || !channelAuthorized_)
            {
                return EngineResult::RadioNotReady;
            }
            const Bss &candidate = station_.candidate();
            LinkContext link {};
            link.station = stationAddress_;
            link.bssid = candidate.beacon.bssid;
            link.security = LinkSecurity::Wpa2Ccmp;
            link.associated = true;
            link.rfReady = trust.radioReady;
            link.channelPermitted = trust.channelAuthorized;
            link.pairwiseAndGroupKeysInstalled = true;
            Msdu msdu {};
            // After decrypt, the borrowed EAPOL points into receiveScratch.
            // Both plaintext workspaces are erased on all subsequent exits.
            const ScopedFrameClear rxClear(receiveScratch, receiveScratchBytes);
            const ScopedFrameClear txClear(transmitScratch,
                                           transmitScratchBytes);
            const DataPathResult admitted = inspectProtectedStationRx(
                link, encrypted, encryptedBytes, includesFcs,
                trust.dmaAndFcsVerified, receive, epoch, receiveScratch,
                receiveScratchBytes, msdu);
            if (admitted != DataPathResult::Ok ||
                msdu.etherType != kEtherTypeEapol)
            {
                return EngineResult::InvalidReceivedFrame;
            }
            const EngineResult prepared = finishAuthenticatedGroupRekey(
                msdu, trust, receive, transmit, epoch, nextSequence_,
                transmitScratch, transmitScratchBytes, out, capacity, action);
            if (prepared == EngineResult::Ok)
            {
                nextSequence_ =
                    static_cast<uint16_t>((nextSequence_ + 1U) & kSequenceMask);
            }
            return prepared;
        }

        EngineResult WifiEngine::finishAuthenticatedGroupRekey(
            const Msdu &verified, const InputTrust &trust,
            crypto::CcmpSession &receive, crypto::CcmpSession &transmit,
            uint64_t epoch, uint16_t sequence, uint8_t *transmitScratch,
            size_t transmitScratchBytes, uint8_t *out, size_t capacity,
            EngineAction &action)
        {
            const MemoryRange ranges[] {
                {this, sizeof(*this)},
                {&verified, sizeof(verified)},
                {verified.payload, verified.payloadLength},
                {&trust, sizeof(trust)},
                {&receive, sizeof(receive)},
                {&transmit, sizeof(transmit)},
                {transmitScratch, transmitScratchBytes},
                {out, capacity},
                {&action, sizeof(action)},
            };
            if (!disjointRanges(ranges))
            {
                return EngineResult::InvalidInput;
            }
            action = {};
            if (verified.payload == nullptr || out == nullptr ||
                transmitScratch == nullptr || sequence > kSequenceMask)
            {
                return EngineResult::InvalidInput;
            }
            constexpr size_t kGroup2PlainMpduBytes =
                kDataHeaderBytes + kSnapHeaderBytes + kGroup2ReplyBytes;
            constexpr size_t kProtectedGroup2Bytes =
                kGroup2PlainMpduBytes + kCcmpOverheadBytes;
            if (capacity < kProtectedGroup2Bytes ||
                transmitScratchBytes < kGroup2PlainMpduBytes)
            {
                return EngineResult::BufferTooSmall;
            }
            const ScopedFrameClear txClear(transmitScratch,
                                           transmitScratchBytes);
            if (osSupplicantOwned_ || !keysConfigured_ ||
                station_.state() != StationState::HardwareKeysInstalled ||
                link_.status().state != LinkState::Associated ||
                !supplicant_.keysInstalledFor(
                    stationAddress_, station_.candidate().beacon.bssid))
            {
                return EngineResult::InvalidState;
            }
            if (!trust.radioReady || !trust.channelAuthorized ||
                !trust.dmaAndFcsVerified || !trust.ccmpMicAndReplayVerified ||
                !channelAuthorized_)
            {
                return EngineResult::RadioNotReady;
            }
            const Bss &candidate = station_.candidate();
            if (!verified.protectedFrame ||
                verified.etherType != kEtherTypeEapol ||
                !sameMac(verified.destination, stationAddress_) ||
                !sameMac(verified.source, candidate.beacon.bssid))
            {
                return EngineResult::InvalidReceivedFrame;
            }
            LinkContext link {};
            link.station = stationAddress_;
            link.bssid = candidate.beacon.bssid;
            link.security = LinkSecurity::Wpa2Ccmp;
            link.associated = true;
            link.rfReady = trust.radioReady;
            link.channelPermitted = trust.channelAuthorized;
            link.pairwiseAndGroupKeysInstalled = true;
            KeyFrame group {};
            if (parseEapolKey(verified.payload, verified.payloadLength,
                              group) != EapolResult::Ok ||
                group.message != KeyMessage::Group1)
            {
                return EngineResult::InvalidReceivedFrame;
            }
            uint8_t reply[kMaximumEapolReply] {};
            const ScopedFrameClear replyClear(&reply[0], sizeof(reply));
            size_t replyBytes = 0;
            const Wpa2Result security = supplicant_.onGroupMessage1(
                verified.payload, verified.payloadLength, &reply[0],
                sizeof(reply), replyBytes);
            if (security != Wpa2Result::Ok)
            {
                return EngineResult::CryptoFailure;
            }
            // Group1 authentication installs the new GTK. Every later
            // failure must revoke it: never allow a partially acknowledged
            // key epoch to keep sending with uncertain Group2 delivery.
            uint8_t ethernet[kEthernetHeader + kMaximumEapolReply] {};
            const ScopedFrameClear ethClear(&ethernet[0], sizeof(ethernet));
            copyBytes(&ethernet[0], &candidate.beacon.bssid.bytes[0],
                      kMacAddressBytes);
            copyBytes(&ethernet[kMacAddressBytes], &stationAddress_.bytes[0],
                      kMacAddressBytes);
            ethernet[kEtherTypeHighOffset] = kEtherTypeHighEapol;
            ethernet[kEtherTypeLowOffset] = kEtherTypeLowEapol;
            copyBytes(&ethernet[kEthernetHeader], &reply[0], replyBytes);
            SerializedData packet {};
            const DataPathResult encoded = prepareProtectedStationTx(
                link, &ethernet[0], kEthernetHeader + replyBytes, sequence,
                transmit, epoch, transmitScratch, transmitScratchBytes, out,
                capacity, packet);
            if (encoded != DataPathResult::Ok)
            {
                // GTK replacement has already succeeded, but the response
                // cannot be protected. Revoke the external CCMP pairwise PN
                // owners as well as the supplicant and link: clear() alone
                // does not own these caller-provided sessions.
                receive.revoke();
                transmit.revoke();
                clear();
                return encoded == DataPathResult::BufferTooSmall
                           ? EngineResult::BufferTooSmall
                           : EngineResult::CryptoFailure;
            }
            return emitPrepared(ActionKind::TransmitEapol, packet.frameBytes,
                                action);
        }

        EngineResult WifiEngine::checkBeaconTimeout(uint64_t nowMs,
                                                    EngineAction &action)
        {
            if (aliasesEngineIo(this, action, nullptr, 0, nullptr, 0, nullptr,
                                0))
            {
                return EngineResult::InvalidInput;
            }
            action = {};
            if (link_.observeTimeout(nowMs) != LinkMonitorResult::Ok)
            {
                return EngineResult::NoAction;
            }
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
            resetDataSequences();
            management_.clear();
            dataFragments_.clear();
            selected_ = false;
            keysConfigured_ = false;
            osSupplicantOwned_ = false;
            channelAuthorized_ = false;
            scanConfigured_ = false;
            scanOnChannel_ = false;
            scanComplete_ = false;
            scanCount_ = 0;
            scanIndex_ = 0;
        }

        EngineResult WifiEngine::encodeOutgoingEthernet(
            const uint8_t *ethernet, size_t length, uint16_t sequence,
            const InputTrust &trust, uint8_t *out, size_t capacity,
            EngineAction &action)
        {
            if (aliasesEngineIo(this, action, ethernet, length, &trust,
                                sizeof(trust), out, capacity))
            {
                return EngineResult::InvalidInput;
            }
            action = {};
            const StationState state = station_.state();
            if ((state != StationState::AssociatedOpen &&
                 state != StationState::HardwareKeysInstalled) ||
                link_.status().state != LinkState::Associated)
            {
                return EngineResult::InvalidState;
            }
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
            if (context.security == LinkSecurity::Wpa2Ccmp &&
                (ethernet != nullptr) && length >= kEthernetHeader)
            {
                uint8_t header[kEthernetHeader] {};
                __builtin_memcpy(&header[0], ethernet, sizeof(header));
                if (header[kEtherTypeHighOffset] == kEtherTypeHighEapol &&
                    header[kEtherTypeLowOffset] == kEtherTypeLowEapol)
                {
                    return EngineResult::CryptoUnavailable;
                }
            }
            SerializedData serialized {};
            const DataPathResult result = prepareStationTx(
                context, ethernet, length, sequence, out, capacity, serialized);
            if (result == DataPathResult::NeedsCcmpEncryption)
            {
                return EngineResult::CryptoUnavailable;
            }
            if (result != DataPathResult::Ok)
            {
                return result == DataPathResult::BufferTooSmall
                           ? EngineResult::BufferTooSmall
                           : EngineResult::InvalidInput;
            }
            // No transport here: output contains only bytes for the future PCI
            // and native wireless backend; never report IP connectivity.
            return emitPrepared(serialized.isEapol ? ActionKind::TransmitEapol
                                                   : ActionKind::TransmitData,
                                serialized.frameBytes, action);
        }

    } // namespace ieee80211
} // namespace simpleath
