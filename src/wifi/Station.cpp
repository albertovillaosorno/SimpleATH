// SPDX-License-Identifier: AGPL-3.0-only
#include "Station.hpp"
#include "Frames.hpp"
#include "Wpa2Supplicant.hpp"
#include <cstddef>
#include <cstdint>

namespace simpleath
{
    namespace ieee80211
    {
        namespace
        {
            constexpr uint8_t kExtendedRatesElementId = 50;
            constexpr uint8_t kBasicRateFlag = 0x80U;
            constexpr uint8_t kRateCodeMask = 0x7fU;
            constexpr uint16_t kPrivacyCapabilityBit = 0x10U;
            constexpr uint8_t kMaximum2GhzChannel = 14;
            constexpr size_t kRsnPayloadMinimumBytes = 20;
            constexpr uint8_t kRsnElementId = 48;
            constexpr size_t kRsnElementPrefixBytes = 2;
            constexpr size_t kAssociationCapabilitiesOffset = 24;

            template <typename T, size_t N>
            T &boundedElement(T (&elements)[N], size_t index)
            {
                for (T &element : elements)
                {
                    if (index == 0)
                    {
                        return element;
                    }
                    --index;
                }
                __builtin_trap();
            }

            uintptr_t pointerAddress(const void *pointer)
            {
                static_assert(sizeof(uintptr_t) == sizeof(pointer),
                              "station pointer width must match address width");
                uintptr_t address = 0;
                __builtin_memcpy(&address, static_cast<const void *>(&pointer),
                                 sizeof(pointer));
                return address;
            }

            const uint8_t *pointerAt(const uint8_t *base, size_t offset)
            {
                uintptr_t address = pointerAddress(base);
                address += offset;
                const uint8_t *result = nullptr;
                __builtin_memcpy(static_cast<void *>(&result),
                                 static_cast<const void *>(&address),
                                 sizeof(result));
                return result;
            }

            bool overlapsStorage(const void *first, size_t firstBytes,
                                 const void *second, size_t secondBytes)
            {
                if (first == nullptr || second == nullptr || firstBytes == 0 ||
                    secondBytes == 0)
                {
                    return false;
                }
                const auto left = pointerAddress(first);
                const auto right = pointerAddress(second);
                return left <= right ? right - left < firstBytes
                                     : left - right < secondBytes;
            }

            bool responseSharesSelectedRate(const uint8_t *frame, size_t length,
                                            const Beacon &selected)
            {
                // The association parser already validated this 24-byte
                // management header and six-byte fixed response body.
                constexpr size_t kRatesOffset = 24U + 6U;
                if (length < kRatesOffset)
                {
                    return false;
                }
                Elements cursor(pointerAt(frame, kRatesOffset),
                                length - kRatesOffset);
                Element element {};
                bool sharedRate = false;
                while (cursor.next(element) == CursorStatus::Element)
                {
                    if (element.id != 1 &&
                        element.id != kExtendedRatesElementId)
                    {
                        continue;
                    }
                    for (size_t i = 0; i < element.length; ++i)
                    {
                        // A raw BSS may contain optional PHY rates omitted
                        // from our association request. Only negotiated
                        // local/AP rates can make a response compatible.
                        const uint8_t receivedRate =
                            *pointerAt(element.data, i);
                        const bool supported =
                            associationRateSupported(selected, receivedRate);
                        // A response's basic bit is part of the negotiated
                        // BSS contract, not merely a supported PHY code. The
                        // AP cannot upgrade an optional rate to mandatory
                        // after our association request. Duplicate beacon
                        // rates may carry either bit, so accept a required
                        // response rate only when it was originally basic.
                        if ((receivedRate & kBasicRateFlag) != 0)
                        {
                            bool selectedBasic = false;
                            for (size_t j = 0; j < selected.rateCount; ++j)
                            {
                                selectedBasic |=
                                    boundedElement(selected.rates, j) ==
                                    receivedRate;
                            }
                            if (!supported || !selectedBasic)
                            {
                                return false;
                            }
                        }
                        sharedRate |= supported;
                    }
                }
                return sharedRate;
            }
        } // namespace

        Station::Station() = default;

        void Station::reset()
        {
            state_ = StationState::Inactive;
            chosen_ = {};
            stationMac_ = {};
            associationId_ = 0;
        }

        StationResult Station::enterScanning(bool radioInitialized,
                                             bool countryChannelAllowed)
        {
            if (!radioInitialized)
            {
                return StationResult::HardwareNotReady;
            }
            if (!countryChannelAllowed)
            {
                return StationResult::RegulatoryNotReady;
            }
            reset();
            state_ = StationState::Scanning;
            return StationResult::Ok;
        }

        StationResult Station::select(const Mac &station, const Bss &candidate)
        {
            if (state_ != StationState::Scanning)
            {
                return StationResult::InvalidState;
            }
            const Beacon &beacon = candidate.beacon;
            if (!validStationMac(station) || !candidate.occupied ||
                !validStationMac(beacon.bssid) ||
                sameMac(station, beacon.bssid) || !beacon.infrastructure ||
                // The public BSS snapshot flag is not proof of ESS mode.
                // IBSS and contradictory capabilities must not reach auth.
                (beacon.capabilities & 0x0003U) != 0x0001U ||
                beacon.hiddenSsid || beacon.ssidLength == 0 ||
                beacon.ssidLength > sizeof(beacon.ssid) ||
                beacon.channel == 0 || beacon.channel > kMaximum2GhzChannel ||
                beacon.intervalTu == 0 || beacon.rateCount == 0 ||
                beacon.rateCount > sizeof(beacon.rates))
            {
                return StationResult::UnsupportedNetwork;
            }
            // The hidden flag is snapshot metadata, not proof of a visible
            // name. Reject a forged all-zero fixed-length SSID before
            // advancing into authentication; the serializer also refuses it.
            bool hasVisibleSsidByte = false;
            for (size_t i = 0; i < beacon.ssidLength; ++i)
            {
                hasVisibleSsidByte |= boundedElement(beacon.ssid, i) != 0;
            }
            if (!hasVisibleSsidByte)
            {
                return StationResult::UnsupportedNetwork;
            }
            for (size_t i = 0; i < beacon.rateCount; ++i)
            {
                if ((boundedElement(beacon.rates, i) & kRateCodeMask) == 0)
                {
                    return StationResult::UnsupportedNetwork;
                }
            }
            // Never start authentication with an AP that requires an unknown
            // local basic rate, or has no common legacy rate to negotiate.
            if (associationRequestLength(beacon) == 0)
            {
                return StationResult::UnsupportedNetwork;
            }

            // Station::select is public, not only called through ScanCache.
            // Refuse a forged BSS snapshot that disagrees with its own
            // privacy/RSNE advertisement before preparing any TX bytes.
            const Security security = beacon.rsn.security;
            if (security == Security::Open)
            {
                if ((beacon.capabilities & kPrivacyCapabilityBit) != 0 ||
                    beacon.rsn.present || beacon.rsnIeLength != 0)
                {
                    return StationResult::UnsupportedNetwork;
                }
            }
            else if (security == Security::Wpa2Personal)
            {
                if ((beacon.capabilities & kPrivacyCapabilityBit) == 0 ||
                    !beacon.rsn.present || !beacon.rsn.valid ||
                    !beacon.rsn.pairwiseCcmp || !beacon.rsn.groupCcmp ||
                    !beacon.rsn.akmPsk || beacon.rsn.pmfRequired ||
                    beacon.rsnIeLength < kRsnPayloadMinimumBytes ||
                    beacon.rsnIeLength > sizeof(beacon.rsnIe) ||
                    beacon.rsnIe[0] != kRsnElementId ||
                    static_cast<size_t>(beacon.rsnIe[1]) +
                            kRsnElementPrefixBytes !=
                        beacon.rsnIeLength)
                {
                    return StationResult::UnsupportedNetwork;
                }
                Rsn validated {};
                if (parseRsn(&beacon.rsnIe[kRsnElementPrefixBytes],
                             beacon.rsnIeLength - kRsnElementPrefixBytes,
                             validated) != Result::Ok ||
                    validated.security != Security::Wpa2Personal ||
                    validated.pmfRequired || !validated.groupCcmp ||
                    !validated.pairwiseCcmp || !validated.akmPsk)
                {
                    return StationResult::UnsupportedNetwork;
                }
            }
            else
            {
                return StationResult::UnsupportedNetwork;
            }
            chosen_ = candidate;
            stationMac_ = station;
            associationId_ = 0;
            state_ = StationState::CandidateSelected;
            return StationResult::Ok;
        }

        Result Station::authenticationRequest(uint16_t sequence, uint8_t *out,
                                              size_t capacity, size_t &written)
        {
            // Reject aliases before zeroing written or serializing into the
            // station's live association snapshot.
            if (overlapsStorage(out, capacity, &written, sizeof(written)) ||
                overlapsStorage(out, capacity, this, sizeof(*this)) ||
                overlapsStorage(&written, sizeof(written), this, sizeof(*this)))
            {
                return Result::OverlappingBuffers;
            }
            written = 0;
            if (state_ != StationState::CandidateSelected)
            {
                return Result::UnsupportedFrame;
            }
            const Result result =
                makeOpenAuthenticationRequest(stationMac_, chosen_.beacon.bssid,
                                              sequence, out, capacity, written);
            if (result == Result::Ok)
            {
                state_ = StationState::AuthenticationFramePrepared;
            }
            return result;
        }

        StationResult Station::onAuthenticationResponse(const uint8_t *bytes,
                                                        size_t length)
        {
            if (state_ != StationState::AuthenticationFramePrepared)
            {
                return StationResult::InvalidState;
            }
            uint16_t code = 0;
            const Result result = parseAuthenticationResponse(
                bytes, length, stationMac_, chosen_.beacon.bssid, code);
            if (result != Result::Ok)
            {
                return StationResult::FrameRejected;
            }
            if (code != 0)
            {
                state_ = StationState::Failed;
                return StationResult::AssociationRejected;
            }
            state_ = StationState::Authenticated;
            return StationResult::Ok;
        }

        Result Station::associationRequest(uint16_t sequence, uint8_t *out,
                                           size_t capacity, size_t &written)
        {
            if (overlapsStorage(out, capacity, &written, sizeof(written)) ||
                overlapsStorage(out, capacity, this, sizeof(*this)) ||
                overlapsStorage(&written, sizeof(written), this, sizeof(*this)))
            {
                return Result::OverlappingBuffers;
            }
            written = 0;
            if (state_ != StationState::Authenticated)
            {
                return Result::UnsupportedFrame;
            }
            const Result result = makeAssociationRequest(
                stationMac_, chosen_.beacon, sequence, out, capacity, written);
            if (result == Result::Ok)
            {
                state_ = StationState::AssociationFramePrepared;
            }
            return result;
        }

        StationResult Station::onAssociationResponse(const uint8_t *bytes,
                                                     size_t length)
        {
            if (state_ != StationState::AssociationFramePrepared)
            {
                return StationResult::InvalidState;
            }
            uint16_t status = 0;
            uint16_t aid = 0;
            const Result parsed = parseAssociationResponse(
                bytes, length, stationMac_, chosen_.beacon.bssid, status, aid);
            if (parsed != Result::Ok)
            {
                return StationResult::FrameRejected;
            }
            if (status != 0)
            {
                state_ = StationState::Failed;
                return StationResult::AssociationRejected;
            }
            // The AP's successful Association Response must retain the
            // selected BSS's privacy policy. Never advance to Open or WPA2
            // using a response that advertises the opposite protection bit.
            // parseAssociationResponse already proved the 24-byte header and
            // six-byte fixed response body are present.
            if (((static_cast<uint32_t>(
                      *pointerAt(bytes, kAssociationCapabilitiesOffset)) ^
                  static_cast<uint32_t>(chosen_.beacon.capabilities)) &
                 kPrivacyCapabilityBit) != 0)
            {
                return StationResult::FrameRejected;
            }
            // An AP can change its advertised Supported Rates after the
            // scan. A response with no shared selected-BSS rate is not a
            // viable negotiated association; leave this state retryable.
            if (!responseSharesSelectedRate(bytes, length, chosen_.beacon))
            {
                return StationResult::FrameRejected;
            }
            associationId_ = aid;
            if (chosen_.beacon.rsn.security == Security::Wpa2Personal)
            {
                state_ = StationState::WaitingForWpa2Keys;
                return StationResult::Wpa2CryptoNotImplemented;
            }
            state_ = StationState::AssociatedOpen;
            return StationResult::NetworkInterfaceNotImplemented;
        }

        StationResult
        Station::recordInstalledWpa2Keys(const Wpa2Supplicant &supplicant)
        {
            if (state_ != StationState::WaitingForWpa2Keys)
            {
                return StationResult::InvalidState;
            }
            if (!supplicant.keysInstalledFor(stationMac_, chosen_.beacon.bssid))
            {
                return StationResult::Wpa2CryptoNotImplemented;
            }
            // Real packet delivery and macOS 802.11 interface registration are
            // separate steps; do not report a usable network yet.
            state_ = StationState::HardwareKeysInstalled;
            return StationResult::NetworkInterfaceNotImplemented;
        }

    } // namespace ieee80211
} // namespace simpleath
