// SPDX-License-Identifier: AGPL-3.0-only
#include "Station.hpp"
#include "Wpa2Supplicant.hpp"

namespace simpleath
{
    namespace ieee80211
    {
        namespace
        {
            bool overlapsStorage(const void *first, size_t firstBytes,
                                 const void *second, size_t secondBytes)
            {
                if (!first || !second || !firstBytes || !secondBytes)
                    return false;
                const auto left = reinterpret_cast<uintptr_t>(first);
                const auto right = reinterpret_cast<uintptr_t>(second);
                return left <= right ? right - left < firstBytes
                                     : left - right < secondBytes;
            }

            bool responseSharesSelectedRate(const uint8_t *frame, size_t length,
                                            const Beacon &selected)
            {
                // The association parser already validated this 24-byte
                // management header and six-byte fixed response body.
                constexpr size_t kRatesOffset = 24u + 6u;
                if (length < kRatesOffset)
                    return false;
                Elements cursor(frame + kRatesOffset, length - kRatesOffset);
                Element element {};
                while (cursor.next(element) == CursorStatus::Element)
                {
                    if (element.id != 1 && element.id != 50)
                        continue;
                    for (size_t i = 0; i < element.length; ++i)
                        for (size_t j = 0; j < selected.rateCount; ++j)
                            // The basic-rate marker does not change the PHY
                            // rate. At least one selected BSS rate must still
                            // be advertised by the AP on association success.
                            if ((element.data[i] & 0x7fu) ==
                                (selected.rates[j] & 0x7fu))
                                return true;
                }
                return false;
            }
        } // namespace

        Station::Station()
            : state_(StationState::Inactive), chosen_ {}, stationMac_ {},
              associationId_(0)
        {
        }

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
                return StationResult::HardwareNotReady;
            if (!countryChannelAllowed)
                return StationResult::RegulatoryNotReady;
            reset();
            state_ = StationState::Scanning;
            return StationResult::Ok;
        }

        StationResult Station::select(const Mac &station, const Bss &candidate)
        {
            if (state_ != StationState::Scanning)
                return StationResult::InvalidState;
            const Beacon &beacon = candidate.beacon;
            if (!validStationMac(station) || !candidate.occupied ||
                !validStationMac(beacon.bssid) ||
                sameMac(station, beacon.bssid) || !beacon.infrastructure ||
                // The public BSS snapshot flag is not proof of ESS mode.
                // IBSS and contradictory capabilities must not reach auth.
                (beacon.capabilities & 0x0003u) != 0x0001u ||
                beacon.hiddenSsid || beacon.ssidLength == 0 ||
                beacon.ssidLength > sizeof(beacon.ssid) ||
                beacon.channel == 0 || beacon.channel > 14 ||
                beacon.intervalTu == 0 || beacon.rateCount == 0 ||
                beacon.rateCount > sizeof(beacon.rates))
                return StationResult::UnsupportedNetwork;
            // The hidden flag is snapshot metadata, not proof of a visible
            // name. Reject a forged all-zero fixed-length SSID before
            // advancing into authentication; the serializer also refuses it.
            bool hasVisibleSsidByte = false;
            for (size_t i = 0; i < beacon.ssidLength; ++i)
                hasVisibleSsidByte |= beacon.ssid[i] != 0;
            if (!hasVisibleSsidByte)
                return StationResult::UnsupportedNetwork;
            for (size_t i = 0; i < beacon.rateCount; ++i)
                if ((beacon.rates[i] & 0x7fu) == 0)
                    return StationResult::UnsupportedNetwork;

            // Station::select is public, not only called through ScanCache.
            // Refuse a forged BSS snapshot that disagrees with its own
            // privacy/RSNE advertisement before preparing any TX bytes.
            const Security security = beacon.rsn.security;
            if (security == Security::Open)
            {
                if ((beacon.capabilities & 0x10u) != 0 || beacon.rsn.present ||
                    beacon.rsnIeLength != 0)
                    return StationResult::UnsupportedNetwork;
            }
            else if (security == Security::Wpa2Personal)
            {
                if ((beacon.capabilities & 0x10u) == 0 || !beacon.rsn.present ||
                    !beacon.rsn.valid || !beacon.rsn.pairwiseCcmp ||
                    !beacon.rsn.groupCcmp || !beacon.rsn.akmPsk ||
                    beacon.rsn.pmfRequired || beacon.rsnIeLength < 20 ||
                    beacon.rsnIeLength > sizeof(beacon.rsnIe) ||
                    beacon.rsnIe[0] != 48 ||
                    static_cast<size_t>(beacon.rsnIe[1]) + 2 !=
                        beacon.rsnIeLength)
                    return StationResult::UnsupportedNetwork;
                Rsn validated {};
                if (parseRsn(beacon.rsnIe + 2, beacon.rsnIeLength - 2,
                             validated) != Result::Ok ||
                    validated.security != Security::Wpa2Personal ||
                    validated.pmfRequired || !validated.groupCcmp ||
                    !validated.pairwiseCcmp || !validated.akmPsk)
                    return StationResult::UnsupportedNetwork;
            }
            else
                return StationResult::UnsupportedNetwork;
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
                return Result::OverlappingBuffers;
            written = 0;
            if (state_ != StationState::CandidateSelected)
                return Result::UnsupportedFrame;
            const Result result =
                makeOpenAuthenticationRequest(stationMac_, chosen_.beacon.bssid,
                                              sequence, out, capacity, written);
            if (result == Result::Ok)
                state_ = StationState::AuthenticationFramePrepared;
            return result;
        }

        StationResult Station::onAuthenticationResponse(const uint8_t *bytes,
                                                        size_t length)
        {
            if (state_ != StationState::AuthenticationFramePrepared)
                return StationResult::InvalidState;
            uint16_t code = 0;
            const Result result = parseAuthenticationResponse(
                bytes, length, stationMac_, chosen_.beacon.bssid, code);
            if (result != Result::Ok)
                return StationResult::FrameRejected;
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
                return Result::OverlappingBuffers;
            written = 0;
            if (state_ != StationState::Authenticated)
                return Result::UnsupportedFrame;
            const Result result = makeAssociationRequest(
                stationMac_, chosen_.beacon, sequence, out, capacity, written);
            if (result == Result::Ok)
                state_ = StationState::AssociationFramePrepared;
            return result;
        }

        StationResult Station::onAssociationResponse(const uint8_t *bytes,
                                                     size_t length)
        {
            if (state_ != StationState::AssociationFramePrepared)
                return StationResult::InvalidState;
            uint16_t status = 0;
            uint16_t aid = 0;
            const Result parsed = parseAssociationResponse(
                bytes, length, stationMac_, chosen_.beacon.bssid, status, aid);
            if (parsed != Result::Ok)
                return StationResult::FrameRejected;
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
            if (((bytes[24] ^ chosen_.beacon.capabilities) & 0x10u) != 0)
                return StationResult::FrameRejected;
            // An AP can change its advertised Supported Rates after the
            // scan. A response with no shared selected-BSS rate is not a
            // viable negotiated association; leave this state retryable.
            if (!responseSharesSelectedRate(bytes, length, chosen_.beacon))
                return StationResult::FrameRejected;
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
                return StationResult::InvalidState;
            if (!supplicant.keysInstalledFor(stationMac_, chosen_.beacon.bssid))
                return StationResult::Wpa2CryptoNotImplemented;
            // Real packet delivery and macOS 802.11 interface registration are
            // separate steps; do not report a usable network yet.
            state_ = StationState::HardwareKeysInstalled;
            return StationResult::NetworkInterfaceNotImplemented;
        }

    } // namespace ieee80211
} // namespace simpleath
