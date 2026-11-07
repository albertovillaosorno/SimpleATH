// SPDX-License-Identifier: AGPL-3.0-only
#include "Station.hpp"
#include "Wpa2Supplicant.hpp"

namespace simpleath
{
    namespace ieee80211
    {

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
                beacon.hiddenSsid || beacon.ssidLength == 0 ||
                beacon.ssidLength > sizeof(beacon.ssid) ||
                beacon.channel == 0 || beacon.channel > 14 ||
                beacon.intervalTu == 0 || beacon.rateCount == 0 ||
                beacon.rateCount > sizeof(beacon.rates))
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
            if (!supplicant.keysInstalled())
                return StationResult::Wpa2CryptoNotImplemented;
            // Real packet delivery and macOS 802.11 interface registration are
            // separate steps; do not report a usable network yet.
            state_ = StationState::HardwareKeysInstalled;
            return StationResult::NetworkInterfaceNotImplemented;
        }

    } // namespace ieee80211
} // namespace simpleath
