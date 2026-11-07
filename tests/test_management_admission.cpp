// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Alberto Villa Osorno.
// Host-only 802.11 admission regressions; no RF, Apple80211 or DMA inputs.
#include "wifi/Frames.hpp"
#include <cstring>

namespace
{
    using namespace simpleath::ieee80211;

    constexpr size_t kBeaconBytes = 49;
    constexpr size_t kAssocBytes = 34;
    constexpr uint8_t kAp[6] {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    constexpr uint8_t kStation[6] {0x02, 0x66, 0x77, 0x88, 0x99, 0xaa};

    void makeBeacon(uint8_t out[kBeaconBytes])
    {
        std::memset(out, 0, kBeaconBytes);
        out[0] = 0x80; // Beacon management subtype.
        std::memset(out + 4, 0xff, 6);
        std::memcpy(out + 10, kAp, 6);
        std::memcpy(out + 16, kAp, 6);
        out[32] = 100; // Beacon interval.
        out[34] = 1;   // Infrastructure BSS.
        out[36] = 0;   // SSID element.
        out[37] = 4;
        std::memcpy(out + 38, "Test", 4);
        out[42] = 1; // Supported Rates.
        out[43] = 2;
        out[44] = 0x82;
        out[45] = 0x84;
        out[46] = 3; // DS parameter set.
        out[47] = 1;
        out[48] = 6;
    }

    void makeAssoc(uint8_t out[kAssocBytes])
    {
        std::memset(out, 0, kAssocBytes);
        out[0] = 0x10; // Association response.
        std::memcpy(out + 4, kStation, 6);
        std::memcpy(out + 10, kAp, 6);
        std::memcpy(out + 16, kAp, 6);
        out[24] = 1;    // Infrastructure capability.
        out[28] = 0x01; // AID 1, with required top two bits set.
        out[29] = 0xc0;
        out[30] = 1; // Supported rates IE.
        out[31] = 2;
        out[32] = 0x82;
        out[33] = 0x84;
    }

    bool validBeacon()
    {
        uint8_t frame[kBeaconBytes] {};
        makeBeacon(frame);
        Beacon parsed {};
        if (parseBeacon(frame, sizeof(frame), parsed) != Result::Ok ||
            !parsed.infrastructure || parsed.hiddenSsid ||
            parsed.channel != 6 || parsed.intervalTu != 100 ||
            parsed.rateCount != 2 || parsed.rates[0] != 0x82 ||
            parsed.ssidLength != 4 || parsed.ssid[0] != 'T')
            return false;
        Frame header {};
        return parseFrame(frame, sizeof(frame), header) == Result::Ok &&
               header.type == FrameType::Management && header.subtype == 8 &&
               !header.moreFragments && header.fragment == 0;
    }

    bool rejectFragmentsAndForeignBssid()
    {
        uint8_t frame[kBeaconBytes] {};
        makeBeacon(frame);
        Beacon out {};
        frame[1] |= 0x04; // More Fragments on initial fragment.
        if (parseBeacon(frame, sizeof(frame), out) != Result::UnsupportedFrame)
            return false;
        makeBeacon(frame);
        frame[22] = 0x01; // Nonzero fragment index.
        if (parseBeacon(frame, sizeof(frame), out) != Result::UnsupportedFrame)
            return false;
        makeBeacon(frame);
        frame[15] ^= 0x02; // AP's source differs from BSSID.
        if (parseBeacon(frame, sizeof(frame), out) != Result::InvalidFrame)
            return false;
        makeBeacon(frame);
        frame[1] |= 0x40; // Protected management frame without decrypt.
        return parseBeacon(frame, sizeof(frame), out) == Result::InvalidFrame;
    }

    bool rejectInvalidRates()
    {
        uint8_t frame[kBeaconBytes] {};
        makeBeacon(frame);
        Beacon out {};
        frame[42] = 50; // Extended rates alone cannot replace base rates.
        if (parseBeacon(frame, sizeof(frame), out) != Result::InvalidElement)
            return false;
        makeBeacon(frame);
        frame[44] = 0x80; // Invalid zero-valued basic rate.
        if (parseBeacon(frame, sizeof(frame), out) != Result::InvalidElement)
            return false;
        makeBeacon(frame);
        frame[48] = 15; // Unsupported 2.4 GHz channel.
        return parseBeacon(frame, sizeof(frame), out) == Result::InvalidElement;
    }

    bool rejectRsnDowngradeAndDuplicates()
    {
        // WPA2-PSK/CCMP RSN IE and privacy bit on an otherwise valid beacon.
        constexpr uint8_t rsnIe[22] {48, 20,   1,    0,    0,    0x0f, 0xac, 4,
                                     1,  0,    0,    0x0f, 0xac, 4,    1,    0,
                                     0,  0x0f, 0xac, 2,    0,    0};
        uint8_t frame[kBeaconBytes + 2 * sizeof(rsnIe)] {};
        makeBeacon(frame);
        frame[34] = 0x11;
        std::memcpy(frame + kBeaconBytes, rsnIe, sizeof(rsnIe));
        Beacon parsed {};
        if (parseBeacon(frame, kBeaconBytes + sizeof(rsnIe), parsed) !=
                Result::Ok ||
            parsed.rsn.security != Security::Wpa2Personal ||
            !parsed.rsn.pairwiseCcmp || !parsed.rsn.akmPsk ||
            parsed.rsnIeLength != sizeof(rsnIe) ||
            std::memcmp(parsed.rsnIe, rsnIe, sizeof(rsnIe)) != 0)
            return false;
        frame[34] = 0x01; // Forged RSN on an Open capability BSS.
        if (parseBeacon(frame, kBeaconBytes + sizeof(rsnIe), parsed) !=
            Result::InvalidSecurity)
            return false;
        frame[34] = 0x11;
        std::memcpy(frame + kBeaconBytes + sizeof(rsnIe), rsnIe, sizeof(rsnIe));
        if (parseBeacon(frame, sizeof(frame), parsed) !=
            Result::InvalidSecurity)
            return false;
        // Unsupported AKM must not silently change the advertised BSS to Open.
        frame[kBeaconBytes + 19] = 0x7f;
        return parseBeacon(frame, kBeaconBytes + sizeof(rsnIe), parsed) ==
                   Result::Ok &&
               parsed.rsn.security == Security::UnsupportedRsn;
    }

    bool enforceDsHtConsistency()
    {
        uint8_t frame[kBeaconBytes + 24] {};
        makeBeacon(frame);
        frame[kBeaconBytes] = 61;     // HT Operation.
        frame[kBeaconBytes + 1] = 22; // Fixed HT Operation IE length.
        frame[kBeaconBytes + 2] = 11; // Conflicts with DS channel 6.
        Beacon parsed {};
        if (parseBeacon(frame, sizeof(frame), parsed) != Result::InvalidElement)
            return false;
        frame[kBeaconBytes + 2] = 6;
        if (parseBeacon(frame, sizeof(frame), parsed) != Result::Ok ||
            parsed.channel != 6)
            return false;
        frame[kBeaconBytes + 1] = 21; // Truncated/malformed HT Operation.
        return parseBeacon(frame, sizeof(frame), parsed) ==
               Result::InvalidElement;
    }

    bool rejectOverlappingManagementTx()
    {
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        const Mac ap {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        size_t written = 123;

        // A caller-owned SSID inside the output buffer must survive a failed
        // probe request unchanged, even though normal serialization zeroes
        // its output before copying the SSID.
        uint8_t probe[96] {};
        std::memset(probe, 0x5a, sizeof(probe));
        probe[40] = 'T';
        probe[41] = 'e';
        probe[42] = 's';
        probe[43] = 't';
        uint8_t previousProbe[sizeof(probe)] {};
        std::memcpy(previousProbe, probe, sizeof(probe));
        if (makeProbeRequest(station, probe + 40, 4, 1, probe, sizeof(probe),
                             written) != Result::OverlappingBuffers ||
            written != 123 ||
            std::memcmp(probe, previousProbe, sizeof(probe)) != 0)
            return false;

        struct StationBuffer
        {
                Mac input;
                uint8_t spare[64];
        } stationBuffer {station, {}};

        uint8_t previousStation[sizeof(stationBuffer)] {};
        std::memcpy(previousStation, &stationBuffer, sizeof(stationBuffer));
        written = 456;
        if (makeOpenAuthenticationRequest(
                stationBuffer.input, ap, 2,
                reinterpret_cast<uint8_t *>(&stationBuffer),
                sizeof(stationBuffer), written) != Result::OverlappingBuffers ||
            written != 456 ||
            std::memcmp(&stationBuffer, previousStation,
                        sizeof(stationBuffer)) != 0)
            return false;

        Beacon network {};
        network.bssid = ap;
        network.infrastructure = true;
        network.ssidLength = 4;
        std::memcpy(network.ssid, "Test", 4);
        network.rsn.security = Security::Open;
        uint8_t previousNetwork[sizeof(network)] {};
        std::memcpy(previousNetwork, &network, sizeof(network));
        written = 789;
        if (makeAssociationRequest(
                station, network, 3, reinterpret_cast<uint8_t *>(&network),
                sizeof(network), written) != Result::OverlappingBuffers ||
            written != 789 ||
            std::memcmp(&network, previousNetwork, sizeof(network)) != 0)
            return false;

        // The count is also a caller-owned reference. Do not zero it when
        // that reference lives inside the destination buffer.
        struct CountBuffer
        {
                size_t count;
                uint8_t spare[96];
        } countBuffer {321, {}};

        uint8_t previousCount[sizeof(countBuffer)] {};
        std::memcpy(previousCount, &countBuffer, sizeof(countBuffer));
        const uint8_t ssid[4] {'T', 'e', 's', 't'};
        if (makeProbeRequest(station, ssid, sizeof(ssid), 4,
                             reinterpret_cast<uint8_t *>(&countBuffer),
                             sizeof(countBuffer),
                             countBuffer.count) != Result::OverlappingBuffers ||
            std::memcmp(&countBuffer, previousCount, sizeof(countBuffer)) != 0)
            return false;
        return true;
    }

    bool enforceAssociationAdmission()
    {
        uint8_t frame[kAssocBytes] {};
        makeAssoc(frame);
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        const Mac ap {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        uint16_t status = 0xffff;
        uint16_t aid = 0xffff;
        if (parseAssociationResponse(frame, sizeof(frame), station, ap, status,
                                     aid) != Result::Ok ||
            status != 0 || aid != 1)
            return false;
        makeAssoc(frame);
        frame[29] = 0; // Successful AID requires both high bits set.
        if (parseAssociationResponse(frame, sizeof(frame), station, ap, status,
                                     aid) != Result::InvalidFrame)
            return false;
        makeAssoc(frame);
        if (parseAssociationResponse(frame, 30, station, ap, status, aid) !=
            Result::InvalidElement)
            return false;
        makeAssoc(frame);
        frame[32] = 0x80; // Invalid zero-valued rate.
        if (parseAssociationResponse(frame, sizeof(frame), station, ap, status,
                                     aid) != Result::InvalidElement)
            return false;
        makeAssoc(frame);
        frame[1] = 0x04; // Fragmented management handshake response.
        return parseAssociationResponse(frame, sizeof(frame), station, ap,
                                        status,
                                        aid) == Result::UnsupportedFrame;
    }
} // namespace

int main()
{
    if (!validBeacon())
        return 1;
    if (!rejectFragmentsAndForeignBssid())
        return 2;
    if (!rejectInvalidRates())
        return 3;
    if (!rejectRsnDowngradeAndDuplicates())
        return 4;
    if (!enforceDsHtConsistency())
        return 5;
    if (!enforceAssociationAdmission())
        return 6;
    if (!rejectOverlappingManagementTx())
        return 7;
    return 0;
}
