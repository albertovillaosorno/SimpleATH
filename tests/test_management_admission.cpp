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

    bool rejectStaleElementCursorViews()
    {
        uint8_t valid[] {0, 1, 'A'};
        Elements cursor(valid, sizeof(valid));
        Element item {};
        if (cursor.next(item) != CursorStatus::Element || item.id != 0 ||
            item.length != 1 || item.data != valid + 2)
            return false;
        // End must revoke the last borrowed payload pointer; the owner may
        // release DMA-backed bytes after parsing finishes.
        if (cursor.next(item) != CursorStatus::End || item.data != nullptr ||
            item.length != 0 || item.id != 0)
            return false;

        uint8_t truncated[] {0, 1, 'B', 2, 3, 'C'};
        Elements malformed(truncated, sizeof(truncated));
        if (malformed.next(item) != CursorStatus::Element ||
            item.data != truncated + 2)
            return false;
        // A truncated next element must not retain a previously accepted
        // borrowed pointer, or advance past the malformed element.
        if (malformed.next(item) != CursorStatus::Truncated ||
            item.data != nullptr || item.length != 0 || item.id != 0 ||
            malformed.next(item) != CursorStatus::Truncated)
            return false;

        // An output that points into the input frame must not erase its
        // bytes, or cause the cursor to advance on a rejected attempt.
        struct Storage
        {
                Element output;
                uint8_t tail[16];
        } storage {};

        auto *frame = reinterpret_cast<uint8_t *>(&storage);
        frame[0] = 0;
        frame[1] = 0;
        uint8_t original[sizeof(storage)] {};
        std::memcpy(original, frame, sizeof(storage));
        Elements aliased(frame, sizeof(storage));
        if (aliased.next(storage.output) != CursorStatus::Truncated ||
            std::memcmp(original, frame, sizeof(storage)) != 0)
            return false;
        if (aliased.next(item) != CursorStatus::Element || item.id != 0 ||
            item.length != 0 || item.data != frame + 2)
            return false;
        return true;
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

    bool rejectZeroBeaconInterval()
    {
        // A zero TU interval is not a valid AP advertisement. A direct
        // parser consumer must not retain an earlier BSSID/security verdict
        // when the next Beacon or Probe Response has invalid fixed fields.
        uint8_t frame[kBeaconBytes] {};
        makeBeacon(frame);
        Beacon parsed {};
        if (parseBeacon(frame, sizeof(frame), parsed) != Result::Ok)
            return false;
        frame[32] = 0;
        frame[33] = 0;
        if (parseBeacon(frame, sizeof(frame), parsed) != Result::InvalidFrame ||
            parsed.intervalTu != 0 || parsed.ssidLength != 0 ||
            parsed.bssid.bytes[0] != 0 ||
            parsed.rsn.security != Security::UnsupportedRsn)
            return false;
        makeBeacon(frame);
        frame[0] = 0x50; // A directed Probe Response has the same fixed fields.
        std::memcpy(frame + 4, kStation, 6);
        frame[32] = 0;
        return parseBeacon(frame, sizeof(frame), parsed) ==
                   Result::InvalidFrame &&
               parsed.intervalTu == 0 && parsed.ssidLength == 0;
    }

    bool rejectHiddenAssociationName()
    {
        uint8_t frame[kBeaconBytes] {};
        makeBeacon(frame);
        // A hidden AP can advertise a fixed-length, entirely zero SSID.
        // It must not be serialized into an association as a visible name.
        std::memset(frame + 38, 0, 4);
        Beacon hidden {};
        if (parseBeacon(frame, sizeof(frame), hidden) != Result::Ok ||
            !hidden.hiddenSsid || hidden.ssidLength != 4)
            return false;
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        uint8_t output[96] {};
        std::memset(output, 0xa5, sizeof(output));
        size_t written = 77;
        if (makeAssociationRequest(station, hidden, 1, output, sizeof(output),
                                   written) != Result::InvalidSsid ||
            written != 0 || output[0] != 0xa5)
            return false;
        // A forged Beacon may lie about its hidden flag. Only a genuinely
        // nonzero visible name should be eligible for serialization.
        hidden.hiddenSsid = false;
        written = 77;
        if (makeAssociationRequest(station, hidden, 2, output, sizeof(output),
                                   written) != Result::InvalidSsid ||
            written != 0 || output[0] != 0xa5)
            return false;
        makeBeacon(frame);
        Beacon visible {};
        return parseBeacon(frame, sizeof(frame), visible) == Result::Ok &&
               makeAssociationRequest(station, visible, 3, output,
                                      sizeof(output), written) == Result::Ok &&
               written != 0 && output[0] == 0;
    }

    bool rejectSelfBssidManagementTx()
    {
        uint8_t advertisement[kBeaconBytes] {};
        makeBeacon(advertisement);
        Beacon network {};
        if (parseBeacon(advertisement, sizeof(advertisement), network) !=
            Result::Ok)
            return false;
        const Mac ap {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        uint8_t output[128] {};
        std::memset(output, 0xa5, sizeof(output));
        size_t written = 77;
        // Public serializers can be called without Station::select.
        // Refuse a self-AP identity before publishing any on-air bytes.
        if (makeOpenAuthenticationRequest(ap, ap, 1, output, sizeof(output),
                                          written) != Result::InvalidAddress ||
            written != 0 || output[0] != 0xa5)
            return false;
        written = 77;
        if (makeAssociationRequest(ap, network, 2, output, sizeof(output),
                                   written) != Result::InvalidAddress ||
            written != 0 || output[0] != 0xa5)
            return false;
        // Ordinary distinct station/AP addresses remain accepted.
        if (makeOpenAuthenticationRequest(station, ap, 3, output,
                                          sizeof(output),
                                          written) != Result::Ok ||
            written != 30)
            return false;
        return makeAssociationRequest(station, network, 4, output,
                                      sizeof(output), written) == Result::Ok &&
               written != 0;
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
        std::memcpy(frame + 4, kStation, 6); // Beacon must be broadcast.
        if (parseBeacon(frame, sizeof(frame), out) != Result::InvalidFrame)
            return false;
        makeBeacon(frame);
        frame[4] = 0xfe; // Other group-addressed beacons are not broadcast.
        if (parseBeacon(frame, sizeof(frame), out) != Result::InvalidFrame)
            return false;
        makeBeacon(frame);
        frame[0] = 0x50; // A Probe Response may be directed to our station.
        std::memcpy(frame + 4, kStation, 6);
        if (parseBeacon(frame, sizeof(frame), out) != Result::Ok)
            return false;
        makeBeacon(frame);
        frame[1] |= 0x40; // Protected management frame without decrypt.
        return parseBeacon(frame, sizeof(frame), out) == Result::InvalidFrame;
    }

    bool rejectConflictingBssModes()
    {
        uint8_t frame[kBeaconBytes] {};
        makeBeacon(frame);
        Beacon parsed {};
        // IEEE 802.11 ESS and IBSS are mutually exclusive. A forged
        // advertisement setting both must not be selected as infrastructure.
        frame[34] = 3;
        if (parseBeacon(frame, sizeof(frame), parsed) != Result::InvalidFrame)
            return false;
        makeBeacon(frame);
        frame[34] = 2; // A legitimate IBSS remains non-infrastructure.
        if (parseBeacon(frame, sizeof(frame), parsed) != Result::Ok ||
            parsed.infrastructure)
            return false;
        makeBeacon(frame);
        return parseBeacon(frame, sizeof(frame), parsed) == Result::Ok &&
               parsed.infrastructure;
    }

    bool rejectInvalidAssociationTimingAndChannel()
    {
        uint8_t advertisement[kBeaconBytes] {};
        makeBeacon(advertisement);
        Beacon network {};
        if (parseBeacon(advertisement, sizeof(advertisement), network) !=
            Result::Ok)
            return false;
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        uint8_t output[128] {};
        const auto rejected = [&]() -> bool
        {
            std::memset(output, 0xa5, sizeof(output));
            size_t written = 47;
            const size_t needed = associationRequestLength(network);
            const Result result = makeAssociationRequest(
                station, network, 1, output, sizeof(output), written);
            return needed == 0 && result == Result::InvalidFrame &&
                   written == 0 && output[0] == 0xa5;
        };

        // Public clients can synthesize Beacon metadata without parseBeacon
        // or Station::select. Neither a zero beacon cadence nor a missing or
        // invalid channel is a viable association request destination.
        network.intervalTu = 0;
        if (!rejected())
            return false;
        network.intervalTu = 100;
        network.channel = 0;
        if (!rejected())
            return false;
        network.channel = 15;
        if (!rejected())
            return false;
        network.channel = 6;
        size_t written = 0;
        return associationRequestLength(network) != 0 &&
               makeAssociationRequest(station, network, 2, output,
                                      sizeof(output), written) == Result::Ok &&
               written != 0 && output[0] == 0;
    }

    bool rejectForgedBssAssociationTx()
    {
        uint8_t advertisement[kBeaconBytes] {};
        makeBeacon(advertisement);
        Beacon network {};
        if (parseBeacon(advertisement, sizeof(advertisement), network) !=
            Result::Ok)
            return false;
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        uint8_t output[128] {};
        std::memset(output, 0xa5, sizeof(output));
        // A caller-built Beacon can forge the infrastructure flag. The
        // serializer must independently enforce ESS-only capabilities.
        const uint16_t invalidModes[] {0u, 2u, 3u};
        for (const uint16_t mode : invalidModes)
        {
            network.capabilities = mode;
            size_t written = 77;
            if (makeAssociationRequest(station, network, 1, output,
                                       sizeof(output),
                                       written) != Result::InvalidFrame ||
                written != 0 || output[0] != 0xa5)
                return false;
        }
        // Correct infrastructure metadata still produces a request.
        network.capabilities = 1u;
        size_t written = 0;
        return makeAssociationRequest(station, network, 2, output,
                                      sizeof(output), written) == Result::Ok &&
               written != 0 && output[0] == 0;
    }

    bool rejectForgedPrivacyAssociationTx()
    {
        uint8_t advertisement[kBeaconBytes] {};
        makeBeacon(advertisement);
        Beacon network {};
        if (parseBeacon(advertisement, sizeof(advertisement), network) !=
            Result::Ok)
            return false;
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        uint8_t output[128] {};
        const auto rejected = [&]() -> bool
        {
            std::memset(output, 0xa5, sizeof(output));
            size_t written = 37;
            return makeAssociationRequest(station, network, 1, output,
                                          sizeof(output),
                                          written) == Result::InvalidSecurity &&
                   written == 0 && output[0] == 0xa5;
        };

        // Beacon::rsn.security and RSN suite flags are caller-controlled.
        // Neither an Open downgrade of a privacy BSS, nor a forged WPA2
        // upgrade without a real matching RSNE, may emit association bytes.
        network.capabilities = 0x11u; // Privacy on but labeled Open.
        if (!rejected())
            return false;
        network.capabilities = 1u;
        network.rsn.security = Security::Wpa2Personal;
        network.rsn.present = true;
        network.rsn.valid = true;
        network.rsn.groupCcmp = true;
        network.rsn.pairwiseCcmp = true;
        network.rsn.akmPsk = true;
        if (!rejected()) // Privacy off, RSNE absent.
            return false;
        network.capabilities = 0x11u;
        if (!rejected()) // Privacy on, RSNE still absent.
            return false;
        const uint8_t rsnIe[22] {48, 20,   1,    0,    0,    0x0f, 0xac, 4,
                                 1,  0,    0,    0x0f, 0xac, 4,    1,    0,
                                 0,  0x0f, 0xac, 2,    0,    0};
        std::memcpy(network.rsnIe, rsnIe, sizeof(rsnIe));
        network.rsnIeLength = sizeof(rsnIe);
        network.rsnIe[7] = 2; // Fake metadata says CCMP; RSNE says TKIP.
        if (!rejected())
            return false;
        network.rsnIe[7] = 4;
        size_t written = 0;
        return makeAssociationRequest(station, network, 2, output,
                                      sizeof(output), written) == Result::Ok &&
               written != 0 && output[0] == 0;
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

        // Pairwise CCMP and PSK do not make a group-TKIP (or unknown group)
        // advertisement usable by this CCMP-only station. Preserve the
        // parsed suite metadata, but classify it as unsupported for scanning.
        frame[kBeaconBytes + 7] = 2; // Group cipher TKIP.
        if (parseBeacon(frame, kBeaconBytes + sizeof(rsnIe), parsed) !=
                Result::Ok ||
            parsed.rsn.security != Security::UnsupportedRsn ||
            parsed.rsn.groupCcmp || !parsed.rsn.pairwiseCcmp ||
            !parsed.rsn.akmPsk)
            return false;
        frame[kBeaconBytes + 7] = 0x7f; // Unknown group cipher.
        if (parseBeacon(frame, kBeaconBytes + sizeof(rsnIe), parsed) !=
                Result::Ok ||
            parsed.rsn.security != Security::UnsupportedRsn)
            return false;
        frame[kBeaconBytes + 7] = 4; // Restore compatible CCMP group.
        frame[34] = 0x01;            // Forged RSN on an Open capability BSS.
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

        // An absent TX buffer must not bypass alias safety: written may also
        // contain a borrowed SSID source, and clearing it before rejecting
        // the missing buffer would silently mutate the caller's input.
        size_t aliasedLength = 0x11223344u;
        const auto *borrowedSsid =
            reinterpret_cast<const uint8_t *>(&aliasedLength);
        if (makeProbeRequest(station, borrowedSsid, sizeof(aliasedLength), 5,
                             nullptr, 0,
                             aliasedLength) != Result::OverlappingBuffers ||
            aliasedLength != 0x11223344u)
            return false;
        aliasedLength = 99;
        if (makeProbeRequest(station, ssid, sizeof(ssid), 5, nullptr, 0,
                             aliasedLength) != Result::NullBuffer ||
            aliasedLength != 0)
            return false;
        return true;
    }

    bool revokeRejectedRsnSecurity()
    {
        // A reused RSN output must not retain WPA2 authorization after a
        // malformed or absent replacement element. Alias rejection below
        // remains separately required to preserve the input's original bytes.
        constexpr uint8_t validRsn[20] {1, 0,    0,    0x0f, 0xac, 4, 1,
                                        0, 0,    0x0f, 0xac, 4,    1, 0,
                                        0, 0x0f, 0xac, 2,    0,    0};
        Rsn parsed {};
        if (parseRsn(validRsn, sizeof(validRsn), parsed) != Result::Ok ||
            !parsed.valid || parsed.security != Security::Wpa2Personal)
            return false;
        const uint8_t truncated[2] {1, 0};
        if (parseRsn(truncated, sizeof(truncated), parsed) !=
                Result::InvalidSecurity ||
            parsed.valid || parsed.present ||
            parsed.security != Security::UnsupportedRsn)
            return false;
        if (parseRsn(validRsn, sizeof(validRsn), parsed) != Result::Ok)
            return false;
        uint8_t incorrectVersion[sizeof(validRsn)] {};
        std::memcpy(incorrectVersion, validRsn, sizeof(validRsn));
        incorrectVersion[0] = 2;
        if (parseRsn(incorrectVersion, sizeof(incorrectVersion), parsed) !=
                Result::InvalidSecurity ||
            parsed.valid || parsed.present ||
            parsed.security != Security::UnsupportedRsn)
            return false;
        if (parseRsn(validRsn, sizeof(validRsn), parsed) != Result::Ok)
            return false;
        return parseRsn(nullptr, 0, parsed) == Result::NullBuffer &&
               !parsed.valid && !parsed.present &&
               parsed.security == Security::UnsupportedRsn;
    }

    bool revokeRejectedFrameMetadata()
    {
        // Caller-owned parser output may be reused across DMA frames. An
        // unsupported or incomplete header must revoke the earlier BSSID and
        // address rather than leaving it available after a failed result.
        uint8_t advertisement[kBeaconBytes] {};
        makeBeacon(advertisement);
        Frame parsed {};
        if (parseFrame(advertisement, sizeof(advertisement), parsed) !=
                Result::Ok ||
            parsed.headerLength != 24 || parsed.source.bytes[0] != kAp[0])
            return false;
        advertisement[0] |= 1; // Nonzero 802.11 protocol version.
        if (parseFrame(advertisement, sizeof(advertisement), parsed) !=
                Result::UnsupportedFrame ||
            parsed.headerLength != 0 || parsed.source.bytes[0] != 0 ||
            parsed.bssid.bytes[0] != 0)
            return false;
        makeBeacon(advertisement);
        if (parseFrame(advertisement, sizeof(advertisement), parsed) !=
            Result::Ok)
            return false;
        if (parseFrame(advertisement, 1, parsed) != Result::Truncated ||
            parsed.headerLength != 0 || parsed.bssid.bytes[0] != 0)
            return false;
        if (parseFrame(advertisement, sizeof(advertisement), parsed) !=
            Result::Ok)
            return false;
        return parseFrame(nullptr, 0, parsed) == Result::NullBuffer &&
               parsed.headerLength == 0 && parsed.source.bytes[0] == 0;
    }

    bool revokeRejectedBeaconSecurity()
    {
        // A valid WPA2 BSS may precede a malformed or unsupported beacon.
        // Reject the replacement without retaining SSID, BSSID or RSNE
        // authorization from the earlier successful parse.
        constexpr uint8_t rsnIe[22] {48, 20,   1,    0,    0,    0x0f, 0xac, 4,
                                     1,  0,    0,    0x0f, 0xac, 4,    1,    0,
                                     0,  0x0f, 0xac, 2,    0,    0};
        uint8_t advertisement[kBeaconBytes + sizeof(rsnIe)] {};
        makeBeacon(advertisement);
        advertisement[34] |= 0x10; // Privacy bit.
        std::memcpy(advertisement + kBeaconBytes, rsnIe, sizeof(rsnIe));
        Beacon parsed {};
        const auto accepted = [&]()
        {
            return parseBeacon(advertisement, sizeof(advertisement), parsed) ==
                       Result::Ok &&
                   parsed.rsn.security == Security::Wpa2Personal &&
                   parsed.rsnIeLength == sizeof(rsnIe) &&
                   parsed.ssidLength == 4 && parsed.bssid.bytes[0] == kAp[0];
        };
        if (!accepted())
            return false;
        advertisement[0] = 0x40; // Probe request is not an advertisement.
        if (parseBeacon(advertisement, sizeof(advertisement), parsed) !=
                Result::UnsupportedFrame ||
            parsed.rsn.valid ||
            parsed.rsn.security != Security::UnsupportedRsn ||
            parsed.rsnIeLength || parsed.ssidLength || parsed.bssid.bytes[0])
            return false;
        advertisement[0] = 0x80;
        if (!accepted())
            return false;
        if (parseBeacon(advertisement, 3, parsed) != Result::Truncated ||
            parsed.rsn.valid ||
            parsed.rsn.security != Security::UnsupportedRsn ||
            parsed.rsnIeLength || parsed.ssidLength || parsed.bssid.bytes[0])
            return false;
        if (!accepted())
            return false;
        return parseBeacon(nullptr, 0, parsed) == Result::NullBuffer &&
               !parsed.rsn.valid &&
               parsed.rsn.security == Security::UnsupportedRsn &&
               parsed.rsnIeLength == 0 && parsed.ssidLength == 0 &&
               parsed.bssid.bytes[0] == 0;
    }

    bool rejectOverlappingManagementRx()
    {
        Frame parsedFrame {};
        uint8_t previousFrame[sizeof(parsedFrame)] {};
        std::memcpy(previousFrame, &parsedFrame, sizeof(parsedFrame));
        if (parseFrame(reinterpret_cast<const uint8_t *>(&parsedFrame),
                       sizeof(parsedFrame),
                       parsedFrame) != Result::OverlappingBuffers ||
            std::memcmp(&parsedFrame, previousFrame, sizeof(parsedFrame)) != 0)
            return false;

        struct RsnStorage
        {
                Rsn result;
                uint8_t trailing[32];
        } rsnStorage {};

        constexpr uint8_t rsnBody[20] {1, 0,    0,    0x0f, 0xac, 4, 1,
                                       0, 0,    0x0f, 0xac, 4,    1, 0,
                                       0, 0x0f, 0xac, 2,    0,    0};
        std::memcpy(&rsnStorage, rsnBody, sizeof(rsnBody));
        uint8_t previousRsn[sizeof(rsnStorage)] {};
        std::memcpy(previousRsn, &rsnStorage, sizeof(rsnStorage));
        if (parseRsn(reinterpret_cast<const uint8_t *>(&rsnStorage),
                     sizeof(rsnBody),
                     rsnStorage.result) != Result::OverlappingBuffers ||
            std::memcmp(&rsnStorage, previousRsn, sizeof(rsnStorage)) != 0)
            return false;

        Beacon parsedBeacon {};
        uint8_t beacon[kBeaconBytes] {};
        makeBeacon(beacon);
        std::memcpy(&parsedBeacon, beacon, sizeof(beacon));
        uint8_t previousBeacon[sizeof(parsedBeacon)] {};
        std::memcpy(previousBeacon, &parsedBeacon, sizeof(parsedBeacon));
        if (parseBeacon(reinterpret_cast<const uint8_t *>(&parsedBeacon),
                        sizeof(beacon),
                        parsedBeacon) != Result::OverlappingBuffers ||
            std::memcmp(&parsedBeacon, previousBeacon, sizeof(parsedBeacon)) !=
                0)
            return false;

        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        const Mac ap {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};

        struct ResponseBuffer
        {
                uint16_t status;
                uint8_t rest[32];
        } response {};

        auto *responseBytes = reinterpret_cast<uint8_t *>(&response);
        responseBytes[0] = 0xb0; // Authentication response subtype.
        std::memcpy(responseBytes + 4, kStation, 6);
        std::memcpy(responseBytes + 10, kAp, 6);
        std::memcpy(responseBytes + 16, kAp, 6);
        responseBytes[26] = 2; // Open-system response transaction.
        uint8_t previousResponse[sizeof(response)] {};
        std::memcpy(previousResponse, &response, sizeof(response));
        if (parseAuthenticationResponse(responseBytes, 30, station, ap,
                                        response.status) !=
                Result::OverlappingBuffers ||
            std::memcmp(&response, previousResponse, sizeof(response)) != 0)
            return false;

        uint8_t association[kAssocBytes] {};
        makeAssoc(association);
        uint16_t sharedResult = 543;
        if (parseAssociationResponse(association, sizeof(association), station,
                                     ap, sharedResult, sharedResult) !=
                Result::OverlappingBuffers ||
            sharedResult != 543)
            return false;
        return true;
    }

    bool rejectInvalidManagementRxIdentities()
    {
        const Mac empty {};
        const Mac ap {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        uint8_t auth[30] {};
        auth[0] = 0xb0; // Successful Open authentication transaction 2.
        auth[26] = 2;
        uint16_t status = 777;
        // Equality of forged addresses does not make either identity a
        // physical unicast AP or station.
        if (parseAuthenticationResponse(auth, sizeof(auth), empty, empty,
                                        status) != Result::InvalidAddress ||
            status != 777)
            return false;
        std::memcpy(auth + 4, kAp, 6);
        std::memcpy(auth + 10, kAp, 6);
        std::memcpy(auth + 16, kAp, 6);
        if (parseAuthenticationResponse(auth, sizeof(auth), ap, ap, status) !=
                Result::InvalidAddress ||
            status != 777)
            return false;
        std::memcpy(auth + 4, kStation, 6);
        if (parseAuthenticationResponse(auth, sizeof(auth), station, ap,
                                        status) != Result::Ok ||
            status != 0)
            return false;

        uint8_t association[kAssocBytes] {};
        makeAssoc(association);
        std::memset(association + 4, 0, 18);
        status = 777;
        uint16_t aid = 888;
        if (parseAssociationResponse(association, sizeof(association), empty,
                                     empty, status,
                                     aid) != Result::InvalidAddress ||
            status != 777 || aid != 888)
            return false;
        makeAssoc(association);
        std::memcpy(association + 4, kAp, 6);
        if (parseAssociationResponse(association, sizeof(association), ap, ap,
                                     status, aid) != Result::InvalidAddress ||
            status != 777 || aid != 888)
            return false;
        makeAssoc(association);
        return parseAssociationResponse(association, sizeof(association),
                                        station, ap, status,
                                        aid) == Result::Ok &&
               status == 0 && aid == 1;
    }

    bool rejectNonInfrastructureAssociation()
    {
        uint8_t frame[kAssocBytes] {};
        makeAssoc(frame);
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        const Mac ap {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        uint16_t status = 999;
        uint16_t aid = 999;
        frame[24] = 0; // No ESS capability bit.
        if (parseAssociationResponse(frame, sizeof(frame), station, ap, status,
                                     aid) != Result::InvalidFrame ||
            status != 999 || aid != 999)
            return false;
        frame[24] = 3; // ESS and IBSS must not both be set.
        if (parseAssociationResponse(frame, sizeof(frame), station, ap, status,
                                     aid) != Result::InvalidFrame)
            return false;
        frame[24] = 0;
        frame[26] = 1; // Failed association is still a valid rejection.
        return parseAssociationResponse(frame, sizeof(frame), station, ap,
                                        status, aid) == Result::Ok &&
               status == 1 && aid == 0;
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
    if (!rejectOverlappingManagementRx())
        return 8;
    if (!rejectNonInfrastructureAssociation())
        return 9;
    if (!rejectStaleElementCursorViews())
        return 10;
    if (!rejectHiddenAssociationName())
        return 11;
    if (!rejectSelfBssidManagementTx())
        return 12;
    if (!rejectInvalidManagementRxIdentities())
        return 13;
    if (!rejectConflictingBssModes())
        return 14;
    if (!rejectForgedBssAssociationTx())
        return 15;
    if (!rejectForgedPrivacyAssociationTx())
        return 16;
    if (!revokeRejectedRsnSecurity())
        return 17;
    if (!revokeRejectedFrameMetadata())
        return 18;
    if (!revokeRejectedBeaconSecurity())
        return 19;
    if (!rejectZeroBeaconInterval())
        return 20;
    if (!rejectInvalidAssociationTimingAndChannel())
        return 21;
    return 0;
}
