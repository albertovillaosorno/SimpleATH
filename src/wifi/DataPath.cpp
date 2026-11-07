// SPDX-License-Identifier: AGPL-3.0-only
#include "DataPath.hpp"

namespace simpleath
{
    namespace ieee80211
    {
        namespace
        {
            constexpr uint16_t kEtherTypeEapol = 0x888eu;
            constexpr uint16_t kEtherTypeAarp = 0x80f3u;
            constexpr uint16_t kEtherTypeIpx = 0x8137u;
            constexpr size_t kEthernetHeaderBytes = 14u;
            constexpr size_t kDataHeaderBytes = 24u;
            constexpr size_t kSnapBytes = 8u;
            constexpr size_t kFcsBytes = 4u;
            constexpr size_t kMaximumMpduBytes = 2346u;

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

            void copyBytes(uint8_t *dest, const uint8_t *source, size_t length)
            {
                for (size_t i = 0; i < length; ++i)
                    dest[i] = source[i];
            }

            bool validDestination(const Mac &address)
            {
                uint8_t any = 0;
                for (size_t i = 0; i < 6; ++i)
                    any |= address.bytes[i];
                return any !=
                       0; // Multicast/broadcast can be Ethernet destinations.
            }

            bool physicalBssidValid(const Mac &address)
            {
                return validStationMac(address);
            }
        } // namespace

        DataPathResult prepareStationTx(const LinkContext &link,
                                        const uint8_t *ethernet,
                                        size_t ethernetBytes, uint16_t sequence,
                                        uint8_t *out, size_t capacity,
                                        SerializedData &result)
        {
            // Fail without modifying output or result on any validation
            // failure.
            if (!out || !ethernet)
                return DataPathResult::NullBuffer;
            if (!validStationMac(link.station) ||
                !physicalBssidValid(link.bssid))
                return DataPathResult::InvalidAddress;
            if (!link.rfReady)
                return DataPathResult::RadioNotReady;
            if (!link.channelPermitted)
                return DataPathResult::CountryNotAuthorized;
            if (!link.associated)
                return DataPathResult::NotAssociated;
            if (ethernetBytes < kEthernetHeaderBytes)
                return DataPathResult::InvalidEthernetFrame;
            const Mac destination {{ethernet[0], ethernet[1], ethernet[2],
                                    ethernet[3], ethernet[4], ethernet[5]}};
            const Mac source {{ethernet[6], ethernet[7], ethernet[8],
                               ethernet[9], ethernet[10], ethernet[11]}};
            if (!validDestination(destination) ||
                !sameMac(source, link.station))
                return DataPathResult::InvalidAddress;
            const uint16_t etherType =
                static_cast<uint16_t>(ethernet[12]) << 8u | ethernet[13];
            if (etherType < 0x0600u)
                return DataPathResult::InvalidEthernetFrame;

            const bool isEapol = etherType == kEtherTypeEapol;
            if (link.security == LinkSecurity::Wpa2Ccmp && !isEapol)
            {
                if (!link.pairwiseAndGroupKeysInstalled)
                    return DataPathResult::MissingKeys;
                // The secure-data TX path needs CCMP PN/IV/MIC and keycache
                // descriptor integration. Returning plaintext with Protected=1
                // would be unsafe.
                return DataPathResult::NeedsCcmpEncryption;
            }
            if (link.security != LinkSecurity::Wpa2Ccmp &&
                link.security != LinkSecurity::Open)
                return DataPathResult::InvalidEthernetFrame;

            const size_t payloadBytes = ethernetBytes - kEthernetHeaderBytes;
            // Leave room for the hardware FCS. No fragmentation is supported
            // here.
            if (payloadBytes >
                kMaximumMpduBytes - kDataHeaderBytes - kSnapBytes - kFcsBytes)
                return DataPathResult::FrameTooLong;
            const size_t written = kDataHeaderBytes + kSnapBytes + payloadBytes;
            if (capacity < written)
                return DataPathResult::BufferTooSmall;
            // Do not corrupt source identity, payload or output metadata
            // through forged aliases while preparing an on-air frame.
            if (overlaps(out, capacity, ethernet, ethernetBytes) ||
                overlaps(out, capacity, &link, sizeof(link)) ||
                overlaps(out, capacity, &result, sizeof(result)) ||
                overlaps(&result, sizeof(result), ethernet, ethernetBytes) ||
                overlaps(&result, sizeof(result), &link, sizeof(link)))
                return DataPathResult::OverlappingBuffers;

            // 0x0108: data subtype, ToDS=1, FromDS=0, no protection, no
            // fragments.
            for (size_t i = 0; i < kDataHeaderBytes + kSnapBytes; ++i)
                out[i] = 0;
            out[0] = 0x08;
            out[1] = 0x01;
            // addr1=AP receiver, addr2=station transmitter, addr3=final
            // Ethernet DA.
            copyBytes(out + 4, link.bssid.bytes, 6);
            copyBytes(out + 10, link.station.bytes, 6);
            copyBytes(out + 16, destination.bytes, 6);
            const uint16_t sequenceControl =
                static_cast<uint16_t>((sequence & 0x0fffu) << 4u);
            out[22] = static_cast<uint8_t>(sequenceControl);
            out[23] = static_cast<uint8_t>(sequenceControl >> 8u);
            // RFC 1042 LLC/SNAP carries an Ethernet-II Ethertype.
            out[24] = 0xaau;
            out[25] = 0xaau;
            out[26] = 3u;
            out[27] = 0;
            out[28] = 0;
            // IEEE 802.1H bridge-tunnel SNAP is required for Ethernet-II
            // AARP and IPX; RFC 1042 (OUI 00:00:00) is used otherwise.
            out[29] =
                (etherType == kEtherTypeAarp || etherType == kEtherTypeIpx)
                    ? 0xf8u
                    : 0u;
            out[30] = ethernet[12];
            out[31] = ethernet[13];
            copyBytes(out + kDataHeaderBytes + kSnapBytes,
                      ethernet + kEthernetHeaderBytes, payloadBytes);

            SerializedData staged {};
            staged.frameBytes = written;
            staged.onAirLengthIncludingFcs = written + kFcsBytes;
            staged.sequence = sequence & 0x0fffu;
            staged.etherType = etherType;
            staged.needsCcmp = false;
            staged.isEapol = isEapol;
            result = staged;
            return DataPathResult::Ok;
        }

        DataPathResult inspectStationRx(const LinkContext &link,
                                        const uint8_t *frame, size_t frameBytes,
                                        bool fcsIncluded,
                                        bool fcsAndDmaValidated,
                                        bool ccmpMicAndPnValidated,
                                        Msdu &result)
        {
            // A malformed result reference must not erase the selected link
            // identity or DMA-backed input before RX validity checks.
            if (overlaps(&result, sizeof(result), frame, frameBytes) ||
                overlaps(&result, sizeof(result), &link, sizeof(link)))
                return DataPathResult::OverlappingBuffers;
            // An ordinary failed admission revokes stale borrowed RX payload.
            result = {};
            if (!frame)
                return DataPathResult::NullBuffer;
            if (!validStationMac(link.station) ||
                !physicalBssidValid(link.bssid))
                return DataPathResult::InvalidAddress;
            if (!link.rfReady || !link.associated)
                return DataPathResult::NotAssociated;
            if (!link.channelPermitted)
                return DataPathResult::CountryNotAuthorized;
            if (!fcsAndDmaValidated)
                return DataPathResult::InvalidRxStatus;
            Frame header {};
            if (parseFrame(frame, frameBytes, header) != Result::Ok)
                return DataPathResult::MalformedFrame;
            // Only infrastructure AP-to-station frames, not locally generated
            // frames or four-address WDS; other formats require explicit
            // support.
            if (header.type != FrameType::Data || header.toDs ||
                !header.fromDs || !sameMac(header.bssid, link.bssid))
                return DataPathResult::NotFromAssociatedAccessPoint;
            // Multicast/broadcast is accepted; unicast must address our
            // station.
            if ((header.destination.bytes[0] & 1u) == 0 &&
                !sameMac(header.destination, link.station))
                return DataPathResult::NotForThisStation;
            // Unprotected data is permitted only on open associations or EAPOL
            // during WPA2 key exchange. Ethernet type is determined *after*
            // validating RX.
            if (header.protectedFrame && !ccmpMicAndPnValidated)
                return DataPathResult::UnverifiedDecryption;
            Msdu parsed {};
            const Result decoded = decodeLlcData(frame, frameBytes, fcsIncluded,
                                                 ccmpMicAndPnValidated, parsed);
            if (decoded != Result::Ok)
                return DataPathResult::UnsupportedFrame;
            if (link.security == LinkSecurity::Wpa2Ccmp)
            {
                // WPA2-PSK pairwise handshake frames are addressed to this
                // station, never to an arbitrary multicast destination.
                if (parsed.etherType == kEtherTypeEapol &&
                    !sameMac(parsed.destination, link.station))
                    return DataPathResult::NotForThisStation;
                if (parsed.etherType != kEtherTypeEapol)
                {
                    if (!link.pairwiseAndGroupKeysInstalled ||
                        !header.protectedFrame || !ccmpMicAndPnValidated)
                        return DataPathResult::UnverifiedDecryption;
                }
                else if (header.protectedFrame && !ccmpMicAndPnValidated)
                {
                    return DataPathResult::UnverifiedDecryption;
                }
            }
            else if (link.security == LinkSecurity::Open)
            {
                if (header.protectedFrame)
                    return DataPathResult::UnverifiedDecryption;
            }
            else
            {
                return DataPathResult::UnsupportedFrame;
            }
            result = parsed;
            return DataPathResult::Ok;
        }

    } // namespace ieee80211
} // namespace simpleath
