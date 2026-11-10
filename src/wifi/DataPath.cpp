// SPDX-License-Identifier: AGPL-3.0-only
#include "DataPath.hpp"
#include "Eapol.hpp"
#include "wifi/DataFrames.hpp"
#include "wifi/Frames.hpp"
#include <cstddef>
#include <cstdint>

namespace simpleath
{
    namespace ieee80211
    {
        namespace
        {
            constexpr uint16_t kEtherTypeEapol = 0x888eU;
            constexpr uint16_t kEtherTypeAarp = 0x80f3U;
            constexpr uint16_t kEtherTypeIpx = 0x8137U;
            constexpr size_t kEthernetHeaderBytes = 14U;
            constexpr size_t kDataHeaderBytes = 24U;
            constexpr size_t kSnapBytes = 8U;
            constexpr size_t kFcsBytes = 4U;
            constexpr size_t kMaximumMpduBytes = 2346U;
            constexpr uint16_t kMinimumEtherType = 0x0600U;
            constexpr size_t kMacBytes = 6U;
            constexpr size_t kSnapOuiLastIndex = 5U;
            constexpr size_t kSnapTypeHighIndex = 6U;
            constexpr size_t kSnapTypeLowIndex = 7U;
            constexpr uint8_t kMsbShift = 8U;
            constexpr uint8_t kDataToDs = 0x01U;
            constexpr uint8_t kDataFrame = 0x08U;
            constexpr uint8_t kSnapSap = 0xaaU;
            constexpr uint8_t kSnapUnnumbered = 3U;
            constexpr uint8_t kBridgeTunnelOui = 0xf8U;
            constexpr uint16_t kSequenceMask = 0x0fffU;
            constexpr uint8_t kSequenceFragmentBits = 4U;

            struct EthernetHeaderBytes
            {
                    uint8_t destination[kMacBytes];
                    uint8_t source[kMacBytes];
                    uint8_t type[2];
            };

            static_assert(sizeof(EthernetHeaderBytes) == kEthernetHeaderBytes,
                          "Ethernet-II header must be exactly 14 bytes");

            struct StationTxHeader
            {
                    uint8_t control[2];
                    uint8_t duration[2];
                    uint8_t receiver[kMacBytes];
                    uint8_t transmitter[kMacBytes];
                    uint8_t destination[kMacBytes];
                    uint8_t sequence[2];
                    uint8_t snap[kSnapBytes];
            };

            static_assert(sizeof(StationTxHeader) ==
                              kDataHeaderBytes + kSnapBytes,
                          "802.11 ToDS with LLC/SNAP must be 32 bytes");

            uintptr_t pointerAddress(const void *pointer)
            {
                static_assert(sizeof(uintptr_t) == sizeof(pointer),
                              "pointer address representation must match");
                uintptr_t address = 0;
                __builtin_memcpy(&address, static_cast<const void *>(&pointer),
                                 sizeof(pointer));
                return address;
            }

            bool overlaps(const void *a, size_t aBytes, const void *b,
                          size_t bBytes)
            {
                if (a == nullptr || b == nullptr || aBytes == 0 || bBytes == 0)
                {
                    return false;
                }
                const auto first = pointerAddress(a);
                const auto second = pointerAddress(b);
                return first <= second ? second - first < aBytes
                                       : first - second < bBytes;
            }

            // Every caller validates its source/destination capacity and
            // disjointness before constructing the 802.11 wire frame.
            void copyBytes(uint8_t *dest, const uint8_t *source, size_t length)
            {
                if (length != 0U)
                {
                    __builtin_memcpy(dest, source, length);
                }
            }

            bool validDestination(const Mac &address)
            {
                uint8_t any = 0;
                for (const unsigned char byte : address.bytes)
                {
                    any |= byte;
                }
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
            if ((out == nullptr) || (ethernet == nullptr))
            {
                return DataPathResult::NullBuffer;
            }
            // The selected station and the AP must be distinct; callers can
            // construct LinkContext without passing station association.
            if (!validStationMac(link.station) ||
                !physicalBssidValid(link.bssid) ||
                sameMac(link.station, link.bssid))
            {
                return DataPathResult::InvalidAddress;
            }
            if (!link.rfReady)
            {
                return DataPathResult::RadioNotReady;
            }
            if (!link.channelPermitted)
            {
                return DataPathResult::CountryNotAuthorized;
            }
            if (!link.associated)
            {
                return DataPathResult::NotAssociated;
            }
            // The link's keycache claim belongs to its selected security
            // mode. A forged Open association with stale WPA2 keys must not
            // authorize unprotected transmission through this public API.
            if (link.security == LinkSecurity::Open &&
                link.pairwiseAndGroupKeysInstalled)
            {
                return DataPathResult::InvalidSecurityState;
            }
            if (ethernetBytes < kEthernetHeaderBytes)
            {
                return DataPathResult::InvalidEthernetFrame;
            }
            EthernetHeaderBytes header {};
            __builtin_memcpy(&header, ethernet, sizeof(header));
            Mac destination {};
            Mac source {};
            __builtin_memcpy(&destination.bytes[0], &header.destination[0],
                             sizeof(header.destination));
            __builtin_memcpy(&source.bytes[0], &header.source[0],
                             sizeof(header.source));
            if (!validDestination(destination) ||
                !sameMac(source, link.station))
            {
                return DataPathResult::InvalidAddress;
            }
            const auto etherType = static_cast<uint16_t>(
                (static_cast<uint32_t>(header.type[0]) << kMsbShift) |
                static_cast<uint32_t>(header.type[1]));
            if (etherType < kMinimumEtherType)
            {
                return DataPathResult::InvalidEthernetFrame;
            }

            const bool isEapol = etherType == kEtherTypeEapol;
            // Open associations have no 802.1X transport or supplicant in
            // this driver. Only the separately parsed WPA2-PSK M2/M4 path
            // may serialize EAPOL; do not send arbitrary cleartext EAPOL
            // through the ordinary Open Ethernet-II data serializer.
            if (link.security == LinkSecurity::Open && isEapol)
            {
                return DataPathResult::InvalidEthernetFrame;
            }
            // This WPA2-PSK transport only emits pairwise M2/M4 to the
            // selected AP; never serialize EAPOL to a forged group or peer
            // destination through the public data-path API.
            if (link.security == LinkSecurity::Wpa2Ccmp && isEapol)
            {
                if (!sameMac(destination, link.bssid))
                {
                    return DataPathResult::InvalidAddress;
                }
                // The public Ethernet serializer must not become a generic
                // plaintext EAPOL injection path. Only the initial 4-way
                // exchange's supplicant replies have an explicit exception.
                // A parsed reply must occupy the entire supplied Ethernet
                // payload; any trailing bytes would be sent unauthenticated.
                KeyFrame key {};
                const size_t eapolBytes = ethernetBytes - kEthernetHeaderBytes;
                if (parseEapolKey(ethernet + kEthernetHeaderBytes, eapolBytes,
                                  key) != EapolResult::Ok ||
                    key.eapolLength != eapolBytes ||
                    (key.message != KeyMessage::Pairwise2 &&
                     key.message != KeyMessage::Pairwise4))
                {
                    return DataPathResult::InvalidEthernetFrame;
                }
                // M2 is only valid while awaiting key installation. M4 is
                // the final cleartext 4-way response AFTER MIC-checked M3
                // has installed pairwise and group keycache state.
                if (key.message == KeyMessage::Pairwise2 &&
                    link.pairwiseAndGroupKeysInstalled)
                {
                    return DataPathResult::NeedsCcmpEncryption;
                }
                if (key.message == KeyMessage::Pairwise4 &&
                    !link.pairwiseAndGroupKeysInstalled)
                {
                    return DataPathResult::MissingKeys;
                }
            }
            if (link.security == LinkSecurity::Wpa2Ccmp && !isEapol)
            {
                if (!link.pairwiseAndGroupKeysInstalled)
                {
                    return DataPathResult::MissingKeys;
                }
                // The secure-data TX path needs CCMP PN/IV/MIC and keycache
                // descriptor integration. Returning plaintext with Protected=1
                // would be unsafe.
                return DataPathResult::NeedsCcmpEncryption;
            }
            if (link.security != LinkSecurity::Wpa2Ccmp &&
                link.security != LinkSecurity::Open)
            {
                return DataPathResult::InvalidEthernetFrame;
            }

            const size_t payloadBytes = ethernetBytes - kEthernetHeaderBytes;
            // Leave room for the hardware FCS. No fragmentation is supported
            // here.
            if (payloadBytes >
                kMaximumMpduBytes - kDataHeaderBytes - kSnapBytes - kFcsBytes)
            {
                return DataPathResult::FrameTooLong;
            }
            const size_t written = kDataHeaderBytes + kSnapBytes + payloadBytes;
            if (capacity < written)
            {
                return DataPathResult::BufferTooSmall;
            }
            // Do not corrupt source identity, payload or output metadata
            // through forged aliases while preparing an on-air frame.
            if (overlaps(out, capacity, ethernet, ethernetBytes) ||
                overlaps(out, capacity, &link, sizeof(link)) ||
                overlaps(out, capacity, &result, sizeof(result)) ||
                overlaps(&result, sizeof(result), ethernet, ethernetBytes) ||
                overlaps(&result, sizeof(result), &link, sizeof(link)))
            {
                return DataPathResult::OverlappingBuffers;
            }

            // 0x0108: data subtype, ToDS=1, FromDS=0, no protection,
            // no fragments. Construct the entire fixed 802.11+LLC header
            // before copying it to caller-owned output, never by relying on
            // unchecked raw output offsets.
            StationTxHeader stagedHeader {};
            stagedHeader.control[0] = kDataFrame;
            stagedHeader.control[1] = kDataToDs;
            // addr1=AP receiver, addr2=station transmitter, addr3=final DA.
            __builtin_memcpy(&stagedHeader.receiver[0], &link.bssid.bytes[0],
                             sizeof(stagedHeader.receiver));
            __builtin_memcpy(&stagedHeader.transmitter[0],
                             &link.station.bytes[0],
                             sizeof(stagedHeader.transmitter));
            __builtin_memcpy(&stagedHeader.destination[0],
                             &destination.bytes[0],
                             sizeof(stagedHeader.destination));
            const auto sequenceControl = static_cast<uint16_t>(
                static_cast<uint32_t>(sequence & kSequenceMask)
                << kSequenceFragmentBits);
            stagedHeader.sequence[0] = static_cast<uint8_t>(sequenceControl);
            stagedHeader.sequence[1] =
                static_cast<uint8_t>(sequenceControl >> kMsbShift);
            // RFC 1042 SNAP, except 802.1H bridge-tunnel for AARP/IPX.
            stagedHeader.snap[0] = kSnapSap;
            stagedHeader.snap[1] = kSnapSap;
            stagedHeader.snap[2] = kSnapUnnumbered;
            stagedHeader.snap[kSnapOuiLastIndex] =
                (etherType == kEtherTypeAarp || etherType == kEtherTypeIpx)
                    ? kBridgeTunnelOui
                    : 0U;
            stagedHeader.snap[kSnapTypeHighIndex] = header.type[0];
            stagedHeader.snap[kSnapTypeLowIndex] = header.type[1];
            __builtin_memcpy(out, &stagedHeader, sizeof(stagedHeader));
            copyBytes(out + sizeof(stagedHeader),
                      ethernet + kEthernetHeaderBytes, payloadBytes);

            SerializedData staged {};
            staged.frameBytes = written;
            staged.onAirLengthIncludingFcs = written + kFcsBytes;
            staged.sequence = sequence & kSequenceMask;
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
            {
                return DataPathResult::OverlappingBuffers;
            }
            // An ordinary failed admission revokes stale borrowed RX payload.
            result = {};
            if (frame == nullptr)
            {
                return DataPathResult::NullBuffer;
            }
            // The selected station and the AP must be distinct; callers can
            // construct LinkContext without passing station association.
            if (!validStationMac(link.station) ||
                !physicalBssidValid(link.bssid) ||
                sameMac(link.station, link.bssid))
            {
                return DataPathResult::InvalidAddress;
            }
            if (!link.rfReady || !link.associated)
            {
                return DataPathResult::NotAssociated;
            }
            if (!link.channelPermitted)
            {
                return DataPathResult::CountryNotAuthorized;
            }
            // Revoke any stale borrowed MSDU if this Open association still
            // claims key installation from an incompatible WPA2 session.
            if (link.security == LinkSecurity::Open &&
                link.pairwiseAndGroupKeysInstalled)
            {
                return DataPathResult::InvalidSecurityState;
            }
            if (!fcsAndDmaValidated)
            {
                return DataPathResult::InvalidRxStatus;
            }
            Frame header {};
            if (parseFrame(frame, frameBytes, header) != Result::Ok)
            {
                return DataPathResult::MalformedFrame;
            }
            // Only infrastructure AP-to-station frames, not locally generated
            // frames or four-address WDS; other formats require explicit
            // support.
            if (header.type != FrameType::Data || header.toDs ||
                !header.fromDs || !sameMac(header.bssid, link.bssid))
            {
                return DataPathResult::NotFromAssociatedAccessPoint;
            }
            // FromDS address 3 is the originating Ethernet source, not the
            // access point. Never forward a forged group or zero source into
            // the native Ethernet interface, even with a valid AP receiver.
            if (!validStationMac(header.source))
            {
                return DataPathResult::InvalidAddress;
            }
            // Multicast/broadcast is accepted; unicast must address our
            // station.
            if ((header.destination.bytes[0] & 1U) == 0 &&
                !sameMac(header.destination, link.station))
            {
                return DataPathResult::NotForThisStation;
            }
            // Unprotected data is permitted only on open associations or EAPOL
            // during WPA2 key exchange. Ethernet type is determined *after*
            // validating RX.
            if (header.protectedFrame && !ccmpMicAndPnValidated)
            {
                return DataPathResult::UnverifiedDecryption;
            }
            Msdu parsed {};
            const Result decoded = decodeLlcData(frame, frameBytes, fcsIncluded,
                                                 ccmpMicAndPnValidated, parsed);
            if (decoded != Result::Ok)
            {
                return DataPathResult::UnsupportedFrame;
            }
            if (link.security == LinkSecurity::Wpa2Ccmp)
            {
                // WPA2-PSK pairwise handshake frames are addressed to this
                // station, never to an arbitrary multicast destination.
                if (parsed.etherType == kEtherTypeEapol)
                {
                    if (!sameMac(parsed.destination, link.station))
                    {
                        return DataPathResult::NotForThisStation;
                    }
                    // Only the selected BSSID is this limited WPA2-PSK
                    // station's authenticator. A different unicast Ethernet
                    // SA may be bridged by the AP, but must not inject M1/M3
                    // into the pairwise handshake. Ordinary data can retain
                    // a distinct wired/bridged Ethernet source.
                    if (!sameMac(parsed.source, link.bssid))
                    {
                        return DataPathResult::NotFromAssociatedAccessPoint;
                    }
                    // Even an affirmative caller-supplied MIC/PN trust bit
                    // cannot authorize a protected handshake packet before
                    // this selected link has actually installed its keys.
                    if (header.protectedFrame &&
                        !link.pairwiseAndGroupKeysInstalled)
                    {
                        return DataPathResult::UnverifiedDecryption;
                    }
                    // Cleartext EAPOL is reserved for initial M1/M3 before
                    // the PTK/GTK exists. After installation, an AP-origin
                    // EAPOL frame needs verified CCMP protection; accepting
                    // a plaintext rekey request would bypass the key port.
                    if (!header.protectedFrame &&
                        link.pairwiseAndGroupKeysInstalled)
                    {
                        return DataPathResult::UnverifiedDecryption;
                    }
                    // There is no reviewed post-install group-rekey path.
                    // A verified CCMP bit alone cannot make an arbitrary
                    // encrypted EAPOL packet an authorized engine action.
                    if (link.pairwiseAndGroupKeysInstalled)
                    {
                        return DataPathResult::UnsupportedFrame;
                    }
                    // The only pre-install plaintext exception is an exact
                    // AP-origin M1 or M3; malformed, group, supplicant-side
                    // or trailing EAPOL data must not enter the handshake.
                    KeyFrame key {};
                    if (parseEapolKey(parsed.payload, parsed.payloadLength,
                                      key) != EapolResult::Ok ||
                        key.eapolLength != parsed.payloadLength ||
                        (key.message != KeyMessage::Pairwise1 &&
                         key.message != KeyMessage::Pairwise3))
                    {
                        return DataPathResult::UnsupportedFrame;
                    }
                }
                if (parsed.etherType != kEtherTypeEapol)
                {
                    if (!link.pairwiseAndGroupKeysInstalled ||
                        !header.protectedFrame || !ccmpMicAndPnValidated)
                    {
                        return DataPathResult::UnverifiedDecryption;
                    }
                }
                else if (header.protectedFrame && !ccmpMicAndPnValidated)
                {
                    return DataPathResult::UnverifiedDecryption;
                }
            }
            else if (link.security == LinkSecurity::Open)
            {
                if (header.protectedFrame)
                {
                    return DataPathResult::UnverifiedDecryption;
                }
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
