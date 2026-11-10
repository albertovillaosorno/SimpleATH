#include "DataPath.hpp"
#include "Eapol.hpp"
#include "crypto/Ccmp.hpp"
#include "wifi/DataFrames.hpp"
#include "wifi/Frames.hpp"
#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    namespace ieee80211
    {
        namespace
        {
            constexpr uint16_t kEtherTypeEapol = 0x888eU;
            constexpr uint16_t kGroup2KeyInformation = 0x0302U;
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
            constexpr uint16_t kGroup1CcmpKeyLength = 16U;
            constexpr uint16_t kGroup1MinimumKeyDataBytes = 24U;

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

            const uint8_t *byteAt(const uint8_t *base, size_t offset)
            {
                const uintptr_t address = pointerAddress(base) + offset;
                const uint8_t *result = nullptr;
                __builtin_memcpy(static_cast<void *>(&result), &address,
                                 sizeof(result));
                return result;
            }

            uint8_t *writableByteAt(uintptr_t baseAddress, size_t offset)
            {
                const uintptr_t address = baseAddress + offset;
                uint8_t *result = nullptr;
                __builtin_memcpy(static_cast<void *>(&result), &address,
                                 sizeof(result));
                return result;
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

        namespace
        {
            struct StationTxRequest
            {
                    const LinkContext *link;
                    const uint8_t *ethernet;
                    size_t ethernetBytes;
                    uint16_t sequence;
                    uint8_t *out;
                    size_t capacity;
                    SerializedData *result;
                    bool protectedWpa2;
            };
        } // namespace

        static DataPathResult validateStationTxLink(const LinkContext &link,
                                                    bool protectedWpa2)
        {
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
            if (protectedWpa2 && (link.security != LinkSecurity::Wpa2Ccmp ||
                                  !link.pairwiseAndGroupKeysInstalled))
            {
                return DataPathResult::InvalidSecurityState;
            }
            if (link.security == LinkSecurity::Open &&
                link.pairwiseAndGroupKeysInstalled)
            {
                return DataPathResult::InvalidSecurityState;
            }
            return DataPathResult::Ok;
        }

        static DataPathResult
        validateStationTxEapol(const StationTxRequest &request,
                               const Mac &destination)
        {
            const auto &link = *request.link;
            const auto *ethernet = request.ethernet;
            const size_t ethernetBytes = request.ethernetBytes;
            const bool protectedWpa2 = request.protectedWpa2;
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
            if (parseEapolKey(byteAt(ethernet, kEthernetHeaderBytes),
                              eapolBytes, key) != EapolResult::Ok ||
                key.eapolLength != eapolBytes ||
                (protectedWpa2
                     ? (key.message != KeyMessage::Group2 ||
                        key.keyInformation != kGroup2KeyInformation ||
                        key.keyLength != 0U || key.keyDataLength != 0U)
                     : (key.message != KeyMessage::Pairwise2 &&
                        key.message != KeyMessage::Pairwise4)))
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
            return DataPathResult::Ok;
        }

        static DataPathResult
        validateStationTxPayload(const StationTxRequest &request,
                                 const Mac &destination, uint16_t etherType)
        {
            const auto &link = *request.link;
            const bool protectedWpa2 = request.protectedWpa2;
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
                return validateStationTxEapol(request, destination);
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
                if (!protectedWpa2)
                {
                    return DataPathResult::NeedsCcmpEncryption;
                }
            }
            if (link.security != LinkSecurity::Wpa2Ccmp &&
                link.security != LinkSecurity::Open)
            {
                return DataPathResult::InvalidEthernetFrame;
            }

            return DataPathResult::Ok;
        }

        static DataPathResult
        prepareStationTxFrame(const StationTxRequest &request)
        {
            const auto &link = *request.link;
            const auto *ethernet = request.ethernet;
            const size_t ethernetBytes = request.ethernetBytes;
            const uint16_t sequence = request.sequence;
            auto *out = request.out;
            const size_t capacity = request.capacity;
            auto &result = *request.result;
            const bool protectedWpa2 = request.protectedWpa2;
            // Fail without modifying output or result on any validation
            // failure.
            if ((out == nullptr) || (ethernet == nullptr))
            {
                return DataPathResult::NullBuffer;
            }
            const DataPathResult authorized =
                validateStationTxLink(link, protectedWpa2);
            if (authorized != DataPathResult::Ok)
            {
                return authorized;
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
            const DataPathResult authorizedPayload =
                validateStationTxPayload(request, destination, etherType);
            if (authorizedPayload != DataPathResult::Ok)
            {
                return authorizedPayload;
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
            copyBytes(writableByteAt(pointerAddress(out), sizeof(stagedHeader)),
                      byteAt(ethernet, kEthernetHeaderBytes), payloadBytes);

            SerializedData staged {};
            staged.frameBytes = written;
            staged.onAirLengthIncludingFcs = written + kFcsBytes;
            staged.sequence = sequence & kSequenceMask;
            staged.etherType = etherType;
            staged.needsCcmp = protectedWpa2;
            staged.isEapol = isEapol;
            result = staged;
            return DataPathResult::Ok;
        }

        DataPathResult prepareStationTx(const LinkContext &link,
                                        const uint8_t *ethernet,
                                        size_t ethernetBytes, uint16_t sequence,
                                        uint8_t *out, size_t capacity,
                                        SerializedData &result)
        {
            return prepareStationTxFrame({
                &link,
                ethernet,
                ethernetBytes,
                sequence,
                out,
                capacity,
                &result,
                false,
            });
        }

        DataPathResult prepareProtectedStationTx(
            const LinkContext &link, const uint8_t *ethernet,
            size_t ethernetBytes, uint16_t sequence,
            crypto::CcmpSession &pairwise, uint64_t epoch, uint8_t *scratch,
            size_t scratchCapacity, uint8_t *out, size_t capacity,
            SerializedData &result)
        {
            if (ethernet == nullptr || scratch == nullptr || out == nullptr)
            {
                return DataPathResult::NullBuffer;
            }
            if (overlaps(out, capacity, ethernet, ethernetBytes) ||
                overlaps(out, capacity, scratch, scratchCapacity) ||
                overlaps(out, capacity, &link, sizeof(link)) ||
                overlaps(out, capacity, &result, sizeof(result)) ||
                overlaps(scratch, scratchCapacity, &pairwise,
                         sizeof(pairwise)) ||
                overlaps(out, capacity, &pairwise, sizeof(pairwise)) ||
                overlaps(&result, sizeof(result), &pairwise,
                         sizeof(pairwise)) ||
                overlaps(scratch, scratchCapacity, ethernet, ethernetBytes) ||
                overlaps(scratch, scratchCapacity, &link, sizeof(link)) ||
                overlaps(&result, sizeof(result), scratch, scratchCapacity) ||
                overlaps(&result, sizeof(result), ethernet, ethernetBytes) ||
                overlaps(&result, sizeof(result), &link, sizeof(link)))
            {
                return DataPathResult::OverlappingBuffers;
            }
            if (!pairwise.installed())
            {
                return DataPathResult::MissingKeys;
            }
            SerializedData staged {};
            const auto prepared = prepareStationTxFrame({
                &link,
                ethernet,
                ethernetBytes,
                sequence,
                scratch,
                scratchCapacity,
                &staged,
                true,
            });
            if (prepared != DataPathResult::Ok)
            {
                return prepared;
            }
            constexpr size_t kCcmpOverheadBytes = 16U;
            if (staged.frameBytes >
                kMaximumMpduBytes - kFcsBytes - kCcmpOverheadBytes)
            {
                volatile uint8_t *const clear = scratch;
                for (size_t i = 0; i < staged.frameBytes; ++i)
                {
                    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
                    clear[i] = 0;
                }
                return DataPathResult::FrameTooLong;
            }
            size_t written = 0;
            const auto encrypted = pairwise.protect(
                epoch, scratch, staged.frameBytes, out, capacity, written);
            volatile uint8_t *const clear = scratch;
            for (size_t i = 0; i < staged.frameBytes; ++i)
            {
                // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
                clear[i] = 0;
            }
            if (encrypted != crypto::CcmpResult::Ok)
            {
                return encrypted == crypto::CcmpResult::BufferTooSmall
                           ? DataPathResult::BufferTooSmall
                           : DataPathResult::EncryptionFailed;
            }
            staged.frameBytes = written;
            staged.onAirLengthIncludingFcs = written + kFcsBytes;
            staged.needsCcmp = false;
            result = staged;
            return DataPathResult::Ok;
        }

        static bool aliasesProtectedRxIo(const LinkContext &link,
                                         const uint8_t *encrypted,
                                         size_t encryptedBytes,
                                         crypto::CcmpSession &receive,
                                         const uint8_t *scratch,
                                         size_t scratchCapacity, Msdu &result)
        {
            return overlaps(&result, sizeof(result), encrypted,
                            encryptedBytes) ||
                   overlaps(&result, sizeof(result), scratch,
                            scratchCapacity) ||
                   overlaps(&result, sizeof(result), &link, sizeof(link)) ||
                   overlaps(&result, sizeof(result), &receive,
                            sizeof(receive)) ||
                   overlaps(scratch, scratchCapacity, encrypted,
                            encryptedBytes) ||
                   overlaps(scratch, scratchCapacity, &link, sizeof(link)) ||
                   overlaps(scratch, scratchCapacity, &receive,
                            sizeof(receive)) ||
                   overlaps(encrypted, encryptedBytes, &link, sizeof(link)) ||
                   overlaps(encrypted, encryptedBytes, &receive,
                            sizeof(receive));
        }

        static DataPathResult protectedRxLinkStatus(const LinkContext &link,
                                                    bool dmaValidated,
                                                    bool sessionInstalled)
        {
            if (!dmaValidated)
            {
                return DataPathResult::InvalidRxStatus;
            }
            if (link.security != LinkSecurity::Wpa2Ccmp ||
                !validStationMac(link.station) ||
                !physicalBssidValid(link.bssid) ||
                sameMac(link.station, link.bssid))
            {
                return DataPathResult::InvalidSecurityState;
            }
            if (!link.associated || !link.rfReady)
            {
                return DataPathResult::NotAssociated;
            }
            if (!link.channelPermitted)
            {
                return DataPathResult::CountryNotAuthorized;
            }
            return link.pairwiseAndGroupKeysInstalled && sessionInstalled
                       ? DataPathResult::Ok
                       : DataPathResult::MissingKeys;
        }

        static DataPathResult
        protectedRxCryptoFailure(crypto::CcmpResult authenticated)
        {
            if (authenticated == crypto::CcmpResult::BufferTooSmall)
            {
                return DataPathResult::BufferTooSmall;
            }
            return authenticated == crypto::CcmpResult::MissingKey
                       ? DataPathResult::MissingKeys
                       : DataPathResult::UnverifiedDecryption;
        }

        DataPathResult inspectProtectedStationRx(
            const LinkContext &link, const uint8_t *encrypted,
            size_t encryptedBytes, bool containsFcs, bool fcsAndDmaValidated,
            crypto::CcmpSession &receive, uint64_t epoch, uint8_t *scratch,
            size_t scratchCapacity, Msdu &result)
        {
            // Reject overlaps before clearing the result or writing scratch:
            // all are caller-owned, and receive retains secret key state.
            if (aliasesProtectedRxIo(link, encrypted, encryptedBytes, receive,
                                     scratch, scratchCapacity, result))
            {
                return DataPathResult::OverlappingBuffers;
            }
            result = {};
            if (encrypted == nullptr || scratch == nullptr)
            {
                return DataPathResult::NullBuffer;
            }
            const auto linkStatus = protectedRxLinkStatus(
                link, fcsAndDmaValidated, receive.installed());
            if (linkStatus != DataPathResult::Ok)
            {
                return linkStatus;
            }
            if (encryptedBytes < (containsFcs ? kFcsBytes : 0U))
            {
                return DataPathResult::MalformedFrame;
            }
            const size_t mpduBytes =
                encryptedBytes - (containsFcs ? kFcsBytes : 0U);
            Frame header {};
            if (parseFrame(encrypted, mpduBytes, header) != Result::Ok ||
                header.type != FrameType::Data || !header.protectedFrame)
            {
                return DataPathResult::MalformedFrame;
            }
            if (header.toDs || !header.fromDs ||
                !sameMac(header.bssid, link.bssid) ||
                !validStationMac(header.source))
            {
                return DataPathResult::NotFromAssociatedAccessPoint;
            }
            const bool group = (header.destination.bytes[0] & 1U) != 0U;
            if (!group && !sameMac(header.destination, link.station))
            {
                return DataPathResult::NotForThisStation;
            }
            // Check the wire key ID only after verifying the CCMP IV span.
            // A forged group MPDU must not use the pairwise key and vice
            // versa; unprotect independently checks the selected key ID/MIC.
            constexpr size_t kCcmpExtIvBytes = 8U;
            constexpr size_t kCcmpMicBytes = 8U;
            constexpr uint8_t kKeyIdShift = 6U;
            if (mpduBytes <
                header.headerLength + kCcmpExtIvBytes + kCcmpMicBytes + 1U)
            {
                return DataPathResult::MalformedFrame;
            }
            uint8_t iv[4] {};
            __builtin_memcpy(&iv[0], byteAt(encrypted, header.headerLength),
                             sizeof(iv));
            const auto keyId = static_cast<uint8_t>(iv[3] >> kKeyIdShift);
            if ((group && keyId == 0U) || (!group && keyId != 0U))
            {
                return DataPathResult::UnverifiedDecryption;
            }
            size_t plainBytes = 0;
            const auto authenticated =
                receive.unprotect(epoch, encrypted, mpduBytes, scratch,
                                  scratchCapacity, plainBytes);
            if (authenticated != crypto::CcmpResult::Ok)
            {
                return protectedRxCryptoFailure(authenticated);
            }
            // CcmpSession intentionally clears the encrypted wire Protected
            // bit on its plaintext output. Restore the authenticated bit on
            // our private plaintext header for the existing RX admission
            // contract; this is NEVER done before CCMP MIC/PN acceptance.
            constexpr size_t kControlFlagsOffset = 1U;
            constexpr uint8_t kProtectedFrameBit = 0x40U;
            // The validated fixed header guarantees this 1-byte writable span.
            // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            scratch[kControlFlagsOffset] |= kProtectedFrameBit;
            const auto admitted = inspectStationRx(link, scratch, plainBytes,
                                                   false, true, true, result);
            if (admitted != DataPathResult::Ok)
            {
                volatile uint8_t *const clear = scratch;
                for (size_t i = 0; i < plainBytes; ++i)
                {
                    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
                    clear[i] = 0;
                }
            }
            return admitted;
        }

        static DataPathResult validateStationRxEapol(const LinkContext &link,
                                                     const Frame &header,
                                                     const Msdu &parsed,
                                                     bool ccmpMicAndPnValidated)
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
            if (header.protectedFrame && !link.pairwiseAndGroupKeysInstalled)
            {
                return DataPathResult::UnverifiedDecryption;
            }
            // Cleartext EAPOL is reserved for initial M1/M3 before
            // the PTK/GTK exists. After installation, an AP-origin
            // EAPOL frame needs verified CCMP protection; accepting
            // a plaintext rekey request would bypass the key port.
            if (!header.protectedFrame && link.pairwiseAndGroupKeysInstalled)
            {
                return DataPathResult::UnverifiedDecryption;
            }
            // EAPOL is never a generic writable network payload.
            // Permit post-install Group1 only after this same-link
            // CCMP RX has independently verified MIC/PN and the owner
            // has removed the CCMP IV/MIC before passing plaintext.
            // Wpa2Supplicant still must authenticate the EAPOL MIC,
            // replay floor and GTK before returning Group2.
            KeyFrame key {};
            if (parseEapolKey(parsed.payload, parsed.payloadLength, key) !=
                    EapolResult::Ok ||
                key.eapolLength != parsed.payloadLength)
            {
                return DataPathResult::UnsupportedFrame;
            }
            if (link.pairwiseAndGroupKeysInstalled)
            {
                constexpr uint16_t kGroup1KeyInformation = 0x1382U;
                if (!header.protectedFrame || !ccmpMicAndPnValidated ||
                    key.message != KeyMessage::Group1 ||
                    key.keyInformation != kGroup1KeyInformation ||
                    key.keyLength != kGroup1CcmpKeyLength ||
                    key.keyDataLength < kGroup1MinimumKeyDataBytes)
                {
                    return DataPathResult::UnsupportedFrame;
                }
            }
            else if (key.message != KeyMessage::Pairwise1 &&
                     key.message != KeyMessage::Pairwise3)
            {
                // Before keys exist, only cleartext AP M1/M3 is valid.
                return DataPathResult::UnsupportedFrame;
            }
            return DataPathResult::Ok;
        }

        static DataPathResult
        validateStationRxSecurity(const LinkContext &link, const Frame &header,
                                  const Msdu &parsed,
                                  bool ccmpMicAndPnValidated)
        {
            if (link.security == LinkSecurity::Wpa2Ccmp)
            {
                // WPA2-PSK pairwise handshake frames are addressed to this
                // station, never to an arbitrary multicast destination.
                if (parsed.etherType == kEtherTypeEapol)
                {
                    const DataPathResult eapol = validateStationRxEapol(
                        link, header, parsed, ccmpMicAndPnValidated);
                    if (eapol != DataPathResult::Ok)
                    {
                        return eapol;
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
            const DataPathResult authorized = validateStationRxSecurity(
                link, header, parsed, ccmpMicAndPnValidated);
            if (authorized != DataPathResult::Ok)
            {
                return authorized;
            }
            result = parsed;
            return DataPathResult::Ok;
        }

    } // namespace ieee80211
} // namespace simpleath
