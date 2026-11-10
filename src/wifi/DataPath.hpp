// SPDX-License-Identifier: AGPL-3.0-only
// Infrastructure-station 802.11 data path framing (RFC 1042 LLC/SNAP).
// NO RF transmission, packet encryption, PCI DMA, or macOS network interface.
#ifndef SIMPLEATH_WIFI_DATA_PATH_HPP
#define SIMPLEATH_WIFI_DATA_PATH_HPP

#include "DataFrames.hpp"

namespace simpleath
{
    namespace ieee80211
    {
        namespace crypto
        {
            class CcmpSession;
        }

        enum class DataPathResult : uint8_t
        {
            Ok,
            NullBuffer,
            InvalidAddress,
            InvalidEthernetFrame,
            FrameTooLong,
            BufferTooSmall,
            OverlappingBuffers,
            RadioNotReady,
            NotAssociated,
            CountryNotAuthorized,
            MissingKeys,
            NeedsCcmpEncryption,
            NotFromAssociatedAccessPoint,
            NotForThisStation,
            InvalidRxStatus,
            UnverifiedDecryption,
            MalformedFrame,
            UnsupportedFrame,
            InvalidSecurityState,
            EncryptionFailed,
        };

        enum class LinkSecurity : uint8_t
        {
            Open,
            Wpa2Ccmp,
        };

        // A native macOS wireless interface must supply these values from the
        // actual association, PHY, regulatory and keycache state. Never set
        // flags to true merely because a descriptor or management frame could
        // be serialized.
        struct LinkContext
        {
                Mac station;
                Mac bssid;
                LinkSecurity security;
                bool associated;
                bool rfReady;
                bool channelPermitted;
                bool pairwiseAndGroupKeysInstalled;
        };

        struct SerializedData
        {
                size_t frameBytes;
                size_t onAirLengthIncludingFcs;
                uint16_t sequence;
                uint16_t etherType;
                bool needsCcmp;
                bool isEapol;
        };

        // Serialize one Ethernet-II MSDU to an unprotected 802.11 ToDS data
        // frame. WPA2 non-EAPOL traffic requires a separately implemented CCMP
        // path and will fail closed until that exists. Only a complete parsed
        // WPA2 EAPOL M2 before key install or M4 after key install is allowed,
        // and it must address the selected BSSID, never a group or peer.
        // The result has NO FCS;
        // hardware would append it only after its PHY/crypto TX path is
        // properly implemented. This routine NEVER submits a packet to the
        // device. Input, link and output/result storage must be disjoint;
        // aliases are rejected before any output is modified. An Open link
        // must not retain a WPA2 key-installed claim from a previous session.
        DataPathResult prepareStationTx(const LinkContext &link,
                                        const uint8_t *ethernet,
                                        size_t ethernetBytes, uint16_t sequence,
                                        uint8_t *out, size_t capacity,
                                        SerializedData &result);

        // Serialize an associated WPA2 Ethernet-II MSDU and encrypt it with
        // the installed pairwise CCMP key/PN epoch before exposing any output.
        // Accepts ordinary non-EAPOL data or an exact MIC-authenticated
        // supplicant Group2 EAPOL reply; NEVER permits M2/M4 to be encrypted
        // through this path or Group2 to be sent through prepareStationTx.
        // The native key owner must bind CCMP to this association, use a
        // fresh same-epoch TK/PN state, and gate TX on real RF/TPC authority.
        // scratch is caller-owned disjoint MPDU storage, cleared after use.
        // Failed encryption leaves output, result and old TX PN untouched.
        DataPathResult prepareProtectedStationTx(
            const LinkContext &link, const uint8_t *ethernet,
            size_t ethernetBytes, uint16_t sequence,
            crypto::CcmpSession &pairwise, uint64_t epoch, uint8_t *scratch,
            size_t scratchCapacity, uint8_t *out, size_t capacity,
            SerializedData &result);

        // Gate a decoded 802.11 MSDU before it is ever delivered into a native
        // network interface. The caller must have checked the EDMA RX status,
        // FCS and decrypted integrity/packet number using a real hardware
        // backend. Association addresses must be valid; WPA2-PSK EAPOL
        // handshake traffic must be unicast to this station. Only a complete
        // parsed AP-side M1/M3 is accepted as cleartext before key install.
        // Post-install EAPOL is limited to a complete AP-origin protected
        // Group1 after an independently validated same-link CCMP MIC/PN;
        // the supplicant must separately authenticate its EAPOL MIC/replay.
        // No other protected/cleartext EAPOL is admitted. On error,
        // output is zeroed, including its borrowed payload pointer. A result
        // overlapping the link or RX frame returns OverlappingBuffers without
        // modifying the aliased memory. Open links with a key-installed
        // claim fail closed and revoke stale RX results.
        DataPathResult inspectStationRx(const LinkContext &link,
                                        const uint8_t *ieeeFrame,
                                        size_t ieeeFrameBytes, bool fcsIncluded,
                                        bool fcsAndDmaValidated,
                                        bool ccmpMicAndPnValidated,
                                        Msdu &result);

    } // namespace ieee80211
} // namespace simpleath
#endif
