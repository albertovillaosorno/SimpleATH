// SPDX-License-Identifier: GPL-2.0-only
// Safe extraction of RFC 1042 LLC/SNAP payload from 802.11 data frames.
// This decoder does not perform encryption, decryption, or packet delivery.
#ifndef SIMPLEATH_WIFI_DATA_FRAMES_HPP
#define SIMPLEATH_WIFI_DATA_FRAMES_HPP

#include "Frames.hpp"

namespace simpleath
{
    namespace ieee80211
    {

        struct Msdu
        {
                Mac destination;
                Mac source;
                uint16_t etherType;
                const uint8_t *payload;
                size_t payloadLength;
                bool protectedFrame;
                bool qosFrame;
        };

        // A protected frame may be parsed only when the platform backend has
        // already verified decryption, replay/PN and MIC integrity, with no
        // hardware key miss. Crypto headers/trailers must already have been
        // removed, leaving plaintext LLC immediately after the 802.11 header.
        // AARP/IPX require bridge-tunnel SNAP OUI 00:00:f8; all other
        // Ethernet-II types, including EAPOL, require RFC 1042 OUI 00:00:00.
        // Input remains owned by the caller. A-MSDU aggregation, CF variants
        // and fragmented MSDUs are deliberately rejected. On ordinary error
        // the output is zeroed, including its borrowed payload pointer. An
        // output overlapping the frame returns OverlappingBuffers untouched.
        Result decodeLlcData(const uint8_t *frame, size_t frameBytes,
                             bool containsFcs, bool verifiedDecryptionAndMic,
                             Msdu &out);

        // Ethernet-II packet handoff into a native OS-owned receive pool.
        // Caller must first prove DMA/FCS, station association, destination,
        // duplicate suppression and, for protected frames, CCMP MIC/replay.
        // This routine only copies an already accepted borrowed MSDU; it
        // neither authorizes its security state nor retains its payload.
        // On ordinary errors written is cleared; aliases are rejected before
        // any output mutation. Never call with a DMA lifetime that expired.
        Result encodeReceivedEthernet(const Msdu &msdu, uint8_t *out,
                                      size_t capacity, size_t &written);

    } // namespace ieee80211
} // namespace simpleath
#endif
