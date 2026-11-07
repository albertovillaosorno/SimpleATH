// SPDX-License-Identifier: AGPL-3.0-only
// Safe extraction of RFC 1042 LLC/SNAP payload from 802.11 data frames.
// This decoder does not perform encryption, decryption, or packet delivery.
#ifndef SIMPLEATH_WIFI_DATA_FRAMES_HPP
#define SIMPLEATH_WIFI_DATA_FRAMES_HPP

#include "Frames.hpp"

namespace simpleath {
namespace ieee80211 {

struct Msdu {
    Mac destination;
    Mac source;
    uint16_t etherType;
    const uint8_t *payload;
    size_t payloadLength;
    bool protectedFrame;
    bool qosFrame;
};

// A protected frame may be parsed only when the platform backend has already
// verified decryption, replay/PN and MIC integrity, with no hardware key miss.
// Crypto headers/trailers must already have been removed, leaving plaintext
// LLC immediately after the 802.11 header. Input remains owned by the caller.
// A-MSDU aggregation and fragmented MSDUs are deliberately rejected.
Result decodeLlcData(const uint8_t *frame, size_t frameBytes,
                     bool containsFcs, bool verifiedDecryptionAndMic,
                     Msdu &out);

} // namespace ieee80211
} // namespace simpleath
#endif
