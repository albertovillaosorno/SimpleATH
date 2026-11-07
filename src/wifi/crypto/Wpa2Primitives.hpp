// SPDX-License-Identifier: AGPL-3.0-only
// Portable WPA2-PSK cryptographic primitives. This is not an entropy source,
// keychain, negotiated RSN policy, CCMP packet engine or hardware key backend.
//
// These algorithms have not been built, run, vector-verified, or integrated
// with the target macOS Tahoe kernel. No RF or DMA calls are made.
#ifndef SIMPLEATH_WIFI_WPA2_PRIMITIVES_HPP
#define SIMPLEATH_WIFI_WPA2_PRIMITIVES_HPP

#include <stddef.h>
#include <stdint.h>
#include "../Frames.hpp"

namespace simpleath {
namespace ieee80211 {
namespace crypto {

enum class Error : uint8_t {
    Ok,
    InvalidArgument,
    InvalidPassword,
    InvalidSsid,
    BufferTooSmall,
    BadWrappedLength,
    KeyWrapIntegrityError
};

// PBKDF2-HMAC-SHA1, 4096 rounds, 32-byte PMK. This permits WPA2 PSK
// passphrases (8..63 bytes); raw 64-hex-digit PMKs belong to a separate API.
Error derivePmk(const uint8_t *passphrase, size_t passphraseLength,
                const uint8_t *ssid, size_t ssidLength,
                uint8_t outputPmk[32]);

// WPA2-CCMP PRF-384 over ordered MAC addresses and nonces; 48-byte PTK
// layout = KCK(16) || KEK(16) || TK(16). Never log/serialize the output.
Error derivePtk(const uint8_t pmk[32], const Mac &ap, const Mac &station,
                const uint8_t aNonce[32], const uint8_t sNonce[32],
                uint8_t outputPtk[48]);

// HMAC-SHA1-128 for WPA2 EAPOL-Key descriptor version 2.
// Caller must supply the whole EAPOL frame with its MIC field zeroed.
Error calculateMic(const uint8_t kck[16],
                   const uint8_t *eapol, size_t frameBytes,
                   uint8_t outputMic[16]);

// RFC3394 AES-128-Key-Unwrap. Bounds fixed to WPA2 EAPOL key-data maximum
// of 512 bytes. Rejects integrity-check failure without publishing plaintext.
// Wrapped data must be 24..512 bytes, multiple of 8, and disjoint from out.
Error unwrapKey(const uint8_t kek[16], const uint8_t *wrapped,
                size_t wrappedBytes, uint8_t *output,
                size_t outputCapacity, size_t &outputBytes);

} // namespace crypto
} // namespace ieee80211
} // namespace simpleath

#endif
