// SPDX-License-Identifier: AGPL-3.0-only
// Portable WPA2-PSK cryptographic primitives. This is not an entropy source,
// keychain, negotiated RSN policy, CCMP packet engine or hardware key backend.
//
// The portable host suite verifies PBKDF2, PTK and MIC vectors, an RFC3394
// AES unwrap vector, and output alias guards. It is not a timing audit or build
// of the target macOS Tahoe kernel extension. No RF or DMA calls are made.
#ifndef SIMPLEATH_WIFI_WPA2_PRIMITIVES_HPP
#define SIMPLEATH_WIFI_WPA2_PRIMITIVES_HPP

#include "../Frames.hpp"
#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    namespace ieee80211
    {
        namespace crypto
        {
            constexpr size_t kPmkBytes = 32;
            constexpr size_t kNonceBytes = 32;
            constexpr size_t kPtkBytes = 48;
            constexpr size_t kAesKeyBytes = 16;

            enum class Error : uint8_t
            {
                Ok,
                InvalidArgument,
                InvalidPassword,
                InvalidSsid,
                BufferTooSmall,
                BadWrappedLength,
                KeyWrapIntegrityError,
            };

            // PBKDF2-HMAC-SHA1, 4096 rounds, 32-byte PMK. This permits WPA2 PSK
            // passphrases (8..63 bytes); raw 64-hex-digit PMKs belong to a
            // separate API.
            Error derivePmk(const uint8_t *passphrase, size_t passphraseLength,
                            const uint8_t *ssid, size_t ssidLength,
                            uint8_t outputPmk[kPmkBytes]);

            // WPA2-CCMP PRF-384 over ordered MAC addresses and nonces; 48-byte
            // PTK layout = KCK(16) || KEK(16) || TK(16). Never log/serialize
            // the output. Output must not overlap either MAC identity, the PMK
            // or either nonce.
            Error derivePtk(const uint8_t pmk[kPmkBytes], const Mac &ap,
                            const Mac &station,
                            const uint8_t aNonce[kNonceBytes],
                            const uint8_t sNonce[kNonceBytes],
                            uint8_t outputPtk[kPtkBytes]);

            // HMAC-SHA1-128 for WPA2 EAPOL-Key descriptor version 2.
            // Caller must supply the whole EAPOL frame with its MIC field
            // zeroed. The output must not overlap the KCK or signed bytes.
            Error calculateMic(const uint8_t kck[kAesKeyBytes],
                               const uint8_t *eapol, size_t frameBytes,
                               uint8_t outputMic[kAesKeyBytes]);

            // RFC3394 AES-128-Key-Unwrap. Bounds fixed to WPA2 EAPOL key-data
            // maximum of 512 bytes. Rejects integrity-check failure without
            // publishing plaintext. Wrapped data must be 24..512 bytes,
            // multiple of 8, and disjoint from out. The outputBytes
            // reference must not alias the KEK, ciphertext or output storage;
            // invalid aliases are rejected without modifying those bytes.
            Error unwrapKey(const uint8_t kek[kAesKeyBytes],
                            const uint8_t *wrapped, size_t wrappedBytes,
                            uint8_t *output, size_t outputCapacity,
                            size_t &outputBytes);

        } // namespace crypto
    } // namespace ieee80211
} // namespace simpleath

#endif
