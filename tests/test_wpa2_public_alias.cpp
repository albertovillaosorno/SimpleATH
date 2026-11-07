// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Alberto Villa Osorno.
// Host-only regression for public WPA2 outputs: no radio, kernel or DMA.
#include "wifi/crypto/Wpa2Primitives.hpp"
#include <cstring>

namespace
{
    using namespace simpleath::ieee80211;
    using namespace simpleath::ieee80211::crypto;

    struct IdentityStorage
    {
            Mac ap;
            uint8_t remainder[48];
    };

    struct alignas(size_t) LengthStorage
    {
            size_t value;
            uint8_t remainder[48];
    };

    bool rejectIdentityAlias()
    {
        IdentityStorage storage {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}, {}};
        const IdentityStorage before = storage;
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        uint8_t pmk[32] {};
        uint8_t anonce[32] {};
        uint8_t snonce[32] {};
        anonce[0] = 1;
        snonce[0] = 2;
        if (derivePtk(pmk, storage.ap, station, anonce, snonce,
                      storage.ap.bytes) != Error::InvalidArgument ||
            std::memcmp(&storage, &before, sizeof(storage)) != 0)
            return false;

        IdentityStorage stationStorage {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa},
                                        {}};
        const IdentityStorage stationBefore = stationStorage;
        if (derivePtk(pmk, storage.ap, stationStorage.ap, anonce, snonce,
                      stationStorage.ap.bytes) != Error::InvalidArgument ||
            std::memcmp(&stationStorage, &stationBefore,
                        sizeof(stationStorage)) != 0)
            return false;
        uint8_t independentPtk[48] {};
        return derivePtk(pmk, storage.ap, station, anonce, snonce,
                         independentPtk) == Error::Ok;
    }

    bool rejectMicKeyAlias()
    {
        uint8_t kck[16] {};
        uint8_t eapol[99] {};
        for (size_t i = 0; i < sizeof(kck); ++i)
            kck[i] = static_cast<uint8_t>(i + 1);
        uint8_t original[sizeof(kck)] {};
        std::memcpy(original, kck, sizeof(kck));
        if (calculateMic(kck, eapol, sizeof(eapol), kck) !=
                Error::InvalidArgument ||
            std::memcmp(kck, original, sizeof(kck)) != 0)
            return false;
        uint8_t independent[16] {};
        return calculateMic(kck, eapol, sizeof(eapol), independent) ==
                   Error::Ok &&
               std::memcmp(kck, original, sizeof(kck)) == 0;
    }

    bool rejectLengthReferenceAliases()
    {
        uint8_t kek[16] {};
        uint8_t wrapped[24] {};
        uint8_t output[32] {};

        // Typed size_t storage is also the first bytes of the KEK argument.
        // A failure must not even reset that output-length reference.
        LengthStorage keyStorage {0x1122334455667788ull, {}};
        const LengthStorage keyBefore = keyStorage;
        const auto *keyBytes = reinterpret_cast<const uint8_t *>(&keyStorage);
        if (unwrapKey(keyBytes, wrapped, sizeof(wrapped), output,
                      sizeof(output),
                      keyStorage.value) != Error::InvalidArgument ||
            std::memcmp(&keyStorage, &keyBefore, sizeof(keyStorage)) != 0)
            return false;

        // The writable length reference may likewise be inside ciphertext.
        LengthStorage wrappedStorage {0x8877665544332211ull, {}};
        const LengthStorage wrappedBefore = wrappedStorage;
        const auto *wrappedBytes =
            reinterpret_cast<const uint8_t *>(&wrappedStorage);
        if (unwrapKey(kek, wrappedBytes, 24, output, sizeof(output),
                      wrappedStorage.value) != Error::InvalidArgument ||
            std::memcmp(&wrappedStorage, &wrappedBefore,
                        sizeof(wrappedStorage)) != 0)
            return false;

        // Nor may a result length erase a plaintext output before checking.
        LengthStorage plainStorage {0x0102030405060708ull, {}};
        const LengthStorage plainBefore = plainStorage;
        auto *plainBytes = reinterpret_cast<uint8_t *>(&plainStorage);
        return unwrapKey(kek, wrapped, sizeof(wrapped), plainBytes, 32,
                         plainStorage.value) == Error::InvalidArgument &&
               std::memcmp(&plainStorage, &plainBefore, sizeof(plainStorage)) ==
                   0;
    }

    bool derivePublishedPmkVector()
    {
        // IEEE 802.11 WPA2-PSK known answer: password / IEEE, 4096 rounds.
        const uint8_t password[] {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
        const uint8_t ssid[] {'I', 'E', 'E', 'E'};
        const uint8_t expected[32] {
            0xf4, 0x2c, 0x6f, 0xc5, 0x2d, 0xf0, 0xeb, 0xef, 0x9e, 0xbb, 0x4b,
            0x90, 0xb3, 0x8a, 0x5f, 0x90, 0x2e, 0x83, 0xfe, 0x1b, 0x13, 0x5a,
            0x70, 0xe2, 0x3a, 0xed, 0x76, 0x2e, 0x97, 0x10, 0xa1, 0x2e};
        uint8_t pmk[32] {};
        return derivePmk(password, sizeof(password), ssid, sizeof(ssid), pmk) ==
                   Error::Ok &&
               std::memcmp(pmk, expected, sizeof(expected)) == 0;
    }

    bool deriveReferencePtkVector()
    {
        // Python stdlib HMAC-SHA1 reference, independent of this C++ PRF:
        // HMAC(PMK, "Pairwise key expansion" || NUL || sorted IDs || counter).
        const uint8_t pmk[32] {0xf4, 0x2c, 0x6f, 0xc5, 0x2d, 0xf0, 0xeb, 0xef,
                               0x9e, 0xbb, 0x4b, 0x90, 0xb3, 0x8a, 0x5f, 0x90,
                               0x2e, 0x83, 0xfe, 0x1b, 0x13, 0x5a, 0x70, 0xe2,
                               0x3a, 0xed, 0x76, 0x2e, 0x97, 0x10, 0xa1, 0x2e};
        const Mac ap {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        uint8_t aNonce[32] {};
        uint8_t sNonce[32] {};
        for (size_t i = 0; i < sizeof(aNonce); ++i)
        {
            aNonce[i] = static_cast<uint8_t>(i);
            sNonce[i] = static_cast<uint8_t>(i + sizeof(aNonce));
        }
        const uint8_t expected[48] {
            0x54, 0xbf, 0xa1, 0x6e, 0xde, 0x33, 0x9e, 0x9b, 0xd5, 0x55,
            0x88, 0x3e, 0x57, 0xbd, 0x53, 0x93, 0x59, 0x18, 0xbd, 0xa2,
            0x3d, 0x31, 0x69, 0x3c, 0x38, 0x44, 0xf9, 0xb9, 0x2e, 0xf7,
            0x40, 0xc5, 0xc9, 0x98, 0x9f, 0x97, 0x53, 0x32, 0xcc, 0xa1,
            0x4d, 0x0f, 0xd7, 0xa8, 0xf6, 0xf4, 0x44, 0x8a};
        uint8_t ptk[48] {};
        return derivePtk(pmk, ap, station, aNonce, sNonce, ptk) == Error::Ok &&
               std::memcmp(ptk, expected, sizeof(expected)) == 0;
    }

    bool calculateReferenceMicVector()
    {
        // Independent Python HMAC-SHA1-128 over a synthetic 99-byte EAPOL
        // key frame with the 16-octet MIC field zeroed (octets 81..96).
        const uint8_t kck[16] {0x54, 0xbf, 0xa1, 0x6e, 0xde, 0x33, 0x9e, 0x9b,
                               0xd5, 0x55, 0x88, 0x3e, 0x57, 0xbd, 0x53, 0x93};
        const uint8_t expected[16] {0x43, 0x1e, 0xc9, 0xa1, 0x7e, 0x26,
                                    0x17, 0xe4, 0xa0, 0x76, 0x8f, 0xa0,
                                    0x43, 0xcb, 0xb9, 0x39};
        uint8_t eapol[99] {};
        for (size_t i = 0; i < sizeof(eapol); ++i)
            eapol[i] = static_cast<uint8_t>(i);
        for (size_t i = 81; i < 97; ++i)
            eapol[i] = 0;
        uint8_t mic[16] {};
        return calculateMic(kck, eapol, sizeof(eapol), mic) == Error::Ok &&
               std::memcmp(mic, expected, sizeof(expected)) == 0;
    }

    bool unwrapPublicRfc3394Vector()
    {
        // RFC 3394 section 4.1: 128-bit KEK, 128-bit key data.
        const uint8_t kek[16] {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                               0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
        const uint8_t ciphertext[24] {0x1f, 0xa6, 0x8b, 0x0a, 0x81, 0x12,
                                      0xb4, 0x47, 0xae, 0xf3, 0x4b, 0xd8,
                                      0xfb, 0x5a, 0x7b, 0x82, 0x9d, 0x3e,
                                      0x86, 0x23, 0x71, 0xd2, 0xcf, 0xe5};
        const uint8_t expected[16] {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                                    0xcc, 0xdd, 0xee, 0xff};
        uint8_t plaintext[16] {};
        size_t length = 99;
        if (unwrapKey(kek, ciphertext, sizeof(ciphertext), plaintext,
                      sizeof(plaintext), length) != Error::Ok ||
            length != sizeof(plaintext) ||
            std::memcmp(plaintext, expected, sizeof(expected)) != 0)
            return false;

        // Mutating a valid wrap must not publish unverified key bytes.
        uint8_t corrupted[sizeof(ciphertext)] {};
        std::memcpy(corrupted, ciphertext, sizeof(corrupted));
        corrupted[0] ^= 1;
        uint8_t sentinel[sizeof(plaintext)] {};
        std::memset(sentinel, 0xa5, sizeof(sentinel));
        uint8_t expectedSentinel[sizeof(sentinel)] {};
        std::memcpy(expectedSentinel, sentinel, sizeof(sentinel));
        length = 99;
        return unwrapKey(kek, corrupted, sizeof(corrupted), sentinel,
                         sizeof(sentinel),
                         length) == Error::KeyWrapIntegrityError &&
               length == 0 &&
               std::memcmp(sentinel, expectedSentinel, sizeof(sentinel)) == 0;
    }
} // namespace

int main()
{
    if (!rejectIdentityAlias())
        return 1;
    if (!rejectMicKeyAlias())
        return 2;
    if (!rejectLengthReferenceAliases())
        return 3;
    if (!unwrapPublicRfc3394Vector())
        return 4;
    if (!derivePublishedPmkVector())
        return 5;
    if (!deriveReferencePtkVector())
        return 6;
    if (!calculateReferenceMicVector())
        return 7;
    return 0;
}
