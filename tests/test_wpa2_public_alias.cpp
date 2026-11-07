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
    return 0;
}
