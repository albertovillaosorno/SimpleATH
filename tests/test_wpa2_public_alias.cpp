// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Alberto Villa Osorno.
// Host-only regression for public WPA2 outputs: no radio, kernel or DMA.
#include "wifi/Frames.hpp"
#include "wifi/crypto/Wpa2Primitives.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>

namespace
{
    using namespace simpleath::ieee80211;
    using namespace simpleath::ieee80211::crypto;

    constexpr size_t kPmkBytes = 32U;
    constexpr size_t kPtkBytes = 48U;
    constexpr size_t kMicBytes = 16U;
    constexpr size_t kKekBytes = 16U;
    constexpr size_t kWrappedBytes = 24U;
    constexpr size_t kEapolBytes = 99U;
    constexpr int kPublishedPmkFailed = 5;
    constexpr int kReferencePtkFailed = 6;
    constexpr int kReferenceMicFailed = 7;
    constexpr int kSameIdentityFailed = 8;
    constexpr size_t kPasswordBytes = 8U;
    constexpr size_t kSsidBytes = 4U;
    constexpr size_t kMicFieldStart = 81U;
    constexpr size_t kMicFieldEnd = 97U;
    constexpr uint8_t kSentinel = 0xa5U;
    constexpr uint64_t kKeyStorageValue = 0x1122334455667788ULL;
    constexpr uint64_t kWrappedStorageValue = 0x8877665544332211ULL;
    constexpr uint64_t kPlainStorageValue = 0x0102030405060708ULL;
    constexpr Mac kAp {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
    constexpr Mac kStation {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};

    struct IdentityStorage
    {
            Mac ap;
            std::array<uint8_t, kPtkBytes> remainder;
    };

    bool rejectIdentityAlias()
    {
        IdentityStorage storage {kAp, {}};
        const IdentityStorage before = storage;
        const Mac station = kStation;
        std::array<uint8_t, kPmkBytes> pmk {};
        std::array<uint8_t, kPmkBytes> anonce {};
        std::array<uint8_t, kPmkBytes> snonce {};
        anonce.at(0) = 1;
        snonce.at(0) = 2;
        if (derivePtk(pmk.data(), storage.ap, station, anonce.data(),
                      snonce.data(),
                      &storage.ap.bytes[0]) != Error::InvalidArgument ||
            std::memcmp(&storage, &before, sizeof(storage)) != 0)
        {
            return false;
        }

        IdentityStorage stationStorage {kStation, {}};
        const IdentityStorage stationBefore = stationStorage;
        if (derivePtk(pmk.data(), storage.ap, stationStorage.ap, anonce.data(),
                      snonce.data(),
                      &stationStorage.ap.bytes[0]) != Error::InvalidArgument ||
            std::memcmp(&stationStorage, &stationBefore,
                        sizeof(stationStorage)) != 0)
        {
            return false;
        }
        std::array<uint8_t, kPtkBytes> independentPtk {};
        return derivePtk(pmk.data(), storage.ap, station, anonce.data(),
                         snonce.data(), independentPtk.data()) == Error::Ok;
    }

    bool rejectSamePtkIdentity()
    {
        // A standalone PTK request must not derive traffic keys for a
        // self-authenticating AP/station pair, even with two valid unicast
        // MACs and distinct nonces. Rejection leaves old output untouched.
        const Mac identity = kAp;
        std::array<uint8_t, kPmkBytes> pmk {};
        std::array<uint8_t, kPmkBytes> anonce {};
        std::array<uint8_t, kPmkBytes> snonce {};
        anonce.at(0) = 1;
        snonce.at(0) = 2;
        std::array<uint8_t, kPtkBytes> output {};
        std::memset(output.data(), kSentinel, output.size());
        std::array<uint8_t, output.size()> before {};
        std::memset(before.data(), kSentinel, before.size());
        return derivePtk(pmk.data(), identity, identity, anonce.data(),
                         snonce.data(),
                         output.data()) == Error::InvalidArgument &&
               std::memcmp(output.data(), before.data(), output.size()) == 0;
    }

    bool rejectMicKeyAlias()
    {
        std::array<uint8_t, kMicBytes> kck {};
        std::array<uint8_t, kEapolBytes> eapol {};
        for (size_t i = 0; i < kck.size(); ++i)
        {
            kck.at(i) = static_cast<uint8_t>(i + 1);
        }
        std::array<uint8_t, kck.size()> original {};
        std::memcpy(original.data(), kck.data(), kck.size());
        if (calculateMic(kck.data(), eapol.data(), eapol.size(), kck.data()) !=
                Error::InvalidArgument ||
            std::memcmp(kck.data(), original.data(), kck.size()) != 0)
        {
            return false;
        }
        std::array<uint8_t, kMicBytes> independent {};
        return calculateMic(kck.data(), eapol.data(), eapol.size(),
                            independent.data()) == Error::Ok &&
               std::memcmp(kck.data(), original.data(), kck.size()) == 0;
    }

    bool rejectLengthReferenceAliases()
    {
        std::array<uint8_t, kKekBytes> kek {};
        std::array<uint8_t, kWrappedBytes> wrapped {};
        std::array<uint8_t, kPmkBytes> output {};

        // A suitably aligned byte array provides storage for a live size_t.
        // The same bytes are deliberately passed as a KEK input, so rejected
        // aliasing must preserve even the caller's result-length reference.
        alignas(size_t) std::array<uint8_t, kPtkBytes> keyStorage {};
        size_t &keyLength = *::new(keyStorage.data()) size_t {kKeyStorageValue};
        const auto keyBefore = keyStorage;
        if (unwrapKey(keyStorage.data(), wrapped.data(), wrapped.size(),
                      output.data(), output.size(),
                      keyLength) != Error::InvalidArgument ||
            keyStorage != keyBefore)
        {
            return false;
        }

        // The writable length reference may be within the ciphertext.
        alignas(size_t) std::array<uint8_t, kPtkBytes> wrappedStorage {};
        size_t &wrappedLength =
            *::new(wrappedStorage.data()) size_t {kWrappedStorageValue};
        const auto wrappedBefore = wrappedStorage;
        if (unwrapKey(kek.data(), wrappedStorage.data(), kWrappedBytes,
                      output.data(), output.size(),
                      wrappedLength) != Error::InvalidArgument ||
            wrappedStorage != wrappedBefore)
        {
            return false;
        }

        // Nor may a result length erase the plaintext output before checking.
        alignas(size_t) std::array<uint8_t, kPtkBytes> plainStorage {};
        size_t &plainLength =
            *::new(plainStorage.data()) size_t {kPlainStorageValue};
        const auto plainBefore = plainStorage;
        return unwrapKey(kek.data(), wrapped.data(), wrapped.size(),
                         plainStorage.data(), kPmkBytes,
                         plainLength) == Error::InvalidArgument &&
               plainStorage == plainBefore;
    }

    bool derivePublishedPmkVector()
    {
        // IEEE 802.11 WPA2-PSK known answer: password / IEEE, 4096 rounds.
        constexpr std::array<uint8_t, kPasswordBytes> password {
            'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
        };
        constexpr std::array<uint8_t, kSsidBytes> ssid {'I', 'E', 'E', 'E'};
        constexpr std::array<uint8_t, kPmkBytes> expected {
            0xf4, 0x2c, 0x6f, 0xc5, 0x2d, 0xf0, 0xeb, 0xef, 0x9e, 0xbb, 0x4b,
            0x90, 0xb3, 0x8a, 0x5f, 0x90, 0x2e, 0x83, 0xfe, 0x1b, 0x13, 0x5a,
            0x70, 0xe2, 0x3a, 0xed, 0x76, 0x2e, 0x97, 0x10, 0xa1, 0x2e,
        };
        std::array<uint8_t, kPmkBytes> pmk {};
        return derivePmk(password.data(), password.size(), ssid.data(),
                         ssid.size(), pmk.data()) == Error::Ok &&
               std::memcmp(pmk.data(), expected.data(), expected.size()) == 0;
    }

    bool deriveReferencePtkVector()
    {
        // Python stdlib HMAC-SHA1 reference, independent of this C++ PRF:
        // HMAC(PMK, "Pairwise key expansion" || NUL || sorted IDs || counter).
        constexpr std::array<uint8_t, kPmkBytes> pmk {
            0xf4, 0x2c, 0x6f, 0xc5, 0x2d, 0xf0, 0xeb, 0xef, 0x9e, 0xbb, 0x4b,
            0x90, 0xb3, 0x8a, 0x5f, 0x90, 0x2e, 0x83, 0xfe, 0x1b, 0x13, 0x5a,
            0x70, 0xe2, 0x3a, 0xed, 0x76, 0x2e, 0x97, 0x10, 0xa1, 0x2e,
        };
        const Mac ap = kAp;
        const Mac station = kStation;
        std::array<uint8_t, kPmkBytes> aNonce {};
        std::array<uint8_t, kPmkBytes> sNonce {};
        for (size_t i = 0; i < aNonce.size(); ++i)
        {
            aNonce.at(i) = static_cast<uint8_t>(i);
            sNonce.at(i) = static_cast<uint8_t>(i + aNonce.size());
        }
        constexpr std::array<uint8_t, kPtkBytes> expected {
            0x54, 0xbf, 0xa1, 0x6e, 0xde, 0x33, 0x9e, 0x9b, 0xd5, 0x55,
            0x88, 0x3e, 0x57, 0xbd, 0x53, 0x93, 0x59, 0x18, 0xbd, 0xa2,
            0x3d, 0x31, 0x69, 0x3c, 0x38, 0x44, 0xf9, 0xb9, 0x2e, 0xf7,
            0x40, 0xc5, 0xc9, 0x98, 0x9f, 0x97, 0x53, 0x32, 0xcc, 0xa1,
            0x4d, 0x0f, 0xd7, 0xa8, 0xf6, 0xf4, 0x44, 0x8a,
        };
        std::array<uint8_t, kPtkBytes> ptk {};
        return derivePtk(pmk.data(), ap, station, aNonce.data(), sNonce.data(),
                         ptk.data()) == Error::Ok &&
               std::memcmp(ptk.data(), expected.data(), expected.size()) == 0;
    }

    bool calculateReferenceMicVector()
    {
        // Independent Python HMAC-SHA1-128 over a synthetic 99-byte EAPOL
        // key frame with the 16-octet MIC field zeroed (octets 81..96).
        constexpr std::array<uint8_t, kMicBytes> kck {
            0x54, 0xbf, 0xa1, 0x6e, 0xde, 0x33, 0x9e, 0x9b,
            0xd5, 0x55, 0x88, 0x3e, 0x57, 0xbd, 0x53, 0x93,
        };
        constexpr std::array<uint8_t, kMicBytes> expected {
            0x43, 0x1e, 0xc9, 0xa1, 0x7e, 0x26, 0x17, 0xe4,
            0xa0, 0x76, 0x8f, 0xa0, 0x43, 0xcb, 0xb9, 0x39,
        };
        std::array<uint8_t, kEapolBytes> eapol {};
        for (size_t i = 0; i < eapol.size(); ++i)
        {
            eapol.at(i) = static_cast<uint8_t>(i);
        }
        for (size_t i = kMicFieldStart; i < kMicFieldEnd; ++i)
        {
            eapol.at(i) = 0;
        }
        std::array<uint8_t, kMicBytes> mic {};
        return calculateMic(kck.data(), eapol.data(), eapol.size(),
                            mic.data()) == Error::Ok &&
               std::memcmp(mic.data(), expected.data(), expected.size()) == 0;
    }

    bool unwrapPublicRfc3394Vector()
    {
        // RFC 3394 section 4.1: 128-bit KEK, 128-bit key data.
        constexpr std::array<uint8_t, kKekBytes> kek {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        };
        constexpr std::array<uint8_t, kWrappedBytes> ciphertext {
            0x1f, 0xa6, 0x8b, 0x0a, 0x81, 0x12, 0xb4, 0x47,
            0xae, 0xf3, 0x4b, 0xd8, 0xfb, 0x5a, 0x7b, 0x82,
            0x9d, 0x3e, 0x86, 0x23, 0x71, 0xd2, 0xcf, 0xe5,
        };
        constexpr std::array<uint8_t, kMicBytes> expected {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        };
        std::array<uint8_t, kMicBytes> plaintext {};
        size_t length = kEapolBytes;
        if (unwrapKey(kek.data(), ciphertext.data(), ciphertext.size(),
                      plaintext.data(), plaintext.size(),
                      length) != Error::Ok ||
            length != plaintext.size() ||
            std::memcmp(plaintext.data(), expected.data(), expected.size()) !=
                0)
        {
            return false;
        }

        // Mutating a valid wrap must not publish unverified key bytes.
        std::array<uint8_t, ciphertext.size()> corrupted {};
        std::memcpy(corrupted.data(), ciphertext.data(), corrupted.size());
        corrupted.at(0U) = static_cast<uint8_t>(corrupted.at(0U) ^ 1U);
        std::array<uint8_t, plaintext.size()> sentinel {};
        std::memset(sentinel.data(), kSentinel, sentinel.size());
        std::array<uint8_t, sentinel.size()> expectedSentinel {};
        std::memcpy(expectedSentinel.data(), sentinel.data(), sentinel.size());
        length = kEapolBytes;
        return unwrapKey(kek.data(), corrupted.data(), corrupted.size(),
                         sentinel.data(), sentinel.size(),
                         length) == Error::KeyWrapIntegrityError &&
               length == 0 &&
               std::memcmp(sentinel.data(), expectedSentinel.data(),
                           sentinel.size()) == 0;
    }
} // namespace

int main()
{
    if (!rejectIdentityAlias())
    {
        return 1;
    }
    if (!rejectMicKeyAlias())
    {
        return 2;
    }
    if (!rejectLengthReferenceAliases())
    {
        return 3;
    }
    if (!unwrapPublicRfc3394Vector())
    {
        return 4;
    }
    if (!derivePublishedPmkVector())
    {
        return kPublishedPmkFailed;
    }
    if (!deriveReferencePtkVector())
    {
        return kReferencePtkFailed;
    }
    if (!calculateReferenceMicVector())
    {
        return kReferenceMicFailed;
    }
    if (!rejectSamePtkIdentity())
    {
        return kSameIdentityFailed;
    }
    return 0;
}
