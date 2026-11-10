// Original compact implementation of the published SHA-1, PBKDF2, WPA2
// PRF-384, AES-128 inverse cipher and RFC3394 key unwrap algorithms.
//
// Specifications: FIPS 180-4, RFC 2104, RFC 2898, IEEE 802.11-2020
// Annex J, FIPS 197 and RFC 3394. Only synthetic host-vector tests have
// exercised this source; no Tahoe kext build or security audit is authorized.
#include "Wpa2Primitives.hpp"
#include "AesTables.hpp"
#include "wifi/Frames.hpp"
#include <cstddef>
#include <cstdint>

namespace simpleath
{
    namespace ieee80211
    {
        namespace crypto
        {
            namespace
            {

                constexpr size_t kShaBlock = 64U;
                constexpr size_t kShaDigest = 20U;
                constexpr size_t kMaximumKeyData = 512U;
                constexpr size_t kPmkLength = 32U;
                constexpr size_t kPtkLength = 48U;
                constexpr size_t kPbkdf2MinPasswordBytes = 8U;
                constexpr size_t kPbkdf2MaxPasswordBytes = 63U;
                constexpr size_t kPbkdf2MaxSsidBytes = 32U;
                constexpr size_t kPbkdf2SaltCounterBytes = 4U;
                constexpr size_t kPbkdf2SaltBytes =
                    kPbkdf2MaxSsidBytes + kPbkdf2SaltCounterBytes;
                constexpr uint32_t kPbkdf2Blocks = 2U;
                constexpr unsigned kPbkdf2Rounds = 4096U;
                constexpr size_t kPtkMacPairBytes = 2U * kMacAddressBytes;
                constexpr size_t kPtkSecondNonceOffset =
                    kPtkMacPairBytes + kNonceBytes;
                constexpr size_t kPtkOrderedBytes =
                    kPtkSecondNonceOffset + kNonceBytes;
                constexpr uint8_t kPtkPrfBlocks = 3U;
                constexpr size_t kPtkSliceCount = 4U;
                constexpr size_t kMicMinimumEapolBytes = 99U;
                constexpr size_t kMicMaximumEapolBytes = 2048U;
                constexpr size_t kWrapUnitBytes = 8U;
                constexpr size_t kWrapMinimumCipherBytes = 3U * kWrapUnitBytes;
                constexpr int kWrapLastInverseRound = 5;
                constexpr uint8_t kWrapIntegrityByte = 0xa6U;
                constexpr unsigned kWordBits = 32U;
                constexpr unsigned kByteBits = 8U;
                constexpr unsigned kWordBytes = 4U;
                constexpr unsigned kHighestWordShift = 24U;
                constexpr unsigned kMiddleWordShift = 16U;
                constexpr unsigned kLowerWordShift = kByteBits;
                constexpr size_t kShaStateWords = 5U;
                constexpr size_t kShaScheduleWords = 80U;
                constexpr size_t kShaInitialWords = 16U;
                constexpr size_t kShaRound1 = 20U;
                constexpr size_t kShaRound2 = 40U;
                constexpr size_t kShaRound3 = 60U;
                constexpr size_t kShaLengthBytes = 8U;
                constexpr size_t kShaPaddingOffset = 56U;
                constexpr uint32_t kShaRoundConstant1 = 0x5a827999U;
                constexpr uint32_t kShaRoundConstant2 = 0x6ed9eba1U;
                constexpr uint32_t kShaRoundConstant3 = 0x8f1bbcdcU;
                constexpr uint32_t kShaRoundConstant4 = 0xca62c1d6U;
                constexpr uint32_t kShaInitialState0 = 0x67452301U;
                constexpr uint32_t kShaInitialState1 = 0xefcdab89U;
                constexpr uint32_t kShaInitialState2 = 0x98badcfeU;
                constexpr uint32_t kShaInitialState3 = 0x10325476U;
                constexpr uint32_t kShaInitialState4 = 0xc3d2e1f0U;
                constexpr uint8_t kShaPaddingStart = 0x80U;
                constexpr size_t kAesBlockBytes = 16U;
                constexpr size_t kAesExpandedBytes = 176U;
                constexpr size_t kAesColumnBytes = 4U;
                constexpr size_t kAesRounds = 10U;
                constexpr int kAesLastInverseRound = 9;
                constexpr unsigned kAesRconStep = 2U;
                constexpr uint8_t kGfHighBit = 0x80U;
                constexpr uint8_t kGfReduction = 0x1bU;
                constexpr uint8_t kMix09 = 9U;
                constexpr uint8_t kMix11 = 11U;
                constexpr uint8_t kMix13 = 13U;
                constexpr uint8_t kMix14 = 14U;
                constexpr uint8_t kHmacInnerPadByte = 0x36U;
                constexpr uint8_t kHmacOuterPadByte = 0x5cU;
                constexpr unsigned kShaRotateA = 5U;
                constexpr unsigned kShaRotateB = 30U;
                constexpr size_t kShaScheduleBackA = 3U;
                constexpr size_t kShaScheduleBackB = 8U;
                constexpr size_t kShaScheduleBackC = 14U;
                constexpr size_t kShaScheduleBackD = 16U;

                template <typename T, size_t N>
                T &elementAt(T (&array)[N], size_t index)
                {
                    if (index >= N)
                    {
                        __builtin_trap();
                    }
                    // The explicit capacity check is sufficient for the
                    // freestanding fixed-size crypto scratch arrays.
                    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
                    return array[index];
                }

                template <typename T, size_t N> T *arrayData(T (&array)[N])
                {
                    return &array[0U];
                }

                template <typename T> T &byteAt(T *span, size_t offset)
                {
                    // Public call sites establish their buffer capacity.
                    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
                    return span[offset];
                }

                void wipe(void *storage, size_t length)
                {
                    auto *ptr = static_cast<volatile uint8_t *>(storage);
                    for (size_t i = 0; i < length; ++i)
                    {
                        byteAt(ptr, i) = 0;
                    }
                }

                void bytesCopy(uint8_t *out, const uint8_t *in, size_t length)
                {
                    for (size_t i = 0; i < length; ++i)
                    {
                        byteAt(out, i) = byteAt(in, i);
                    }
                }

                bool byteLess(const uint8_t *a, const uint8_t *b, size_t length)
                {
                    for (size_t i = 0; i < length; ++i)
                    {
                        if (byteAt(a, i) < byteAt(b, i))
                        {
                            return true;
                        }
                        if (byteAt(a, i) > byteAt(b, i))
                        {
                            return false;
                        }
                    }
                    return false;
                }

                uint32_t rotl32(uint32_t a, unsigned n)
                {
                    return (a << n) | (a >> (kWordBits - n));
                }

                uint32_t read32be(const uint8_t *p)
                {
                    return (static_cast<uint32_t>(byteAt(p, 0U))
                            << kHighestWordShift) |
                           (static_cast<uint32_t>(byteAt(p, 1U))
                            << kMiddleWordShift) |
                           (static_cast<uint32_t>(byteAt(p, 2U))
                            << kLowerWordShift) |
                           byteAt(p, 3U);
                }

                void write32be(uint8_t *p, uint32_t v)
                {
                    byteAt(p, 0U) =
                        static_cast<uint8_t>(v >> kHighestWordShift);
                    byteAt(p, 1U) = static_cast<uint8_t>(v >> kMiddleWordShift);
                    byteAt(p, 2U) = static_cast<uint8_t>(v >> kLowerWordShift);
                    byteAt(p, 3U) = static_cast<uint8_t>(v);
                }

                struct Sha1
                {
                        uint32_t state[kShaStateWords];
                        uint64_t totalBytes;
                        uint8_t block[kShaBlock];
                        size_t buffered;
                };

                void shaBlock(Sha1 &ctx, const uint8_t bytes[kShaBlock])
                {
                    uint32_t words[kShaScheduleWords] {};
                    for (size_t i = 0; i < kShaInitialWords; ++i)
                    {
                        elementAt(words, i) =
                            read32be(&byteAt(bytes, kWordBytes * i));
                    }
                    for (size_t i = kShaInitialWords; i < kShaScheduleWords;
                         ++i)
                    {
                        elementAt(words, i) =
                            rotl32(elementAt(words, i - kShaScheduleBackA) ^
                                       elementAt(words, i - kShaScheduleBackB) ^
                                       elementAt(words, i - kShaScheduleBackC) ^
                                       elementAt(words, i - kShaScheduleBackD),
                                   1U);
                    }
                    uint32_t a = elementAt(ctx.state, 0U);
                    uint32_t b = elementAt(ctx.state, 1U);
                    uint32_t c = elementAt(ctx.state, 2U);
                    uint32_t d = elementAt(ctx.state, 3U);
                    uint32_t e = elementAt(ctx.state, 4U);
                    for (size_t i = 0; i < kShaScheduleWords; ++i)
                    {
                        uint32_t f = 0;
                        uint32_t k = 0;
                        if (i < kShaRound1)
                        {
                            f = (b & c) | (~b & d);
                            k = kShaRoundConstant1;
                        }
                        else if (i < kShaRound2)
                        {
                            f = b ^ c ^ d;
                            k = kShaRoundConstant2;
                        }
                        else if (i < kShaRound3)
                        {
                            f = (b & c) | (b & d) | (c & d);
                            k = kShaRoundConstant3;
                        }
                        else
                        {
                            f = b ^ c ^ d;
                            k = kShaRoundConstant4;
                        }
                        const uint32_t tmp = rotl32(a, kShaRotateA) + f + e +
                                             k + elementAt(words, i);
                        e = d;
                        d = c;
                        c = rotl32(b, kShaRotateB);
                        b = a;
                        a = tmp;
                    }
                    elementAt(ctx.state, 0U) += a;
                    elementAt(ctx.state, 1U) += b;
                    elementAt(ctx.state, 2U) += c;
                    elementAt(ctx.state, 3U) += d;
                    elementAt(ctx.state, 4U) += e;
                    wipe(arrayData(words), sizeof(words));
                }

                void shaInit(Sha1 &ctx)
                {
                    ctx = {};
                    elementAt(ctx.state, 0U) = kShaInitialState0;
                    elementAt(ctx.state, 1U) = kShaInitialState1;
                    elementAt(ctx.state, 2U) = kShaInitialState2;
                    elementAt(ctx.state, 3U) = kShaInitialState3;
                    elementAt(ctx.state, 4U) = kShaInitialState4;
                }

                void shaUpdate(Sha1 &ctx, const uint8_t *data, size_t length)
                {
                    ctx.totalBytes += length;
                    for (size_t i = 0; i < length; ++i)
                    {
                        elementAt(ctx.block, ctx.buffered++) = byteAt(data, i);
                        if (ctx.buffered == kShaBlock)
                        {
                            shaBlock(ctx, arrayData(ctx.block));
                            ctx.buffered = 0;
                        }
                    }
                }

                void shaFinal(Sha1 &ctx, uint8_t out[kShaDigest])
                {
                    const uint64_t bits = ctx.totalBytes * kByteBits;
                    const uint8_t one = kShaPaddingStart;
                    const uint8_t zero = 0;
                    shaUpdate(ctx, &one, 1U);
                    while (ctx.buffered != kShaPaddingOffset)
                    {
                        shaUpdate(ctx, &zero, 1U);
                    }
                    uint8_t length[kShaLengthBytes] {};
                    for (size_t i = 0; i < kShaLengthBytes; ++i)
                    {
                        elementAt(length, kShaLengthBytes - 1U - i) =
                            static_cast<uint8_t>(bits >> (kByteBits * i));
                    }
                    shaUpdate(ctx, arrayData(length), sizeof(length));
                    for (size_t i = 0; i < kShaStateWords; ++i)
                    {
                        write32be(&byteAt(out, kWordBytes * i),
                                  elementAt(ctx.state, i));
                    }
                    wipe(arrayData(length), sizeof(length));
                    wipe(&ctx, sizeof(ctx));
                }

                struct Slice
                {
                        const uint8_t *data;
                        size_t length;
                };

                void hmacSha1Slices(const uint8_t *key, size_t keyLength,
                                    const Slice *items, size_t count,
                                    uint8_t digest[kShaDigest])
                {
                    uint8_t normalized[kShaBlock] {};
                    if (keyLength > kShaBlock)
                    {
                        Sha1 temp {};
                        shaInit(temp);
                        shaUpdate(temp, key, keyLength);
                        shaFinal(temp, arrayData(normalized));
                    }
                    else
                    {
                        bytesCopy(arrayData(normalized), key, keyLength);
                    }
                    uint8_t innerPad[kShaBlock] {};
                    uint8_t outerPad[kShaBlock] {};
                    for (size_t i = 0; i < kShaBlock; ++i)
                    {
                        elementAt(innerPad, i) =
                            elementAt(normalized, i) ^ kHmacInnerPadByte;
                        elementAt(outerPad, i) =
                            elementAt(normalized, i) ^ kHmacOuterPadByte;
                    }
                    uint8_t inner[kShaDigest] {};
                    Sha1 ctx {};
                    shaInit(ctx);
                    shaUpdate(ctx, arrayData(innerPad), kShaBlock);
                    for (size_t i = 0; i < count; ++i)
                    {
                        shaUpdate(ctx, byteAt(items, i).data,
                                  byteAt(items, i).length);
                    }
                    shaFinal(ctx, arrayData(inner));
                    shaInit(ctx);
                    shaUpdate(ctx, arrayData(outerPad), kShaBlock);
                    shaUpdate(ctx, arrayData(inner), sizeof(inner));
                    shaFinal(ctx, digest);
                    wipe(arrayData(normalized), sizeof(normalized));
                    wipe(arrayData(inner), sizeof(inner));
                    wipe(arrayData(innerPad), sizeof(innerPad));
                    wipe(arrayData(outerPad), sizeof(outerPad));
                }

                struct GfFactors
                {
                        uint8_t multiplicand;
                        uint8_t multiplier;
                };

                uint8_t gfMultiply(const GfFactors &factors)
                {
                    uint8_t a = factors.multiplicand;
                    uint8_t b = factors.multiplier;
                    uint8_t product = 0;
                    for (unsigned i = 0; i < kByteBits; ++i)
                    {
                        if ((b & 1U) != 0U)
                        {
                            product ^= a;
                        }
                        const bool high = (a & kGfHighBit) != 0;
                        a = static_cast<uint8_t>(
                            (static_cast<unsigned>(a) << 1U) ^
                            (high ? kGfReduction : 0U));
                        b >>= 1U;
                    }
                    return product;
                }

                void expandAes128(const uint8_t key[kAesBlockBytes],
                                  uint8_t expanded[kAesExpandedBytes])
                {
                    bytesCopy(expanded, key, kAesBlockBytes);
                    uint8_t rcon = 1;
                    size_t i = kAesBlockBytes;
                    while (i < kAesExpandedBytes)
                    {
                        uint8_t tmp[kAesColumnBytes] = {
                            byteAt(expanded, i - kAesColumnBytes),
                            byteAt(expanded, i - (kAesColumnBytes - 1U)),
                            byteAt(expanded, i - (kAesColumnBytes - 2U)),
                            byteAt(expanded, i - 1),
                        };
                        if (i % kAesBlockBytes == 0)
                        {
                            const uint8_t first = elementAt(tmp, 0);
                            elementAt(tmp, 0) =
                                elementAt(kAesSbox, elementAt(tmp, 1)) ^ rcon;
                            elementAt(tmp, 1) =
                                elementAt(kAesSbox, elementAt(tmp, 2));
                            elementAt(tmp, 2) =
                                elementAt(kAesSbox, elementAt(tmp, 3));
                            elementAt(tmp, 3) = elementAt(kAesSbox, first);
                            rcon = gfMultiply({rcon, kAesRconStep});
                        }
                        for (const unsigned char k : tmp)
                        {
                            // C++14 does not order lhs post-increment against
                            // rhs evaluation.
                            byteAt(expanded, i) = static_cast<uint8_t>(
                                byteAt(expanded, i - kAesBlockBytes) ^ k);
                            ++i;
                        }
                        wipe(arrayData(tmp), sizeof(tmp));
                    }
                }

                void addRoundKey(uint8_t state[kAesBlockBytes],
                                 const uint8_t expanded[kAesExpandedBytes],
                                 size_t round)
                {
                    for (size_t i = 0; i < kAesBlockBytes; ++i)
                    {
                        byteAt(state, i) ^=
                            byteAt(expanded, (round * kAesBlockBytes) + i);
                    }
                }

                void inverseShiftRows(uint8_t state[kAesBlockBytes])
                {
                    uint8_t old[kAesBlockBytes] {};
                    bytesCopy(arrayData(old), state, sizeof(old));
                    // AES state is column major.
                    for (size_t col = 0; col < kAesColumnBytes; ++col)
                    {
                        byteAt(state, kAesColumnBytes * col) =
                            elementAt(old, kAesColumnBytes * col);
                        byteAt(state, (kAesColumnBytes * col) + 1) = elementAt(
                            old, (4 * ((col + 3U) % kAesColumnBytes)) + 1);
                        byteAt(state, (kAesColumnBytes * col) + 2) = elementAt(
                            old, (4 * ((col + 2U) % kAesColumnBytes)) + 2);
                        byteAt(state, (kAesColumnBytes * col) + 3) = elementAt(
                            old, (4 * ((col + 1U) % kAesColumnBytes)) + 3);
                    }
                    wipe(arrayData(old), sizeof(old));
                }

                void inverseMixColumns(uint8_t state[kAesBlockBytes])
                {
                    for (size_t col = 0; col < kAesColumnBytes; ++col)
                    {
                        const size_t offset = col * kAesColumnBytes;
                        const uint8_t a = byteAt(state, offset);
                        const uint8_t b = byteAt(state, offset + 1);
                        const uint8_t c = byteAt(state, offset + 2);
                        const uint8_t d = byteAt(state, offset + 3);
                        byteAt(state, offset) =
                            static_cast<unsigned>(gfMultiply({a, kMix14})) ^
                            gfMultiply({b, kMix11}) ^ gfMultiply({c, kMix13}) ^
                            gfMultiply({d, kMix09});
                        byteAt(state, offset + 1) =
                            static_cast<unsigned>(gfMultiply({a, kMix09})) ^
                            gfMultiply({b, kMix14}) ^ gfMultiply({c, kMix11}) ^
                            gfMultiply({d, kMix13});
                        byteAt(state, offset + 2) =
                            static_cast<unsigned>(gfMultiply({a, kMix13})) ^
                            gfMultiply({b, kMix09}) ^ gfMultiply({c, kMix14}) ^
                            gfMultiply({d, kMix11});
                        byteAt(state, offset + 3) =
                            static_cast<unsigned>(gfMultiply({a, kMix11})) ^
                            gfMultiply({b, kMix13}) ^ gfMultiply({c, kMix09}) ^
                            gfMultiply({d, kMix14});
                    }
                }

                struct AesDecryptInputs
                {
                        const uint8_t *expanded;
                        const uint8_t *encrypted;
                };

                void aes128DecryptBlock(const AesDecryptInputs &inputs,
                                        uint8_t plain[kAesBlockBytes])
                {
                    const auto *expanded = inputs.expanded;
                    const auto *encrypted = inputs.encrypted;
                    uint8_t state[kAesBlockBytes] {};
                    bytesCopy(arrayData(state), encrypted, sizeof(state));
                    addRoundKey(arrayData(state), expanded, kAesRounds);
                    for (int round = kAesLastInverseRound; round >= 1; --round)
                    {
                        inverseShiftRows(arrayData(state));
                        for (uint8_t &v : state)
                        {
                            v = elementAt(kAesInverseSbox, v);
                        }
                        addRoundKey(arrayData(state), expanded,
                                    static_cast<size_t>(round));
                        inverseMixColumns(arrayData(state));
                    }
                    inverseShiftRows(arrayData(state));
                    for (uint8_t &v : state)
                    {
                        v = elementAt(kAesInverseSbox, v);
                    }
                    addRoundKey(arrayData(state), expanded, 0);
                    bytesCopy(plain, arrayData(state), sizeof(state));
                    wipe(arrayData(state), sizeof(state));
                }

                uintptr_t addressOf(const void *pointer)
                {
                    static_assert(sizeof(pointer) == sizeof(uintptr_t),
                                  "crypto pointers must fit a native address");
                    uintptr_t address = 0U;
                    __builtin_memcpy(&address,
                                     static_cast<const void *>(&pointer),
                                     sizeof(address));
                    return address;
                }

                bool disjoint(const void *a, size_t aLength, const void *b,
                              size_t bLength)
                {
                    const uintptr_t left = addressOf(a);
                    const uintptr_t right = addressOf(b);
                    return left <= right ? right - left >= aLength
                                         : left - right >= bLength;
                }

            } // namespace

            Error derivePmk(const uint8_t *passphrase, size_t passphraseLength,
                            const uint8_t *ssid, size_t ssidLength,
                            uint8_t outputPmk[kPmkLength])
            {
                if ((passphrase == nullptr) || (ssid == nullptr) ||
                    (outputPmk == nullptr))
                {
                    return Error::InvalidArgument;
                }
                if (passphraseLength < kPbkdf2MinPasswordBytes ||
                    passphraseLength > kPbkdf2MaxPasswordBytes)
                {
                    return Error::InvalidPassword;
                }
                if (ssidLength == 0 || ssidLength > kPbkdf2MaxSsidBytes)
                {
                    return Error::InvalidSsid;
                }
                if (!disjoint(passphrase, passphraseLength, outputPmk,
                              kPmkLength) ||
                    !disjoint(ssid, ssidLength, outputPmk, kPmkLength))
                {
                    return Error::InvalidArgument;
                }
                uint8_t salt[kPbkdf2SaltBytes] {};
                bytesCopy(arrayData(salt), ssid, ssidLength);
                uint8_t result[kPmkLength] {};
                for (uint32_t block = 1; block <= kPbkdf2Blocks; ++block)
                {
                    elementAt(salt, ssidLength) =
                        static_cast<uint8_t>(block >> kHighestWordShift);
                    elementAt(salt, ssidLength + 1U) =
                        static_cast<uint8_t>(block >> kMiddleWordShift);
                    elementAt(salt, ssidLength + 2U) =
                        static_cast<uint8_t>(block >> kLowerWordShift);
                    elementAt(salt, ssidLength + 3U) =
                        static_cast<uint8_t>(block);
                    const Slice piece {
                        arrayData(salt),
                        ssidLength + kPbkdf2SaltCounterBytes,
                    };
                    uint8_t previous[kShaDigest] {};
                    hmacSha1Slices(passphrase, passphraseLength, &piece, 1,
                                   arrayData(previous));
                    uint8_t xorValue[kShaDigest] {};
                    bytesCopy(arrayData(xorValue), arrayData(previous),
                              sizeof(xorValue));
                    for (unsigned round = 1; round < kPbkdf2Rounds; ++round)
                    {
                        const Slice prev {
                            arrayData(previous),
                            sizeof(previous),
                        };
                        uint8_t next[kShaDigest] {};
                        hmacSha1Slices(passphrase, passphraseLength, &prev, 1,
                                       arrayData(next));
                        for (size_t i = 0; i < kShaDigest; ++i)
                        {
                            elementAt(xorValue, i) ^= elementAt(next, i);
                        }
                        bytesCopy(arrayData(previous), arrayData(next),
                                  sizeof(previous));
                        wipe(arrayData(next), sizeof(next));
                    }
                    const size_t start = (block - 1U) * kShaDigest;
                    const size_t count = start + kShaDigest <= kPmkLength
                                             ? kShaDigest
                                             : kPmkLength - start;
                    bytesCopy(&elementAt(result, start), arrayData(xorValue),
                              count);
                    wipe(arrayData(previous), sizeof(previous));
                    wipe(arrayData(xorValue), sizeof(xorValue));
                }
                bytesCopy(outputPmk, arrayData(result), sizeof(result));
                wipe(arrayData(result), sizeof(result));
                wipe(arrayData(salt), sizeof(salt));
                return Error::Ok;
            }

            Error derivePtk(const uint8_t pmk[kPmkLength], const Mac &ap,
                            const Mac &station,
                            const uint8_t aNonce[kNonceBytes],
                            const uint8_t sNonce[kNonceBytes],
                            uint8_t outputPtk[kPtkLength])
            {
                if ((pmk == nullptr) || (aNonce == nullptr) ||
                    (sNonce == nullptr) || (outputPtk == nullptr))
                {
                    return Error::InvalidArgument;
                }
                // Public callers need not pass through station selection.
                // An authenticator cannot also be the supplicant whose
                // traffic keys are being derived.
                if (!validStationMac(ap) || !validStationMac(station) ||
                    sameMac(ap, station))
                {
                    return Error::InvalidArgument;
                }
                // The MAC identities are references supplied by the caller,
                // not necessarily detached values. Even though the derivation
                // reads them before publishing the PTK, never overwrite an AP
                // or station identity through an aliased output buffer.
                if (!disjoint(pmk, kPmkLength, outputPtk, kPtkLength) ||
                    !disjoint(aNonce, kNonceBytes, outputPtk, kPtkLength) ||
                    !disjoint(sNonce, kNonceBytes, outputPtk, kPtkLength) ||
                    !disjoint(arrayData(ap.bytes), sizeof(ap.bytes), outputPtk,
                              kPtkLength) ||
                    !disjoint(arrayData(station.bytes), sizeof(station.bytes),
                              outputPtk, kPtkLength))
                {
                    return Error::InvalidArgument;
                }
                uint8_t ptk[kPtkLength] {};
                uint8_t ordered[kPtkOrderedBytes] {};
                const bool macOrder =
                    byteLess(arrayData(ap.bytes), arrayData(station.bytes),
                             kMacAddressBytes);
                const bool nonceOrder = byteLess(aNonce, sNonce, kNonceBytes);
                bytesCopy(arrayData(ordered),
                          macOrder ? arrayData(ap.bytes)
                                   : arrayData(station.bytes),
                          kMacAddressBytes);
                bytesCopy(&elementAt(ordered, kMacAddressBytes),
                          macOrder ? arrayData(station.bytes)
                                   : arrayData(ap.bytes),
                          kMacAddressBytes);
                bytesCopy(&elementAt(ordered, kPtkMacPairBytes),
                          nonceOrder ? aNonce : sNonce, kNonceBytes);
                bytesCopy(&elementAt(ordered, kPtkSecondNonceOffset),
                          nonceOrder ? sNonce : aNonce, kNonceBytes);
                constexpr uint8_t label[] = {
                    'P', 'a', 'i', 'r', 'w', 'i', 's', 'e', ' ', 'k', 'e',
                    'y', ' ', 'e', 'x', 'p', 'a', 'n', 's', 'i', 'o', 'n',
                };
                const uint8_t separator = 0;
                for (uint8_t counter = 0; counter < kPtkPrfBlocks; ++counter)
                {
                    const Slice parts[] = {
                        {
                            arrayData(label),
                            sizeof(label),
                        },
                        {&separator, 1U},
                        {arrayData(ordered), sizeof(ordered)},
                        {&counter, 1U},
                    };
                    uint8_t digest[kShaDigest] {};
                    hmacSha1Slices(pmk, kPmkLength, arrayData(parts),
                                   kPtkSliceCount, arrayData(digest));
                    const size_t offset =
                        static_cast<size_t>(counter) * kShaDigest;
                    const size_t remaining = kPtkLength - offset;
                    bytesCopy(&elementAt(ptk, offset), arrayData(digest),
                              remaining < sizeof(digest) ? remaining
                                                         : sizeof(digest));
                    wipe(arrayData(digest), sizeof(digest));
                }
                bytesCopy(outputPtk, arrayData(ptk), sizeof(ptk));
                wipe(arrayData(ptk), sizeof(ptk));
                wipe(arrayData(ordered), sizeof(ordered));
                return Error::Ok;
            }

            Error calculateMic(const uint8_t kck[kAesKeyBytes],
                               const uint8_t *eapol, size_t frameBytes,
                               uint8_t outputMic[kAesKeyBytes])
            {
                if ((kck == nullptr) || (eapol == nullptr) ||
                    (outputMic == nullptr) ||
                    frameBytes < kMicMinimumEapolBytes ||
                    frameBytes > kMicMaximumEapolBytes)
                {
                    return Error::InvalidArgument;
                }
                // The output must not overwrite the KCK or signed input.
                // In particular, returning a MIC in the key buffer would
                // silently destroy the caller's live session secret.
                if (!disjoint(outputMic, kAesKeyBytes, kck, kAesKeyBytes) ||
                    !disjoint(outputMic, kAesKeyBytes, eapol, frameBytes))
                {
                    return Error::InvalidArgument;
                }
                const Slice input {eapol, frameBytes};
                uint8_t digest[kShaDigest] {};
                hmacSha1Slices(kck, kAesKeyBytes, &input, 1U,
                               arrayData(digest));
                bytesCopy(outputMic, arrayData(digest), kAesKeyBytes);
                wipe(arrayData(digest), sizeof(digest));
                return Error::Ok;
            }

            Error unwrapKey(const uint8_t kek[kAesKeyBytes],
                            const uint8_t *wrapped, size_t wrappedBytes,
                            uint8_t *output, size_t outputCapacity,
                            size_t &outputBytes)
            {
                // outputBytes is a writable reference and could be forged to
                // refer into the KEK, wrapped ciphertext or plaintext output.
                // Reject such aliases BEFORE clearing it, so invalid calls
                // cannot mutate the key or the packet being authenticated.
                const auto *countBytes =
                    static_cast<const void *>(&outputBytes);
                if (((kek != nullptr) &&
                     !disjoint(countBytes, sizeof(outputBytes), kek,
                               kAesKeyBytes)) ||
                    ((wrapped != nullptr) &&
                     !disjoint(countBytes, sizeof(outputBytes), wrapped,
                               wrappedBytes)) ||
                    ((output != nullptr) &&
                     !disjoint(countBytes, sizeof(outputBytes), output,
                               outputCapacity)))
                {
                    return Error::InvalidArgument;
                }
                outputBytes = 0;
                if ((kek == nullptr) || (wrapped == nullptr) ||
                    (output == nullptr))
                {
                    return Error::InvalidArgument;
                }
                if (wrappedBytes < kWrapMinimumCipherBytes ||
                    wrappedBytes > kMaximumKeyData ||
                    wrappedBytes % kWrapUnitBytes != 0)
                {
                    return Error::BadWrappedLength;
                }
                const size_t plainBytes = wrappedBytes - kWrapUnitBytes;
                if (outputCapacity < plainBytes)
                {
                    return Error::BufferTooSmall;
                }
                if (!disjoint(kek, kAesKeyBytes, output, plainBytes) ||
                    !disjoint(wrapped, wrappedBytes, output, plainBytes))
                {
                    return Error::InvalidArgument;
                }
                uint8_t expanded[kAesExpandedBytes] {};
                expandAes128(kek, arrayData(expanded));
                uint8_t a[kWrapUnitBytes] {};
                bytesCopy(arrayData(a), wrapped, kWrapUnitBytes);
                uint8_t result[kMaximumKeyData] {};
                bytesCopy(arrayData(result), &byteAt(wrapped, kWrapUnitBytes),
                          plainBytes);
                const size_t n = plainBytes / kWrapUnitBytes;
                for (int j = kWrapLastInverseRound; j >= 0; --j)
                {
                    for (size_t i = n; i > 0; --i)
                    {
                        uint8_t encrypted[kAesBlockBytes] {};
                        uint8_t decrypted[kAesBlockBytes] {};
                        bytesCopy(arrayData(encrypted), arrayData(a),
                                  kWrapUnitBytes);
                        const uint64_t t = (static_cast<uint64_t>(n) *
                                            static_cast<uint64_t>(j)) +
                                           i;
                        for (size_t index = 0; index < kWrapUnitBytes; ++index)
                        {
                            elementAt(encrypted, kWrapUnitBytes - 1U - index) ^=
                                static_cast<uint8_t>(t >> (kByteBits * index));
                        }
                        bytesCopy(&elementAt(encrypted, kWrapUnitBytes),
                                  &elementAt(result, (i - 1U) * kWrapUnitBytes),
                                  kWrapUnitBytes);
                        aes128DecryptBlock(
                            {arrayData(expanded), arrayData(encrypted)},
                            arrayData(decrypted));
                        bytesCopy(arrayData(a), arrayData(decrypted),
                                  kWrapUnitBytes);
                        bytesCopy(&elementAt(result, (i - 1U) * kWrapUnitBytes),
                                  &elementAt(decrypted, kWrapUnitBytes),
                                  kWrapUnitBytes);
                        wipe(arrayData(encrypted), sizeof(encrypted));
                        wipe(arrayData(decrypted), sizeof(decrypted));
                    }
                }
                uint8_t mismatch = 0;
                for (const unsigned char i : a)
                {
                    mismatch |= static_cast<uint8_t>(i ^ kWrapIntegrityByte);
                }
                wipe(arrayData(a), sizeof(a));
                wipe(arrayData(expanded), sizeof(expanded));
                if (mismatch != 0)
                {
                    wipe(arrayData(result), sizeof(result));
                    return Error::KeyWrapIntegrityError;
                }
                bytesCopy(output, arrayData(result), plainBytes);
                outputBytes = plainBytes;
                wipe(arrayData(result), sizeof(result));
                return Error::Ok;
            }

        } // namespace crypto
    } // namespace ieee80211
} // namespace simpleath
