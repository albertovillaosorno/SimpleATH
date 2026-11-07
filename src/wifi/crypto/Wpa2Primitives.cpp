// SPDX-License-Identifier: AGPL-3.0-only
// Original compact implementation of the published SHA-1, PBKDF2, WPA2
// PRF-384, AES-128 inverse cipher and RFC3394 key unwrap algorithms.
//
// Specifications: FIPS 180-4, RFC 2104, RFC 2898, IEEE 802.11-2020
// Annex J, FIPS 197 and RFC 3394. Only synthetic host-vector tests have
// exercised this source; no Tahoe kext build or security audit is authorized.
#include "Wpa2Primitives.hpp"
#include "AesTables.hpp"

namespace simpleath
{
    namespace ieee80211
    {
        namespace crypto
        {
            namespace
            {

                constexpr size_t kShaBlock = 64u;
                constexpr size_t kShaDigest = 20u;
                constexpr size_t kMaximumKeyData = 512u;
                constexpr size_t kPmkLength = 32u;
                constexpr size_t kPtkLength = 48u;

                void wipe(void *storage, size_t length)
                {
                    volatile uint8_t *ptr =
                        static_cast<volatile uint8_t *>(storage);
                    for (size_t i = 0; i < length; ++i)
                        ptr[i] = 0;
                }

                void bytesCopy(uint8_t *out, const uint8_t *in, size_t length)
                {
                    for (size_t i = 0; i < length; ++i)
                        out[i] = in[i];
                }

                bool byteLess(const uint8_t *a, const uint8_t *b, size_t length)
                {
                    for (size_t i = 0; i < length; ++i)
                    {
                        if (a[i] < b[i])
                            return true;
                        if (a[i] > b[i])
                            return false;
                    }
                    return false;
                }

                uint32_t rotl32(uint32_t a, unsigned n)
                {
                    return (a << n) | (a >> (32u - n));
                }

                uint32_t read32be(const uint8_t *p)
                {
                    return (static_cast<uint32_t>(p[0]) << 24u) |
                           (static_cast<uint32_t>(p[1]) << 16u) |
                           (static_cast<uint32_t>(p[2]) << 8u) | p[3];
                }

                void write32be(uint8_t *p, uint32_t v)
                {
                    p[0] = static_cast<uint8_t>(v >> 24u);
                    p[1] = static_cast<uint8_t>(v >> 16u);
                    p[2] = static_cast<uint8_t>(v >> 8u);
                    p[3] = static_cast<uint8_t>(v);
                }

                struct Sha1
                {
                        uint32_t state[5];
                        uint64_t totalBytes;
                        uint8_t block[64];
                        size_t buffered;
                };

                void shaBlock(Sha1 &ctx, const uint8_t bytes[64])
                {
                    uint32_t words[80] {};
                    for (size_t i = 0; i < 16; ++i)
                        words[i] = read32be(bytes + 4 * i);
                    for (size_t i = 16; i < 80; ++i)
                        words[i] = rotl32(words[i - 3] ^ words[i - 8] ^
                                              words[i - 14] ^ words[i - 16],
                                          1u);
                    uint32_t a = ctx.state[0];
                    uint32_t b = ctx.state[1];
                    uint32_t c = ctx.state[2];
                    uint32_t d = ctx.state[3];
                    uint32_t e = ctx.state[4];
                    for (size_t i = 0; i < 80; ++i)
                    {
                        uint32_t f = 0, k = 0;
                        if (i < 20)
                        {
                            f = (b & c) | (~b & d);
                            k = 0x5a827999u;
                        }
                        else if (i < 40)
                        {
                            f = b ^ c ^ d;
                            k = 0x6ed9eba1u;
                        }
                        else if (i < 60)
                        {
                            f = (b & c) | (b & d) | (c & d);
                            k = 0x8f1bbcdcu;
                        }
                        else
                        {
                            f = b ^ c ^ d;
                            k = 0xca62c1d6u;
                        }
                        const uint32_t tmp =
                            rotl32(a, 5u) + f + e + k + words[i];
                        e = d;
                        d = c;
                        c = rotl32(b, 30u);
                        b = a;
                        a = tmp;
                    }
                    ctx.state[0] += a;
                    ctx.state[1] += b;
                    ctx.state[2] += c;
                    ctx.state[3] += d;
                    ctx.state[4] += e;
                    wipe(words, sizeof(words));
                }

                void shaInit(Sha1 &ctx)
                {
                    ctx = {};
                    ctx.state[0] = 0x67452301u;
                    ctx.state[1] = 0xefcdab89u;
                    ctx.state[2] = 0x98badcfeu;
                    ctx.state[3] = 0x10325476u;
                    ctx.state[4] = 0xc3d2e1f0u;
                }

                void shaUpdate(Sha1 &ctx, const uint8_t *data, size_t length)
                {
                    ctx.totalBytes += length;
                    for (size_t i = 0; i < length; ++i)
                    {
                        ctx.block[ctx.buffered++] = data[i];
                        if (ctx.buffered == kShaBlock)
                        {
                            shaBlock(ctx, ctx.block);
                            ctx.buffered = 0;
                        }
                    }
                }

                void shaFinal(Sha1 &ctx, uint8_t out[kShaDigest])
                {
                    const uint64_t bits = ctx.totalBytes * 8u;
                    const uint8_t one = 0x80u;
                    const uint8_t zero = 0;
                    shaUpdate(ctx, &one, 1u);
                    while (ctx.buffered != 56)
                        shaUpdate(ctx, &zero, 1u);
                    uint8_t length[8] {};
                    for (size_t i = 0; i < 8; ++i)
                        length[7u - i] = static_cast<uint8_t>(bits >> (8u * i));
                    shaUpdate(ctx, length, sizeof(length));
                    for (size_t i = 0; i < 5; ++i)
                        write32be(out + 4u * i, ctx.state[i]);
                    wipe(length, sizeof(length));
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
                        shaFinal(temp, normalized);
                    }
                    else
                    {
                        bytesCopy(normalized, key, keyLength);
                    }
                    uint8_t innerPad[kShaBlock] {};
                    uint8_t outerPad[kShaBlock] {};
                    for (size_t i = 0; i < kShaBlock; ++i)
                    {
                        innerPad[i] = normalized[i] ^ 0x36u;
                        outerPad[i] = normalized[i] ^ 0x5cu;
                    }
                    uint8_t inner[kShaDigest] {};
                    Sha1 ctx {};
                    shaInit(ctx);
                    shaUpdate(ctx, innerPad, kShaBlock);
                    for (size_t i = 0; i < count; ++i)
                        shaUpdate(ctx, items[i].data, items[i].length);
                    shaFinal(ctx, inner);
                    shaInit(ctx);
                    shaUpdate(ctx, outerPad, kShaBlock);
                    shaUpdate(ctx, inner, sizeof(inner));
                    shaFinal(ctx, digest);
                    wipe(normalized, sizeof(normalized));
                    wipe(inner, sizeof(inner));
                    wipe(innerPad, sizeof(innerPad));
                    wipe(outerPad, sizeof(outerPad));
                }

                uint8_t gfMultiply(uint8_t a, uint8_t b)
                {
                    uint8_t product = 0;
                    for (unsigned i = 0; i < 8; ++i)
                    {
                        if (b & 1u)
                            product ^= a;
                        const bool high = (a & 0x80u) != 0;
                        a = static_cast<uint8_t>((a << 1u) ^
                                                 (high ? 0x1bu : 0));
                        b >>= 1u;
                    }
                    return product;
                }

                void expandAes128(const uint8_t key[16], uint8_t expanded[176])
                {
                    bytesCopy(expanded, key, 16);
                    uint8_t rcon = 1;
                    size_t i = 16;
                    while (i < 176)
                    {
                        uint8_t tmp[4] = {expanded[i - 4], expanded[i - 3],
                                          expanded[i - 2], expanded[i - 1]};
                        if (i % 16 == 0)
                        {
                            const uint8_t first = tmp[0];
                            tmp[0] = kAesSbox[tmp[1]] ^ rcon;
                            tmp[1] = kAesSbox[tmp[2]];
                            tmp[2] = kAesSbox[tmp[3]];
                            tmp[3] = kAesSbox[first];
                            rcon = gfMultiply(rcon, 2);
                        }
                        for (size_t k = 0; k < 4; ++k)
                        {
                            // C++14 does not order lhs post-increment against
                            // rhs evaluation.
                            expanded[i] =
                                static_cast<uint8_t>(expanded[i - 16] ^ tmp[k]);
                            ++i;
                        }
                        wipe(tmp, sizeof(tmp));
                    }
                }

                void addRoundKey(uint8_t state[16], const uint8_t expanded[176],
                                 size_t round)
                {
                    for (size_t i = 0; i < 16; ++i)
                        state[i] ^= expanded[round * 16u + i];
                }

                void inverseShiftRows(uint8_t state[16])
                {
                    uint8_t old[16] {};
                    bytesCopy(old, state, sizeof(old));
                    // AES state is column major.
                    for (size_t col = 0; col < 4; ++col)
                    {
                        state[4 * col] = old[4 * col];
                        state[4 * col + 1] = old[4 * ((col + 3u) % 4u) + 1];
                        state[4 * col + 2] = old[4 * ((col + 2u) % 4u) + 2];
                        state[4 * col + 3] = old[4 * ((col + 1u) % 4u) + 3];
                    }
                    wipe(old, sizeof(old));
                }

                void inverseMixColumns(uint8_t state[16])
                {
                    for (size_t col = 0; col < 4; ++col)
                    {
                        const size_t offset = col * 4;
                        const uint8_t a = state[offset];
                        const uint8_t b = state[offset + 1];
                        const uint8_t c = state[offset + 2];
                        const uint8_t d = state[offset + 3];
                        state[offset] = gfMultiply(a, 14) ^ gfMultiply(b, 11) ^
                                        gfMultiply(c, 13) ^ gfMultiply(d, 9);
                        state[offset + 1] =
                            gfMultiply(a, 9) ^ gfMultiply(b, 14) ^
                            gfMultiply(c, 11) ^ gfMultiply(d, 13);
                        state[offset + 2] =
                            gfMultiply(a, 13) ^ gfMultiply(b, 9) ^
                            gfMultiply(c, 14) ^ gfMultiply(d, 11);
                        state[offset + 3] =
                            gfMultiply(a, 11) ^ gfMultiply(b, 13) ^
                            gfMultiply(c, 9) ^ gfMultiply(d, 14);
                    }
                }

                void aes128DecryptBlock(const uint8_t expanded[176],
                                        const uint8_t encrypted[16],
                                        uint8_t plain[16])
                {
                    uint8_t state[16] {};
                    bytesCopy(state, encrypted, sizeof(state));
                    addRoundKey(state, expanded, 10);
                    for (int round = 9; round >= 1; --round)
                    {
                        inverseShiftRows(state);
                        for (uint8_t &v : state)
                            v = kAesInverseSbox[v];
                        addRoundKey(state, expanded,
                                    static_cast<size_t>(round));
                        inverseMixColumns(state);
                    }
                    inverseShiftRows(state);
                    for (uint8_t &v : state)
                        v = kAesInverseSbox[v];
                    addRoundKey(state, expanded, 0);
                    bytesCopy(plain, state, sizeof(state));
                    wipe(state, sizeof(state));
                }

                bool disjoint(const uint8_t *a, size_t aLength,
                              const uint8_t *b, size_t bLength)
                {
                    const uintptr_t left = reinterpret_cast<uintptr_t>(a);
                    const uintptr_t right = reinterpret_cast<uintptr_t>(b);
                    return left <= right ? right - left >= aLength
                                         : left - right >= bLength;
                }

            } // namespace

            Error derivePmk(const uint8_t *passphrase, size_t passphraseLength,
                            const uint8_t *ssid, size_t ssidLength,
                            uint8_t outputPmk[32])
            {
                if (!passphrase || !ssid || !outputPmk)
                    return Error::InvalidArgument;
                if (passphraseLength < 8 || passphraseLength > 63)
                    return Error::InvalidPassword;
                if (ssidLength == 0 || ssidLength > 32)
                    return Error::InvalidSsid;
                if (!disjoint(passphrase, passphraseLength, outputPmk, 32) ||
                    !disjoint(ssid, ssidLength, outputPmk, 32))
                    return Error::InvalidArgument;
                uint8_t salt[36] {};
                bytesCopy(salt, ssid, ssidLength);
                uint8_t result[32] {};
                for (uint32_t block = 1; block <= 2; ++block)
                {
                    salt[ssidLength] = static_cast<uint8_t>(block >> 24u);
                    salt[ssidLength + 1] = static_cast<uint8_t>(block >> 16u);
                    salt[ssidLength + 2] = static_cast<uint8_t>(block >> 8u);
                    salt[ssidLength + 3] = static_cast<uint8_t>(block);
                    const Slice piece {salt, ssidLength + 4u};
                    uint8_t previous[kShaDigest] {};
                    hmacSha1Slices(passphrase, passphraseLength, &piece, 1,
                                   previous);
                    uint8_t xorValue[kShaDigest] {};
                    bytesCopy(xorValue, previous, sizeof(xorValue));
                    for (unsigned round = 1; round < 4096; ++round)
                    {
                        const Slice prev {previous, sizeof(previous)};
                        uint8_t next[kShaDigest] {};
                        hmacSha1Slices(passphrase, passphraseLength, &prev, 1,
                                       next);
                        for (size_t i = 0; i < kShaDigest; ++i)
                            xorValue[i] ^= next[i];
                        bytesCopy(previous, next, sizeof(previous));
                        wipe(next, sizeof(next));
                    }
                    const size_t start = (block - 1u) * kShaDigest;
                    const size_t count = start + kShaDigest <= kPmkLength
                                             ? kShaDigest
                                             : kPmkLength - start;
                    bytesCopy(result + start, xorValue, count);
                    wipe(previous, sizeof(previous));
                    wipe(xorValue, sizeof(xorValue));
                }
                bytesCopy(outputPmk, result, sizeof(result));
                wipe(result, sizeof(result));
                wipe(salt, sizeof(salt));
                return Error::Ok;
            }

            Error derivePtk(const uint8_t pmk[32], const Mac &ap,
                            const Mac &station, const uint8_t aNonce[32],
                            const uint8_t sNonce[32], uint8_t outputPtk[48])
            {
                if (!pmk || !aNonce || !sNonce || !outputPtk)
                    return Error::InvalidArgument;
                if (!validStationMac(ap) || !validStationMac(station))
                    return Error::InvalidArgument;
                // The MAC identities are references supplied by the caller,
                // not necessarily detached values. Even though the derivation
                // reads them before publishing the PTK, never overwrite an AP
                // or station identity through an aliased output buffer.
                if (!disjoint(pmk, 32, outputPtk, kPtkLength) ||
                    !disjoint(aNonce, 32, outputPtk, kPtkLength) ||
                    !disjoint(sNonce, 32, outputPtk, kPtkLength) ||
                    !disjoint(ap.bytes, sizeof(ap.bytes), outputPtk,
                              kPtkLength) ||
                    !disjoint(station.bytes, sizeof(station.bytes), outputPtk,
                              kPtkLength))
                    return Error::InvalidArgument;
                uint8_t ptk[kPtkLength] {};
                uint8_t ordered[76] {};
                const bool macOrder = byteLess(ap.bytes, station.bytes, 6);
                const bool nonceOrder = byteLess(aNonce, sNonce, 32);
                bytesCopy(ordered, macOrder ? ap.bytes : station.bytes, 6);
                bytesCopy(ordered + 6, macOrder ? station.bytes : ap.bytes, 6);
                bytesCopy(ordered + 12, nonceOrder ? aNonce : sNonce, 32);
                bytesCopy(ordered + 44, nonceOrder ? sNonce : aNonce, 32);
                constexpr char label[] = "Pairwise key expansion";
                const uint8_t separator = 0;
                for (uint8_t counter = 0; counter < 3; ++counter)
                {
                    const Slice parts[] = {
                        {reinterpret_cast<const uint8_t *>(label),
                         sizeof(label) - 1u},
                        {&separator, 1u},
                        {ordered, sizeof(ordered)},
                        {&counter, 1u}};
                    uint8_t digest[kShaDigest] {};
                    hmacSha1Slices(pmk, 32, parts, 4, digest);
                    const size_t offset =
                        static_cast<size_t>(counter) * kShaDigest;
                    const size_t remaining = kPtkLength - offset;
                    bytesCopy(ptk + offset, digest,
                              remaining < sizeof(digest) ? remaining
                                                         : sizeof(digest));
                    wipe(digest, sizeof(digest));
                }
                bytesCopy(outputPtk, ptk, sizeof(ptk));
                wipe(ptk, sizeof(ptk));
                wipe(ordered, sizeof(ordered));
                return Error::Ok;
            }

            Error calculateMic(const uint8_t kck[16], const uint8_t *eapol,
                               size_t frameBytes, uint8_t outputMic[16])
            {
                if (!kck || !eapol || !outputMic || frameBytes < 99u ||
                    frameBytes > 2048u)
                    return Error::InvalidArgument;
                // The output must not overwrite the KCK or signed input.
                // In particular, returning a MIC in the key buffer would
                // silently destroy the caller's live session secret.
                if (!disjoint(outputMic, 16, kck, 16) ||
                    !disjoint(outputMic, 16, eapol, frameBytes))
                    return Error::InvalidArgument;
                const Slice input {eapol, frameBytes};
                uint8_t digest[kShaDigest] {};
                hmacSha1Slices(kck, 16, &input, 1, digest);
                bytesCopy(outputMic, digest, 16);
                wipe(digest, sizeof(digest));
                return Error::Ok;
            }

            Error unwrapKey(const uint8_t kek[16], const uint8_t *wrapped,
                            size_t wrappedBytes, uint8_t *output,
                            size_t outputCapacity, size_t &outputBytes)
            {
                // outputBytes is a writable reference and could be forged to
                // refer into the KEK, wrapped ciphertext or plaintext output.
                // Reject such aliases BEFORE clearing it, so invalid calls
                // cannot mutate the key or the packet being authenticated.
                const auto *countBytes =
                    reinterpret_cast<const uint8_t *>(&outputBytes);
                if ((kek &&
                     !disjoint(countBytes, sizeof(outputBytes), kek, 16)) ||
                    (wrapped && !disjoint(countBytes, sizeof(outputBytes),
                                          wrapped, wrappedBytes)) ||
                    (output && !disjoint(countBytes, sizeof(outputBytes),
                                         output, outputCapacity)))
                    return Error::InvalidArgument;
                outputBytes = 0;
                if (!kek || !wrapped || !output)
                    return Error::InvalidArgument;
                if (wrappedBytes < 24 || wrappedBytes > kMaximumKeyData ||
                    wrappedBytes % 8u != 0)
                    return Error::BadWrappedLength;
                const size_t plainBytes = wrappedBytes - 8u;
                if (outputCapacity < plainBytes)
                    return Error::BufferTooSmall;
                if (!disjoint(kek, 16, output, plainBytes) ||
                    !disjoint(wrapped, wrappedBytes, output, plainBytes))
                    return Error::InvalidArgument;
                uint8_t expanded[176] {};
                expandAes128(kek, expanded);
                uint8_t a[8] {};
                bytesCopy(a, wrapped, 8);
                uint8_t result[kMaximumKeyData] {};
                bytesCopy(result, wrapped + 8, plainBytes);
                const size_t n = plainBytes / 8u;
                for (int j = 5; j >= 0; --j)
                {
                    for (size_t i = n; i > 0; --i)
                    {
                        uint8_t encrypted[16] {};
                        uint8_t decrypted[16] {};
                        bytesCopy(encrypted, a, 8);
                        const uint64_t t = static_cast<uint64_t>(n) *
                                               static_cast<uint64_t>(j) +
                                           i;
                        for (size_t index = 0; index < 8; ++index)
                            encrypted[7u - index] ^=
                                static_cast<uint8_t>(t >> (8u * index));
                        bytesCopy(encrypted + 8, result + (i - 1u) * 8u, 8);
                        aes128DecryptBlock(expanded, encrypted, decrypted);
                        bytesCopy(a, decrypted, 8);
                        bytesCopy(result + (i - 1u) * 8u, decrypted + 8, 8);
                        wipe(encrypted, sizeof(encrypted));
                        wipe(decrypted, sizeof(decrypted));
                    }
                }
                uint8_t mismatch = 0;
                for (size_t i = 0; i < 8; ++i)
                    mismatch |= static_cast<uint8_t>(a[i] ^ 0xa6u);
                wipe(a, sizeof(a));
                wipe(expanded, sizeof(expanded));
                if (mismatch != 0)
                {
                    wipe(result, sizeof(result));
                    return Error::KeyWrapIntegrityError;
                }
                bytesCopy(output, result, plainBytes);
                outputBytes = plainBytes;
                wipe(result, sizeof(result));
                return Error::Ok;
            }

        } // namespace crypto
    } // namespace ieee80211
} // namespace simpleath
