// SPDX-License-Identifier: AGPL-3.0-only
// CCMP-128: IEEE 802.11 CCMP nonce/AAD/ExtIV and NIST SP 800-38C CCM.
// FIPS 197 AES-128 forward cipher. No device, RF, entropy or OS I/O.
#include "Ccmp.hpp"
#include "AesTables.hpp"

#include <cstddef>
#include <cstdint>

namespace simpleath
{
    namespace ieee80211
    {
        namespace crypto
        {
            // IEEE byte indices and AES/CCM field masks are fixed wire-format
            // constants. Integer promotion of uint8_t to int is nonnegative,
            // and the C++14 kernel ABI intentionally exposes bounded C arrays.
            // NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,bugprone-signed-bitwise,cppcoreguidelines-pro-bounds-array-to-pointer-decay)
            namespace
            {
                constexpr size_t kHeaderBytes = 24U;
                constexpr size_t kExtIvBytes = 8U;
                constexpr size_t kMicBytes = 8U;
                constexpr size_t kBlockBytes = 16U;
                constexpr size_t kExpandedKeyBytes = 176U;
                constexpr size_t kAesRounds = 10U;
                constexpr size_t kNonceBytes = 13U;
                constexpr size_t kAadBytes = 22U;
                constexpr uint8_t kProtected = 0x40U;
                constexpr uint8_t kExtendedIv = 0x20U;
                constexpr uint8_t kCcmB0Flags = 0x59U;
                constexpr uint8_t kCcmCtrFlags = 0x01U;
                constexpr uint8_t kToDs = 0x01U;
                constexpr uint8_t kFromDs = 0x02U;
                constexpr uint8_t kFragmentFlag = 0x04U;
                constexpr uint8_t kKeyIdShift = 6U;

                template <size_t Capacity> class Bytes
                {
                    private:
                        uint8_t storage[Capacity] {};

                    public:
                        uint8_t &at(size_t index)
                        {
                            if (index >= Capacity)
                            {
                                __builtin_trap();
                            }
                            // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
                            return storage[index];
                        }

                        const uint8_t &at(size_t index) const
                        {
                            if (index >= Capacity)
                            {
                                __builtin_trap();
                            }
                            // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
                            return storage[index];
                        }

                        uint8_t *data()
                        {
                            return &storage[0U];
                        }

                        const uint8_t *data() const
                        {
                            return &storage[0U];
                        }
                };

                uint8_t *byteAt(uint8_t *base, size_t offset)
                {
                    // Caller validates byte capacity before this indexed view.
                    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
                    return &base[offset];
                }

                const uint8_t *byteAt(const uint8_t *base, size_t offset)
                {
                    // Callers validate the complete packet before offsets.
                    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
                    return &base[offset];
                }

                void secureWipe(void *buffer, size_t bytes)
                {
                    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                    auto *cursor = static_cast<volatile uint8_t *>(buffer);
                    for (size_t i = 0U; i < bytes; ++i)
                    {
                        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
                        cursor[i] = 0U;
                    }
                }

                uintptr_t addressOf(const void *pointer)
                {
                    uintptr_t address = 0U;
                    static_assert(sizeof(address) == sizeof(pointer),
                                  "pointer address must fit uintptr_t");
                    __builtin_memcpy(&address,
                                     static_cast<const void *>(&pointer),
                                     sizeof(pointer));
                    return address;
                }

                bool overlap(const void *left, size_t leftBytes,
                             const void *right, size_t rightBytes)
                {
                    if (left == nullptr || right == nullptr ||
                        leftBytes == 0U || rightBytes == 0U)
                    {
                        return false;
                    }
                    const uintptr_t a = addressOf(left);
                    const uintptr_t b = addressOf(right);
                    return a <= b ? b - a < leftBytes : a - b < rightBytes;
                }

                uint8_t xtime(uint8_t value)
                {
                    return static_cast<uint8_t>(
                        (value << 1U) ^ ((value & 0x80U) != 0U ? 0x1bU : 0U));
                }

                void expandKey(const uint8_t key[kCcmpTemporalKeyBytes],
                               Bytes<kExpandedKeyBytes> &expanded)
                {
                    __builtin_memcpy(expanded.data(), key,
                                     kCcmpTemporalKeyBytes);
                    uint8_t rcon = 1U;
                    for (size_t offset = kCcmpTemporalKeyBytes;
                         offset < kExpandedKeyBytes; offset += 4U)
                    {
                        Bytes<4U> word {};
                        for (size_t i = 0U; i < 4U; ++i)
                        {
                            word.at(i) = expanded.at(offset - 4U + i);
                        }
                        if ((offset % kCcmpTemporalKeyBytes) == 0U)
                        {
                            const uint8_t rotated = word.at(0U);
                            // AES S-box is indexed only by 8-bit values.
                            // NOLINTBEGIN(cppcoreguidelines-pro-bounds-constant-array-index)
                            word.at(0U) = static_cast<uint8_t>(
                                kAesSbox[word.at(1U)] ^ rcon);
                            word.at(1U) = kAesSbox[word.at(2U)];
                            word.at(2U) = kAesSbox[word.at(3U)];
                            word.at(3U) = kAesSbox[rotated];
                            // NOLINTEND(cppcoreguidelines-pro-bounds-constant-array-index)
                            rcon = xtime(rcon);
                        }
                        for (size_t i = 0U; i < 4U; ++i)
                        {
                            expanded.at(offset + i) = static_cast<uint8_t>(
                                expanded.at(offset + i -
                                            kCcmpTemporalKeyBytes) ^
                                word.at(i));
                        }
                        secureWipe(&word, sizeof(word));
                    }
                }

                void aesEncrypt(const Bytes<kExpandedKeyBytes> &expanded,
                                const Bytes<kBlockBytes> &input,
                                Bytes<kBlockBytes> &output)
                {
                    Bytes<kBlockBytes> state = input;
                    for (size_t i = 0U; i < kBlockBytes; ++i)
                    {
                        state.at(i) ^= expanded.at(i);
                    }
                    for (size_t round = 1U; round <= kAesRounds; ++round)
                    {
                        Bytes<kBlockBytes> shifted {};
                        for (size_t column = 0U; column < 4U; ++column)
                        {
                            for (size_t row = 0U; row < 4U; ++row)
                            {
                                const size_t sboxIndex =
                                    (((column + row) % 4U) * 4U) + row;
                                // AES state is one octet, always within Sbox.
                                const uint8_t substituted =
                                    *byteAt(&kAesSbox[0U], state.at(sboxIndex));
                                shifted.at((column * 4U) + row) = substituted;
                            }
                        }
                        if (round != kAesRounds)
                        {
                            for (size_t column = 0U; column < 4U; ++column)
                            {
                                const size_t c = column * 4U;
                                const uint8_t a = shifted.at(c);
                                const uint8_t b = shifted.at(c + 1U);
                                const uint8_t d = shifted.at(c + 2U);
                                const uint8_t e = shifted.at(c + 3U);
                                const uint8_t all = a ^ b ^ d ^ e;
                                state.at(c) = a ^ all ^ xtime(a ^ b);
                                state.at(c + 1U) = b ^ all ^ xtime(b ^ d);
                                state.at(c + 2U) = d ^ all ^ xtime(d ^ e);
                                state.at(c + 3U) = e ^ all ^ xtime(e ^ a);
                            }
                        }
                        else
                        {
                            state = shifted;
                        }
                        for (size_t i = 0U; i < kBlockBytes; ++i)
                        {
                            state.at(i) ^=
                                expanded.at((round * kBlockBytes) + i);
                        }
                        secureWipe(&shifted, sizeof(shifted));
                    }
                    output = state;
                    secureWipe(&state, sizeof(state));
                }

                bool validHeader(const uint8_t *frame, size_t bytes,
                                 bool encrypted, const uint8_t transmitter[6U])
                {
                    if (frame == nullptr || bytes < kHeaderBytes + 1U ||
                        bytes > kCcmpMaximumMpduBytes)
                    {
                        return false;
                    }
                    const uint8_t control0 = *byteAt(frame, 0U);
                    const uint8_t control1 = *byteAt(frame, 1U);
                    const uint8_t direction = control1 & (kToDs | kFromDs);
                    if (control0 != 0x08U ||
                        (direction != kToDs && direction != kFromDs) ||
                        (control1 & (kFragmentFlag | kProtected)) !=
                            (encrypted ? kProtected : 0U) ||
                        (*byteAt(frame, 22U) & 0x0fU) != 0U)
                    {
                        return false;
                    }
                    return __builtin_memcmp(byteAt(frame, 10U), transmitter,
                                            kCcmpMacBytes) == 0;
                }

                void buildNonce(Bytes<kNonceBytes> &nonce,
                                const uint8_t *header, uint64_t pn)
                {
                    nonce.at(0U) = 0U; // Legacy non-QoS priority.
                    __builtin_memcpy(&nonce.at(1U), byteAt(header, 10U),
                                     kCcmpMacBytes);
                    for (size_t i = 0U; i < 6U; ++i)
                    {
                        nonce.at(7U + i) =
                            static_cast<uint8_t>(pn >> (8U * (5U - i)));
                    }
                }

                void buildAad(Bytes<kAadBytes> &aad, const uint8_t *header)
                {
                    aad.at(0U) = *byteAt(header, 0U) & 0x8fU;
                    aad.at(1U) = *byteAt(header, 1U) & 0xc7U;
                    __builtin_memcpy(&aad.at(2U), byteAt(header, 4U), 18U);
                    aad.at(20U) = *byteAt(header, 22U) & 0x0fU;
                    aad.at(21U) = 0U;
                }

                void macBlock(Bytes<kBlockBytes> &chain,
                              const Bytes<kBlockBytes> &block,
                              const Bytes<kExpandedKeyBytes> &key)
                {
                    Bytes<kBlockBytes> mixed {};
                    for (size_t i = 0U; i < kBlockBytes; ++i)
                    {
                        mixed.at(i) = chain.at(i) ^ block.at(i);
                    }
                    aesEncrypt(key, mixed, chain);
                    secureWipe(&mixed, sizeof(mixed));
                }

                void ctrBlock(Bytes<kBlockBytes> &block,
                              const Bytes<kNonceBytes> &nonce, uint16_t count)
                {
                    block = {};
                    block.at(0U) = kCcmCtrFlags;
                    __builtin_memcpy(&block.at(1U), nonce.data(), kNonceBytes);
                    block.at(14U) = static_cast<uint8_t>(count >> 8U);
                    block.at(15U) = static_cast<uint8_t>(count);
                }

                void computeTag(
                    const Bytes<kExpandedKeyBytes> &key,
                    const Bytes<kNonceBytes> &nonce,
                    // Header carries the masked AAD; plain is
                    // authenticated message content, never IV.
                    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
                    const uint8_t *header, const uint8_t *plain, size_t length,
                    Bytes<kMicBytes> &tag)
                {
                    Bytes<kBlockBytes> block {};
                    Bytes<kBlockBytes> chain {};
                    block.at(0U) = kCcmB0Flags;
                    __builtin_memcpy(&block.at(1U), nonce.data(), kNonceBytes);
                    block.at(14U) = static_cast<uint8_t>(length >> 8U);
                    block.at(15U) = static_cast<uint8_t>(length);
                    macBlock(chain, block, key);

                    Bytes<kAadBytes> aad {};
                    buildAad(aad, header);
                    block = {};
                    block.at(0U) = 0U;
                    block.at(1U) = static_cast<uint8_t>(kAadBytes);
                    __builtin_memcpy(&block.at(2U), aad.data(), 14U);
                    macBlock(chain, block, key);
                    block = {};
                    __builtin_memcpy(block.data(), &aad.at(14U), 8U);
                    macBlock(chain, block, key);
                    for (size_t offset = 0U; offset < length;
                         offset += kBlockBytes)
                    {
                        block = {};
                        const size_t remain = length - offset;
                        const size_t count =
                            remain < kBlockBytes ? remain : kBlockBytes;
                        __builtin_memcpy(block.data(), byteAt(plain, offset),
                                         count);
                        macBlock(chain, block, key);
                    }
                    ctrBlock(block, nonce, 0U);
                    Bytes<kBlockBytes> s0 {};
                    aesEncrypt(key, block, s0);
                    for (size_t i = 0U; i < kMicBytes; ++i)
                    {
                        tag.at(i) = chain.at(i) ^ s0.at(i);
                    }
                    secureWipe(&s0, sizeof(s0));
                    secureWipe(&aad, sizeof(aad));
                    secureWipe(&block, sizeof(block));
                    secureWipe(&chain, sizeof(chain));
                }

                void cryptPayload(const Bytes<kExpandedKeyBytes> &key,
                                  const Bytes<kNonceBytes> &nonce,
                                  const uint8_t *input, uint8_t *output,
                                  size_t length)
                {
                    Bytes<kBlockBytes> counter {};
                    Bytes<kBlockBytes> stream {};
                    for (size_t offset = 0U; offset < length;
                         offset += kBlockBytes)
                    {
                        ctrBlock(
                            counter, nonce,
                            static_cast<uint16_t>(1U + (offset / kBlockBytes)));
                        aesEncrypt(key, counter, stream);
                        const size_t count = (length - offset < kBlockBytes)
                                                 ? length - offset
                                                 : kBlockBytes;
                        for (size_t i = 0U; i < count; ++i)
                        {
                            *byteAt(output, offset + i) =
                                *byteAt(input, offset + i) ^ stream.at(i);
                        }
                    }
                    secureWipe(&counter, sizeof(counter));
                    secureWipe(&stream, sizeof(stream));
                }

                bool validIo(const void *owner, size_t ownerBytes,
                             const uint8_t *frame, size_t bytes,
                             const uint8_t *output, size_t capacity,
                             const size_t &written)
                {
                    return !overlap(owner, ownerBytes, frame, bytes) &&
                           !overlap(owner, ownerBytes, output, capacity) &&
                           !overlap(owner, ownerBytes, &written,
                                    sizeof(written)) &&
                           !overlap(frame, bytes, output, capacity) &&
                           !overlap(frame, bytes, &written, sizeof(written)) &&
                           !overlap(output, capacity, &written,
                                    sizeof(written));
                }

                bool constantTimeMic(const Bytes<kMicBytes> &tag,
                                     const uint8_t *wire)
                {
                    uint8_t different = 0U;
                    for (size_t i = 0U; i < kMicBytes; ++i)
                    {
                        different |= tag.at(i) ^ *byteAt(wire, i);
                    }
                    return different == 0U;
                }
            } // namespace

            CcmpSession::~CcmpSession()
            {
                revoke();
            }

            void CcmpSession::revoke()
            {
                secureWipe(key_, sizeof(key_));
                secureWipe(transmitter_, sizeof(transmitter_));
                epoch_ = 0U;
                txPn_ = 0U;
                rxFloor_ = 0U;
                keyId_ = 0U;
                installed_ = false;
            }

            CcmpResult
            CcmpSession::install(const uint8_t key[kCcmpTemporalKeyBytes],
                                 const uint8_t transmitter[kCcmpMacBytes],
                                 uint8_t keyId, uint64_t epoch,
                                 uint64_t lastTransmittedPn,
                                 uint64_t receiveFloor)
            {
                if (installed_ || key == nullptr || transmitter == nullptr ||
                    epoch == 0U || keyId > 3U ||
                    lastTransmittedPn > kCcmpMaximumPacketNumber ||
                    receiveFloor > kCcmpMaximumPacketNumber ||
                    overlap(this, sizeof(*this), key, kCcmpTemporalKeyBytes) ||
                    overlap(this, sizeof(*this), transmitter, kCcmpMacBytes) ||
                    overlap(key, kCcmpTemporalKeyBytes, transmitter,
                            kCcmpMacBytes) ||
                    (*byteAt(transmitter, 0U) & 1U) != 0U)
                {
                    return CcmpResult::InvalidArgument;
                }
                uint8_t any = 0U;
                for (size_t i = 0U; i < kCcmpMacBytes; ++i)
                {
                    any |= *byteAt(transmitter, i);
                }
                if (any == 0U)
                {
                    return CcmpResult::InvalidArgument;
                }
                __builtin_memcpy(key_, key, kCcmpTemporalKeyBytes);
                __builtin_memcpy(transmitter_, transmitter, kCcmpMacBytes);
                epoch_ = epoch;
                txPn_ = lastTransmittedPn;
                rxFloor_ = receiveFloor;
                keyId_ = keyId;
                installed_ = true;
                return CcmpResult::Ok;
            }

            CcmpResult CcmpSession::protect(uint64_t epoch,
                                            const uint8_t *frame, size_t bytes,
                                            uint8_t *output, size_t capacity,
                                            size_t &written)
            {
                if (!installed_)
                {
                    return CcmpResult::MissingKey;
                }
                if (epoch != epoch_)
                {
                    return CcmpResult::WrongEpoch;
                }
                if (frame == nullptr || output == nullptr ||
                    !validIo(this, sizeof(*this), frame, bytes, output,
                             capacity, written))
                {
                    return CcmpResult::OverlappingBuffers;
                }
                if (keyId_ != 0U ||
                    !validHeader(frame, bytes, false, transmitter_))
                {
                    return CcmpResult::UnsupportedFrame;
                }
                if (bytes > kCcmpMaximumMpduBytes - kExtIvBytes - kMicBytes)
                {
                    return CcmpResult::InvalidFrame;
                }
                const size_t resultBytes = bytes + kExtIvBytes + kMicBytes;
                if (capacity < resultBytes)
                {
                    return CcmpResult::BufferTooSmall;
                }
                if (txPn_ >= kCcmpMaximumPacketNumber)
                {
                    return CcmpResult::PacketNumberExhausted;
                }
                const uint64_t pn = txPn_ + 1U;
                Bytes<kCcmpMaximumMpduBytes> result {};
                __builtin_memcpy(result.data(), frame, kHeaderBytes);
                result.at(1U) |= kProtected;
                result.at(24U) = static_cast<uint8_t>(pn);
                result.at(25U) = static_cast<uint8_t>(pn >> 8U);
                result.at(26U) = 0U;
                result.at(27U) =
                    static_cast<uint8_t>(kExtendedIv | (keyId_ << kKeyIdShift));
                for (size_t i = 2U; i < 6U; ++i)
                {
                    result.at(26U + i) = static_cast<uint8_t>(pn >> (8U * i));
                }
                Bytes<kExpandedKeyBytes> expanded {};
                expandKey(key_, expanded);
                Bytes<kNonceBytes> nonce {};
                buildNonce(nonce, frame, pn);
                const size_t payloadBytes = bytes - kHeaderBytes;
                Bytes<kMicBytes> tag {};
                computeTag(expanded, nonce, result.data(),
                           byteAt(frame, kHeaderBytes), payloadBytes, tag);
                cryptPayload(expanded, nonce, byteAt(frame, kHeaderBytes),
                             &result.at(kHeaderBytes + kExtIvBytes),
                             payloadBytes);
                __builtin_memcpy(&result.at(resultBytes - kMicBytes),
                                 tag.data(), kMicBytes);
                __builtin_memcpy(output, result.data(), resultBytes);
                written = resultBytes;
                txPn_ = pn;
                secureWipe(&expanded, sizeof(expanded));
                secureWipe(&nonce, sizeof(nonce));
                secureWipe(&tag, sizeof(tag));
                secureWipe(&result, sizeof(result));
                return CcmpResult::Ok;
            }

            CcmpResult CcmpSession::unprotect(uint64_t epoch,
                                              const uint8_t *frame,
                                              size_t bytes, uint8_t *output,
                                              size_t capacity, size_t &written)
            {
                if (!installed_)
                {
                    return CcmpResult::MissingKey;
                }
                if (epoch != epoch_)
                {
                    return CcmpResult::WrongEpoch;
                }
                if (frame == nullptr || output == nullptr ||
                    !validIo(this, sizeof(*this), frame, bytes, output,
                             capacity, written))
                {
                    return CcmpResult::OverlappingBuffers;
                }
                if (bytes < kHeaderBytes + kExtIvBytes + kMicBytes + 1U ||
                    !validHeader(frame, bytes, true, transmitter_))
                {
                    return CcmpResult::UnsupportedFrame;
                }
                const size_t payloadBytes =
                    bytes - kHeaderBytes - kExtIvBytes - kMicBytes;
                const size_t resultBytes = kHeaderBytes + payloadBytes;
                if (capacity < resultBytes)
                {
                    return CcmpResult::BufferTooSmall;
                }
                const uint8_t *iv = byteAt(frame, kHeaderBytes);
                if (*byteAt(iv, 2U) != 0U ||
                    *byteAt(iv, 3U) !=
                        static_cast<uint8_t>(kExtendedIv |
                                             (keyId_ << kKeyIdShift)))
                {
                    return CcmpResult::InvalidFrame;
                }
                uint64_t pn = static_cast<uint64_t>(*byteAt(iv, 0U)) |
                              (static_cast<uint64_t>(*byteAt(iv, 1U)) << 8U);
                for (size_t i = 2U; i < 6U; ++i)
                {
                    pn |= static_cast<uint64_t>(*byteAt(iv, 2U + i))
                          << (8U * i);
                }
                if (pn == 0U || pn <= rxFloor_)
                {
                    return CcmpResult::ReplayDetected;
                }
                Bytes<kExpandedKeyBytes> expanded {};
                expandKey(key_, expanded);
                Bytes<kNonceBytes> nonce {};
                buildNonce(nonce, frame, pn);
                Bytes<kCcmpMaximumMpduBytes> result {};
                __builtin_memcpy(result.data(), frame, kHeaderBytes);
                result.at(1U) &= static_cast<uint8_t>(~kProtected);
                cryptPayload(expanded, nonce,
                             byteAt(frame, kHeaderBytes + kExtIvBytes),
                             &result.at(kHeaderBytes), payloadBytes);
                Bytes<kMicBytes> tag {};
                computeTag(expanded, nonce, frame, &result.at(kHeaderBytes),
                           payloadBytes, tag);
                const bool authenticated =
                    constantTimeMic(tag, byteAt(frame, bytes - kMicBytes));
                if (authenticated)
                {
                    __builtin_memcpy(output, result.data(), resultBytes);
                    written = resultBytes;
                    rxFloor_ = pn;
                }
                secureWipe(&tag, sizeof(tag));
                secureWipe(&nonce, sizeof(nonce));
                secureWipe(&expanded, sizeof(expanded));
                secureWipe(&result, sizeof(result));
                return authenticated ? CcmpResult::Ok : CcmpResult::MicMismatch;
            }

            // NOLINTEND(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,bugprone-signed-bitwise,cppcoreguidelines-pro-bounds-array-to-pointer-decay)
        } // namespace crypto
    } // namespace ieee80211
} // namespace simpleath
