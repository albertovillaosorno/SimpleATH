// SPDX-License-Identifier: AGPL-3.0-only
#include "Eapol.hpp"

#include <cstddef>
#include <cstdint>

namespace simpleath
{
    namespace ieee80211
    {
        static constexpr size_t kEapolHeaderBytes = 4;
        static constexpr size_t kEapolKeyFixedBytes = 95;
        static constexpr size_t kMaxEapolBodyBytes = 2048;
        static constexpr size_t kKeyNonceBytes = 32;
        static constexpr size_t kKeyMicBytes = 16;
        static constexpr size_t kKeyRscOffset = 61;
        static constexpr size_t kKeyNonceOffset = 13;
        static constexpr size_t kKeyMicOffset = 77;
        static constexpr uint8_t kKeyDescriptorType = 2;
        static constexpr uint8_t kKeyDescriptorVersion = 2;
        static constexpr uint16_t kUnsupportedInfo = 0xe030U;
        static constexpr uint32_t kBitsPerByte = 8;
        static constexpr size_t kReplayCounterBytes = 8;
        static constexpr size_t kKeyDataLengthOffset = 93;
        static constexpr uint8_t kEapolKeyPacketType = 3;
        // Exact WPA2-PSK CCMP M1/M3 Key Information masks: RSN version 2,
        // pairwise, ACK and M3-only install/MIC/secure/encrypted bits.
        static constexpr uint16_t kPairwise1Info = 0x008aU;
        static constexpr uint16_t kPairwise3Info = 0x13caU;
        static constexpr uint16_t kCcmpKeyBytes = 16;

        static uint16_t readBig16(const uint8_t *const bytes)
        {
            return static_cast<uint16_t>(static_cast<uint16_t>(bytes[0])
                                         << kBitsPerByte) |
                   static_cast<uint16_t>(bytes[1]);
        }

        static uint64_t readBig64(const uint8_t *const bytes)
        {
            uint64_t result = 0;
            for (size_t i = 0; i < kReplayCounterBytes; ++i)
            {
                result = (result << kBitsPerByte) | bytes[i];
            }
            return result;
        }

        static bool anyNonzero(const uint8_t *const bytes, size_t length)
        {
            uint8_t aggregate = 0;
            for (size_t i = 0; i < length; ++i)
            {
                aggregate |= bytes[i];
            }
            return aggregate != 0;
        }

        static bool overlapsStorage(const void *const firstBuffer,
                                    size_t firstBytes,
                                    const void *const secondBuffer,
                                    size_t secondBytes)
        {
            if (!firstBuffer || !secondBuffer || !firstBytes || !secondBytes)
            {
                return false;
            }
            const auto first = reinterpret_cast<uintptr_t>(firstBuffer);
            const auto second = reinterpret_cast<uintptr_t>(secondBuffer);
            return first <= second ? second - first < firstBytes
                                   : first - second < secondBytes;
        }

        static bool atWireOffset(const uint8_t *const frame,
                                 const uint8_t *const field, size_t offset)
        {
            const auto origin = reinterpret_cast<uintptr_t>(frame);
            const auto location = reinterpret_cast<uintptr_t>(field);
            return location >= origin && location - origin == offset;
        }

        static bool replayMetadataMatchesWire(const KeyFrame &frame)
        {
            // ReplayGuard accepts public, caller-built KeyFrame values. Keep
            // every borrowed subfield and the scalar replay/key fields tied
            // to the same bounded EAPOL image, not detached caller storage.
            // The M3 MIC bytes may already be zeroed for verification, so
            // never reparse the whole packet at this stage.
            if (frame.eapolBytes == nullptr || frame.nonce == nullptr ||
                frame.eapolLength < kEapolHeaderBytes + kEapolKeyFixedBytes ||
                frame.eapolLength > kEapolHeaderBytes + kMaxEapolBodyBytes)
                return false;
            if (!atWireOffset(frame.eapolBytes, frame.nonce,
                              kEapolHeaderBytes + kKeyNonceOffset) ||
                !atWireOffset(frame.eapolBytes, frame.keyRsc,
                              kEapolHeaderBytes + kKeyRscOffset) ||
                !atWireOffset(frame.eapolBytes, frame.mic,
                              kEapolHeaderBytes + kKeyMicOffset) ||
                !atWireOffset(frame.eapolBytes, frame.keyData,
                              kEapolHeaderBytes + kEapolKeyFixedBytes))
                return false;
            // A fabricated KeyFrame must not approve a mismatched fixed
            // EAPOL-Key body/key-data length that the parser would reject.
            // This also prevents an undeclared suffix from entering the public
            // replay transition as if it were part of a parsed key packet.
            if (frame.eapolLength - kEapolHeaderBytes !=
                kEapolKeyFixedBytes + frame.keyDataLength)
                return false;
            const uint8_t *const bytes = frame.eapolBytes;
            if (bytes[0] < 1 || bytes[0] > 3 ||
                bytes[1] != kEapolKeyPacketType ||
                bytes[kEapolHeaderBytes] != kKeyDescriptorType ||
                static_cast<size_t>(readBig16(bytes + 2)) + kEapolHeaderBytes !=
                    frame.eapolLength)
                return false;
            return readBig16(bytes + kEapolHeaderBytes + 1) ==
                       frame.keyInformation &&
                   readBig16(bytes + kEapolHeaderBytes + 3) ==
                       frame.keyLength &&
                   readBig64(bytes + kEapolHeaderBytes + 5) ==
                       frame.replayCounter &&
                   readBig16(bytes + kEapolHeaderBytes +
                             kKeyDataLengthOffset) == frame.keyDataLength;
        }

        EapolResult parseEapolKey(const uint8_t *const frame, size_t length,
                                  KeyFrame &out)
        {
            // A borrowed EAPOL-Key frame must not be overwritten with parsed
            // metadata: the MIC, nonce and replay counter still refer to it.
            if (overlapsStorage(frame, length, &out, sizeof(out)))
            {
                return EapolResult::OverlappingBuffers;
            }
            // Revocation on ordinary failure is mandatory: KeyFrame contains
            // borrowed nonce/MIC/key-data pointers into an earlier RX frame.
            // Keep the alias check above this write to preserve DMA evidence.
            out = {};
            if (frame == nullptr)
            {
                return EapolResult::NullBuffer;
            }
            if (length < kEapolHeaderBytes)
            {
                return EapolResult::TooShort;
            }
            if (frame[0] < 1 || frame[0] > 3)
            {
                return EapolResult::UnsupportedVersion;
            }
            if (frame[1] != kEapolKeyPacketType)
            {
                return EapolResult::UnsupportedType;
            }

            const size_t bodyLength = readBig16(frame + 2);
            if (bodyLength > kMaxEapolBodyBytes ||
                bodyLength > length - kEapolHeaderBytes)
            {
                return EapolResult::BadLength;
            }
            // EAPOL-Key fixed portion = 95 bytes after the EAPOL header.
            if (bodyLength < kEapolKeyFixedBytes)
            {
                return EapolResult::TooShort;
            }
            const uint8_t *const body = frame + kEapolHeaderBytes;
            if (body[0] != kKeyDescriptorType)
            {
                return EapolResult::UnsupportedCipher;
            }
            const uint16_t info = readBig16(body + 1);
            const auto version = static_cast<uint8_t>(info & 7U);
            if (version != kKeyDescriptorVersion)
            {
                // WPA2-PSK CCMP uses HMAC-SHA1-128 key descriptor version 2.
                // TKIP and AES-CMAC descriptor semantics are not implemented
                // here.
                return EapolResult::UnsupportedCipher;
            }
            const uint16_t keyLength = readBig16(body + 3);
            const uint64_t replay = readBig64(body + 5);
            const uint8_t *const nonce = body + kKeyNonceOffset;
            const uint8_t *const mic = body + kKeyMicOffset;
            const uint16_t keyDataLength =
                readBig16(body + kKeyDataLengthOffset);
            if (keyDataLength > bodyLength - kEapolKeyFixedBytes ||
                bodyLength !=
                    static_cast<size_t>(kEapolKeyFixedBytes + keyDataLength))
            {
                return EapolResult::BadLength;
            }

            const bool pairwise = (info & 0x0008U) != 0;
            const bool install = (info & 0x0040U) != 0;
            const bool ack = (info & 0x0080U) != 0;
            const bool hasMic = (info & 0x0100U) != 0;
            const bool secure = (info & 0x0200U) != 0;
            const bool error = (info & 0x0400U) != 0;
            const bool request = (info & 0x0800U) != 0;
            const bool encryptedData = (info & 0x1000U) != 0;
            // RSN does not use the legacy Key Index, SMK/PeerKey, or
            // reserved Key Information bits in this PSK-CCMP handshake.
            // An unset MIC flag also requires an all-zero MIC field.
            if (error || request || (info & kUnsupportedInfo) != 0 ||
                hasMic != anyNonzero(mic, kKeyMicBytes))
            {
                return EapolResult::InvalidKeyInformation;
            }

            KeyMessage message = KeyMessage::Unknown;
            if (pairwise)
            {
                if (ack && !hasMic && !install && !secure && !encryptedData &&
                    anyNonzero(nonce, kKeyNonceBytes))
                {
                    message = KeyMessage::Pairwise1;
                }
                else if (!ack && hasMic && !install && !secure &&
                         !encryptedData)
                {
                    message = KeyMessage::Pairwise2;
                }
                else if (ack && hasMic && install && secure && encryptedData)
                {
                    message = KeyMessage::Pairwise3;
                }
                else if (!ack && hasMic && !install && secure && !encryptedData)
                {
                    message = KeyMessage::Pairwise4;
                }
            }
            else
            {
                if (ack && hasMic && !install && secure && encryptedData)
                {
                    message = KeyMessage::Group1;
                }
                else if (!ack && hasMic && !install && secure && !encryptedData)
                {
                    message = KeyMessage::Group2;
                }
            }
            if (message == KeyMessage::Unknown)
            {
                return EapolResult::UnsupportedMessage;
            }
            // The authenticator's M1/M3 carry the 16-byte CCMP Key Length;
            // supplicant M2/M4 carry zero. All pairwise messages must agree
            // with this advertised role, not just their MIC/ACK flags.
            // M2 must also contain the supplicant's nonzero SNonce.
            if (pairwise && (keyLength != (ack ? kCcmpKeyBytes : 0u) ||
                             (message == KeyMessage::Pairwise2 &&
                              !anyNonzero(nonce, kKeyNonceBytes))))
            {
                return EapolResult::InvalidKeyInformation;
            }

            KeyFrame parsed {};
            parsed.eapolBytes = frame;
            parsed.eapolLength = bodyLength + kEapolHeaderBytes;
            parsed.nonce = nonce;
            parsed.keyRsc = body + kKeyRscOffset;
            parsed.mic = mic;
            parsed.keyData = body + kEapolKeyFixedBytes;
            parsed.keyDataLength = keyDataLength;
            parsed.keyInformation = info;
            parsed.keyLength = keyLength;
            parsed.replayCounter = replay;
            parsed.descriptorVersion = version;
            parsed.message = message;
            parsed.hasMic = hasMic;
            parsed.keyAck = ack;
            parsed.secure = secure;
            parsed.encryptedData = encryptedData;
            parsed.installationRequested = install;
            out = parsed;
            return EapolResult::Ok;
        }

        ReplayGuard::ReplayGuard()
            : phase_(HandshakePhase::Empty), latestReplayCounter_(0),
              initialAnonce_ {}
        {
        }

        void ReplayGuard::reset()
        {
            phase_ = HandshakePhase::Empty;
            latestReplayCounter_ = 0;
            for (uint8_t &byte : initialAnonce_)
            {
                byte = 0;
            }
        }

        EapolResult ReplayGuard::acceptMessage1(const KeyFrame &frame)
        {
            // A caller may not borrow its nonce or frame metadata from the
            // replay guard: advancing it would corrupt the still-read input.
            if (overlapsStorage(this, sizeof(*this), &frame, sizeof(frame)) ||
                overlapsStorage(this, sizeof(*this), frame.eapolBytes,
                                frame.eapolLength) ||
                overlapsStorage(this, sizeof(*this), frame.nonce,
                                kKeyNonceBytes))
            {
                return EapolResult::OverlappingBuffers;
            }
            // A public KeyFrame is not necessarily parser-created. In
            // particular, an all-zero authenticator nonce cannot become the
            // retained replay identity of a synthetically forged M1.
            if (frame.message != KeyMessage::Pairwise1 ||
                frame.keyInformation != kPairwise1Info ||
                frame.descriptorVersion != kKeyDescriptorVersion ||
                frame.keyLength != kCcmpKeyBytes || frame.hasMic ||
                !frame.keyAck || frame.secure || frame.encryptedData ||
                frame.installationRequested ||
                !replayMetadataMatchesWire(frame) ||
                // Unlike M3, M1 has no MIC. Do not trust an old parser result
                // if an untrusted RX buffer now contains nonzero MIC bytes.
                anyNonzero(frame.eapolBytes + kEapolHeaderBytes + kKeyMicOffset,
                           kKeyMicBytes) ||
                !anyNonzero(frame.nonce, kKeyNonceBytes))
            {
                return EapolResult::InvalidKeyInformation;
            }
            if (phase_ != HandshakePhase::Empty)
            {
                return EapolResult::InvalidState;
            }
            latestReplayCounter_ = frame.replayCounter;
            for (size_t i = 0; i < sizeof(initialAnonce_); ++i)
            {
                initialAnonce_[i] = frame.nonce[i];
            }
            phase_ = HandshakePhase::AwaitingMessage3;
            return EapolResult::Ok;
        }

        EapolResult ReplayGuard::acceptVerifiedMessage3(const KeyFrame &frame,
                                                        bool micVerified)
        {
            if (overlapsStorage(this, sizeof(*this), &frame, sizeof(frame)) ||
                overlapsStorage(this, sizeof(*this), frame.eapolBytes,
                                frame.eapolLength) ||
                overlapsStorage(this, sizeof(*this), frame.nonce,
                                kKeyNonceBytes))
            {
                return EapolResult::OverlappingBuffers;
            }
            if (phase_ != HandshakePhase::AwaitingMessage3 ||
                frame.message != KeyMessage::Pairwise3)
            {
                return EapolResult::InvalidState;
            }
            if (!micVerified)
            {
                return EapolResult::MicNotVerified;
            }
            // A caller's MIC-verification assertion cannot turn an M1-style
            // frame into a verified M3 without the parser-required Key Info
            // flags. Reject it before advancing the replay counter or phase.
            if (frame.keyInformation != kPairwise3Info ||
                frame.descriptorVersion != kKeyDescriptorVersion ||
                frame.keyLength != kCcmpKeyBytes || !frame.hasMic ||
                !frame.keyAck || !frame.secure || !frame.encryptedData ||
                !frame.installationRequested)
                return EapolResult::InvalidKeyInformation;
            if (frame.nonce == nullptr ||
                frame.replayCounter <= latestReplayCounter_)
            {
                return EapolResult::ReplayDetected;
            }
            if (!replayMetadataMatchesWire(frame))
                return EapolResult::InvalidKeyInformation;
            uint8_t difference = 0;
            for (size_t i = 0; i < sizeof(initialAnonce_); ++i)
            {
                difference |=
                    static_cast<uint8_t>(initialAnonce_[i] ^ frame.nonce[i]);
            }
            if (difference != 0)
            {
                return EapolResult::InvalidKeyInformation;
            }
            latestReplayCounter_ = frame.replayCounter;
            phase_ = HandshakePhase::Message3MicVerified;
            return EapolResult::Ok;
        }

    } // namespace ieee80211
} // namespace simpleath
