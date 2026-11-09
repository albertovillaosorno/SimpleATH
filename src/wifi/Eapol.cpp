// SPDX-License-Identifier: AGPL-3.0-only
#include "Eapol.hpp"

#include <cstddef>
#include <cstdint>

namespace simpleath
{
    namespace ieee80211
    {
        static constexpr size_t K_EAPOL_HEADER_BYTES = 4;
        static constexpr size_t K_EAPOL_KEY_FIXED_BYTES = 95;
        static constexpr size_t K_MAX_EAPOL_BODY_BYTES = 2048;
        static constexpr size_t K_KEY_NONCE_BYTES = 32;
        static constexpr size_t K_KEY_MIC_BYTES = 16;
        static constexpr size_t K_KEY_RSC_OFFSET = 61;
        static constexpr size_t K_KEY_NONCE_OFFSET = 13;
        static constexpr size_t K_KEY_MIC_OFFSET = 77;
        static constexpr uint8_t K_KEY_DESCRIPTOR_TYPE = 2;
        static constexpr uint8_t K_KEY_DESCRIPTOR_VERSION = 2;
        static constexpr uint16_t K_UNSUPPORTED_INFO = 0xe030U;
        static constexpr uint32_t K_BITS_PER_BYTE = 8;
        static constexpr size_t K_REPLAY_COUNTER_BYTES = 8;
        static constexpr size_t K_KEY_DATA_LENGTH_OFFSET = 93;
        static constexpr uint8_t K_EAPOL_KEY_PACKET_TYPE = 3;
        // Exact WPA2-PSK CCMP M1/M3 Key Information masks: RSN version 2,
        // pairwise, ACK and M3-only install/MIC/secure/encrypted bits.
        static constexpr uint16_t K_PAIRWISE_1_INFO = 0x008aU;
        static constexpr uint16_t K_PAIRWISE_3_INFO = 0x13caU;
        static constexpr uint16_t K_CCMP_KEY_BYTES = 16;

        static uint16_t read_big16(const uint8_t *const bytes)
        {
            return static_cast<uint16_t>(static_cast<uint16_t>(bytes[0])
                                         << K_BITS_PER_BYTE) |
                   static_cast<uint16_t>(bytes[1]);
        }

        static uint64_t read_big64(const uint8_t *const bytes)
        {
            uint64_t result = 0;
            for (size_t i = 0; i < K_REPLAY_COUNTER_BYTES; ++i)
            {
                result = (result << K_BITS_PER_BYTE) | bytes[i];
            }
            return result;
        }

        static bool any_nonzero(const uint8_t *const bytes, size_t length)
        {
            uint8_t aggregate = 0;
            for (size_t i = 0; i < length; ++i)
            {
                aggregate |= bytes[i];
            }
            return aggregate != 0;
        }

        static bool overlaps_storage(const void *const first_buffer,
                                     size_t first_bytes,
                                     const void *const second_buffer,
                                     size_t second_bytes)
        {
            if (!first_buffer || !second_buffer || !first_bytes ||
                !second_bytes)
            {
                return false;
            }
            const auto first = reinterpret_cast<uintptr_t>(first_buffer);
            const auto second = reinterpret_cast<uintptr_t>(second_buffer);
            return first <= second ? second - first < first_bytes
                                   : first - second < second_bytes;
        }

        static bool at_wire_offset(const uint8_t *const frame,
                                   const uint8_t *const field, size_t offset)
        {
            const auto origin = reinterpret_cast<uintptr_t>(frame);
            const auto location = reinterpret_cast<uintptr_t>(field);
            return location >= origin && location - origin == offset;
        }

        static bool replay_metadata_matches_wire(const KeyFrame &frame)
        {
            // ReplayGuard accepts public, caller-built KeyFrame values. Keep
            // every borrowed subfield and the scalar replay/key fields tied
            // to the same bounded EAPOL image, not detached caller storage.
            // The M3 MIC bytes may already be zeroed for verification, so
            // never reparse the whole packet at this stage.
            if (frame.eapolBytes == nullptr || frame.nonce == nullptr ||
                frame.eapolLength <
                    K_EAPOL_HEADER_BYTES + K_EAPOL_KEY_FIXED_BYTES ||
                frame.eapolLength >
                    K_EAPOL_HEADER_BYTES + K_MAX_EAPOL_BODY_BYTES)
                return false;
            if (!at_wire_offset(frame.eapolBytes, frame.nonce,
                                K_EAPOL_HEADER_BYTES + K_KEY_NONCE_OFFSET) ||
                !at_wire_offset(frame.eapolBytes, frame.keyRsc,
                                K_EAPOL_HEADER_BYTES + K_KEY_RSC_OFFSET) ||
                !at_wire_offset(frame.eapolBytes, frame.mic,
                                K_EAPOL_HEADER_BYTES + K_KEY_MIC_OFFSET) ||
                !at_wire_offset(frame.eapolBytes, frame.keyData,
                                K_EAPOL_HEADER_BYTES + K_EAPOL_KEY_FIXED_BYTES))
                return false;
            // A fabricated KeyFrame must not approve a mismatched fixed
            // EAPOL-Key body/key-data length that the parser would reject.
            // This also prevents an undeclared suffix from entering the public
            // replay transition as if it were part of a parsed key packet.
            if (frame.eapolLength - K_EAPOL_HEADER_BYTES !=
                K_EAPOL_KEY_FIXED_BYTES + frame.keyDataLength)
                return false;
            const uint8_t *const bytes = frame.eapolBytes;
            if (bytes[0] < 1 || bytes[0] > 3 ||
                bytes[1] != K_EAPOL_KEY_PACKET_TYPE ||
                bytes[K_EAPOL_HEADER_BYTES] != K_KEY_DESCRIPTOR_TYPE ||
                static_cast<size_t>(read_big16(bytes + 2)) +
                        K_EAPOL_HEADER_BYTES !=
                    frame.eapolLength)
                return false;
            return read_big16(bytes + K_EAPOL_HEADER_BYTES + 1) ==
                       frame.keyInformation &&
                   read_big16(bytes + K_EAPOL_HEADER_BYTES + 3) ==
                       frame.keyLength &&
                   read_big64(bytes + K_EAPOL_HEADER_BYTES + 5) ==
                       frame.replayCounter &&
                   read_big16(bytes + K_EAPOL_HEADER_BYTES +
                              K_KEY_DATA_LENGTH_OFFSET) == frame.keyDataLength;
        }

        EapolResult parseEapolKey(const uint8_t *const frame, size_t length,
                                  KeyFrame &out)
        {
            // A borrowed EAPOL-Key frame must not be overwritten with parsed
            // metadata: the MIC, nonce and replay counter still refer to it.
            if (overlaps_storage(frame, length, &out, sizeof(out)))
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
            if (length < K_EAPOL_HEADER_BYTES)
            {
                return EapolResult::TooShort;
            }
            if (frame[0] < 1 || frame[0] > 3)
            {
                return EapolResult::UnsupportedVersion;
            }
            if (frame[1] != K_EAPOL_KEY_PACKET_TYPE)
            {
                return EapolResult::UnsupportedType;
            }

            const size_t body_length = read_big16(frame + 2);
            if (body_length > K_MAX_EAPOL_BODY_BYTES ||
                body_length > length - K_EAPOL_HEADER_BYTES)
            {
                return EapolResult::BadLength;
            }
            // EAPOL-Key fixed portion = 95 bytes after the EAPOL header.
            if (body_length < K_EAPOL_KEY_FIXED_BYTES)
            {
                return EapolResult::TooShort;
            }
            const uint8_t *const body = frame + K_EAPOL_HEADER_BYTES;
            if (body[0] != K_KEY_DESCRIPTOR_TYPE)
            {
                return EapolResult::UnsupportedCipher;
            }
            const uint16_t info = read_big16(body + 1);
            const auto version = static_cast<uint8_t>(info & 7U);
            if (version != K_KEY_DESCRIPTOR_VERSION)
            {
                // WPA2-PSK CCMP uses HMAC-SHA1-128 key descriptor version 2.
                // TKIP and AES-CMAC descriptor semantics are not implemented
                // here.
                return EapolResult::UnsupportedCipher;
            }
            const uint16_t key_length = read_big16(body + 3);
            const uint64_t replay = read_big64(body + 5);
            const uint8_t *const nonce = body + K_KEY_NONCE_OFFSET;
            const uint8_t *const mic = body + K_KEY_MIC_OFFSET;
            const uint16_t key_data_length =
                read_big16(body + K_KEY_DATA_LENGTH_OFFSET);
            if (key_data_length > body_length - K_EAPOL_KEY_FIXED_BYTES ||
                body_length != static_cast<size_t>(K_EAPOL_KEY_FIXED_BYTES +
                                                   key_data_length))
            {
                return EapolResult::BadLength;
            }

            const bool pairwise = (info & 0x0008U) != 0;
            const bool install = (info & 0x0040U) != 0;
            const bool ack = (info & 0x0080U) != 0;
            const bool has_mic = (info & 0x0100U) != 0;
            const bool secure = (info & 0x0200U) != 0;
            const bool error = (info & 0x0400U) != 0;
            const bool request = (info & 0x0800U) != 0;
            const bool encrypted_data = (info & 0x1000U) != 0;
            // RSN does not use the legacy Key Index, SMK/PeerKey, or
            // reserved Key Information bits in this PSK-CCMP handshake.
            // An unset MIC flag also requires an all-zero MIC field.
            if (error || request || (info & K_UNSUPPORTED_INFO) != 0 ||
                has_mic != any_nonzero(mic, K_KEY_MIC_BYTES))
            {
                return EapolResult::InvalidKeyInformation;
            }

            KeyMessage message = KeyMessage::Unknown;
            if (pairwise)
            {
                if (ack && !has_mic && !install && !secure && !encrypted_data &&
                    any_nonzero(nonce, K_KEY_NONCE_BYTES))
                {
                    message = KeyMessage::Pairwise1;
                }
                else if (!ack && has_mic && !install && !secure &&
                         !encrypted_data)
                {
                    message = KeyMessage::Pairwise2;
                }
                else if (ack && has_mic && install && secure && encrypted_data)
                {
                    message = KeyMessage::Pairwise3;
                }
                else if (!ack && has_mic && !install && secure &&
                         !encrypted_data)
                {
                    message = KeyMessage::Pairwise4;
                }
            }
            else
            {
                if (ack && has_mic && !install && secure && encrypted_data)
                {
                    message = KeyMessage::Group1;
                }
                else if (!ack && has_mic && !install && secure &&
                         !encrypted_data)
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
            if (pairwise && (key_length != (ack ? K_CCMP_KEY_BYTES : 0u) ||
                             (message == KeyMessage::Pairwise2 &&
                              !any_nonzero(nonce, K_KEY_NONCE_BYTES))))
            {
                return EapolResult::InvalidKeyInformation;
            }

            KeyFrame parsed {};
            parsed.eapolBytes = frame;
            parsed.eapolLength = body_length + K_EAPOL_HEADER_BYTES;
            parsed.nonce = nonce;
            parsed.keyRsc = body + K_KEY_RSC_OFFSET;
            parsed.mic = mic;
            parsed.keyData = body + K_EAPOL_KEY_FIXED_BYTES;
            parsed.keyDataLength = key_data_length;
            parsed.keyInformation = info;
            parsed.keyLength = key_length;
            parsed.replayCounter = replay;
            parsed.descriptorVersion = version;
            parsed.message = message;
            parsed.hasMic = has_mic;
            parsed.keyAck = ack;
            parsed.secure = secure;
            parsed.encryptedData = encrypted_data;
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
            if (overlaps_storage(this, sizeof(*this), &frame, sizeof(frame)) ||
                overlaps_storage(this, sizeof(*this), frame.eapolBytes,
                                 frame.eapolLength) ||
                overlaps_storage(this, sizeof(*this), frame.nonce,
                                 K_KEY_NONCE_BYTES))
            {
                return EapolResult::OverlappingBuffers;
            }
            // A public KeyFrame is not necessarily parser-created. In
            // particular, an all-zero authenticator nonce cannot become the
            // retained replay identity of a synthetically forged M1.
            if (frame.message != KeyMessage::Pairwise1 ||
                frame.keyInformation != K_PAIRWISE_1_INFO ||
                frame.descriptorVersion != K_KEY_DESCRIPTOR_VERSION ||
                frame.keyLength != K_CCMP_KEY_BYTES || frame.hasMic ||
                !frame.keyAck || frame.secure || frame.encryptedData ||
                frame.installationRequested ||
                !replay_metadata_matches_wire(frame) ||
                // Unlike M3, M1 has no MIC. Do not trust an old parser result
                // if an untrusted RX buffer now contains nonzero MIC bytes.
                any_nonzero(frame.eapolBytes + K_EAPOL_HEADER_BYTES +
                                K_KEY_MIC_OFFSET,
                            K_KEY_MIC_BYTES) ||
                !any_nonzero(frame.nonce, K_KEY_NONCE_BYTES))
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
                                                        bool mic_verified)
        {
            if (overlaps_storage(this, sizeof(*this), &frame, sizeof(frame)) ||
                overlaps_storage(this, sizeof(*this), frame.eapolBytes,
                                 frame.eapolLength) ||
                overlaps_storage(this, sizeof(*this), frame.nonce,
                                 K_KEY_NONCE_BYTES))
            {
                return EapolResult::OverlappingBuffers;
            }
            if (phase_ != HandshakePhase::AwaitingMessage3 ||
                frame.message != KeyMessage::Pairwise3)
            {
                return EapolResult::InvalidState;
            }
            if (!mic_verified)
            {
                return EapolResult::MicNotVerified;
            }
            // A caller's MIC-verification assertion cannot turn an M1-style
            // frame into a verified M3 without the parser-required Key Info
            // flags. Reject it before advancing the replay counter or phase.
            if (frame.keyInformation != K_PAIRWISE_3_INFO ||
                frame.descriptorVersion != K_KEY_DESCRIPTOR_VERSION ||
                frame.keyLength != K_CCMP_KEY_BYTES || !frame.hasMic ||
                !frame.keyAck || !frame.secure || !frame.encryptedData ||
                !frame.installationRequested)
                return EapolResult::InvalidKeyInformation;
            if (frame.nonce == nullptr ||
                frame.replayCounter <= latestReplayCounter_)
            {
                return EapolResult::ReplayDetected;
            }
            if (!replay_metadata_matches_wire(frame))
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
