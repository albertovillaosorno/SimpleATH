// SPDX-License-Identifier: AGPL-3.0-only
#include "Eapol.hpp"

namespace simpleath
{
    namespace ieee80211
    {
        namespace
        {
            uint16_t readBig16(const uint8_t *bytes)
            {
                return static_cast<uint16_t>(static_cast<uint16_t>(bytes[0])
                                             << 8u) |
                       static_cast<uint16_t>(bytes[1]);
            }

            uint64_t readBig64(const uint8_t *bytes)
            {
                uint64_t result = 0;
                for (size_t i = 0; i < 8; ++i)
                    result = (result << 8u) | bytes[i];
                return result;
            }

            bool anyNonzero(const uint8_t *bytes, size_t length)
            {
                uint8_t aggregate = 0;
                for (size_t i = 0; i < length; ++i)
                    aggregate |= bytes[i];
                return aggregate != 0;
            }
        } // namespace

        EapolResult parseEapolKey(const uint8_t *frame, size_t length,
                                  KeyFrame &out)
        {
            if (!frame)
                return EapolResult::NullBuffer;
            if (length < 4)
                return EapolResult::TooShort;
            if (frame[0] < 1 || frame[0] > 3)
                return EapolResult::UnsupportedVersion;
            if (frame[1] != 3)
                return EapolResult::UnsupportedType;

            const size_t bodyLength = readBig16(frame + 2);
            if (bodyLength > 2048u || bodyLength > length - 4)
                return EapolResult::BadLength;
            // EAPOL-Key fixed portion = 95 bytes after the EAPOL header.
            if (bodyLength < 95)
                return EapolResult::TooShort;
            const uint8_t *body = frame + 4;
            if (body[0] != 2)
                return EapolResult::UnsupportedCipher;
            const uint16_t info = readBig16(body + 1);
            const uint8_t version = static_cast<uint8_t>(info & 7u);
            if (version != 2)
            {
                // WPA2-PSK CCMP uses HMAC-SHA1-128 key descriptor version 2.
                // TKIP and AES-CMAC descriptor semantics are not implemented
                // here.
                return EapolResult::UnsupportedCipher;
            }
            const uint16_t keyLength = readBig16(body + 3);
            const uint64_t replay = readBig64(body + 5);
            const uint8_t *nonce = body + 13;
            const uint8_t *mic = body + 77;
            const uint16_t keyDataLength = readBig16(body + 93);
            if (keyDataLength > bodyLength - 95u ||
                bodyLength != static_cast<size_t>(95u + keyDataLength))
                return EapolResult::BadLength;

            const bool pairwise = (info & 0x0008u) != 0;
            const bool install = (info & 0x0040u) != 0;
            const bool ack = (info & 0x0080u) != 0;
            const bool hasMic = (info & 0x0100u) != 0;
            const bool secure = (info & 0x0200u) != 0;
            const bool error = (info & 0x0400u) != 0;
            const bool request = (info & 0x0800u) != 0;
            const bool encryptedData = (info & 0x1000u) != 0;
            // RSN does not use the legacy Key Index, SMK/PeerKey, or
            // reserved Key Information bits in this PSK-CCMP handshake.
            // An unset MIC flag also requires an all-zero MIC field.
            constexpr uint16_t kUnsupportedInfo = 0xe030u;
            if (error || request || (info & kUnsupportedInfo) != 0 ||
                hasMic != anyNonzero(mic, 16))
                return EapolResult::InvalidKeyInformation;

            KeyMessage message = KeyMessage::Unknown;
            if (pairwise)
            {
                if (ack && !hasMic && !install && !secure && !encryptedData &&
                    anyNonzero(nonce, 32))
                    message = KeyMessage::Pairwise1;
                else if (!ack && hasMic && !install && !secure &&
                         !encryptedData)
                    message = KeyMessage::Pairwise2;
                else if (ack && hasMic && install && secure && encryptedData)
                    message = KeyMessage::Pairwise3;
                else if (!ack && hasMic && !install && secure && !encryptedData)
                    message = KeyMessage::Pairwise4;
            }
            else
            {
                if (ack && hasMic && !install && secure && encryptedData)
                    message = KeyMessage::Group1;
                else if (!ack && hasMic && !install && secure && !encryptedData)
                    message = KeyMessage::Group2;
            }
            if (message == KeyMessage::Unknown)
                return EapolResult::UnsupportedMessage;

            KeyFrame parsed {};
            parsed.eapolBytes = frame;
            parsed.eapolLength = bodyLength + 4;
            parsed.nonce = nonce;
            parsed.keyRsc = body + 61u;
            parsed.mic = mic;
            parsed.keyData = body + 95;
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
            for (size_t i = 0; i < sizeof(initialAnonce_); ++i)
                initialAnonce_[i] = 0;
        }

        EapolResult ReplayGuard::acceptMessage1(const KeyFrame &frame)
        {
            if (frame.message != KeyMessage::Pairwise1 || !frame.nonce)
                return EapolResult::InvalidKeyInformation;
            if (phase_ != HandshakePhase::Empty)
                return EapolResult::InvalidState;
            latestReplayCounter_ = frame.replayCounter;
            for (size_t i = 0; i < sizeof(initialAnonce_); ++i)
                initialAnonce_[i] = frame.nonce[i];
            phase_ = HandshakePhase::AwaitingMessage3;
            return EapolResult::Ok;
        }

        EapolResult ReplayGuard::acceptVerifiedMessage3(const KeyFrame &frame,
                                                        bool micVerified)
        {
            if (phase_ != HandshakePhase::AwaitingMessage3 ||
                frame.message != KeyMessage::Pairwise3)
                return EapolResult::InvalidState;
            if (!micVerified)
                return EapolResult::MicNotVerified;
            if (!frame.nonce || frame.replayCounter <= latestReplayCounter_)
                return EapolResult::ReplayDetected;
            uint8_t difference = 0;
            for (size_t i = 0; i < sizeof(initialAnonce_); ++i)
                difference |=
                    static_cast<uint8_t>(initialAnonce_[i] ^ frame.nonce[i]);
            if (difference != 0)
                return EapolResult::InvalidKeyInformation;
            latestReplayCounter_ = frame.replayCounter;
            phase_ = HandshakePhase::Message3MicVerified;
            return EapolResult::Ok;
        }

    } // namespace ieee80211
} // namespace simpleath
