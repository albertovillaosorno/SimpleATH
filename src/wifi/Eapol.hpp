// SPDX-License-Identifier: AGPL-3.0-only
// WPA2 EAPOL-Key framing and replay screening. This is NOT a key engine:
// MIC validation, PTK derivation, AES key unwrap and hardware key installation
// require a separate reviewed crypto provider and real driver integration.
#ifndef SIMPLEATH_WIFI_EAPOL_HPP
#define SIMPLEATH_WIFI_EAPOL_HPP

#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    namespace ieee80211
    {

        constexpr size_t kEapolAnonceBytes = 32;

        enum class EapolResult : uint8_t
        {
            Ok,
            NullBuffer,
            TooShort,
            BadLength,
            UnsupportedVersion,
            UnsupportedType,
            UnsupportedCipher,
            InvalidKeyInformation,
            UnsupportedMessage,
            ReplayDetected,
            InvalidState,
            MicNotVerified,
            OverlappingBuffers,
        };

        enum class KeyMessage : uint8_t
        {
            Unknown,
            Pairwise1,
            Pairwise2,
            Pairwise3,
            Pairwise4,
            Group1,
            Group2,
        };

        struct KeyFrame
        {
                const uint8_t *eapolBytes;
                size_t eapolLength;
                const uint8_t *nonce;
                // Eight Key RSC octets borrowed from eapolBytes; CCMP GTK
                // receive PN is in octets 0..5, least significant first.
                const uint8_t *keyRsc;
                const uint8_t *mic;
                const uint8_t *keyData;
                uint16_t keyDataLength;
                uint16_t keyInformation;
                uint16_t keyLength;
                uint64_t replayCounter;
                uint8_t descriptorVersion;
                KeyMessage message;
                bool hasMic;
                bool keyAck;
                bool secure;
                bool encryptedData;
                bool installationRequested;
        };

        // KeyFrame borrows pointers into frame; the result object cannot
        // overlap those input bytes. On an overlap no input or output changes.
        // All other failures clear stale borrowed output pointers and metadata.
        EapolResult parseEapolKey(const uint8_t *frame, size_t length,
                                  KeyFrame &out);

        enum class HandshakePhase : uint8_t
        {
            Empty,
            AwaitingMessage3,
            Message3MicVerified,
        };

        // This is only a replay guard. A verified MIC is necessary for message
        // 3, but it is not sufficient to claim a completed WPA2 four-way
        // handshake. All borrowed frame fields must point into the same wire
        // image at their defined offsets, and neither the frame nor its
        // metadata may overlap this guard's persistent state.
        class ReplayGuard
        {
            public:
                ReplayGuard();
                void reset();
                EapolResult acceptMessage1(const KeyFrame &frame);
                EapolResult acceptVerifiedMessage3(const KeyFrame &frame,
                                                   bool micVerified);

                HandshakePhase phase() const
                {
                    return phase_;
                }

                uint64_t lastReplayCounter() const
                {
                    return latestReplayCounter_;
                }

            private:
                HandshakePhase phase_ {HandshakePhase::Empty};
                uint64_t latestReplayCounter_ {0};
                uint8_t initialAnonce_[kEapolAnonceBytes] {};
        };

    } // namespace ieee80211
} // namespace simpleath
#endif
