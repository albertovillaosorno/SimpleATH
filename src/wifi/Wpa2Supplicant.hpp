// SPDX-License-Identifier: AGPL-3.0-only
// WPA2-PSK/CCMP 4-way handshake state and key installation coordination.
// Cryptographic operations MUST use a reviewed OS/platform backend.
#ifndef SIMPLEATH_WIFI_WPA2_SUPPLICANT_HPP
#define SIMPLEATH_WIFI_WPA2_SUPPLICANT_HPP

#include "Eapol.hpp"
#include "Frames.hpp"

namespace simpleath
{
    namespace ieee80211
    {

        enum class Wpa2Result : uint8_t
        {
            Ok,
            InvalidArgument,
            InvalidState,
            MalformedEapol,
            WrongMessage,
            InvalidReplayCounter,
            CryptoProviderMissing,
            RandomFailure,
            KeyDerivationFailure,
            MicCalculationFailure,
            MicMismatch,
            GtkUnwrapFailure,
            GtkMissingOrMalformed,
            RsnMismatch,
            InvalidKeySequenceCounter,
            HardwareKeyInstallFailure,
            BufferTooSmall
        };

        enum class Wpa2State : uint8_t
        {
            Inactive,
            AwaitingMessage1,
            AwaitingMessage3,
            HardwareKeysInstalled,
            Failed
        };

        // Callbacks run synchronously under the station's serialized workloop.
        // The backend MUST implement the correct 802.11i PSK-CCMP algorithms:
        //
        //   derivePtk: "Pairwise key expansion" PRF-384 (HMAC-SHA1) over
        //              ordered AA/SPA and ANonce/SNonce; outputs KCK, KEK, TK.
        //   micSha1:   HMAC-SHA1-128 (16 bytes) over the complete EAPOL frame
        //              with the key MIC field cleared by this implementation.
        //   unwrapGtk: RFC3394 AES key unwrap using the KEK. Authenticate M3
        //              before decrypting it and reject an invalid integrity
        //              check.
        //
        // Credentials/PMK must be supplied by a separately authorized upper
        // layer. The radio must have completed safe EEPROM/PHY and regulatory
        // initialization. The platform must never expose keys to IORegistry or
        // debug logs.
        struct Wpa2Crypto
        {
                void *context;
                bool (*generateNonce)(void *context, uint8_t outNonce[32]);
                bool (*derivePtk)(void *context, const uint8_t pmk[32],
                                  const Mac &ap, const Mac &station,
                                  const uint8_t aNonce[32],
                                  const uint8_t sNonce[32], uint8_t ptk[48]);
                bool (*micSha1)(void *context, const uint8_t kck[16],
                                const uint8_t *eapol, size_t length,
                                uint8_t mic[16]);
                bool (*unwrapGtk)(void *context, const uint8_t kek[16],
                                  const uint8_t *wrapped, size_t wrappedLength,
                                  uint8_t *out, size_t capacity,
                                  size_t *resultLength);
                bool (*installPairwiseTk)(void *context, const Mac &ap,
                                          const uint8_t tk[16]);
                // M3's MIC-authenticated Key RSC must seed the GTK receive
                // PN/replay state; refuse success if hardware cannot do so.
                bool (*installGroupGtk)(void *context, uint8_t keyId,
                                        const uint8_t gtk[16],
                                        const uint8_t keyRsc[8]);
                // Must roll back even partially programmed pairwise/group
                // slots when an install callback returns false. Idempotent
                // after partial writes, before the first successful install.
                void (*removeInstalledKeys)(void *context);
        };

        // Only the EAPOL handshake, NOT encryption of MPDUs, CCMP packet
        // numbers, Wi-Fi registration, DHCP or hardware RX/TX, is modeled here.
        class Wpa2Supplicant
        {
            public:
                Wpa2Supplicant();
                ~Wpa2Supplicant();
                Wpa2Supplicant(const Wpa2Supplicant &) = delete;
                Wpa2Supplicant &operator=(const Wpa2Supplicant &) = delete;

                // Use the exact validated BSS RSNE (ID, length, payload)
                // from Beacon/Probe Response to bind M3 to the association.
                // Credential/RSNE sources and callback metadata/context must
                // not alias this state or one another's writable context.
                Wpa2Result begin(const Wpa2Crypto &crypto, const Mac &station,
                                 const Mac &ap, const uint8_t pmk[32],
                                 const uint8_t *expectedRsnIe,
                                 size_t expectedRsnIeLength);
                // AP source/BSSID and 802.11 decryption/CRC must be verified
                // externally. The RX frame, TX buffer, written reference,
                // supplicant state and retained crypto context must be
                // disjoint. Detectable aliases return InvalidArgument without
                // modifying any output or invoking a crypto callback; the
                // owner guarantees the complete opaque callback allocation
                // cannot alias either buffer.
                Wpa2Result onMessage1(const uint8_t *eapol, size_t length,
                                      uint8_t *outMessage2, size_t capacity,
                                      size_t &written);
                Wpa2Result onMessage3(const uint8_t *eapol, size_t length,
                                      uint8_t *outMessage4, size_t capacity,
                                      size_t &written);
                // The owner calls reset before its crypto and PCI contexts are
                // released.
                void reset();

                Wpa2State state() const
                {
                    return state_;
                }

                bool keysInstalled() const
                {
                    return state_ == Wpa2State::HardwareKeysInstalled;
                }

            private:
                Wpa2Result fail(Wpa2Result error);
                static void secureClear(uint8_t *ptr, size_t length);
                Wpa2State state_;
                Wpa2Crypto crypto_;
                ReplayGuard replay_;
                Mac station_;
                Mac ap_;
                uint8_t pmk_[32];
                uint8_t ptk_[48];
                uint8_t snonce_[32];
                uint8_t expectedRsnIe_[257];
                size_t expectedRsnIeLength_;
                uint8_t eapolVersion_;
                bool keyInstallAttempted_;
        };

    } // namespace ieee80211
} // namespace simpleath
#endif
