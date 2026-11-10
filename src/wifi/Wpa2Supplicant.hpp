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
        constexpr size_t kWpa2PmkBytes = 32;
        constexpr size_t kWpa2PtkBytes = 48;
        constexpr size_t kWpa2NonceBytes = kEapolAnonceBytes;
        constexpr size_t kWpa2KeyBytes = 16;
        constexpr size_t kWpa2KeyRscBytes = 8;

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
            BufferTooSmall,
        };

        enum class Wpa2State : uint8_t
        {
            Inactive,
            AwaitingMessage1,
            AwaitingMessage3,
            HardwareKeysInstalled,
            Failed,
            ProcessingMessage1,
            ProcessingMessage3,
            ProcessingGroupMessage1,
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
                bool (*generateNonce)(void *context,
                                      uint8_t outNonce[kWpa2NonceBytes]);
                bool (*derivePtk)(void *context,
                                  const uint8_t pmk[kWpa2PmkBytes],
                                  const Mac &ap, const Mac &station,
                                  const uint8_t aNonce[kWpa2NonceBytes],
                                  const uint8_t sNonce[kWpa2NonceBytes],
                                  uint8_t ptk[kWpa2PtkBytes]);
                bool (*micSha1)(void *context, const uint8_t kck[kWpa2KeyBytes],
                                const uint8_t *eapol, size_t length,
                                uint8_t mic[kWpa2KeyBytes]);
                bool (*unwrapGtk)(void *context,
                                  const uint8_t kek[kWpa2KeyBytes],
                                  const uint8_t *wrapped, size_t wrappedLength,
                                  uint8_t *out, size_t capacity,
                                  size_t *resultLength);
                bool (*installPairwiseTk)(void *context, const Mac &ap,
                                          const uint8_t tk[kWpa2KeyBytes]);
                // M3's MIC-authenticated Key RSC must seed the GTK receive
                // PN/replay state; refuse success if hardware cannot do so.
                bool (*installGroupGtk)(void *context, uint8_t keyId,
                                        const uint8_t gtk[kWpa2KeyBytes],
                                        const uint8_t keyRsc[kWpa2KeyRscBytes]);
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
                Wpa2Supplicant(Wpa2Supplicant &&) = delete;
                Wpa2Supplicant &operator=(Wpa2Supplicant &&) = delete;

                // Use the exact validated BSS RSNE (ID, length, payload)
                // from Beacon/Probe Response to bind M3 to the association.
                // Credential/RSNE sources and callback metadata/context must
                // not alias this state or one another's writable context.
                Wpa2Result begin(const Wpa2Crypto &crypto, const Mac &station,
                                 const Mac &ap,
                                 const uint8_t pmk[kWpa2PmkBytes],
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
                // After the four-way handshake, authenticate a protected
                // Group Key Handshake message 1 and install its GTK. The
                // resulting Group2 EAPOL frame MUST be sent through a real
                // CCMP-protected data path with an installed pairwise TK;
                // never transmit it in cleartext. Failed output submission
                // requires the owner to reset and revoke keys.
                Wpa2Result onGroupMessage1(const uint8_t *eapol, size_t length,
                                           uint8_t *outGroup2, size_t capacity,
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

                // An installed keycache is bound to one station/AP identity.
                // Public consumers must not treat another link's handshake as
                // authorization for their own station data path.
                bool keysInstalledFor(const Mac &station, const Mac &ap) const
                {
                    return keysInstalled() && sameMac(station, station_) &&
                           sameMac(ap, ap_);
                }

            private:
                Wpa2Result fail(Wpa2Result error);
                static void secureClear(uint8_t *ptr, size_t length);
                Wpa2State state_ {Wpa2State::Inactive};
                Wpa2Crypto crypto_ {};
                ReplayGuard replay_;
                Mac station_ {};
                Mac ap_ {};
                uint8_t pmk_[kWpa2PmkBytes] {};
                uint8_t ptk_[kWpa2PtkBytes] {};
                uint8_t snonce_[kWpa2NonceBytes] {};
                uint8_t expectedRsnIe_[kMaxRsnIeBytes] {};
                size_t expectedRsnIeLength_ {0};
                uint8_t eapolVersion_ {0};
                bool keyInstallAttempted_ {false};
                uint64_t lastGroupReplayCounter_ {0};
                // Reset/begin revoke callbacks from an earlier handshake even
                // when a provider reenters reset()+begin() before returning.
                uint64_t sessionEpoch_ {0};
        };

    } // namespace ieee80211
} // namespace simpleath
#endif
