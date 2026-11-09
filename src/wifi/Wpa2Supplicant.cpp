// SPDX-License-Identifier: AGPL-3.0-only
#include "Wpa2Supplicant.hpp"

namespace simpleath
{
    namespace ieee80211
    {
        namespace
        {
            constexpr size_t kEapolHeaderBytes = 4;
            constexpr size_t kKeyFixedBytes = 95;
            constexpr size_t kMessage4Length =
                kEapolHeaderBytes + kKeyFixedBytes;
            constexpr size_t kRsnIeBytes = 22;
            constexpr size_t kMessage2Length = kMessage4Length + kRsnIeBytes;
            constexpr size_t kMaximumEapolHandshakeBytes = 1024;
            constexpr size_t kMaximumGtkPlaintext = 512;
            const uint8_t kRsnCcmpPskIe[kRsnIeBytes] = {
                48, 20,                   // RSN element header; version 1.
                1,  0,  0, 0x0f, 0xac, 4, // Group cipher: CCMP.
                1,  0,  0, 0x0f, 0xac, 4, // Pairwise cipher: CCMP.
                1,  0,  0, 0x0f, 0xac, 2, // Key management: PSK.
                0,  0 // RSN capabilities: PMF not negotiated.
            };

            // Crypto callbacks may reset and restart this owner. Keep the
            // previous session's secret inputs in zeroized call-local storage
            // so revoked callbacks cannot borrow newly installed credentials.
            template <size_t N> struct ScopedSecret
            {
                    uint8_t bytes[N] {};
                    ScopedSecret() = default;
                    ScopedSecret(const ScopedSecret &) = delete;
                    ScopedSecret &operator=(const ScopedSecret &) = delete;

                    ~ScopedSecret()
                    {
                        volatile uint8_t *out = bytes;
                        for (size_t i = 0; i < N; ++i)
                            out[i] = 0;
                    }
            };

            void copyBytes(uint8_t *destination, const uint8_t *source,
                           size_t count)
            {
                for (size_t i = 0; i < count; ++i)
                    destination[i] = source[i];
            }

            void putBig16(uint8_t *buffer, uint16_t value)
            {
                buffer[0] = static_cast<uint8_t>(value >> 8u);
                buffer[1] = static_cast<uint8_t>(value);
            }

            void putBig64(uint8_t *buffer, uint64_t value)
            {
                for (size_t i = 0; i < 8; ++i)
                {
                    buffer[7u - i] = static_cast<uint8_t>(value);
                    value >>= 8u;
                }
            }

            bool constantTimeEqual(const uint8_t *left, const uint8_t *right,
                                   size_t count)
            {
                uint8_t mismatch = 0;
                for (size_t i = 0; i < count; ++i)
                    mismatch |= static_cast<uint8_t>(left[i] ^ right[i]);
                return mismatch == 0;
            }

            bool nonzero(const uint8_t *value, size_t count)
            {
                uint8_t aggregate = 0;
                for (size_t i = 0; i < count; ++i)
                    aggregate |= value[i];
                return aggregate != 0;
            }

            bool overlaps(const void *a, size_t aBytes, const void *b,
                          size_t bBytes)
            {
                if (!a || !b || !aBytes || !bBytes)
                    return false;
                const auto first = reinterpret_cast<uintptr_t>(a);
                const auto second = reinterpret_cast<uintptr_t>(b);
                return first <= second ? second - first < aBytes
                                       : first - second < bBytes;
            }

            // No borrowed credential/association bytes may alias a live
            // supplicant. begin() installs callbacks and copies secrets; an
            // overlapping source could be rewritten during that transition.
            // A callback context also cannot start in any borrowed argument;
            // the owner ensures its complete allocation is disjoint.
            bool beginInputsDisjoint(const void *owner, size_t ownerBytes,
                                     const Wpa2Crypto &crypto,
                                     const Mac &station, const Mac &ap,
                                     const uint8_t *pmk, const uint8_t *rsn,
                                     size_t rsnBytes)
            {
                struct Span
                {
                        const void *address;
                        size_t bytes;
                };

                const Span inputs[] = {{&crypto, sizeof(crypto)},
                                       {&station, sizeof(station)},
                                       {&ap, sizeof(ap)},
                                       {pmk, 32},
                                       {rsn, rsnBytes}};
                if (overlaps(crypto.context, 1, owner, ownerBytes))
                    return false;
                for (const Span &input : inputs)
                {
                    if (overlaps(input.address, input.bytes, owner,
                                 ownerBytes) ||
                        overlaps(input.address, input.bytes, crypto.context, 1))
                        return false;
                }
                return true;
            }

            // The RX frame can be DMA-owned and written is a caller-supplied
            // reference. Reject aliases before written=0 or any crypto/state
            // transition, including an opaque callback context starting in
            // writable storage. Its full allocation remains an owner contract.
            bool handshakeIoDisjoint(const void *owner, size_t ownerBytes,
                                     const void *context, const uint8_t *eapol,
                                     size_t length, const uint8_t *out,
                                     size_t capacity, const size_t &written)
            {
                return !overlaps(&written, sizeof(written), eapol, length) &&
                       !overlaps(&written, sizeof(written), out, capacity) &&
                       !overlaps(&written, sizeof(written), owner,
                                 ownerBytes) &&
                       !overlaps(&written, sizeof(written), context, 1) &&
                       !overlaps(out, capacity, eapol, length) &&
                       !overlaps(out, capacity, owner, ownerBytes) &&
                       !overlaps(out, capacity, context, 1) &&
                       !overlaps(eapol, length, owner, ownerBytes) &&
                       !overlaps(eapol, length, context, 1);
            }

            void populateEapolKey(uint8_t *message, size_t length,
                                  uint8_t version, uint16_t keyInfo,
                                  uint64_t replayCounter, const uint8_t *nonce)
            {
                for (size_t i = 0; i < length; ++i)
                    message[i] = 0;
                message[0] = version;
                message[1] = 3; // IEEE 802.1X EAPOL-Key.
                putBig16(message + 2, static_cast<uint16_t>(length - 4u));
                uint8_t *body = message + kEapolHeaderBytes;
                body[0] = 2; // RSN key descriptor.
                putBig16(body + 1, keyInfo);
                // The Supplicant's M2/M4 Key Length is zero (IEEE 802.11);
                // only Authenticator M1/M3 carry the CCMP TK length of 16.
                putBig16(body + 3, 0);
                putBig64(body + 5, replayCounter);
                if (nonce)
                    copyBytes(body + 13, nonce, 32);
                putBig16(body + 93,
                         static_cast<uint16_t>(length - kMessage4Length));
            }

            Wpa2Result parseM3KeyData(const uint8_t *plaintext, size_t length,
                                      const uint8_t *expectedRsnIe,
                                      size_t expectedRsnIeLength,
                                      uint8_t &keyId, uint8_t gtk[16])
            {
                bool foundGtk = false;
                bool foundRsn = false;
                size_t offset = 0;
                while (offset < length)
                {
                    // IEEE 802.11 AES-wrap padding is 0xdd, then zero octets.
                    // Do not confuse a vendor KDE with nonzero data for
                    // padding.
                    if (plaintext[offset] == 0xdd)
                    {
                        bool padding = true;
                        for (size_t i = offset + 1; i < length; ++i)
                            padding = padding && plaintext[i] == 0;
                        if (padding)
                            break;
                    }
                    if (length - offset < 2)
                        return Wpa2Result::GtkMissingOrMalformed;
                    const uint8_t tag = plaintext[offset];
                    const size_t size = plaintext[offset + 1];
                    offset += 2;
                    if (size > length - offset)
                        return Wpa2Result::GtkMissingOrMalformed;
                    const uint8_t *element = plaintext + offset;
                    if (tag == 48)
                    {
                        // M3 must reproduce the associated BSS's RSNE; do not
                        // install keys for a changed suite/AKM/PMF policy.
                        if (foundRsn || size + 2u != expectedRsnIeLength ||
                            expectedRsnIe[0] != tag ||
                            expectedRsnIe[1] != size ||
                            !constantTimeEqual(element, expectedRsnIe + 2u,
                                               size))
                            return Wpa2Result::RsnMismatch;
                        foundRsn = true;
                    }
                    else if (tag == 221 && size >= 4 && element[0] == 0 &&
                             element[1] == 0x0f && element[2] == 0xac &&
                             element[3] == 1)
                    {
                        // CCMP GTK KDE: OUI(3), type(1), key-id(1),
                        // reserved(1), 16-byte GTK. Reject
                        // duplicate/short/malformed KDEs.
                        if (foundGtk || size != 22 || element[5] != 0)
                            return Wpa2Result::GtkMissingOrMalformed;
                        keyId = static_cast<uint8_t>(element[4] & 3u);
                        if ((element[4] & 0xfcu) != 0)
                            return Wpa2Result::GtkMissingOrMalformed;
                        copyBytes(gtk, element + 6, 16);
                        foundGtk = true;
                    }
                    offset += size;
                }
                if (!foundRsn)
                    return Wpa2Result::RsnMismatch;
                return foundGtk ? Wpa2Result::Ok
                                : Wpa2Result::GtkMissingOrMalformed;
            }
        } // namespace

        Wpa2Supplicant::Wpa2Supplicant()
            : state_(Wpa2State::Inactive), crypto_ {}, replay_ {}, station_ {},
              ap_ {}, pmk_ {}, ptk_ {}, snonce_ {}, expectedRsnIe_ {},
              expectedRsnIeLength_(0), eapolVersion_(0),
              keyInstallAttempted_(false), sessionEpoch_(0)
        {
        }

        Wpa2Supplicant::~Wpa2Supplicant()
        {
            // Owner MUST call reset() before the backend context is destroyed.
            // Destructor only wipes local secrets and never dereferences
            // callbacks.
            secureClear(pmk_, sizeof(pmk_));
            secureClear(ptk_, sizeof(ptk_));
            secureClear(snonce_, sizeof(snonce_));
        }

        void Wpa2Supplicant::secureClear(uint8_t *ptr, size_t length)
        {
            volatile uint8_t *bytes = ptr;
            for (size_t i = 0; i < length; ++i)
                bytes[i] = 0;
        }

        Wpa2Result Wpa2Supplicant::fail(Wpa2Result error)
        {
            const bool rollback = keyInstallAttempted_;
            const Wpa2Crypto previousCrypto = crypto_;
            // Mark failed and revoke stored secrets BEFORE an untrusted
            // rollback callback. A reentrant reset/begin owns fresh state.
            keyInstallAttempted_ = false;
            secureClear(pmk_, sizeof(pmk_));
            secureClear(ptk_, sizeof(ptk_));
            secureClear(snonce_, sizeof(snonce_));
            secureClear(expectedRsnIe_, sizeof(expectedRsnIe_));
            expectedRsnIeLength_ = 0;
            state_ = Wpa2State::Failed;
            if (rollback && previousCrypto.removeInstalledKeys)
                previousCrypto.removeInstalledKeys(previousCrypto.context);
            return error;
        }

        void Wpa2Supplicant::reset()
        {
            const bool rollback = keyInstallAttempted_;
            const Wpa2Crypto previousCrypto = crypto_;
            // Revoke the in-flight callback's epoch before it can resume.
            // Clear state BEFORE rollback, which itself may call reset/begin.
            ++sessionEpoch_;
            keyInstallAttempted_ = false;
            secureClear(pmk_, sizeof(pmk_));
            secureClear(ptk_, sizeof(ptk_));
            secureClear(snonce_, sizeof(snonce_));
            secureClear(expectedRsnIe_, sizeof(expectedRsnIe_));
            expectedRsnIeLength_ = 0;
            crypto_ = {};
            replay_.reset();
            station_ = {};
            ap_ = {};
            eapolVersion_ = 0;
            state_ = Wpa2State::Inactive;
            if (rollback && previousCrypto.removeInstalledKeys)
                previousCrypto.removeInstalledKeys(previousCrypto.context);
        }

        Wpa2Result Wpa2Supplicant::begin(const Wpa2Crypto &crypto,
                                         const Mac &station, const Mac &ap,
                                         const uint8_t pmk[32],
                                         const uint8_t *expectedRsnIe,
                                         size_t expectedRsnIeLength)
        {
            if (!beginInputsDisjoint(this, sizeof(*this), crypto, station, ap,
                                     pmk, expectedRsnIe, expectedRsnIeLength))
                return Wpa2Result::InvalidArgument;
            if (state_ != Wpa2State::Inactive)
                return Wpa2Result::InvalidState;
            // A public supplicant must not authenticate a forged association
            // whose local station and authenticator addresses are identical.
            if (!pmk || !validStationMac(station) || !validStationMac(ap) ||
                sameMac(station, ap) || !nonzero(pmk, 32))
                return Wpa2Result::InvalidArgument;
            // This snapshot came from a validated Beacon/Probe Response.
            // A missing or unsupported RSNE cannot be treated as WPA2-PSK.
            if (!expectedRsnIe || expectedRsnIeLength < 2u ||
                expectedRsnIeLength > sizeof(expectedRsnIe_) ||
                expectedRsnIe[0] != 48 ||
                expectedRsnIe[1] != expectedRsnIeLength - 2u)
                return Wpa2Result::InvalidArgument;
            Rsn advertised {};
            if (parseRsn(expectedRsnIe + 2u, expectedRsnIeLength - 2u,
                         advertised) != Result::Ok ||
                !advertised.groupCcmp || !advertised.pairwiseCcmp ||
                !advertised.akmPsk || advertised.pmfRequired)
                return Wpa2Result::InvalidArgument;
            if (!crypto.context || !crypto.generateNonce || !crypto.derivePtk ||
                !crypto.micSha1 || !crypto.unwrapGtk ||
                !crypto.installPairwiseTk || !crypto.installGroupGtk ||
                !crypto.removeInstalledKeys)
                return Wpa2Result::CryptoProviderMissing;
            crypto_ = crypto;
            station_ = station;
            ap_ = ap;
            copyBytes(pmk_, pmk, sizeof(pmk_));
            copyBytes(expectedRsnIe_, expectedRsnIe, expectedRsnIeLength);
            expectedRsnIeLength_ = expectedRsnIeLength;
            ++sessionEpoch_;
            state_ = Wpa2State::AwaitingMessage1;
            return Wpa2Result::Ok;
        }

        Wpa2Result Wpa2Supplicant::onMessage1(const uint8_t *eapol,
                                              size_t length,
                                              uint8_t *outMessage2,
                                              size_t capacity, size_t &written)
        {
            if (!handshakeIoDisjoint(this, sizeof(*this), crypto_.context,
                                     eapol, length, outMessage2, capacity,
                                     written))
                return Wpa2Result::InvalidArgument;
            written = 0;
            if (state_ != Wpa2State::AwaitingMessage1)
                return Wpa2Result::InvalidState;
            if (!outMessage2 || capacity < kMessage2Length)
                return Wpa2Result::BufferTooSmall;
            const uint64_t epoch = sessionEpoch_;
            // M1 is not MIC-protected. Still capture its complete input once
            // so the stored ANonce/replay counter and PTK derivation cannot
            // observe different versions of a mutable RX/DMA buffer.
            KeyFrame preflight {};
            if (parseEapolKey(eapol, length, preflight) != EapolResult::Ok)
                return Wpa2Result::MalformedEapol;
            // A valid parsed EAPOL prefix does not authenticate extra RX
            // bytes. The direct public handshake API requires the exact
            // declared packet, just like the station data-path admission.
            if (preflight.eapolLength != length)
                return Wpa2Result::MalformedEapol;
            if (preflight.eapolLength > kMaximumEapolHandshakeBytes)
                return Wpa2Result::WrongMessage;
            uint8_t receivedM1[kMaximumEapolHandshakeBytes] {};
            copyBytes(receivedM1, eapol, preflight.eapolLength);
            KeyFrame parsed {};
            if (parseEapolKey(receivedM1, preflight.eapolLength, parsed) !=
                EapolResult::Ok)
            {
                secureClear(receivedM1, sizeof(receivedM1));
                return Wpa2Result::MalformedEapol;
            }
            if (parsed.message != KeyMessage::Pairwise1 ||
                parsed.keyLength != 16)
            {
                secureClear(receivedM1, sizeof(receivedM1));
                return Wpa2Result::WrongMessage;
            }
            if (replay_.acceptMessage1(parsed) != EapolResult::Ok)
            {
                secureClear(receivedM1, sizeof(receivedM1));
                return Wpa2Result::InvalidReplayCounter;
            }
            state_ = Wpa2State::ProcessingMessage1;
            uint8_t generatedNonce[32] {};
            const bool nonceGenerated =
                crypto_.generateNonce(crypto_.context, generatedNonce);
            if (sessionEpoch_ != epoch)
            {
                secureClear(generatedNonce, sizeof(generatedNonce));
                secureClear(receivedM1, sizeof(receivedM1));
                return Wpa2Result::InvalidState;
            }
            if (!nonceGenerated ||
                !nonzero(generatedNonce, sizeof(generatedNonce)))
            {
                secureClear(generatedNonce, sizeof(generatedNonce));
                secureClear(receivedM1, sizeof(receivedM1));
                return fail(Wpa2Result::RandomFailure);
            }
            ScopedSecret<32> pmkSnapshot {};
            copyBytes(pmkSnapshot.bytes, pmk_, sizeof(pmk_));
            const Mac apSnapshot = ap_;
            const Mac stationSnapshot = station_;
            uint8_t derivedPtk[48] {};
            const bool derived = crypto_.derivePtk(
                crypto_.context, pmkSnapshot.bytes, apSnapshot, stationSnapshot,
                parsed.nonce, generatedNonce, derivedPtk);
            if (sessionEpoch_ != epoch)
            {
                secureClear(generatedNonce, sizeof(generatedNonce));
                secureClear(derivedPtk, sizeof(derivedPtk));
                secureClear(receivedM1, sizeof(receivedM1));
                return Wpa2Result::InvalidState;
            }
            if (!derived)
            {
                secureClear(generatedNonce, sizeof(generatedNonce));
                secureClear(derivedPtk, sizeof(derivedPtk));
                secureClear(receivedM1, sizeof(receivedM1));
                return fail(Wpa2Result::KeyDerivationFailure);
            }
            copyBytes(snonce_, generatedNonce, sizeof(snonce_));
            copyBytes(ptk_, derivedPtk, sizeof(ptk_));
            secureClear(generatedNonce, sizeof(generatedNonce));
            secureClear(derivedPtk, sizeof(derivedPtk));
            eapolVersion_ = parsed.eapolBytes[0];
            secureClear(receivedM1, sizeof(receivedM1));

            uint8_t response[kMessage2Length] {};
            populateEapolKey(response, sizeof(response), eapolVersion_, 0x010au,
                             parsed.replayCounter, snonce_);
            copyBytes(response + kMessage4Length, kRsnCcmpPskIe, kRsnIeBytes);
            ScopedSecret<16> kckSnapshot {};
            copyBytes(kckSnapshot.bytes, ptk_, sizeof(kckSnapshot.bytes));
            ScopedSecret<kMessage2Length> m2MicInput {};
            copyBytes(m2MicInput.bytes, response, sizeof(response));
            uint8_t calculatedMic[16] {};
            const bool signedMessage2 =
                crypto_.micSha1(crypto_.context, kckSnapshot.bytes, response,
                                sizeof(response), calculatedMic);
            if (sessionEpoch_ != epoch)
            {
                secureClear(response, sizeof(response));
                secureClear(calculatedMic, sizeof(calculatedMic));
                return Wpa2Result::InvalidState;
            }
            // A provider that returns success without producing a MIC cannot
            // advance the handshake with an unparseable plaintext M2.
            if (!signedMessage2 ||
                !nonzero(calculatedMic, sizeof(calculatedMic)) ||
                !constantTimeEqual(response, m2MicInput.bytes,
                                   sizeof(response)))
            {
                secureClear(response, sizeof(response));
                secureClear(calculatedMic, sizeof(calculatedMic));
                return fail(Wpa2Result::MicCalculationFailure);
            }
            copyBytes(response + kEapolHeaderBytes + 77u, calculatedMic,
                      sizeof(calculatedMic));
            secureClear(calculatedMic, sizeof(calculatedMic));
            copyBytes(outMessage2, response, sizeof(response));
            secureClear(response, sizeof(response));
            written = kMessage2Length;
            state_ = Wpa2State::AwaitingMessage3;
            return Wpa2Result::Ok;
        }

        Wpa2Result Wpa2Supplicant::onMessage3(const uint8_t *eapol,
                                              size_t length,
                                              uint8_t *outMessage4,
                                              size_t capacity, size_t &written)
        {
            if (!handshakeIoDisjoint(this, sizeof(*this), crypto_.context,
                                     eapol, length, outMessage4, capacity,
                                     written))
                return Wpa2Result::InvalidArgument;
            written = 0;
            if (state_ != Wpa2State::AwaitingMessage3)
                return Wpa2Result::InvalidState;
            if (!outMessage4 || capacity < kMessage4Length)
                return Wpa2Result::BufferTooSmall;
            const uint64_t epoch = sessionEpoch_;
            // Preflight the untrusted input only to bound the copy. Reparse
            // the private snapshot: KeyFrame contains borrowed pointers and
            // scalar replay/key-length fields, none of which may describe a
            // different DMA image than the bytes authenticated by the MIC.
            KeyFrame preflight {};
            if (parseEapolKey(eapol, length, preflight) != EapolResult::Ok)
                return Wpa2Result::MalformedEapol;
            // A valid parsed EAPOL prefix does not authenticate extra RX
            // bytes. The direct public handshake API requires the exact
            // declared packet, just like the station data-path admission.
            if (preflight.eapolLength != length)
                return Wpa2Result::MalformedEapol;
            if (preflight.eapolLength > kMaximumEapolHandshakeBytes)
                return Wpa2Result::WrongMessage;
            uint8_t signedEapol[kMaximumEapolHandshakeBytes] {};
            copyBytes(signedEapol, eapol, preflight.eapolLength);
            KeyFrame parsed {};
            if (parseEapolKey(signedEapol, preflight.eapolLength, parsed) !=
                EapolResult::Ok)
            {
                secureClear(signedEapol, sizeof(signedEapol));
                return Wpa2Result::MalformedEapol;
            }
            if (parsed.message != KeyMessage::Pairwise3 ||
                parsed.keyLength != 16 || parsed.keyDataLength < 24 ||
                parsed.keyDataLength > kMaximumGtkPlaintext)
            {
                secureClear(signedEapol, sizeof(signedEapol));
                return Wpa2Result::WrongMessage;
            }

            // All subsequent authenticated fields, including nonce, replay
            // counter, Key RSC and GTK ciphertext, now belong to this bounded
            // private copy rather than potentially mutable RX/DMA memory.
            // The received MIC and the signed bytes must come from the same
            // bounded RX snapshot; never reread mutable caller/DMA memory
            // after creating that snapshot.
            uint8_t receivedMic[16] {};
            copyBytes(receivedMic, signedEapol + kEapolHeaderBytes + 77u,
                      sizeof(receivedMic));
            for (size_t i = 0; i < sizeof(receivedMic); ++i)
                signedEapol[kEapolHeaderBytes + 77u + i] = 0;
            ScopedSecret<48> ptkSnapshot {};
            copyBytes(ptkSnapshot.bytes, ptk_, sizeof(ptk_));
            const Mac apSnapshot = ap_;
            state_ = Wpa2State::ProcessingMessage3;
            // Even a callback that violates its const input contract must
            // not change the RSC, replay fields or GTK ciphertext AFTER
            // calculating a matching MIC. Replay/unwrap still borrow this
            // same stack image after the synchronous provider returns.
            ScopedSecret<kMaximumEapolHandshakeBytes> micInputSnapshot {};
            copyBytes(micInputSnapshot.bytes, signedEapol, parsed.eapolLength);
            uint8_t expectedMic[16] {};
            const bool verifiedMic =
                crypto_.micSha1(crypto_.context, ptkSnapshot.bytes, signedEapol,
                                parsed.eapolLength, expectedMic);
            if (sessionEpoch_ != epoch)
            {
                secureClear(signedEapol, sizeof(signedEapol));
                secureClear(receivedMic, sizeof(receivedMic));
                secureClear(expectedMic, sizeof(expectedMic));
                return Wpa2Result::InvalidState;
            }
            if (!verifiedMic ||
                !constantTimeEqual(signedEapol, micInputSnapshot.bytes,
                                   parsed.eapolLength))
            {
                // A successful provider must not authenticate bytes and
                // then substitute different replay or key-install inputs.
                secureClear(signedEapol, sizeof(signedEapol));
                secureClear(receivedMic, sizeof(receivedMic));
                secureClear(expectedMic, sizeof(expectedMic));
                return fail(Wpa2Result::MicCalculationFailure);
            }
            const bool micValid = constantTimeEqual(receivedMic, expectedMic,
                                                    sizeof(receivedMic));
            secureClear(receivedMic, sizeof(receivedMic));
            // Copy the group receive PN from the same immutable snapshot
            // whose MIC was just verified, not the original DMA-backed input.
            uint8_t authenticatedRsc[8] {};
            if (micValid)
                copyBytes(authenticatedRsc,
                          signedEapol + kEapolHeaderBytes + 61u,
                          sizeof(authenticatedRsc));
            secureClear(expectedMic, sizeof(expectedMic));
            if (!micValid)
            {
                secureClear(signedEapol, sizeof(signedEapol));
                return fail(Wpa2Result::MicMismatch);
            }
            if (replay_.acceptVerifiedMessage3(parsed, true) != EapolResult::Ok)
            {
                secureClear(signedEapol, sizeof(signedEapol));
                return fail(Wpa2Result::InvalidReplayCounter);
            }
            // IEEE 802.11 CCMP Key RSC has six PN octets then two zero octets.
            if (authenticatedRsc[6] != 0 || authenticatedRsc[7] != 0)
            {
                secureClear(signedEapol, sizeof(signedEapol));
                return fail(Wpa2Result::InvalidKeySequenceCounter);
            }

            uint8_t decrypted[kMaximumGtkPlaintext] {};
            size_t decryptedLength = 0;
            const bool unwrapped = crypto_.unwrapGtk(
                crypto_.context, ptkSnapshot.bytes + 16u, parsed.keyData,
                parsed.keyDataLength, decrypted, sizeof(decrypted),
                &decryptedLength);
            // Reject a backend that changes const input after MIC verification.
            // Key installation must consume only the authenticated M3 image.
            const bool authenticatedInputUnchanged = constantTimeEqual(
                signedEapol, micInputSnapshot.bytes, parsed.eapolLength);
            // The ciphertext and nonce are not needed after unwrap; ensure
            // even a provider failure cannot leave the authenticated RX image
            // in kernel stack memory past this operation.
            secureClear(signedEapol, sizeof(signedEapol));
            if (sessionEpoch_ != epoch)
            {
                secureClear(decrypted, sizeof(decrypted));
                secureClear(authenticatedRsc, sizeof(authenticatedRsc));
                return Wpa2Result::InvalidState;
            }
            if (!unwrapped || !authenticatedInputUnchanged ||
                decryptedLength == 0 || decryptedLength > sizeof(decrypted))
            {
                secureClear(decrypted, sizeof(decrypted));
                return fail(Wpa2Result::GtkUnwrapFailure);
            }
            uint8_t gtk[16] {};
            uint8_t keyId = 0;
            const Wpa2Result keyData =
                parseM3KeyData(decrypted, decryptedLength, expectedRsnIe_,
                               expectedRsnIeLength_, keyId, gtk);
            secureClear(decrypted, sizeof(decrypted));
            if (keyData != Wpa2Result::Ok)
            {
                secureClear(gtk, sizeof(gtk));
                return fail(keyData);
            }
            uint8_t response[kMessage4Length] {};
            populateEapolKey(response, sizeof(response), eapolVersion_, 0x030au,
                             parsed.replayCounter, nullptr);
            ScopedSecret<kMessage4Length> m4MicInput {};
            copyBytes(m4MicInput.bytes, response, sizeof(response));
            uint8_t calculatedMic[16] {};
            const bool signedResponse =
                crypto_.micSha1(crypto_.context, ptkSnapshot.bytes, response,
                                sizeof(response), calculatedMic);
            if (sessionEpoch_ != epoch)
            {
                secureClear(gtk, sizeof(gtk));
                secureClear(response, sizeof(response));
                secureClear(calculatedMic, sizeof(calculatedMic));
                return Wpa2Result::InvalidState;
            }
            // Do not install keys until M4 is a valid, MIC-bearing response.
            // The public EAPOL-Key parser rejects MIC-present/zero frames.
            if (!signedResponse ||
                !nonzero(calculatedMic, sizeof(calculatedMic)) ||
                !constantTimeEqual(response, m4MicInput.bytes,
                                   sizeof(response)))
            {
                secureClear(gtk, sizeof(gtk));
                secureClear(response, sizeof(response));
                secureClear(calculatedMic, sizeof(calculatedMic));
                return fail(Wpa2Result::MicCalculationFailure);
            }
            copyBytes(response + kEapolHeaderBytes + 77u, calculatedMic,
                      sizeof(calculatedMic));
            secureClear(calculatedMic, sizeof(calculatedMic));

            // Software confirmation only. The platform callbacks must actually
            // install CCMP keys and persist them to valid hardware keycache
            // slots.
            // A failed callback can still leave a partially written key slot.
            // Arm rollback before either hardware installation attempt.
            keyInstallAttempted_ = true;
            const bool pairwiseInstalled = crypto_.installPairwiseTk(
                crypto_.context, apSnapshot, ptkSnapshot.bytes + 32u);
            if (sessionEpoch_ != epoch)
            {
                secureClear(gtk, sizeof(gtk));
                secureClear(response, sizeof(response));
                return Wpa2Result::InvalidState;
            }
            if (!pairwiseInstalled)
            {
                secureClear(gtk, sizeof(gtk));
                secureClear(response, sizeof(response));
                return fail(Wpa2Result::HardwareKeyInstallFailure);
            }
            const bool groupInstalled = crypto_.installGroupGtk(
                crypto_.context, keyId, gtk, authenticatedRsc);
            if (sessionEpoch_ != epoch)
            {
                secureClear(gtk, sizeof(gtk));
                secureClear(response, sizeof(response));
                return Wpa2Result::InvalidState;
            }
            if (!groupInstalled)
            {
                secureClear(gtk, sizeof(gtk));
                secureClear(response, sizeof(response));
                return fail(Wpa2Result::HardwareKeyInstallFailure);
            }
            secureClear(gtk, sizeof(gtk));
            copyBytes(outMessage4, response, sizeof(response));
            secureClear(response, sizeof(response));
            written = kMessage4Length;
            secureClear(pmk_, sizeof(pmk_));
            secureClear(ptk_, sizeof(ptk_));
            secureClear(snonce_, sizeof(snonce_));
            state_ = Wpa2State::HardwareKeysInstalled;
            return Wpa2Result::Ok;
        }

    } // namespace ieee80211
} // namespace simpleath
