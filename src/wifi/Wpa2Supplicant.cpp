#include "Wpa2Supplicant.hpp"
#include "wifi/Eapol.hpp"
#include "wifi/Frames.hpp"
#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    namespace ieee80211
    {
        namespace
        {
            constexpr size_t kBitsPerOctet = 8U;
            constexpr size_t kReplayCounterBytes = sizeof(uint64_t);
            constexpr size_t kReplayCounterLastIndex = kReplayCounterBytes - 1U;
            constexpr size_t kEapolReplayOffset = 5U;
            constexpr size_t kEapolNonceOffset = 13U;
            constexpr size_t kEapolKeyDataLengthOffset = 93U;
            constexpr size_t kEapolMicOffset = 77U;
            constexpr size_t kEapolRscOffset = 61U;
            constexpr size_t kKdeReservedOffset = 5U;
            constexpr size_t kGtkKdeDataOffset = 6U;
            constexpr size_t kRscReservedFirstIndex = 6U;
            constexpr size_t kRscReservedLastIndex = 7U;
            constexpr size_t kGtkKdeSize = 22U;
            constexpr size_t kMinimumWrappedGtkBytes = 24U;
            constexpr uint8_t kAesWrapPad = 0xddU;
            constexpr uint8_t kRsnElementId = 48U;
            constexpr uint8_t kVendorElementId = 221U;
            constexpr uint8_t kRsnOuiMiddle = 0x0fU;
            constexpr uint8_t kRsnOuiLow = 0xacU;
            constexpr uint8_t kGtkReservedIdMask = 0xfcU;
            constexpr uint16_t kPairwiseM2Flags = 0x010aU;
            constexpr uint16_t kPairwiseM4Flags = 0x030aU;
            constexpr uint16_t kGroupM2Flags = 0x0302U;
            constexpr size_t kPtkTemporalKeyOffset = kWpa2PmkBytes;
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
                0,  0, // RSN capabilities: PMF not negotiated.
            };

            // Retain the array extent during overload resolution. The
            // explicit final decay is confined to the byte-oriented C/IOKit
            // callback boundary instead of happening at every call site.
            template <typename Byte, size_t N> Byte *rawBytes(Byte (&bytes)[N])
            {
                return static_cast<Byte *>(bytes);
            }

            // Match the existing bounded byte-address contract used by
            // Frames.cpp and the EEPROM parser. The caller validates the
            // logical span; conversion rejects null/overflow before access.
            template <typename Byte> Byte *byteOffset(Byte *base, size_t offset)
            {
                static_assert(sizeof(base) == sizeof(uintptr_t),
                              "byte address width must match pointer width");
                if (base == nullptr)
                {
                    return nullptr;
                }
                uintptr_t address = 0;
                __builtin_memcpy(&address, static_cast<const void *>(&base),
                                 sizeof(address));
                if (offset > UINTPTR_MAX - address)
                {
                    return nullptr;
                }
                address += offset;
                Byte *result = nullptr;
                __builtin_memcpy(static_cast<void *>(&result), &address,
                                 sizeof(result));
                return result;
            }

            // Crypto callbacks may reset and restart this owner. Keep the
            // previous session's secret inputs in zeroized call-local storage
            // so revoked callbacks cannot borrow newly installed credentials.
            // Own secrets in a bounded container so a zeroizing scope does
            // not expose its backing storage as a public raw array.
            template <size_t N> class ScopedSecret
            {
                public:
                    ScopedSecret() = default;
                    ScopedSecret(const ScopedSecret &) = delete;
                    ScopedSecret &operator=(const ScopedSecret &) = delete;
                    ScopedSecret(ScopedSecret &&) = delete;
                    ScopedSecret &operator=(ScopedSecret &&) = delete;

                    ~ScopedSecret()
                    {
                        for (volatile uint8_t &byte : bytes_)
                        {
                            byte = 0;
                        }
                    }

                    uint8_t *data()
                    {
                        return static_cast<uint8_t *>(bytes_);
                    }

                    const uint8_t *data() const
                    {
                        return static_cast<const uint8_t *>(bytes_);
                    }

                    constexpr size_t size() const
                    {
                        return N;
                    }

                    bool clearByte(size_t index)
                    {
                        if (index >= N)
                        {
                            return false;
                        }
                        *byteOffset(data(), index) = 0;
                        return true;
                    }

                private:
                    uint8_t bytes_[N] {};
            };

            void copyBytes(uint8_t *destination, const uint8_t *source,
                           size_t count)
            {
                // The bounded caller owns both regions. A memmove retains
                // the old byte-copy contract even for partially aliased
                // buffers and avoids arithmetic on opaque byte pointers.
                if (count != 0U)
                {
                    __builtin_memmove(destination, source, count);
                }
            }

            void putBig16(uint8_t *buffer, uint16_t value)
            {
                *byteOffset(buffer, 0U) =
                    static_cast<uint8_t>(value >> kBitsPerOctet);
                *byteOffset(buffer, 1U) = static_cast<uint8_t>(value);
            }

            void putBig64(uint8_t *buffer, uint64_t value)
            {
                for (size_t i = 0; i < kReplayCounterBytes; ++i)
                {
                    *byteOffset(buffer, kReplayCounterLastIndex - i) =
                        static_cast<uint8_t>(value);
                    value >>= kBitsPerOctet;
                }
            }

            bool constantTimeEqual(const uint8_t *left, const uint8_t *right,
                                   size_t count)
            {
                uint8_t mismatch = 0;
                for (size_t i = 0; i < count; ++i)
                {
                    mismatch |= static_cast<uint8_t>(*byteOffset(left, i) ^
                                                     *byteOffset(right, i));
                }
                return mismatch == 0;
            }

            bool nonzero(const uint8_t *value, size_t count)
            {
                uint8_t aggregate = 0;
                for (size_t i = 0; i < count; ++i)
                {
                    aggregate |= *byteOffset(value, i);
                }
                return aggregate != 0;
            }

            bool overlaps(const void *a, size_t aBytes, const void *b,
                          size_t bBytes)
            {
                if ((a == nullptr) || (b == nullptr) || (aBytes == 0U) ||
                    (bBytes == 0U))
                {
                    return false;
                }
                static_assert(sizeof(a) == sizeof(uintptr_t),
                              "pointer address width must match uintptr_t");
                uintptr_t first = 0;
                uintptr_t second = 0;
                __builtin_memcpy(&first, static_cast<const void *>(&a),
                                 sizeof(a));
                __builtin_memcpy(&second, static_cast<const void *>(&b),
                                 sizeof(b));
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
                // Each borrowed range is checked against the owner and the
                // callback's mutable context before installing credentials.
                const auto disjoint = [owner, ownerBytes, &crypto](
                                          const void *address, size_t bytes)
                {
                    return !overlaps(address, bytes, owner, ownerBytes) &&
                           !overlaps(address, bytes, crypto.context, 1U);
                };
                return !overlaps(crypto.context, 1U, owner, ownerBytes) &&
                       disjoint(&crypto, sizeof(crypto)) &&
                       disjoint(&station, sizeof(station)) &&
                       disjoint(&ap, sizeof(ap)) &&
                       disjoint(pmk, kWpa2PmkBytes) && disjoint(rsn, rsnBytes);
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

            struct EapolKeyFields
            {
                    uint8_t version;
                    uint16_t keyInfo;
                    uint64_t replayCounter;
            };

            void populateEapolKey(uint8_t *message, size_t length,
                                  const EapolKeyFields &fields,
                                  const uint8_t *nonce)
            {
                for (size_t i = 0; i < length; ++i)
                {
                    *byteOffset(message, i) = 0;
                }
                *byteOffset(message, 0U) = fields.version;
                *byteOffset(message, 1U) = 3; // IEEE 802.1X EAPOL-Key.
                putBig16(byteOffset(message, 2U),
                         static_cast<uint16_t>(length - 4U));
                uint8_t *body = byteOffset(message, kEapolHeaderBytes);
                *byteOffset(body, 0U) = 2; // RSN key descriptor.
                putBig16(byteOffset(body, 1U), fields.keyInfo);
                // The Supplicant's M2/M4 Key Length is zero (IEEE 802.11);
                // only Authenticator M1/M3 carry the CCMP TK length of 16.
                putBig16(byteOffset(body, 3U), 0);
                putBig64(byteOffset(body, kEapolReplayOffset),
                         fields.replayCounter);
                if (nonce != nullptr)
                {
                    copyBytes(byteOffset(body, kEapolNonceOffset), nonce,
                              kWpa2PmkBytes);
                }
                putBig16(byteOffset(body, kEapolKeyDataLengthOffset),
                         static_cast<uint16_t>(length - kMessage4Length));
            }

            // Guard the selected element's full length before inspecting OUI.
            bool isCcmpGtkVendorKde(const uint8_t *element, size_t size)
            {
                return size >= 4U && *byteOffset(element, 0U) == 0 &&
                       *byteOffset(element, 1U) == kRsnOuiMiddle &&
                       *byteOffset(element, 2U) == kRsnOuiLow &&
                       *byteOffset(element, 3U) == 1;
            }

            bool rsnElementMatches(const uint8_t *element, size_t size,
                                   const uint8_t *expected,
                                   size_t expectedLength, uint8_t tag)
            {
                return size + 2U == expectedLength &&
                       *byteOffset(expected, 0U) == tag &&
                       *byteOffset(expected, 1U) == size &&
                       constantTimeEqual(element, byteOffset(expected, 2U),
                                         size);
            }

            bool isAesWrapPadding(const uint8_t *remaining, size_t length)
            {
                if (length == 0U || *remaining != kAesWrapPad)
                {
                    return false;
                }
                for (size_t i = 1U; i < length; ++i)
                {
                    if (*byteOffset(remaining, i) != 0U)
                    {
                        return false;
                    }
                }
                return true;
            }

            struct IntegrityView
            {
                    const uint8_t *current;
                    const uint8_t *snapshot;
                    size_t length;
            };

            bool unchanged(const IntegrityView &view)
            {
                return constantTimeEqual(view.current, view.snapshot,
                                         view.length);
            }

            bool validAuthenticatedMic(bool completed, const IntegrityView &key,
                                       const IntegrityView &frame)
            {
                return completed && unchanged(key) && unchanged(frame);
            }

            struct GtkUnwrapOutcome
            {
                    bool unwrapped;
                    bool inputUnchanged;
                    bool keyUnchanged;
                    size_t written;
                    size_t capacity;
            };

            bool validGtkUnwrapOutcome(const GtkUnwrapOutcome &outcome)
            {
                return outcome.unwrapped && outcome.inputUnchanged &&
                       outcome.keyUnchanged && outcome.written != 0U &&
                       outcome.written <= outcome.capacity;
            }

            struct MicValidation
            {
                    bool completed;
                    const uint8_t *mic;
                    size_t micLength;
                    IntegrityView key;
                    IntegrityView frame;
            };

            bool validSignedMic(const MicValidation &check)
            {
                return check.completed && nonzero(check.mic, check.micLength) &&
                       unchanged(check.key) && unchanged(check.frame);
            }

            struct KeyInstallValidation
            {
                    bool completed;
                    IntegrityView gtk;
                    IntegrityView rsc;
                    IntegrityView key;
            };

            bool validKeyInstall(const KeyInstallValidation &check)
            {
                return check.completed && unchanged(check.gtk) &&
                       unchanged(check.rsc) && unchanged(check.key);
            }

            struct UnwrapValidation
            {
                    bool completed;
                    size_t bytes;
                    size_t capacity;
                    IntegrityView frame;
                    IntegrityView key;
            };

            bool validUnwrap(const UnwrapValidation &check)
            {
                return check.completed && check.bytes != 0U &&
                       check.bytes <= check.capacity &&
                       unchanged(check.frame) && unchanged(check.key);
            }

            bool hasMessage4Capacity(const uint8_t *buffer, size_t capacity)
            {
                return buffer != nullptr && capacity >= kMessage4Length;
            }

            bool validPairwiseMessage3(const KeyFrame &parsed)
            {
                return parsed.message == KeyMessage::Pairwise3 &&
                       parsed.keyLength == kWpa2KeyBytes &&
                       parsed.keyDataLength >= kMinimumWrappedGtkBytes &&
                       parsed.keyDataLength <= kMaximumGtkPlaintext;
            }

            // Keep short-circuit semantics: only inspect the parsed EAPOL
            // length after a complete and structurally valid parse.
            bool exactEapolPrefix(const uint8_t *eapol, size_t length,
                                  KeyFrame &parsed)
            {
                return parseEapolKey(eapol, length, parsed) ==
                           EapolResult::Ok &&
                       parsed.eapolLength == length;
            }

            bool validKeyRsc(const uint8_t *rsc)
            {
                return *byteOffset(rsc, kRscReservedFirstIndex) == 0U &&
                       *byteOffset(rsc, kRscReservedLastIndex) == 0U;
            }

            bool validGroupMessage1(const KeyFrame &parsed)
            {
                return parsed.message == KeyMessage::Group1 &&
                       parsed.keyLength == kWpa2KeyBytes &&
                       parsed.keyDataLength >= kMinimumWrappedGtkBytes &&
                       parsed.keyDataLength <= kMaximumGtkPlaintext;
            }

            Wpa2Result parseM3KeyData(const uint8_t *plaintext, size_t length,
                                      const uint8_t *expectedRsnIe,
                                      size_t expectedRsnIeLength,
                                      uint8_t &keyId,
                                      uint8_t gtk[kWpa2KeyBytes],
                                      bool requireRsn)
            {
                bool foundGtk = false;
                bool foundRsn = false;
                size_t offset = 0;
                while (offset < length)
                {
                    // IEEE 802.11 AES-wrap padding is 0xdd, then zero octets.
                    // Do not confuse a vendor KDE with nonzero data for
                    // padding.
                    if (isAesWrapPadding(byteOffset(plaintext, offset),
                                         length - offset))
                    {
                        break;
                    }
                    if (length - offset < 2)
                    {
                        return Wpa2Result::GtkMissingOrMalformed;
                    }
                    const uint8_t tag = *byteOffset(plaintext, offset);
                    const size_t size = *byteOffset(plaintext, offset + 1U);
                    offset += 2;
                    if (size > length - offset)
                    {
                        return Wpa2Result::GtkMissingOrMalformed;
                    }
                    const uint8_t *element = byteOffset(plaintext, offset);
                    if (tag == kRsnElementId)
                    {
                        // M3 must reproduce the associated BSS's RSNE; do not
                        // install keys for a changed suite/AKM/PMF policy.
                        if (!requireRsn || foundRsn ||
                            !rsnElementMatches(element, size, expectedRsnIe,
                                               expectedRsnIeLength, tag))
                        {
                            return Wpa2Result::RsnMismatch;
                        }
                        foundRsn = true;
                    }
                    else if (tag == kVendorElementId &&
                             isCcmpGtkVendorKde(element, size))
                    {
                        // CCMP GTK KDE: OUI(3), type(1), key-id(1),
                        // reserved(1), 16-byte GTK. Reject
                        // duplicate/short/malformed KDEs.
                        if (foundGtk || size != kGtkKdeSize ||
                            *byteOffset(element, kKdeReservedOffset) != 0)
                        {
                            return Wpa2Result::GtkMissingOrMalformed;
                        }
                        keyId =
                            static_cast<uint8_t>(*byteOffset(element, 4U) & 3U);
                        if ((*byteOffset(element, 4U) & kGtkReservedIdMask) !=
                            0)
                        {
                            return Wpa2Result::GtkMissingOrMalformed;
                        }
                        copyBytes(gtk, byteOffset(element, kGtkKdeDataOffset),
                                  kWpa2KeyBytes);
                        foundGtk = true;
                    }
                    offset += size;
                }
                if (requireRsn && !foundRsn)
                {
                    return Wpa2Result::RsnMismatch;
                }
                return foundGtk ? Wpa2Result::Ok
                                : Wpa2Result::GtkMissingOrMalformed;
            }
        } // namespace

        Wpa2Supplicant::Wpa2Supplicant() = default;

        Wpa2Supplicant::~Wpa2Supplicant()
        {
            // Owner MUST call reset() before the backend context is destroyed.
            // Destructor only wipes local secrets and never dereferences
            // callbacks.
            secureClear(rawBytes(pmk_), sizeof(pmk_));
            secureClear(rawBytes(ptk_), sizeof(ptk_));
            secureClear(rawBytes(snonce_), sizeof(snonce_));
        }

        void Wpa2Supplicant::secureClear(uint8_t *ptr, size_t length)
        {
            volatile uint8_t *bytes = ptr;
            for (size_t i = 0; i < length; ++i)
            {
                *byteOffset(bytes, i) = 0;
            }
        }

        Wpa2Result Wpa2Supplicant::fail(Wpa2Result error)
        {
            const bool rollback = keyInstallAttempted_;
            const Wpa2Crypto previousCrypto = crypto_;
            // Mark failed and revoke stored secrets BEFORE an untrusted
            // rollback callback. A reentrant reset/begin owns fresh state.
            keyInstallAttempted_ = false;
            lastGroupReplayCounter_ = 0;
            secureClear(rawBytes(pmk_), sizeof(pmk_));
            secureClear(rawBytes(ptk_), sizeof(ptk_));
            secureClear(rawBytes(snonce_), sizeof(snonce_));
            secureClear(rawBytes(expectedRsnIe_), sizeof(expectedRsnIe_));
            expectedRsnIeLength_ = 0;
            state_ = Wpa2State::Failed;
            if (rollback && (previousCrypto.removeInstalledKeys != nullptr))
            {
                previousCrypto.removeInstalledKeys(previousCrypto.context);
            }
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
            lastGroupReplayCounter_ = 0;
            secureClear(rawBytes(pmk_), sizeof(pmk_));
            secureClear(rawBytes(ptk_), sizeof(ptk_));
            secureClear(rawBytes(snonce_), sizeof(snonce_));
            secureClear(rawBytes(expectedRsnIe_), sizeof(expectedRsnIe_));
            expectedRsnIeLength_ = 0;
            crypto_ = {};
            replay_.reset();
            station_ = {};
            ap_ = {};
            eapolVersion_ = 0;
            state_ = Wpa2State::Inactive;
            if (rollback && (previousCrypto.removeInstalledKeys != nullptr))
            {
                previousCrypto.removeInstalledKeys(previousCrypto.context);
            }
        }

        Wpa2Result Wpa2Supplicant::begin(const Wpa2Crypto &crypto,
                                         const Mac &station, const Mac &ap,
                                         const uint8_t pmk[kWpa2PmkBytes],
                                         const uint8_t *expectedRsnIe,
                                         size_t expectedRsnIeLength)
        {
            if (!beginInputsDisjoint(this, sizeof(*this), crypto, station, ap,
                                     pmk, expectedRsnIe, expectedRsnIeLength))
            {
                return Wpa2Result::InvalidArgument;
            }
            if (state_ != Wpa2State::Inactive)
            {
                return Wpa2Result::InvalidState;
            }
            // A public supplicant must not authenticate a forged association
            // whose local station and authenticator addresses are identical.
            if ((pmk == nullptr) || !validStationMac(station) ||
                !validStationMac(ap) || sameMac(station, ap) ||
                !nonzero(pmk, kWpa2PmkBytes))
            {
                return Wpa2Result::InvalidArgument;
            }
            // This snapshot came from a validated Beacon/Probe Response.
            // A missing or unsupported RSNE cannot be treated as WPA2-PSK.
            if ((expectedRsnIe == nullptr) || expectedRsnIeLength < 2U ||
                expectedRsnIeLength > sizeof(expectedRsnIe_) ||
                *byteOffset(expectedRsnIe, 0U) != kRsnElementId ||
                *byteOffset(expectedRsnIe, 1U) != expectedRsnIeLength - 2U)
            {
                return Wpa2Result::InvalidArgument;
            }
            Rsn advertised {};
            if (parseRsn(byteOffset(expectedRsnIe, 2U),
                         expectedRsnIeLength - 2U, advertised) != Result::Ok ||
                !advertised.groupCcmp || !advertised.pairwiseCcmp ||
                !advertised.akmPsk || advertised.pmfRequired)
            {
                return Wpa2Result::InvalidArgument;
            }
            if ((crypto.context == nullptr) ||
                (crypto.generateNonce == nullptr) ||
                (crypto.derivePtk == nullptr) || (crypto.micSha1 == nullptr) ||
                (crypto.unwrapGtk == nullptr) ||
                (crypto.installPairwiseTk == nullptr) ||
                (crypto.installGroupGtk == nullptr) ||
                (crypto.removeInstalledKeys == nullptr))
            {
                return Wpa2Result::CryptoProviderMissing;
            }
            crypto_ = crypto;
            station_ = station;
            ap_ = ap;
            copyBytes(rawBytes(pmk_), pmk, sizeof(pmk_));
            copyBytes(rawBytes(expectedRsnIe_), expectedRsnIe,
                      expectedRsnIeLength);
            expectedRsnIeLength_ = expectedRsnIeLength;
            lastGroupReplayCounter_ = 0;
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
            {
                return Wpa2Result::InvalidArgument;
            }
            written = 0;
            if (state_ != Wpa2State::AwaitingMessage1)
            {
                return Wpa2Result::InvalidState;
            }
            if ((outMessage2 == nullptr) || capacity < kMessage2Length)
            {
                return Wpa2Result::BufferTooSmall;
            }
            const uint64_t epoch = sessionEpoch_;
            // M1 is not MIC-protected. Still capture its complete input once
            // so the stored ANonce/replay counter and PTK derivation cannot
            // observe different versions of a mutable RX/DMA buffer.
            KeyFrame preflight {};
            if (parseEapolKey(eapol, length, preflight) != EapolResult::Ok)
            {
                return Wpa2Result::MalformedEapol;
            }
            // A valid parsed EAPOL prefix does not authenticate extra RX
            // bytes. The direct public handshake API requires the exact
            // declared packet, just like the station data-path admission.
            if (preflight.eapolLength != length)
            {
                return Wpa2Result::MalformedEapol;
            }
            if (preflight.eapolLength > kMaximumEapolHandshakeBytes)
            {
                return Wpa2Result::WrongMessage;
            }
            uint8_t receivedM1[kMaximumEapolHandshakeBytes] {};
            copyBytes(rawBytes(receivedM1), eapol, preflight.eapolLength);
            KeyFrame parsed {};
            if (parseEapolKey(rawBytes(receivedM1), preflight.eapolLength,
                              parsed) != EapolResult::Ok)
            {
                secureClear(rawBytes(receivedM1), sizeof(receivedM1));
                return Wpa2Result::MalformedEapol;
            }
            if (parsed.message != KeyMessage::Pairwise1 ||
                parsed.keyLength != kWpa2KeyBytes)
            {
                secureClear(rawBytes(receivedM1), sizeof(receivedM1));
                return Wpa2Result::WrongMessage;
            }
            if (replay_.acceptMessage1(parsed) != EapolResult::Ok)
            {
                secureClear(rawBytes(receivedM1), sizeof(receivedM1));
                return Wpa2Result::InvalidReplayCounter;
            }
            state_ = Wpa2State::ProcessingMessage1;
            uint8_t generatedNonce[kWpa2NonceBytes] {};
            const bool nonceGenerated = crypto_.generateNonce(
                crypto_.context, rawBytes(generatedNonce));
            if (sessionEpoch_ != epoch)
            {
                secureClear(rawBytes(generatedNonce), sizeof(generatedNonce));
                secureClear(rawBytes(receivedM1), sizeof(receivedM1));
                return Wpa2Result::InvalidState;
            }
            if (!nonceGenerated ||
                !nonzero(rawBytes(generatedNonce), sizeof(generatedNonce)))
            {
                secureClear(rawBytes(generatedNonce), sizeof(generatedNonce));
                secureClear(rawBytes(receivedM1), sizeof(receivedM1));
                return fail(Wpa2Result::RandomFailure);
            }
            ScopedSecret<kWpa2PmkBytes> pmkSnapshot {};
            copyBytes(pmkSnapshot.data(), rawBytes(pmk_), sizeof(pmk_));
            const Mac apSnapshot = ap_;
            const Mac stationSnapshot = station_;
            ScopedSecret<kWpa2NonceBytes> snonceSnapshot {};
            copyBytes(snonceSnapshot.data(), rawBytes(generatedNonce),
                      sizeof(generatedNonce));
            ScopedSecret<kWpa2NonceBytes> anonceSnapshot {};
            copyBytes(anonceSnapshot.data(), parsed.nonce,
                      anonceSnapshot.size());
            uint8_t derivedPtk[kWpa2PtkBytes] {};
            const bool derived = crypto_.derivePtk(
                crypto_.context, pmkSnapshot.data(), apSnapshot,
                stationSnapshot, parsed.nonce, rawBytes(generatedNonce),
                rawBytes(derivedPtk));
            if (sessionEpoch_ != epoch)
            {
                secureClear(rawBytes(generatedNonce), sizeof(generatedNonce));
                secureClear(rawBytes(derivedPtk), sizeof(derivedPtk));
                secureClear(rawBytes(receivedM1), sizeof(receivedM1));
                return Wpa2Result::InvalidState;
            }
            // The external PTK provider only borrows read-only PMK, M1
            // ANonce, SNonce and link identities. A callback that corrupts
            // those inputs but reports success must never publish a signed
            // M2 for key material different from the observed handshake.
            if (!derived ||
                !constantTimeEqual(pmkSnapshot.data(), rawBytes(pmk_),
                                   sizeof(pmk_)) ||
                !constantTimeEqual(anonceSnapshot.data(), parsed.nonce,
                                   anonceSnapshot.size()) ||
                !constantTimeEqual(snonceSnapshot.data(),
                                   rawBytes(generatedNonce),
                                   sizeof(generatedNonce)) ||
                !sameMac(apSnapshot, ap_) ||
                !sameMac(stationSnapshot, station_))
            {
                secureClear(rawBytes(generatedNonce), sizeof(generatedNonce));
                secureClear(rawBytes(derivedPtk), sizeof(derivedPtk));
                secureClear(rawBytes(receivedM1), sizeof(receivedM1));
                return fail(Wpa2Result::KeyDerivationFailure);
            }
            copyBytes(rawBytes(snonce_), rawBytes(generatedNonce),
                      sizeof(snonce_));
            copyBytes(rawBytes(ptk_), rawBytes(derivedPtk), sizeof(ptk_));
            secureClear(rawBytes(generatedNonce), sizeof(generatedNonce));
            secureClear(rawBytes(derivedPtk), sizeof(derivedPtk));
            eapolVersion_ = *parsed.eapolBytes;
            secureClear(rawBytes(receivedM1), sizeof(receivedM1));

            uint8_t response[kMessage2Length] {};
            populateEapolKey(
                rawBytes(response), sizeof(response),
                {eapolVersion_, kPairwiseM2Flags, parsed.replayCounter},
                rawBytes(snonce_));
            copyBytes(byteOffset(rawBytes(response), kMessage4Length),
                      rawBytes(kRsnCcmpPskIe), kRsnIeBytes);
            ScopedSecret<kWpa2KeyBytes> kckSnapshot {};
            copyBytes(kckSnapshot.data(), rawBytes(ptk_), kckSnapshot.size());
            ScopedSecret<kMessage2Length> m2MicInput {};
            copyBytes(m2MicInput.data(), rawBytes(response), sizeof(response));
            uint8_t calculatedMic[kWpa2KeyBytes] {};
            const bool signedMessage2 = crypto_.micSha1(
                crypto_.context, kckSnapshot.data(), rawBytes(response),
                sizeof(response), rawBytes(calculatedMic));
            if (sessionEpoch_ != epoch)
            {
                secureClear(rawBytes(response), sizeof(response));
                secureClear(rawBytes(calculatedMic), sizeof(calculatedMic));
                return Wpa2Result::InvalidState;
            }
            // A provider that returns success without producing a MIC cannot
            // advance the handshake with an unparseable plaintext M2.
            if (!signedMessage2 ||
                !nonzero(rawBytes(calculatedMic), sizeof(calculatedMic)) ||
                !constantTimeEqual(rawBytes(response), m2MicInput.data(),
                                   sizeof(response)))
            {
                secureClear(rawBytes(response), sizeof(response));
                secureClear(rawBytes(calculatedMic), sizeof(calculatedMic));
                return fail(Wpa2Result::MicCalculationFailure);
            }
            copyBytes(byteOffset(rawBytes(response),
                                 kEapolHeaderBytes + kEapolMicOffset),
                      rawBytes(calculatedMic), sizeof(calculatedMic));
            secureClear(rawBytes(calculatedMic), sizeof(calculatedMic));
            copyBytes(outMessage2, rawBytes(response), sizeof(response));
            secureClear(rawBytes(response), sizeof(response));
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
            {
                return Wpa2Result::InvalidArgument;
            }
            written = 0;
            if (state_ != Wpa2State::AwaitingMessage3)
            {
                return Wpa2Result::InvalidState;
            }
            if (!hasMessage4Capacity(outMessage4, capacity))
            {
                return Wpa2Result::BufferTooSmall;
            }
            const uint64_t epoch = sessionEpoch_;
            // Preflight the untrusted input only to bound the copy. Reparse
            // the private snapshot: KeyFrame contains borrowed pointers and
            // scalar replay/key-length fields, none of which may describe a
            // different DMA image than the bytes authenticated by the MIC.
            KeyFrame preflight {};
            if (parseEapolKey(eapol, length, preflight) != EapolResult::Ok)
            {
                return Wpa2Result::MalformedEapol;
            }
            // A valid parsed EAPOL prefix does not authenticate extra RX
            // bytes. The direct public handshake API requires the exact
            // declared packet, just like the station data-path admission.
            if (preflight.eapolLength != length)
            {
                return Wpa2Result::MalformedEapol;
            }
            if (preflight.eapolLength > kMaximumEapolHandshakeBytes)
            {
                return Wpa2Result::WrongMessage;
            }
            uint8_t signedEapol[kMaximumEapolHandshakeBytes] {};
            copyBytes(rawBytes(signedEapol), eapol, preflight.eapolLength);
            KeyFrame parsed {};
            if (parseEapolKey(rawBytes(signedEapol), preflight.eapolLength,
                              parsed) != EapolResult::Ok)
            {
                secureClear(rawBytes(signedEapol), sizeof(signedEapol));
                return Wpa2Result::MalformedEapol;
            }
            if (!validPairwiseMessage3(parsed))
            {
                secureClear(rawBytes(signedEapol), sizeof(signedEapol));
                return Wpa2Result::WrongMessage;
            }

            // All subsequent authenticated fields, including nonce, replay
            // counter, Key RSC and GTK ciphertext, now belong to this bounded
            // private copy rather than potentially mutable RX/DMA memory.
            // The received MIC and the signed bytes must come from the same
            // bounded RX snapshot; never reread mutable caller/DMA memory
            // after creating that snapshot.
            uint8_t receivedMic[kWpa2KeyBytes] {};
            copyBytes(rawBytes(receivedMic),
                      byteOffset(rawBytes(signedEapol),
                                 kEapolHeaderBytes + kEapolMicOffset),
                      sizeof(receivedMic));
            for (size_t i = 0; i < sizeof(receivedMic); ++i)
            {
                *byteOffset(rawBytes(signedEapol),
                            kEapolHeaderBytes + kEapolMicOffset + i) = 0;
            }
            ScopedSecret<kWpa2PtkBytes> ptkSnapshot {};
            copyBytes(ptkSnapshot.data(), rawBytes(ptk_), sizeof(ptk_));
            const Mac apSnapshot = ap_;
            state_ = Wpa2State::ProcessingMessage3;
            // Even a callback that violates its const input contract must
            // not change the RSC, replay fields or GTK ciphertext AFTER
            // calculating a matching MIC. Replay/unwrap still borrow this
            // same stack image after the synchronous provider returns.
            ScopedSecret<kMaximumEapolHandshakeBytes> micInputSnapshot {};
            copyBytes(micInputSnapshot.data(), rawBytes(signedEapol),
                      parsed.eapolLength);
            uint8_t expectedMic[kWpa2KeyBytes] {};
            const bool verifiedMic = crypto_.micSha1(
                crypto_.context, ptkSnapshot.data(), rawBytes(signedEapol),
                parsed.eapolLength, rawBytes(expectedMic));
            if (sessionEpoch_ != epoch)
            {
                secureClear(rawBytes(signedEapol), sizeof(signedEapol));
                secureClear(rawBytes(receivedMic), sizeof(receivedMic));
                secureClear(rawBytes(expectedMic), sizeof(expectedMic));
                return Wpa2Result::InvalidState;
            }
            if (!validAuthenticatedMic(
                    verifiedMic,
                    {ptkSnapshot.data(), rawBytes(ptk_), sizeof(ptk_)},
                    {
                        rawBytes(signedEapol),
                        micInputSnapshot.data(),
                        parsed.eapolLength,
                    }))
            {
                // A successful provider must not authenticate bytes and
                // then substitute different replay or key-install inputs.
                secureClear(rawBytes(signedEapol), sizeof(signedEapol));
                secureClear(rawBytes(receivedMic), sizeof(receivedMic));
                secureClear(rawBytes(expectedMic), sizeof(expectedMic));
                return fail(Wpa2Result::MicCalculationFailure);
            }
            const bool micValid =
                constantTimeEqual(rawBytes(receivedMic), rawBytes(expectedMic),
                                  sizeof(receivedMic));
            secureClear(rawBytes(receivedMic), sizeof(receivedMic));
            // Copy the group receive PN from the same immutable snapshot
            // whose MIC was just verified, not the original DMA-backed input.
            uint8_t authenticatedRsc[kWpa2KeyRscBytes] {};
            if (micValid)
            {
                copyBytes(rawBytes(authenticatedRsc),
                          byteOffset(rawBytes(signedEapol),
                                     kEapolHeaderBytes + kEapolRscOffset),
                          sizeof(authenticatedRsc));
            }
            secureClear(rawBytes(expectedMic), sizeof(expectedMic));
            if (!micValid)
            {
                secureClear(rawBytes(signedEapol), sizeof(signedEapol));
                return fail(Wpa2Result::MicMismatch);
            }
            if (replay_.acceptVerifiedMessage3(parsed, true) != EapolResult::Ok)
            {
                secureClear(rawBytes(signedEapol), sizeof(signedEapol));
                return fail(Wpa2Result::InvalidReplayCounter);
            }
            // IEEE 802.11 CCMP Key RSC has six PN octets then two zero octets.
            if (!validKeyRsc(rawBytes(authenticatedRsc)))
            {
                secureClear(rawBytes(signedEapol), sizeof(signedEapol));
                return fail(Wpa2Result::InvalidKeySequenceCounter);
            }

            uint8_t decrypted[kMaximumGtkPlaintext] {};
            size_t decryptedLength = 0;
            const bool unwrapped = crypto_.unwrapGtk(
                crypto_.context, byteOffset(ptkSnapshot.data(), kWpa2KeyBytes),
                parsed.keyData, parsed.keyDataLength, rawBytes(decrypted),
                sizeof(decrypted), &decryptedLength);
            // Reject a backend that changes const input after MIC verification.
            // Key installation must consume only the authenticated M3 image.
            const bool authenticatedInputUnchanged =
                constantTimeEqual(rawBytes(signedEapol),
                                  micInputSnapshot.data(), parsed.eapolLength);
            const bool unwrapKeyUnchanged = constantTimeEqual(
                ptkSnapshot.data(), rawBytes(ptk_), sizeof(ptk_));
            // The ciphertext and nonce are not needed after unwrap; ensure
            // even a provider failure cannot leave the authenticated RX image
            // in kernel stack memory past this operation.
            secureClear(rawBytes(signedEapol), sizeof(signedEapol));
            if (sessionEpoch_ != epoch)
            {
                secureClear(rawBytes(decrypted), sizeof(decrypted));
                secureClear(rawBytes(authenticatedRsc),
                            sizeof(authenticatedRsc));
                return Wpa2Result::InvalidState;
            }
            if (!validGtkUnwrapOutcome({
                    unwrapped,
                    authenticatedInputUnchanged,
                    unwrapKeyUnchanged,
                    decryptedLength,
                    sizeof(decrypted),
                }))
            {
                secureClear(rawBytes(decrypted), sizeof(decrypted));
                return fail(Wpa2Result::GtkUnwrapFailure);
            }
            uint8_t gtk[kWpa2KeyBytes] {};
            uint8_t keyId = 0;
            const Wpa2Result keyData = parseM3KeyData(
                rawBytes(decrypted), decryptedLength, rawBytes(expectedRsnIe_),
                expectedRsnIeLength_, keyId, rawBytes(gtk), true);
            secureClear(rawBytes(decrypted), sizeof(decrypted));
            if (keyData != Wpa2Result::Ok)
            {
                secureClear(rawBytes(gtk), sizeof(gtk));
                return fail(keyData);
            }
            uint8_t response[kMessage4Length] {};
            populateEapolKey(
                rawBytes(response), sizeof(response),
                {eapolVersion_, kPairwiseM4Flags, parsed.replayCounter},
                nullptr);
            ScopedSecret<kMessage4Length> m4MicInput {};
            copyBytes(m4MicInput.data(), rawBytes(response), sizeof(response));
            uint8_t calculatedMic[kWpa2KeyBytes] {};
            const bool signedResponse = crypto_.micSha1(
                crypto_.context, ptkSnapshot.data(), rawBytes(response),
                sizeof(response), rawBytes(calculatedMic));
            if (sessionEpoch_ != epoch)
            {
                secureClear(rawBytes(gtk), sizeof(gtk));
                secureClear(rawBytes(response), sizeof(response));
                secureClear(rawBytes(calculatedMic), sizeof(calculatedMic));
                return Wpa2Result::InvalidState;
            }
            // Do not install keys until M4 is a valid, MIC-bearing response.
            // The public EAPOL-Key parser rejects MIC-present/zero frames.
            if (!validSignedMic({
                    signedResponse,
                    rawBytes(calculatedMic),
                    sizeof(calculatedMic),
                    {ptkSnapshot.data(), rawBytes(ptk_), sizeof(ptk_)},
                    {
                        rawBytes(response),
                        m4MicInput.data(),
                        sizeof(response),
                    },
                }))
            {
                secureClear(rawBytes(gtk), sizeof(gtk));
                secureClear(rawBytes(response), sizeof(response));
                secureClear(rawBytes(calculatedMic), sizeof(calculatedMic));
                return fail(Wpa2Result::MicCalculationFailure);
            }
            copyBytes(byteOffset(rawBytes(response),
                                 kEapolHeaderBytes + kEapolMicOffset),
                      rawBytes(calculatedMic), sizeof(calculatedMic));
            secureClear(rawBytes(calculatedMic), sizeof(calculatedMic));

            // The native installer receives borrowed, const TK/GTK/RSC
            // bytes. Snapshot the authenticated group inputs before calling
            // it: a broken provider must not replace an M3-authenticated key
            // or replay floor while still reporting installation success.
            ScopedSecret<kWpa2KeyBytes> gtkSnapshot {};
            ScopedSecret<kWpa2KeyRscBytes> rscSnapshot {};
            copyBytes(gtkSnapshot.data(), rawBytes(gtk), sizeof(gtk));
            copyBytes(rscSnapshot.data(), rawBytes(authenticatedRsc),
                      sizeof(authenticatedRsc));
            // Software confirmation only. The platform callbacks must actually
            // install CCMP keys and persist them to valid hardware keycache
            // slots.
            // A failed callback can still leave a partially written key slot.
            // Arm rollback before either hardware installation attempt.
            keyInstallAttempted_ = true;
            const bool pairwiseInstalled = crypto_.installPairwiseTk(
                crypto_.context, apSnapshot,
                byteOffset(ptkSnapshot.data(), kPtkTemporalKeyOffset));
            if (sessionEpoch_ != epoch)
            {
                secureClear(rawBytes(gtk), sizeof(gtk));
                secureClear(rawBytes(response), sizeof(response));
                return Wpa2Result::InvalidState;
            }
            if (!pairwiseInstalled ||
                !constantTimeEqual(ptkSnapshot.data(), rawBytes(ptk_),
                                   sizeof(ptk_)))
            {
                secureClear(rawBytes(gtk), sizeof(gtk));
                secureClear(rawBytes(response), sizeof(response));
                return fail(Wpa2Result::HardwareKeyInstallFailure);
            }
            const bool groupInstalled =
                crypto_.installGroupGtk(crypto_.context, keyId, rawBytes(gtk),
                                        rawBytes(authenticatedRsc));
            if (sessionEpoch_ != epoch)
            {
                secureClear(rawBytes(gtk), sizeof(gtk));
                secureClear(rawBytes(response), sizeof(response));
                return Wpa2Result::InvalidState;
            }
            if (!validKeyInstall({
                    groupInstalled,
                    {rawBytes(gtk), gtkSnapshot.data(), sizeof(gtk)},
                    {
                        rawBytes(authenticatedRsc),
                        rscSnapshot.data(),
                        sizeof(authenticatedRsc),
                    },
                    {ptkSnapshot.data(), rawBytes(ptk_), sizeof(ptk_)},
                }))
            {
                secureClear(rawBytes(gtk), sizeof(gtk));
                secureClear(rawBytes(response), sizeof(response));
                return fail(Wpa2Result::HardwareKeyInstallFailure);
            }
            secureClear(rawBytes(gtk), sizeof(gtk));
            copyBytes(outMessage4, rawBytes(response), sizeof(response));
            secureClear(rawBytes(response), sizeof(response));
            written = kMessage4Length;
            secureClear(rawBytes(pmk_), sizeof(pmk_));
            // The initial PTK temporal key is installed in hardware. Keep
            // only KCK/KEK for later authenticated GTK updates; neither
            // retained TK nor SNonce/PMK is needed after M4.
            secureClear(byteOffset(rawBytes(ptk_), kPtkTemporalKeyOffset),
                        sizeof(ptk_) - kPtkTemporalKeyOffset);
            secureClear(rawBytes(snonce_), sizeof(snonce_));
            lastGroupReplayCounter_ = replay_.lastReplayCounter();
            state_ = Wpa2State::HardwareKeysInstalled;
            return Wpa2Result::Ok;
        }

        Wpa2Result Wpa2Supplicant::onGroupMessage1(const uint8_t *eapol,
                                                   size_t length,
                                                   uint8_t *outGroup2,
                                                   size_t capacity,
                                                   size_t &written)
        {
            if (!handshakeIoDisjoint(this, sizeof(*this), crypto_.context,
                                     eapol, length, outGroup2, capacity,
                                     written))
            {
                return Wpa2Result::InvalidArgument;
            }
            written = 0;
            if (state_ != Wpa2State::HardwareKeysInstalled)
            {
                return Wpa2Result::InvalidState;
            }
            if (!hasMessage4Capacity(outGroup2, capacity))
            {
                return Wpa2Result::BufferTooSmall;
            }
            KeyFrame preflight {};
            if (!exactEapolPrefix(eapol, length, preflight))
            {
                return Wpa2Result::MalformedEapol;
            }
            if (preflight.eapolLength > kMaximumEapolHandshakeBytes)
            {
                return Wpa2Result::WrongMessage;
            }
            ScopedSecret<kMaximumEapolHandshakeBytes> authenticated {};
            copyBytes(authenticated.data(), eapol, length);
            KeyFrame key {};
            if (parseEapolKey(authenticated.data(), length, key) !=
                EapolResult::Ok)
            {
                return Wpa2Result::MalformedEapol;
            }
            if (!validGroupMessage1(key))
            {
                return Wpa2Result::WrongMessage;
            }
            // A Group1 reply must never reinstall a GTK for an old PN/replay
            // epoch. The M3 floor is retained when the four-way completes.
            if (key.replayCounter <= lastGroupReplayCounter_)
            {
                return Wpa2Result::InvalidReplayCounter;
            }
            if (!validKeyRsc(key.keyRsc))
            {
                return Wpa2Result::InvalidKeySequenceCounter;
            }
            uint8_t receivedMic[kWpa2KeyBytes] {};
            copyBytes(rawBytes(receivedMic), key.mic, sizeof(receivedMic));
            for (size_t index = 0; index < sizeof(receivedMic); ++index)
            {
                if (!authenticated.clearByte(kEapolHeaderBytes +
                                             kEapolMicOffset + index))
                {
                    return fail(Wpa2Result::MalformedEapol);
                }
            }
            ScopedSecret<kMaximumEapolHandshakeBytes> micInput {};
            copyBytes(micInput.data(), authenticated.data(), length);
            ScopedSecret<kWpa2PmkBytes> keyMaterial {};
            copyBytes(keyMaterial.data(), rawBytes(ptk_), keyMaterial.size());
            const uint64_t epoch = sessionEpoch_;
            state_ = Wpa2State::ProcessingGroupMessage1;
            uint8_t expectedMic[kWpa2KeyBytes] {};
            const bool micCalculated = crypto_.micSha1(
                crypto_.context, keyMaterial.data(), authenticated.data(),
                length, rawBytes(expectedMic));
            if (sessionEpoch_ != epoch)
            {
                secureClear(rawBytes(expectedMic), sizeof(expectedMic));
                return Wpa2Result::InvalidState;
            }
            const bool micInputIntact =
                constantTimeEqual(authenticated.data(), micInput.data(),
                                  length) &&
                constantTimeEqual(keyMaterial.data(), rawBytes(ptk_), 32);
            const bool micMatches =
                constantTimeEqual(rawBytes(receivedMic), rawBytes(expectedMic),
                                  sizeof(receivedMic));
            secureClear(rawBytes(receivedMic), sizeof(receivedMic));
            secureClear(rawBytes(expectedMic), sizeof(expectedMic));
            if (!micCalculated || !micInputIntact)
            {
                return fail(Wpa2Result::MicCalculationFailure);
            }
            if (!micMatches)
            {
                // Invalid MIC does not allow an unauthenticated peer to
                // revoke otherwise installed keys. Retain the same replay
                // floor and await a newly authenticated group message.
                state_ = Wpa2State::HardwareKeysInstalled;
                return Wpa2Result::MicMismatch;
            }
            ScopedSecret<kMaximumGtkPlaintext> plaintext {};
            size_t plaintextBytes = 0;
            const bool unwrapped = crypto_.unwrapGtk(
                crypto_.context, byteOffset(keyMaterial.data(), kWpa2KeyBytes),
                key.keyData, key.keyDataLength, plaintext.data(),
                plaintext.size(), &plaintextBytes);
            if (sessionEpoch_ != epoch)
            {
                return Wpa2Result::InvalidState;
            }
            if (!validUnwrap({
                    unwrapped,
                    plaintextBytes,
                    plaintext.size(),
                    {authenticated.data(), micInput.data(), length},
                    {keyMaterial.data(), rawBytes(ptk_), kWpa2PmkBytes},
                }))
            {
                return fail(Wpa2Result::GtkUnwrapFailure);
            }
            ScopedSecret<kWpa2KeyBytes> gtk {};
            uint8_t keyId = 0;
            const Wpa2Result parsed = parseM3KeyData(
                plaintext.data(), plaintextBytes, rawBytes(expectedRsnIe_),
                expectedRsnIeLength_, keyId, gtk.data(), false);
            if (parsed != Wpa2Result::Ok)
            {
                return fail(parsed);
            }
            uint8_t response[kMessage4Length] {};
            // Group2: descriptor V2, MIC and Secure, no pairwise/ACK bit.
            populateEapolKey(rawBytes(response), sizeof(response),
                             {eapolVersion_, kGroupM2Flags, key.replayCounter},
                             nullptr);
            ScopedSecret<kMessage4Length> responseSnapshot {};
            copyBytes(responseSnapshot.data(), rawBytes(response),
                      sizeof(response));
            uint8_t responseMic[kWpa2KeyBytes] {};
            const bool replySigned = crypto_.micSha1(
                crypto_.context, keyMaterial.data(), rawBytes(response),
                sizeof(response), rawBytes(responseMic));
            if (sessionEpoch_ != epoch)
            {
                secureClear(rawBytes(responseMic), sizeof(responseMic));
                secureClear(rawBytes(response), sizeof(response));
                return Wpa2Result::InvalidState;
            }
            if (!validSignedMic({
                    replySigned,
                    rawBytes(responseMic),
                    sizeof(responseMic),
                    {keyMaterial.data(), rawBytes(ptk_), kWpa2PmkBytes},
                    {
                        rawBytes(response),
                        responseSnapshot.data(),
                        sizeof(response),
                    },
                }))
            {
                secureClear(rawBytes(responseMic), sizeof(responseMic));
                secureClear(rawBytes(response), sizeof(response));
                return fail(Wpa2Result::MicCalculationFailure);
            }
            copyBytes(byteOffset(rawBytes(response),
                                 kEapolHeaderBytes + kEapolMicOffset),
                      rawBytes(responseMic), sizeof(responseMic));
            secureClear(rawBytes(responseMic), sizeof(responseMic));
            // The hardware callback is untrusted even when its inputs are
            // declared const. Keep the authenticated GTK/RSC immutable across
            // the keycache install attempt, including a partial-write failure.
            ScopedSecret<kWpa2KeyBytes> gtkSnapshot {};
            ScopedSecret<kWpa2KeyRscBytes> rscSnapshot {};
            copyBytes(gtkSnapshot.data(), gtk.data(), gtk.size());
            copyBytes(rscSnapshot.data(), key.keyRsc, rscSnapshot.size());
            const bool installed = crypto_.installGroupGtk(
                crypto_.context, keyId, gtk.data(), rscSnapshot.data());
            if (sessionEpoch_ != epoch)
            {
                secureClear(rawBytes(response), sizeof(response));
                return Wpa2Result::InvalidState;
            }
            if (!validKeyInstall({
                    installed,
                    {gtk.data(), gtkSnapshot.data(), gtk.size()},
                    {rscSnapshot.data(), key.keyRsc, rscSnapshot.size()},
                    {keyMaterial.data(), rawBytes(ptk_), kWpa2PmkBytes},
                }))
            {
                secureClear(rawBytes(response), sizeof(response));
                return fail(Wpa2Result::HardwareKeyInstallFailure);
            }
            // Commit only after authenticated GTK install. A failing native
            // CCMP Group2 submission must revoke the session via reset().
            lastGroupReplayCounter_ = key.replayCounter;
            state_ = Wpa2State::HardwareKeysInstalled;
            copyBytes(outGroup2, rawBytes(response), sizeof(response));
            written = sizeof(response);
            secureClear(rawBytes(response), sizeof(response));
            return Wpa2Result::Ok;
        }

    } // namespace ieee80211
} // namespace simpleath
