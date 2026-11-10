// SPDX-License-Identifier: AGPL-3.0-only
#include "Wpa2CryptoAdapter.hpp"
#include "wifi/Frames.hpp"
#include "wifi/Wpa2Supplicant.hpp"
#include "wifi/crypto/Wpa2Primitives.hpp"
#include <cstddef>
#include <cstdint>

namespace simpleath
{
    namespace ieee80211
    {
        namespace crypto
        {
            namespace
            {
                // Callback outputs must not overwrite the adapter, its
                // retained callbacks, or the address of the opaque hardware
                // context. Only the context's starting byte is known here;
                // callers must guarantee its entire allocation is disjoint.
                // Compare distances rather than
                // forming potentially overflowing pointer ends.
                bool overlaps(const void *a, size_t aBytes, const void *b,
                              size_t bBytes)
                {
                    if ((a == nullptr) || (b == nullptr) || (aBytes == 0U) ||
                        (bBytes == 0U))
                    {
                        return false;
                    }
                    uintptr_t first = 0;
                    uintptr_t second = 0;
                    static_assert(sizeof(uintptr_t) == sizeof(a),
                                  "provider context must fit uintptr_t");
                    __builtin_memcpy(&first, static_cast<const void *>(&a),
                                     sizeof(a));
                    __builtin_memcpy(&second, static_cast<const void *>(&b),
                                     sizeof(b));
                    return first <= second ? second - first < aBytes
                                           : first - second < bBytes;
                }
            } // namespace

            Adapter::Adapter() = default;

            bool Adapter::configure(const KeyHardware &hardware)
            {
                // The opaque callback owner cannot point into this adapter
                // or the borrowed provider table: callbacks may write their
                // contexts, and both locations carry trusted function data.
                // Reject all detectable aliases before retaining anything.
                if (overlaps(hardware.context, 1, this, sizeof(*this)) ||
                    overlaps(hardware.context, 1, &hardware,
                             sizeof(hardware)) ||
                    overlaps(&hardware, sizeof(hardware), this,
                             sizeof(*this)) ||
                    configured_ || (hardware.context == nullptr) ||
                    (hardware.secureRandom == nullptr) ||
                    (hardware.installPairwise == nullptr) ||
                    (hardware.installGroup == nullptr) ||
                    (hardware.removeKeys == nullptr))
                {
                    return false;
                }
                hardware_ = hardware;
                configured_ = true;
                ++generation_;
                return true;
            }

            void Adapter::clear()
            {
                // The associated Wpa2Supplicant must have reset and removed
                // keys before the owner detaches the underlying PCI service and
                // wipes this context.
                hardware_ = {};
                configured_ = false;
                ++generation_;
            }

            Wpa2Crypto Adapter::callbacks()
            {
                if (!configured_)
                {
                    return {};
                }
                Wpa2Crypto functions {};
                functions.context = this;
                functions.generateNonce = nonce;
                functions.derivePtk = ptk;
                functions.micSha1 = mic;
                functions.unwrapGtk = unwrap;
                functions.installPairwiseTk = pairwise;
                functions.installGroupGtk = group;
                functions.removeInstalledKeys = remove;
                return functions;
            }

            bool Adapter::nonce(void *context, uint8_t outNonce[kNonceBytes])
            {
                if ((context == nullptr) || (outNonce == nullptr))
                {
                    return false;
                }
                const auto *adapter = static_cast<const Adapter *>(context);
                if (!adapter->configured_ ||
                    (adapter->hardware_.secureRandom == nullptr) ||
                    overlaps(adapter, sizeof(*adapter), outNonce,
                             kNonceBytes) ||
                    overlaps(adapter->hardware_.context, 1, outNonce,
                             kNonceBytes))
                {
                    return false;
                }
                // A provider may fail after filling only part of the nonce.
                // Never publish a partial result into a reusable caller
                // buffer, or report success for a no-op provider that leaves
                // its zero-initialized scratch space unchanged.
                const uint64_t generation = adapter->generation_;
                uint8_t generated[kNonceBytes] {};
                const bool providerSucceeded = adapter->hardware_.secureRandom(
                    adapter->hardware_.context, &generated[0],
                    sizeof(generated));
                uint8_t any = 0;
                for (const uint8_t byte : generated)
                {
                    any |= byte;
                }
                const bool valid = providerSucceeded && any != 0 &&
                                   adapter->configured_ &&
                                   adapter->generation_ == generation;
                if (valid)
                {
                    __builtin_memcpy(outNonce, &generated[0],
                                     sizeof(generated));
                }
                // The volatile view forces key-erasure stores before return.
                for (volatile uint8_t &secretOctet : generated)
                {
                    secretOctet = 0;
                }
                return valid;
            }

            bool Adapter::ptk(void *context, const uint8_t pmk[kPmkBytes],
                              const Mac &ap, const Mac &station,
                              const uint8_t aNonce[kNonceBytes],
                              const uint8_t sNonce[kNonceBytes],
                              uint8_t outPtk[kPtkBytes])
            {
                const auto *adapter = static_cast<const Adapter *>(context);
                if ((adapter == nullptr) || !adapter->configured_ ||
                    overlaps(adapter, sizeof(*adapter), outPtk, kPtkBytes) ||
                    overlaps(adapter->hardware_.context, 1, outPtk, kPtkBytes))
                {
                    return false;
                }
                return derivePtk(pmk, ap, station, aNonce, sNonce, outPtk) ==
                       Error::Ok;
            }

            bool Adapter::mic(void *context, const uint8_t key[kAesKeyBytes],
                              const uint8_t *eapol, size_t frameBytes,
                              uint8_t outMic[kAesKeyBytes])
            {
                const auto *adapter = static_cast<const Adapter *>(context);
                if ((adapter == nullptr) || !adapter->configured_ ||
                    overlaps(adapter, sizeof(*adapter), outMic, kAesKeyBytes) ||
                    overlaps(adapter->hardware_.context, 1, outMic,
                             kAesKeyBytes))
                {
                    return false;
                }
                return calculateMic(key, eapol, frameBytes, outMic) ==
                       Error::Ok;
            }

            bool Adapter::unwrap(void *context, const uint8_t kek[kAesKeyBytes],
                                 const uint8_t *wrapped, size_t wrappedBytes,
                                 uint8_t *out, size_t capacity,
                                 size_t *resultLength)
            {
                const auto *adapter = static_cast<const Adapter *>(context);
                if ((adapter == nullptr) || (resultLength == nullptr) ||
                    !adapter->configured_ ||
                    overlaps(adapter, sizeof(*adapter), resultLength,
                             sizeof(*resultLength)) ||
                    overlaps(adapter, sizeof(*adapter), out, capacity) ||
                    overlaps(adapter->hardware_.context, 1, resultLength,
                             sizeof(*resultLength)) ||
                    overlaps(adapter->hardware_.context, 1, out, capacity))
                {
                    return false;
                }
                // unwrapKey rejects overlapping length/key/ciphertext/output
                // storage BEFORE it initializes the result length. Do not
                // clear the length here and bypass that protection.
                return unwrapKey(kek, wrapped, wrappedBytes, out, capacity,
                                 *resultLength) == Error::Ok;
            }

            bool Adapter::pairwise(void *context, const Mac &ap,
                                   const uint8_t key[kAesKeyBytes])
            {
                if ((context == nullptr) || (key == nullptr))
                {
                    return false;
                }
                const auto *adapter = static_cast<const Adapter *>(context);
                // Callbacks are public and may be invoked without passing
                // through the supplicant's checked BSS identity.
                if (!validStationMac(ap) || !adapter->configured_ ||
                    (adapter->hardware_.installPairwise == nullptr))
                {
                    return false;
                }
                // An install can report success after the provider has
                // retired and reconfigured this same adapter. Never promote
                // that stale completion into installed-key readiness.
                const uint64_t generation = adapter->generation_;
                const bool installed = adapter->hardware_.installPairwise(
                    adapter->hardware_.context, ap, key);
                return installed && adapter->configured_ &&
                       adapter->generation_ == generation;
            }

            bool Adapter::group(void *context, uint8_t keyId,
                                const uint8_t key[kAesKeyBytes],
                                const uint8_t keyRsc[kWpa2KeyRscBytes])
            {
                if ((context == nullptr) || (key == nullptr) ||
                    (keyRsc == nullptr))
                {
                    return false;
                }
                const auto *adapter = static_cast<const Adapter *>(context);
                // The hardware must never see a reserved GTK index or the
                // two reserved octets after the six-byte CCMP receive PN.
                constexpr uint8_t kMaximumGtkKeyId = 3;
                constexpr size_t kRscReservedOctet0 = 6;
                constexpr size_t kRscReservedOctet1 = 7;
                uint8_t rsc[kWpa2KeyRscBytes] {};
                __builtin_memcpy(&rsc[0], keyRsc, sizeof(rsc));
                if (keyId > kMaximumGtkKeyId || rsc[kRscReservedOctet0] != 0 ||
                    rsc[kRscReservedOctet1] != 0 || !adapter->configured_ ||
                    (adapter->hardware_.installGroup == nullptr))
                {
                    return false;
                }
                const uint64_t generation = adapter->generation_;
                const bool installed = adapter->hardware_.installGroup(
                    adapter->hardware_.context, keyId, key, keyRsc);
                return installed && adapter->configured_ &&
                       adapter->generation_ == generation;
            }

            void Adapter::remove(void *context)
            {
                if (context == nullptr)
                {
                    return;
                }
                const auto *adapter = static_cast<const Adapter *>(context);
                if (adapter->configured_ &&
                    (adapter->hardware_.removeKeys != nullptr))
                {
                    adapter->hardware_.removeKeys(adapter->hardware_.context);
                }
            }

        } // namespace crypto
    } // namespace ieee80211
} // namespace simpleath
