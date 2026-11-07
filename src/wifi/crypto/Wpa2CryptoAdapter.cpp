// SPDX-License-Identifier: AGPL-3.0-only
#include "Wpa2CryptoAdapter.hpp"

namespace simpleath
{
    namespace ieee80211
    {
        namespace crypto
        {
            namespace
            {
                // Callback outputs must not overwrite the adapter or its
                // retained provider callbacks. Compare distances rather than
                // forming potentially overflowing pointer ends.
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
            } // namespace

            Adapter::Adapter() : hardware_ {}, configured_(false)
            {
            }

            bool Adapter::configure(const KeyHardware &hw)
            {
                if (configured_ || !hw.context || !hw.secureRandom ||
                    !hw.installPairwise || !hw.installGroup || !hw.removeKeys)
                    return false;
                hardware_ = hw;
                configured_ = true;
                return true;
            }

            void Adapter::clear()
            {
                // The associated Wpa2Supplicant must have reset and removed
                // keys before the owner detaches the underlying PCI service and
                // wipes this context.
                hardware_ = {};
                configured_ = false;
            }

            Wpa2Crypto Adapter::callbacks()
            {
                if (!configured_)
                    return {};
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

            bool Adapter::nonce(void *context, uint8_t outNonce[32])
            {
                if (!context || !outNonce)
                    return false;
                auto *adapter = static_cast<Adapter *>(context);
                if (!adapter->configured_ || !adapter->hardware_.secureRandom ||
                    overlaps(adapter, sizeof(*adapter), outNonce, 32))
                    return false;
                return adapter->hardware_.secureRandom(
                    adapter->hardware_.context, outNonce, 32);
            }

            bool Adapter::ptk(void *context, const uint8_t pmk[32],
                              const Mac &ap, const Mac &station,
                              const uint8_t aNonce[32],
                              const uint8_t sNonce[32], uint8_t outPtk[48])
            {
                if (!context || !static_cast<Adapter *>(context)->configured_ ||
                    overlaps(context, sizeof(Adapter), outPtk, 48))
                    return false;
                return derivePtk(pmk, ap, station, aNonce, sNonce, outPtk) ==
                       Error::Ok;
            }

            bool Adapter::mic(void *context, const uint8_t key[16],
                              const uint8_t *eapol, size_t frameBytes,
                              uint8_t outMic[16])
            {
                if (!context || !static_cast<Adapter *>(context)->configured_ ||
                    overlaps(context, sizeof(Adapter), outMic, 16))
                    return false;
                return calculateMic(key, eapol, frameBytes, outMic) ==
                       Error::Ok;
            }

            bool Adapter::unwrap(void *context, const uint8_t kek[16],
                                 const uint8_t *wrapped, size_t wrappedBytes,
                                 uint8_t *out, size_t capacity,
                                 size_t *resultLength)
            {
                if (!context || !resultLength ||
                    !static_cast<Adapter *>(context)->configured_ ||
                    overlaps(context, sizeof(Adapter), resultLength,
                             sizeof(*resultLength)) ||
                    overlaps(context, sizeof(Adapter), out, capacity))
                    return false;
                // unwrapKey rejects overlapping length/key/ciphertext/output
                // storage BEFORE it initializes the result length. Do not
                // clear the length here and bypass that protection.
                return unwrapKey(kek, wrapped, wrappedBytes, out, capacity,
                                 *resultLength) == Error::Ok;
            }

            bool Adapter::pairwise(void *context, const Mac &ap,
                                   const uint8_t key[16])
            {
                if (!context || !key)
                    return false;
                auto *adapter = static_cast<Adapter *>(context);
                return adapter->configured_ &&
                       adapter->hardware_.installPairwise &&
                       adapter->hardware_.installPairwise(
                           adapter->hardware_.context, ap, key);
            }

            bool Adapter::group(void *context, uint8_t keyId,
                                const uint8_t key[16], const uint8_t keyRsc[8])
            {
                if (!context || !key || !keyRsc)
                    return false;
                auto *adapter = static_cast<Adapter *>(context);
                return adapter->configured_ &&
                       adapter->hardware_.installGroup &&
                       adapter->hardware_.installGroup(
                           adapter->hardware_.context, keyId, key, keyRsc);
            }

            void Adapter::remove(void *context)
            {
                if (!context)
                    return;
                auto *adapter = static_cast<Adapter *>(context);
                if (adapter->configured_ && adapter->hardware_.removeKeys)
                    adapter->hardware_.removeKeys(adapter->hardware_.context);
            }

        } // namespace crypto
    } // namespace ieee80211
} // namespace simpleath
