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
                // Callback outputs must not overwrite the adapter, its
                // retained callbacks, or the address of the opaque hardware
                // context. Only the context's starting byte is known here;
                // callers must guarantee its entire allocation is disjoint.
                // Compare distances rather than
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

            Adapter::Adapter()
                : hardware_ {}, configured_(false), generation_(0)
            {
            }

            bool Adapter::configure(const KeyHardware &hw)
            {
                // The opaque callback owner cannot point into this adapter
                // or the borrowed provider table: callbacks may write their
                // contexts, and both locations carry trusted function data.
                // Reject all detectable aliases before retaining anything.
                if (overlaps(hw.context, 1, this, sizeof(*this)) ||
                    overlaps(hw.context, 1, &hw, sizeof(hw)) ||
                    overlaps(&hw, sizeof(hw), this, sizeof(*this)) ||
                    configured_ || !hw.context || !hw.secureRandom ||
                    !hw.installPairwise || !hw.installGroup || !hw.removeKeys)
                    return false;
                hardware_ = hw;
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
                    overlaps(adapter, sizeof(*adapter), outNonce, 32) ||
                    overlaps(adapter->hardware_.context, 1, outNonce, 32))
                    return false;
                // A provider may fail after filling only part of the nonce.
                // Never publish a partial result into a reusable caller
                // buffer, or report success for a no-op provider that leaves
                // its zero-initialized scratch space unchanged.
                const uint64_t generation = adapter->generation_;
                uint8_t generated[32] {};
                const bool providerSucceeded = adapter->hardware_.secureRandom(
                    adapter->hardware_.context, generated, sizeof(generated));
                uint8_t any = 0;
                for (uint8_t byte : generated)
                    any |= byte;
                const bool valid = providerSucceeded && any != 0 &&
                                   adapter->configured_ &&
                                   adapter->generation_ == generation;
                if (valid)
                    for (size_t i = 0; i < sizeof(generated); ++i)
                        outNonce[i] = generated[i];
                volatile uint8_t *secret = generated;
                for (size_t i = 0; i < sizeof(generated); ++i)
                    secret[i] = 0;
                return valid;
            }

            bool Adapter::ptk(void *context, const uint8_t pmk[32],
                              const Mac &ap, const Mac &station,
                              const uint8_t aNonce[32],
                              const uint8_t sNonce[32], uint8_t outPtk[48])
            {
                auto *adapter = static_cast<Adapter *>(context);
                if (!adapter || !adapter->configured_ ||
                    overlaps(adapter, sizeof(*adapter), outPtk, 48) ||
                    overlaps(adapter->hardware_.context, 1, outPtk, 48))
                    return false;
                return derivePtk(pmk, ap, station, aNonce, sNonce, outPtk) ==
                       Error::Ok;
            }

            bool Adapter::mic(void *context, const uint8_t key[16],
                              const uint8_t *eapol, size_t frameBytes,
                              uint8_t outMic[16])
            {
                auto *adapter = static_cast<Adapter *>(context);
                if (!adapter || !adapter->configured_ ||
                    overlaps(adapter, sizeof(*adapter), outMic, 16) ||
                    overlaps(adapter->hardware_.context, 1, outMic, 16))
                    return false;
                return calculateMic(key, eapol, frameBytes, outMic) ==
                       Error::Ok;
            }

            bool Adapter::unwrap(void *context, const uint8_t kek[16],
                                 const uint8_t *wrapped, size_t wrappedBytes,
                                 uint8_t *out, size_t capacity,
                                 size_t *resultLength)
            {
                auto *adapter = static_cast<Adapter *>(context);
                if (!adapter || !resultLength || !adapter->configured_ ||
                    overlaps(adapter, sizeof(*adapter), resultLength,
                             sizeof(*resultLength)) ||
                    overlaps(adapter, sizeof(*adapter), out, capacity) ||
                    overlaps(adapter->hardware_.context, 1, resultLength,
                             sizeof(*resultLength)) ||
                    overlaps(adapter->hardware_.context, 1, out, capacity))
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
                // Callbacks are public and may be invoked without passing
                // through the supplicant's checked BSS identity.
                return validStationMac(ap) && adapter->configured_ &&
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
                // The hardware must never see a reserved GTK index or the
                // two reserved octets after the six-byte CCMP receive PN.
                return keyId <= 3 && keyRsc[6] == 0 && keyRsc[7] == 0 &&
                       adapter->configured_ &&
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
