// SPDX-License-Identifier: AGPL-3.0-only
// Synthetic provider only: test nonce publication, never actual entropy.
#include "wifi/crypto/Wpa2CryptoAdapter.hpp"
#include <cstring>

namespace
{
    using namespace simpleath::ieee80211;
    using namespace simpleath::ieee80211::crypto;

    enum class RandomCase : uint8_t
    {
        PartialFailure,
        EmptySuccess,
        CompleteSuccess
    };

    struct Provider
    {
            RandomCase behavior = RandomCase::PartialFailure;
            unsigned calls = 0;
            unsigned pairwiseCalls = 0;
            unsigned groupCalls = 0;
            Adapter *adapter = nullptr;
            bool replaceDuringRandom = false;
            bool replaceDuringPairwise = false;
            bool replaceDuringGroup = false;
            bool replacementConfigured = false;

            static bool random(void *context, uint8_t *out, size_t length)
            {
                auto &self = *static_cast<Provider *>(context);
                ++self.calls;
                if (length != 32)
                    return false;
                if (self.behavior == RandomCase::PartialFailure)
                {
                    // A CSPRNG error may occur after filling part of a buffer.
                    // The adapter must not publish those incomplete bytes.
                    for (size_t i = 0; i < 8; ++i)
                        out[i] = 0x55;
                    return false;
                }
                if (self.behavior == RandomCase::EmptySuccess)
                    return true; // Contract-violating provider; no fresh nonce.
                for (size_t i = 0; i < length; ++i)
                    out[i] = static_cast<uint8_t>(i + 1);
                if (self.replaceDuringRandom)
                {
                    // Reentrant hardware teardown/reconfiguration must not
                    // publish an in-flight nonce from the retired provider,
                    // even if the replacement reuses the same callback table.
                    self.replaceDuringRandom = false;
                    self.adapter->clear();
                    const KeyHardware replacement {&self, random, pairwise,
                                                   group, remove};
                    self.replacementConfigured =
                        self.adapter->configure(replacement);
                }
                return true;
            }

            static void replace(Provider &self)
            {
                self.adapter->clear();
                const KeyHardware replacement {&self, random, pairwise, group,
                                               remove};
                self.replacementConfigured =
                    self.adapter->configure(replacement);
            }

            static bool pairwise(void *context, const Mac &, const uint8_t[16])
            {
                auto &self = *static_cast<Provider *>(context);
                ++self.pairwiseCalls;
                if (self.replaceDuringPairwise)
                {
                    self.replaceDuringPairwise = false;
                    replace(self);
                }
                return true;
            }

            static bool group(void *context, uint8_t, const uint8_t[16],
                              const uint8_t[8])
            {
                auto &self = *static_cast<Provider *>(context);
                ++self.groupCalls;
                if (self.replaceDuringGroup)
                {
                    self.replaceDuringGroup = false;
                    replace(self);
                }
                return true;
            }

            static void remove(void *)
            {
            }
    };
} // namespace

int main()
{
    Provider provider {};
    Adapter adapter;
    provider.adapter = &adapter;
    const KeyHardware hardware {&provider, Provider::random, Provider::pairwise,
                                Provider::group, Provider::remove};
    if (!adapter.configure(hardware))
        return 1;
    const Wpa2Crypto callbacks = adapter.callbacks();
    uint8_t nonce[32] {};
    std::memset(nonce, 0xa5, sizeof(nonce));
    uint8_t original[sizeof(nonce)] {};
    std::memcpy(original, nonce, sizeof(original));
    if (callbacks.generateNonce(callbacks.context, nonce) ||
        provider.calls != 1 || std::memcmp(nonce, original, sizeof(nonce)) != 0)
        return 2;

    provider.behavior = RandomCase::EmptySuccess;
    if (callbacks.generateNonce(callbacks.context, nonce) ||
        provider.calls != 2 || std::memcmp(nonce, original, sizeof(nonce)) != 0)
        return 3;

    provider.behavior = RandomCase::CompleteSuccess;
    if (!callbacks.generateNonce(callbacks.context, nonce) ||
        provider.calls != 3)
        return 4;
    for (size_t i = 0; i < sizeof(nonce); ++i)
        if (nonce[i] != static_cast<uint8_t>(i + 1))
            return 5;
    std::memset(nonce, 0xa5, sizeof(nonce));
    provider.replaceDuringRandom = true;
    if (callbacks.generateNonce(callbacks.context, nonce) ||
        !provider.replacementConfigured || provider.calls != 4 ||
        std::memcmp(nonce, original, sizeof(nonce)) != 0)
        return 6;
    if (!callbacks.generateNonce(callbacks.context, nonce) ||
        provider.calls != 5)
        return 7;
    for (size_t i = 0; i < sizeof(nonce); ++i)
        if (nonce[i] != static_cast<uint8_t>(i + 1))
            return 8;
    // Direct callback callers cannot bypass the supplicant's address,
    // CCMP key index and reserved Key RSC preflight to program hardware.
    const Mac invalidAp {{0x01, 0x11, 0x22, 0x33, 0x44, 0x55}};
    const Mac validAp {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
    uint8_t key[16] {};
    key[0] = 1;
    uint8_t validRsc[8] {1, 2, 3, 4, 5, 6, 0, 0};
    uint8_t invalidRsc[8] {1, 2, 3, 4, 5, 6, 1, 0};
    if (callbacks.installPairwiseTk(callbacks.context, invalidAp, key) ||
        provider.pairwiseCalls != 0)
        return 9;
    if (!callbacks.installPairwiseTk(callbacks.context, validAp, key) ||
        provider.pairwiseCalls != 1)
        return 10;
    if (callbacks.installGroupGtk(callbacks.context, 4, key, validRsc) ||
        callbacks.installGroupGtk(callbacks.context, 2, key, invalidRsc) ||
        provider.groupCalls != 0)
        return 11;
    if (!callbacks.installGroupGtk(callbacks.context, 2, key, validRsc) ||
        provider.groupCalls != 1)
        return 12;
    // An install callback can retire and reconfigure the provider while it
    // returns success for the OLD hardware owner. Such a stale completion
    // cannot authorize pairwise or group key installation in the new epoch.
    provider.replacementConfigured = false;
    provider.replaceDuringPairwise = true;
    if (callbacks.installPairwiseTk(callbacks.context, validAp, key) ||
        !provider.replacementConfigured || provider.pairwiseCalls != 2)
        return 13;
    if (!callbacks.installPairwiseTk(callbacks.context, validAp, key) ||
        provider.pairwiseCalls != 3)
        return 14;
    provider.replacementConfigured = false;
    provider.replaceDuringGroup = true;
    if (callbacks.installGroupGtk(callbacks.context, 2, key, validRsc) ||
        !provider.replacementConfigured || provider.groupCalls != 2)
        return 15;
    if (!callbacks.installGroupGtk(callbacks.context, 2, key, validRsc) ||
        provider.groupCalls != 3)
        return 16;
    adapter.clear();
    return 0;
}
