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
                return true;
            }

            static bool pairwise(void *, const Mac &, const uint8_t[16])
            {
                return false;
            }

            static bool group(void *, uint8_t, const uint8_t[16],
                              const uint8_t[8])
            {
                return false;
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
    adapter.clear();
    return 0;
}
