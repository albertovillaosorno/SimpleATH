// Copyright:
//   - Copyright © 2026 Alberto Villa Osorno
// SPDX-License-Identifier:
//   - MIT
// Confidential:
//   - false
// License-File:
//   - LICENSE-MIT
// Provenance:
//   - SimpleATH original; independently developed or locally authored
//
// Boundary-Contract:
// - Owns:
//   - Offline regression cases for wpa2 adapter entropy.
// - Must-Not:
//   - Require physical hardware, mutate installed drivers, or suppress
//     failures.
// - Allows:
//   - Inputs: isolated fixtures and reproducible source-under-test inputs.
//   - Outputs: assertions and observable regression verdicts.
//   - Side effects: test-local temporary files and bounded subprocesses only.
// - Split-When:
//   - A separate protocol stage needs independent validation and ownership.
// - Merge-When:
//   - The caller directly owns this narrow contract without reuse.
// - Summary:
//   - Offline regression cases for wpa2 adapter entropy.
// - Description:
//   - Implements or verifies the test_wpa2_adapter_entropy source boundary.
// - Usage:
//   - Executed by offline host test discovery or the native test harness.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Offline regression cases for wpa2 adapter entropy.

// Synthetic provider only: test nonce publication, never actual entropy.
#include "wifi/Frames.hpp"
#include "wifi/Wpa2Supplicant.hpp"
#include "wifi/crypto/Wpa2CryptoAdapter.hpp"
#include <array>
#include <cstddef>
#include <cstdint>

namespace
{
    using namespace simpleath::ieee80211;
    using namespace simpleath::ieee80211::crypto;

    constexpr size_t kNonceBytes = 32U;
    constexpr size_t kKeyBytes = 16U;
    constexpr size_t kRscBytes = 8U;
    constexpr size_t kPartialBytes = 8U;
    constexpr size_t kValidRscBytes = 6U;
    constexpr uint8_t kPartialPattern = 0x55U;
    constexpr uint8_t kSentinelPattern = 0xa5U;
    constexpr int kDiagnosticModulo = 251;
    constexpr unsigned kCallsAfterReplacement = 5U;

    enum class RandomCase : uint8_t
    {
        PartialFailure,
        EmptySuccess,
        CompleteSuccess,
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
                if (length != kNonceBytes)
                {
                    return false;
                }
                if (self.behavior == RandomCase::PartialFailure)
                {
                    // A CSPRNG error may occur after filling part of a buffer.
                    // The adapter must not publish those incomplete bytes.
                    std::array<uint8_t, kPartialBytes> partial {};
                    partial.fill(kPartialPattern);
                    __builtin_memcpy(out, partial.data(), partial.size());
                    return false;
                }
                if (self.behavior == RandomCase::EmptySuccess)
                {
                    return true; // Contract-violating provider; no fresh nonce.
                }
                std::array<uint8_t, kNonceBytes> generated {};
                for (size_t index = 0U; index < generated.size(); ++index)
                {
                    generated.at(index) = static_cast<uint8_t>(index + 1U);
                }
                __builtin_memcpy(out, generated.data(), generated.size());
                if (self.replaceDuringRandom)
                {
                    // Reentrant hardware teardown/reconfiguration must not
                    // publish an in-flight nonce from the retired provider,
                    // even if the replacement reuses the same callback table.
                    self.replaceDuringRandom = false;
                    self.adapter->clear();
                    const KeyHardware replacement {
                        &self, random, pairwise, group, remove,
                    };
                    self.replacementConfigured =
                        self.adapter->configure(replacement);
                }
                return true;
            }

            static void replace(Provider &self)
            {
                self.adapter->clear();
                const KeyHardware replacement {
                    &self, random, pairwise, group, remove,
                };
                self.replacementConfigured =
                    self.adapter->configure(replacement);
            }

            static bool pairwise(void *context, const Mac & /*unused*/,
                                 const uint8_t /*unused*/[kKeyBytes])
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

            static bool group(void *context, uint8_t /*unused*/,
                              const uint8_t /*unused*/[kKeyBytes],
                              const uint8_t /*unused*/[kRscBytes])
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

            static void remove(void * /*unused*/)
            {
            }
    };

    int nonceCases(Provider &provider, const Wpa2Crypto &callbacks)
    {
        std::array<uint8_t, kNonceBytes> nonce {};
        nonce.fill(kSentinelPattern);
        const auto original = nonce;
        if (callbacks.generateNonce(callbacks.context, nonce.data()) ||
            provider.calls != 1U || nonce != original)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        provider.behavior = RandomCase::EmptySuccess;
        if (callbacks.generateNonce(callbacks.context, nonce.data()) ||
            provider.calls != 2U || nonce != original)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        provider.behavior = RandomCase::CompleteSuccess;
        if (!callbacks.generateNonce(callbacks.context, nonce.data()) ||
            provider.calls != 3U)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        for (size_t index = 0U; index < nonce.size(); ++index)
        {
            if (nonce.at(index) != static_cast<uint8_t>(index + 1U))
            {
                return (__LINE__ % kDiagnosticModulo) + 1;
            }
        }
        nonce.fill(kSentinelPattern);
        provider.replaceDuringRandom = true;
        if (callbacks.generateNonce(callbacks.context, nonce.data()) ||
            !provider.replacementConfigured || provider.calls != 4U ||
            nonce != original)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        if (!callbacks.generateNonce(callbacks.context, nonce.data()) ||
            provider.calls != kCallsAfterReplacement)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        for (size_t index = 0U; index < nonce.size(); ++index)
        {
            if (nonce.at(index) != static_cast<uint8_t>(index + 1U))
            {
                return (__LINE__ % kDiagnosticModulo) + 1;
            }
        }
        return 0;
    }

    int keyCases(Provider &provider, const Wpa2Crypto &callbacks)
    {
        // Callback callers cannot bypass address, CCMP key index or Key
        // RSC preflight to program hardware, even after nonce readiness.
        const Mac invalidAp {{0x01, 0x11, 0x22, 0x33, 0x44, 0x55}};
        const Mac validAp {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        std::array<uint8_t, kKeyBytes> key {};
        key.at(0U) = 1U;
        std::array<uint8_t, kRscBytes> validRsc {};
        for (size_t index = 0U; index < kValidRscBytes; ++index)
        {
            validRsc.at(index) = static_cast<uint8_t>(index + 1U);
        }
        auto invalidRsc = validRsc;
        invalidRsc.at(kValidRscBytes) = 1U;
        if (callbacks.installPairwiseTk(callbacks.context, invalidAp,
                                        key.data()) ||
            provider.pairwiseCalls != 0U)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        if (!callbacks.installPairwiseTk(callbacks.context, validAp,
                                         key.data()) ||
            provider.pairwiseCalls != 1U)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        if (callbacks.installGroupGtk(callbacks.context, 4U, key.data(),
                                      validRsc.data()) ||
            callbacks.installGroupGtk(callbacks.context, 2U, key.data(),
                                      invalidRsc.data()) ||
            provider.groupCalls != 0U)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        if (!callbacks.installGroupGtk(callbacks.context, 2U, key.data(),
                                       validRsc.data()) ||
            provider.groupCalls != 1U)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        // Reentrant replacement invalidates a success from the old owner;
        // neither a pairwise nor GTK callback may install stale key state.
        provider.replacementConfigured = false;
        provider.replaceDuringPairwise = true;
        if (callbacks.installPairwiseTk(callbacks.context, validAp,
                                        key.data()) ||
            !provider.replacementConfigured || provider.pairwiseCalls != 2U)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        if (!callbacks.installPairwiseTk(callbacks.context, validAp,
                                         key.data()) ||
            provider.pairwiseCalls != 3U)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        provider.replacementConfigured = false;
        provider.replaceDuringGroup = true;
        if (callbacks.installGroupGtk(callbacks.context, 2U, key.data(),
                                      validRsc.data()) ||
            !provider.replacementConfigured || provider.groupCalls != 2U)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        if (!callbacks.installGroupGtk(callbacks.context, 2U, key.data(),
                                       validRsc.data()) ||
            provider.groupCalls != 3U)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        return 0;
    }
} // namespace

int main()
{
    Provider provider {};
    Adapter adapter;
    provider.adapter = &adapter;
    const KeyHardware hardware {
        &provider,       Provider::random, Provider::pairwise,
        Provider::group, Provider::remove,
    };
    if (!adapter.configure(hardware))
    {
        return 1;
    }
    const Wpa2Crypto callbacks = adapter.callbacks();
    if (const int nonce = nonceCases(provider, callbacks))
    {
        return nonce;
    }
    const int keys = keyCases(provider, callbacks);
    adapter.clear();
    return keys;
}
