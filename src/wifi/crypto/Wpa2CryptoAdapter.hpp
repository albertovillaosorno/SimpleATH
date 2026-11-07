// SPDX-License-Identifier: AGPL-3.0-only
// Bridges portable WPA2 primitives to the existing EAPOL supplicant.
// A real macOS backend MUST provide CSPRNG and AR9565 CCMP keycache operations.
// No dummy entropy, fabricated keys or software-only "installed" result.
#ifndef SIMPLEATH_WIFI_WPA2_CRYPTO_ADAPTER_HPP
#define SIMPLEATH_WIFI_WPA2_CRYPTO_ADAPTER_HPP

#include "../Wpa2Supplicant.hpp"
#include "Wpa2Primitives.hpp"

namespace simpleath
{
    namespace ieee80211
    {
        namespace crypto
        {

            struct KeyHardware
            {
                    void *context;
                    // MUST be backed by a kernel cryptographic random
                    // generator; never device timestamps, predictable counters
                    // or boot time.
                    bool (*secureRandom)(void *context, uint8_t *data,
                                         size_t length);
                    // MUST program the device's true CCMP keycache using
                    // validated PCI owner and keep the correct key-ids, address
                    // and PN state.
                    bool (*installPairwise)(void *context, const Mac &ap,
                                            const uint8_t key[16]);
                    // keyRsc is the MIC-authenticated EAPOL M3 RSC:
                    // CCMP receive PN bytes 0..5 (least-significant first),
                    // followed by two zeros. Install GTK and receive PN/replay
                    // floor as one fail-closed operation. Never reset PN to 0.
                    bool (*installGroup)(void *context, uint8_t keyId,
                                         const uint8_t key[16],
                                         const uint8_t keyRsc[8]);
                    void (*removeKeys)(void *context);
            };

            class Adapter final
            {
                public:
                    Adapter();
                    Adapter(const Adapter &) = delete;
                    Adapter &operator=(const Adapter &) = delete;
                    // All callbacks must be real, nonblocking and serialized.
                    // This layer cannot authenticate their implementation or
                    // claim hardware readiness.
                    bool configure(const KeyHardware &hardware);
                    // Invalid adapter returns an all-null backend, which the
                    // supplicant will reject in begin(). Callbacks are valid
                    // only while Adapter lives.
                    Wpa2Crypto callbacks();
                    void clear();

                private:
                    static bool nonce(void *context, uint8_t outNonce[32]);
                    static bool ptk(void *context, const uint8_t pmk[32],
                                    const Mac &ap, const Mac &station,
                                    const uint8_t aNonce[32],
                                    const uint8_t sNonce[32],
                                    uint8_t outPtk[48]);
                    static bool mic(void *context, const uint8_t key[16],
                                    const uint8_t *eapol, size_t frameBytes,
                                    uint8_t outMic[16]);
                    static bool unwrap(void *context, const uint8_t kek[16],
                                       const uint8_t *wrapped,
                                       size_t wrappedBytes, uint8_t *out,
                                       size_t capacity, size_t *resultLength);
                    static bool pairwise(void *context, const Mac &ap,
                                         const uint8_t key[16]);
                    static bool group(void *context, uint8_t keyId,
                                      const uint8_t key[16],
                                      const uint8_t keyRsc[8]);
                    static void remove(void *context);
                    KeyHardware hardware_;
                    bool configured_;
            };

        } // namespace crypto
    } // namespace ieee80211
} // namespace simpleath
#endif
