// SPDX-License-Identifier: AGPL-3.0-only
// Fake WPA2 callbacks and EAPOL bytes only: no radio, keycache or PCI I/O.
#include "wifi/Wpa2Supplicant.hpp"
#include <cstring>

using namespace simpleath::ieee80211;

namespace
{
    constexpr uint8_t kRsnIe[22] {48, 20,   1,    0,    0,    0x0f, 0xac, 4,
                                  1,  0,    0,    0x0f, 0xac, 4,    1,    0,
                                  0,  0x0f, 0xac, 2,    0,    0};
    const Mac kStation {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
    const Mac kAp {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};

    struct FakeCrypto
    {
            size_t sentinel = 1234567;
            unsigned calls = 0;
            uint8_t padding[256] {};
    };

    bool nonce(void *ctx, uint8_t out[32])
    {
        ++static_cast<FakeCrypto *>(ctx)->calls;
        for (size_t i = 0; i < 32; ++i)
            out[i] = static_cast<uint8_t>(i + 1);
        return true;
    }

    bool derive(void *ctx, const uint8_t[32], const Mac &, const Mac &,
                const uint8_t[32], const uint8_t[32], uint8_t out[48])
    {
        ++static_cast<FakeCrypto *>(ctx)->calls;
        for (size_t i = 0; i < 48; ++i)
            out[i] = static_cast<uint8_t>(i + 1);
        return true;
    }

    bool mic(void *ctx, const uint8_t[16], const uint8_t *, size_t,
             uint8_t out[16])
    {
        ++static_cast<FakeCrypto *>(ctx)->calls;
        for (size_t i = 0; i < 16; ++i)
            out[i] = 0x55;
        return true;
    }

    bool unwrap(void *, const uint8_t[16], const uint8_t *, size_t, uint8_t *,
                size_t, size_t *)
    {
        return false;
    }

    bool pairwise(void *, const Mac &, const uint8_t[16])
    {
        return false;
    }

    bool group(void *, uint8_t, const uint8_t[16], const uint8_t[8])
    {
        return false;
    }

    void remove(void *)
    {
    }

    Wpa2Crypto fakeCallbacks(FakeCrypto &ctx)
    {
        return {&ctx, nonce, derive, mic, unwrap, pairwise, group, remove};
    }

    void makeM1(uint8_t *frame)
    {
        for (size_t i = 0; i < 99; ++i)
            frame[i] = 0;
        frame[0] = 2;    // EAPOL version 2.
        frame[1] = 3;    // EAPOL-Key.
        frame[3] = 95;   // 95-byte fixed descriptor body.
        frame[4] = 2;    // RSN descriptor type.
        frame[6] = 0x8a; // Pairwise, ACK, descriptor version 2.
        frame[8] = 16;   // CCMP key length.
        frame[16] = 1;   // Nonzero replay counter.
        frame[17] = 7;   // Nonzero ANonce.
    }

    struct alignas(size_t) RxWord
    {
            size_t word;
            uint8_t rest[256];
    };
} // namespace

int main()
{
    FakeCrypto fake {};
    Wpa2Supplicant supplicant;
    uint8_t pmk[32] {};
    pmk[0] = 1;
    if (supplicant.begin(fakeCallbacks(fake), kStation, kAp, pmk, kRsnIe,
                         sizeof(kRsnIe)) != Wpa2Result::Ok)
        return 1;

    RxWord rx {};
    auto *m1 = reinterpret_cast<uint8_t *>(&rx);
    makeM1(m1);
    RxWord preserved = rx;
    uint8_t response[256] {};
    if (supplicant.onMessage1(m1, 99, response, sizeof(response), rx.word) !=
            Wpa2Result::InvalidArgument ||
        std::memcmp(&rx, &preserved, sizeof(rx)) || fake.calls ||
        supplicant.state() != Wpa2State::AwaitingMessage1)
        return 2;

    size_t written = 99;
    if (supplicant.onMessage1(m1, 99, m1 + 4, 200, written) !=
            Wpa2Result::InvalidArgument ||
        written != 99 || std::memcmp(&rx, &preserved, sizeof(rx)) ||
        fake.calls || supplicant.state() != Wpa2State::AwaitingMessage1)
        return 3;

    RxWord tx {};
    auto *txBytes = reinterpret_cast<uint8_t *>(&tx);
    tx.word = 0x12345678;
    const RxWord savedTx = tx;
    if (supplicant.onMessage1(m1, 99, txBytes, sizeof(tx), tx.word) !=
            Wpa2Result::InvalidArgument ||
        std::memcmp(&tx, &savedTx, sizeof(tx)) || fake.calls)
        return 4;

    if (supplicant.onMessage1(m1, 99, response, sizeof(response),
                              fake.sentinel) != Wpa2Result::InvalidArgument ||
        fake.sentinel != 1234567 || fake.calls)
        return 5;
    if (supplicant.onMessage1(m1, 99, reinterpret_cast<uint8_t *>(&fake), 121,
                              written) != Wpa2Result::InvalidArgument ||
        fake.sentinel != 1234567 || fake.calls || written != 99)
        return 6;

    if (supplicant.onMessage1(m1, 99, response, sizeof(response), written) !=
            Wpa2Result::Ok ||
        written != 121 || fake.calls != 3 ||
        supplicant.state() != Wpa2State::AwaitingMessage3 ||
        response[3] != 117 || response[7] != 0 || response[8] != 0 ||
        std::memcmp(&rx, &preserved, sizeof(rx)))
        return 7;

    // M3 must reject the same aliases *before* clearing its output length,
    // even if the incoming frame is not itself a valid M3.
    if (supplicant.onMessage3(m1, 99, response, sizeof(response), rx.word) !=
            Wpa2Result::InvalidArgument ||
        std::memcmp(&rx, &preserved, sizeof(rx)) || fake.calls != 3 ||
        supplicant.state() != Wpa2State::AwaitingMessage3)
        return 8;
    if (supplicant.onMessage3(m1, 99, reinterpret_cast<uint8_t *>(&supplicant),
                              121, written) != Wpa2Result::InvalidArgument ||
        written != 121 || supplicant.state() != Wpa2State::AwaitingMessage3 ||
        fake.calls != 3)
        return 9;
    if (supplicant.onMessage3(m1, 99, response, sizeof(response), written) !=
            Wpa2Result::WrongMessage ||
        written || fake.calls != 3 ||
        supplicant.state() != Wpa2State::AwaitingMessage3)
        return 10;
    supplicant.reset();
    return 0;
}
