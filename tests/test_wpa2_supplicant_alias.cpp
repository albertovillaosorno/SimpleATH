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

    // Synthetic M3 fixture: deliberately fake crypto tests state and rollback,
    // not the cryptographic authenticity or Tahoe keycache implementation.
    struct HandshakeCallbacks
    {
            bool pairwiseSuccess = true;
            bool groupSuccess = true;
            bool alteredRsn = false;
            unsigned nonceCalls = 0;
            unsigned ptkCalls = 0;
            unsigned micCalls = 0;
            unsigned unwrapCalls = 0;
            unsigned pairwiseCalls = 0;
            unsigned groupCalls = 0;
            unsigned rollbackCalls = 0;
            uint8_t installedTk[16] {};
            uint8_t installedGtk[16] {};
            uint8_t installedRsc[8] {};
            uint8_t installedKeyId = 0;
    };

    bool handshakeNonce(void *context, uint8_t out[32])
    {
        auto &state = *static_cast<HandshakeCallbacks *>(context);
        ++state.nonceCalls;
        for (size_t index = 0; index < 32; ++index)
            out[index] = static_cast<uint8_t>(index + 1);
        return true;
    }

    bool handshakePtk(void *context, const uint8_t[32], const Mac &,
                      const Mac &, const uint8_t[32], const uint8_t[32],
                      uint8_t out[48])
    {
        auto &state = *static_cast<HandshakeCallbacks *>(context);
        ++state.ptkCalls;
        for (size_t index = 0; index < 48; ++index)
            out[index] = static_cast<uint8_t>(index + 1);
        return true;
    }

    bool handshakeMic(void *context, const uint8_t[16], const uint8_t *, size_t,
                      uint8_t out[16])
    {
        auto &state = *static_cast<HandshakeCallbacks *>(context);
        ++state.micCalls;
        for (size_t index = 0; index < 16; ++index)
            out[index] = 0x55;
        return true;
    }

    bool handshakeUnwrap(void *context, const uint8_t[16], const uint8_t *,
                         size_t, uint8_t *out, size_t capacity, size_t *written)
    {
        auto &state = *static_cast<HandshakeCallbacks *>(context);
        ++state.unwrapCalls;
        if (capacity < 48)
            return false;
        std::memcpy(out, kRsnIe, sizeof(kRsnIe));
        if (state.alteredRsn)
            out[3] = 1; // Changed M3 RSNE must never install keycache slots.
        const uint8_t gtkKde[24] {0xdd, 22,   0,    0x0f, 0xac, 1,
                                  2,    0,    0xa0, 0xa1, 0xa2, 0xa3,
                                  0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9,
                                  0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf};
        std::memcpy(out + sizeof(kRsnIe), gtkKde, sizeof(gtkKde));
        out[46] = 0xdd; // AES-wrap padding marker followed by zero.
        out[47] = 0;
        *written = 48;
        return true;
    }

    bool handshakePairwise(void *context, const Mac &ap, const uint8_t tk[16])
    {
        auto &state = *static_cast<HandshakeCallbacks *>(context);
        ++state.pairwiseCalls;
        if (std::memcmp(ap.bytes, kAp.bytes, sizeof(ap.bytes)) != 0)
            return false;
        std::memcpy(state.installedTk, tk, sizeof(state.installedTk));
        return state.pairwiseSuccess;
    }

    bool handshakeGroup(void *context, uint8_t keyId, const uint8_t gtk[16],
                        const uint8_t rsc[8])
    {
        auto &state = *static_cast<HandshakeCallbacks *>(context);
        ++state.groupCalls;
        state.installedKeyId = keyId;
        std::memcpy(state.installedGtk, gtk, sizeof(state.installedGtk));
        std::memcpy(state.installedRsc, rsc, sizeof(state.installedRsc));
        return state.groupSuccess;
    }

    void handshakeRollback(void *context)
    {
        ++static_cast<HandshakeCallbacks *>(context)->rollbackCalls;
    }

    Wpa2Crypto handshakeCrypto(HandshakeCallbacks &state)
    {
        return {&state,         handshakeNonce,   handshakePtk,
                handshakeMic,   handshakeUnwrap,  handshakePairwise,
                handshakeGroup, handshakeRollback};
    }

    void makeM3(uint8_t (&frame)[155])
    {
        std::memset(frame, 0, sizeof(frame));
        frame[0] = 2;     // EAPOL version.
        frame[1] = 3;     // EAPOL-Key.
        frame[3] = 151;   // Fixed 95-byte body and 56-byte wrapped payload.
        frame[4] = 2;     // RSN key descriptor.
        frame[5] = 0x13;  // Encrypted data, secure, MIC, ACK, install.
        frame[6] = 0xca;  // Pairwise, descriptor version 2.
        frame[8] = 16;    // CCMP pairwise key length.
        frame[16] = 2;    // M3 replay counter strictly exceeds M1=1.
        frame[17] = 7;    // Same authenticator nonce as M1.
        frame[65] = 0x34; // Key RSC: six little-endian GTK PN bytes.
        frame[66] = 0x12;
        frame[70] = 0x01;
        for (size_t index = 81; index < 97; ++index)
            frame[index] = 0x55; // Fake MIC, checked against callback.
        frame[98] = 56;          // Wrapped key-data size in bytes.
        for (size_t index = 99; index < sizeof(frame); ++index)
            frame[index] = static_cast<uint8_t>(index);
    }

    enum class HandshakeCase : uint8_t
    {
        Success,
        PairwiseFailure,
        GroupFailure,
        InvalidRsc,
        InvalidReplay,
        InvalidMic,
        ChangedRsn
    };

    bool exerciseM3(HandshakeCase scenario)
    {
        HandshakeCallbacks state {};
        state.pairwiseSuccess = scenario != HandshakeCase::PairwiseFailure;
        state.groupSuccess = scenario != HandshakeCase::GroupFailure;
        state.alteredRsn = scenario == HandshakeCase::ChangedRsn;
        Wpa2Supplicant supplicant;
        uint8_t pmk[32] {};
        pmk[0] = 1;
        if (supplicant.begin(handshakeCrypto(state), kStation, kAp, pmk, kRsnIe,
                             sizeof(kRsnIe)) != Wpa2Result::Ok)
            return false;
        uint8_t m1[99] {};
        makeM1(m1);
        uint8_t m2[121] {};
        size_t m2Written = 0;
        if (supplicant.onMessage1(m1, sizeof(m1), m2, sizeof(m2), m2Written) !=
                Wpa2Result::Ok ||
            m2Written != sizeof(m2) || state.nonceCalls != 1 ||
            state.ptkCalls != 1 || state.micCalls != 1)
            return false;
        uint8_t m3[155] {};
        makeM3(m3);
        if (scenario == HandshakeCase::InvalidRsc)
            m3[71] = 1; // High RSC byte is forbidden for CCMP GTK.
        if (scenario == HandshakeCase::InvalidReplay)
            m3[16] = 1; // Replay counter not greater than M1.
        if (scenario == HandshakeCase::InvalidMic)
            m3[81] ^= 1;
        uint8_t m4[99] {};
        std::memset(m4, 0xa5, sizeof(m4));
        size_t m4Written = 17;
        const Wpa2Result result =
            supplicant.onMessage3(m3, sizeof(m3), m4, sizeof(m4), m4Written);
        if (scenario == HandshakeCase::Success)
        {
            const uint8_t expectedRsc[8] {0x34, 0x12, 0, 0, 0, 1, 0, 0};
            if (result != Wpa2Result::Ok || m4Written != sizeof(m4) ||
                !supplicant.keysInstalled() || state.pairwiseCalls != 1 ||
                state.groupCalls != 1 || state.rollbackCalls != 0 ||
                state.installedKeyId != 2 || state.unwrapCalls != 1 ||
                state.micCalls != 3 ||
                std::memcmp(state.installedRsc, expectedRsc, 8) != 0)
                return false;
            for (size_t index = 0; index < 16; ++index)
                if (state.installedTk[index] != index + 33 ||
                    state.installedGtk[index] != index + 0xa0)
                    return false;
            supplicant.reset();
            return state.rollbackCalls == 1 &&
                   supplicant.state() == Wpa2State::Inactive;
        }
        Wpa2Result expected = Wpa2Result::HardwareKeyInstallFailure;
        if (scenario == HandshakeCase::InvalidRsc)
            expected = Wpa2Result::InvalidKeySequenceCounter;
        if (scenario == HandshakeCase::InvalidReplay)
            expected = Wpa2Result::InvalidReplayCounter;
        if (scenario == HandshakeCase::InvalidMic)
            expected = Wpa2Result::MicMismatch;
        if (scenario == HandshakeCase::ChangedRsn)
            expected = Wpa2Result::RsnMismatch;
        if (result != expected || m4Written != 0 || m4[0] != 0xa5 ||
            supplicant.keysInstalled() ||
            supplicant.state() != Wpa2State::Failed)
            return false;
        const bool installationFailed =
            scenario == HandshakeCase::PairwiseFailure ||
            scenario == HandshakeCase::GroupFailure;
        if (state.rollbackCalls != (installationFailed ? 1u : 0u) ||
            state.pairwiseCalls != (installationFailed ? 1u : 0u) ||
            state.groupCalls !=
                (scenario == HandshakeCase::GroupFailure ? 1u : 0u) ||
            state.unwrapCalls !=
                (scenario == HandshakeCase::InvalidMic ||
                         scenario == HandshakeCase::InvalidReplay ||
                         scenario == HandshakeCase::InvalidRsc
                     ? 0u
                     : 1u))
            return false;
        supplicant.reset();
        return state.rollbackCalls == (installationFailed ? 1u : 0u);
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
    auto callbacks = fakeCallbacks(fake);
    callbacks.context = &supplicant;
    if (supplicant.begin(callbacks, kStation, kAp, pmk, kRsnIe,
                         sizeof(kRsnIe)) != Wpa2Result::InvalidArgument ||
        supplicant.state() != Wpa2State::Inactive || fake.calls)
        return 11;
    callbacks.context = &callbacks;
    if (supplicant.begin(callbacks, kStation, kAp, pmk, kRsnIe,
                         sizeof(kRsnIe)) != Wpa2Result::InvalidArgument ||
        supplicant.state() != Wpa2State::Inactive || fake.calls)
        return 12;
    callbacks = fakeCallbacks(fake);
    const auto *aliasedPmk = reinterpret_cast<const uint8_t *>(&supplicant);
    if (supplicant.begin(callbacks, kStation, kAp, aliasedPmk, kRsnIe,
                         sizeof(kRsnIe)) != Wpa2Result::InvalidArgument ||
        supplicant.state() != Wpa2State::Inactive || fake.calls)
        return 13;
    if (supplicant.begin(callbacks, kStation, kAp, pmk, aliasedPmk,
                         sizeof(kRsnIe)) != Wpa2Result::InvalidArgument ||
        supplicant.state() != Wpa2State::Inactive || fake.calls)
        return 14;
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
    const HandshakeCase scenarios[] = {
        HandshakeCase::Success,       HandshakeCase::PairwiseFailure,
        HandshakeCase::GroupFailure,  HandshakeCase::InvalidRsc,
        HandshakeCase::InvalidReplay, HandshakeCase::InvalidMic,
        HandshakeCase::ChangedRsn};
    for (const auto scenario : scenarios)
        if (!exerciseM3(scenario))
            return 15 + static_cast<int>(scenario);
    return 0;
}
