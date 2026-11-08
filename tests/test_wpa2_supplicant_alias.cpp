// SPDX-License-Identifier: AGPL-3.0-only
// Fake WPA2 callbacks and EAPOL bytes only: no radio, keycache or PCI I/O.
#include "wifi/Station.hpp"
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
            Wpa2Supplicant *owner = nullptr;
            bool revokeOnNonce = false;
            bool revokeOnPtk = false;
            unsigned revokeMicCall = 0;
            unsigned zeroMicCall = 0;
            bool revokeOnUnwrap = false;
            bool revokeOnPairwise = false;
            bool revokeOnGroup = false;
            unsigned nonceCalls = 0;
            unsigned ptkCalls = 0;
            unsigned micCalls = 0;
            unsigned unwrapCalls = 0;
            unsigned pairwiseCalls = 0;
            unsigned groupCalls = 0;
            unsigned rollbackCalls = 0;
            uint8_t observedPmk = 0;
            uint8_t observedKck = 0;
            uint8_t observedKek = 0;
            uint8_t installedTk[16] {};
            uint8_t installedGtk[16] {};
            uint8_t installedRsc[8] {};
            uint8_t installedKeyId = 0;
    };

    bool handshakeNonce(void *context, uint8_t out[32])
    {
        auto &state = *static_cast<HandshakeCallbacks *>(context);
        ++state.nonceCalls;
        if (state.revokeOnNonce && state.owner)
            state.owner->reset();
        for (size_t index = 0; index < 32; ++index)
            out[index] = static_cast<uint8_t>(index + 1);
        return true;
    }

    bool handshakePtk(void *context, const uint8_t pmk[32], const Mac &,
                      const Mac &, const uint8_t[32], const uint8_t[32],
                      uint8_t out[48])
    {
        auto &state = *static_cast<HandshakeCallbacks *>(context);
        ++state.ptkCalls;
        if (state.revokeOnPtk && state.owner)
            state.owner->reset();
        state.observedPmk = pmk[0];
        for (size_t index = 0; index < 48; ++index)
            out[index] = static_cast<uint8_t>(index + 1);
        return true;
    }

    bool handshakeMic(void *context, const uint8_t kck[16], const uint8_t *,
                      size_t, uint8_t out[16])
    {
        auto &state = *static_cast<HandshakeCallbacks *>(context);
        ++state.micCalls;
        if (state.revokeMicCall == state.micCalls && state.owner)
            state.owner->reset();
        state.observedKck = kck[0];
        for (size_t index = 0; index < 16; ++index)
            out[index] = state.zeroMicCall == state.micCalls ? 0 : 0x55;
        return true;
    }

    bool handshakeUnwrap(void *context, const uint8_t kek[16], const uint8_t *,
                         size_t, uint8_t *out, size_t capacity, size_t *written)
    {
        auto &state = *static_cast<HandshakeCallbacks *>(context);
        ++state.unwrapCalls;
        if (state.revokeOnUnwrap && state.owner)
            state.owner->reset();
        state.observedKek = kek[0];
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
        if (state.revokeOnPairwise && state.owner)
            state.owner->reset();
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
        if (state.revokeOnGroup && state.owner)
            state.owner->reset();
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

    bool waitingForKeys(Station &owner, const Mac &station, const Mac &ap)
    {
        // A caller-built but internally consistent WPA2 BSS can drive the
        // portable station state machine without native radio or TX.
        Bss candidate {};
        candidate.occupied = true;
        candidate.beacon.bssid = ap;
        candidate.beacon.capabilities = 0x11; // ESS + privacy.
        candidate.beacon.infrastructure = true;
        candidate.beacon.intervalTu = 100;
        candidate.beacon.channel = 6;
        candidate.beacon.ssidLength = 4;
        std::memcpy(candidate.beacon.ssid, "Test", 4);
        candidate.beacon.rates[0] = 0x82;
        candidate.beacon.rates[1] = 0x84;
        candidate.beacon.rateCount = 2;
        candidate.beacon.rsn.security = Security::Wpa2Personal;
        candidate.beacon.rsn.present = true;
        candidate.beacon.rsn.valid = true;
        candidate.beacon.rsn.pairwiseCcmp = true;
        candidate.beacon.rsn.groupCcmp = true;
        candidate.beacon.rsn.akmPsk = true;
        candidate.beacon.rsnIeLength = sizeof(kRsnIe);
        std::memcpy(candidate.beacon.rsnIe, kRsnIe, sizeof(kRsnIe));
        if (owner.enterScanning(true, true) != StationResult::Ok ||
            owner.select(station, candidate) != StationResult::Ok)
            return false;

        uint8_t outgoing[128] {};
        size_t written = 0;
        if (owner.authenticationRequest(1, outgoing, sizeof(outgoing),
                                        written) != Result::Ok)
            return false;
        uint8_t auth[30] {};
        auth[0] = 0xb0; // Open authentication response.
        std::memcpy(auth + 4, station.bytes, 6);
        std::memcpy(auth + 10, ap.bytes, 6);
        std::memcpy(auth + 16, ap.bytes, 6);
        auth[26] = 2; // Transaction 2, status zero.
        if (owner.onAuthenticationResponse(auth, sizeof(auth)) !=
                StationResult::Ok ||
            owner.associationRequest(2, outgoing, sizeof(outgoing), written) !=
                Result::Ok)
            return false;

        uint8_t assoc[34] {};
        assoc[0] = 0x10; // Association response.
        std::memcpy(assoc + 4, station.bytes, 6);
        std::memcpy(assoc + 10, ap.bytes, 6);
        std::memcpy(assoc + 16, ap.bytes, 6);
        assoc[24] = 0x11; // ESS + privacy, matching the WPA2 BSS.
        assoc[28] = 1;
        assoc[29] = 0xc0; // Valid AID 1.
        assoc[30] = 1;    // Supported rates.
        assoc[31] = 2;
        assoc[32] = 0x82;
        assoc[33] = 0x84;
        return owner.onAssociationResponse(assoc, sizeof(assoc)) ==
                   StationResult::Wpa2CryptoNotImplemented &&
               owner.state() == StationState::WaitingForWpa2Keys;
    }

    // A standalone EAPOL-Key operation must consume exactly the declared
    // packet. A permissive lower-level parser may identify a valid prefix,
    // but neither the M1 replay state nor M3 keycache may accept a trailing,
    // unauthenticated suffix supplied by a direct public caller.
    bool rejectTrailingHandshakeBytes()
    {
        HandshakeCallbacks callbacks {};
        Wpa2Supplicant supplicant;
        uint8_t pmk[32] {};
        pmk[0] = 1;
        if (supplicant.begin(handshakeCrypto(callbacks), kStation, kAp, pmk,
                             kRsnIe, sizeof(kRsnIe)) != Wpa2Result::Ok)
            return false;
        uint8_t m1[100] {};
        makeM1(m1);
        m1[99] = 0xa5;
        uint8_t m2[121] {};
        std::memset(m2, 0xa5, sizeof(m2));
        size_t written = 17;
        if (supplicant.onMessage1(m1, sizeof(m1), m2, sizeof(m2), written) !=
                Wpa2Result::MalformedEapol ||
            written != 0 || m2[0] != 0xa5 || callbacks.nonceCalls != 0 ||
            supplicant.state() != Wpa2State::AwaitingMessage1)
            return false;
        if (supplicant.onMessage1(m1, sizeof(m1) - 1, m2, sizeof(m2),
                                  written) != Wpa2Result::Ok ||
            written != sizeof(m2) || callbacks.micCalls != 1)
            return false;
        uint8_t m3[155] {};
        makeM3(m3);
        uint8_t trailingM3[156] {};
        std::memcpy(trailingM3, m3, sizeof(m3));
        trailingM3[155] = 0x5a;
        uint8_t m4[99] {};
        std::memset(m4, 0xa5, sizeof(m4));
        written = 17;
        if (supplicant.onMessage3(trailingM3, sizeof(trailingM3), m4,
                                  sizeof(m4),
                                  written) != Wpa2Result::MalformedEapol ||
            written != 0 || m4[0] != 0xa5 || callbacks.micCalls != 1 ||
            callbacks.unwrapCalls != 0 || callbacks.pairwiseCalls != 0 ||
            supplicant.state() != Wpa2State::AwaitingMessage3)
            return false;
        if (supplicant.onMessage3(m3, sizeof(m3), m4, sizeof(m4), written) !=
                Wpa2Result::Ok ||
            written != sizeof(m4) || !supplicant.keysInstalled())
            return false;
        supplicant.reset();
        return callbacks.rollbackCalls == 1;
    }

    bool rejectZeroMicCallback(unsigned zeroMicCall)
    {
        // A callback reporting success with a zero MIC cannot authorize an
        // EAPOL-Key response: the public parser rejects MIC-present/zero.
        // M4 must be checked BEFORE any keycache installation is attempted.
        HandshakeCallbacks callbacks {};
        callbacks.zeroMicCall = zeroMicCall;
        Wpa2Supplicant supplicant;
        uint8_t pmk[32] {};
        pmk[0] = 1;
        if (supplicant.begin(handshakeCrypto(callbacks), kStation, kAp, pmk,
                             kRsnIe, sizeof(kRsnIe)) != Wpa2Result::Ok)
            return false;
        uint8_t m1[99] {};
        makeM1(m1);
        uint8_t m2[121] {};
        std::memset(m2, 0xa5, sizeof(m2));
        size_t written = 17;
        const Wpa2Result first =
            supplicant.onMessage1(m1, sizeof(m1), m2, sizeof(m2), written);
        if (zeroMicCall == 1)
        {
            if (first != Wpa2Result::MicCalculationFailure || written != 0 ||
                m2[0] != 0xa5 || callbacks.micCalls != 1 ||
                callbacks.pairwiseCalls || callbacks.groupCalls ||
                supplicant.state() != Wpa2State::Failed ||
                supplicant.keysInstalled())
                return false;
        }
        else
        {
            if (first != Wpa2Result::Ok || written != sizeof(m2))
                return false;
            uint8_t m3[155] {};
            makeM3(m3);
            uint8_t m4[99] {};
            std::memset(m4, 0xa5, sizeof(m4));
            written = 17;
            const Wpa2Result third =
                supplicant.onMessage3(m3, sizeof(m3), m4, sizeof(m4), written);
            if (third != Wpa2Result::MicCalculationFailure || written != 0 ||
                m4[0] != 0xa5 || callbacks.micCalls != 3 ||
                callbacks.unwrapCalls != 1 || callbacks.pairwiseCalls ||
                callbacks.groupCalls || supplicant.keysInstalled() ||
                supplicant.state() != Wpa2State::Failed)
                return false;
        }
        supplicant.reset();
        return callbacks.rollbackCalls == 0;
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
            // Keys installed for a different link must not authorize a
            // public Station to enter HardwareKeysInstalled.
            const Mac foreignStation {{0x02, 0x66, 0x77, 0x88, 0x99, 0xbb}};
            const Mac foreignAp {{0x02, 0x11, 0x22, 0x33, 0x44, 0x66}};
            Station wrongStation;
            Station wrongAp;
            Station correct;
            if (!waitingForKeys(wrongStation, foreignStation, kAp) ||
                !waitingForKeys(wrongAp, kStation, foreignAp) ||
                !waitingForKeys(correct, kStation, kAp) ||
                wrongStation.recordInstalledWpa2Keys(supplicant) !=
                    StationResult::Wpa2CryptoNotImplemented ||
                wrongStation.state() != StationState::WaitingForWpa2Keys ||
                wrongAp.recordInstalledWpa2Keys(supplicant) !=
                    StationResult::Wpa2CryptoNotImplemented ||
                wrongAp.state() != StationState::WaitingForWpa2Keys ||
                correct.recordInstalledWpa2Keys(supplicant) !=
                    StationResult::NetworkInterfaceNotImplemented ||
                correct.state() != StationState::HardwareKeysInstalled)
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

    // Crypto callbacks may synchronously revoke the owner. No continuation
    // may call a cleared provider, publish a response, or restore old state.
    bool rejectRevokedCallback(unsigned stage)
    {
        HandshakeCallbacks callbacks {};
        Wpa2Supplicant supplicant;
        callbacks.owner = &supplicant;
        callbacks.revokeOnNonce = stage == 0;
        callbacks.revokeOnPtk = stage == 1;
        callbacks.revokeMicCall = stage == 2   ? 1u
                                  : stage == 3 ? 2u
                                  : stage == 7 ? 3u
                                               : 0u;
        callbacks.revokeOnUnwrap = stage == 4;
        callbacks.revokeOnPairwise = stage == 5;
        callbacks.revokeOnGroup = stage == 6;
        uint8_t pmk[32] {};
        pmk[0] = 1;
        if (supplicant.begin(handshakeCrypto(callbacks), kStation, kAp, pmk,
                             kRsnIe, sizeof(kRsnIe)) != Wpa2Result::Ok)
            return false;
        uint8_t m1[99] {};
        makeM1(m1);
        uint8_t m2[121] {};
        std::memset(m2, 0xa5, sizeof(m2));
        size_t written = 123;
        if (stage <= 2)
        {
            if (supplicant.onMessage1(m1, sizeof(m1), m2, sizeof(m2),
                                      written) != Wpa2Result::InvalidState ||
                written != 0 || m2[0] != 0xa5 ||
                supplicant.state() != Wpa2State::Inactive ||
                callbacks.groupCalls || callbacks.pairwiseCalls)
                return false;
            return (stage != 1 || callbacks.observedPmk == 1) &&
                   (stage != 2 || callbacks.observedKck == 1);
        }
        if (supplicant.onMessage1(m1, sizeof(m1), m2, sizeof(m2), written) !=
                Wpa2Result::Ok ||
            written != sizeof(m2))
            return false;
        uint8_t m3[155] {};
        makeM3(m3);
        uint8_t m4[99] {};
        std::memset(m4, 0xa5, sizeof(m4));
        written = 123;
        const Wpa2Result outcome =
            supplicant.onMessage3(m3, sizeof(m3), m4, sizeof(m4), written);
        const unsigned expectedRollback = (stage == 5 || stage == 6) ? 1u : 0u;
        return outcome == Wpa2Result::InvalidState && written == 0 &&
               m4[0] == 0xa5 && supplicant.state() == Wpa2State::Inactive &&
               callbacks.rollbackCalls == expectedRollback &&
               callbacks.groupCalls == (stage == 6 ? 1u : 0u) &&
               callbacks.pairwiseCalls ==
                   ((stage == 5 || stage == 6) ? 1u : 0u) &&
               ((stage != 3 && stage != 7) || callbacks.observedKck == 1) &&
               (stage != 4 || callbacks.observedKek == 17) &&
               (stage != 5 || callbacks.installedTk[0] == 33);
    }

    bool rejectEapolParserInputAlias()
    {
        uint8_t independent[99] {};
        makeM1(independent);
        KeyFrame parsed {};
        if (parseEapolKey(independent, sizeof(independent), parsed) !=
                EapolResult::Ok ||
            parsed.message != KeyMessage::Pairwise1 ||
            parsed.eapolBytes != independent || parsed.eapolLength != 99)
            return false;

        struct AliasedInput
        {
                KeyFrame result;
                uint8_t storage[128];
        } input {};

        auto *bytes = reinterpret_cast<uint8_t *>(&input);
        makeM1(bytes);
        uint8_t before[sizeof(input)] {};
        std::memcpy(before, &input, sizeof(input));
        if (parseEapolKey(bytes, 99, input.result) !=
                EapolResult::OverlappingBuffers ||
            std::memcmp(&input, before, sizeof(input)) != 0)
            return false;

        ReplayGuard guard;
        const auto *guardBytes = reinterpret_cast<const uint8_t *>(&guard);
        KeyFrame aliasedNonce = parsed;
        aliasedNonce.nonce = guardBytes;
        if (guard.acceptMessage1(aliasedNonce) !=
                EapolResult::OverlappingBuffers ||
            guard.phase() != HandshakePhase::Empty ||
            guard.lastReplayCounter() != 0)
            return false;
        if (guard.acceptMessage1(parsed) != EapolResult::Ok ||
            guard.phase() != HandshakePhase::AwaitingMessage3 ||
            guard.lastReplayCounter() != 1)
            return false;
        aliasedNonce.message = KeyMessage::Pairwise3;
        aliasedNonce.replayCounter = 2;
        if (guard.acceptVerifiedMessage3(aliasedNonce, true) !=
                EapolResult::OverlappingBuffers ||
            guard.phase() != HandshakePhase::AwaitingMessage3 ||
            guard.lastReplayCounter() != 1)
            return false;

        // A reused parser output must not keep old borrowed RX pointers when
        // a subsequent malformed input is refused. Only an overlap contract
        // error preserves the output untouched.
        independent[0] = 0;
        if (parseEapolKey(independent, sizeof(independent), parsed) !=
                EapolResult::UnsupportedVersion ||
            parsed.eapolBytes || parsed.eapolLength || parsed.nonce ||
            parsed.mic || parsed.keyData ||
            parsed.message != KeyMessage::Unknown)
            return false;
        independent[0] = 2;
        if (parseEapolKey(independent, sizeof(independent), parsed) !=
                EapolResult::Ok ||
            parseEapolKey(nullptr, 0, parsed) != EapolResult::NullBuffer ||
            parsed.eapolBytes || parsed.nonce || parsed.mic || parsed.keyData)
            return false;
        return true;
    }

    bool rejectMalformedMessage2()
    {
        // Pairwise M2 includes a freshly generated nonzero SNonce and
        // advertises zero Key Length. Merely setting MIC+pairwise flags
        // must not classify a malformed message as a valid WPA2 handshake.
        uint8_t message[99] {};
        makeM1(message);
        message[5] = 0x01;  // MIC present; no authenticator ACK.
        message[6] = 0x0a;  // Pairwise, RSN descriptor version 2.
        message[8] = 0;     // Supplicant Key Length is zero.
        message[81] = 0x55; // Synthetic nonzero MIC, not authenticated here.
        KeyFrame parsed {};
        if (parseEapolKey(message, sizeof(message), parsed) !=
                EapolResult::Ok ||
            parsed.message != KeyMessage::Pairwise2)
            return false;
        message[17] = 0; // Invalid all-zero SNonce.
        if (parseEapolKey(message, sizeof(message), parsed) !=
                EapolResult::InvalidKeyInformation ||
            parsed.eapolBytes || parsed.nonce)
            return false;
        message[17] = 7;
        message[8] = 16; // M1/M3 key length must not be copied to M2.
        return parseEapolKey(message, sizeof(message), parsed) ==
                   EapolResult::InvalidKeyInformation &&
               !parsed.eapolBytes && !parsed.nonce;
    }

    bool rejectWrongPairwiseKeyLengths()
    {
        // The authenticator M1/M3 carry CCMP Key Length=16. The
        // supplicant M2/M4 carry zero. A public parsed KeyFrame should
        // not claim a valid handshake message with opposite lengths.
        uint8_t first[99] {};
        makeM1(first);
        KeyFrame parsed {};
        first[8] = 0;
        if (parseEapolKey(first, sizeof(first), parsed) !=
                EapolResult::InvalidKeyInformation ||
            parsed.eapolBytes || parsed.nonce)
            return false;
        first[8] = 16;
        if (parseEapolKey(first, sizeof(first), parsed) != EapolResult::Ok ||
            parsed.message != KeyMessage::Pairwise1)
            return false;

        uint8_t third[155] {};
        makeM3(third);
        third[8] = 0;
        if (parseEapolKey(third, sizeof(third), parsed) !=
                EapolResult::InvalidKeyInformation ||
            parsed.eapolBytes || parsed.nonce)
            return false;
        third[8] = 16;
        if (parseEapolKey(third, sizeof(third), parsed) != EapolResult::Ok ||
            parsed.message != KeyMessage::Pairwise3)
            return false;

        uint8_t fourth[99] {};
        makeM1(fourth);
        fourth[5] = 0x03; // MIC+secure, no ACK or key install.
        fourth[6] = 0x0a;
        fourth[8] = 0;
        fourth[17] = 0;
        fourth[81] = 0x55;
        if (parseEapolKey(fourth, sizeof(fourth), parsed) != EapolResult::Ok ||
            parsed.message != KeyMessage::Pairwise4)
            return false;
        fourth[8] = 16;
        return parseEapolKey(fourth, sizeof(fourth), parsed) ==
                   EapolResult::InvalidKeyInformation &&
               !parsed.eapolBytes && !parsed.nonce;
    }

    bool rejectForgedReplayMetadata()
    {
        // ReplayGuard is a public boundary: a caller-built KeyFrame cannot
        // bypass the parser's M1/M3 Key Information and CCMP constraints.
        uint8_t m1[99] {};
        makeM1(m1);
        KeyFrame first {};
        if (parseEapolKey(m1, sizeof(m1), first) != EapolResult::Ok)
            return false;
        ReplayGuard guard;
        uint8_t emptyNonce[32] {};
        KeyFrame forged = first;
        forged.nonce = emptyNonce;
        if (guard.acceptMessage1(forged) !=
                EapolResult::InvalidKeyInformation ||
            guard.phase() != HandshakePhase::Empty ||
            guard.lastReplayCounter() != 0)
            return false;
        forged = first;
        forged.hasMic = true;
        if (guard.acceptMessage1(forged) !=
                EapolResult::InvalidKeyInformation ||
            guard.phase() != HandshakePhase::Empty)
            return false;
        forged = first;
        forged.keyInformation ^= 0x20u; // Unsupported legacy Key Index.
        if (guard.acceptMessage1(forged) !=
                EapolResult::InvalidKeyInformation ||
            guard.phase() != HandshakePhase::Empty)
            return false;
        forged = first;
        forged.keyLength = 0;
        if (guard.acceptMessage1(forged) !=
                EapolResult::InvalidKeyInformation ||
            guard.phase() != HandshakePhase::Empty)
            return false;
        if (guard.acceptMessage1(first) != EapolResult::Ok)
            return false;

        uint8_t m3[155] {};
        makeM3(m3);
        KeyFrame third {};
        if (parseEapolKey(m3, sizeof(m3), third) != EapolResult::Ok)
            return false;
        forged = third;
        forged.hasMic = false;
        if (guard.acceptVerifiedMessage3(forged, true) !=
                EapolResult::InvalidKeyInformation ||
            guard.phase() != HandshakePhase::AwaitingMessage3 ||
            guard.lastReplayCounter() != first.replayCounter)
            return false;
        forged = third;
        forged.keyInformation = first.keyInformation; // M1 mask, M3 flags.
        if (guard.acceptVerifiedMessage3(forged, true) !=
                EapolResult::InvalidKeyInformation ||
            guard.phase() != HandshakePhase::AwaitingMessage3)
            return false;
        forged = third;
        forged.keyLength = 0;
        if (guard.acceptVerifiedMessage3(forged, true) !=
                EapolResult::InvalidKeyInformation ||
            guard.phase() != HandshakePhase::AwaitingMessage3)
            return false;
        return guard.acceptVerifiedMessage3(third, true) == EapolResult::Ok &&
               guard.phase() == HandshakePhase::Message3MicVerified &&
               guard.lastReplayCounter() == third.replayCounter;
    }

    bool rejectForgedReplayWireMetadata()
    {
        // ReplayGuard is public: a caller may copy parser metadata then
        // substitute a different nonce or scalar replay counter. Never
        // advance on values detached from the actual EAPOL-Key image.
        uint8_t firstBytes[99] {};
        makeM1(firstBytes);
        KeyFrame first {};
        if (parseEapolKey(firstBytes, sizeof(firstBytes), first) !=
            EapolResult::Ok)
            return false;
        ReplayGuard guard;
        // The direct replay API cannot trust metadata copied from an earlier
        // parse when the borrowed M1 bytes have since changed. A MIC bit of
        // zero demands all-zero MIC bytes, independent of the caller's bool.
        firstBytes[81] = 0x5a;
        if (guard.acceptMessage1(first) != EapolResult::InvalidKeyInformation ||
            guard.phase() != HandshakePhase::Empty)
            return false;
        firstBytes[81] = 0;
        // A caller can also adjust the declared EAPOL length without fixing
        // the fixed key body/key-data length. A parser would reject this.
        uint8_t extraFirst[100] {};
        std::memcpy(extraFirst, firstBytes, sizeof(firstBytes));
        extraFirst[3] = 96; // Declared body exceeds fixed+keyDataLength.
        extraFirst[99] = 0xa5;
        KeyFrame extra = first;
        extra.eapolBytes = extraFirst;
        extra.eapolLength = sizeof(extraFirst);
        extra.nonce = extraFirst + 17;
        extra.mic = extraFirst + 81;
        extra.keyRsc = extraFirst + 65;
        extra.keyData = extraFirst + 99;
        if (guard.acceptMessage1(extra) != EapolResult::InvalidKeyInformation ||
            guard.phase() != HandshakePhase::Empty)
            return false;
        KeyFrame forged = first;
        uint8_t detachedNonce[32] {};
        std::memcpy(detachedNonce, first.nonce, sizeof(detachedNonce));
        forged.nonce = detachedNonce;
        if (guard.acceptMessage1(forged) !=
                EapolResult::InvalidKeyInformation ||
            guard.phase() != HandshakePhase::Empty)
            return false;
        forged = first;
        ++forged.replayCounter;
        if (guard.acceptMessage1(forged) !=
                EapolResult::InvalidKeyInformation ||
            guard.lastReplayCounter() != 0)
            return false;
        forged = first;
        forged.eapolBytes = nullptr;
        if (guard.acceptMessage1(forged) != EapolResult::InvalidKeyInformation)
            return false;
        forged = first;
        --forged.eapolLength;
        if (guard.acceptMessage1(forged) != EapolResult::InvalidKeyInformation)
            return false;
        if (guard.acceptMessage1(first) != EapolResult::Ok)
            return false;

        uint8_t thirdBytes[155] {};
        makeM3(thirdBytes);
        KeyFrame third {};
        if (parseEapolKey(thirdBytes, sizeof(thirdBytes), third) !=
            EapolResult::Ok)
            return false;
        uint8_t extraThird[156] {};
        std::memcpy(extraThird, thirdBytes, sizeof(thirdBytes));
        extraThird[3] = 152; // 95 fixed + 56 key data != 152.
        extraThird[155] = 0x5a;
        extra = third;
        extra.eapolBytes = extraThird;
        extra.eapolLength = sizeof(extraThird);
        extra.nonce = extraThird + 17;
        extra.mic = extraThird + 81;
        extra.keyRsc = extraThird + 65;
        extra.keyData = extraThird + 99;
        if (guard.acceptVerifiedMessage3(extra, true) !=
                EapolResult::InvalidKeyInformation ||
            guard.phase() != HandshakePhase::AwaitingMessage3 ||
            guard.lastReplayCounter() != first.replayCounter)
            return false;
        forged = third;
        std::memcpy(detachedNonce, third.nonce, sizeof(detachedNonce));
        forged.nonce = detachedNonce;
        if (guard.acceptVerifiedMessage3(forged, true) !=
                EapolResult::InvalidKeyInformation ||
            guard.phase() != HandshakePhase::AwaitingMessage3)
            return false;
        forged = third;
        ++forged.replayCounter;
        if (guard.acceptVerifiedMessage3(forged, true) !=
                EapolResult::InvalidKeyInformation ||
            guard.lastReplayCounter() != first.replayCounter)
            return false;
        forged = third;
        forged.eapolBytes = nullptr;
        if (guard.acceptVerifiedMessage3(forged, true) !=
            EapolResult::InvalidKeyInformation)
            return false;
        forged = third;
        --forged.eapolLength;
        if (guard.acceptVerifiedMessage3(forged, true) !=
            EapolResult::InvalidKeyInformation)
            return false;
        return guard.acceptVerifiedMessage3(third, true) == EapolResult::Ok &&
               guard.phase() == HandshakePhase::Message3MicVerified &&
               guard.lastReplayCounter() == third.replayCounter;
    }

    struct alignas(size_t) RxWord
    {
            size_t word;
            uint8_t rest[256];
    };
} // namespace

int main()
{
    if (!rejectZeroMicCallback(1) || !rejectZeroMicCallback(3))
        return 48;
    if (!rejectTrailingHandshakeBytes())
        return 46;
    if (!rejectMalformedMessage2())
        return 40;
    if (!rejectWrongPairwiseKeyLengths())
        return 41;
    if (!rejectForgedReplayMetadata())
        return 39;
    if (!rejectForgedReplayWireMetadata())
        return 42;
    if (!rejectEapolParserInputAlias())
        return 25;
    FakeCrypto fake {};
    Wpa2Supplicant supplicant;
    uint8_t pmk[32] {};
    pmk[0] = 1;
    auto callbacks = fakeCallbacks(fake);
    // Do not establish a PSK handshake with an AP identity equal to our
    // station, even if both individual MACs are otherwise valid unicast.
    if (supplicant.begin(fakeCallbacks(fake), kStation, kStation, pmk, kRsnIe,
                         sizeof(kRsnIe)) != Wpa2Result::InvalidArgument ||
        supplicant.state() != Wpa2State::Inactive || fake.calls)
        return 38;
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
    for (unsigned stage = 0; stage <= 7; ++stage)
        if (!rejectRevokedCallback(stage))
            return 30 + static_cast<int>(stage);
    return 0;
}
