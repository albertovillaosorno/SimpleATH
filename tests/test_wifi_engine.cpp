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
//   - Offline regression cases for wifi engine.
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
//   - Offline regression cases for wifi engine.
// - Description:
//   - Implements or verifies the test_wifi_engine source boundary.
// - Usage:
//   - Executed by offline host test discovery or the native test harness.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Offline regression cases for wifi engine.

// Synthetic WPA2 M1-M4 and protected Group1/Group2 integration.
// Wrapped GTK bytes were generated independently with OpenSSL AES-128-ECB
// RFC3394 key-wrap for the deterministic PMK/nonces below. No kernel/RF I/O.
#include "wifi/DataFrames.hpp"
#include "wifi/DataPath.hpp"
#include "wifi/Eapol.hpp"
#include "wifi/Frames.hpp"
#include "wifi/Station.hpp"
#include "wifi/WifiEngine.hpp"
#include "wifi/crypto/Ccmp.hpp"
#include "wifi/crypto/Wpa2CryptoAdapter.hpp"
#include "wifi/crypto/Wpa2Primitives.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace
{
    using namespace simpleath::ieee80211;
    // This fixture builds literal IEEE 802.11/EAPOL wire octets and fixed
    // OpenSSL reference vectors, not production parameter policy. All such
    // numeric offsets and key sizes are deliberately exact on-air values.
    // NOLINTBEGIN(*avoid-magic-numbers,readability-magic-numbers)
    constexpr uint64_t kEpoch = 410U;
    constexpr int kFailureModulo = 250;
    constexpr std::array<uint8_t, 6> kAp {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
    constexpr std::array<uint8_t, 6> kStation {
        {0x02, 0x66, 0x77, 0x88, 0x99, 0xaa},
    };
    constexpr std::array<uint8_t, 22> kRsn {
        {
            48,   20,   1, 0, 0, 0x0f, 0xac, 4,    1, 0, 0,
            0x0f, 0xac, 4, 1, 0, 0,    0x0f, 0xac, 2, 0, 0,
        },
    };
    constexpr std::array<uint8_t, 56> kM3Wrapped {
        {
            0x4c, 0x51, 0xd0, 0x67, 0x12, 0xef, 0x6f, 0xe5, 0x3c, 0x2c,
            0xc0, 0xed, 0x05, 0xa8, 0xb8, 0x58, 0x38, 0xfc, 0x67, 0xb5,
            0x0b, 0xed, 0xcb, 0x87, 0xf2, 0x7b, 0x0e, 0x1a, 0x02, 0xa8,
            0xe6, 0x8a, 0x07, 0xa7, 0xfd, 0xb2, 0x38, 0xd1, 0xf9, 0xae,
            0x8d, 0x3b, 0x2f, 0x99, 0x9e, 0x4b, 0x50, 0xff, 0x6a, 0xea,
            0xa7, 0x06, 0xf7, 0x25, 0x9d, 0xc0,
        },
    };
    constexpr std::array<uint8_t, 40> kGroupWrapped {
        {
            0x78, 0xef, 0x43, 0xb6, 0xcb, 0xff, 0x40, 0xef, 0x4b, 0x64,
            0xcd, 0xbe, 0xda, 0xfe, 0x50, 0x86, 0x87, 0x05, 0x5a, 0x68,
            0x96, 0x84, 0x9f, 0x3c, 0x4c, 0xae, 0x5e, 0x44, 0x44, 0x3f,
            0xe8, 0x9d, 0xd9, 0x11, 0x08, 0xc8, 0xf8, 0xa2, 0x8a, 0x12,
        },
    };
    constexpr std::array<uint8_t, 16> kPairwiseTk {
        {
            0x61,
            0x57,
            0x1e,
            0x08,
            0xcc,
            0xd4,
            0x9e,
            0xc4,
            0x2d,
            0x62,
            0x7d,
            0x4b,
            0x98,
            0xac,
            0x9d,
            0xcc,
        },
    };
    constexpr std::array<uint8_t, 4> kSsid {{'T', 'e', 's', 't'}};
    constexpr InputTrust kTrust {true, true, true, true};

    struct Provider
    {
            unsigned pairwise = 0;
            unsigned groups = 0;
            unsigned revocations = 0;
            uint8_t gtkIndex = 0;

            static bool random(void * /*context*/, uint8_t *buffer,
                               size_t length)
            {
                if (length != 32)
                {
                    return false;
                }
                std::array<uint8_t, 32> nonce {};
                for (size_t index = 0; index < nonce.size(); ++index)
                {
                    nonce.at(index) = static_cast<uint8_t>(index + 1U);
                }
                std::memcpy(buffer, nonce.data(), nonce.size());
                return true;
            }

            static bool installPairwise(void *context, const Mac &ap,
                                        const uint8_t tk[16])
            {
                auto &provider = *static_cast<Provider *>(context);
                ++provider.pairwise;
                return std::memcmp(&ap.bytes[0], kAp.data(), kAp.size()) == 0 &&
                       std::memcmp(tk, kPairwiseTk.data(),
                                   kPairwiseTk.size()) == 0;
            }

            static bool installGroup(void *context, uint8_t id,
                                     const uint8_t *gtk, const uint8_t *rsc)
            {
                auto &provider = *static_cast<Provider *>(context);
                ++provider.groups;
                provider.gtkIndex = id;
                return gtk != nullptr && rsc != nullptr;
            }

            static void remove(void *context)
            {
                ++static_cast<Provider *>(context)->revocations;
            }
    };

    template <size_t N> void fromAp(std::array<uint8_t, N> &frame)
    {
        frame.fill(0U);
        frame.at(0) = 0x08; // Data, FromDS.
        frame.at(1) = 0x02;
        std::memcpy(&frame.at(4), kStation.data(), kStation.size());
        std::memcpy(&frame.at(10), kAp.data(), kAp.size());
        std::memcpy(&frame.at(16), kAp.data(), kAp.size());
        const std::array<uint8_t, 8> snap {
            {0xaa, 0xaa, 0x03, 0, 0, 0, 0x88, 0x8e},
        };
        std::memcpy(&frame.at(24), snap.data(), snap.size());
    }

    std::array<uint8_t, 71> wpa2Beacon()
    {
        std::array<uint8_t, 71> frame {};
        frame.at(0) = 0x80;
        std::memset(&frame.at(4), 0xff, 6);
        std::memcpy(&frame.at(10), kAp.data(), kAp.size());
        std::memcpy(&frame.at(16), kAp.data(), kAp.size());
        frame.at(32) = 100;
        frame.at(34) = 0x11;
        frame.at(36) = 0;
        frame.at(37) = 4;
        std::memcpy(&frame.at(38), kSsid.data(), kSsid.size());
        frame.at(42) = 1;
        frame.at(43) = 2;
        frame.at(44) = 0x82;
        frame.at(45) = 0x84;
        frame.at(46) = 3;
        frame.at(47) = 1;
        frame.at(48) = 6;
        std::memcpy(&frame.at(49), kRsn.data(), kRsn.size());
        return frame;
    }

    std::array<uint8_t, 30> authenticationResponse()
    {
        std::array<uint8_t, 30> frame {};
        frame.at(0) = 0xb0;
        std::memcpy(&frame.at(4), kStation.data(), kStation.size());
        std::memcpy(&frame.at(10), kAp.data(), kAp.size());
        std::memcpy(&frame.at(16), kAp.data(), kAp.size());
        frame.at(26) = 2;
        return frame;
    }

    std::array<uint8_t, 34> associationResponse()
    {
        std::array<uint8_t, 34> frame {};
        frame.at(0) = 0x10;
        std::memcpy(&frame.at(4), kStation.data(), kStation.size());
        std::memcpy(&frame.at(10), kAp.data(), kAp.size());
        std::memcpy(&frame.at(16), kAp.data(), kAp.size());
        frame.at(24) = 0x11;
        frame.at(28) = 1;
        frame.at(29) = 0xc0;
        frame.at(30) = 1;
        frame.at(31) = 2;
        frame.at(32) = 0x82;
        frame.at(33) = 0x84;
        return frame;
    }

    std::array<uint8_t, 99> makeM1()
    {
        std::array<uint8_t, 99> eapol {};
        eapol.at(0) = 2;
        eapol.at(1) = 3;
        eapol.at(3) = 95;
        eapol.at(4) = 2;
        eapol.at(6) = 0x8a;
        eapol.at(8) = 16;
        eapol.at(16) = 1;
        eapol.at(17) = 7;
        return eapol;
    }

    struct KeyReplyType
    {
            uint8_t keyFlags;
            uint8_t replay;
    };

    template <size_t DataBytes>
    std::array<uint8_t, 99 + DataBytes>
    makeSignedKey(KeyReplyType replyType,
                  const std::array<uint8_t, DataBytes> &wrapped,
                  const uint8_t *kck)
    {
        std::array<uint8_t, 99 + DataBytes> eapol {};
        eapol.at(0) = 2;
        eapol.at(1) = 3;
        eapol.at(3) = static_cast<uint8_t>(95 + DataBytes);
        eapol.at(4) = 2;
        eapol.at(5) = 0x13;
        eapol.at(6) = replyType.keyFlags;
        eapol.at(8) = 16;
        eapol.at(16) = replyType.replay;
        if (replyType.keyFlags == 0xca)
        {
            eapol.at(17) = 7; // Same ANonce as M1.
        }
        else
        {
            eapol.at(65) = 0x77; // New GTK RSC.
        }
        eapol.at(98) = static_cast<uint8_t>(DataBytes);
        std::memcpy(&eapol.at(99), wrapped.data(), wrapped.size());
        std::array<uint8_t, 16> mic {};
        if (crypto::calculateMic(kck, eapol.data(), eapol.size(), mic.data()) !=
            crypto::Error::Ok)
        {
            return {};
        }
        std::memcpy(&eapol.at(81), mic.data(), mic.size());
        return eapol;
    }

    template <size_t Payload>
    std::array<uint8_t, 32 + Payload>
    cleartextApFrame(const std::array<uint8_t, Payload> &eapol)
    {
        std::array<uint8_t, 32 + Payload> frame {};
        fromAp(frame);
        std::memcpy(&frame.at(32), eapol.data(), eapol.size());
        return frame;
    }

    bool joinAndInstall(WifiEngine &engine, Provider &provider,
                        const uint8_t *kck)
    {
        const crypto::KeyHardware hardware {
            &provider,
            Provider::random,
            Provider::installPairwise,
            Provider::installGroup,
            Provider::remove,
        };
        const auto beacon = wpa2Beacon();
        const auto auth = authenticationResponse();
        const auto assoc = associationResponse();
        const auto m1 = cleartextApFrame(makeM1());
        const auto m3 =
            cleartextApFrame(makeSignedKey({0xca, 2}, kM3Wrapped, kck));
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        const Mac ap {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        const std::array<uint8_t, 32> pmk {{1}};
        std::array<uint8_t, 512> tx {};
        EngineAction action {};
        if (!engine.configureKeys(hardware) ||
            engine.startScan(true, true) != EngineResult::Ok ||
            engine.acceptRx(beacon.data(), beacon.size(), kTrust, {-40, 1000},
                            tx.data(), tx.size(), action) != EngineResult::Ok ||
            engine.chooseNetworkForDriverSupplicant(
                station, ap, kSsid.data(), kSsid.size(), 6, pmk.data()) !=
                EngineResult::Ok ||
            engine.requestAuthentication(1, tx.data(), tx.size(), action) !=
                EngineResult::Ok ||
            engine.acceptRx(auth.data(), auth.size(), kTrust, {-40, 1001},
                            tx.data(), tx.size(), action) != EngineResult::Ok ||
            engine.acceptRx(assoc.data(), assoc.size(), kTrust, {-40, 1002},
                            tx.data(), tx.size(), action) != EngineResult::Ok ||
            engine.stationState() != StationState::WaitingForWpa2Keys ||
            engine.acceptRx(m1.data(), m1.size(), kTrust, {-40, 1003},
                            tx.data(), tx.size(), action) != EngineResult::Ok ||
            engine.acceptRx(m3.data(), m3.size(), kTrust, {-40, 1004},
                            tx.data(), tx.size(), action) != EngineResult::Ok ||
            action.kind != ActionKind::TransmitEapol ||
            engine.stationState() != StationState::HardwareKeysInstalled)
        {
            return false;
        }
        return provider.pairwise == 1 && provider.groups == 1 &&
               provider.revocations == 0;
    }

    // One coherent fixture checks the M1-M4 epoch and its replay/rollback.
    // NOLINTNEXTLINE(readability-function-cognitive-complexity)
    int protectedGroupExchange()
    {
        // Deterministic PMK/ANonce/SNonce fixture. The independently wrapped
        // payloads above decrypt only under its derived KEK.
        const std::array<uint8_t, 32> pmk {{1}};
        std::array<uint8_t, 32> anonce {{7}};
        std::array<uint8_t, 32> snonce {};
        for (size_t index = 0; index < snonce.size(); ++index)
        {
            snonce.at(index) = static_cast<uint8_t>(index + 1U);
        }
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        const Mac ap {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        std::array<uint8_t, 48> ptk {};
        if (crypto::derivePtk(pmk.data(), ap, station, anonce.data(),
                              snonce.data(), ptk.data()) != crypto::Error::Ok ||
            std::memcmp(&ptk.at(32), kPairwiseTk.data(), 16) != 0)
        {
            return (__LINE__ % kFailureModulo) + 1;
        }
        Provider provider {};
        WifiEngine engine;
        if (!joinAndInstall(engine, provider, ptk.data()))
        {
            return (__LINE__ % kFailureModulo) + 1;
        }
        crypto::CcmpSession apTx {};
        crypto::CcmpSession stationRx {};
        crypto::CcmpSession stationTx {};
        crypto::CcmpSession apRx {};
        if (apTx.install(kPairwiseTk.data(), kAp.data(), 0, kEpoch, 0, 0) !=
                crypto::CcmpResult::Ok ||
            stationRx.install(kPairwiseTk.data(), kAp.data(), 0, kEpoch, 0,
                              0) != crypto::CcmpResult::Ok ||
            stationTx.install(kPairwiseTk.data(), kStation.data(), 0, kEpoch, 0,
                              0) != crypto::CcmpResult::Ok ||
            apRx.install(kPairwiseTk.data(), kStation.data(), 0, kEpoch, 0,
                         0) != crypto::CcmpResult::Ok)
        {
            return (__LINE__ % kFailureModulo) + 1;
        }
        auto group1 = cleartextApFrame(
            makeSignedKey({0x82, 3}, kGroupWrapped, ptk.data()));
        std::array<uint8_t, 512> encrypted {};
        size_t encryptedBytes = 0;
        if (apTx.protect(kEpoch, group1.data(), group1.size(), encrypted.data(),
                         encrypted.size(),
                         encryptedBytes) != crypto::CcmpResult::Ok)
        {
            return (__LINE__ % kFailureModulo) + 1;
        }
        std::array<uint8_t, 512> rxScratch {};
        std::array<uint8_t, 512> txScratch {};
        std::array<uint8_t, 512> output {};
        EngineAction action {
            ActionKind::ReceivedPayload, 77, 0x888e, nullptr, 0, false,
        };
        // Short output or aliased workspaces must fail without consuming PN,
        // installing GTK or modifying caller-owned output/action storage.
        if (engine.acceptProtectedGroupRekey(
                encrypted.data(), encryptedBytes, false, kTrust, stationRx,
                stationTx, kEpoch, rxScratch.data(), rxScratch.size(),
                txScratch.data(), txScratch.size(), output.data(), 146,
                action) != EngineResult::BufferTooSmall ||
            action.kind != ActionKind::None || stationRx.receiveFloor() != 0 ||
            provider.groups != 1)
        {
            return (__LINE__ % kFailureModulo) + 1;
        }
        action.kind = ActionKind::ReceivedPayload;
        if (engine.acceptProtectedGroupRekey(
                encrypted.data(), encryptedBytes, false, kTrust, stationRx,
                stationTx, kEpoch, rxScratch.data(), rxScratch.size(),
                txScratch.data(), txScratch.size(), rxScratch.data(),
                rxScratch.size(), action) != EngineResult::InvalidInput ||
            action.kind != ActionKind::ReceivedPayload ||
            stationRx.receiveFloor() != 0 || provider.groups != 1)
        {
            return (__LINE__ % kFailureModulo) + 1;
        }
        if (engine.acceptProtectedGroupRekey(
                encrypted.data(), encryptedBytes, false, kTrust, stationRx,
                stationTx, kEpoch, rxScratch.data(), rxScratch.size(),
                txScratch.data(), txScratch.size(), output.data(),
                output.size(), action) != EngineResult::Ok ||
            action.kind != ActionKind::TransmitEapol || action.bytes == 0 ||
            provider.groups != 2 || provider.gtkIndex != 1 ||
            stationRx.receiveFloor() != 1 || stationTx.lastTransmittedPn() != 1)
        {
            return (__LINE__ % kFailureModulo) + 1;
        }
        std::array<uint8_t, 512> decoded {};
        size_t decodedBytes = 0;
        if (apRx.unprotect(kEpoch, output.data(), action.bytes, decoded.data(),
                           decoded.size(),
                           decodedBytes) != crypto::CcmpResult::Ok ||
            decodedBytes != 32 + 99 ||
            std::memcmp(&decoded.at(4), kAp.data(), kAp.size()) != 0)
        {
            return (__LINE__ % kFailureModulo) + 1;
        }
        KeyFrame group2 {};
        if (parseEapolKey(&decoded.at(32), 99, group2) != EapolResult::Ok ||
            group2.message != KeyMessage::Group2 || group2.replayCounter != 3)
        {
            return (__LINE__ % kFailureModulo) + 1;
        }
        for (const uint8_t byte : rxScratch)
        {
            if (byte != 0)
            {
                return (__LINE__ % kFailureModulo) + 1;
            }
        }
        for (const uint8_t byte : txScratch)
        {
            if (byte != 0)
            {
                return (__LINE__ % kFailureModulo) + 1;
            }
        }
        if (engine.acceptProtectedGroupRekey(
                encrypted.data(), encryptedBytes, false, kTrust, stationRx,
                stationTx, kEpoch, rxScratch.data(), rxScratch.size(),
                txScratch.data(), txScratch.size(), output.data(),
                output.size(), action) != EngineResult::InvalidReceivedFrame ||
            provider.groups != 2 || stationTx.lastTransmittedPn() != 1)
        {
            return (__LINE__ % kFailureModulo) + 1;
        }
        // A new authenticated CCMP packet with a wrong EAPOL MIC must not
        // revoke the accepted GTK or emit a Group2 reply.
        group1.at(32 + 81) ^= 1U;
        if (apTx.protect(kEpoch, group1.data(), group1.size(), encrypted.data(),
                         encrypted.size(),
                         encryptedBytes) != crypto::CcmpResult::Ok ||
            engine.acceptProtectedGroupRekey(
                encrypted.data(), encryptedBytes, false, kTrust, stationRx,
                stationTx, kEpoch, rxScratch.data(), rxScratch.size(),
                txScratch.data(), txScratch.size(), output.data(),
                output.size(), action) != EngineResult::CryptoFailure ||
            provider.groups != 2 || provider.revocations != 0 ||
            stationTx.lastTransmittedPn() != 1)
        {
            return (__LINE__ % kFailureModulo) + 1;
        }
        // Authentication and GTK installation can succeed even if a
        // supplied TX key session is absent. Then revoke all keys and the
        // association, rather than leave an unacknowledged GTK active.
        group1 = cleartextApFrame(
            makeSignedKey({0x82, 4}, kGroupWrapped, ptk.data()));
        if (apTx.protect(kEpoch, group1.data(), group1.size(), encrypted.data(),
                         encrypted.size(),
                         encryptedBytes) != crypto::CcmpResult::Ok)
        {
            return (__LINE__ % kFailureModulo) + 1;
        }
        crypto::CcmpSession missingTx {};
        // Native RX authenticates Group1 once, then completes its GTK/Group2
        // response from the borrowed verified MSDU. Do not decrypt again:
        // the receive session's PN floor must advance only once.
        const LinkContext link {
            station, ap, LinkSecurity::Wpa2Ccmp, true, true, true, true};
        Msdu verified {};
        if (inspectProtectedStationRx(link, encrypted.data(), encryptedBytes,
                                      false, true, stationRx, kEpoch,
                                      rxScratch.data(), rxScratch.size(),
                                      verified) != DataPathResult::Ok ||
            stationRx.receiveFloor() != 3 || verified.etherType != 0x888e ||
            !verified.protectedFrame)
        {
            return (__LINE__ % kFailureModulo) + 1;
        }
        InputTrust missingMicProof = kTrust;
        missingMicProof.ccmpMicAndReplayVerified = false;
        if (engine.finishAuthenticatedGroupRekey(
                verified, missingMicProof, stationRx, missingTx, kEpoch, 312,
                txScratch.data(), txScratch.size(), output.data(),
                output.size(), action) != EngineResult::RadioNotReady ||
            provider.groups != 2 || stationRx.receiveFloor() != 3)
        {
            return (__LINE__ % kFailureModulo) + 1;
        }
        action.kind = ActionKind::ReceivedPayload;
        if (engine.finishAuthenticatedGroupRekey(
                verified, kTrust, stationRx, missingTx, kEpoch, 312,
                txScratch.data(), txScratch.size(), rxScratch.data(),
                rxScratch.size(), action) != EngineResult::InvalidInput ||
            action.kind != ActionKind::ReceivedPayload || provider.groups != 2)
        {
            return (__LINE__ % kFailureModulo) + 1;
        }
        if (engine.finishAuthenticatedGroupRekey(
                verified, kTrust, stationRx, missingTx, kEpoch, 312,
                txScratch.data(), txScratch.size(), output.data(),
                output.size(), action) != EngineResult::CryptoFailure ||
            provider.groups != 3 || provider.revocations != 1 ||
            engine.stationState() != StationState::Inactive ||
            stationRx.installed() || missingTx.installed() ||
            action.kind != ActionKind::None)
        {
            return (__LINE__ % kFailureModulo) + 1;
        }
        rxScratch.fill(0U);
        return 0;
    }

    // The native single-decrypt route succeeds with one verified CCMP RX,
    // an explicit transmitter sequence and the matching GTK/Group2 reply.
    // NOLINTNEXTLINE(readability-function-cognitive-complexity)
    int verifiedNativeGroupExchange()
    {
        const std::array<uint8_t, 32> pmk {{1}};
        std::array<uint8_t, 32> anonce {{7}};
        std::array<uint8_t, 32> snonce {};
        for (size_t index = 0; index < snonce.size(); ++index)
        {
            snonce.at(index) = static_cast<uint8_t>(index + 1U);
        }
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        const Mac ap {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        std::array<uint8_t, 48> ptk {};
        if (crypto::derivePtk(pmk.data(), ap, station, anonce.data(),
                              snonce.data(), ptk.data()) != crypto::Error::Ok)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        Provider provider {};
        WifiEngine engine;
        if (!joinAndInstall(engine, provider, ptk.data()))
        {
            return __LINE__ % kFailureModulo + 1;
        }
        crypto::CcmpSession apTx {};
        crypto::CcmpSession stationRx {};
        crypto::CcmpSession stationTx {};
        crypto::CcmpSession apRx {};
        if (apTx.install(kPairwiseTk.data(), kAp.data(), 0, kEpoch, 0, 0) !=
                crypto::CcmpResult::Ok ||
            stationRx.install(kPairwiseTk.data(), kAp.data(), 0, kEpoch, 0,
                              0) != crypto::CcmpResult::Ok ||
            stationTx.install(kPairwiseTk.data(), kStation.data(), 0, kEpoch, 0,
                              0) != crypto::CcmpResult::Ok ||
            apRx.install(kPairwiseTk.data(), kStation.data(), 0, kEpoch, 0,
                         0) != crypto::CcmpResult::Ok)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        const auto group1 = cleartextApFrame(
            makeSignedKey({0x82, 3}, kGroupWrapped, ptk.data()));
        std::array<uint8_t, 512> encrypted {};
        size_t encryptedBytes = 0;
        if (apTx.protect(kEpoch, group1.data(), group1.size(), encrypted.data(),
                         encrypted.size(),
                         encryptedBytes) != crypto::CcmpResult::Ok)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        std::array<uint8_t, 512> rxScratch {};
        const LinkContext link {
            station, ap, LinkSecurity::Wpa2Ccmp, true, true, true, true};
        Msdu verified {};
        if (inspectProtectedStationRx(link, encrypted.data(), encryptedBytes,
                                      false, true, stationRx, kEpoch,
                                      rxScratch.data(), rxScratch.size(),
                                      verified) != DataPathResult::Ok ||
            stationRx.receiveFloor() != 1)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        std::array<uint8_t, 512> txScratch {};
        std::array<uint8_t, 512> output {};
        EngineAction action {};
        if (engine.finishAuthenticatedGroupRekey(
                verified, kTrust, stationRx, stationTx, kEpoch, 4096,
                txScratch.data(), txScratch.size(), output.data(),
                output.size(), action) != EngineResult::InvalidInput ||
            provider.groups != 1 || stationTx.lastTransmittedPn() != 0)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        constexpr uint16_t kNativeSequence = 312;
        if (engine.finishAuthenticatedGroupRekey(
                verified, kTrust, stationRx, stationTx, kEpoch, kNativeSequence,
                txScratch.data(), txScratch.size(), output.data(),
                output.size(), action) != EngineResult::Ok ||
            action.kind != ActionKind::TransmitEapol || action.bytes == 0 ||
            provider.groups != 2 || stationRx.receiveFloor() != 1 ||
            stationTx.lastTransmittedPn() != 1)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        std::array<uint8_t, 512> decoded {};
        size_t decodedBytes = 0;
        if (apRx.unprotect(kEpoch, output.data(), action.bytes, decoded.data(),
                           decoded.size(),
                           decodedBytes) != crypto::CcmpResult::Ok ||
            decodedBytes != 32 + 99 ||
            (static_cast<unsigned>(decoded.at(23)) * 16U +
             static_cast<unsigned>(decoded.at(22)) / 16U) != kNativeSequence)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        KeyFrame group2 {};
        if (parseEapolKey(&decoded.at(32), 99, group2) != EapolResult::Ok ||
            group2.message != KeyMessage::Group2 || group2.replayCounter != 3)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        // Exact same Group1 MIC/replay cannot drive another GTK installation
        // or consume another pairwise TX PN without a new authenticated AP
        // Group1. The copied MSDU remains borrowed from rxScratch.
        if (engine.finishAuthenticatedGroupRekey(
                verified, kTrust, stationRx, stationTx, kEpoch, 313,
                txScratch.data(), txScratch.size(), output.data(),
                output.size(), action) != EngineResult::CryptoFailure ||
            provider.groups != 2 || stationTx.lastTransmittedPn() != 1)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        rxScratch.fill(0U);
        return 0;
    }

    // NOLINTEND(*avoid-magic-numbers,readability-magic-numbers)
} // namespace

int main()
{
    const int baseline = protectedGroupExchange();
    return baseline == 0 ? verifiedNativeGroupExchange() : baseline;
}
