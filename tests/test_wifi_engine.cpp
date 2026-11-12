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

    bool rejectAssociatedBeaconPolicyDrift()
    {
        // A fully associated WPA2 BSSID cannot refresh its beacon deadline
        // using changed RF/security policy. The same-BSSID hidden-name case
        // remains valid because the underlying selected SSID is retained.
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
            return false;
        }
        Provider provider {};
        WifiEngine engine;
        if (!joinAndInstall(engine, provider, ptk.data()) ||
            engine.linkStatus().state != LinkState::Associated ||
            engine.linkStatus().acceptedBeacons != 0U)
        {
            return false;
        }
        const uint64_t initialBeaconMs = engine.linkStatus().lastBeaconMs;
        std::array<uint8_t, 512> tx {};
        EngineAction action {};
        auto reject =
            [&](const std::array<uint8_t, 71> &advertisement, uint64_t nowMs)
        {
            action.kind = ActionKind::TransmitData;
            return engine.acceptRx(advertisement.data(), advertisement.size(),
                                   kTrust, {-40, nowMs}, tx.data(), tx.size(),
                                   action) ==
                       EngineResult::InvalidReceivedFrame &&
                   action.kind == ActionKind::None &&
                   engine.linkStatus().state == LinkState::Associated &&
                   engine.linkStatus().lastBeaconMs == initialBeaconMs &&
                   engine.linkStatus().acceptedBeacons == 0U;
        };
        auto advertisement = wpa2Beacon();
        advertisement.at(48) = 11U; // Same BSSID, different primary channel.
        if (!reject(advertisement, 1050U))
        {
            return false;
        }
        advertisement = wpa2Beacon();
        advertisement.at(34) &= static_cast<uint8_t>(~0x10U); // Open downgrade.
        if (!reject(advertisement, 1051U))
        {
            return false;
        }
        advertisement = wpa2Beacon();
        advertisement.at(69) = 0x80U; // WPA2 + newly advertised PMF ability.
        if (!reject(advertisement, 1052U))
        {
            return false;
        }
        advertisement = wpa2Beacon();
        advertisement.at(38) = 'X'; // Same BSSID, different visible SSID.
        if (!reject(advertisement, 1053U))
        {
            return false;
        }
        advertisement = wpa2Beacon();
        advertisement.at(44) = 0x8cU; // Unnegotiated mandatory 6-Mbps rate.
        if (!reject(advertisement, 1054U))
        {
            return false;
        }
        advertisement = wpa2Beacon();
        if (engine.acceptRx(advertisement.data(), advertisement.size(), kTrust,
                            {-40, 1055U}, tx.data(), tx.size(),
                            action) != EngineResult::NoAction ||
            engine.linkStatus().acceptedBeacons != 1U ||
            engine.linkStatus().lastBeaconMs != 1055U)
        {
            return false;
        }
        advertisement.at(45) = 0x0cU; // Newly optional 6-Mbps rate is safe.
        if (engine.acceptRx(advertisement.data(), advertisement.size(), kTrust,
                            {-40, 1056U}, tx.data(), tx.size(),
                            action) != EngineResult::NoAction ||
            engine.linkStatus().acceptedBeacons != 2U ||
            engine.linkStatus().lastBeaconMs != 1056U)
        {
            return false;
        }
        advertisement = wpa2Beacon();
        std::memset(&advertisement.at(38), 0, kSsid.size());
        if (engine.acceptRx(advertisement.data(), advertisement.size(), kTrust,
                            {-40, 1057U}, tx.data(), tx.size(),
                            action) != EngineResult::NoAction ||
            engine.linkStatus().acceptedBeacons != 3U ||
            engine.linkStatus().lastBeaconMs != 1057U)
        {
            return false;
        }
        // An expired association must retire even when the first incoming
        // frame is a spoofed same-BSSID beacon with a wrong channel. Never
        // let the mismatch bypass the preexisting one-shot LinkLost action.
        advertisement = wpa2Beacon();
        advertisement.at(48) = 11U;
        if (engine.acceptRx(advertisement.data(), advertisement.size(), kTrust,
                            {-40, 2258U}, tx.data(), tx.size(),
                            action) != EngineResult::Ok ||
            action.kind != ActionKind::LinkLost ||
            engine.linkStatus().reason != LinkLoss::BeaconTimeout ||
            engine.linkStatus().state != LinkState::ReconnectPending ||
            engine.linkStatus().acceptedBeacons != 3U ||
            engine.linkStatus().lastBeaconMs != 1057U ||
            engine.checkBeaconTimeout(2259U, action) != EngineResult::NoAction)
        {
            return false;
        }
        return true;
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
        // The native owner now polls this exact portable beacon deadline on
        // its independent association watchdog. A silent AP loss must not
        // require another received MPDU to retire an otherwise live port.
        EngineAction timeout {};
        const uint64_t lastBeacon = engine.linkStatus().lastBeaconMs;
        // A backwards monotonic observation must not be mistaken for a
        // healthy still-associated beacon lease by the native timer owner.
        if (lastBeacon == 0 ||
            engine.checkBeaconTimeout(lastBeacon - 1U, timeout) !=
                EngineResult::InvalidInput ||
            timeout.kind != ActionKind::None ||
            engine.linkStatus().state != LinkState::Associated)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        if (engine.checkBeaconTimeout(lastBeacon + 1U, timeout) !=
                EngineResult::NoAction ||
            timeout.kind != ActionKind::None ||
            engine.linkStatus().state != LinkState::Associated ||
            engine.checkBeaconTimeout(lastBeacon + 30001U, timeout) !=
                EngineResult::Ok ||
            timeout.kind != ActionKind::LinkLost ||
            engine.linkStatus().state != LinkState::ReconnectPending ||
            engine.linkStatus().reason != LinkLoss::BeaconTimeout ||
            engine.checkBeaconTimeout(lastBeacon + 30002U, timeout) !=
                EngineResult::NoAction ||
            timeout.kind != ActionKind::None)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        // The physical owner must quiesce DMA/remove keys separately;
        // portable link timeout alone never asserts that those steps ran.
        engine.radioStopped(lastBeacon + 30002U, false);
        if (engine.linkStatus().state != LinkState::RadioUnavailable ||
            engine.stationState() != StationState::Inactive)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        rxScratch.fill(0U);
        return 0;
    }

    std::array<uint8_t, 33> addbaRequest()
    {
        std::array<uint8_t, 33> frame {};
        frame.at(0) = 0xd0; // Management Action subtype, unprotected.
        std::memcpy(&frame.at(4), kStation.data(), kStation.size());
        std::memcpy(&frame.at(10), kAp.data(), kAp.size());
        std::memcpy(&frame.at(16), kAp.data(), kAp.size());
        frame.at(24) = 3;    // BlockAck category.
        frame.at(25) = 0;    // ADDBA Request.
        frame.at(26) = 0x9a; // Dialogue token.
        frame.at(27) = 0x17; // TID 5, A-MSDU, immediate policy, 64 slots.
        frame.at(28) = 0x10;
        frame.at(29) = 0x23; // Timeout 0x0123 TU.
        frame.at(30) = 0x01;
        frame.at(31) = 0xf0; // Initial sequence 4095, fragment 0.
        frame.at(32) = 0xff;
        return frame;
    }

    // The portable and native control paths refuse all BA negotiations until
    // an actual synchronized, key/association-local RX reorder owner exists.
    // NOLINTNEXTLINE(readability-function-cognitive-complexity)
    int checkedBlockAckDecline()
    {
        auto requestBytes = addbaRequest();
        AddbaRequest request {};
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        const Mac ap {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        if (parseAddbaRequest(requestBytes.data(), requestBytes.size(),
                              request) != Result::Ok ||
            request.dialogToken != 0x9a || request.tid != 5 ||
            request.bufferSize != 64 || request.timeoutTu != 0x0123 ||
            request.startingSequence != 4095 || !request.immediate ||
            !request.amsduPermitted)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        std::array<uint8_t, 128> reply {};
        reply.fill(0x7d);
        size_t written = 999;
        if (makeAddbaDecline(station, ap, request, 4095, reply.data(), 32,
                             written) != Result::BufferTooSmall ||
            written != 0 || reply.at(0) != 0x7d ||
            makeAddbaDecline(station, ap, request, 4095, reply.data(),
                             reply.size(), written) != Result::Ok ||
            written != 33 || reply.at(0) != 0xd0 || reply.at(22) != 0xf0 ||
            reply.at(23) != 0xff || reply.at(24) != 3 || reply.at(25) != 1 ||
            reply.at(26) != 0x9a || reply.at(27) != 37 || reply.at(28) != 0 ||
            reply.at(29) != 0x16 || reply.at(30) != 0x10 ||
            reply.at(31) != 0x23 || reply.at(32) != 0x01 ||
            std::memcmp(&reply.at(4), kAp.data(), kAp.size()) != 0 ||
            std::memcmp(&reply.at(10), kStation.data(), kStation.size()) != 0)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        auto corrupt = requestBytes;
        corrupt.at(31) = 0xf1; // Fragment number may not enter a BA anchor.
        if (parseAddbaRequest(corrupt.data(), corrupt.size(), request) !=
                Result::InvalidFrame ||
            request.bufferSize != 0)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        corrupt = requestBytes;
        corrupt.at(27) &= 0x3f;
        corrupt.at(28) = 0x00; // A zero receive window is invalid.
        if (parseAddbaRequest(corrupt.data(), corrupt.size(), request) !=
                Result::InvalidFrame ||
            parseAddbaRequest(requestBytes.data(), 32, request) !=
                Result::Truncated ||
            request.bufferSize != 0)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        std::array<uint8_t, 34> trailing {};
        std::memcpy(trailing.data(), requestBytes.data(), requestBytes.size());
        if (parseAddbaRequest(trailing.data(), trailing.size(), request) !=
            Result::InvalidFrame)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        corrupt = requestBytes;
        corrupt.at(1) = 0x40; // Protected PMF action without key authority.
        if (parseAddbaRequest(corrupt.data(), corrupt.size(), request) !=
            Result::UnsupportedFrame)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        corrupt = requestBytes;
        corrupt.at(24) = 4; // Not a BlockAck category.
        if (parseAddbaRequest(corrupt.data(), corrupt.size(), request) !=
            Result::UnsupportedFrame)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        const std::array<uint8_t, 32> pmk {{1}};
        std::array<uint8_t, 32> anonce {{7}};
        std::array<uint8_t, 32> snonce {};
        for (size_t i = 0; i < snonce.size(); ++i)
        {
            snonce.at(i) = static_cast<uint8_t>(i + 1U);
        }
        std::array<uint8_t, 48> ptk {};
        Provider provider {};
        WifiEngine engine;
        if (crypto::derivePtk(pmk.data(), ap, station, anonce.data(),
                              snonce.data(), ptk.data()) != crypto::Error::Ok ||
            !joinAndInstall(engine, provider, ptk.data()))
        {
            return __LINE__ % kFailureModulo + 1;
        }
        EngineAction action {};
        reply.fill(0x7d);
        if (engine.acceptRx(requestBytes.data(), requestBytes.size(), kTrust,
                            {-41, 1005}, reply.data(), 32,
                            action) != EngineResult::BufferTooSmall ||
            action.kind != ActionKind::None || reply.at(0) != 0x7d ||
            engine.acceptRx(requestBytes.data(), requestBytes.size(), kTrust,
                            {-41, 1006}, reply.data(), reply.size(),
                            action) != EngineResult::Ok ||
            action.kind != ActionKind::TransmitAddbaDecline ||
            action.bytes != 33 || reply.at(27) != 37 ||
            reply.at(22) != 0) // Native owner assigns the MAC TX sequence.
        {
            return __LINE__ % kFailureModulo + 1;
        }
        corrupt = requestBytes;
        corrupt.at(10) ^= 0x02; // Foreign AP cannot solicit a reply.
        if (engine.acceptRx(corrupt.data(), corrupt.size(), kTrust, {-41, 1007},
                            reply.data(), reply.size(),
                            action) != EngineResult::NoAction ||
            action.kind != ActionKind::None)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        corrupt = requestBytes;
        corrupt.at(4) ^= 0x02; // Another station's unicast action.
        if (engine.acceptRx(corrupt.data(), corrupt.size(), kTrust, {-41, 1008},
                            reply.data(), reply.size(),
                            action) != EngineResult::NoAction ||
            action.kind != ActionKind::None)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        corrupt = requestBytes;
        corrupt.at(31) |= 0x01; // Malformed active AP request.
        if (engine.acceptRx(corrupt.data(), corrupt.size(), kTrust, {-41, 1009},
                            reply.data(), reply.size(),
                            action) != EngineResult::InvalidReceivedFrame ||
            action.kind != ActionKind::None)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        InputTrust unverified = kTrust;
        unverified.dmaAndFcsVerified = false;
        if (engine.acceptRx(requestBytes.data(), requestBytes.size(),
                            unverified, {-41, 1010}, reply.data(), reply.size(),
                            action) != EngineResult::InvalidInput ||
            action.kind != ActionKind::None)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        std::array<uint8_t, 37> withFcs {};
        std::memcpy(withFcs.data(), requestBytes.data(), requestBytes.size());
        InputTrust verifiedFcs = kTrust;
        verifiedFcs.rxFrameIncludesFcs = true;
        if (engine.acceptRx(withFcs.data(), withFcs.size(), verifiedFcs,
                            {-41, 1011}, reply.data(), reply.size(),
                            action) != EngineResult::Ok ||
            action.kind != ActionKind::TransmitAddbaDecline)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        engine.radioStopped(1012, false);
        if (engine.acceptRx(requestBytes.data(), requestBytes.size(), kTrust,
                            {-41, 1013}, reply.data(), reply.size(),
                            action) != EngineResult::NoAction ||
            action.kind != ActionKind::None)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        return 0;
    }

    // Bound every valid 10-bit BlockAck window/TID while preserving the
    // exact refusal wire layout; none of these proposals creates an RX lease.
    // NOLINTNEXTLINE(readability-function-cognitive-complexity)
    int checkedBlockAckBoundaries()
    {
        auto frame = addbaRequest();
        AddbaRequest request {};
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        const Mac ap {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        std::array<uint8_t, 33> response {};
        constexpr std::array<uint16_t, 7> kWindows {
            {1U, 2U, 15U, 63U, 64U, 256U, 1023U}};
        for (uint16_t window : kWindows)
        {
            const uint16_t tid = static_cast<uint16_t>(window & 15U);
            const uint16_t parameters =
                static_cast<uint16_t>((window << 6U) | (tid << 2U) | 1U);
            frame.at(27) = static_cast<uint8_t>(parameters);
            frame.at(28) = static_cast<uint8_t>(parameters >> 8U);
            if (parseAddbaRequest(frame.data(), frame.size(), request) !=
                    Result::Ok ||
                request.bufferSize != window || request.tid != tid ||
                request.immediate || !request.amsduPermitted)
            {
                return __LINE__ % kFailureModulo + 1;
            }
            size_t written = 0;
            if (makeAddbaDecline(station, ap, request, 73, response.data(),
                                 response.size(), written) != Result::Ok ||
                written != response.size() || response.at(22) != 0x90 ||
                response.at(23) != 0x04 || response.at(27) != 37 ||
                response.at(28) != 0)
            {
                return __LINE__ % kFailureModulo + 1;
            }
            const uint16_t refusal = static_cast<uint16_t>(
                response.at(29) |
                (static_cast<uint16_t>(response.at(30)) << 8U));
            if (refusal !=
                static_cast<uint16_t>((window << 6U) | (tid << 2U) | 2U))
            {
                return __LINE__ % kFailureModulo + 1;
            }
        }
        size_t written = 999;
        if (makeAddbaDecline(station, ap, request, 4096, response.data(),
                             response.size(),
                             written) != Result::InvalidFrame ||
            written != 0)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        written = 999;
        // A public serializer must also reject a forged management header,
        // even if its addresses happen to match the associated station.
        request.header.moreFragments = true;
        if (makeAddbaDecline(station, ap, request, 1, response.data(),
                             response.size(),
                             written) != Result::InvalidFrame ||
            written != 0)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        request.header.moreFragments = false;
        written = 999;
        const uint8_t dialogue = request.dialogToken;
        // Overlapping output and *request* is rejected before writing.
        auto *aliased = reinterpret_cast<uint8_t *>(&request);
        if (makeAddbaDecline(station, ap, request, 1, aliased, sizeof(request),
                             written) != Result::OverlappingBuffers ||
            written != 999 || request.dialogToken != dialogue)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        return 0;
    }

    // Two Ethernet-II MSDUs inside one CCMP-authenticated QoS MPDU.
    // The source and protected A-MSDU selector are included in the SPP MIC.
    std::array<uint8_t, 73> protectedAggregatePlain()
    {
        std::array<uint8_t, 73> frame {};
        frame.at(0) = 0x88;
        frame.at(1) = 0x02;
        std::memcpy(&frame.at(4), kStation.data(), kStation.size());
        std::memcpy(&frame.at(10), kAp.data(), kAp.size());
        std::memcpy(&frame.at(16), kAp.data(), kAp.size());
        frame.at(22) = 0x30; // QoS sequence 3.
        frame.at(24) = 0x80; // QoS TID 0, A-MSDU Present.
        for (const size_t start : {26U, 50U})
        {
            std::memcpy(&frame.at(start), kStation.data(), kStation.size());
            std::memcpy(&frame.at(start + 6), kAp.data(), kAp.size());
            frame.at(start + 13) = 9; // LLC/SNAP(8) plus one byte.
            frame.at(start + 14) = 0xaa;
            frame.at(start + 15) = 0xaa;
            frame.at(start + 16) = 0x03;
            frame.at(start + 20) = 0x08; // EtherType IPv4.
        }
        frame.at(48) = 'A';
        frame.at(72) = 'B';
        return frame;
    }

    // One decrypt, two borrowed subframes, one QoS sequence admission.
    // NOLINTNEXTLINE(readability-function-cognitive-complexity)
    int verifiedNativeAggregateRx()
    {
        const std::array<uint8_t, 32> pmk {{1}};
        std::array<uint8_t, 32> anonce {{7}};
        std::array<uint8_t, 32> snonce {};
        for (size_t i = 0; i < snonce.size(); ++i)
        {
            snonce.at(i) = static_cast<uint8_t>(i + 1U);
        }
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        const Mac ap {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        std::array<uint8_t, 48> ptk {};
        Provider provider {};
        WifiEngine engine;
        if (crypto::derivePtk(pmk.data(), ap, station, anonce.data(),
                              snonce.data(), ptk.data()) != crypto::Error::Ok ||
            !joinAndInstall(engine, provider, ptk.data()))
        {
            return __LINE__ % kFailureModulo + 1;
        }
        crypto::CcmpSession apTx {};
        crypto::CcmpSession stationRx {};
        crypto::CcmpSession unnegotiated {};
        if (apTx.install(kPairwiseTk.data(), kAp.data(), 0, kEpoch, 0, 0,
                         true) != crypto::CcmpResult::Ok ||
            stationRx.install(kPairwiseTk.data(), kAp.data(), 0, kEpoch, 0, 0,
                              true) != crypto::CcmpResult::Ok ||
            unnegotiated.install(kPairwiseTk.data(), kAp.data(), 0, kEpoch, 0,
                                 0) != crypto::CcmpResult::Ok)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        auto plain = protectedAggregatePlain();
        std::array<uint8_t, 256> wire {};
        size_t wireBytes = 0;
        if (apTx.protect(kEpoch, plain.data(), plain.size(), wire.data(),
                         wire.size(), wireBytes) != crypto::CcmpResult::Ok)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        const LinkContext link {
            station, ap, LinkSecurity::Wpa2Ccmp, true, true, true, true};
        std::array<uint8_t, 256> scratch {};
        AmsduPayload decoded {};
        if (inspectProtectedStationAmsduRx(
                link, wire.data(), wireBytes, false, true, unnegotiated, kEpoch,
                scratch.data(), scratch.size(),
                decoded) != DataPathResult::UnverifiedDecryption ||
            unnegotiated.receiveFloor() != 0)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        // Physical DMA supplies the FCS layout; the portable parser strips
        // it only after the caller attests its independent FCS validation.
        if (inspectProtectedStationAmsduRx(link, wire.data(), wireBytes + 4U,
                                           true, true, stationRx, kEpoch,
                                           scratch.data(), scratch.size(),
                                           decoded) != DataPathResult::Ok ||
            stationRx.receiveFloor() != 1 || decoded.count != 2)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        const size_t plainBytes = wireBytes - 16U;
        AmsduPayload accepted {};
        InputTrust noMic = kTrust;
        noMic.ccmpMicAndReplayVerified = false;
        if (engine.acceptVerifiedProtectedAmsduRx(scratch.data(), plainBytes,
                                                  noMic, accepted) !=
                EngineResult::InvalidState ||
            accepted.count != 0 ||
            engine.acceptVerifiedProtectedAmsduRx(scratch.data(), plainBytes,
                                                  kTrust, accepted) !=
                EngineResult::Ok ||
            accepted.count != 2 || accepted.subframes[0].payload[0] != 'A' ||
            accepted.subframes[1].payload[0] != 'B')
        {
            return __LINE__ % kFailureModulo + 1;
        }
        // A new authenticated PN but the same QoS sequence must not publish
        // another copy, even when the retry bit is absent.
        if (apTx.protect(kEpoch, plain.data(), plain.size(), wire.data(),
                         wire.size(), wireBytes) != crypto::CcmpResult::Ok ||
            inspectProtectedStationAmsduRx(link, wire.data(), wireBytes, false,
                                           true, stationRx, kEpoch,
                                           scratch.data(), scratch.size(),
                                           decoded) != DataPathResult::Ok ||
            stationRx.receiveFloor() != 2 ||
            engine.acceptVerifiedProtectedAmsduRx(scratch.data(), plainBytes,
                                                  kTrust, accepted) !=
                EngineResult::NoAction ||
            accepted.count != 0)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        // Changing the QoS sequence starts a fresh delivery, but a cleared
        // or lost association must never retain the old delivery lease.
        plain.at(22) = 0x40;
        if (apTx.protect(kEpoch, plain.data(), plain.size(), wire.data(),
                         wire.size(), wireBytes) != crypto::CcmpResult::Ok ||
            inspectProtectedStationAmsduRx(link, wire.data(), wireBytes, false,
                                           true, stationRx, kEpoch,
                                           scratch.data(), scratch.size(),
                                           decoded) != DataPathResult::Ok ||
            engine.acceptVerifiedProtectedAmsduRx(scratch.data(), plainBytes,
                                                  kTrust,
                                                  accepted) != EngineResult::Ok)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        engine.clear();
        return engine.acceptVerifiedProtectedAmsduRx(scratch.data(), plainBytes,
                                                     kTrust, accepted) ==
                           EngineResult::InvalidState &&
                       accepted.count == 0
                   ? 0
                   : __LINE__ % kFailureModulo + 1;
    }

    // CCMP MIC/PN is not a substitute for 802.11 per-TID duplicate history.
    // Two independently authenticated PNs with the same on-air sequence
    // represent only one delivered MSDU, even if Retry is absent.
    // NOLINTNEXTLINE(readability-function-cognitive-complexity)
    int verifiedNativeOrdinarySequenceRx()
    {
        const std::array<uint8_t, 32> pmk {{1}};
        std::array<uint8_t, 32> anonce {{7}};
        std::array<uint8_t, 32> snonce {};
        for (size_t i = 0; i < snonce.size(); ++i)
        {
            snonce.at(i) = static_cast<uint8_t>(i + 1U);
        }
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        const Mac ap {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        std::array<uint8_t, 48> ptk {};
        Provider provider {};
        WifiEngine engine;
        if (crypto::derivePtk(pmk.data(), ap, station, anonce.data(),
                              snonce.data(), ptk.data()) != crypto::Error::Ok ||
            !joinAndInstall(engine, provider, ptk.data()))
        {
            return __LINE__ % kFailureModulo + 1;
        }
        crypto::CcmpSession apTx {};
        crypto::CcmpSession stationRx {};
        if (apTx.install(kPairwiseTk.data(), kAp.data(), 0, kEpoch, 0, 0) !=
                crypto::CcmpResult::Ok ||
            stationRx.install(kPairwiseTk.data(), kAp.data(), 0, kEpoch, 0,
                              0) != crypto::CcmpResult::Ok)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        std::array<uint8_t, 38> plain {};
        fromAp(plain);
        plain.at(22) = 0x10; // Legacy sequence one.
        plain.at(30) = 0x08; // IPv4, not EAPOL.
        plain.at(31) = 0x00;
        plain.at(32) = 'D';
        std::array<uint8_t, 512> wire {};
        std::array<uint8_t, 512> scratch {};
        const LinkContext link {
            station, ap, LinkSecurity::Wpa2Ccmp, true, true, true, true};
        auto transmitAndAdmit =
            [&](const uint8_t *frame, size_t length, const InputTrust &trust)
        {
            size_t wireBytes = 0;
            if (apTx.protect(kEpoch, frame, length, wire.data(), wire.size(),
                             wireBytes) != crypto::CcmpResult::Ok)
            {
                return EngineResult::CryptoFailure;
            }
            Msdu verified {};
            if (inspectProtectedStationRx(link, wire.data(), wireBytes, false,
                                          true, stationRx, kEpoch,
                                          scratch.data(), scratch.size(),
                                          verified) != DataPathResult::Ok)
            {
                return EngineResult::CryptoFailure;
            }
            return engine.acceptVerifiedProtectedDataRx(wire.data(), wireBytes,
                                                        trust, verified);
        };
        InputTrust missingMic = kTrust;
        missingMic.ccmpMicAndReplayVerified = false;
        if (transmitAndAdmit(plain.data(), plain.size(), kTrust) !=
                EngineResult::Ok ||
            transmitAndAdmit(plain.data(), plain.size(), kTrust) !=
                EngineResult::NoAction)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        // Failed trust proof must not consume the new sequence.
        plain.at(22) = 0x20;
        if (transmitAndAdmit(plain.data(), plain.size(), missingMic) !=
                EngineResult::InvalidState ||
            transmitAndAdmit(plain.data(), plain.size(), kTrust) !=
                EngineResult::Ok)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        // Detached or altered station-identity output cannot authorize a
        // fresh sequence, even after the packet's CCMP proof succeeded.
        plain.at(22) = 0x30;
        size_t identityWireBytes = 0;
        Msdu identityVerified {};
        if (apTx.protect(kEpoch, plain.data(), plain.size(), wire.data(),
                         wire.size(),
                         identityWireBytes) != crypto::CcmpResult::Ok ||
            inspectProtectedStationRx(link, wire.data(), identityWireBytes,
                                      false, true, stationRx, kEpoch,
                                      scratch.data(), scratch.size(),
                                      identityVerified) != DataPathResult::Ok)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        Msdu mismatched = identityVerified;
        mismatched.source.bytes[5] ^= 1U;
        if (engine.acceptVerifiedProtectedDataRx(wire.data(), identityWireBytes,
                                                 kTrust, mismatched) !=
                EngineResult::InvalidReceivedFrame ||
            engine.acceptVerifiedProtectedDataRx(wire.data(), 24U, kTrust,
                                                 identityVerified) !=
                EngineResult::InvalidReceivedFrame ||
            engine.acceptVerifiedProtectedDataRx(wire.data(), identityWireBytes,
                                                 kTrust, identityVerified) !=
                EngineResult::Ok)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        // QoS TID three and TID four each have independent windows from
        // legacy and from one another, even with the same sequence number.
        std::array<uint8_t, 40> qos {};
        std::memcpy(qos.data(), plain.data(), 24);
        std::memcpy(qos.data() + 26, plain.data() + 24, 14);
        qos.at(0) = 0x88;
        qos.at(24) = 3;
        if (transmitAndAdmit(qos.data(), qos.size(), kTrust) !=
                EngineResult::Ok ||
            transmitAndAdmit(qos.data(), qos.size(), kTrust) !=
                EngineResult::NoAction)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        qos.at(24) = 4;
        if (transmitAndAdmit(qos.data(), qos.size(), kTrust) !=
            EngineResult::Ok)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        // Each encrypted fragment has its own CCMP PN/MIC; the last one
        // may advance sequence history only after full station reassembly.
        plain.at(22) = 0x50;
        std::array<uint8_t, 32> first {};
        std::array<uint8_t, 30> last {};
        std::memcpy(first.data(), plain.data(), first.size());
        std::memcpy(last.data(), plain.data(), 24);
        std::memcpy(last.data() + 24, plain.data() + 32, 6);
        first.at(1) = 0x06; // FromDS, More Fragments.
        last.at(1) = 0x02;
        last.at(22) = 0x51; // Same 12-bit sequence, fragment one.
        auto completeFragments = [&]()
        {
            std::array<uint8_t, 128> firstWire {};
            std::array<uint8_t, 128> lastWire {};
            size_t firstBytes = 0;
            size_t lastBytes = 0;
            if (apTx.protect(kEpoch, first.data(), first.size(),
                             firstWire.data(), firstWire.size(), firstBytes,
                             true) != crypto::CcmpResult::Ok ||
                apTx.protect(kEpoch, last.data(), last.size(), lastWire.data(),
                             lastWire.size(), lastBytes,
                             true) != crypto::CcmpResult::Ok)
            {
                return EngineResult::CryptoFailure;
            }
            ProtectedFragmentStream fragments {};
            Msdu reassembled {};
            if (inspectProtectedFragmentStationRx(
                    link, firstWire.data(), firstBytes, false, true, stationRx,
                    kEpoch, fragments, 1U, scratch.data(), scratch.size(),
                    reassembled) != DataPathResult::PendingFragments ||
                reassembled.payload != nullptr ||
                inspectProtectedFragmentStationRx(
                    link, lastWire.data(), lastBytes, false, true, stationRx,
                    kEpoch, fragments, 2U, scratch.data(), scratch.size(),
                    reassembled) != DataPathResult::Ok)
            {
                return EngineResult::CryptoFailure;
            }
            return engine.acceptVerifiedProtectedDataRx(
                lastWire.data(), lastBytes, kTrust, reassembled);
        };
        if (completeFragments() != EngineResult::Ok ||
            completeFragments() != EngineResult::NoAction)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        // An EAPOL MSDU is not ordinary data; its MIC/replay state belongs
        // exclusively to the supplicant's Group1 path.
        const auto eapol = cleartextApFrame(
            makeSignedKey({0x82, 3}, kGroupWrapped, ptk.data()));
        if (transmitAndAdmit(eapol.data(), eapol.size(), kTrust) !=
            EngineResult::InvalidReceivedFrame)
        {
            return __LINE__ % kFailureModulo + 1;
        }
        engine.clear();
        return transmitAndAdmit(plain.data(), plain.size(), kTrust) ==
                       EngineResult::InvalidState
                   ? 0
                   : __LINE__ % kFailureModulo + 1;
    }

    // NOLINTEND(*avoid-magic-numbers,readability-magic-numbers)
} // namespace

int main()
{
    if (!rejectAssociatedBeaconPolicyDrift())
    {
        return 78;
    }
    const int baseline = protectedGroupExchange();
    if (baseline != 0)
    {
        return baseline;
    }
    const int native = verifiedNativeGroupExchange();
    if (native != 0)
    {
        return native;
    }
    const int blockAck = checkedBlockAckDecline();
    if (blockAck != 0)
    {
        return blockAck;
    }
    const int boundaries = checkedBlockAckBoundaries();
    if (boundaries != 0)
    {
        return boundaries;
    }
    const int aggregate = verifiedNativeAggregateRx();
    return aggregate == 0 ? verifiedNativeOrdinarySequenceRx() : aggregate;
}
