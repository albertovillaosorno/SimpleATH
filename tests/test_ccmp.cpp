// SPDX-License-Identifier: AGPL-3.0-only
// Host-only CCMP-128 frame tests; no RF, kernel crypto or installed keys.
// Known AES-CCM ciphertext/MIC independently checked against OpenSSL EVP.
#include "wifi/crypto/Ccmp.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

using namespace simpleath::ieee80211::crypto;

namespace
{
    // Packet constants are exact published 802.11/CCM offsets and fixed
    // regression vector octets, rather than arbitrary numeric configuration.
    // NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    constexpr uint64_t kEpoch = 9001U;
    constexpr size_t kProtectedHeader = 32U;
    constexpr int kDiagnosticModulo = 251;
    constexpr std::array<uint8_t, 16U> kTk {
        0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U, 9U, 10U, 11U, 12U, 13U, 14U, 15U,
    };
    constexpr std::array<uint8_t, 6U> kTransmitter {
        0x02U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U,
    };
    // Fixed 802.11 ToDS header and LLC/SNAP 0x0800 followed by "hello world".
    constexpr std::array<uint8_t, 43U> kPlain {
        0x08U, 0x01U, 0U,    0U,    0x02U, 0xaaU, 0xbbU, 0xccU, 0xddU,
        0xeeU, 0x02U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x02U, 0x33U,
        0x44U, 0x55U, 0x66U, 0x77U, 0U,    0U,    0xaaU, 0xaaU, 0x03U,
        0U,    0U,    0U,    0x08U, 0U,    'h',   'e',   'l',   'l',
        'o',   ' ',   'w',   'o',   'r',   'l',   'd',
    };
    // OpenSSL 3.5 EVP_aes_128_ccm nonce 00:02:11:22:33:44:55:00:00:00:00:00:01,
    // AAD = (frame control 08:41) || addresses || sequence 00:00, MIC=8.
    constexpr std::array<uint8_t, 27U> kExpectedCipherAndTag {
        0x61U, 0xd6U, 0xd3U, 0x3dU, 0x81U, 0xdfU, 0x62U, 0x96U, 0x66U,
        0x08U, 0x65U, 0x56U, 0x6eU, 0xe5U, 0x95U, 0xf7U, 0xc6U, 0xd1U,
        0xfbU, 0x39U, 0xa5U, 0x8cU, 0xd7U, 0xf2U, 0xa1U, 0xedU, 0x08U,
    };

    bool fresh(CcmpSession &session, uint8_t keyId = 0U, uint64_t lastTx = 0U,
               uint64_t rxFloor = 0U)
    {
        return session.install(kTk.data(), kTransmitter.data(), keyId, kEpoch,
                               lastTx, rxFloor) == CcmpResult::Ok;
    }

    // Test the input byte count and output byte count separately. Their
    // identical size_t types are required by the C++14 byte-buffer ABI.
    // NOLINTBEGIN(readability-suspicious-call-argument)
    int testIndependentVector()
    {
        CcmpSession tx {};
        CcmpSession rx {};
        if (!fresh(tx) || !fresh(rx))
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        std::array<uint8_t, kCcmpMaximumMpduBytes> wire {};
        size_t written = 0U;
        if (tx.protect(kEpoch, kPlain.data(), kPlain.size(), wire.data(),
                       wire.size(), written) != CcmpResult::Ok ||
            written != kPlain.size() + 16U || wire.at(1U) != 0x41U ||
            wire.at(24U) != 1U || wire.at(25U) != 0U || wire.at(26U) != 0U ||
            wire.at(27U) != 0x20U || tx.lastTransmittedPn() != 1U ||
            std::memcmp(&wire.at(kProtectedHeader),
                        kExpectedCipherAndTag.data(),
                        kExpectedCipherAndTag.size()) != 0)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        std::array<uint8_t, kCcmpMaximumMpduBytes> plain {};
        size_t recovered = 0U;
        if (rx.unprotect(kEpoch, wire.data(), written, plain.data(),
                         plain.size(), recovered) != CcmpResult::Ok ||
            recovered != kPlain.size() || rx.receiveFloor() != 1U ||
            std::memcmp(plain.data(), kPlain.data(), kPlain.size()) != 0)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        // Repeating the same ciphertext is a replay, even with valid MIC.
        return rx.unprotect(kEpoch, wire.data(), written, plain.data(),
                            plain.size(),
                            recovered) == CcmpResult::ReplayDetected
                   ? 0
                   : (__LINE__ % kDiagnosticModulo) + 1;
    }

    int testTamperingAndNoDisclosure()
    {
        CcmpSession tx {};
        CcmpSession rx {};
        if (!fresh(tx) || !fresh(rx))
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        std::array<uint8_t, kCcmpMaximumMpduBytes> wire {};
        size_t written = 0U;
        if (tx.protect(kEpoch, kPlain.data(), kPlain.size(), wire.data(),
                       wire.size(), written) != CcmpResult::Ok)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        std::array<uint8_t, kCcmpMaximumMpduBytes> output {};
        output.fill(0xa5U);
        const auto untouched = output;
        size_t recovered = 777U;
        const auto original = wire;
        const size_t kMutations[] {
            kProtectedHeader,
            kProtectedHeader + 5U,
            kProtectedHeader + 19U,
            4U,
            16U,
            written - 1U,
        };
        for (const size_t offset : kMutations)
        {
            wire = original;
            wire.at(offset) ^= 1U;
            if (rx.unprotect(kEpoch, wire.data(), written, output.data(),
                             output.size(),
                             recovered) != CcmpResult::MicMismatch ||
                recovered != 777U || output != untouched ||
                rx.receiveFloor() != 0U)
            {
                return (__LINE__ % kDiagnosticModulo) + 1;
            }
        }
        wire = original;
        wire.at(26U) = 1U;
        if (rx.unprotect(kEpoch, wire.data(), written, output.data(),
                         output.size(),
                         recovered) != CcmpResult::InvalidFrame ||
            recovered != 777U || output != untouched)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        wire = original;
        wire.at(27U) ^= 0x20U;
        if (rx.unprotect(kEpoch, wire.data(), written, output.data(),
                         output.size(), recovered) != CcmpResult::InvalidFrame)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        wire = original;
        wire.at(28U) = 0U;
        wire.at(24U) = 0U;
        if (rx.unprotect(kEpoch, wire.data(), written, output.data(),
                         output.size(),
                         recovered) != CcmpResult::ReplayDetected)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        wire = original;
        if (rx.unprotect(kEpoch + 1U, wire.data(), written, output.data(),
                         output.size(), recovered) != CcmpResult::WrongEpoch ||
            rx.receiveFloor() != 0U || output != untouched)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        return 0;
    }

    int testBoundsAndOwnership()
    {
        CcmpSession tx {};
        CcmpSession rx {};
        if (!fresh(tx) || !fresh(rx, 1U))
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        std::array<uint8_t, kCcmpMaximumMpduBytes> wire {};
        wire.fill(0xa5U);
        size_t written = 999U;
        if (tx.protect(kEpoch, kPlain.data(), kPlain.size(), wire.data(),
                       kPlain.size() + 15U,
                       written) != CcmpResult::BufferTooSmall ||
            written != 999U || wire.at(0U) != 0xa5U ||
            tx.lastTransmittedPn() != 0U ||
            tx.protect(kEpoch, wire.data(), kPlain.size(), wire.data(),
                       wire.size(),
                       written) != CcmpResult::OverlappingBuffers ||
            tx.lastTransmittedPn() != 0U ||
            rx.protect(kEpoch, kPlain.data(), kPlain.size(), wire.data(),
                       wire.size(), written) != CcmpResult::UnsupportedFrame)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        auto malformed = kPlain;
        malformed.at(0U) = 0x88U; // QoS data unsupported.
        if (tx.protect(kEpoch, malformed.data(), malformed.size(), wire.data(),
                       wire.size(), written) != CcmpResult::UnsupportedFrame)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        malformed = kPlain;
        malformed.at(1U) |= 0x04U; // MoreFragments.
        if (tx.protect(kEpoch, malformed.data(), malformed.size(), wire.data(),
                       wire.size(), written) != CcmpResult::UnsupportedFrame)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        malformed = kPlain;
        malformed.at(22U) = 1U; // Fragment index.
        if (tx.protect(kEpoch, malformed.data(), malformed.size(), wire.data(),
                       wire.size(), written) != CcmpResult::UnsupportedFrame)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        // An occupied session may not reset the same TK and reuse PN.
        if (tx.install(kTk.data(), kTransmitter.data(), 0U, kEpoch, 0U, 0U) !=
            CcmpResult::InvalidArgument)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        tx.revoke();
        return !tx.installed() &&
                       tx.protect(kEpoch, kPlain.data(), kPlain.size(),
                                  wire.data(), wire.size(),
                                  written) == CcmpResult::MissingKey
                   ? 0
                   : (__LINE__ % kDiagnosticModulo) + 1;
    }

    int testPacketNumberAndLargeFrames()
    {
        CcmpSession nearlyExhausted {};
        if (!fresh(nearlyExhausted, 0U, kCcmpMaximumPacketNumber - 1U))
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        std::array<uint8_t, kCcmpMaximumMpduBytes> wire {};
        size_t written = 0U;
        if (nearlyExhausted.protect(kEpoch, kPlain.data(), kPlain.size(),
                                    wire.data(), wire.size(),
                                    written) != CcmpResult::Ok ||
            nearlyExhausted.lastTransmittedPn() != kCcmpMaximumPacketNumber ||
            nearlyExhausted.protect(kEpoch, kPlain.data(), kPlain.size(),
                                    wire.data(), wire.size(), written) !=
                CcmpResult::PacketNumberExhausted)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        CcmpSession tx {};
        CcmpSession rx {};
        if (!fresh(tx) || !fresh(rx))
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        std::array<uint8_t, kCcmpMaximumMpduBytes> plain {};
        std::memcpy(plain.data(), kPlain.data(), kPlain.size());
        for (size_t i = kPlain.size(); i < 2300U; ++i)
        {
            plain.at(i) = static_cast<uint8_t>(i & 0xffU);
        }
        for (const size_t count : {
                 size_t {25U},
                 size_t {39U},
                 size_t {43U},
                 size_t {300U},
                 size_t {1024U},
                 size_t {2300U},
             })
        {
            std::array<uint8_t, kCcmpMaximumMpduBytes> recovered {};
            size_t decrypted = 0U;
            if (tx.protect(kEpoch, plain.data(), count, wire.data(),
                           wire.size(), written) != CcmpResult::Ok ||
                rx.unprotect(kEpoch, wire.data(), written, recovered.data(),
                             recovered.size(), decrypted) != CcmpResult::Ok ||
                decrypted != count ||
                std::memcmp(plain.data(), recovered.data(), count) != 0 ||
                rx.receiveFloor() != tx.lastTransmittedPn())
            {
                return (__LINE__ % kDiagnosticModulo) + 1;
            }
        }
        return 0;
    }

    // NOLINTEND(readability-suspicious-call-argument)
    // NOLINTEND(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
} // namespace

int main()
{
    if (const int result = testIndependentVector())
    {
        return result;
    }
    if (const int result = testTamperingAndNoDisclosure())
    {
        return result;
    }
    if (const int result = testBoundsAndOwnership())
    {
        return result;
    }
    return testPacketNumberAndLargeFrames();
}
