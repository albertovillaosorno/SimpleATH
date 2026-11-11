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
//   - Native driver contracts and implementation for tahoe join codec.
// - Must-Not:
//   - Invent hardware readiness, weaken buffer bounds, or assume ABI
//     compatibility.
// - Allows:
//   - Inputs: validated register, protocol, platform, or device state from
//     callers.
//   - Outputs: bounded native transitions, messages, or explicit errors.
//   - Side effects: only the device and kernel operations owned by this module.
// - Split-When:
//   - A separate protocol stage needs independent validation and ownership.
// - Merge-When:
//   - The caller directly owns this narrow contract without reuse.
// - Summary:
//   - Native driver contracts and implementation for tahoe join codec.
// - Description:
//   - Implements or verifies the TahoeJoinCodec source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for tahoe join codec.

// Bounded, source-derived modern WCL join-request decoding for the AR9565.
// The native owner must confirm PCI/RF/channel authority and securely retire
// each copied credential; decoding is never association authorization.
#ifndef SIMPLEATH_TAHOE_JOIN_CODEC_HPP
#define SIMPLEATH_TAHOE_JOIN_CODEC_HPP

#include "../../wifi/crypto/Wpa2Primitives.hpp"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace simpleath
{
    namespace tahoe
    {
        constexpr size_t kWclJoinRequestBytes = 0x2ccU;
        constexpr size_t kWclPmkBytes = 32U;
        constexpr size_t kWclSsidBytes = 32U;
        constexpr size_t kWclBssidBytes = 6U;

        struct JoinSelection
        {
                uint8_t ssid[kWclSsidBytes] {};
                uint8_t bssid[kWclBssidBytes] {};
                uint8_t pmk[kWclPmkBytes] {};
                uint8_t ssidLength {0};
                uint8_t channel {0};
                bool wpa2Personal {false};
        };

        // Explicitly erase the private PMK and all association metadata on
        // success, abort, cancellation, teardown or any native owner failure.
        inline void clearJoin(JoinSelection &selection)
        {
            // Volatile scalar stores keep the secret erase observable even
            // under whole-program optimization and no-exceptions kext builds.
            for (volatile uint8_t &byte : selection.pmk)
            {
                byte = 0;
            }
            for (volatile uint8_t &byte : selection.ssid)
            {
                byte = 0;
            }
            for (volatile uint8_t &byte : selection.bssid)
            {
                byte = 0;
            }
            selection.ssidLength = 0;
            selection.channel = 0;
            selection.wpa2Personal = false;
        }

        namespace join_codec_detail
        {
            constexpr size_t kLowerAuthOffset = 0x10U;
            constexpr size_t kUpperAuthOffset = 0x14U;
            constexpr size_t kSsidLengthOffset = 0x1cU;
            constexpr size_t kSsidOffset = 0x20U;
            constexpr size_t kKeyLengthOffset = 0x44U;
            constexpr size_t kKeyCipherOffset = 0x48U;
            constexpr size_t kKeyOffset = 0x50U;
            constexpr size_t kRsnLengthOffset = 0xd4U;
            constexpr size_t kRsnOffset = 0xd6U;
            constexpr size_t kMloFlagsOffset = 0x1e0U;
            constexpr size_t kCandidateCountOffset = 0x214U;
            constexpr size_t kBssidOffset = 0x21cU;
            constexpr size_t kChannelSpecOffset = 0x228U;
            constexpr size_t kMaxCandidates = 10U;
            constexpr size_t kCandidateStride = 18U;
            constexpr size_t kCandidateStart = 0x218U;
            constexpr uint16_t kChannel20Mhz2Ghz = 0x1000U;
            constexpr uint8_t kMax2GhzChannel = 14U;
            constexpr uint32_t kOpenSystemAuthentication = 1U;
            constexpr uint32_t kWpa2PersonalAuthentication = 1U << 3U;
            constexpr uint32_t kWclCipherPmk = 6U;
            constexpr uint32_t kWclCipherPmksa = 7U;
            constexpr uint32_t kWclCipherPassphrase = 10U;
            constexpr size_t kMinPassphraseBytes = 8U;
            constexpr size_t kMaxPassphraseBytes = 63U;
            constexpr uint8_t kRsnElement = 48U;
            constexpr uint16_t kRsnVersion = 1U;
            constexpr size_t kMaxRsnBytes = 257U;
            constexpr uint16_t kChannelBandWidthMask = 0xff00U;
            constexpr uint8_t kMloFlag = 0x80U;

            inline bool overlaps(const void *left, size_t leftBytes,
                                 const void *right, size_t rightBytes)
            {
                if (left == nullptr || right == nullptr || leftBytes == 0U ||
                    rightBytes == 0U)
                {
                    return false;
                }
                uintptr_t a = 0;
                uintptr_t b = 0;
                static_assert(sizeof(a) == sizeof(left),
                              "native pointer widths must match");
                __builtin_memcpy(&a, static_cast<const void *>(&left),
                                 sizeof(a));
                __builtin_memcpy(&b, static_cast<const void *>(&right),
                                 sizeof(b));
                return a <= b ? b - a < leftBytes : a - b < rightBytes;
            }

            inline uint8_t readByte(const uint8_t *bytes, size_t offset)
            {
                // A fixed native WCL byte-envelope, bounded at decode entry.
// NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
                return bytes[offset];
            }

            inline void copyField(const uint8_t *bytes, size_t offset,
                                  void *destination, size_t length)
            {
                // The decode contract bounds each fixed field in 0x2cc.
// NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
                __builtin_memcpy(destination, bytes + offset, length);
            }

            inline uint16_t read16(const uint8_t *bytes, size_t offset)
            {
                uint16_t result = 0;
                copyField(bytes, offset, &result, sizeof(result));
                return result;
            }

            inline uint32_t read32(const uint8_t *bytes, size_t offset)
            {
                uint32_t result = 0;
                copyField(bytes, offset, &result, sizeof(result));
                return result;
            }

            inline bool derivePassphrase(const uint8_t *bytes, size_t keyLength,
                                         JoinSelection &selection)
            {
                uint8_t password[kMaxPassphraseBytes] {};
                copyField(bytes, kKeyOffset, &password[0], keyLength);
                uint8_t zeros = 0;
                size_t processed = 0;
                for (const uint8_t byte : password)
                {
                    if (processed == keyLength)
                    {
                        break;
                    }
                    zeros |= static_cast<uint8_t>(byte == 0);
                    ++processed;
                }
                const auto status =
                    zeros == 0
                        ? ieee80211::crypto::derivePmk(
                              &password[0], keyLength, &selection.ssid[0],
                              selection.ssidLength, &selection.pmk[0])
                        : ieee80211::crypto::Error::InvalidPassword;
                for (volatile uint8_t &byte : password)
                {
                    byte = 0;
                }
                if (status != ieee80211::crypto::Error::Ok)
                {
                    clearJoin(selection);
                    return false;
                }
                return true;
            }
        } // namespace join_codec_detail

        // Only supports an explicit 20-MHz 2.4-GHz station join, either truly
        // open or WPA2-PSK with a host-derived PMK (32-byte PMK or an 8..63
        // byte passphrase derived through the portable PBKDF2). WEP/TKIP,
        // SAE/WPA3, enterprise, 5/6 GHz, MLO and ambiguous auth are rejected.
        // The caller must supply exactly the native WCL request allocation;
        // neither arbitrary length nor a fabricated request is permitted.
        // Failed decoding leaves the destination entirely unchanged.
        inline bool decodeJoin(const uint8_t *bytes, size_t length,
                               JoinSelection &out)
        {
            using namespace join_codec_detail;
            if (bytes == nullptr || length != kWclJoinRequestBytes ||
                overlaps(bytes, length, &out, sizeof(out)))
            {
                return false;
            }
            const uint32_t candidates = read32(bytes, kCandidateCountOffset);
            const uint32_t ssidLength = read32(bytes, kSsidLengthOffset);
            const uint32_t keyLength = read32(bytes, kKeyLengthOffset);
            const uint32_t lower = read32(bytes, kLowerAuthOffset);
            const uint32_t upper = read32(bytes, kUpperAuthOffset);
            const uint32_t cipher = read32(bytes, kKeyCipherOffset);
            const uint16_t rsnLength = read16(bytes, kRsnLengthOffset);
            const uint16_t spec = read16(bytes, kChannelSpecOffset);
            const auto channel = static_cast<uint8_t>(spec & 0xffU);
            if (candidates == 0 || candidates > kMaxCandidates ||
                kCandidateStart + (candidates * kCandidateStride) > length ||
                ssidLength == 0 || ssidLength > sizeof(out.ssid) ||
                lower != kOpenSystemAuthentication ||
                (spec & kChannelBandWidthMask) != kChannel20Mhz2Ghz ||
                channel == 0 || channel > kMax2GhzChannel ||
                rsnLength > kMaxRsnBytes ||
                // The WCL join candidate must be a non-MLO unicast BSSID.
                (readByte(bytes, kMloFlagsOffset) & kMloFlag) != 0 ||
                (readByte(bytes, kBssidOffset) & 1U) != 0)
            {
                return false;
            }
            uint8_t addressBits = 0;
            for (size_t i = 0; i < sizeof(out.bssid); ++i)
            {
                addressBits |= readByte(bytes, kBssidOffset + i);
            }
            if (addressBits == 0)
            {
                return false;
            }
            const bool open =
                upper == 0 && keyLength == 0 && cipher == 0 && rsnLength == 0;
            const bool rawPmk =
                keyLength == kWclPmkBytes &&
                (cipher == kWclCipherPmk || cipher == kWclCipherPmksa);
            const bool passphrase = keyLength >= kMinPassphraseBytes &&
                                    keyLength <= kMaxPassphraseBytes &&
                                    cipher == kWclCipherPassphrase;
            const bool personal =
                upper == kWpa2PersonalAuthentication && (rawPmk || passphrase);
            if (!open && !personal)
            {
                return false;
            }
            if (personal && rsnLength != 0 &&
                (rsnLength < 4U || readByte(bytes, kRsnOffset) != kRsnElement ||
                 static_cast<size_t>(readByte(bytes, kRsnOffset + 1U)) + 2U !=
                     rsnLength ||
                 read16(bytes, kRsnOffset + 2U) != kRsnVersion))
            {
                return false;
            }
            JoinSelection selection {};
            copyField(bytes, kSsidOffset, &selection.ssid[0], ssidLength);
            copyField(bytes, kBssidOffset, &selection.bssid[0],
                      sizeof(selection.bssid));
            selection.ssidLength = static_cast<uint8_t>(ssidLength);
            selection.channel = channel;
            selection.wpa2Personal = personal;
            if (personal && rawPmk)
            {
                uint8_t bits = 0;
                for (size_t i = 0; i < kWclPmkBytes; ++i)
                {
                    bits |= readByte(bytes, kKeyOffset + i);
                }
                if (bits == 0)
                {
                    return false;
                }
                copyField(bytes, kKeyOffset, &selection.pmk[0], kWclPmkBytes);
            }
            if (personal && passphrase &&
                !derivePassphrase(bytes, keyLength, selection))
            {
                return false;
            }
            out = selection;
            clearJoin(selection);
            return true;
        }
    } // namespace tahoe
} // namespace simpleath
#endif
