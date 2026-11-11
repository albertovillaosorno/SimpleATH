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
//   - Native driver contracts and implementation for tahoe scan codec.
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
//   - Native driver contracts and implementation for tahoe scan codec.
// - Description:
//   - Implements or verifies the TahoeScanCodec source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for tahoe scan codec.

#ifndef SIMPLEATH_TAHOE_SCAN_CODEC_HPP
#define SIMPLEATH_TAHOE_SCAN_CODEC_HPP
#include "../../wifi/LegacyScanBridge.hpp"
#include "bluetooth/UsbBytes.hpp"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace simpleath
{
    namespace tahoe
    {
        // Exact modern WCL request offsets, separate from legacy SCAN_REQ.
        constexpr size_t kWclScanBssidBytes = 6U;
        constexpr size_t kWclScanSsidBytes = 32U;
        constexpr size_t kWclScanHeaderBytes = 0x58U;
        constexpr size_t kWclSsidLengthOffset = 0x1cU;
        constexpr size_t kWclKindOffset = 0x40U;
        constexpr size_t kWclEntryCountOffset = 0x54U;
        constexpr size_t kWclFilterBssidOffset = 0x14U;
        constexpr size_t kWclFilterSsidOffset = 0x20U;
        constexpr size_t kWclScanEntryBytes = 12U;
        constexpr size_t kWclEntryChannelOffset = 4U;
        constexpr size_t kWclEntryFlagsOffset = 8U;
        constexpr uint32_t kWclMaximumEntries = 400U;
        constexpr uint32_t kWclMaximumKind = 4U;
        constexpr uint8_t kWclAllOnes = 0xffU;
        constexpr uint8_t kWclChannelMinimum = 1U;
        constexpr uint8_t kWclChannelMaximum = 14U;
        constexpr uint16_t kWclAllChannels = 0x3fffU;
        constexpr uint32_t kWclChannel2GhzFlag = 0x8U;
        constexpr uint32_t kWclChannel5GhzFlag = 0x10U;
        constexpr uint32_t kWclChannel6GhzFlag = 0x2000U;
        constexpr size_t kWclBssPrefixBytes = 0x44U;
        constexpr size_t kWclBssSsidLengthBytes = 2U;
        constexpr size_t kWclBssFixedTailBytes = 3U;
        constexpr size_t kWclMaxRsnInformationElementBytes = 257U;
        constexpr size_t kWclRateElementMax = 8U;
        constexpr size_t kWclBasicRatesHeaderBytes = 2U;
        constexpr size_t kWclExtendedRatesHeaderBytes = 4U;
        constexpr uint8_t kWclSupportedRatesElement = 1U;
        constexpr uint8_t kWclExtendedRatesElement = 50U;
        constexpr uint8_t kWclChannelElement = 3U;
        constexpr uint8_t kWclRsnElement = 48U;
        constexpr size_t kWclRsnHeaderBytes = 2U;
        constexpr size_t kWclBssSsidOffset = 6U;
        constexpr size_t kWclBssSsidLengthOffset = 0x26U;
        constexpr size_t kWclBssChannelOffset = 0x27U;
        constexpr size_t kWclBssBssidOffset = 0x29U;
        constexpr size_t kWclBssSignalOffset = 0x30U;
        constexpr size_t kWclBssBeaconOffset = 0x38U;
        constexpr size_t kWclBssCapabilitiesOffset = 0x3aU;
        constexpr size_t kWclBssFlagsOffset = 0x40U;
        constexpr uint16_t kWclChannelTag = 0x1000U;
        constexpr uint32_t kWclSignalMeasuredBit = (1U << 14U);
        constexpr uint32_t kWclHasSsidBit = 2U;

        // A native caller must not serialize a BSS over the snapshot from
        // which it is reading, or decode a request into its own request bytes.
        // Subtraction avoids overflowing when an untrusted extent is large.
        inline uintptr_t scanPointerAddress(const void *pointer)
        {
            uintptr_t address = 0;
            static_assert(sizeof(address) == sizeof(pointer),
                          "native pointer width must match uintptr_t");
            __builtin_memcpy(&address, static_cast<const void *>(&pointer),
                             sizeof(pointer));
            return address;
        }

        inline bool scanRangesOverlap(const void *left, size_t leftBytes,
                                      const void *right, size_t rightBytes)
        {
            if (left == nullptr || right == nullptr || leftBytes == 0 ||
                rightBytes == 0)
            {
                return false;
            }
            const uintptr_t a = scanPointerAddress(left);
            const uintptr_t b = scanPointerAddress(right);
            return a >= b ? a - b < rightBytes : b - a < leftBytes;
        }

        // All reads are bounded by the caller's fixed native request extent.
        struct ScanFilter
        {
                uint32_t identifier;
                uint16_t channels;
                uint8_t bssid[kWclScanBssidBytes];
                uint8_t ssid[kWclScanSsidBytes];
                uint8_t ssidLength;
                bool directedBssid;
        };

        inline bool decodeScan(const uint8_t *bytes, size_t length,
                               ScanFilter &out)
        {
            // Check before clearing out: when it aliases the input, even a
            // rejected request must not destroy its own source bytes.
            if (scanRangesOverlap(bytes, length, &out, sizeof(out)))
            {
                return false;
            }
            out = {};
            if (bytes == nullptr || length < kWclScanHeaderBytes)
            {
                return false;
            }
            uint32_t ssidLength = 0;
            uint32_t kind = 0;
            uint32_t count = 0;
            memcpy(&ssidLength, usbByteOffset(bytes, kWclSsidLengthOffset),
                   sizeof(ssidLength));
            memcpy(&kind, usbByteOffset(bytes, kWclKindOffset), sizeof(kind));
            memcpy(&count, usbByteOffset(bytes, kWclEntryCountOffset),
                   sizeof(count));
            if (ssidLength > sizeof(out.ssid) || kind < 1 ||
                kind > kWclMaximumKind || count > kWclMaximumEntries ||
                count > (length - kWclScanHeaderBytes) / kWclScanEntryBytes)
            {
                return false;
            }
            ScanFilter parsed {};
            memcpy(&parsed.identifier, bytes, sizeof(parsed.identifier));
            memcpy(&parsed.bssid[0U],
                   usbByteOffset(bytes, kWclFilterBssidOffset),
                   sizeof(parsed.bssid));
            memcpy(&parsed.ssid[0U], usbByteOffset(bytes, kWclFilterSsidOffset),
                   ssidLength);
            parsed.ssidLength = static_cast<uint8_t>(ssidLength);
            uint8_t addressBits = 0;
            uint8_t broadcastBits = kWclAllOnes;
            for (const auto byte : parsed.bssid)
            {
                addressBits |= byte;
                broadcastBits &= byte;
            }
            parsed.directedBssid =
                addressBits != 0 && broadcastBits != kWclAllOnes;
            if (parsed.directedBssid && (parsed.bssid[0] & 1U) != 0)
            {
                return false;
            }
            parsed.channels = count == 0 ? kWclAllChannels : 0;
            for (uint32_t i = 0; i < count; ++i)
            {
                uint32_t channel = 0;
                uint32_t flags = 0;
                const auto offset =
                    kWclScanHeaderBytes +
                    (static_cast<size_t>(i) * kWclScanEntryBytes);
                memcpy(&channel,
                       usbByteOffset(bytes, offset + kWclEntryChannelOffset),
                       sizeof(channel));
                memcpy(&flags,
                       usbByteOffset(bytes, offset + kWclEntryFlagsOffset),
                       sizeof(flags));
                // A 6 GHz channel number can overlap a 2.4 GHz number.
                // AR9565 is 2.4 GHz only; preserve native band identity.
                if (channel >= kWclChannelMinimum &&
                    channel <= kWclChannelMaximum &&
                    (flags & kWclChannel2GhzFlag) != 0 &&
                    (flags & (kWclChannel5GhzFlag | kWclChannel6GhzFlag)) == 0)
                {
                    parsed.channels |=
                        static_cast<uint16_t>(1U << (channel - 1U));
                }
            }
            if (parsed.channels == 0)
            {
                return false;
            }
            out = parsed;
            return true;
        }

        inline bool scanMatches(const ScanFilter &filter, const uint8_t *bssid,
                                const uint8_t *ssid, size_t ssidLength,
                                uint8_t channel)
        {
            if (bssid == nullptr || ssid == nullptr ||
                channel < kWclChannelMinimum || channel > kWclChannelMaximum ||
                ssidLength > kWclScanSsidBytes ||
                (filter.channels & (1U << (channel - 1U))) == 0)
            {
                return false;
            }
            return (!filter.directedBssid || memcmp(&filter.bssid[0U], bssid,
                                                    kWclScanBssidBytes) == 0) &&
                   (filter.ssidLength == 0 ||
                    (filter.ssidLength == ssidLength &&
                     memcmp(&filter.ssid[0U], ssid, ssidLength) == 0));
        }

        constexpr size_t kScanMessageBytes =
            kWclBssPrefixBytes + kWclBssSsidLengthBytes + kWclScanSsidBytes +
            kWclExtendedRatesHeaderBytes + kWclScanSsidBytes +
            kWclBssFixedTailBytes + kWclMaxRsnInformationElementBytes;

        template <typename T>
        inline void storeScan(uint8_t *bytes, size_t offset, T value)
        {
            memcpy(usbByteOffset(bytes, offset), &value, sizeof(value));
        }

        // Output must be independent of the copied BSS. Return zero without
        // modifying output on an invalid snapshot or insufficient capacity.
        inline size_t encodeScanBss(const ieee80211::NativeBssSnapshot &bss,
                                    uint8_t *message, size_t capacity)
        {
            if (message == nullptr || bss.ssidLength > sizeof(bss.ssid) ||
                bss.channel < kWclChannelMinimum ||
                bss.channel > kWclChannelMaximum ||
                bss.rateCount > sizeof(bss.rates) ||
                bss.rsnIeLength > sizeof(bss.rsnInformationElement))
            {
                return 0;
            }
            if (bss.rsnIeLength != 0 &&
                (bss.rsnIeLength < kWclRsnHeaderBytes ||
                 bss.rsnInformationElement[0U] != kWclRsnElement ||
                 static_cast<size_t>(bss.rsnInformationElement[1U]) +
                         kWclRsnHeaderBytes !=
                     bss.rsnIeLength))
            {
                return 0;
            }
            const size_t ratesLength =
                bss.rateCount == 0 ? 0
                                   : static_cast<size_t>(bss.rateCount) +
                                         (bss.rateCount > kWclRateElementMax
                                              ? kWclExtendedRatesHeaderBytes
                                              : kWclBasicRatesHeaderBytes);
            const size_t total = kWclBssPrefixBytes + kWclBssSsidLengthBytes +
                                 bss.ssidLength + ratesLength +
                                 kWclBssFixedTailBytes + bss.rsnIeLength;
            if (capacity < total ||
                scanRangesOverlap(message, total, &bss, sizeof(bss)))
            {
                return 0;
            }
            memset(message, 0, total);
            size_t cursor = kWclBssPrefixBytes;
            *usbByteOffset(message, cursor++) = 0;
            *usbByteOffset(message, cursor++) = bss.ssidLength;
            memcpy(usbByteOffset(message, cursor), &bss.ssid[0U],
                   bss.ssidLength);
            cursor += bss.ssidLength;
            if (bss.rateCount != 0)
            {
                const uint8_t initial = bss.rateCount > kWclRateElementMax
                                            ? kWclRateElementMax
                                            : bss.rateCount;
                *usbByteOffset(message, cursor++) = kWclSupportedRatesElement;
                *usbByteOffset(message, cursor++) = initial;
                memcpy(usbByteOffset(message, cursor), &bss.rates[0U], initial);
                cursor += initial;
                if (bss.rateCount > initial)
                {
                    *usbByteOffset(message, cursor++) =
                        kWclExtendedRatesElement;
                    *usbByteOffset(message, cursor++) =
                        static_cast<uint8_t>(bss.rateCount - initial);
                    memcpy(usbByteOffset(message, cursor),
                           usbByteOffset(&bss.rates[0U], initial),
                           bss.rateCount - initial);
                    cursor += bss.rateCount - initial;
                }
            }
            *usbByteOffset(message, cursor++) = kWclChannelElement;
            *usbByteOffset(message, cursor++) = kWclSupportedRatesElement;
            *usbByteOffset(message, cursor++) = bss.channel;
            memcpy(usbByteOffset(message, cursor),
                   &bss.rsnInformationElement[0U], bss.rsnIeLength);
            cursor += bss.rsnIeLength;
            storeScan<uint32_t>(
                message, 0, static_cast<uint32_t>(cursor - kWclBssPrefixBytes));
            storeScan<uint16_t>(
                message, 4,
                static_cast<uint16_t>(kWclChannelTag | bss.channel));
            memcpy(usbByteOffset(message, kWclBssSsidOffset), &bss.ssid[0U],
                   bss.ssidLength);
            *usbByteOffset(message, kWclBssSsidLengthOffset) = bss.ssidLength;
            *usbByteOffset(message, kWclBssChannelOffset) = bss.channel;
            memcpy(usbByteOffset(message, kWclBssBssidOffset),
                   &bss.bssid.bytes[0U], kWclScanBssidBytes);
            storeScan<int32_t>(message, kWclBssSignalOffset, bss.rssiDbm);
            storeScan<uint16_t>(message, kWclBssBeaconOffset,
                                bss.beaconIntervalTu);
            storeScan<uint16_t>(message, kWclBssCapabilitiesOffset,
                                bss.capabilities);
            storeScan<uint32_t>(
                message, kWclBssFlagsOffset,
                (bss.ssidLength != 0 ? kWclHasSsidBit : 0U) |
                    (bss.signalMeasured ? kWclSignalMeasuredBit : 0U));
            return cursor;
        }
    } // namespace tahoe
} // namespace simpleath
#endif
