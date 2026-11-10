#ifndef SIMPLEATH_TAHOE_SCAN_CODEC_HPP
#define SIMPLEATH_TAHOE_SCAN_CODEC_HPP
#include "../../wifi/LegacyScanBridge.hpp"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace simpleath
{
    namespace tahoe
    {
        // Exact modern WCL request offsets, separate from legacy SCAN_REQ.
        // All reads are bounded by the caller's fixed native request extent.
        struct ScanFilter
        {
                uint32_t identifier;
                uint16_t channels;
                uint8_t bssid[6];
                uint8_t ssid[32];
                uint8_t ssidLength;
                bool directedBssid;
        };

        inline bool decodeScan(const uint8_t *bytes, size_t length,
                               ScanFilter &out)
        {
            out = {};
            if (bytes == nullptr || length < 0x58)
            {
                return false;
            }
            uint32_t ssidLength = 0;
            uint32_t kind = 0;
            uint32_t count = 0;
            memcpy(&ssidLength, bytes + 0x1c, sizeof(ssidLength));
            memcpy(&kind, bytes + 0x40, sizeof(kind));
            memcpy(&count, bytes + 0x54, sizeof(count));
            if (ssidLength > sizeof(out.ssid) || kind < 1 || kind > 4 ||
                count > 400 || count > (length - 0x58) / 12)
            {
                return false;
            }
            ScanFilter parsed {};
            memcpy(&parsed.identifier, bytes, sizeof(parsed.identifier));
            memcpy(parsed.bssid, bytes + 0x14, sizeof(parsed.bssid));
            memcpy(parsed.ssid, bytes + 0x20, ssidLength);
            parsed.ssidLength = static_cast<uint8_t>(ssidLength);
            uint8_t addressBits = 0;
            uint8_t broadcastBits = 0xff;
            for (auto byte : parsed.bssid)
            {
                addressBits |= byte;
                broadcastBits &= byte;
            }
            parsed.directedBssid = addressBits != 0 && broadcastBits != 0xff;
            if (parsed.directedBssid && (parsed.bssid[0] & 1U) != 0)
            {
                return false;
            }
            parsed.channels = count == 0 ? 0x3fff : 0;
            for (uint32_t i = 0; i < count; ++i)
            {
                uint32_t channel = 0;
                uint32_t flags = 0;
                const auto offset = 0x58 + static_cast<size_t>(i) * 12;
                memcpy(&channel, bytes + offset + 4, sizeof(channel));
                memcpy(&flags, bytes + offset + 8, sizeof(flags));
                // A 6 GHz channel number can overlap a 2.4 GHz number.
                // AR9565 is 2.4 GHz only; preserve native band identity.
                if (channel >= 1 && channel <= 14 && (flags & 0x8U) != 0 &&
                    (flags & (0x10U | 0x2000U)) == 0)
                {
                    parsed.channels |=
                        static_cast<uint16_t>(1U << (channel - 1));
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
            if (bssid == nullptr || ssid == nullptr || channel < 1 ||
                channel > 14 || ssidLength > 32 ||
                (filter.channels & (1U << (channel - 1))) == 0)
            {
                return false;
            }
            return (!filter.directedBssid ||
                    memcmp(filter.bssid, bssid, 6) == 0) &&
                   (filter.ssidLength == 0 ||
                    (filter.ssidLength == ssidLength &&
                     memcmp(filter.ssid, ssid, ssidLength) == 0));
        }

        constexpr size_t kScanMessageBytes = 0x44 + 2 + 32 + 4 + 32 + 3 + 257;

        template <typename T>
        inline void storeScan(uint8_t *bytes, size_t offset, T value)
        {
            memcpy(bytes + offset, &value, sizeof(value));
        }

        // Output must be independent of the copied BSS. Return zero without
        // modifying output on an invalid snapshot or insufficient capacity.
        inline size_t encodeScanBss(const ieee80211::NativeBssSnapshot &bss,
                                    uint8_t *message, size_t capacity)
        {
            if (message == nullptr || bss.ssidLength > sizeof(bss.ssid) ||
                bss.channel < 1 || bss.channel > 14 ||
                bss.rateCount > sizeof(bss.rates) ||
                bss.rsnIeLength > sizeof(bss.rsnInformationElement))
            {
                return 0;
            }
            if (bss.rsnIeLength != 0 &&
                (bss.rsnIeLength < 2 || bss.rsnInformationElement[0] != 48 ||
                 static_cast<size_t>(bss.rsnInformationElement[1]) + 2 !=
                     bss.rsnIeLength))
            {
                return 0;
            }
            const size_t ratesLength =
                bss.rateCount == 0 ? 0
                                   : static_cast<size_t>(bss.rateCount) +
                                         (bss.rateCount > 8 ? 4 : 2);
            const size_t total =
                0x44 + 2 + bss.ssidLength + ratesLength + 3 + bss.rsnIeLength;
            if (capacity < total)
            {
                return 0;
            }
            memset(message, 0, total);
            size_t cursor = 0x44;
            message[cursor++] = 0;
            message[cursor++] = bss.ssidLength;
            memcpy(message + cursor, bss.ssid, bss.ssidLength);
            cursor += bss.ssidLength;
            if (bss.rateCount != 0)
            {
                const uint8_t initial = bss.rateCount > 8 ? 8 : bss.rateCount;
                message[cursor++] = 1;
                message[cursor++] = initial;
                memcpy(message + cursor, bss.rates, initial);
                cursor += initial;
                if (bss.rateCount > initial)
                {
                    message[cursor++] = 50;
                    message[cursor++] =
                        static_cast<uint8_t>(bss.rateCount - initial);
                    memcpy(message + cursor, bss.rates + initial,
                           bss.rateCount - initial);
                    cursor += bss.rateCount - initial;
                }
            }
            message[cursor++] = 3;
            message[cursor++] = 1;
            message[cursor++] = bss.channel;
            memcpy(message + cursor, bss.rsnInformationElement,
                   bss.rsnIeLength);
            cursor += bss.rsnIeLength;
            storeScan<uint32_t>(message, 0,
                                static_cast<uint32_t>(cursor - 0x44));
            storeScan<uint16_t>(message, 4,
                                static_cast<uint16_t>(0x1000U | bss.channel));
            memcpy(message + 6, bss.ssid, bss.ssidLength);
            message[0x26] = bss.ssidLength;
            message[0x27] = bss.channel;
            memcpy(message + 0x29, bss.bssid.bytes, 6);
            storeScan<int32_t>(message, 0x30, bss.rssiDbm);
            storeScan<uint16_t>(message, 0x38, bss.beaconIntervalTu);
            storeScan<uint16_t>(message, 0x3a, bss.capabilities);
            storeScan<uint32_t>(message, 0x40,
                                (bss.ssidLength != 0 ? 2U : 0U) |
                                    (bss.signalMeasured ? (1U << 14) : 0U));
            return cursor;
        }
    } // namespace tahoe
} // namespace simpleath
#endif
