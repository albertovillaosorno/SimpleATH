#include "bluetooth/UsbBytes.hpp"
#include "platform/tahoe/TahoeScanCodec.hpp"
#include "wifi/LegacyScanBridge.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace
{
    template <typename T, size_t N>
    void put(std::array<uint8_t, N> &bytes, size_t offset, T value)
    {
        memcpy(simpleath::usbByteOffset(bytes.data(), offset), &value,
               sizeof(value));
    }

    using namespace simpleath::tahoe;
    using simpleath::tahoe::decodeScan;
    using simpleath::tahoe::encodeScanBss;
    using simpleath::tahoe::ScanFilter;
    using simpleath::tahoe::scanMatches;

    constexpr size_t kRequestStorageBytes = 0x1550U;
    constexpr uint32_t kSyntheticScanIdentifier = 0x12345678U;
    constexpr uint32_t kObservedScanKind = 2U;
    constexpr uint32_t kAllowedChannel = 6U;
    constexpr uint32_t kExpectedTwoGhzFlags = 0x8U;
    constexpr uint32_t kInvalidSixGhzFlags = 0x2008U;
    constexpr uint32_t kInvalidFiveGhzFlags = 0x18U;
    constexpr uint32_t kTooManyChannelEntries = kWclMaximumEntries + 1U;
    constexpr uint8_t kSentinelByte = 0xa5U;
    constexpr uint8_t kRsnPayloadLengthMaximum = 255U;
    constexpr uint8_t kRsnPayloadLengthShort = 254U;
    constexpr int8_t kExampleRssiDbm = -50;
    constexpr uint16_t kExampleBeaconIntervalTu = 100U;
    constexpr size_t kScanHeaderSsidPayloadBytes =
        kWclBssSsidLengthBytes + kWclScanSsidBytes;
    constexpr size_t kFirstExtendedRateOffset = kScanHeaderSsidPayloadBytes +
                                                kWclBasicRatesHeaderBytes +
                                                kWclRateElementMax;
    constexpr uint8_t kChannelTagUpperByte = 0x10U;
    constexpr int kFailureUnexpectedBand = 5;
    constexpr int kFailureForeignBand = 6;
    constexpr int kFailureChannelCount = 7;
    constexpr int kFailureEncodedBss = 8;
    constexpr int kFailureTruncatedMessage = 9;
    constexpr int kFailureInvalidRsn = 10;
    constexpr int kFailureTooManyRates = 11;
    constexpr int kFailureAliasedEncoder = 12;
    constexpr int kFailurePartiallyAliasedEncoder = 13;
    constexpr int kFailureAliasedDecoder = 14;
} // namespace

int main()
{
    std::array<uint8_t, kRequestStorageBytes> request {};
    put<uint32_t>(request, 0, kSyntheticScanIdentifier);
    put<uint32_t>(request, kWclKindOffset, kObservedScanKind);
    ScanFilter filter {};
    if (!decodeScan(request.data(), request.size(), filter) ||
        filter.identifier != kSyntheticScanIdentifier ||
        filter.channels != kWclAllChannels)
    {
        return 1;
    }
    put<uint32_t>(request, kWclEntryCountOffset, 1U);
    put<uint32_t>(request, kWclScanHeaderBytes + kWclEntryChannelOffset,
                  kAllowedChannel);
    put<uint32_t>(request, kWclScanHeaderBytes + kWclEntryFlagsOffset,
                  kExpectedTwoGhzFlags);
    for (size_t length = 0; length < kWclScanHeaderBytes + kWclScanEntryBytes;
         ++length)
    {
        if (decodeScan(request.data(), length, filter))
        {
            return 2;
        }
    }
    if (!decodeScan(request.data(), request.size(), filter) ||
        filter.channels != (1U << (kAllowedChannel - 1U)))
    {
        return 3;
    }
    const std::array<uint8_t, kWclScanBssidBytes> bssid {{2, 3, 4, 5, 6, 7}};
    const std::array<uint8_t, 4> ssid {{'a', 0, 'b', 'c'}};
    memcpy(simpleath::usbByteOffset(request.data(), kWclFilterBssidOffset),
           bssid.data(), bssid.size());
    memcpy(simpleath::usbByteOffset(request.data(), kWclFilterSsidOffset),
           ssid.data(), ssid.size());
    put<uint32_t>(request, kWclSsidLengthOffset,
                  static_cast<uint32_t>(ssid.size()));
    if (!decodeScan(request.data(), request.size(), filter) ||
        !scanMatches(filter, bssid.data(), ssid.data(), ssid.size(),
                     kAllowedChannel) ||
        scanMatches(filter, bssid.data(), ssid.data(), ssid.size(), 1))
    {
        return 4;
    }
    put<uint32_t>(request, kWclScanHeaderBytes + kWclEntryFlagsOffset,
                  kInvalidSixGhzFlags);
    if (decodeScan(request.data(), request.size(), filter))
    {
        return kFailureUnexpectedBand;
    }
    put<uint32_t>(request, kWclScanHeaderBytes + kWclEntryFlagsOffset,
                  kInvalidFiveGhzFlags);
    if (decodeScan(request.data(), request.size(), filter))
    {
        return kFailureForeignBand;
    }
    put<uint32_t>(request, kWclScanHeaderBytes + kWclEntryFlagsOffset,
                  kExpectedTwoGhzFlags);
    put<uint32_t>(request, kWclEntryCountOffset, kTooManyChannelEntries);
    if (decodeScan(request.data(), request.size(), filter))
    {
        return kFailureChannelCount;
    }
    simpleath::ieee80211::NativeBssSnapshot bss {};
    bss.ssidLength = sizeof(bss.ssid);
    bss.channel = kAllowedChannel;
    bss.rateCount = sizeof(bss.rates);
    bss.rsnIeLength = sizeof(bss.rsnInformationElement);
    bss.rsnInformationElement[0U] = kWclRsnElement;
    bss.rsnInformationElement[1U] = kRsnPayloadLengthMaximum;
    bss.rssiDbm = kExampleRssiDbm;
    bss.signalMeasured = true;
    bss.beaconIntervalTu = kExampleBeaconIntervalTu;
    memcpy(&bss.bssid.bytes[0U], bssid.data(), bssid.size());
    std::array<uint8_t, kScanMessageBytes + 1U> message {};
    message.fill(kSentinelByte);
    const auto length = encodeScanBss(bss, message.data(), message.size() - 1);
    if (length != kScanMessageBytes || message.back() != kSentinelByte ||
        message.at(kWclBssSsidLengthOffset) != bss.ssidLength ||
        message.at(kWclBssChannelOffset) != bss.channel ||
        message.at(kWclEntryChannelOffset) != bss.channel ||
        message.at(kWclEntryChannelOffset + 1U) != kChannelTagUpperByte ||
        message.at(kWclBssPrefixBytes + kScanHeaderSsidPayloadBytes) !=
            kWclSupportedRatesElement ||
        message.at(kWclBssPrefixBytes + kFirstExtendedRateOffset) !=
            kWclExtendedRatesElement)
    {
        return kFailureEncodedBss;
    }
    message.fill(kSentinelByte);
    if (encodeScanBss(bss, message.data(), length - 1) != 0 ||
        message.front() != kSentinelByte)
    {
        return kFailureTruncatedMessage;
    }
    bss.rsnInformationElement[1U] = kRsnPayloadLengthShort;
    if (encodeScanBss(bss, message.data(), message.size()) != 0 ||
        message.front() != kSentinelByte)
    {
        return kFailureInvalidRsn;
    }
    bss.rsnInformationElement[1U] = kRsnPayloadLengthMaximum;
    bss.rateCount = sizeof(bss.rates) + 1U;
    if (encodeScanBss(bss, message.data(), message.size()) != 0)
    {
        return kFailureTooManyRates;
    }

    // A native output buffer aliasing the input snapshot must be rejected
    // *before* the encoder clears it. This covers complete and partial
    // overlap, not only an identical start address.
    bss = {};
    bss.channel = kAllowedChannel;
    bss.ssidLength = 1U;
    bss.ssid[0U] = 'x';
    std::array<uint8_t, sizeof(bss)> sourceBytes {};
    memcpy(sourceBytes.data(), &bss, sizeof(bss));
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *const aliased = reinterpret_cast<uint8_t *>(&bss);
    if (encodeScanBss(bss, aliased, sizeof(bss)) != 0)
    {
        return kFailureAliasedEncoder;
    }
    std::array<uint8_t, sizeof(bss)> afterBytes {};
    memcpy(afterBytes.data(), &bss, sizeof(bss));
    if (sourceBytes != afterBytes)
    {
        return kFailureAliasedEncoder;
    }
    const size_t partialOffset = offsetof(
        simpleath::ieee80211::NativeBssSnapshot, rsnInformationElement);
    if (encodeScanBss(bss, simpleath::usbByteOffset(aliased, partialOffset),
                      sizeof(bss) - partialOffset) != 0)
    {
        return kFailurePartiallyAliasedEncoder;
    }
    memcpy(afterBytes.data(), &bss, sizeof(bss));
    if (sourceBytes != afterBytes)
    {
        return kFailurePartiallyAliasedEncoder;
    }

    // A shared request/output owner must not erase its own request bytes
    // while parsing. The supplied extent is backed by this full fixture.
    struct AliasedScanRequest
    {
            ScanFilter result;
            uint8_t trailing[kWclScanHeaderBytes];
    } aliasedRequest {};

    aliasedRequest.result.identifier = kSyntheticScanIdentifier;
    std::array<uint8_t, sizeof(aliasedRequest)> requestCopy {};
    memcpy(requestCopy.data(), &aliasedRequest, sizeof(aliasedRequest));
    const auto *const requestBytes =
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        reinterpret_cast<const uint8_t *>(&aliasedRequest);
    if (decodeScan(requestBytes, sizeof(aliasedRequest), aliasedRequest.result))
    {
        return kFailureAliasedDecoder;
    }
    std::array<uint8_t, sizeof(aliasedRequest)> afterRequest {};
    memcpy(afterRequest.data(), &aliasedRequest, sizeof(aliasedRequest));
    if (requestCopy != afterRequest)
    {
        return kFailureAliasedDecoder;
    }
    return 0;
}
