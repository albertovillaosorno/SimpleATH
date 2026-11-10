#include "platform/tahoe/TahoeScanCodec.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace
{
    template <typename T, size_t N>
    void put(std::array<uint8_t, N> &bytes, size_t offset, T value)
    {
        memcpy(bytes.data() + offset, &value, sizeof(value));
    }

    using simpleath::tahoe::decodeScan;
    using simpleath::tahoe::encodeScanBss;
    using simpleath::tahoe::ScanFilter;
    using simpleath::tahoe::scanMatches;
} // namespace

int main()
{
    std::array<uint8_t, 0x1550> request {};
    put<uint32_t>(request, 0, 0x12345678);
    put<uint32_t>(request, 0x40, 2);
    ScanFilter filter {};
    if (!decodeScan(request.data(), request.size(), filter) ||
        filter.identifier != 0x12345678 || filter.channels != 0x3fff)
    {
        return 1;
    }
    put<uint32_t>(request, 0x54, 1);
    put<uint32_t>(request, 0x5c, 6);
    put<uint32_t>(request, 0x60, 8);
    for (size_t length = 0; length < 0x64; ++length)
    {
        if (decodeScan(request.data(), length, filter))
        {
            return 2;
        }
    }
    if (!decodeScan(request.data(), request.size(), filter) ||
        filter.channels != (1U << 5))
    {
        return 3;
    }
    const std::array<uint8_t, 6> bssid {{2, 3, 4, 5, 6, 7}};
    const std::array<uint8_t, 4> ssid {{'a', 0, 'b', 'c'}};
    memcpy(request.data() + 0x14, bssid.data(), bssid.size());
    memcpy(request.data() + 0x20, ssid.data(), ssid.size());
    put<uint32_t>(request, 0x1c, static_cast<uint32_t>(ssid.size()));
    if (!decodeScan(request.data(), request.size(), filter) ||
        !scanMatches(filter, bssid.data(), ssid.data(), ssid.size(), 6) ||
        scanMatches(filter, bssid.data(), ssid.data(), ssid.size(), 1))
    {
        return 4;
    }
    put<uint32_t>(request, 0x60, 0x2008);
    if (decodeScan(request.data(), request.size(), filter))
    {
        return 5;
    }
    put<uint32_t>(request, 0x60, 0x18);
    if (decodeScan(request.data(), request.size(), filter))
    {
        return 6;
    }
    put<uint32_t>(request, 0x60, 8);
    put<uint32_t>(request, 0x54, 401);
    if (decodeScan(request.data(), request.size(), filter))
    {
        return 7;
    }
    simpleath::ieee80211::NativeBssSnapshot bss {};
    bss.ssidLength = 32;
    bss.channel = 6;
    bss.rateCount = 32;
    bss.rsnIeLength = 257;
    bss.rsnInformationElement[0] = 48;
    bss.rsnInformationElement[1] = 255;
    bss.rssiDbm = -50;
    bss.signalMeasured = true;
    bss.beaconIntervalTu = 100;
    memcpy(bss.bssid.bytes, bssid.data(), bssid.size());
    std::array<uint8_t, simpleath::tahoe::kScanMessageBytes + 1> message {};
    message.fill(0xa5);
    const auto length = encodeScanBss(bss, message.data(), message.size() - 1);
    if (length != simpleath::tahoe::kScanMessageBytes ||
        message.back() != 0xa5 || message.at(0x26) != 32 ||
        message.at(0x27) != 6 || message.at(4) != 6 || message.at(5) != 0x10 ||
        message.at(0x44 + 34) != 1 || message.at(0x44 + 34 + 10) != 50)
    {
        return 8;
    }
    message.fill(0xa5);
    if (encodeScanBss(bss, message.data(), length - 1) != 0 ||
        message.front() != 0xa5)
    {
        return 9;
    }
    bss.rsnInformationElement[1] = 254;
    if (encodeScanBss(bss, message.data(), message.size()) != 0 ||
        message.front() != 0xa5)
    {
        return 10;
    }
    bss.rsnInformationElement[1] = 255;
    bss.rateCount = 33;
    if (encodeScanBss(bss, message.data(), message.size()) != 0)
    {
        return 11;
    }
    return 0;
}
