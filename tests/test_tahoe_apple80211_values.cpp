// Offline byte-layout regression for the SDK-independent Tahoe request values.
// Fixtures exercise the historical 802.11 fixed envelopes on x86_64 only;
// they are not an attestation of a live 25G332 KDK implementation.
#include "platform/tahoe/TahoeApple80211Values.hpp"
#include "platform/tahoe/TahoeCapabilities.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace
{
    using namespace simpleath::tahoe;

    template <typename T>
    bool matches(const T &value, const std::array<uint8_t, sizeof(T)> &expected)
    {
        std::array<uint8_t, sizeof(T)> actual {};
        std::memcpy(actual.data(), &value, sizeof(T));
        return actual == expected;
    }
} // namespace

int main()
{
    // Version request has a 16-bit length at byte 4, followed by the fixed
    // 256-byte version string at byte 6 (and an aligned two-byte tail).
    NativeApple80211Version version {};
    version.version = kApple80211Version;
    version.stringLength = 3U;
    version.string[0] = 'A';
    version.string[1] = 'T';
    version.string[2] = 'H';
    std::array<uint8_t, sizeof(version)> versionWire {};
    versionWire.at(0) = 1U;
    versionWire.at(4) = 3U;
    versionWire.at(6) = 'A';
    versionWire.at(7) = 'T';
    versionWire.at(8) = 'H';
    if (!matches(version, versionWire))
    {
        return 1;
    }

    NativeApple80211Power power {};
    power.version = kApple80211Version;
    power.numRadios = 1U;
    power.powerState[0] = kApple80211PowerOn;
    std::array<uint8_t, sizeof(power)> powerWire {};
    powerWire.at(0) = 1U;
    powerWire.at(4) = 1U;
    powerWire.at(8) = 1U;
    if (!matches(power, powerWire))
    {
        return 2;
    }

    NativeApple80211Channel channel {};
    channel.version = kApple80211Version;
    channel.channel.version = kApple80211Version;
    channel.channel.channel = 6U;
    channel.channel.flags = kApple80211Channel2Ghz | kApple80211Channel20Mhz;
    std::array<uint8_t, sizeof(channel)> channelWire {};
    channelWire.at(0) = 1U;
    channelWire.at(4) = 1U;
    channelWire.at(8) = 6U;
    channelWire.at(12) = 0x0aU;
    if (!matches(channel, channelWire))
    {
        return 3;
    }

    NativeApple80211Country country {};
    country.version = kApple80211Version;
    country.countryCode[0] = 'M';
    country.countryCode[1] = 'X';
    std::array<uint8_t, sizeof(country)> countryWire {};
    countryWire.at(0) = 1U;
    countryWire.at(4) = 'M';
    countryWire.at(5) = 'X';
    if (!matches(country, countryWire))
    {
        return 4;
    }

    NativeApple80211Rssi rssi {};
    rssi.version = kApple80211Version;
    rssi.numRadios = 1U;
    rssi.unit = kApple80211RssiDbm;
    rssi.radio[0] = -50;
    rssi.aggregate = -50;
    std::array<uint8_t, sizeof(rssi)> rssiWire {};
    rssiWire.at(0) = 1U;
    rssiWire.at(4) = 1U;
    constexpr size_t kRadioOffset = 12U;
    constexpr size_t kAggregateOffset = 28U;
    for (const auto offset : {kRadioOffset, kAggregateOffset})
    {
        rssiWire.at(offset + 0U) = 0xceU;
        rssiWire.at(offset + 1U) = 0xffU;
        rssiWire.at(offset + 2U) = 0xffU;
        rssiWire.at(offset + 3U) = 0xffU;
    }
    if (!matches(rssi, rssiWire))
    {
        return 5;
    }

    NativeApple80211StationMode mode {};
    mode.version = kApple80211Version;
    mode.mode = kApple80211StationMode;
    const std::array<uint8_t, sizeof(mode)> modeWire {
        {1U, 0U, 0U, 0U, 1U, 0U, 0U, 0U}};
    if (!matches(mode, modeWire))
    {
        return 6;
    }

    // Existing station inventory must occupy the same 8-byte WCL get
    // envelopes; this adapter does not change power save or NSS reports.
    if (sizeof(NativeApple80211Nss) != sizeof(NativeNssStatus) ||
        sizeof(NativeApple80211PowerSave) != sizeof(NativePowerSaveStatus))
    {
        return 7;
    }
    const auto nss = ar9565NssStatus();
    const auto save = ar9565PowerSaveStatus();
    NativeApple80211Nss nssWire {};
    NativeApple80211PowerSave saveWire {};
    std::memcpy(&nssWire, &nss, sizeof(nssWire));
    std::memcpy(&saveWire, &save, sizeof(saveWire));
    if (nssWire.version != kApple80211Version || nssWire.streams != 1U ||
        saveWire.version != kApple80211Version ||
        saveWire.level != kApple80211PowerSaveDisabled)
    {
        return 8;
    }
    return 0;
}
