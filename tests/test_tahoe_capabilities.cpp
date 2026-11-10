// Native card capability layout and station/security inventory, no RF I/O.
#include "platform/tahoe/TahoeCapabilities.hpp"
#include <array>
#include <cstdint>
#include <cstring>

namespace
{
    constexpr size_t kExpectedWireBytes = 28U;
    constexpr size_t kCompletionByte = 5U;
    constexpr size_t kBitmapWireOffset = 4U;
    constexpr size_t kGuardOffset = 1U;
    constexpr uint8_t kCcmpBitmap = 0x08U;
    constexpr uint8_t kStationBitmap = 0x46U;
    constexpr uint8_t kScanBitmap = 0x40U;
    constexpr uint8_t kGuardByte = 0xaaU;
    constexpr int kWireMismatchExit = 5;
} // namespace

int main()
{
    using namespace simpleath::tahoe;
    const auto record = ar9565Capabilities();
    if (record.version != 1 || sizeof(record) != kExpectedWireBytes)
    {
        return 1;
    }
    std::array<uint8_t, kNativeCapabilityBytes> expected {};
    expected.at(0) = kCcmpBitmap;
    expected.at(1) = kStationBitmap;
    expected.at(2) = kScanBitmap;
    expected.at(kCompletionByte) = kScanBitmap;
    // Later native bitmap bytes control 6GHz, HE, EHT, SAE and OWE. They
    // must contain actual zeroed output, never old kernel-buffer contents.
    size_t index = 0;
    for (const auto value : record.capabilities)
    {
        if (value != expected.at(index++))
        {
            return 2;
        }
    }
    for (const auto value : record.reserved)
    {
        if (value != 0U)
        {
            return 3;
        }
    }
    std::array<uint8_t, kExpectedWireBytes + 2U> envelope {};
    envelope.fill(kGuardByte);
    std::memcpy(&envelope.at(kGuardOffset), &record, sizeof(record));
    if (envelope.front() != kGuardByte || envelope.back() != kGuardByte ||
        envelope.at(kGuardOffset) != 1U)
    {
        return 4;
    }
    index = kGuardOffset + kBitmapWireOffset;
    for (const auto value : expected)
    {
        if (envelope.at(index++) != value)
        {
            return kWireMismatchExit;
        }
    }
    return 0;
}
