// Offline Ethernet-II copy from an accepted 802.11 MSDU; no radio or OS I/O.
#include "wifi/DataFrames.hpp"
#include "wifi/Frames.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

int main()
{
    using simpleath::ieee80211::encodeReceivedEthernet;
    using simpleath::ieee80211::Msdu;
    using simpleath::ieee80211::Result;
    constexpr size_t kCapacity = 1518U;
    constexpr size_t kHeaderBytes = 14U;
    constexpr size_t kTypeHighOffset = 12U;
    constexpr size_t kTypeLowOffset = 13U;
    constexpr uint16_t kIpv4 = 0x0800U;
    constexpr uint16_t kInvalidType = 0x0500U;
    constexpr uint8_t kFirstPayloadByte = 0x45U;
    constexpr uint8_t kSecondPayloadByte = 0xa5U;
    constexpr uint8_t kIpv4TypeHighByte = 0x08U;
    constexpr uint8_t kEtherTypeLowByte = 0x00U;
    constexpr size_t kPayloadBytes = 2U;
    constexpr uint8_t kDestinationFirstByte = 0x24U;
    constexpr uint8_t kSourceFirstByte = 0x42U;
    constexpr size_t kSourceOffset = 6U;
    constexpr size_t kExpectedBytes = kHeaderBytes + kPayloadBytes;

    std::array<uint8_t, kPayloadBytes> payload {
        kFirstPayloadByte,
        kSecondPayloadByte,
    };
    std::array<uint8_t, kCapacity> ethernet {};
    Msdu msdu {};
    msdu.payload = payload.data();
    msdu.payloadLength = payload.size();
    msdu.etherType = kIpv4;
    msdu.destination.bytes[0] = kDestinationFirstByte;
    msdu.source.bytes[0] = kSourceFirstByte;
    size_t written = 0;
    if (encodeReceivedEthernet(msdu, ethernet.data(), ethernet.size(),
                               written) != Result::Ok ||
        written != kExpectedBytes ||
        ethernet.front() != kDestinationFirstByte ||
        ethernet.at(kSourceOffset) != kSourceFirstByte ||
        ethernet.at(kTypeHighOffset) != kIpv4TypeHighByte ||
        ethernet.at(kTypeLowOffset) != kEtherTypeLowByte ||
        ethernet.at(kHeaderBytes) != kFirstPayloadByte ||
        ethernet.at(kHeaderBytes + 1U) != kSecondPayloadByte)
    {
        return EXIT_FAILURE;
    }

    if (encodeReceivedEthernet(msdu, ethernet.data(), kHeaderBytes, written) !=
            Result::BufferTooSmall ||
        written != 0U || ethernet.at(kHeaderBytes) != kFirstPayloadByte)
    {
        return EXIT_FAILURE;
    }
    written = kExpectedBytes;
    if (encodeReceivedEthernet(msdu, payload.data(), payload.size(), written) !=
            Result::OverlappingBuffers ||
        written != kExpectedBytes || payload.front() != kFirstPayloadByte)
    {
        return EXIT_FAILURE;
    }
    msdu.etherType = kInvalidType;
    if (encodeReceivedEthernet(msdu, ethernet.data(), ethernet.size(),
                               written) != Result::InvalidFrame ||
        written != 0U)
    {
        return EXIT_FAILURE;
    }
    msdu.etherType = kIpv4;
    msdu.payloadLength = 0U;
    if (encodeReceivedEthernet(msdu, ethernet.data(), ethernet.size(),
                               written) != Result::Ok ||
        written != kHeaderBytes)
    {
        return EXIT_FAILURE;
    }
    msdu.payloadLength = payload.size();
    if (encodeReceivedEthernet(msdu, nullptr, 0U, written) !=
            Result::NullBuffer ||
        written != 0U)
    {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
