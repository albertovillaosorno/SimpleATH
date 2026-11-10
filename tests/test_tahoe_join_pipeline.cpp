// Integration fixture: one WCL join byte envelope crosses the portable WPA2
// supplicant selection boundary. No live radio, OS credentials or kext I/O.
#include "platform/tahoe/TahoeJoinCodec.hpp"
#include "wifi/Frames.hpp"
#include "wifi/Station.hpp"
#include "wifi/WifiEngine.hpp"
#include "wifi/crypto/Wpa2CryptoAdapter.hpp"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>

namespace
{
    using namespace simpleath;
    using namespace simpleath::ieee80211;
    using namespace simpleath::tahoe;

    constexpr size_t kBeaconPrefixBytes = 49U;
    constexpr size_t kJoinSsidOffset = 0x20U;
    constexpr size_t kJoinSsidLengthOffset = 0x1cU;
    constexpr size_t kJoinKeyLengthOffset = 0x44U;
    constexpr size_t kJoinKeyCipherOffset = 0x48U;
    constexpr size_t kJoinKeyOffset = 0x50U;
    constexpr size_t kJoinBssidOffset = 0x21cU;
    constexpr size_t kJoinChannelOffset = 0x228U;
    constexpr size_t kJoinLowerAuthOffset = 0x10U;
    constexpr size_t kJoinUpperAuthOffset = 0x14U;
    constexpr size_t kJoinCandidateCountOffset = 0x214U;
    constexpr size_t kBeaconCapOffset = 34U;
    constexpr size_t kBeaconSourceOffset = 10U;
    constexpr size_t kBeaconBssidOffset = 16U;
    constexpr size_t kBeaconSsidOffset = 38U;
    constexpr size_t kBeaconRatesOffset = 42U;
    constexpr size_t kBeaconSsidLength = 4U;
    constexpr size_t kBssidLength = 6U;
    constexpr size_t kTxCapacity = 256U;
    constexpr uint32_t kOpenAuth = 1U;
    constexpr uint32_t kPskAuth = 1U << 3U;
    constexpr uint32_t kPmkCipher = 6U;
    constexpr uint8_t kPmkFirstByte = 0xa5U;
    constexpr uint16_t kChannel6Spec = 0x1006U;
    constexpr uint8_t kChannel = 6U;
    constexpr int8_t kSignalDbm = -39;
    constexpr uint64_t kObservationTimeMs = 101U;
    constexpr uint16_t kAuthenticationSequence = 3U;
    constexpr size_t kAuthDestinationOffset = 4U;
    constexpr uint8_t kPrivacyCapability = 0x11U;
    constexpr uint8_t kRate1Mbps = 0x82U;
    constexpr uint8_t kRate2Mbps = 0x84U;
    constexpr uint8_t kSsidIe = 0U;
    constexpr uint8_t kRatesIe = 1U;
    constexpr uint8_t kDsIe = 3U;
    constexpr uint8_t kBeaconType = 0x80U;
    constexpr uint8_t kBssidMarker = 0x55U;
    constexpr uint8_t kBroadcastOctet = 0xffU;
    constexpr size_t kBeaconIntervalOffset = 32U;
    constexpr uint8_t kBeaconIntervalTu = 100U;
    constexpr size_t kBeaconSsidIeOffset = 36U;
    constexpr size_t kBeaconSsidLengthFieldOffset = 37U;
    constexpr size_t kBeaconChannelLengthOffset = 47U;
    constexpr size_t kBeaconChannelOffset = 48U;
    constexpr std::array<uint8_t, 22U> kRsnIe {
        {
            48,   20,   1, 0, 0, 0x0f, 0xac, 4,    1, 0, 0,
            0x0f, 0xac, 4, 1, 0, 0,    0x0f, 0xac, 2, 0, 0,
        },
    };
    constexpr std::array<uint8_t, kBssidLength> kAp {
        {0x02, 0x11, 0x22, 0x33, 0x44, kBssidMarker},
    };
    constexpr std::array<uint8_t, kBeaconSsidLength> kSsid {
        {'T', 'e', 's', 't'},
    };

    template <typename T>
    void writeJoin(std::array<uint8_t, kWclJoinRequestBytes> &wire,
                   size_t offset, T value)
    {
        std::memcpy(&wire.at(offset), &value, sizeof(value));
    }

    std::array<uint8_t, kWclJoinRequestBytes> joinBytes()
    {
        std::array<uint8_t, kWclJoinRequestBytes> join {};
        writeJoin<uint32_t>(join, kJoinLowerAuthOffset, kOpenAuth);
        writeJoin<uint32_t>(join, kJoinUpperAuthOffset, kPskAuth);
        writeJoin<uint32_t>(join, kJoinSsidLengthOffset, kSsid.size());
        std::copy(kSsid.begin(), kSsid.end(),
                  std::next(join.begin(), kJoinSsidOffset));
        writeJoin<uint32_t>(join, kJoinKeyLengthOffset, kWclPmkBytes);
        writeJoin<uint32_t>(join, kJoinKeyCipherOffset, kPmkCipher);
        join.at(kJoinKeyOffset) = kPmkFirstByte;
        std::copy(kAp.begin(), kAp.end(),
                  std::next(join.begin(), kJoinBssidOffset));
        writeJoin<uint32_t>(join, kJoinCandidateCountOffset, 1U);
        writeJoin<uint16_t>(join, kJoinChannelOffset, kChannel6Spec);
        return join;
    }

    std::array<uint8_t, kBeaconPrefixBytes + kRsnIe.size()> wpa2Beacon()
    {
        std::array<uint8_t, kBeaconPrefixBytes + kRsnIe.size()> frame {};
        frame.at(0) = kBeaconType;
        std::fill_n(std::next(frame.begin(), kAuthDestinationOffset),
                    kBssidLength, kBroadcastOctet);
        std::copy(kAp.begin(), kAp.end(),
                  std::next(frame.begin(), kBeaconSourceOffset));
        std::copy(kAp.begin(), kAp.end(),
                  std::next(frame.begin(), kBeaconBssidOffset));
        frame.at(kBeaconIntervalOffset) = kBeaconIntervalTu;
        frame.at(kBeaconCapOffset) = kPrivacyCapability;
        frame.at(kBeaconSsidIeOffset) = kSsidIe;
        frame.at(kBeaconSsidLengthFieldOffset) = kSsid.size();
        std::copy(kSsid.begin(), kSsid.end(),
                  std::next(frame.begin(), kBeaconSsidOffset));
        frame.at(kBeaconRatesOffset) = kRatesIe;
        frame.at(kBeaconRatesOffset + 1U) = 2U;
        frame.at(kBeaconRatesOffset + 2U) = kRate1Mbps;
        frame.at(kBeaconRatesOffset + 3U) = kRate2Mbps;
        frame.at(kBeaconRatesOffset + 4U) = kDsIe;
        frame.at(kBeaconChannelLengthOffset) = 1U;
        frame.at(kBeaconChannelOffset) = kChannel;
        std::copy(kRsnIe.begin(), kRsnIe.end(),
                  std::next(frame.begin(), kBeaconPrefixBytes));
        return frame;
    }

    void observeFakeCallback(void *context)
    {
        auto *counter = static_cast<uint32_t *>(context);
        ++*counter;
    }

    bool fakeRandom(void *context, uint8_t *output, size_t length)
    {
        observeFakeCallback(context);
        if (output != nullptr && length != 0)
        {
            std::memset(output, 0, length);
        }
        return false; // No entropy available in the offline fixture.
    }

    bool fakePairwise(void *context, const Mac &peer, const uint8_t *key)
    {
        observeFakeCallback(context);
        static_cast<void>(peer);
        static_cast<void>(key);
        return false;
    }

    // A public KeyHardware C callback has two adjacent wire-key pointers.
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    bool fakeGroup(void *context, uint8_t id, const uint8_t *key,
                   const uint8_t *rsc)
    {
        observeFakeCallback(context);
        static_cast<void>(id);
        static_cast<void>(key);
        static_cast<void>(rsc);
        return false;
    }

    void fakeRemove(void *context)
    {
        observeFakeCallback(context);
    }

    bool joinViaDriverSupplicant()
    {
        const auto request = joinBytes();
        auto beacon = wpa2Beacon();
        JoinSelection decoded {};
        WifiEngine engine;
        uint32_t context = 1;
        const crypto::KeyHardware hardware {
            &context, fakeRandom, fakePairwise, fakeGroup, fakeRemove,
        };
        const InputTrust trust {true, true, true, false};
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        Mac ap {};
        std::array<uint8_t, kTxCapacity> tx {};
        EngineAction action {};
        if (!decodeJoin(request.data(), request.size(), decoded) ||
            !decoded.wpa2Personal || !engine.configureKeys(hardware) ||
            engine.startScan(true, true) != EngineResult::Ok ||
            engine.acceptRx(beacon.data(), beacon.size(), trust,
                            {kSignalDbm, kObservationTimeMs}, tx.data(),
                            tx.size(), action) != EngineResult::Ok)
        {
            clearJoin(decoded);
            return false;
        }
        std::copy(std::begin(decoded.bssid), std::end(decoded.bssid),
                  std::begin(ap.bytes));
        const EngineResult selected = engine.chooseNetworkForDriverSupplicant(
            station, ap, &decoded.ssid[0], decoded.ssidLength, decoded.channel,
            &decoded.pmk[0]);
        clearJoin(decoded);
        if (selected != EngineResult::Ok || decoded.pmk[0] != 0 ||
            decoded.ssidLength != 0 || engine.osSupplicantOwnsWpa2() ||
            engine.stationState() != StationState::CandidateSelected ||
            engine.requestAuthentication(kAuthenticationSequence, tx.data(),
                                         tx.size(),
                                         action) != EngineResult::Ok ||
            action.kind != ActionKind::TransmitAuthentication ||
            action.nativeInterfaceUsable)
        {
            return false;
        }
        return std::equal(kAp.begin(), kAp.end(),
                          std::next(tx.begin(), kAuthDestinationOffset));
    }

    bool joinExactOpenWithConfiguredKeyBackend()
    {
        auto wire = joinBytes();
        writeJoin<uint32_t>(wire, kJoinUpperAuthOffset, 0U);
        writeJoin<uint32_t>(wire, kJoinKeyLengthOffset, 0U);
        writeJoin<uint32_t>(wire, kJoinKeyCipherOffset, 0U);
        JoinSelection join {};
        const auto wpa2 = wpa2Beacon();
        std::array<uint8_t, kBeaconPrefixBytes> open {};
        std::copy_n(wpa2.begin(), open.size(), open.begin());
        open.at(kBeaconCapOffset) = 1U; // Infrastructure, no privacy.
        WifiEngine engine;
        uint32_t callbacks = 1;
        const crypto::KeyHardware hardware {
            &callbacks, fakeRandom, fakePairwise, fakeGroup, fakeRemove,
        };
        const InputTrust trust {true, true, true, false};
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        Mac ap {};
        std::array<uint8_t, kTxCapacity> tx {};
        EngineAction action {};
        if (!decodeJoin(wire.data(), wire.size(), join) || join.wpa2Personal ||
            !engine.configureKeys(hardware) ||
            engine.startScan(true, true) != EngineResult::Ok ||
            engine.acceptRx(open.data(), open.size(), trust,
                            {kSignalDbm, kObservationTimeMs}, tx.data(),
                            tx.size(), action) != EngineResult::Ok)
        {
            clearJoin(join);
            return false;
        }
        std::copy(std::begin(join.bssid), std::end(join.bssid),
                  std::begin(ap.bytes));
        const auto selected = engine.chooseNetworkForDriverOpen(
            station, ap, &join.ssid[0], join.ssidLength, join.channel);
        clearJoin(join);
        if (selected != EngineResult::Ok || engine.osSupplicantOwnsWpa2() ||
            engine.requestAuthentication(kAuthenticationSequence, tx.data(),
                                         tx.size(),
                                         action) != EngineResult::Ok ||
            action.nativeInterfaceUsable)
        {
            return false;
        }
        return std::equal(kAp.begin(), kAp.end(),
                          std::next(tx.begin(), kAuthDestinationOffset));
    }
} // namespace

int main()
{
    return (joinViaDriverSupplicant() &&
            joinExactOpenWithConfiguredKeyBackend())
               ? 0
               : 1;
}
