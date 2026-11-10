// Offline native join lifecycle and wire-envelope regression fixtures.
#include "platform/tahoe/TahoeJoinEvents.hpp"
#include "platform/tahoe/TahoeJoinSession.hpp"
#include <algorithm>
#include <array>
#include <cstring>

namespace
{
    using namespace simpleath::tahoe;
    constexpr std::array<uint8_t, 6> kAp {{2, 0, 0, 0, 0, 7}};

    JoinObservation associated()
    {
        JoinObservation state {};
        state.epoch = 41;
        state.requestId = 9;
        state.associationGeneration = 3;
        std::memcpy(state.bssid, kAp.data(), kAp.size());
        state.phase = NativeJoinPhase::Handshaking;
        state.associated = true;
        return state;
    }

    bool genuineWpa2Progress()
    {
        JoinSession join;
        if (!join.begin(41, 9, kAp.data(), true) ||
            join.begin(41, 10, kAp.data(), true))
        {
            return false;
        }
        auto state = associated();
        state.associated = false;
        state.phase = NativeJoinPhase::Authenticating;
        if (join.observe(state) != NoJoinNotice || !join.pending())
        {
            return false;
        }
        state = associated();
        if (join.observe(state) != AssociationNotice ||
            join.observe(state) != NoJoinNotice || !join.pending())
        {
            return false;
        }
        state.phase = NativeJoinPhase::Ready;
        state.controlledPortOpen = true;
        // A real key installation still cannot invent the first beacon.
        if (join.observe(state) != SupplicantNotice || !join.pending() ||
            join.observe(state) != NoJoinNotice)
        {
            return false;
        }
        state.beaconObserved = true;
        if (join.observe(state) != (BeaconNotice | ConnectionNotice) ||
            join.pending() || join.observe(state) != NoJoinNotice)
        {
            return false;
        }
        state.associated = false;
        return join.observe(state) == DisconnectionNotice && !join.active();
    }

    bool sameLifetimeOnly()
    {
        const auto reject = [](JoinObservation state)
        {
            JoinSession join;
            return join.begin(41, 9, kAp.data(), true) &&
                   join.observe(state) == FailureNotice && !join.active();
        };
        auto state = associated();
        state.epoch = 42;
        if (!reject(state))
            return false;
        state = associated();
        state.requestId = 8;
        if (!reject(state))
            return false;
        state = associated();
        state.associationGeneration = 0;
        if (!reject(state))
            return false;
        state = associated();
        state.bssid[5] = 8;
        if (!reject(state))
            return false;
        JoinSession join;
        state = associated();
        if (!join.begin(41, 9, kAp.data(), true) ||
            join.observe(state) != AssociationNotice)
        {
            return false;
        }
        ++state.associationGeneration;
        return join.observe(state) == FailureNotice;
    }

    bool openAndFailure()
    {
        JoinSession join;
        auto state = associated();
        if (!join.begin(41, 9, kAp.data(), false))
            return false;
        state.beaconObserved = true;
        if (join.observe(state) != (AssociationNotice | BeaconNotice) ||
            !join.pending())
        {
            return false;
        }
        state.phase = NativeJoinPhase::Ready;
        if (join.observe(state) != NoJoinNotice || !join.pending())
        {
            return false;
        }
        state.controlledPortOpen = true;
        if (join.observe(state) != ConnectionNotice)
            return false;
        join.reset();
        if (!join.begin(41, 10, kAp.data(), true))
            return false;
        state.requestId = 10;
        state.phase = NativeJoinPhase::Failed;
        state.status = -1;
        return join.observe(state) == FailureNotice &&
               join.observe(state) == NoJoinNotice &&
               join.lose() == NoJoinNotice;
    }

    template <typename T> T field(const uint8_t *bytes, size_t offset)
    {
        T result {};
        std::memcpy(&result, bytes + offset, sizeof(result));
        return result;
    }

    bool wireContracts()
    {
        std::array<uint8_t, kWclConnectionEventBytes + 1> output {};
        output.back() = 0x55;
        if (encodeJoinEvent(kWclAssociationEvent, kAp.data(), 0, 0, true,
                            output.data(), output.size()) != 0x1c ||
            field<uint16_t>(output.data(), 0) != 0 ||
            std::memcmp(output.data() + 5, kAp.data(), 6) != 0 ||
            field<int32_t>(output.data(), 20) != 0)
        {
            return false;
        }
        if (encodeJoinEvent(kWclConnectionEvent, kAp.data(), -7, 13, false,
                            output.data(), output.size()) != 0xa4 ||
            field<uint16_t>(output.data(), 0) != 1 ||
            field<uint16_t>(output.data(), 2) != 13 ||
            std::memcmp(output.data() + 4, kAp.data(), 6) != 0 ||
            field<int32_t>(output.data(), 12) != -7 || output.back() != 0x55)
        {
            return false;
        }
        if (encodeJoinEvent(kWclFirstBeaconEvent, kAp.data(), 0, 0, true,
                            output.data(), output.size()) != 0x14 ||
            std::memcmp(output.data() + 4, kAp.data(), 6) != 0 ||
            encodeJoinEvent(kWclSupplicantEvent, kAp.data(), 0, 0, true,
                            output.data(), output.size()) != 0x28 ||
            field<uint32_t>(output.data(), 0) != 1 ||
            field<int32_t>(output.data(), 8) != 0)
        {
            return false;
        }
        if (encodeJoinEvent(kWclLinkEvent, kAp.data(), 0, 0, true,
                            output.data(), output.size()) != 0x10 ||
            output[6] != 1 || std::memcmp(output.data(), kAp.data(), 6) != 0)
        {
            return false;
        }
        const auto before = output;
        return encodeJoinEvent(kWclConnectionEvent, kAp.data(), 0, 0, true,
                               output.data(), 0xa3) == 0 &&
               output == before &&
               encodeJoinEvent(0, kAp.data(), 0, 0, true, output.data(),
                               output.size()) == 0 &&
               encodeJoinEvent(kWclLinkEvent, nullptr, 0, 0, true,
                               output.data(), output.size()) == 0;
    }
} // namespace

int main()
{
    if (!genuineWpa2Progress())
        return 1;
    if (!sameLifetimeOnly())
        return 2;
    if (!openAndFailure())
        return 3;
    if (!wireContracts())
        return 4;
    return 0;
}
