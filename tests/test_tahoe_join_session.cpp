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
//   - Offline regression cases for tahoe join session.
// - Must-Not:
//   - Require physical hardware, mutate installed drivers, or suppress
//     failures.
// - Allows:
//   - Inputs: isolated fixtures and reproducible source-under-test inputs.
//   - Outputs: assertions and observable regression verdicts.
//   - Side effects: test-local temporary files and bounded subprocesses only.
// - Split-When:
//   - A separate protocol stage needs independent validation and ownership.
// - Merge-When:
//   - The caller directly owns this narrow contract without reuse.
// - Summary:
//   - Offline regression cases for tahoe join session.
// - Description:
//   - Implements or verifies the test_tahoe_join_session source boundary.
// - Usage:
//   - Executed by offline host test discovery or the native test harness.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Offline regression cases for tahoe join session.

// Offline native join lifecycle and wire-envelope regression fixtures.
#include "bluetooth/UsbBytes.hpp"
#include "platform/tahoe/TahoeJoinEvents.hpp"
#include "platform/tahoe/TahoeJoinSession.hpp"
#include <array>
#include <cstdint>
#include <cstring>

namespace
{
    using namespace simpleath::tahoe;
    constexpr uint64_t kObservedEpoch = 41U;
    constexpr uint64_t kWrongEpoch = 42U;
    constexpr uint64_t kFirstRequestId = 9U;
    constexpr uint64_t kSecondRequestId = 10U;
    constexpr uint64_t kStaleRequestId = 8U;
    constexpr uint8_t kCorruptedBssidOctet = 8U;
    constexpr uint8_t kSentinelByte = 0x55U;
    constexpr JoinEventOutcome kRejectedOutcome {-7, 13U};
    constexpr std::array<uint8_t, kWclMacAddressBytes> kAp {{2, 0, 0, 0, 0, 7}};

    JoinObservation associated()
    {
        JoinObservation state {};
        state.epoch = kObservedEpoch;
        state.requestId = kFirstRequestId;
        state.associationGeneration = 3;
        std::memcpy(&state.bssid[0U], kAp.data(), kAp.size());
        state.phase = NativeJoinPhase::Handshaking;
        state.associated = true;
        return state;
    }

    bool genuineWpa2Progress()
    {
        JoinSession join;
        if (!join.begin(kObservedEpoch, kFirstRequestId, kAp.data(), true) ||
            join.begin(kObservedEpoch, kSecondRequestId, kAp.data(), true))
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
            return join.begin(kObservedEpoch, kFirstRequestId, kAp.data(),
                              true) &&
                   join.observe(state) == FailureNotice && !join.active();
        };
        auto state = associated();
        state.epoch = kWrongEpoch;
        if (!reject(state))
        {
            return false;
        }
        state = associated();
        state.requestId = kStaleRequestId;
        if (!reject(state))
        {
            return false;
        }
        state = associated();
        state.associationGeneration = 0;
        if (!reject(state))
        {
            return false;
        }
        state = associated();
        state.bssid[kWclMacAddressBytes - 1U] = kCorruptedBssidOctet;
        if (!reject(state))
        {
            return false;
        }
        JoinSession join;
        state = associated();
        if (!join.begin(kObservedEpoch, kFirstRequestId, kAp.data(), true) ||
            join.observe(state) != AssociationNotice)
        {
            return false;
        }
        ++state.associationGeneration;
        return join.observe(state) == FailureNotice;
    }

    bool failedStatusCannotAdvance()
    {
        // A source adapter can report failure before it updates its phase.
        // Do not announce Association/Beacon/Connection from a stale Ready
        // snapshot whose result explicitly failed.
        JoinSession pending;
        auto state = associated();
        state.phase = NativeJoinPhase::Ready;
        state.beaconObserved = true;
        state.controlledPortOpen = true;
        state.status = -7;
        if (!pending.begin(kObservedEpoch, kFirstRequestId, kAp.data(), true) ||
            pending.observe(state) != FailureNotice || pending.active() ||
            pending.observe(state) != NoJoinNotice)
        {
            return false;
        }
        JoinSession connected;
        state.status = 0;
        if (!connected.begin(kObservedEpoch, kFirstRequestId, kAp.data(),
                             true) ||
            connected.observe(state) != (AssociationNotice | BeaconNotice |
                                         SupplicantNotice | ConnectionNotice))
        {
            return false;
        }
        state.status = -7;
        return connected.observe(state) == DisconnectionNotice &&
               !connected.active() && connected.observe(state) == NoJoinNotice;
    }

    bool openAndFailure()
    {
        JoinSession join;
        auto state = associated();
        if (!join.begin(kObservedEpoch, kFirstRequestId, kAp.data(), false))
        {
            return false;
        }
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
        {
            return false;
        }
        join.reset();
        if (!join.begin(kObservedEpoch, kSecondRequestId, kAp.data(), true))
        {
            return false;
        }
        state.requestId = kSecondRequestId;
        state.phase = NativeJoinPhase::Failed;
        state.status = -1;
        return join.observe(state) == FailureNotice &&
               join.observe(state) == NoJoinNotice &&
               join.lose() == NoJoinNotice;
    }

    template <typename T> T field(const uint8_t *bytes, size_t offset)
    {
        T result {};
        std::memcpy(&result, simpleath::usbByteOffset(bytes, offset),
                    sizeof(result));
        return result;
    }

    bool wireContracts()
    {
        std::array<uint8_t, kWclConnectionEventBytes + 1> output {};
        output.back() = kSentinelByte;
        if (encodeJoinEvent(kWclAssociationEvent, kAp.data(), {0, 0}, true,
                            output.data(),
                            output.size()) != kWclAssociationEventBytes ||
            field<uint16_t>(output.data(), 0) != 0 ||
            std::memcmp(&output.at(kWclAssociationBssidOffset), kAp.data(),
                        kAp.size()) != 0 ||
            field<int32_t>(output.data(), kWclAssociationStatusOffset) != 0)
        {
            return false;
        }
        if (encodeJoinEvent(kWclConnectionEvent, kAp.data(), kRejectedOutcome,
                            false, output.data(),
                            output.size()) != kWclConnectionEventBytes ||
            field<uint16_t>(output.data(), 0) != 1 ||
            field<uint16_t>(output.data(), 2) != kRejectedOutcome.reason ||
            std::memcmp(&output.at(kWclCommonBssidOffset), kAp.data(),
                        kAp.size()) != 0 ||
            field<int32_t>(output.data(), kWclCommonStatusOffset) !=
                kRejectedOutcome.driverStatus ||
            output.back() != kSentinelByte)
        {
            return false;
        }
        if (encodeJoinEvent(kWclFirstBeaconEvent, kAp.data(), {0, 0}, true,
                            output.data(),
                            output.size()) != kWclBeaconEventBytes ||
            std::memcmp(&output.at(kWclCommonBssidOffset), kAp.data(),
                        kAp.size()) != 0 ||
            encodeJoinEvent(kWclSupplicantEvent, kAp.data(), {0, 0}, true,
                            output.data(),
                            output.size()) != kWclSupplicantEventBytes ||
            field<uint32_t>(output.data(), 0) != 1 ||
            field<int32_t>(output.data(), kWclStatusOffset) != 0)
        {
            return false;
        }
        if (encodeJoinEvent(kWclLinkEvent, kAp.data(), {0, 0}, true,
                            output.data(),
                            output.size()) != kWclLinkEventBytes ||
            output.at(kWclLinkStateOffset) != 1 ||
            std::memcmp(output.data(), kAp.data(), kAp.size()) != 0)
        {
            return false;
        }
        const auto before = output;
        return encodeJoinEvent(kWclConnectionEvent, kAp.data(), {0, 0}, true,
                               output.data(),
                               kWclConnectionEventBytes - 1U) == 0 &&
               output == before &&
               encodeJoinEvent(0, kAp.data(), {0, 0}, true, output.data(),
                               output.size()) == 0 &&
               encodeJoinEvent(kWclLinkEvent, nullptr, {0, 0}, true,
                               output.data(), output.size()) == 0;
    }
} // namespace

int main()
{
    if (!genuineWpa2Progress())
    {
        return 1;
    }
    if (!sameLifetimeOnly())
    {
        return 2;
    }
    if (!openAndFailure())
    {
        return 3;
    }
    if (!wireContracts())
    {
        return 4;
    }
    if (!failedStatusCannotAdvance())
    {
        return 5;
    }
    return 0;
}
