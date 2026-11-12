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
//   - Offline regression cases for native wireless epoch.
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
//   - Offline regression cases for native wireless epoch.
// - Description:
//   - Implements or verifies the test_native_wireless_epoch source boundary.
// - Usage:
//   - Executed by offline host test discovery or the native test harness.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Offline regression cases for native wireless epoch.

// Portable host checks for the actual Tahoe native Ethernet callback gate.
#include "platform/NativeLinkRetirement.hpp"
#include "platform/tahoe/NativeWirelessEpoch.hpp"
#include <stdint.h>

namespace
{
    struct FakeLinkHardware
    {
            bool queueCanIsolate = true;
            bool pendingTransmit = false;
            bool keyEraseSucceeds = true;
            bool queueIsolated = false;
            int queueCalls = 0;
            int eraseCalls = 0;
    };

    bool isolateQueue(void *context, uint64_t epoch)
    {
        auto &fake = *static_cast<FakeLinkHardware *>(context);
        if (epoch == 0)
        {
            return false;
        }
        ++fake.queueCalls;
        fake.queueIsolated = fake.queueCanIsolate;
        return fake.queueIsolated && !fake.pendingTransmit;
    }

    bool eraseHardwareKeys(void *context, uint64_t epoch)
    {
        auto &fake = *static_cast<FakeLinkHardware *>(context);
        if (epoch == 0 || !fake.queueIsolated)
        {
            return false;
        }
        ++fake.eraseCalls;
        return fake.keyEraseSucceeds;
    }

    struct FakeWirelessEvent
    {
            simpleath::tahoe::WirelessEvent event {};
            uint64_t epoch {};
            uint64_t generation {};
    };

    bool checkCriticalWirelessEventRetention()
    {
        using simpleath::tahoe::evictWirelessNoncriticalEvent;
        using simpleath::tahoe::WirelessEvent;
        // Logical order wraps at index two: completion, TX wakeup,
        // association update, completion. A new completion displaces the
        // oldest noncritical event without reordering either completion.
        FakeWirelessEvent wrapped[4] {};
        wrapped[2] = {WirelessEvent::ScanFinished, 41U, 101U};
        wrapped[3] = {WirelessEvent::TransmitAvailable, 41U, 0U};
        wrapped[0] = {WirelessEvent::AssociationChanged, 42U, 0U};
        wrapped[1] = {WirelessEvent::ScanFinished, 42U, 102U};
        if (!evictWirelessNoncriticalEvent(wrapped, 2U, 4U))
        {
            return false;
        }
        wrapped[1] = {WirelessEvent::ScanFinished, 43U, 103U};
        if (wrapped[2].event != WirelessEvent::ScanFinished ||
            wrapped[2].epoch != 41U || wrapped[2].generation != 101U ||
            wrapped[3].event != WirelessEvent::AssociationChanged ||
            wrapped[3].epoch != 42U || wrapped[3].generation != 0U ||
            wrapped[0].event != WirelessEvent::ScanFinished ||
            wrapped[0].epoch != 42U || wrapped[0].generation != 102U ||
            wrapped[1].event != WirelessEvent::ScanFinished ||
            wrapped[1].epoch != 43U || wrapped[1].generation != 103U)
        {
            return false;
        }
        // A saturated mailbox containing only non-discardable completion
        // intents must reject a new event, not erase a pending SCAN_DONE.
        FakeWirelessEvent completions[2] {
            {WirelessEvent::ScanFinished, 50U, 104U},
            {WirelessEvent::ProviderStopped, 50U, 0U},
        };
        if (evictWirelessNoncriticalEvent(completions, 0U, 2U) ||
            evictWirelessNoncriticalEvent(completions, 1U, 1U) ||
            evictWirelessNoncriticalEvent(completions, 2U, 2U) ||
            completions[0].epoch != 50U || completions[1].epoch != 50U)
        {
            return false;
        }
        // Stale terminal notifications can fill a bounded ring after
        // repeated cancelled requests. A newer scan may
        // displace an earlier generation, but not a duplicate of itself.
        // Wrap the logical queue across the physical array boundary.
        FakeWirelessEvent stale[4] {};
        stale[2] = {WirelessEvent::ScanFinished, 51U, 31U};
        stale[3] = {WirelessEvent::ScanFinished, 51U, 32U};
        stale[0] = {WirelessEvent::ScanFinished, 51U, 33U};
        stale[1] = {WirelessEvent::ScanFinished, 51U, 34U};
        using simpleath::tahoe::evictWirelessSupersededScanEvent;
        if (!evictWirelessSupersededScanEvent(stale, 2U, 4U, 51U, 35U))
        {
            return false;
        }
        stale[1] = {WirelessEvent::ScanFinished, 51U, 35U};
        if (stale[2].generation != 32U || stale[3].generation != 33U ||
            stale[0].generation != 34U || stale[1].generation != 35U ||
            evictWirelessSupersededScanEvent(stale, 0U, 3U, 51U, 36U) ||
            evictWirelessSupersededScanEvent(stale, 4U, 4U, 51U, 36U) ||
            evictWirelessSupersededScanEvent(stale, 2U, 4U, 0U, 36U) ||
            evictWirelessSupersededScanEvent(stale, 2U, 4U, 51U, 0U))
        {
            return false;
        }
        FakeWirelessEvent duplicates[2] {
            {WirelessEvent::ScanFinished, 52U, 36U},
            {WirelessEvent::ScanFinished, 52U, 36U},
        };
        if (evictWirelessSupersededScanEvent(duplicates, 0U, 2U, 52U, 36U) ||
            duplicates[0].generation != 36U || duplicates[1].generation != 36U)
        {
            return false;
        }
        // A late notification for an older generation must not evict a
        // newer completion simply because the generation fields differ.
        FakeWirelessEvent newer[2] {
            {WirelessEvent::ScanFinished, 52U, 40U},
            {WirelessEvent::ScanFinished, 52U, 41U},
        };
        if (evictWirelessSupersededScanEvent(newer, 0U, 2U, 52U, 39U) ||
            newer[0].generation != 40U || newer[1].generation != 41U)
        {
            return false;
        }
        FakeWirelessEvent stopped[2] {
            {WirelessEvent::ProviderStopped, 52U, 0U},
            {WirelessEvent::ScanFinished, 52U, 37U},
        };
        if (!evictWirelessSupersededScanEvent(stopped, 0U, 2U, 52U, 38U) ||
            stopped[0].event != WirelessEvent::ProviderStopped ||
            stopped[1].generation != 0U)
        {
            return false;
        }
        FakeWirelessEvent regular[2] {
            {WirelessEvent::RadioChanged, 1U},
            {WirelessEvent::TransmitAvailable, 2U},
        };
        if (!evictWirelessNoncriticalEvent(regular, 0U, 2U) ||
            regular[0].epoch != 2U || regular[1].epoch != 0U)
        {
            return false;
        }
        return true;
    }

    bool checkNativeLinkRetirement()
    {
        using simpleath::NativeLinkRetirementBackend;
        using simpleath::retireNativeLinkHardware;
        FakeLinkHardware fake {};
        NativeLinkRetirementBackend backend {
            &fake,
            isolateQueue,
            eraseHardwareKeys,
        };
        constexpr uint64_t kOwnerEpoch = 42U;
        // Physical quiescence precedes any wipe. Even successful erasure
        // permanently forbids reusing this queue in the former PCI epoch.
        auto result = retireNativeLinkHardware(backend, kOwnerEpoch,
                                               kOwnerEpoch, true, kOwnerEpoch);
        if (!result.queueIsolated || !result.hardwareKeysErased ||
            !result.requiresNewPhysicalEpoch || fake.queueCalls != 1 ||
            fake.eraseCalls != 1)
        {
            return false;
        }
        fake = {};
        fake.keyEraseSucceeds = false;
        result = retireNativeLinkHardware(backend, kOwnerEpoch, kOwnerEpoch,
                                          true, kOwnerEpoch);
        if (!result.queueIsolated || result.hardwareKeysErased ||
            !result.requiresNewPhysicalEpoch || fake.queueCalls != 1 ||
            fake.eraseCalls != 1)
        {
            return false;
        }
        // A queue with an outstanding device-owned transmit descriptor or
        // failed MAC/bus isolation must never receive a keycache wipe.
        fake = {};
        fake.queueCanIsolate = false;
        result = retireNativeLinkHardware(backend, kOwnerEpoch, kOwnerEpoch,
                                          true, kOwnerEpoch);
        if (result.queueIsolated || result.hardwareKeysErased ||
            !result.requiresNewPhysicalEpoch || fake.queueCalls != 1 ||
            fake.eraseCalls != 0)
        {
            return false;
        }
        // Physical isolation alone is insufficient to scrub a key still
        // referenced by a device-owned outgoing management descriptor.
        fake = {};
        fake.pendingTransmit = true;
        result = retireNativeLinkHardware(backend, kOwnerEpoch, kOwnerEpoch,
                                          true, kOwnerEpoch);
        if (result.queueIsolated || result.hardwareKeysErased ||
            !result.requiresNewPhysicalEpoch || !fake.queueIsolated ||
            fake.queueCalls != 1 || fake.eraseCalls != 0)
        {
            return false;
        }
        fake = {};
        result = retireNativeLinkHardware(backend, kOwnerEpoch - 1U,
                                          kOwnerEpoch, true, kOwnerEpoch);
        if (result.queueIsolated || result.hardwareKeysErased ||
            !result.requiresNewPhysicalEpoch || fake.queueCalls != 0 ||
            fake.eraseCalls != 0)
        {
            return false;
        }
        result = retireNativeLinkHardware(backend, 0, kOwnerEpoch, true,
                                          kOwnerEpoch);
        if (result.queueIsolated || result.hardwareKeysErased ||
            fake.queueCalls != 0 || fake.eraseCalls != 0)
        {
            return false;
        }
        result = retireNativeLinkHardware(backend, kOwnerEpoch, kOwnerEpoch,
                                          false, kOwnerEpoch);
        if (!result.queueIsolated || result.hardwareKeysErased ||
            fake.queueCalls != 1 || fake.eraseCalls != 0)
        {
            return false;
        }
        fake = {};
        result = retireNativeLinkHardware(backend, kOwnerEpoch, kOwnerEpoch,
                                          true, kOwnerEpoch - 1U);
        if (!result.queueIsolated || result.hardwareKeysErased ||
            fake.queueCalls != 1 || fake.eraseCalls != 0)
        {
            return false;
        }
        backend.eraseKeys = nullptr;
        fake = {};
        result = retireNativeLinkHardware(backend, kOwnerEpoch, kOwnerEpoch,
                                          true, kOwnerEpoch);
        if (!result.queueIsolated || result.hardwareKeysErased ||
            fake.queueCalls != 1 || fake.eraseCalls != 0)
        {
            return false;
        }
        backend.isolate = nullptr;
        fake = {};
        result = retireNativeLinkHardware(backend, kOwnerEpoch, kOwnerEpoch,
                                          true, kOwnerEpoch);
        if (result.queueIsolated || result.hardwareKeysErased ||
            !result.requiresNewPhysicalEpoch || fake.queueCalls != 0 ||
            fake.eraseCalls != 0)
        {
            return false;
        }
        backend.isolate = isolateQueue;
        backend.context = nullptr;
        result = retireNativeLinkHardware(backend, kOwnerEpoch, kOwnerEpoch,
                                          true, kOwnerEpoch);
        return !result.queueIsolated && !result.hardwareKeysErased &&
               result.requiresNewPhysicalEpoch && fake.queueCalls == 0 &&
               fake.eraseCalls == 0;
    }
} // namespace

int main()
{
    using simpleath::tahoe::acceptWirelessJoinCommit;
    using simpleath::tahoe::acceptWirelessPortIdentity;
    using simpleath::tahoe::acceptWirelessReceiveIdentity;
    using simpleath::tahoe::acceptWirelessSnapshot;
    using simpleath::tahoe::mayDeliverWirelessData;
    using simpleath::tahoe::WirelessDataPortLease;
    constexpr uint64_t first = 1U;
    constexpr uint64_t second = 2U;
    constexpr uint64_t latest = UINT64_MAX;
    if (acceptWirelessReceiveIdentity(0, 0, 0, 0, false) ||
        acceptWirelessReceiveIdentity(first, 0, first, first, false) ||
        acceptWirelessReceiveIdentity(0, first, first, first, false) ||
        acceptWirelessReceiveIdentity(first, first, 0, 0, false))
    {
        return 1;
    }
    if (!acceptWirelessReceiveIdentity(first, first, first, first, false) ||
        !acceptWirelessReceiveIdentity(second, second, second, second, false) ||
        !acceptWirelessReceiveIdentity(latest, latest, latest, latest, false))
    {
        return 2;
    }
    // A retired PCI epoch cannot be relabeled as a current association.
    if (acceptWirelessReceiveIdentity(first, second, first, first, false) ||
        acceptWirelessReceiveIdentity(second, first, first, first, false))
    {
        return 3;
    }
    // A reconnected AP within one PCI epoch must not accept a previous
    // association's callback or an early successor callback either.
    if (acceptWirelessReceiveIdentity(first, first, first, second, false) ||
        acceptWirelessReceiveIdentity(first, first, second, first, false) ||
        acceptWirelessReceiveIdentity(first, first, 0, second, false))
    {
        return 4;
    }
    // ProviderStopped revokes matching identities as well as stale ones.
    if (acceptWirelessReceiveIdentity(first, first, first, first, true) ||
        acceptWirelessReceiveIdentity(latest, latest, latest, latest, true))
    {
        constexpr int kStoppedProviderFailure = 5;
        return kStoppedProviderFailure;
    }
    // A stale provider call must not roll back a new PCI epoch, nor revive
    // a previous association after a link event arrived during the call.
    if (!acceptWirelessSnapshot(first, first, 0, 0, false) ||
        !acceptWirelessSnapshot(second, first, 1, 1, false) ||
        acceptWirelessSnapshot(first, second, 1, 1, false) ||
        acceptWirelessSnapshot(first, first, 0, 1, false) ||
        acceptWirelessSnapshot(0, first, 1, 1, false) ||
        acceptWirelessSnapshot(second, first, 1, 1, true))
    {
        constexpr int kSnapshotRaceFailure = 6;
        return kSnapshotRaceFailure;
    }
    // A provider may synchronously reset, complete or replace the active
    // join before its outer callback returns success. The old WCL request
    // must not observe a successor's join ID as its own success.
    if (!acceptWirelessJoinCommit(first, first, first, first) ||
        !acceptWirelessJoinCommit(latest, latest, latest, latest) ||
        acceptWirelessJoinCommit(0, first, first, first) ||
        acceptWirelessJoinCommit(first, 0, first, first) ||
        acceptWirelessJoinCommit(first, first, second, first) ||
        acceptWirelessJoinCommit(first, first, first, second) ||
        acceptWirelessJoinCommit(second, first, first, first) ||
        acceptWirelessJoinCommit(first, second, first, first))
    {
        constexpr int kJoinCompletionRaceFailure = 7;
        return kJoinCompletionRaceFailure;
    }
    if (!acceptWirelessPortIdentity(first, first, first, first, first, first) ||
        !acceptWirelessPortIdentity(latest, latest, latest, latest, latest,
                                    latest) ||
        acceptWirelessPortIdentity(0, first, first, first, first, first) ||
        acceptWirelessPortIdentity(first, 0, first, first, first, first) ||
        acceptWirelessPortIdentity(first, first, 0, first, first, first) ||
        acceptWirelessPortIdentity(first, first, first, second, first, first) ||
        acceptWirelessPortIdentity(first, first, first, first, second, first) ||
        acceptWirelessPortIdentity(first, first, first, first, first, second))
    {
        constexpr int kPortGenerationRaceFailure = 8;
        return kPortGenerationRaceFailure;
    }
    // A valid controlled port is still insufficient for ordinary Ethernet
    // before a current, beacon-confirmed association. Pre-port EAPOL is
    // separately admitted by the physical owner, not by this data lease.
    WirelessDataPortLease data {first, true, true, false, true, true, true};
    constexpr int kPrematureDataFailure = 9;
    if (!mayDeliverWirelessData(data))
    {
        return kPrematureDataFailure;
    }
    data.associatedBeaconObserved = false;
    if (mayDeliverWirelessData(data))
    {
        return kPrematureDataFailure;
    }
    data.associatedBeaconObserved = true;
    data.associationGeneration = 0U;
    if (mayDeliverWirelessData(data))
    {
        return kPrematureDataFailure;
    }
    data.associationGeneration = first;
    data.controlledPortOpen = false;
    if (mayDeliverWirelessData(data))
    {
        return kPrematureDataFailure;
    }
    data.controlledPortOpen = true;
    data.associated = false;
    if (mayDeliverWirelessData(data))
    {
        return kPrematureDataFailure;
    }
    data.associated = true;
    data.rfKillBlocked = true;
    if (mayDeliverWirelessData(data))
    {
        return kPrematureDataFailure;
    }
    data.rfKillBlocked = false;
    data.radioAvailable = false;
    if (mayDeliverWirelessData(data))
    {
        return kPrematureDataFailure;
    }
    data.radioAvailable = true;
    data.powered = false;
    if (mayDeliverWirelessData(data))
    {
        return kPrematureDataFailure;
    }
    data.powered = true;
    if (!mayDeliverWirelessData(data))
    {
        return kPrematureDataFailure;
    }
    using simpleath::tahoe::acceptWirelessScanCompletion;
    constexpr int kStaleScanCompletionFailure = 12;
    if (!acceptWirelessScanCompletion(first, first, first, first, true,
                                      false) ||
        !acceptWirelessScanCompletion(latest, latest, latest, latest, true,
                                      false) ||
        acceptWirelessScanCompletion(0, first, first, first, true, false) ||
        acceptWirelessScanCompletion(first, 0, first, first, true, false) ||
        acceptWirelessScanCompletion(first, first, 0, first, true, false) ||
        acceptWirelessScanCompletion(first, first, first, 0, true, false) ||
        acceptWirelessScanCompletion(first, first, second, first, true,
                                     false) ||
        acceptWirelessScanCompletion(first, first, first, second, true,
                                     false) ||
        acceptWirelessScanCompletion(first, second, first, first, true,
                                     false) ||
        acceptWirelessScanCompletion(first, first, first, first, false,
                                     false) ||
        acceptWirelessScanCompletion(first, first, first, first, true, true))
    {
        return kStaleScanCompletionFailure;
    }
    constexpr int kCriticalEventFailure = 11;
    if (!checkCriticalWirelessEventRetention())
    {
        return kCriticalEventFailure;
    }
    constexpr int kLinkRetirementFailure = 10;
    return static_cast<int>(!checkNativeLinkRetirement()) *
           kLinkRetirementFailure;
}
