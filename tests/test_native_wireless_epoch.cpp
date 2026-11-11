// Portable host checks for the actual Tahoe native Ethernet callback gate.
#include "platform/tahoe/NativeWirelessEpoch.hpp"
#include <stdint.h>

int main()
{
    using simpleath::tahoe::acceptWirelessJoinCommit;
    using simpleath::tahoe::acceptWirelessPortIdentity;
    using simpleath::tahoe::acceptWirelessReceiveIdentity;
    using simpleath::tahoe::acceptWirelessSnapshot;
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
    return 0;
}
