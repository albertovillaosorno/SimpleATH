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
//   - Native driver contracts and implementation for native wireless epoch.
// - Must-Not:
//   - Invent hardware readiness, weaken buffer bounds, or assume ABI
//     compatibility.
// - Allows:
//   - Inputs: validated register, protocol, platform, or device state from
//     callers.
//   - Outputs: bounded native transitions, messages, or explicit errors.
//   - Side effects: only the device and kernel operations owned by this module.
// - Split-When:
//   - A separate protocol stage needs independent validation and ownership.
// - Merge-When:
//   - The caller directly owns this narrow contract without reuse.
// - Summary:
//   - Native driver contracts and implementation for native wireless epoch.
// - Description:
//   - Implements or verifies the NativeWirelessEpoch source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for native wireless epoch.

// Epoch policy for provider-to-Tahoe Ethernet callbacks. Portable by design.
#ifndef SIMPLEATH_TAHOE_NATIVE_WIRELESS_EPOCH_HPP
#define SIMPLEATH_TAHOE_NATIVE_WIRELESS_EPOCH_HPP
#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    namespace tahoe
    {
        // Provider-to-controller notifications retain their wire values.
        // The final provider event is terminal; ScanFinished is a one-shot
        // completion that must not be displaced by high-rate TX wakeups.
        enum class WirelessEvent : uint32_t
        {
            RadioChanged,
            ScanFinished,
            AssociationChanged,
            LinkChanged,
            TransmitAvailable,
            ProviderStopped,
        };

        // State notifications can arrive on the provider gate after a native
        // poll sampled its owner snapshot. Drain these before publishing WCL
        // join/link status, then obtain one fresh physical snapshot. A TX
        // wakeup and one-shot scan completion do not themselves invalidate
        // association or radio availability.
        inline bool wirelessEventInvalidatesSnapshot(WirelessEvent event)
        {
            return event == WirelessEvent::RadioChanged ||
                   event == WirelessEvent::AssociationChanged ||
                   event == WirelessEvent::LinkChanged ||
                   event == WirelessEvent::ProviderStopped;
        }

        // Called only while holding the native mailbox lock. A full bounded
        // ring may discard one ordinary notification to make room for a real
        // scan completion. Preserve all earlier scan completions and their
        // order even when the ring wraps. The caller decrements count and
        // appends its new event at the newly freed logical tail.
        template <typename Record, size_t Capacity>
        inline bool evictWirelessNoncriticalEvent(Record (&ring)[Capacity],
                                                  size_t head, size_t count)
        {
            if (Capacity == 0U || head >= Capacity || count != Capacity)
            {
                return false;
            }
            for (size_t offset = 0; offset < count; ++offset)
            {
                const size_t index = (head + offset) % Capacity;
                if (ring[index].event == WirelessEvent::ScanFinished ||
                    ring[index].event == WirelessEvent::ProviderStopped)
                {
                    continue;
                }
                for (size_t shift = offset; shift + 1U < count; ++shift)
                {
                    ring[(head + shift) % Capacity] =
                        ring[(head + shift + 1U) % Capacity];
                }
                ring[(head + count - 1U) % Capacity] = {};
                return true;
            }
            return false;
        }

        // A controller accepts only one logical scan at a time. When every
        // mailbox slot holds a terminal event, a newer completed generation
        // supersedes a strictly older scan completion; the old WCL request
        // can no longer receive that event. Keep ProviderStopped, duplicate
        // notices and newer generations protected. Call this only
        // under the mailbox lock, after ordinary event eviction has failed.
        template <typename Record, size_t Capacity>
        inline bool evictWirelessSupersededScanEvent(Record (&ring)[Capacity],
                                                     size_t head, size_t count,
                                                     uint64_t currentEpoch,
                                                     uint64_t currentGeneration)
        {
            if (Capacity == 0U || head >= Capacity || count != Capacity ||
                currentEpoch == 0U || currentGeneration == 0U)
            {
                return false;
            }
            for (size_t offset = 0; offset < count; ++offset)
            {
                const size_t index = (head + offset) % Capacity;
                if (ring[index].event != WirelessEvent::ScanFinished ||
                    ring[index].epoch > currentEpoch ||
                    (ring[index].epoch == currentEpoch &&
                     ring[index].generation >= currentGeneration))
                {
                    continue;
                }
                for (size_t shift = offset; shift + 1U < count; ++shift)
                {
                    ring[(head + shift) % Capacity] =
                        ring[(head + shift + 1U) % Capacity];
                }
                ring[(head + count - 1U) % Capacity] = {};
                return true;
            }
            return false;
        }

        // A sampled PCI epoch must be checked again under the owner's
        // serialized gate before starting any physical work. The native
        // transport then rechecks that accepted identity against its mailbox.
        inline bool acceptWirelessScanStart(uint64_t sampledEpoch,
                                            uint64_t acceptedEpoch,
                                            uint64_t generation,
                                            uint64_t mailboxEpoch,
                                            bool providerStopped)
        {
            return !providerStopped && sampledEpoch != 0U && generation != 0U &&
                   sampledEpoch == acceptedEpoch &&
                   acceptedEpoch == mailboxEpoch;
        }

        // Scan completion is identified by both PCI epoch and bridge
        // generation. A queued completion must never finish a replacement
        // scan even after that replacement's own dwell has ended. Require
        // physical scan termination as independent confirmation; failed or
        // cancelled results are verified by the provider's scanNext check.
        inline bool acceptWirelessScanCompletion(uint64_t eventEpoch,
                                                 uint64_t eventGeneration,
                                                 uint64_t activeScanEpoch,
                                                 uint64_t activeScanGeneration,
                                                 bool providerLive,
                                                 bool physicalScanRunning)
        {
            return providerLive && eventEpoch != 0U && eventGeneration != 0U &&
                   eventEpoch == activeScanEpoch &&
                   eventGeneration == activeScanGeneration &&
                   !physicalScanRunning;
        }

        // Ordinary Skywalk Ethernet is a later stage than the physical
        // association and pre-port EAPOL exchange. The radio must have
        // observed a beacon from the selected AP before a controlled port
        // can deliver ordinary data. This is an independent mailbox gate:
        // a stale OS queue enable must never upgrade an unconfirmed join.
        struct WirelessDataPortLease
        {
                uint64_t associationGeneration;
                bool radioAvailable;
                bool powered;
                bool rfKillBlocked;
                bool associated;
                bool controlledPortOpen;
                bool associatedBeaconObserved;
        };

        inline bool mayDeliverWirelessData(const WirelessDataPortLease &state)
        {
            return state.associationGeneration != 0U && state.radioAvailable &&
                   state.powered && !state.rfKillBlocked && state.associated &&
                   state.controlledPortOpen && state.associatedBeaconObserved;
        }

        // A callback from a retired PCI epoch or a superseded same-epoch AP
        // association cannot be granted access to a successor's mailbox.
        // An epoch advance becomes visible through notify()/snapshot(); a
        // receive callback must NEVER advance the consumer epoch itself.
        // A provider snapshot is sampled outside the transport mailbox lock.
        // An intervening asynchronous event may supersede that sample; never
        // publish stale owner state after an epoch advance or link change.
        inline bool acceptWirelessSnapshot(uint64_t sampledEpoch,
                                           uint64_t activeEpoch,
                                           uint64_t sampledEventRevision,
                                           uint64_t activeEventRevision,
                                           bool providerStopped)
        {
            return !providerStopped && sampledEpoch != 0U &&
                   sampledEpoch >= activeEpoch &&
                   sampledEventRevision == activeEventRevision;
        }

        // A synchronous provider join can finish after a replacement request
        // starts on the same PCI epoch, or after a radio reset advances the
        // epoch. Only its own observed join request may be acknowledged to WCL.
        inline bool acceptWirelessJoinCommit(uint64_t requestedEpoch,
                                             uint64_t requestedId,
                                             uint64_t observedEpoch,
                                             uint64_t observedId)
        {
            return requestedEpoch != 0U && requestedId != 0U &&
                   requestedEpoch == observedEpoch && requestedId == observedId;
        }

        // An authorization submitted from a native work loop must not open or
        // roll back a successor's controlled port on the PCI provider gate.
        inline bool acceptWirelessPortIdentity(uint64_t requestedEpoch,
                                               uint64_t requestedJoinId,
                                               uint64_t requestedAssociation,
                                               uint64_t observedEpoch,
                                               uint64_t observedJoinId,
                                               uint64_t observedAssociation)
        {
            return requestedEpoch != 0U && requestedJoinId != 0U &&
                   requestedAssociation != 0U &&
                   requestedEpoch == observedEpoch &&
                   requestedJoinId == observedJoinId &&
                   requestedAssociation == observedAssociation;
        }

        inline bool acceptWirelessReceiveIdentity(uint64_t callbackEpoch,
                                                  uint64_t activeEpoch,
                                                  uint64_t callbackAssociation,
                                                  uint64_t activeAssociation,
                                                  bool providerStopped)
        {
            return !providerStopped && callbackEpoch != 0U &&
                   callbackEpoch == activeEpoch && callbackAssociation != 0U &&
                   callbackAssociation == activeAssociation;
        }
    } // namespace tahoe
} // namespace simpleath
#endif
