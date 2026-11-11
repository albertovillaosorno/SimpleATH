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
#include <stdint.h>

namespace simpleath
{
    namespace tahoe
    {
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
