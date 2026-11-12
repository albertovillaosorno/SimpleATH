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
//   - Native driver contracts and implementation for tahoe data path admission.
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
//   - Native driver contracts and implementation for tahoe data path admission.
// - Description:
//   - Implements or verifies the TahoeDataPathAdmission source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: tahoe data path admission.
#ifndef SIMPLEATH_TAHOE_DATA_PATH_ADMISSION_HPP
#define SIMPLEATH_TAHOE_DATA_PATH_ADMISSION_HPP

#include <stdint.h>

namespace simpleath
{
    namespace tahoe
    {
        // This is the gate for ordinary native Skywalk Ethernet queues, not
        // pre-port EAPOL transport. A queued OS enable request is scoped to
        // one physical radio epoch; new associations must independently open
        // their controlled port and observe the expected AP beacon.
        struct NativeDataPathAdmission
        {
                uint64_t requestEpoch;
                uint64_t radioEpoch;
                uint64_t associationGeneration;
                bool requested;
                // One local WCL join must own this exact physical AP before
                // a fresh OS queue enable can admit ordinary Ethernet data.
                bool wclJoinConnected;
                bool radioAvailable;
                bool powered;
                bool rfKillBlocked;
                bool associated;
                bool controlledPortOpen;
                bool associatedBeaconObserved;
        };

        constexpr bool
        mayEnableNativeDataPath(const NativeDataPathAdmission &state)
        {
            return state.requested && state.wclJoinConnected &&
                   state.requestEpoch != 0 &&
                   state.requestEpoch == state.radioEpoch &&
                   state.associationGeneration != 0 && state.radioAvailable &&
                   state.powered && !state.rfKillBlocked && state.associated &&
                   state.controlledPortOpen && state.associatedBeaconObserved;
        }
    } // namespace tahoe
} // namespace simpleath
#endif
