// Copyright (c) 2026 SimpleATH contributors.
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
            return state.requested && state.requestEpoch != 0 &&
                   state.requestEpoch == state.radioEpoch &&
                   state.associationGeneration != 0 && state.radioAvailable &&
                   state.powered && !state.rfKillBlocked && state.associated &&
                   state.controlledPortOpen && state.associatedBeaconObserved;
        }
    } // namespace tahoe
} // namespace simpleath
#endif
