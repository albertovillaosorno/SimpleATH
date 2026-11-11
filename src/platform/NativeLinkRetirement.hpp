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
//   - Same-epoch native link-loss queue isolation and key retirement order.
// - Must-Not:
//   - Treat stale owner state, incomplete DMA isolation or failed key erasure
//     as permission to reconnect or reuse a physical key slot.
// - Allows:
//   - Inputs: explicit physical owner epoch, key-cache epoch and callbacks.
//   - Outputs: bounded isolation/erasure evidence and a reset requirement.
//   - Side effects: only callback-owned same-epoch device operations.
// - Split-When:
//   - An independently owned device reset stage needs separate coordination.
// - Merge-When:
//   - The native owner directly consumes this ordered retirement policy.
// - Summary:
//   - Native link loss quarantines before a conditional hardware key wipe.
// - Description:
//   - Gives portable tests a fakeable queue and key erasure boundary.
// - Usage:
//   - Invoke synchronously under the native PCI command gate.
// - Defaults:
//   - Missing proof or failed callbacks require a fresh physical reset.
//
// Module: Same-epoch native link-loss retirement policy.

#ifndef SIMPLEATH_NATIVE_LINK_RETIREMENT_HPP
#define SIMPLEATH_NATIVE_LINK_RETIREMENT_HPP

#include <stdint.h>

namespace simpleath
{
    struct NativeLinkRetirementBackend
    {
            void *context;
            // Must prevent new TX/RX, automatic MAC responses and bus DMA.
            // Return true only with no outstanding TX descriptor and proof
            // of physical isolation; leave the old queue permanently retired.
            bool (*isolate)(void *context, uint64_t epoch);
            // Called ONLY after isolation for this same physical epoch.
            bool (*eraseKeys)(void *context, uint64_t epoch);
    };

    struct NativeLinkRetirementResult
    {
            bool queueIsolated;
            bool hardwareKeysErased;
            // Even successful erasure cannot restart this retired queue.
            bool requiresNewPhysicalEpoch;
    };

    inline NativeLinkRetirementResult
    retireNativeLinkHardware(const NativeLinkRetirementBackend &backend,
                             uint64_t requestedEpoch, uint64_t ownerEpoch,
                             bool keyCacheInitialized, uint64_t keyCacheEpoch)
    {
        NativeLinkRetirementResult out {false, false, true};
        if (requestedEpoch == 0 || requestedEpoch != ownerEpoch ||
            backend.context == nullptr || backend.isolate == nullptr)
        {
            return out;
        }
        out.queueIsolated = backend.isolate(backend.context, requestedEpoch);
        if (out.queueIsolated && keyCacheInitialized &&
            keyCacheEpoch == requestedEpoch && backend.eraseKeys != nullptr)
        {
            out.hardwareKeysErased =
                backend.eraseKeys(backend.context, requestedEpoch);
        }
        return out;
    }
} // namespace simpleath

#endif
