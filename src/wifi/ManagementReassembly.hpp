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
//   - Bounded, session-local 802.11 management MPDU reassembly.
// - Must-Not:
//   - Interpret incomplete fragments, bypass FCS/PMF, or grant radio access.
// - Allows:
//   - Inputs: independently FCS-verified, ordered management MPDUs and time.
//   - Outputs: borrowed complete MPDU or a pending/invalid result.
//   - Side effects: only fixed-capacity, owner-local fragment state.
// - Split-When:
//   - Reassembly requires an independent protocol or native lifetime owner.
// - Merge-When:
//   - The receiver can own this small, bounded protocol stage directly.
// - Summary:
//   - Reassembles one unprotected management exchange without dynamic memory.
// - Description:
//   - Verifies fragment identity, order, lifetime and full-frame limits.
// - Usage:
//   - Called synchronously by WifiEngine under the current receive owner.
// - Defaults:
//   - Missing, stale, reordered or oversized fragments fail closed.
//
// Module: One-session 802.11 management fragment reassembly.
#ifndef SIMPLEATH_MANAGEMENT_REASSEMBLY_HPP
#define SIMPLEATH_MANAGEMENT_REASSEMBLY_HPP

#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    namespace ieee80211
    {
        constexpr size_t kManagementReassembledBytes = 2342U;
        constexpr uint64_t kManagementFragmentTimeoutMs = 500U;

        enum class ManagementFragmentResult : uint8_t
        {
            Complete,
            Pending,
            Rejected,
        };

        struct ManagementFrameView
        {
                const uint8_t *bytes {};
                size_t length {};
        };

        // Serialized by the existing WifiEngine RX owner. No allocations,
        // timers, PHY assumptions, or authentication are supplied here.
        // Incomplete frames are never published to management parsers.
        // A complete view is borrowed until the next ingest() or clear().
        class ManagementReassembly
        {
            public:
                ManagementReassembly() = default;
                ~ManagementReassembly() = default;
                ManagementReassembly(const ManagementReassembly &) = delete;
                ManagementReassembly(ManagementReassembly &&) = delete;
                ManagementReassembly &
                operator=(ManagementReassembly &&) = delete;
                ManagementReassembly &
                operator=(const ManagementReassembly &) = delete;

                void clear();
                ManagementFragmentResult ingest(const uint8_t *frame,
                                                size_t length, uint64_t nowMs,
                                                ManagementFrameView &out);

            private:
                void appendPayload(const uint8_t *payload, size_t count);
                uint8_t packet_[kManagementReassembledBytes] {};
                size_t used_ {};
                uint64_t startedMs_ {};
                uint16_t sequence_ {};
                uint8_t nextFragment_ {};
                bool pending_ {};
        };
    } // namespace ieee80211
} // namespace simpleath
#endif
