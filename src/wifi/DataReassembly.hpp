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
//   - Bounded open-infrastructure 802.11 data-fragment reassembly.
// - Must-Not:
//   - Reassemble protected MPDUs or bypass FCS, association or duplicate gates.
// - Allows:
//   - Inputs: independently FCS-verified open data MPDUs and monotonic time.
//   - Outputs: borrowed complete MPDU or pending/invalid result.
//   - Side effects: fixed-capacity, association-local fragment state.
// - Split-When:
//   - Cryptographic per-fragment state needs an independent security owner.
// - Merge-When:
//   - The receive owner can safely retain this fixed-size state.
// - Summary:
//   - Reassembles one ordinary or QoS open data MSDU without allocation.
// - Description:
//   - Checks fragment identity, order, timeout, size and QoS consistency.
// - Usage:
//   - Called synchronously by the WifiEngine RX owner after FCS admission.
// - Defaults:
//   - Malformed, protected and out-of-order fragments fail closed.
//
// Module: Bounded open-data fragmentation contract.
#ifndef SIMPLEATH_WIFI_DATA_REASSEMBLY_HPP
#define SIMPLEATH_WIFI_DATA_REASSEMBLY_HPP

#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    namespace ieee80211
    {
        constexpr size_t kDataReassembledBytes = 2342U;
        constexpr uint64_t kDataFragmentTimeoutMs = 500U;

        enum class DataFragmentResult : uint8_t
        {
            Complete,
            Pending,
            Rejected,
        };

        struct DataFrameView
        {
                const uint8_t *bytes {};
                size_t length {};
        };

        // Single active fragment sequence, serialized on the native workloop.
        // Views into owned storage expire at the next ingest() or clear().
        // The caller must not retain borrowed DMA or assembled payload views.
        class DataReassembly
        {
            public:
                DataReassembly() = default;
                ~DataReassembly() = default;
                DataReassembly(const DataReassembly &) = delete;
                DataReassembly(DataReassembly &&) = delete;
                DataReassembly &operator=(const DataReassembly &) = delete;
                DataReassembly &operator=(DataReassembly &&) = delete;

                void clear();
                DataFragmentResult ingest(const uint8_t *frame, size_t length,
                                          uint64_t nowMs, DataFrameView &out);

            private:
                void append(const uint8_t *bytes, size_t length);
                uint8_t packet_[kDataReassembledBytes] {};
                size_t used_ {};
                size_t headerBytes_ {};
                uint64_t startedMs_ {};
                uint64_t lastMs_ {};
                uint16_t sequence_ {};
                uint8_t nextFragment_ {};
                bool pending_ {};
        };
    } // namespace ieee80211
} // namespace simpleath
#endif
