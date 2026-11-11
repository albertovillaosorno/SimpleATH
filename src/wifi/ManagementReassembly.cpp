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
#include "ManagementReassembly.hpp"
#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    namespace ieee80211
    {
        namespace
        {
            constexpr size_t kHeaderBytes = 24U;
            constexpr size_t kSequenceOffset = 22U;
            constexpr size_t kAddressesOffset = 4U;
            constexpr size_t kAddressesBytes = 18U;
            constexpr uint8_t kMoreFragments = 0x04U;
            constexpr uint8_t kProtected = 0x40U;
            constexpr uint8_t kDsAndOrder = 0x83U;
            constexpr uint8_t kVersionAndTypeMask = 0x0fU;
            constexpr uint8_t kFragmentMask = 0x0fU;
            constexpr uint8_t kMaximumFragment = 15U;
            constexpr uint8_t kFragmentZeroLowMask = 0xf0U;
            // All bits except More Fragments and Retry must stay unchanged
            // within the same management exchange.
            constexpr uint32_t kControlIdentityMask = 0xf3U;
            constexpr uint32_t kSequenceIdentityMask = 0xfff0U;
            constexpr uint32_t kBitsPerByte = 8U;

            bool overlaps(const void *left, size_t leftBytes, const void *right,
                          size_t rightBytes)
            {
                if (left == nullptr || right == nullptr || leftBytes == 0U ||
                    rightBytes == 0U)
                {
                    return false;
                }
                uintptr_t first = 0;
                uintptr_t second = 0;
                static_assert(sizeof(first) == sizeof(left),
                              "pointer and uintptr_t must have equal width");
                __builtin_memcpy(&first, static_cast<const void *>(&left),
                                 sizeof(left));
                __builtin_memcpy(&second, static_cast<const void *>(&right),
                                 sizeof(right));
                return first <= second ? second - first < leftBytes
                                       : first - second < rightBytes;
            }

            // Input spans have already been bounded. Construct byte offsets
            // without an unchecked pointer subscript into borrowed DMA data.
            const uint8_t *byteAt(const uint8_t *base, size_t offset)
            {
                uintptr_t address = 0;
                static_assert(sizeof(address) == sizeof(base),
                              "pointer must fit a uintptr_t");
                __builtin_memcpy(&address, static_cast<const void *>(&base),
                                 sizeof(base));
                address += offset;
                const uint8_t *result = nullptr;
                __builtin_memcpy(static_cast<void *>(&result),
                                 static_cast<const void *>(&address),
                                 sizeof(result));
                return result;
            }

        } // namespace

        void ManagementReassembly::clear()
        {
            // No credentials are kept here. Erase stale management bytes
            // and abandon incomplete exchanges on every session change.
            __builtin_memset(&packet_[0], 0, sizeof(packet_));
            used_ = 0;
            startedMs_ = 0;
            sequence_ = 0;
            nextFragment_ = 0;
            pending_ = false;
        }

        void ManagementReassembly::appendPayload(const uint8_t *payload,
                                                 size_t count)
        {
            // ingest() proved count <= capacity - used_. Reconstruct the
            // destination offset from owned storage; no unbounded indexing.
            const uint8_t *base = &packet_[0];
            uintptr_t address = 0;
            static_assert(sizeof(address) == sizeof(base),
                          "owned pointer must fit a uintptr_t");
            __builtin_memcpy(&address, static_cast<const void *>(&base),
                             sizeof(base));
            address += used_;
            uint8_t *dest = nullptr;
            __builtin_memcpy(static_cast<void *>(&dest),
                             static_cast<const void *>(&address), sizeof(dest));
            __builtin_memcpy(dest, payload, count);
            used_ += count;
        }

        ManagementFragmentResult
        ManagementReassembly::ingest(const uint8_t *frame, size_t length,
                                     uint64_t nowMs, ManagementFrameView &out)
        {
            if (overlaps(&out, sizeof(out), this, sizeof(*this)) ||
                overlaps(&out, sizeof(out), frame, length) ||
                overlaps(frame, length, this, sizeof(*this)))
            {
                return ManagementFragmentResult::Rejected;
            }
            out = {};
            if (frame == nullptr || length < kHeaderBytes ||
                length > kManagementReassembledBytes)
            {
                clear();
                return ManagementFragmentResult::Rejected;
            }
            uint8_t header[kHeaderBytes] {};
            __builtin_memcpy(&header[0], frame, sizeof(header));
            if ((header[0] & kVersionAndTypeMask) != 0U ||
                (header[1] & kDsAndOrder) != 0U)
            {
                clear();
                return ManagementFragmentResult::Rejected;
            }
            const auto control = static_cast<uint16_t>(
                static_cast<uint32_t>(header[kSequenceOffset]) |
                (static_cast<uint32_t>(header[kSequenceOffset + 1U])
                 << kBitsPerByte));
            const auto fragment = static_cast<uint8_t>(control & kFragmentMask);
            const bool more = (header[1] & kMoreFragments) != 0U;
            if (!more && fragment == 0U)
            {
                // Ordinary unfragmented management is checked by the normal
                // caller, including PMF/robust-frame security requirements.
                out = {frame, length};
                return ManagementFragmentResult::Complete;
            }
            // FCS alone does not authenticate PMF fragments. Their crypto
            // reassembly belongs to an explicitly verified protected owner.
            if ((header[1] & kProtected) != 0U || length == kHeaderBytes ||
                (more && fragment == kMaximumFragment))
            {
                clear();
                return ManagementFragmentResult::Rejected;
            }
            if (fragment == 0U)
            {
                clear();
                __builtin_memcpy(&packet_[0], frame, length);
                used_ = length;
                startedMs_ = nowMs;
                sequence_ = static_cast<uint16_t>(
                    static_cast<uint32_t>(control) & kSequenceIdentityMask);
                nextFragment_ = 1U;
                pending_ = true;
                return ManagementFragmentResult::Pending;
            }
            if (!pending_ || fragment != nextFragment_ || nowMs < startedMs_ ||
                nowMs - startedMs_ > kManagementFragmentTimeoutMs ||
                header[0] != packet_[0] ||
                ((static_cast<uint32_t>(header[1]) ^
                  static_cast<uint32_t>(packet_[1])) &
                 kControlIdentityMask) != 0U ||
                (static_cast<uint32_t>(control) & kSequenceIdentityMask) !=
                    sequence_ ||
                __builtin_memcmp(byteAt(frame, kAddressesOffset),
                                 &packet_[kAddressesOffset],
                                 kAddressesBytes) != 0 ||
                length - kHeaderBytes > sizeof(packet_) - used_)
            {
                clear();
                return ManagementFragmentResult::Rejected;
            }
            const size_t payload = length - kHeaderBytes;
            appendPayload(byteAt(frame, kHeaderBytes), payload);
            ++nextFragment_;
            if (more)
            {
                return ManagementFragmentResult::Pending;
            }
            // Reconstructed canonical MPDU has no FCS, fragment bits or retry.
            packet_[1] = static_cast<uint8_t>(
                static_cast<uint32_t>(packet_[1]) & kControlIdentityMask);
            packet_[kSequenceOffset] &= kFragmentZeroLowMask;
            pending_ = false;
            out = {&packet_[0], used_};
            return ManagementFragmentResult::Complete;
        }
    } // namespace ieee80211
} // namespace simpleath
