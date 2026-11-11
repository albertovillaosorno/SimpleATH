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
#include "DataReassembly.hpp"
#include "Frames.hpp"
#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    namespace ieee80211
    {
        namespace
        {
            constexpr size_t kMinimumHeaderBytes = 24U;
            constexpr size_t kAddressOffset = 4U;
            constexpr size_t kAddressSpan = 18U;
            constexpr size_t kSequenceOffset = 22U;
            constexpr size_t kQosOffset = 24U;
            constexpr size_t kQosBytes = 2U;
            constexpr uint8_t kOrdinaryDataSubtype = 0U;
            constexpr uint8_t kQosDataSubtype = 8U;
            constexpr uint8_t kAmsduPresent = 0x80U;
            constexpr uint8_t kOrdered = 0x80U;
            constexpr uint8_t kMaximumFragment = 15U;
            constexpr uint8_t kHighSequenceMask = 0xf0U;
            constexpr uint8_t kControlIdentityMask = 0xf3U;
            constexpr uint16_t kSequenceIdentityMask = 0xfff0U;
            constexpr uint8_t kBitsPerByte = 8U;

            bool overlaps(const void *first, size_t firstBytes,
                          const void *second, size_t secondBytes)
            {
                if (first == nullptr || second == nullptr || firstBytes == 0U ||
                    secondBytes == 0U)
                {
                    return false;
                }
                uintptr_t left = 0;
                uintptr_t right = 0;
                static_assert(sizeof(left) == sizeof(first),
                              "pointer and uintptr_t must have same width");
                __builtin_memcpy(&left, static_cast<const void *>(&first),
                                 sizeof(first));
                __builtin_memcpy(&right, static_cast<const void *>(&second),
                                 sizeof(second));
                return left <= right ? right - left < firstBytes
                                     : left - right < secondBytes;
            }

            template <typename Byte> Byte *at(Byte *base, size_t offset)
            {
                uintptr_t address = 0;
                static_assert(sizeof(address) == sizeof(base),
                              "pointer must fit in uintptr_t");
                __builtin_memcpy(&address, static_cast<const void *>(&base),
                                 sizeof(base));
                address += offset;
                Byte *result = nullptr;
                __builtin_memcpy(static_cast<void *>(&result),
                                 static_cast<const void *>(&address),
                                 sizeof(result));
                return result;
            }

        } // namespace

        void DataReassembly::clear()
        {
            __builtin_memset(&packet_[0], 0, sizeof(packet_));
            used_ = 0;
            headerBytes_ = 0;
            startedMs_ = 0;
            lastMs_ = 0;
            sequence_ = 0;
            nextFragment_ = 0;
            pending_ = false;
        }

        void DataReassembly::append(const uint8_t *bytes, size_t length)
        {
            // Bounded by the caller, including the retained MPDU header.
            auto *destination = at(&packet_[0], used_);
            __builtin_memcpy(destination, bytes, length);
            used_ += length;
        }

        DataFragmentResult DataReassembly::ingest(const uint8_t *frame,
                                                  size_t length, uint64_t nowMs,
                                                  DataFrameView &out)
        {
            if (overlaps(&out, sizeof(out), this, sizeof(*this)) ||
                overlaps(&out, sizeof(out), frame, length) ||
                overlaps(frame, length, this, sizeof(*this)))
            {
                return DataFragmentResult::Rejected;
            }
            out = {};
            if (frame == nullptr || length < kMinimumHeaderBytes ||
                length > kDataReassembledBytes)
            {
                clear();
                return DataFragmentResult::Rejected;
            }
            Frame parsed {};
            if (parseFrame(frame, length, parsed) != Result::Ok ||
                parsed.type != FrameType::Data ||
                (parsed.subtype != kOrdinaryDataSubtype &&
                 parsed.subtype != kQosDataSubtype) ||
                parsed.toDs || !parsed.fromDs ||
                parsed.headerLength >= length ||
                (parsed.subtype == kQosDataSubtype &&
                 (parsed.headerLength != kQosOffset + kQosBytes)))
            {
                clear();
                return DataFragmentResult::Rejected;
            }
            uint8_t header[kQosOffset + kQosBytes] {};
            __builtin_memcpy(&header[0], frame, parsed.headerLength);
            if ((header[1] & kOrdered) != 0U ||
                (parsed.subtype == kQosDataSubtype &&
                 (header[kQosOffset] & kAmsduPresent) != 0U))
            {
                clear();
                return DataFragmentResult::Rejected;
            }
            // Even an unfragmented protected MPDU must never be surfaced by
            // this strictly OPEN data owner. Per-fragment CCMP PN/MIC must be
            // authorized by its distinct security/session owner instead.
            if (parsed.protectedFrame ||
                (parsed.moreFragments && parsed.fragment == kMaximumFragment))
            {
                clear();
                return DataFragmentResult::Rejected;
            }
            if (!parsed.moreFragments && parsed.fragment == 0U)
            {
                out = {frame, length};
                return DataFragmentResult::Complete;
            }
            const auto sequence = static_cast<uint16_t>(
                static_cast<uint32_t>(header[kSequenceOffset]) |
                (static_cast<uint32_t>(header[kSequenceOffset + 1U])
                 << kBitsPerByte));
            if (parsed.fragment == 0U)
            {
                clear();
                __builtin_memcpy(&packet_[0], frame, length);
                used_ = length;
                headerBytes_ = parsed.headerLength;
                sequence_ = sequence & kSequenceIdentityMask;
                startedMs_ = nowMs;
                lastMs_ = nowMs;
                nextFragment_ = 1U;
                pending_ = true;
                return DataFragmentResult::Pending;
            }
            if (!pending_ || parsed.fragment != nextFragment_ ||
                parsed.headerLength != headerBytes_ || nowMs < lastMs_ ||
                nowMs < startedMs_ ||
                nowMs - startedMs_ > kDataFragmentTimeoutMs ||
                header[0] != packet_[0] ||
                ((static_cast<uint32_t>(header[1]) ^
                  static_cast<uint32_t>(packet_[1])) &
                 kControlIdentityMask) != 0U ||
                (sequence & kSequenceIdentityMask) != sequence_ ||
                __builtin_memcmp(at(frame, kAddressOffset),
                                 &packet_[kAddressOffset], kAddressSpan) != 0 ||
                (parsed.subtype == kQosDataSubtype &&
                 __builtin_memcmp(at(frame, kQosOffset), &packet_[kQosOffset],
                                  kQosBytes) != 0) ||
                length - parsed.headerLength > sizeof(packet_) - used_)
            {
                clear();
                return DataFragmentResult::Rejected;
            }
            append(at(frame, parsed.headerLength),
                   length - parsed.headerLength);
            lastMs_ = nowMs;
            ++nextFragment_;
            if (parsed.moreFragments)
            {
                return DataFragmentResult::Pending;
            }
            // Restore a canonical unfragmented header; downstream admission
            // still checks AP/station addresses, LLC/SNAP and duplicates.
            packet_[1] &= kControlIdentityMask;
            packet_[kSequenceOffset] &= kHighSequenceMask;
            pending_ = false;
            out = {&packet_[0], used_};
            return DataFragmentResult::Complete;
        }
    } // namespace ieee80211
} // namespace simpleath
