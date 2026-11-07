// SPDX-License-Identifier: AGPL-3.0-only
// Linux-derived descriptor format/constants retain their upstream notice.
/*
 * Copyright (c) 2008-2011 Atheros Communications Inc.
 * Copyright (c) 2010-2011 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
// Reference SHA-256:
// ar9003_mac.c:
// a99f8fb18052510161232331e5fc98757619713e6f2ad69d1897f77597c0188b
// ar9003_mac.h:
// 47ada2b3a635aaf3cadb7b9f93bbff676da27bdc566e4a332124f21bbf0c7461
//
// mac.h:
// 10025cb48d6443f8c21a841326742562b6394a6df820c1499a5370f059ed9cd9
#include "Ar9003Descriptors.hpp"

#include <cstddef>
#include <cstdint>

namespace simpleath
{
    namespace edma
    {
        static constexpr uint32_t K_VENDOR = 0x168c0000U;
        static constexpr uint32_t K_TX_DESCRIPTOR_BITS = 0xc000U;
        static constexpr uint32_t K_TX_DESCRIPTOR_DWORDS =
            0x18U; // AR9565; other AR9003 = 0x17.
        static constexpr uint32_t K_BUFFER_LENGTH_MASK = 0x0fffU;
        static constexpr uint32_t K_VALID_QUEUE_MAX = 9U;
        static constexpr uint32_t K_TX_INFO_INDEX = 0U;
        static constexpr uint32_t K_LINK_INDEX = 1U;
        static constexpr uint32_t K_CHECKSUM_INDEX = 10U;
        static constexpr uint32_t K_SEGMENT_COUNT = 4U;
        static constexpr uint32_t K_SEGMENT_ADDRESS_INDEX = 2U;
        static constexpr uint32_t K_SEGMENT_LENGTH_INDEX = 3U;
        static constexpr uint32_t K_SEGMENT_STRIDE = 2U;
        static constexpr uint32_t K_LOW_HALF_MASK = 0xffffU;
        static constexpr uint32_t K_HIGH_HALF_MASK = 0xffff0000U;
        static constexpr uint32_t K_RESERVED_TYPE_MASK = 0x3000U;
        static constexpr uint32_t K_INFO_LENGTH_MASK = 0xffU;
        static constexpr uint32_t K_QUEUE_SHIFT = 8U;
        static constexpr uint32_t K_QUEUE_MASK = 0x0fU;
        static constexpr uint32_t K_BUS_ALIGNMENT_MASK = 3U;
        static constexpr uint32_t K_LENGTH_SHIFT = 16U;
        static constexpr uint64_t K_MAX_BUS_ADDRESS = 0xffffffffULL;
        // AR9003 RX status word positions and versioned silicon bit fields.
        static constexpr uint32_t K_RX_INFO_WORD = 0U;
        static constexpr uint32_t K_RX_RATE_WORD = 1U;
        static constexpr uint32_t K_RX_LENGTH_WORD = 2U;
        static constexpr uint32_t K_RX_TIMESTAMP_WORD = 3U;
        static constexpr uint32_t K_RX_HT_WORD = 4U;
        static constexpr uint32_t K_RX_RSSI_WORD = 5U;
        static constexpr uint32_t K_RX_FLAGS_WORD = 11U;
        static constexpr uint32_t K_RX_LENGTH_MASK = 0x0fffU;
        static constexpr uint32_t K_RX_MORE_FRAGMENTS = 0x1000U;
        static constexpr uint32_t K_RX_HT40 = 0x2U;
        static constexpr uint32_t K_RX_BYTE_SHIFT = 24U;
        static constexpr uint32_t K_RX_COMPLETE = 0x1U;
        static constexpr uint32_t K_RX_FRAME_VALID = 0x2U;
        static constexpr uint32_t K_RX_CRC_ERROR = 0x4U;
        static constexpr uint32_t K_RX_DECRYPT_ERROR = 0x8U;
        static constexpr uint32_t K_RX_PHY_ERROR = 0x10U;
        static constexpr uint32_t K_RX_MIC_ERROR = 0x20U;
        static constexpr uint32_t K_RX_AGGREGATION_CONTINUES = 0x00010000U;
        static constexpr uint32_t K_RX_AGGREGATED = 0x00020000U;
        static constexpr uint32_t K_RX_AGGREGATION_FIRST = 0x20000000U;
        static constexpr uint32_t K_RX_KEY_MISS = 0x80000000U;

        // Reject caller-forged overlapping input/output storage before
        // any write; raw status can belong to a DMA-visible ring.
        static bool overlaps_storage(const void *const first,
                                     size_t first_bytes,
                                     const void *const second,
                                     size_t second_bytes)
        {
            const auto left = reinterpret_cast<uintptr_t>(first);
            const auto right = reinterpret_cast<uintptr_t>(second);
            return first_bytes != 0 && second_bytes != 0 &&
                   (left >= right ? left - right < second_bytes
                                  : right - left < first_bytes);
        }

        uint16_t txPointerChecksum(const TxDescriptor &descriptor)
        {
            // Sum exactly the AR9003 pointer fields, with unsigned 32-bit wrap.
            // Same layout as ar9003_mac.c, but independent implementation.
            uint32_t sum = descriptor.word[K_TX_INFO_INDEX] +
                           descriptor.word[K_LINK_INDEX];
            for (size_t slot = 0; slot < K_SEGMENT_COUNT; ++slot)
            {
                sum += descriptor.word[K_SEGMENT_ADDRESS_INDEX +
                                       (slot * K_SEGMENT_STRIDE)];
                sum += descriptor.word[K_SEGMENT_LENGTH_INDEX +
                                       (slot * K_SEGMENT_STRIDE)];
            }
            const uint32_t folded =
                (sum & K_LOW_HALF_MASK) + (sum >> K_LENGTH_SHIFT);
            return static_cast<uint16_t>(folded & K_LOW_HALF_MASK);
        }

        bool validTxPointerDescriptor(const TxDescriptor &descriptor)
        {
            const uint32_t info = descriptor.word[K_TX_INFO_INDEX];
            if ((info & K_HIGH_HALF_MASK) != K_VENDOR ||
                (info & K_TX_DESCRIPTOR_BITS) != K_TX_DESCRIPTOR_BITS ||
                (info & K_RESERVED_TYPE_MASK) != 0 ||
                (info & K_INFO_LENGTH_MASK) != K_TX_DESCRIPTOR_DWORDS ||
                ((info >> K_QUEUE_SHIFT) & K_QUEUE_MASK) > K_VALID_QUEUE_MAX ||
                (descriptor.word[K_LINK_INDEX] & K_BUS_ALIGNMENT_MASK) != 0)
            {
                return false;
            }

            // The pointer codec only emits contiguous, nonempty segments.
            // A matching checksum is not evidence that a caller-constructed
            // descriptor contains even one mapped payload segment.
            bool found_segment = false;
            bool found_gap = false;
            for (size_t index = 0; index < K_SEGMENT_COUNT; ++index)
            {
                const uint32_t address =
                    descriptor.word[K_SEGMENT_ADDRESS_INDEX +
                                    (index * K_SEGMENT_STRIDE)];
                const uint32_t encoded =
                    descriptor.word[K_SEGMENT_LENGTH_INDEX +
                                    (index * K_SEGMENT_STRIDE)];
                if (address == 0 && encoded == 0)
                {
                    found_gap = true;
                    continue;
                }
                const uint32_t length = encoded >> K_LENGTH_SHIFT;
                if (found_gap || address == 0 || length == 0 ||
                    length > K_BUFFER_LENGTH_MASK ||
                    encoded != (length << K_LENGTH_SHIFT) ||
                    length - 1U >
                        static_cast<uint32_t>(K_MAX_BUS_ADDRESS) - address)
                {
                    return false;
                }
                found_segment = true;
            }
            return found_segment &&
                   (descriptor.word[K_CHECKSUM_INDEX] & K_LOW_HALF_MASK) ==
                       txPointerChecksum(descriptor);
        }

        DescriptorError encodeTxPointers(const TxPointerBlock &input,
                                         TxDescriptor &out)
        {
            if (overlaps_storage(&input, sizeof(input), &out, sizeof(out)))
            {
                return DescriptorError::OverlappingBuffers;
            }
            if (input.queue > K_VALID_QUEUE_MAX)
            {
                return DescriptorError::InvalidQueue;
            }
            if (input.segmentCount == 0 || input.segmentCount > K_SEGMENT_COUNT)
            {
                return DescriptorError::InvalidSegmentCount;
            }
            if (input.nextDescriptorBusAddress != 0 &&
                (input.nextDescriptorBusAddress & K_BUS_ALIGNMENT_MASK) != 0)
            {
                return DescriptorError::InvalidLink;
            }

            TxDescriptor staged {};
            staged.word[K_TX_INFO_INDEX] =
                K_VENDOR | K_TX_DESCRIPTOR_BITS |
                (static_cast<uint32_t>(input.queue) << K_QUEUE_SHIFT) |
                K_TX_DESCRIPTOR_DWORDS;
            staged.word[K_LINK_INDEX] = input.nextDescriptorBusAddress;

            for (uint8_t index = 0; index < input.segmentCount; ++index)
            {
                const Segment &segment = input.segment[index];
                if (segment.busAddress == 0 ||
                    segment.busAddress > K_MAX_BUS_ADDRESS)
                {
                    return DescriptorError::InvalidAddress;
                }
                if (segment.length == 0 ||
                    segment.length > K_BUFFER_LENGTH_MASK)
                {
                    return DescriptorError::InvalidLength;
                }
                if (segment.length - 1U >
                    K_MAX_BUS_ADDRESS - segment.busAddress)
                {
                    return DescriptorError::InvalidAddress;
                }
                staged.word[K_SEGMENT_ADDRESS_INDEX +
                            (index * K_SEGMENT_STRIDE)] =
                    static_cast<uint32_t>(segment.busAddress);
                staged
                    .word[K_SEGMENT_LENGTH_INDEX + (index * K_SEGMENT_STRIDE)] =
                    static_cast<uint32_t>(segment.length) << K_LENGTH_SHIFT;
            }
            staged.word[K_CHECKSUM_INDEX] = txPointerChecksum(staged);
            // Caller must serialize this copy; it is not an atomic DMA
            // publication.
            out = staged;
            return DescriptorError::Ok;
        }

        DescriptorError setNextTxDescriptor(TxDescriptor &descriptor,
                                            uint32_t nextDescriptorBusAddress)
        {
            if (nextDescriptorBusAddress != 0 &&
                (nextDescriptorBusAddress & K_BUS_ALIGNMENT_MASK) != 0)
            {
                return DescriptorError::InvalidLink;
            }
            // A link update must not launder a forged empty/partial pointer
            // block merely because its checksum was recalculated. Rate and
            // power fields are excluded from the pointer checksum.
            if (!validTxPointerDescriptor(descriptor))
            {
                return DescriptorError::InvalidDescriptor;
            }
            // Link updates do not require rewriting rate/power control words.
            descriptor.word[K_LINK_INDEX] = nextDescriptorBusAddress;
            descriptor.word[K_CHECKSUM_INDEX] =
                (descriptor.word[K_CHECKSUM_INDEX] & K_HIGH_HALF_MASK) |
                txPointerChecksum(descriptor);
            return DescriptorError::Ok;
        }

        DescriptorError decodeRxStatus(const RxStatusWords &raw, RxStatus &out)
        {
            // Never clear an output that aliases a DMA-visible status ring.
            // That contract failure leaves both input and output untouched.
            if (overlaps_storage(&raw, sizeof(raw), &out, sizeof(out)))
            {
                return DescriptorError::OverlappingBuffers;
            }
            // A caller must never reuse a prior completed payload/status after
            // this read fails; diagnostic bits remain in the raw words.
            out = {};
            const uint32_t info = raw.word[K_RX_INFO_WORD];
            const uint32_t flags = raw.word[K_RX_FLAGS_WORD];
            if ((info & K_HIGH_HALF_MASK) != K_VENDOR)
            {
                return DescriptorError::InvalidVendor;
            }
            if ((info & K_TX_DESCRIPTOR_BITS) != 0)
            {
                return DescriptorError::CorruptStatus;
            }
            if ((flags & K_RX_COMPLETE) == 0)
            {
                return DescriptorError::Incomplete;
            }

            RxStatus status {};
            status.completed = true;
            status.frameLength = static_cast<uint16_t>(
                raw.word[K_RX_LENGTH_WORD] & K_RX_LENGTH_MASK);
            status.moreFragments =
                (raw.word[K_RX_LENGTH_WORD] & K_RX_MORE_FRAGMENTS) != 0;
            status.timestamp = raw.word[K_RX_TIMESTAMP_WORD];
            status.ht40 = (raw.word[K_RX_HT_WORD] & K_RX_HT40) != 0;
            status.combinedRssi = static_cast<int8_t>(
                (raw.word[K_RX_RSSI_WORD] >> K_RX_BYTE_SHIFT) &
                K_INFO_LENGTH_MASK);
            status.rateCode = static_cast<uint8_t>(
                (raw.word[K_RX_RATE_WORD] >> K_RX_BYTE_SHIFT) &
                K_INFO_LENGTH_MASK);
            status.crcError = (flags & K_RX_CRC_ERROR) != 0;
            status.decryptError = (flags & K_RX_DECRYPT_ERROR) != 0;
            status.phyError = (flags & K_RX_PHY_ERROR) != 0;
            status.micError = (flags & K_RX_MIC_ERROR) != 0;
            status.aggregationContinues =
                (flags & K_RX_AGGREGATION_CONTINUES) != 0;
            status.aggregated = (flags & K_RX_AGGREGATED) != 0;
            status.aggregationFirst = (flags & K_RX_AGGREGATION_FIRST) != 0;
            status.keyMiss = (flags & K_RX_KEY_MISS) != 0;
            status.frameValid = (flags & K_RX_FRAME_VALID) != 0 &&
                                !status.crcError && !status.decryptError &&
                                !status.phyError && !status.micError &&
                                !status.keyMiss;
            if (!status.frameValid || status.frameLength == 0)
            {
                return DescriptorError::ReceiveError;
            }
            out = status;
            return DescriptorError::Ok;
        }

    } // namespace edma
} // namespace simpleath
