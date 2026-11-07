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

namespace simpleath
{
    namespace edma
    {
        namespace
        {
            constexpr uint32_t kVendor = 0x168c0000u;
            constexpr uint32_t kTxDescriptorBits = 0xc000u;
            constexpr uint32_t kTxDescriptorDwords =
                0x18u; // AR9565; other AR9003 = 0x17.
            constexpr uint32_t kBufferLengthMask = 0x0fffu;
            constexpr uint32_t kValidQueueMax = 9u;
            constexpr uint32_t kTxInfoIndex = 0u;
            constexpr uint32_t kLinkIndex = 1u;
            constexpr uint32_t kChecksumIndex = 10u;
        } // namespace

        uint16_t txPointerChecksum(const TxDescriptor &descriptor)
        {
            // Sum exactly the AR9003 pointer fields, with unsigned 32-bit wrap.
            // Same layout as ar9003_mac.c, but independent implementation.
            uint32_t sum =
                descriptor.word[kTxInfoIndex] + descriptor.word[kLinkIndex];
            for (size_t slot = 0; slot < 4; ++slot)
            {
                sum += descriptor.word[2 + slot * 2];
                sum += descriptor.word[3 + slot * 2];
            }
            const uint32_t folded = (sum & 0xffffu) + (sum >> 16u);
            return static_cast<uint16_t>(folded & 0xffffu);
        }

        DescriptorError encodeTxPointers(const TxPointerBlock &input,
                                         TxDescriptor &out)
        {
            if (input.queue > kValidQueueMax)
                return DescriptorError::InvalidQueue;
            if (input.segmentCount == 0 || input.segmentCount > 4)
                return DescriptorError::InvalidSegmentCount;
            if (input.nextDescriptorBusAddress != 0 &&
                (input.nextDescriptorBusAddress & 3u) != 0)
                return DescriptorError::InvalidLink;

            TxDescriptor staged {};
            staged.word[kTxInfoIndex] =
                kVendor | kTxDescriptorBits |
                (static_cast<uint32_t>(input.queue) << 8u) |
                kTxDescriptorDwords;
            staged.word[kLinkIndex] = input.nextDescriptorBusAddress;

            for (uint8_t index = 0; index < input.segmentCount; ++index)
            {
                const Segment &segment = input.segment[index];
                if (segment.busAddress == 0 ||
                    segment.busAddress > 0xffffffffull)
                    return DescriptorError::InvalidAddress;
                if (segment.length == 0 || segment.length > kBufferLengthMask)
                    return DescriptorError::InvalidLength;
                if (segment.length - 1u > 0xffffffffull - segment.busAddress)
                    return DescriptorError::InvalidAddress;
                staged.word[2 + index * 2] =
                    static_cast<uint32_t>(segment.busAddress);
                staged.word[3 + index * 2] =
                    static_cast<uint32_t>(segment.length) << 16u;
            }
            staged.word[kChecksumIndex] = txPointerChecksum(staged);
            // Caller must serialize this copy; it is not an atomic DMA
            // publication.
            out = staged;
            return DescriptorError::Ok;
        }

        DescriptorError setNextTxDescriptor(TxDescriptor &descriptor,
                                            uint32_t nextDescriptorBusAddress)
        {
            if (nextDescriptorBusAddress != 0 &&
                (nextDescriptorBusAddress & 3u) != 0)
                return DescriptorError::InvalidLink;
            // A link update must not launder an uninitialized, stale or
            // checksum-corrupt descriptor into something apparently valid.
            // Pointer checksums exclude the rate/power control fields.
            const uint32_t info = descriptor.word[kTxInfoIndex];
            if ((info & 0xffff0000u) != kVendor ||
                (info & kTxDescriptorBits) != kTxDescriptorBits ||
                (info & 0xffu) != kTxDescriptorDwords ||
                ((info >> 8u) & 0x0fu) > kValidQueueMax ||
                (descriptor.word[kChecksumIndex] & 0xffffu) !=
                    txPointerChecksum(descriptor))
                return DescriptorError::InvalidDescriptor;
            // Link updates do not require rewriting rate/power control words.
            descriptor.word[kLinkIndex] = nextDescriptorBusAddress;
            descriptor.word[kChecksumIndex] =
                (descriptor.word[kChecksumIndex] & 0xffff0000u) |
                txPointerChecksum(descriptor);
            return DescriptorError::Ok;
        }

        DescriptorError decodeRxStatus(const RxStatusWords &raw, RxStatus &out)
        {
            // A caller must never reuse a prior completed payload/status after
            // this read fails; diagnostic bits remain in the raw words.
            out = {};
            const uint32_t info = raw.word[0];
            const uint32_t flags = raw.word[11];
            if ((info & 0xffff0000u) != kVendor)
                return DescriptorError::InvalidVendor;
            if ((info & kTxDescriptorBits) != 0)
                return DescriptorError::CorruptStatus;
            if ((flags & 1u) == 0)
                return DescriptorError::Incomplete;

            RxStatus status {};
            status.completed = true;
            status.frameLength = static_cast<uint16_t>(raw.word[2] & 0x0fffu);
            status.moreFragments = (raw.word[2] & 0x1000u) != 0;
            status.timestamp = raw.word[3];
            status.ht40 = (raw.word[4] & 0x2u) != 0;
            status.combinedRssi =
                static_cast<int8_t>((raw.word[5] >> 24u) & 0xffu);
            status.rateCode =
                static_cast<uint8_t>((raw.word[1] >> 24u) & 0xffu);
            status.crcError = (flags & 0x4u) != 0;
            status.decryptError = (flags & 0x8u) != 0;
            status.phyError = (flags & 0x10u) != 0;
            status.micError = (flags & 0x20u) != 0;
            status.aggregationContinues = (flags & 0x00010000u) != 0;
            status.aggregated = (flags & 0x00020000u) != 0;
            status.aggregationFirst = (flags & 0x20000000u) != 0;
            status.keyMiss = (flags & 0x80000000u) != 0;
            status.frameValid = (flags & 0x2u) != 0 && !status.crcError &&
                                !status.decryptError && !status.phyError &&
                                !status.micError && !status.keyMiss;
            if (!status.frameValid || status.frameLength == 0)
                return DescriptorError::ReceiveError;
            out = status;
            return DescriptorError::Ok;
        }

    } // namespace edma
} // namespace simpleath
