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
        static constexpr uint8_t kHtMcs0 = 0x80U;
        static constexpr uint8_t kHtMcs7 = 0x87U;
        static constexpr uint32_t kVendor = 0x168c0000U;
        static constexpr uint32_t kTxDescriptorBits = 0xc000U;
        static constexpr uint32_t kTxDescriptorDwords =
            0x18U; // AR9565; other AR9003 = 0x17.
        static constexpr uint32_t kBufferLengthMask = 0x0fffU;
        static constexpr uint32_t kValidQueueMax = 9U;
        static constexpr uint32_t kTxInfoIndex = 0U;
        static constexpr uint32_t kLinkIndex = 1U;
        static constexpr uint32_t kChecksumIndex = 10U;
        static constexpr uint32_t kSegmentCount = 4U;
        static constexpr uint32_t kSegmentAddressIndex = 2U;
        static constexpr uint32_t kSegmentLengthIndex = 3U;
        static constexpr uint32_t kSegmentStride = 2U;
        static constexpr uint32_t kLowHalfMask = 0xffffU;
        static constexpr uint32_t kHighHalfMask = 0xffff0000U;
        static constexpr uint32_t kReservedTypeMask = 0x3000U;
        static constexpr uint32_t kInfoLengthMask = 0xffU;
        static constexpr uint32_t kQueueShift = 8U;
        static constexpr uint32_t kQueueMask = 0x0fU;
        static constexpr uint32_t kBusAlignmentMask = 3U;
        static constexpr uint32_t kLengthShift = 16U;
        static constexpr uint64_t kMaxBusAddress = 0xffffffffULL;
        // AR9003 RX status word positions and versioned silicon bit fields.
        static constexpr uint32_t kRxInfoWord = 0U;
        static constexpr uint32_t kRxRateWord = 1U;
        static constexpr uint32_t kRxLengthWord = 2U;
        static constexpr uint32_t kRxTimestampWord = 3U;
        static constexpr uint32_t kRxHtWord = 4U;
        static constexpr uint32_t kRxRssiWord = 5U;
        static constexpr uint32_t kRxFlagsWord = 11U;
        static constexpr uint32_t kRxLengthMask = 0x0fffU;
        // Shortest permitted received 802.11 control MPDU is an ACK/CTS:
        // 10 MAC octets plus 4 received FCS octets. Longer data/management
        // headers are checked by their separate downstream MAC parser.
        static constexpr uint32_t kRxMinMpduBytes = 14U;
        static constexpr uint32_t kRxMaxSingleMpduBytes = 2346U;
        static constexpr uint32_t kRxMoreFragments = 0x1000U;
        static constexpr uint32_t kRxHt40 = 0x2U;
        static constexpr uint32_t kRxByteShift = 24U;
        static constexpr uint32_t kRxComplete = 0x1U;
        static constexpr uint32_t kRxFrameValid = 0x2U;
        static constexpr uint32_t kRxCrcError = 0x4U;
        static constexpr uint32_t kRxDecryptError = 0x8U;
        static constexpr uint32_t kRxPhyError = 0x10U;
        static constexpr uint32_t kRxMicError = 0x20U;
        static constexpr uint32_t kRxAggregationContinues = 0x00010000U;
        static constexpr uint32_t kRxAggregated = 0x00020000U;
        static constexpr uint32_t kRxAggregationFirst = 0x20000000U;
        static constexpr uint32_t kRxKeyMiss = 0x80000000U;

        // A short fixed-index descriptor access remains bounded by the
        // physical C-array extent, without changing its binary DMA layout.
        template <typename T, size_t N>
        static T &boundedElement(T (&items)[N], size_t index)
        {
            for (T &element : items)
            {
                if (index == 0)
                {
                    return element;
                }
                --index;
            }
            __builtin_trap(); // Unreachable after segment-count checks.
        }

        static uintptr_t pointerAddress(const void *pointer)
        {
            static_assert(sizeof(uintptr_t) == sizeof(pointer),
                          "platform pointer and address widths must agree");
            uintptr_t result = 0;
            __builtin_memcpy(&result, static_cast<const void *>(&pointer),
                             sizeof(pointer));
            return result;
        }

        // Reject caller-forged overlapping input/output storage before
        // any write; raw status can belong to a DMA-visible ring.
        static bool overlapsStorage(const void *const first, size_t firstBytes,
                                    const void *const second,
                                    size_t secondBytes)
        {
            if (first == nullptr || second == nullptr || firstBytes == 0 ||
                secondBytes == 0)
            {
                return false;
            }
            const uintptr_t left = pointerAddress(first);
            const uintptr_t right = pointerAddress(second);
            return left >= right ? left - right < secondBytes
                                 : right - left < firstBytes;
        }

        static constexpr uint8_t kCck1Mb = 0x1bU;
        static constexpr uint8_t kCck2MbLong = 0x1aU;
        static constexpr uint8_t kCck5p5MbLong = 0x19U;
        static constexpr uint8_t kCck2MbShort = 0x1eU;
        static constexpr uint8_t kCck5p5MbShort = 0x1dU;
        static constexpr uint8_t kCck11MbLong = 0x18U;
        static constexpr uint8_t kCck11MbShort = 0x1cU;
        static constexpr uint8_t kOfdm6Mb = 0x0bU;
        static constexpr uint8_t kOfdm9Mb = 0x0fU;
        static constexpr uint8_t kOfdm12Mb = 0x0aU;
        static constexpr uint8_t kOfdm18Mb = 0x0eU;
        static constexpr uint8_t kOfdm24Mb = 0x09U;
        static constexpr uint8_t kOfdm36Mb = 0x0dU;
        static constexpr uint8_t kOfdm48Mb = 0x08U;
        static constexpr uint8_t kOfdm54Mb = 0x0cU;

        bool supportedAr9565LegacyRate(uint8_t code)
        {
            switch (code)
            {
                case kCck1Mb:
                case kCck2MbLong:
                case kCck5p5MbLong:
                case kCck2MbShort:
                case kCck5p5MbShort:
                case kCck11MbLong:
                case kCck11MbShort:
                case kOfdm6Mb:
                case kOfdm9Mb:
                case kOfdm12Mb:
                case kOfdm18Mb:
                case kOfdm24Mb:
                case kOfdm36Mb:
                case kOfdm48Mb:
                case kOfdm54Mb:
                    return true;
                default:
                    return false;
            }
        }

        // AR9565 is 1x1 on 2.4 GHz: only legacy rates and HT MCS0..7.
        static bool supportedRxRate(uint8_t code)
        {
            return (code >= kHtMcs0 && code <= kHtMcs7) ||
                   supportedAr9565LegacyRate(code);
        }

        uint16_t txPointerChecksum(const TxDescriptor &descriptor)
        {
            // Sum exactly the AR9003 pointer fields, with unsigned 32-bit wrap.
            // Same layout as ar9003_mac.c, but independent implementation.
            uint32_t sum =
                descriptor.word[kTxInfoIndex] + descriptor.word[kLinkIndex];
            for (size_t slot = 0; slot < kSegmentCount; ++slot)
            {
                sum += boundedElement(descriptor.word,
                                      kSegmentAddressIndex +
                                          (slot * kSegmentStride));
                sum += boundedElement(descriptor.word,
                                      kSegmentLengthIndex +
                                          (slot * kSegmentStride));
            }
            const uint32_t folded =
                (sum & kLowHalfMask) + (sum >> kLengthShift);
            return static_cast<uint16_t>(folded & kLowHalfMask);
        }

        bool validTxPointerDescriptor(const TxDescriptor &descriptor)
        {
            const uint32_t info = descriptor.word[kTxInfoIndex];
            if ((info & kHighHalfMask) != kVendor ||
                (info & kTxDescriptorBits) != kTxDescriptorBits ||
                (info & kReservedTypeMask) != 0 ||
                (info & kInfoLengthMask) != kTxDescriptorDwords ||
                ((info >> kQueueShift) & kQueueMask) > kValidQueueMax ||
                (descriptor.word[kLinkIndex] & kBusAlignmentMask) != 0)
            {
                return false;
            }

            // The pointer codec only emits contiguous, nonempty segments.
            // A matching checksum is not evidence that a caller-constructed
            // descriptor contains even one mapped payload segment.
            bool foundSegment = false;
            bool foundGap = false;
            for (size_t index = 0; index < kSegmentCount; ++index)
            {
                const uint32_t address = boundedElement(
                    descriptor.word,
                    kSegmentAddressIndex + (index * kSegmentStride));
                const uint32_t encoded = boundedElement(
                    descriptor.word,
                    kSegmentLengthIndex + (index * kSegmentStride));
                if (address == 0 && encoded == 0)
                {
                    foundGap = true;
                    continue;
                }
                const uint32_t length = encoded >> kLengthShift;
                if (foundGap || address == 0 || length == 0 ||
                    length > kBufferLengthMask ||
                    encoded != (length << kLengthShift) ||
                    length - 1U >
                        static_cast<uint32_t>(kMaxBusAddress) - address)
                {
                    return false;
                }
                foundSegment = true;
            }
            return foundSegment &&
                   (descriptor.word[kChecksumIndex] & kLowHalfMask) ==
                       txPointerChecksum(descriptor);
        }

        DescriptorError encodeTxPointers(const TxPointerBlock &input,
                                         TxDescriptor &out)
        {
            if (overlapsStorage(&input, sizeof(input), &out, sizeof(out)))
            {
                return DescriptorError::OverlappingBuffers;
            }
            if (input.queue > kValidQueueMax)
            {
                return DescriptorError::InvalidQueue;
            }
            if (input.segmentCount == 0 || input.segmentCount > kSegmentCount)
            {
                return DescriptorError::InvalidSegmentCount;
            }
            if (input.nextDescriptorBusAddress != 0 &&
                (input.nextDescriptorBusAddress & kBusAlignmentMask) != 0)
            {
                return DescriptorError::InvalidLink;
            }

            TxDescriptor staged {};
            staged.word[kTxInfoIndex] =
                kVendor | kTxDescriptorBits |
                (static_cast<uint32_t>(input.queue) << kQueueShift) |
                kTxDescriptorDwords;
            staged.word[kLinkIndex] = input.nextDescriptorBusAddress;

            for (uint8_t index = 0; index < input.segmentCount; ++index)
            {
                const Segment &segment = boundedElement(input.segment, index);
                if (segment.busAddress == 0 ||
                    segment.busAddress > kMaxBusAddress)
                {
                    return DescriptorError::InvalidAddress;
                }
                if (segment.length == 0 || segment.length > kBufferLengthMask)
                {
                    return DescriptorError::InvalidLength;
                }
                if (segment.length - 1U > kMaxBusAddress - segment.busAddress)
                {
                    return DescriptorError::InvalidAddress;
                }
                boundedElement(staged.word, kSegmentAddressIndex +
                                                (index * kSegmentStride)) =
                    static_cast<uint32_t>(segment.busAddress);
                boundedElement(staged.word,
                               kSegmentLengthIndex + (index * kSegmentStride)) =
                    static_cast<uint32_t>(segment.length) << kLengthShift;
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
                (nextDescriptorBusAddress & kBusAlignmentMask) != 0)
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
            descriptor.word[kLinkIndex] = nextDescriptorBusAddress;
            descriptor.word[kChecksumIndex] =
                (descriptor.word[kChecksumIndex] & kHighHalfMask) |
                txPointerChecksum(descriptor);
            return DescriptorError::Ok;
        }

        DescriptorError decodeRxStatus(const RxStatusWords &raw, RxStatus &out)
        {
            // Never clear an output that aliases a DMA-visible status ring.
            // That contract failure leaves both input and output untouched.
            if (overlapsStorage(&raw, sizeof(raw), &out, sizeof(out)))
            {
                return DescriptorError::OverlappingBuffers;
            }
            // A caller must never reuse a prior completed payload/status after
            // this read fails; diagnostic bits remain in the raw words.
            out = {};
            const uint32_t info = raw.word[kRxInfoWord];
            const uint32_t flags = raw.word[kRxFlagsWord];
            if ((info & kHighHalfMask) != kVendor)
            {
                return DescriptorError::InvalidVendor;
            }
            if ((info & kTxDescriptorBits) != 0)
            {
                return DescriptorError::CorruptStatus;
            }
            if ((flags & kRxComplete) == 0)
            {
                return DescriptorError::Incomplete;
            }

            RxStatus status {};
            status.completed = true;
            status.frameLength =
                static_cast<uint16_t>(raw.word[kRxLengthWord] & kRxLengthMask);
            status.moreFragments =
                (raw.word[kRxLengthWord] & kRxMoreFragments) != 0;
            status.timestamp = raw.word[kRxTimestampWord];
            status.ht40 = (raw.word[kRxHtWord] & kRxHt40) != 0;
            status.combinedRssi = static_cast<int8_t>(
                (raw.word[kRxRssiWord] >> kRxByteShift) & kInfoLengthMask);
            status.rateCode = static_cast<uint8_t>(
                (raw.word[kRxRateWord] >> kRxByteShift) & kInfoLengthMask);
            status.crcError = (flags & kRxCrcError) != 0;
            status.decryptError = (flags & kRxDecryptError) != 0;
            status.phyError = (flags & kRxPhyError) != 0;
            status.micError = (flags & kRxMicError) != 0;
            status.aggregationContinues =
                (flags & kRxAggregationContinues) != 0;
            status.aggregated = (flags & kRxAggregated) != 0;
            status.aggregationFirst = (flags & kRxAggregationFirst) != 0;
            status.keyMiss = (flags & kRxKeyMiss) != 0;
            status.frameValid = (flags & kRxFrameValid) != 0 &&
                                !status.crcError && !status.decryptError &&
                                !status.phyError && !status.micError &&
                                !status.keyMiss;
            // AR_RxMore is a chained DMA buffer, not an 802.11 MAC
            // fragment. There is no RX-chain, A-MPDU deaggregation/reorder
            // or BlockAck path here. Even a valid per-MPDU CRC cannot
            // authorize an aggregate's first, middle or last member for
            // native delivery without that independently reviewed pipeline.
            // The 12-bit length field cannot authorize jumbo MPDUs either.
            if (!status.frameValid || status.frameLength < kRxMinMpduBytes ||
                status.frameLength > kRxMaxSingleMpduBytes ||
                !supportedRxRate(status.rateCode) ||
                (status.ht40 && status.rateCode < kHtMcs0) ||
                status.moreFragments || status.aggregated ||
                status.aggregationContinues || status.aggregationFirst)
            {
                return DescriptorError::ReceiveError;
            }
            out = status;
            return DescriptorError::Ok;
        }

    } // namespace edma
} // namespace simpleath
