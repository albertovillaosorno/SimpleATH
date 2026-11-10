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
// AR9003 EDMA descriptor layout, referencing Linux ath9k ar9003_mac.h.
// This portable descriptor codec is NOT an active DMA transport.
#ifndef SIMPLEATH_AR9003_DESCRIPTORS_HPP
#define SIMPLEATH_AR9003_DESCRIPTORS_HPP

#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    namespace edma
    {

        // AR9565 (AR9003) TX control descriptors use 32 x 32-bit words.
        // The descriptor is naturally aligned for cacheline-sized DMA
        // allocation. The future platform backend still must perform mapping
        // and cache coherence.
        constexpr size_t kTxDescriptorBytes = 128U;
        constexpr size_t kTxDescriptorWordCount =
            kTxDescriptorBytes / sizeof(uint32_t);
        constexpr size_t kRxStatusBytes = 48U;
        constexpr size_t kRxStatusWordCount = kRxStatusBytes / sizeof(uint32_t);

        struct alignas(kTxDescriptorBytes) TxDescriptor
        {
                uint32_t word[kTxDescriptorWordCount];
        };

        struct RxStatusWords
        {
                uint32_t word[kRxStatusWordCount];
        };

        static_assert(sizeof(TxDescriptor) == kTxDescriptorBytes,
                      "AR9003 TX descriptor is 128 bytes");
        static_assert(alignof(TxDescriptor) >= kTxDescriptorBytes,
                      "TX descriptor alignment");
        static_assert(sizeof(RxStatusWords) == kRxStatusBytes,
                      "AR9003 EDMA RX status is 48 bytes");

        enum class DescriptorError : uint8_t
        {
            Ok,
            InvalidQueue,
            InvalidSegmentCount,
            InvalidAddress,
            InvalidLength,
            InvalidLink,
            Incomplete,
            InvalidVendor,
            CorruptStatus,
            ReceiveError,
            InvalidDescriptor,
            OverlappingBuffers,
        };

        struct Segment
        {
                // I/O virtual bus address from a mapped DMA command, NOT a host
                // pointer. No raw physical-address fallback. AR9003 descriptor
                // addresses are 32-bit; a 64-bit host address must never be
                // truncated.
                uint64_t busAddress;
                uint16_t length;
        };

        struct TxPointerBlock
        {
                Segment segment[4];
                uint8_t segmentCount;
                uint8_t queue;
                uint32_t nextDescriptorBusAddress;
        };

        // Only encodes the pointer/checksum part of an AR9565 TX descriptor.
        // It does NOT create the rate/power/encryption/duration/aggregation
        // control words or a DMA mapping. NEVER submit this descriptor to the
        // device. The output must not overlap input; an alias is rejected
        // without writes to either buffer.
        DescriptorError encodeTxPointers(const TxPointerBlock &input,
                                         TxDescriptor &out);
        // Validate the canonical pointer fields independently of their
        // checksum. Does not prove IOMMU mapping, DMA ownership or TX safety.
        bool validTxPointerDescriptor(const TxDescriptor &descriptor);
        // Checks the full pointer block, queue and checksum before touching
        // the link. A corrupt descriptor stays unchanged.
        DescriptorError setNextTxDescriptor(TxDescriptor &descriptor,
                                            uint32_t nextDescriptorBusAddress);
        uint16_t txPointerChecksum(const TxDescriptor &descriptor);

        // Keep RX and TX legacy CCK/OFDM modulation admission identical.
        bool supportedAr9565LegacyRate(uint8_t code);

        struct RxStatus
        {
                bool completed;
                bool frameValid;
                bool crcError;
                bool decryptError;
                bool micError;
                bool phyError;
                bool keyMiss;
                bool moreFragments;
                bool aggregated;
                bool aggregationFirst;
                bool aggregationContinues;
                bool ht40;
                uint16_t frameLength;
                uint8_t rateCode;
                int8_t combinedRssi;
                uint32_t timestamp;
        };

        // The last native PCI callback boundary must recheck the complete
        // decoded RX status and the exact DMA span, even when its producer
        // already called decodeRxStatus(). Prevent stale or fabricated status
        // from entering scan/AWDL, association or OS-owned WPA2 processing.
        // This does not establish a live radio, valid channel or key state.
        bool admissibleRxMpdu(const RxStatus &status, size_t dmaBytes);

        // Caller must first synchronize DMA and verify a complete status write.
        // This only decodes status; it does not read payloads or acknowledge
        // IRQs. AR_RxMore marks an incomplete chained DMA buffer and is
        // rejected: there is no RX-chain reassembly here. The future owner
        // must also suppress orphaned tail buffers after a rejected chain;
        // an isolated last descriptor cannot reveal prior chain membership.
        // RX statuses with A-MPDU membership/continuation flags are rejected
        // until a separately reviewed BlockAck/deaggregation/reorder path is
        // available; a valid per-buffer CRC is not aggregate admission.
        // A single RX status longer than the 2346-byte MPDU ceiling is also
        // rejected. RX modulation must be a supported AR9565 legacy rate or
        // single-stream HT MCS0..7; an HT40 indication on a legacy rate is
        // invalid. Caller still proves actual PHY/RX/FCS and DMA integrity.
        // Ordinary errors clear out. An alias with the raw status instead
        // fails without writing into DMA-visible source storage.
        DescriptorError decodeRxStatus(const RxStatusWords &raw, RxStatus &out);

    } // namespace edma
} // namespace simpleath
#endif
