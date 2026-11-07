// SPDX-License-Identifier: AGPL-3.0-only
// AR9003 EDMA descriptor layout, referencing Linux ath9k ar9003_mac.h.
// This portable descriptor codec is NOT an active DMA transport.
#ifndef SIMPLEATH_AR9003_DESCRIPTORS_HPP
#define SIMPLEATH_AR9003_DESCRIPTORS_HPP

#include <stddef.h>
#include <stdint.h>

namespace simpleath {
namespace edma {

// AR9565 (AR9003) TX control descriptors use 32 x 32-bit words.
// The descriptor is naturally aligned for cacheline-sized DMA allocation.
// The future platform backend still must perform mapping and cache coherence.
struct alignas(128) TxDescriptor {
    uint32_t word[32];
};
struct RxStatusWords {
    uint32_t word[12];
};
static_assert(sizeof(TxDescriptor) == 128, "AR9003 TX descriptor is 128 bytes");
static_assert(alignof(TxDescriptor) >= 128, "TX descriptor alignment");
static_assert(sizeof(RxStatusWords) == 48, "AR9003 EDMA RX status is 48 bytes");

enum class DescriptorError : uint8_t {
    Ok,
    InvalidQueue,
    InvalidSegmentCount,
    InvalidAddress,
    InvalidLength,
    InvalidLink,
    Incomplete,
    InvalidVendor,
    CorruptStatus,
    ReceiveError
};

struct Segment {
    // I/O virtual bus address from a mapped DMA command, NOT a host pointer.
    // No raw physical-address fallback. AR9003 descriptor
    // addresses are 32-bit; a 64-bit host address must never be truncated.
    uint64_t busAddress;
    uint16_t length;
};
struct TxPointerBlock {
    Segment segment[4];
    uint8_t segmentCount;
    uint8_t queue;
    uint32_t nextDescriptorBusAddress;
};

// Only encodes the pointer/checksum part of an AR9565 TX descriptor.
// It does NOT create the rate/power/encryption/duration/aggregation control
// words or a DMA mapping. NEVER submit this descriptor to the device.
DescriptorError encodeTxPointers(const TxPointerBlock &input, TxDescriptor &out);
DescriptorError setNextTxDescriptor(TxDescriptor &descriptor,
                                    uint32_t nextDescriptorBusAddress);
uint16_t txPointerChecksum(const TxDescriptor &descriptor);

struct RxStatus {
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

// Caller must first synchronize DMA and verify a complete status write.
// This only decodes status; it does not read payloads or acknowledge IRQs.
DescriptorError decodeRxStatus(const RxStatusWords &raw, RxStatus &out);

} // namespace edma
} // namespace simpleath
#endif
