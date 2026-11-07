// SPDX-License-Identifier: AGPL-3.0-only
// DMA validation and ring ownership metadata for AR9003/AR9565.
// The platform's PCI owner supplies actual DMA mappings, memory barriers,
// interrupt acknowledgements, and hardware queue programming.
#ifndef SIMPLEATH_AR9003_DMA_HPP
#define SIMPLEATH_AR9003_DMA_HPP

#include "Ar9003Descriptors.hpp"
#include <stddef.h>
#include <stdint.h>

namespace simpleath {
namespace dma {

enum class Error : uint8_t {
    Ok,
    MissingBuffer,
    UnmappedBuffer,
    NotSynchronized,
    AddressTooHigh,
    AddressOverflow,
    InsufficientLength,
    InvalidAlignment,
    InvalidCount,
    UninitializedRing,
    RingFull,
    InvalidSlot,
    UnexpectedState,
    NotReadyToTransmit,
    GenerationExhausted
};

enum class Direction : uint8_t { ToDevice, FromDevice };

struct Mapping {
    void *cpuAddress;
    uint64_t deviceBusAddress;
    size_t length;
    Direction direction;
    // True only after the platform's DMA API has made a valid IOMMU mapping.
    bool iommuMapped;
    // True only after the correct cache maintenance / write or read barrier.
    bool synchronized;
};

Error validateMapping(const Mapping &mapping, size_t requiredBytes);
Error validateDescriptorRing(const Mapping &mapping, size_t descriptorBytes,
                             size_t count, size_t alignment);

enum class SlotState : uint8_t {
    Free,
    Reserved,
    ReadyForHardware,
    OwnedByHardware,
    Completed
};

struct RingSlot {
    SlotState state;
    uint32_t generation;
    uint32_t cookie;
    bool dmaMapped;
    bool descriptorCompleted;
};

// Pure metadata machine; does not publish descriptors, set DMA pointers,
// enable interrupts or enable TX. An owner must serialize every method call.
class TxRing {
public:
    enum : size_t { kMaximumSlots = 64 };
    TxRing();
    Error initialize(size_t numberOfSlots);
    Error reserve(size_t &slot, uint32_t cookie);
    Error descriptorPrepared(size_t slot, bool dmaMapped, bool complete);
    Error handedToHardware(size_t slot, bool radioCalibrated,
                           bool channelAllowed, bool keysReady);
    // Capture slot(slotIndex)->generation at reservation time and carry it
    // through completion handling. A reused cookie alone cannot identify DMA.
    Error complete(size_t slot, uint32_t cookie, uint32_t generation);
    Error release(size_t slot);
    void reset();
    size_t active() const { return active_; }
    size_t capacity() const { return capacity_; }
    const RingSlot *slot(size_t index) const;
private:
    RingSlot slots_[kMaximumSlots];
    size_t capacity_;
    size_t active_;
    uint32_t generation_;
};

} // namespace dma
} // namespace simpleath
#endif
