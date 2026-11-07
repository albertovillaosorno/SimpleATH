// SPDX-License-Identifier: AGPL-3.0-only
#include "Ar9003Dma.hpp"
#include <stdint.h>

namespace simpleath
{
    namespace dma
    {

        Error validateMapping(const Mapping &mapping, size_t requiredBytes)
        {
            if (!mapping.cpuAddress || mapping.length == 0 ||
                requiredBytes == 0)
                return Error::MissingBuffer;
            if (!mapping.iommuMapped)
                return Error::UnmappedBuffer;
            if (!mapping.synchronized)
                return Error::NotSynchronized;
            if (mapping.deviceBusAddress == 0 ||
                mapping.deviceBusAddress > 0xffffffffull)
                return Error::AddressTooHigh;
            if (requiredBytes > mapping.length)
                return Error::InsufficientLength;
            if (requiredBytes - 1u > 0xffffffffull - mapping.deviceBusAddress)
                return Error::AddressOverflow;
            return Error::Ok;
        }

        Error validateDescriptorRing(const Mapping &mapping,
                                     size_t descriptorBytes, size_t count,
                                     size_t alignment)
        {
            if (descriptorBytes == 0 || count == 0 ||
                count > TxRing::kMaximumSlots || alignment == 0 ||
                (alignment & (alignment - 1u)) != 0 ||
                descriptorBytes > static_cast<size_t>(0xffffffffu) / count)
                return Error::InvalidCount;
            const size_t required = descriptorBytes * count;
            Error result = validateMapping(mapping, required);
            if (result != Error::Ok)
                return result;
            if (mapping.direction != Direction::ToDevice ||
                (mapping.deviceBusAddress & (alignment - 1u)) != 0 ||
                (reinterpret_cast<uintptr_t>(mapping.cpuAddress) &
                 (alignment - 1u)) != 0)
                return Error::InvalidAlignment;
            return Error::Ok;
        }

        TxRing::TxRing() : slots_ {}, capacity_(0), active_(0), generation_(0)
        {
        }

        Error TxRing::initialize(size_t numberOfSlots)
        {
            if (numberOfSlots == 0 || numberOfSlots > kMaximumSlots)
                return Error::InvalidCount;
            if (capacity_ != 0)
                return Error::UnexpectedState;
            capacity_ = numberOfSlots;
            for (size_t i = 0; i < kMaximumSlots; ++i)
            {
                slots_[i] = {};
                slots_[i].generation = generation_;
                slots_[i].state = SlotState::Free;
            }
            return Error::Ok;
        }

        Error TxRing::reserve(size_t &slot, uint32_t cookie)
        {
            if (capacity_ == 0)
                return Error::UninitializedRing;
            // Never wrap a token and accidentally match an old completion.
            // Recreate the ring owner after complete DMA/callback teardown if
            // exhausted.
            if (generation_ == 0xffffffffu)
                return Error::GenerationExhausted;
            for (size_t i = 0; i < capacity_; ++i)
            {
                if (slots_[i].state != SlotState::Free)
                    continue;
                slots_[i].state = SlotState::Reserved;
                slots_[i].generation = ++generation_;
                slots_[i].cookie = cookie;
                slots_[i].dmaMapped = false;
                slots_[i].descriptorCompleted = false;
                ++active_;
                slot = i;
                return Error::Ok;
            }
            return Error::RingFull;
        }

        Error TxRing::descriptorPrepared(size_t slot, bool dmaMapped,
                                         bool complete)
        {
            if (slot >= capacity_)
                return Error::InvalidSlot;
            if (slots_[slot].state != SlotState::Reserved)
                return Error::UnexpectedState;
            if (!dmaMapped || !complete)
                return Error::NotReadyToTransmit;
            slots_[slot].dmaMapped = true;
            slots_[slot].descriptorCompleted = true;
            slots_[slot].state = SlotState::ReadyForHardware;
            return Error::Ok;
        }

        Error TxRing::handedToHardware(size_t slot, bool radioCalibrated,
                                       bool channelAllowed, bool keysReady)
        {
            if (slot >= capacity_)
                return Error::InvalidSlot;
            if (slots_[slot].state != SlotState::ReadyForHardware)
                return Error::UnexpectedState;
            if (!slots_[slot].dmaMapped || !slots_[slot].descriptorCompleted ||
                !radioCalibrated || !channelAllowed || !keysReady)
                return Error::NotReadyToTransmit;
            // External PCI backend alone can execute a hardware doorbell.
            slots_[slot].state = SlotState::OwnedByHardware;
            return Error::Ok;
        }

        Error TxRing::complete(size_t slot, uint32_t cookie,
                               uint32_t generation)
        {
            if (slot >= capacity_)
                return Error::InvalidSlot;
            if (slots_[slot].state != SlotState::OwnedByHardware ||
                slots_[slot].cookie != cookie ||
                slots_[slot].generation != generation)
                return Error::UnexpectedState;
            slots_[slot].state = SlotState::Completed;
            return Error::Ok;
        }

        Error TxRing::release(size_t slot)
        {
            if (slot >= capacity_)
                return Error::InvalidSlot;
            if (slots_[slot].state != SlotState::Completed &&
                slots_[slot].state != SlotState::Reserved &&
                slots_[slot].state != SlotState::ReadyForHardware)
                return Error::UnexpectedState;
            slots_[slot] = {};
            slots_[slot].generation = generation_;
            slots_[slot].state = SlotState::Free;
            if (active_)
                --active_;
            return Error::Ok;
        }

        void TxRing::reset()
        {
            // The platform MUST stop hardware DMA and reclaim buffers before
            // reset.
            capacity_ = 0;
            active_ = 0;
            // Preserve the reservation-token sequence across
            // reset/reinitialization.
            for (size_t i = 0; i < kMaximumSlots; ++i)
                slots_[i] = {};
        }

        const RingSlot *TxRing::slot(size_t index) const
        {
            return index < capacity_ ? &slots_[index] : nullptr;
        }

    } // namespace dma
} // namespace simpleath
