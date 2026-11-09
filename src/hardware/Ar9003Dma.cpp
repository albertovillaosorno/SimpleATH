// SPDX-License-Identifier: AGPL-3.0-only
#include "Ar9003Dma.hpp"
#include <cstddef>
#include <cstdint>

namespace simpleath
{
    namespace dma
    {
        static constexpr uint64_t kDeviceMaxAddress = 0xffffffffULL;
        static constexpr uint32_t kGenerationMax = 0xffffffffU;

        // Do not let a caller-owned output token overwrite live ring metadata.
        // Compare address distances to avoid pointer-end overflow.
        static bool overlapsStorage(const void *first, size_t firstBytes,
                                    const void *second, size_t secondBytes)
        {
            const auto left = reinterpret_cast<uintptr_t>(first);
            const auto right = reinterpret_cast<uintptr_t>(second);
            return firstBytes != 0 && secondBytes != 0 &&
                   (left >= right ? left - right < secondBytes
                                  : right - left < firstBytes);
        }

        Error validateMapping(const Mapping &mapping, size_t requiredBytes)
        {
            if (mapping.cpuAddress == nullptr || mapping.length == 0 ||
                requiredBytes == 0)
            {
                return Error::MissingBuffer;
            }
            // Caller-built DMA mappings cannot point into their own trusted
            // descriptor metadata. Reject even a partial overlap before an
            // owner can hand that span to the IOMMU or hardware.
            if (overlapsStorage(mapping.cpuAddress, mapping.length, &mapping,
                                sizeof(mapping)))
            {
                return Error::AliasedMetadata;
            }
            // A caller-built Mapping can contain an arbitrary enum value.
            // An unknown DMA direction cannot be safely interpreted by the
            // future IOMMU owner, even if other mapping flags claim success.
            if (mapping.direction != Direction::ToDevice &&
                mapping.direction != Direction::FromDevice)
            {
                return Error::InvalidDirection;
            }
            if (!mapping.iommuMapped)
            {
                return Error::UnmappedBuffer;
            }
            if (!mapping.synchronized)
            {
                return Error::NotSynchronized;
            }
            if (mapping.deviceBusAddress == 0 ||
                mapping.deviceBusAddress > kDeviceMaxAddress)
            {
                return Error::AddressTooHigh;
            }
            if (requiredBytes > mapping.length)
            {
                return Error::InsufficientLength;
            }
            // An IOMMU flag does not make a CPU pointer span valid. Reject
            // mappings whose full retained host allocation wraps uintptr_t,
            // before any future caller can add offsets to that pointer.
            const auto hostStart =
                reinterpret_cast<uintptr_t>(mapping.cpuAddress);
            if (mapping.length - 1U > UINTPTR_MAX - hostStart)
            {
                return Error::AddressOverflow;
            }
            // The IOVA describes the entire retained mapping, not just the
            // minimum descriptor prefix. No mapped byte may exceed 32 bits.
            if (mapping.length - 1U >
                kDeviceMaxAddress - mapping.deviceBusAddress)
            {
                return Error::AddressOverflow;
            }
            return Error::Ok;
        }

        Error validateDescriptorRing(const Mapping &mapping,
                                     size_t descriptorBytes, size_t count,
                                     size_t alignment)
        {
            if (descriptorBytes == 0 || count == 0 ||
                count > TxRing::kMaximumSlots || alignment == 0 ||
                (alignment & (alignment - 1U)) != 0 ||
                descriptorBytes >
                    static_cast<size_t>(kDeviceMaxAddress) / count)
            {
                return Error::InvalidCount;
            }
            const size_t required = descriptorBytes * count;
            const Error result = validateMapping(mapping, required);
            if (result != Error::Ok)
            {
                return result;
            }
            // The first descriptor being aligned is not enough: each later
            // descriptor must also begin on the requested bus/CPU boundary.
            if (count > 1 && descriptorBytes % alignment != 0)
            {
                return Error::InvalidAlignment;
            }
            if (mapping.direction != Direction::ToDevice ||
                (mapping.deviceBusAddress & (alignment - 1U)) != 0 ||
                (reinterpret_cast<uintptr_t>(mapping.cpuAddress) &
                 (alignment - 1U)) != 0)
            {
                return Error::InvalidAlignment;
            }
            return Error::Ok;
        }

        TxRing::TxRing() : slots_ {}, capacity_(0), active_(0), generation_(0)
        {
        }

        Error TxRing::initialize(size_t numberOfSlots)
        {
            if (numberOfSlots == 0 || numberOfSlots > kMaximumSlots)
            {
                return Error::InvalidCount;
            }
            if (capacity_ != 0)
            {
                return Error::UnexpectedState;
            }
            capacity_ = numberOfSlots;
            for (RingSlot &slot : slots_)
            {
                slot = {};
                slot.generation = generation_;
                slot.state = SlotState::Free;
            }
            return Error::Ok;
        }

        Error TxRing::reserve(TxSlotToken &token, uint32_t cookie)
        {
            // A forged output alias inside this ring must not wipe ownership
            // metadata when token is cleared or populated.
            if (overlapsStorage(&token, sizeof(token), this, sizeof(*this)))
            {
                return Error::UnexpectedState;
            }
            // A failed reservation must not destroy a previously minted
            // active token when the caller reuses its output storage. New
            // ownership is written only after a free slot is secured.
            if (capacity_ == 0)
            {
                return Error::UninitializedRing;
            }
            // Never wrap a token and accidentally match an old completion.
            // Recreate the ring owner after complete DMA/callback teardown if
            // exhausted.
            if (generation_ == kGenerationMax)
            {
                return Error::GenerationExhausted;
            }
            for (size_t i = 0; i < capacity_; ++i)
            {
                RingSlot &slot = slots_[i];
                if (slot.state != SlotState::Free)
                {
                    continue;
                }
                slot.state = SlotState::Reserved;
                slot.generation = ++generation_;
                slot.cookie = cookie;
                slot.dmaMapped = false;
                slot.descriptorCompleted = false;
                ++active_;
                token = {i, cookie, slot.generation};
                return Error::Ok;
            }
            return Error::RingFull;
        }

        Error TxRing::descriptorPrepared(const TxSlotToken &token,
                                         bool dmaMapped, bool complete)
        {
            if (token.index >= capacity_)
            {
                return Error::InvalidSlot;
            }
            RingSlot &slot = slots_[token.index];
            if (!matches(token) || slot.state != SlotState::Reserved)
            {
                return Error::UnexpectedState;
            }
            if (!dmaMapped || !complete)
            {
                return Error::NotReadyToTransmit;
            }
            slot.dmaMapped = true;
            slot.descriptorCompleted = true;
            slot.state = SlotState::ReadyForHardware;
            return Error::Ok;
        }

        Error TxRing::handedToHardware(const TxSlotToken &token,
                                       bool radioCalibrated,
                                       bool channelAllowed, bool keysReady)
        {
            if (token.index >= capacity_)
            {
                return Error::InvalidSlot;
            }
            RingSlot &slot = slots_[token.index];
            if (!matches(token) || slot.state != SlotState::ReadyForHardware)
            {
                return Error::UnexpectedState;
            }
            if (!slot.dmaMapped || !slot.descriptorCompleted ||
                !radioCalibrated || !channelAllowed || !keysReady)
            {
                return Error::NotReadyToTransmit;
            }
            // External PCI backend alone can execute a hardware doorbell.
            slot.state = SlotState::OwnedByHardware;
            return Error::Ok;
        }

        Error TxRing::complete(const TxSlotToken &token)
        {
            if (token.index >= capacity_)
            {
                return Error::InvalidSlot;
            }
            RingSlot &slot = slots_[token.index];
            if (!matches(token) || slot.state != SlotState::OwnedByHardware)
            {
                return Error::UnexpectedState;
            }
            slot.state = SlotState::Completed;
            return Error::Ok;
        }

        Error TxRing::release(const TxSlotToken &token)
        {
            if (token.index >= capacity_)
            {
                return Error::InvalidSlot;
            }
            RingSlot &slot = slots_[token.index];
            if (!matches(token) || active_ == 0 ||
                (slot.state != SlotState::Completed &&
                 slot.state != SlotState::Reserved &&
                 slot.state != SlotState::ReadyForHardware))
            {
                return Error::UnexpectedState;
            }
            slot = {};
            slot.generation = generation_;
            slot.state = SlotState::Free;
            --active_;
            return Error::Ok;
        }

        Error TxRing::reset()
        {
            // Even after device quiescence, the owner must retire every
            // descriptor/mapping explicitly. Discarding live metadata here
            // would hide unfinished DMA ownership and stale buffer lifetime.
            if (active_ != 0)
            {
                return Error::UnexpectedState;
            }
            capacity_ = 0;
            // Preserve the reservation-token sequence across
            // reset/reinitialization.
            for (RingSlot &slot : slots_)
            {
                slot = {};
            }
            return Error::Ok;
        }

        bool TxRing::matches(const TxSlotToken &token) const
        {
            if (token.index >= capacity_ || token.generation == 0)
            {
                return false;
            }
            const RingSlot &slot = slots_[token.index];
            return slot.generation == token.generation &&
                   slot.cookie == token.cookie;
        }

        const RingSlot *TxRing::slot(size_t index) const
        {
            return index < capacity_ ? &slots_[index] : nullptr;
        }

    } // namespace dma
} // namespace simpleath
