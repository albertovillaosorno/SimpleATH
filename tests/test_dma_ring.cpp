// SPDX-License-Identifier: AGPL-3.0-only
// Synthetic ring ownership regression: no PCI, DMA or hardware access.
#include "hardware/Ar9003Dma.hpp"

int main()
{
    using namespace simpleath::dma;
    TxRing ring;
    if (ring.initialize(2) != Error::Ok || ring.capacity() != 2 ||
        ring.active() != 0)
        return 1;

    TxSlotToken owned {};
    if (ring.reserve(owned, 7) != Error::Ok || !owned.generation ||
        ring.active() != 1 || !ring.slot(owned.index) ||
        ring.slot(owned.index)->state != SlotState::Reserved)
        return 2;

    // A reset while reserved must be rejected without erasing any token.
    if (ring.reset() != Error::UnexpectedState || ring.capacity() != 2 ||
        ring.active() != 1 ||
        ring.slot(owned.index)->state != SlotState::Reserved ||
        ring.descriptorPrepared(owned, true, true) != Error::Ok)
        return 3;
    if (ring.handedToHardware(owned, true, true, true) != Error::Ok ||
        ring.reset() != Error::UnexpectedState ||
        ring.slot(owned.index)->state != SlotState::OwnedByHardware ||
        ring.release(owned) != Error::UnexpectedState)
        return 4;

    // Even a completed descriptor remains owned until the external mapping
    // has been explicitly released and its metadata slot retired.
    if (ring.complete(owned) != Error::Ok ||
        ring.reset() != Error::UnexpectedState ||
        ring.slot(owned.index)->state != SlotState::Completed ||
        ring.release(owned) != Error::Ok || ring.active() != 0)
        return 5;

    if (ring.reset() != Error::Ok || ring.capacity() != 0 ||
        ring.initialize(2) != Error::Ok)
        return 6;

    // Old completion and release tokens cannot apply to a new generation,
    // even when the allocator reuses the same index and software cookie.
    TxSlotToken fresh {};
    if (ring.reserve(fresh, 7) != Error::Ok || fresh.index != owned.index ||
        fresh.generation <= owned.generation ||
        ring.complete(owned) != Error::UnexpectedState ||
        ring.release(owned) != Error::UnexpectedState ||
        ring.slot(fresh.index)->state != SlotState::Reserved ||
        ring.release(fresh) != Error::Ok || ring.reset() != Error::Ok)
        return 7;

    // A caller can mistakenly place its output token inside the persistent
    // ring allocation. Clearing such an alias on entry destroys slot state,
    // including the outstanding descriptor's ownership and recovery token.
    if (ring.initialize(2) != Error::Ok || ring.reserve(owned, 91) != Error::Ok)
        return 8;
    const RingSlot preserved = *ring.slot(owned.index);
    auto *ownerBytes = reinterpret_cast<uint8_t *>(&ring);
    auto *aliasedToken = reinterpret_cast<TxSlotToken *>(ownerBytes);
    if (ring.reserve(*aliasedToken, 92) != Error::UnexpectedState ||
        ring.capacity() != 2 || ring.active() != 1 ||
        ring.slot(owned.index)->state != preserved.state ||
        ring.slot(owned.index)->generation != preserved.generation ||
        ring.slot(owned.index)->cookie != preserved.cookie ||
        ring.slot(owned.index)->dmaMapped != preserved.dmaMapped ||
        ring.slot(owned.index)->descriptorCompleted !=
            preserved.descriptorCompleted ||
        ring.release(owned) != Error::Ok || ring.reset() != Error::Ok)
        return 9;
    // A fabricated CPU span that wraps host uintptr_t cannot describe a
    // retained DMA allocation, even when the reported device IOVA is valid.
    // No CPU memory is dereferenced in this synthetic mapping regression.
    const Mapping overflowingHost {reinterpret_cast<void *>(UINTPTR_MAX - 3U),
                                   0x1000U,
                                   8,
                                   Direction::ToDevice,
                                   true,
                                   true};
    if (validateMapping(overflowingHost, 8) != Error::AddressOverflow ||
        validateDescriptorRing(overflowingHost, 8, 1, 4) !=
            Error::AddressOverflow)
        return 10;
    alignas(64) uint8_t validHost[64] {};
    const Mapping validMapping {validHost,           0x1000U, sizeof(validHost),
                                Direction::ToDevice, true,    true};
    if (validateMapping(validMapping, sizeof(validHost)) != Error::Ok ||
        validateDescriptorRing(validMapping, 16, 4, 16) != Error::Ok)
        return 11;
    return 0;
}
