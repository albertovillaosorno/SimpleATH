// SPDX-License-Identifier: AGPL-3.0-only
// Synthetic ring ownership regression: no PCI, DMA or hardware access.
#include "hardware/Ar9003Dma.hpp"

namespace
{
    int testReceiveRing()
    {
        using namespace simpleath::dma;
        RxRing rx;
        if (rx.initialize(0) != Error::InvalidCount ||
            rx.initialize(RxRing::kMaximumSlots + 1) != Error::InvalidCount ||
            rx.initialize(2) != Error::Ok ||
            rx.initialize(2) != Error::UnexpectedState || rx.active() != 0 ||
            rx.capacity() != 2)
            return 21;
        RxSlotToken first {}, second {};
        if (rx.reserve(first, 19) != Error::Ok || !first.generation ||
            rx.bufferPrepared(first, false, true) != Error::NotReadyToReceive ||
            rx.bufferPrepared(first, true, false) != Error::NotReadyToReceive ||
            rx.postedToHardware(first, true, true) != Error::UnexpectedState ||
            rx.bufferPrepared(first, true, true) != Error::Ok ||
            rx.postedToHardware(first, false, true) !=
                Error::NotReadyToReceive ||
            rx.postedToHardware(first, true, false) !=
                Error::NotReadyToReceive ||
            rx.postedToHardware(first, true, true) != Error::Ok)
            return 22;
        if (rx.release(first) != Error::UnexpectedState ||
            rx.reset() != Error::UnexpectedState ||
            rx.complete(first, false, true) != Error::UnexpectedState ||
            rx.complete(first, true, false) != Error::NotSynchronized ||
            rx.slot(first.index)->state != SlotState::OwnedByHardware)
            return 23;
        if (rx.reserve(second, 20) != Error::Ok || rx.active() != 2)
            return 24;
        const RxSlotToken saved = first;
        if (rx.reserve(first, 21) != Error::RingFull ||
            first.index != saved.index || first.cookie != saved.cookie ||
            first.generation != saved.generation ||
            rx.release(second) != Error::Ok || rx.active() != 1)
            return 25;
        if (rx.complete(first, true, true) != Error::Ok ||
            rx.complete(first, true, true) != Error::UnexpectedState ||
            rx.release(first) != Error::Ok || rx.reset() != Error::Ok ||
            rx.initialize(2) != Error::Ok)
            return 26;
        RxSlotToken reused {};
        if (rx.reserve(reused, 19) != Error::Ok ||
            reused.index != first.index ||
            reused.generation <= first.generation ||
            rx.complete(first, true, true) != Error::UnexpectedState ||
            rx.release(first) != Error::UnexpectedState ||
            rx.bufferPrepared(reused, true, true) != Error::Ok ||
            rx.postedToHardware(reused, true, true) != Error::Ok ||
            rx.retireQuiesced(reused, false) != Error::UnexpectedState ||
            rx.release(reused) != Error::UnexpectedState ||
            rx.retireQuiesced(reused, true) != Error::Ok ||
            rx.slot(reused.index)->state != SlotState::Quiesced ||
            rx.complete(reused, true, true) != Error::UnexpectedState ||
            rx.release(reused) != Error::Ok || rx.reset() != Error::Ok)
            return 27;
        // A token output alias inside the ring must not clear active state.
        if (rx.initialize(2) != Error::Ok || rx.reserve(first, 31) != Error::Ok)
            return 28;
        auto *aliased = reinterpret_cast<RxSlotToken *>(&rx);
        const RingSlot before = *rx.slot(first.index);
        if (rx.reserve(*aliased, 32) != Error::UnexpectedState ||
            rx.active() != 1 ||
            rx.slot(first.index)->generation != before.generation ||
            rx.slot(first.index)->cookie != before.cookie ||
            rx.release(first) != Error::Ok || rx.reset() != Error::Ok)
            return 29;
        alignas(64) uint8_t host[64] {};
        Mapping receive {host, 0x1000u, sizeof(host), Direction::FromDevice,
                         true, true};
        if (validateReceiveDescriptorRing(receive, 16, 4, 16) != Error::Ok ||
            validateDescriptorRing(receive, 16, 4, 16) !=
                Error::InvalidAlignment)
            return 30;
        receive.direction = Direction::ToDevice;
        if (validateReceiveDescriptorRing(receive, 16, 4, 16) !=
            Error::InvalidAlignment)
            return 31;
        receive.direction = Direction::FromDevice;
        receive.deviceBusAddress = 0xfffffff0u;
        if (validateReceiveDescriptorRing(receive, 16, 4, 16) !=
            Error::AddressOverflow)
            return 32;
        receive.deviceBusAddress = 0x1000u;
        if (validateReceiveDescriptorRing(receive, 17, 3, 16) !=
                Error::InvalidAlignment ||
            validateReceiveDescriptorRing(receive, 16, 0, 16) !=
                Error::InvalidCount)
            return 33;
        return 0;
    }
} // namespace

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

    // RingFull must not destroy the token that still owns a live slot.
    // A caller can reuse the output storage for another attempted reserve;
    // dropping that token would orphan an outstanding DMA descriptor.
    TxSlotToken other {};
    const TxSlotToken firstToken = owned;
    if (ring.reserve(other, 8) != Error::Ok ||
        ring.reserve(owned, 9) != Error::RingFull ||
        owned.index != firstToken.index || owned.cookie != firstToken.cookie ||
        owned.generation != firstToken.generation || ring.active() != 2 ||
        ring.release(other) != Error::Ok)
        return 14;

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
    // A caller-built mapping may point its DMA CPU span into its own
    // descriptor. A DMA write could then corrupt the IOVA, size, direction,
    // or synchronization evidence while the owner still relies on them.
    Mapping metadataMapping = validMapping;
    metadataMapping.cpuAddress = &metadataMapping;
    metadataMapping.length = sizeof(metadataMapping);
    if (validateMapping(metadataMapping, sizeof(metadataMapping)) !=
            Error::AliasedMetadata ||
        validateDescriptorRing(metadataMapping, sizeof(metadataMapping), 1,
                               alignof(Mapping)) != Error::AliasedMetadata)
        return 17;
    // Partial overlap at an interior byte is equally unsafe.
    metadataMapping.cpuAddress =
        reinterpret_cast<uint8_t *>(&metadataMapping) + 4;
    metadataMapping.length = 8;
    if (validateMapping(metadataMapping, 8) != Error::AliasedMetadata ||
        validateDescriptorRing(metadataMapping, 8, 1, alignof(Mapping)) !=
            Error::AliasedMetadata)
        return 18;
    // A 32-bit IOVA must cover the full mapped segment, not merely the
    // caller's short required prefix. Otherwise later offsets can wrap the
    // device's 32-bit address space even though initial validation passed.
    const Mapping crossingIo {validHost,           0xfffffff0U, 32,
                              Direction::ToDevice, true,        true};
    if (validateMapping(crossingIo, 8) != Error::AddressOverflow ||
        validateDescriptorRing(crossingIo, 8, 1, 4) != Error::AddressOverflow)
        return 12;
    const Mapping endingIo {validHost,           0xfffffff0U, 16,
                            Direction::ToDevice, true,        true};
    if (validateMapping(endingIo, 8) != Error::Ok ||
        validateDescriptorRing(endingIo, 8, 1, 4) != Error::Ok)
        return 13;
    // An untrusted caller can cast an arbitrary byte into the public mapping
    // direction enum. Neither TX nor RX may treat that as a real DMA transfer
    // direction merely because the IOVA, size and synchronization flags fit.
    Mapping invalidDirection = validMapping;
    invalidDirection.direction = static_cast<Direction>(0xffu);
    if (validateMapping(invalidDirection, 16) != Error::InvalidDirection ||
        validateDescriptorRing(invalidDirection, 16, 2, 16) !=
            Error::InvalidDirection)
        return 15;
    Mapping receiveMapping = validMapping;
    receiveMapping.direction = Direction::FromDevice;
    if (validateMapping(receiveMapping, 16) != Error::Ok ||
        validateDescriptorRing(receiveMapping, 16, 2, 16) !=
            Error::InvalidAlignment)
        return 16;
    return testReceiveRing();
}
