// SPDX-License-Identifier: AGPL-3.0-only
// Synthetic ring ownership regression: no PCI, DMA or hardware access.
#include "hardware/Ar9003Dma.hpp"
#include <cstddef>
#include <cstdint>
#include <iterator>

namespace
{
    // Synthetic cookies and IOVAs are deliberately distinct across reuse,
    // overflow and aliasing cases; none represent physical DMA addresses.
    constexpr uint32_t kFirstRxCookie = 19U;
    constexpr uint32_t kSecondRxCookie = 20U;
    constexpr uint32_t kFullRxCookie = 21U;
    constexpr uint32_t kAliasRxCookie = 31U;
    constexpr uint32_t kAliasRxRetryCookie = 32U;
    constexpr uint32_t kFirstTxCookie = 7U;
    constexpr uint32_t kSecondTxCookie = 8U;
    constexpr uint32_t kFullTxCookie = 9U;
    constexpr uint32_t kAliasTxCookie = 91U;
    constexpr uint32_t kAliasTxRetryCookie = 92U;
    constexpr uint32_t kQuiescedTxCookie = 121U;
    constexpr size_t kHostBufferBytes = 64U;
    constexpr size_t kDescriptorBytes = 16U;
    constexpr size_t kBadElementSize = 17U;
    constexpr size_t kRxAlignment = 16U;
    constexpr size_t kShortMappingBytes = 8U;
    constexpr uint64_t kMappedBusAddress = 0x1000U;
    constexpr uint64_t kNear32BitEnd = 0xfffffff0U;
    constexpr uint8_t kInvalidMappingDirection = 0xffU;

    // Encode the failed assertion's source line as a nonzero exit status,
    // including when the line number is a multiple of 256.
    int failureAtLine(unsigned line)
    {
        return static_cast<int>(line | 1U);
    }

    int testReceiveRing()
    {
        using namespace simpleath::dma;
        RxRing rx;
        if (rx.initialize(0) != Error::InvalidCount ||
            rx.initialize(RxRing::kMaximumSlots + 1) != Error::InvalidCount ||
            rx.initialize(2) != Error::Ok ||
            rx.initialize(2) != Error::UnexpectedState || rx.active() != 0 ||
            rx.capacity() != 2)
        {
            return failureAtLine(__LINE__);
        }
        RxSlotToken first {};
        RxSlotToken second {};
        if (rx.reserve(first, kFirstRxCookie) != Error::Ok ||
            (first.generation == 0U) ||
            rx.bufferPrepared(first, false, true) != Error::NotReadyToReceive ||
            rx.bufferPrepared(first, true, false) != Error::NotReadyToReceive ||
            rx.postedToHardware(first, true, true) != Error::UnexpectedState ||
            rx.bufferPrepared(first, true, true) != Error::Ok ||
            rx.postedToHardware(first, false, true) !=
                Error::NotReadyToReceive ||
            rx.postedToHardware(first, true, false) !=
                Error::NotReadyToReceive ||
            rx.postedToHardware(first, true, true) != Error::Ok)
        {
            return failureAtLine(__LINE__);
        }
        if (rx.release(first) != Error::UnexpectedState ||
            rx.reset() != Error::UnexpectedState ||
            rx.complete(first, false, true) != Error::UnexpectedState ||
            rx.complete(first, true, false) != Error::NotSynchronized ||
            rx.slot(first.index)->state != SlotState::OwnedByHardware)
        {
            return failureAtLine(__LINE__);
        }
        if (rx.reserve(second, kSecondRxCookie) != Error::Ok ||
            rx.active() != 2)
        {
            return failureAtLine(__LINE__);
        }
        const RxSlotToken saved = first;
        if (rx.reserve(first, kFullRxCookie) != Error::RingFull ||
            first.index != saved.index || first.cookie != saved.cookie ||
            first.generation != saved.generation ||
            rx.release(second) != Error::Ok || rx.active() != 1)
        {
            return failureAtLine(__LINE__);
        }
        if (rx.complete(first, true, true) != Error::Ok ||
            rx.complete(first, true, true) != Error::UnexpectedState ||
            rx.release(first) != Error::Ok || rx.reset() != Error::Ok ||
            rx.initialize(2) != Error::Ok)
        {
            return failureAtLine(__LINE__);
        }
        RxSlotToken reused {};
        if (rx.reserve(reused, kFirstRxCookie) != Error::Ok ||
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
        {
            return failureAtLine(__LINE__);
        }
        // A token output alias inside the ring must not clear active state.
        if (rx.initialize(2) != Error::Ok ||
            rx.reserve(first, kAliasRxCookie) != Error::Ok)
        {
            return failureAtLine(__LINE__);
        }
        // The synthetic alias intentionally points inside ring storage. The
        // ring must reject by address before dereferencing the token.
        RxSlotToken *aliased = nullptr;
        const void *rxObject = &rx;
        static_assert(sizeof(RxSlotToken *) == sizeof(void *),
                      "alias pointers must share a representation size");
        __builtin_memcpy(static_cast<void *>(&aliased),
                         static_cast<const void *>(&rxObject),
                         sizeof(uintptr_t));
        const RingSlot before = *rx.slot(first.index);
        if (rx.reserve(*aliased, kAliasRxRetryCookie) !=
                Error::UnexpectedState ||
            rx.active() != 1 ||
            rx.slot(first.index)->generation != before.generation ||
            rx.slot(first.index)->cookie != before.cookie ||
            rx.release(first) != Error::Ok || rx.reset() != Error::Ok)
        {
            return failureAtLine(__LINE__);
        }
        alignas(kHostBufferBytes) uint8_t host[kHostBufferBytes] {};
        Mapping receive {
            &host[0],     kMappedBusAddress,
            sizeof(host), Direction::FromDevice,
            true,         true,
        };
        if (validateReceiveDescriptorRing(receive, kDescriptorBytes, 4,
                                          kDescriptorBytes) != Error::Ok ||
            validateDescriptorRing(receive, kDescriptorBytes, 4,
                                   kDescriptorBytes) != Error::InvalidAlignment)
        {
            return failureAtLine(__LINE__);
        }
        receive.direction = Direction::ToDevice;
        if (validateReceiveDescriptorRing(receive, kDescriptorBytes, 4,
                                          kDescriptorBytes) !=
            Error::InvalidAlignment)
        {
            return failureAtLine(__LINE__);
        }
        receive.direction = Direction::FromDevice;
        receive.deviceBusAddress = kNear32BitEnd;
        if (validateReceiveDescriptorRing(receive, kDescriptorBytes, 4,
                                          kDescriptorBytes) !=
            Error::AddressOverflow)
        {
            return failureAtLine(__LINE__);
        }
        receive.deviceBusAddress = kMappedBusAddress;
        if (validateReceiveDescriptorRing(receive, kBadElementSize, 3,
                                          kRxAlignment) !=
                Error::InvalidAlignment ||
            validateReceiveDescriptorRing(receive, kDescriptorBytes, 0,
                                          kDescriptorBytes) !=
                Error::InvalidCount)
        {
            return failureAtLine(__LINE__);
        }
        return 0;
    }

    int testMappingMetadata()
    {
        using namespace simpleath::dma;
        // A fabricated CPU span that wraps host uintptr_t cannot describe a
        // retained DMA allocation, even when the reported device IOVA is valid.
        // No CPU memory is dereferenced in this synthetic mapping regression.
        // Copy bits of an out-of-range host span into a pointer without
        // dereferencing it or using a compiler-dependent integer-to-pointer
        // cast.
        const uintptr_t wrappedHostAddress = UINTPTR_MAX - 3U;
        void *wrappedHost = nullptr;
        static_assert(sizeof(wrappedHost) == sizeof(wrappedHostAddress),
                      "host pointer width must match uintptr_t");
        __builtin_memcpy(static_cast<void *>(&wrappedHost), &wrappedHostAddress,
                         sizeof(wrappedHost));
        const Mapping overflowingHost {
            wrappedHost, 0x1000U, 8, Direction::ToDevice, true, true,
        };
        if (validateMapping(overflowingHost, kShortMappingBytes) !=
                Error::AddressOverflow ||
            validateDescriptorRing(overflowingHost, kShortMappingBytes, 1, 4) !=
                Error::AddressOverflow)
        {
            return failureAtLine(__LINE__);
        }
        alignas(kHostBufferBytes) uint8_t validHost[kHostBufferBytes] {};
        const Mapping validMapping {
            &validHost[0],
            kMappedBusAddress,
            sizeof(validHost),
            Direction::ToDevice,
            true,
            true,
        };
        if (validateMapping(validMapping, sizeof(validHost)) != Error::Ok ||
            validateDescriptorRing(validMapping, kDescriptorBytes, 4,
                                   kDescriptorBytes) != Error::Ok)
        {
            return failureAtLine(__LINE__);
        }
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
        {
            return failureAtLine(__LINE__);
        }
        // Partial overlap at an interior byte is equally unsafe.
        uint8_t *metadataBytes = nullptr;
        const void *metadataObject = &metadataMapping;
        static_assert(sizeof(metadataBytes) == sizeof(metadataObject),
                      "object pointers must share a representation size");
        __builtin_memcpy(static_cast<void *>(&metadataBytes),
                         static_cast<const void *>(&metadataObject),
                         sizeof(uintptr_t));
        metadataMapping.cpuAddress = std::next(metadataBytes, 4);
        metadataMapping.length = kShortMappingBytes;
        if (validateMapping(metadataMapping, kShortMappingBytes) !=
                Error::AliasedMetadata ||
            validateDescriptorRing(metadataMapping, kShortMappingBytes, 1,
                                   alignof(Mapping)) != Error::AliasedMetadata)
        {
            return failureAtLine(__LINE__);
        }
        // A 32-bit IOVA must cover the full mapped segment, not merely the
        // caller's short required prefix. Otherwise later offsets can wrap the
        // device's 32-bit address space even though initial validation passed.
        const Mapping crossingIo {
            &validHost[0], kNear32BitEnd, 32, Direction::ToDevice, true, true,
        };
        if (validateMapping(crossingIo, kShortMappingBytes) !=
                Error::AddressOverflow ||
            validateDescriptorRing(crossingIo, kShortMappingBytes, 1, 4) !=
                Error::AddressOverflow)
        {
            return failureAtLine(__LINE__);
        }
        const Mapping endingIo {
            &validHost[0],       kNear32BitEnd, kDescriptorBytes,
            Direction::ToDevice, true,          true,
        };
        if (validateMapping(endingIo, kShortMappingBytes) != Error::Ok ||
            validateDescriptorRing(endingIo, kShortMappingBytes, 1, 4) !=
                Error::Ok)
        {
            return failureAtLine(__LINE__);
        }
        // An untrusted caller can cast an arbitrary byte into the public
        // mapping direction enum. Neither TX nor RX may treat that as a real
        // DMA transfer direction merely because the IOVA, size and
        // synchronization flags fit.
        Mapping invalidDirection = validMapping;
        // Invalid enum representation is input bytes from an untrusted caller,
        // not a C++ out-of-range enum cast.
        __builtin_memcpy(&invalidDirection.direction, &kInvalidMappingDirection,
                         sizeof(invalidDirection.direction));
        if (validateMapping(invalidDirection, kDescriptorBytes) !=
                Error::InvalidDirection ||
            validateDescriptorRing(invalidDirection, kDescriptorBytes, 2,
                                   kDescriptorBytes) != Error::InvalidDirection)
        {
            return failureAtLine(__LINE__);
        }
        Mapping receiveMapping = validMapping;
        receiveMapping.direction = Direction::FromDevice;
        if (validateMapping(receiveMapping, kDescriptorBytes) != Error::Ok ||
            validateDescriptorRing(receiveMapping, kDescriptorBytes, 2,
                                   kDescriptorBytes) != Error::InvalidAlignment)
        {
            return failureAtLine(__LINE__);
        }
        return 0;
    }
} // namespace

int main()
{
    using namespace simpleath::dma;
    TxRing ring;
    if (ring.initialize(2) != Error::Ok || ring.capacity() != 2 ||
        ring.active() != 0)
    {
        return failureAtLine(__LINE__);
    }

    TxSlotToken owned {};
    if (ring.reserve(owned, kFirstTxCookie) != Error::Ok ||
        (owned.generation == 0U) || ring.active() != 1 ||
        (ring.slot(owned.index) == nullptr) ||
        ring.slot(owned.index)->state != SlotState::Reserved)
    {
        return failureAtLine(__LINE__);
    }

    // RingFull must not destroy the token that still owns a live slot.
    // A caller can reuse the output storage for another attempted reserve;
    // dropping that token would orphan an outstanding DMA descriptor.
    TxSlotToken other {};
    const TxSlotToken firstToken = owned;
    if (ring.reserve(other, kSecondTxCookie) != Error::Ok ||
        ring.reserve(owned, kFullTxCookie) != Error::RingFull ||
        owned.index != firstToken.index || owned.cookie != firstToken.cookie ||
        owned.generation != firstToken.generation || ring.active() != 2 ||
        ring.release(other) != Error::Ok)
    {
        return failureAtLine(__LINE__);
    }

    // A reset while reserved must be rejected without erasing any token.
    if (ring.reset() != Error::UnexpectedState || ring.capacity() != 2 ||
        ring.active() != 1 ||
        ring.slot(owned.index)->state != SlotState::Reserved ||
        ring.descriptorPrepared(owned, true, true) != Error::Ok)
    {
        return failureAtLine(__LINE__);
    }
    if (ring.handedToHardware(owned, true, true, true) != Error::Ok ||
        ring.reset() != Error::UnexpectedState ||
        ring.slot(owned.index)->state != SlotState::OwnedByHardware ||
        ring.release(owned) != Error::UnexpectedState)
    {
        return failureAtLine(__LINE__);
    }

    // Even a completed descriptor remains owned until the external mapping
    // has been explicitly released and its metadata slot retired.
    if (ring.complete(owned) != Error::Ok ||
        ring.reset() != Error::UnexpectedState ||
        ring.slot(owned.index)->state != SlotState::Completed ||
        ring.release(owned) != Error::Ok || ring.active() != 0)
    {
        return failureAtLine(__LINE__);
    }

    if (ring.reset() != Error::Ok || ring.capacity() != 0 ||
        ring.initialize(2) != Error::Ok)
    {
        return failureAtLine(__LINE__);
    }

    // Old completion and release tokens cannot apply to a new generation,
    // even when the allocator reuses the same index and software cookie.
    TxSlotToken fresh {};
    if (ring.reserve(fresh, kFirstTxCookie) != Error::Ok ||
        fresh.index != owned.index || fresh.generation <= owned.generation ||
        ring.complete(owned) != Error::UnexpectedState ||
        ring.release(owned) != Error::UnexpectedState ||
        ring.slot(fresh.index)->state != SlotState::Reserved ||
        ring.release(fresh) != Error::Ok || ring.reset() != Error::Ok)
    {
        return failureAtLine(__LINE__);
    }

    // A caller can mistakenly place its output token inside the persistent
    // ring allocation. Clearing such an alias on entry destroys slot state,
    // including the outstanding descriptor's ownership and recovery token.
    if (ring.initialize(2) != Error::Ok ||
        ring.reserve(owned, kAliasTxCookie) != Error::Ok)
    {
        return failureAtLine(__LINE__);
    }
    const RingSlot preserved = *ring.slot(owned.index);
    // A forged output address inside the ring must be rejected by its
    // overlap guard before any access to that token representation.
    TxSlotToken *aliasedToken = nullptr;
    const void *ringObject = &ring;
    static_assert(sizeof(TxSlotToken *) == sizeof(void *),
                  "alias pointers must share a representation size");
    __builtin_memcpy(static_cast<void *>(&aliasedToken),
                     static_cast<const void *>(&ringObject), sizeof(uintptr_t));
    if (ring.reserve(*aliasedToken, kAliasTxRetryCookie) !=
            Error::UnexpectedState ||
        ring.capacity() != 2 || ring.active() != 1 ||
        ring.slot(owned.index)->state != preserved.state ||
        ring.slot(owned.index)->generation != preserved.generation ||
        ring.slot(owned.index)->cookie != preserved.cookie ||
        ring.slot(owned.index)->dmaMapped != preserved.dmaMapped ||
        ring.slot(owned.index)->descriptorCompleted !=
            preserved.descriptorCompleted ||
        ring.release(owned) != Error::Ok || ring.reset() != Error::Ok)
    {
        return failureAtLine(__LINE__);
    }
    // After a verified device shutdown, a TX descriptor still owned at the
    // time of stop must be reclaimed without manufacturing TX success.
    if (ring.initialize(2) != Error::Ok ||
        ring.reserve(owned, kQuiescedTxCookie) != Error::Ok ||
        ring.descriptorPrepared(owned, true, true) != Error::Ok ||
        ring.handedToHardware(owned, true, true, true) != Error::Ok ||
        ring.release(owned) != Error::UnexpectedState ||
        ring.retireQuiesced(owned, false) != Error::UnexpectedState ||
        ring.slot(owned.index)->state != SlotState::OwnedByHardware ||
        ring.retireQuiesced(owned, true) != Error::Ok ||
        ring.slot(owned.index)->state != SlotState::Quiesced ||
        ring.complete(owned) != Error::UnexpectedState ||
        ring.release(owned) != Error::Ok || ring.reset() != Error::Ok)
    {
        return failureAtLine(__LINE__);
    }

    const int mappingResult = testMappingMetadata();
    return mappingResult == 0 ? testReceiveRing() : mappingResult;
}
