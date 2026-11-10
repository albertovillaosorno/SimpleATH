// SPDX-License-Identifier: AGPL-3.0-only
#ifndef SIMPLEATH_AR9565_KEY_CACHE_HPP
#define SIMPLEATH_AR9565_KEY_CACHE_HPP

#include "../wifi/Frames.hpp"
#include <cstddef>
#include <cstdint>

namespace simpleath
{
    constexpr size_t kCcmpKeyBytes = 16;
    constexpr size_t kCcmpRscBytes = 8;
    constexpr uint16_t kCcmpPairwiseSlot = 4;
    constexpr uint8_t kCcmpGroupSlots = 4;

    enum class KeyCacheResult : uint8_t
    {
        Ok,
        InvalidBackend,
        InvalidBar,
        InvalidKey,
        InvalidAddress,
        InvalidRsc,
        NotInitialized,
        WrongOwner,
        SlotOccupied,
        ResetRequired,
        OwnershipLost,
        WriteFailed,
        ReadFailed,
        VerifyFailed,
    };

    struct KeyCacheBackend
    {
            void *context;
            uint64_t ownerEpoch;
            uint32_t barLengthBytes;
            // Native work-loop gate only. Every invocation must recheck PCI
            // ownership, D0, same epoch and quiesced DMA/MAC auto-responses.
            // The caller must prevent TX/RX from accessing the cache while
            // any of these operations runs. write32 must drain posted writes.
            bool (*permit)(void *context, uint64_t epoch);
            bool (*read32)(void *context, uint32_t offset, uint32_t *value);
            bool (*write32)(void *context, uint32_t offset, uint32_t value);
    };

    // Secrets live only in hardware and ephemeral write scratch, never here.
    // This metadata cannot authorize protected packet delivery: native RX
    // must independently verify CCMP MIC/PN and TX must manage non-reuse of PN.
    struct KeyCacheGroup
    {
            uint64_t receiveFloor = 0;
            bool installed = false;
    };

    struct KeyCacheState
    {
            void *ownerContext = nullptr;
            uint64_t ownerEpoch = 0;
            KeyCacheGroup group[kCcmpGroupSlots] {};
            bool initialized = false;
            bool pairwiseInstalled = false;
            bool requiresReset = false;
    };

    struct KeyCacheProgress
    {
            KeyCacheResult result;
            size_t completedWrites;
            size_t completedReads;
            uint32_t lastOffset;
            bool requiresReset;
    };

    // Full 128-slot scrub before trusting any keycache state. This is not a
    // hardware reset. A lost owner or uncertain write latches requiresReset;
    // only an independently confirmed full device reset permits discarding
    // such a state and beginning a fresh initialization.
    KeyCacheProgress initializeAr9565KeyCache(const KeyCacheBackend &backend,
                                              KeyCacheState &state);

    // Pairwise slot 4 is held for the peer AP; group key ids 0..3 use the
    // fixed hardware slots. Duplicate installs are refused to avoid accidental
    // replay/PN reset. The native owner must serialize handshakes and rekeys.
    KeyCacheProgress installAr9565PairwiseKey(const KeyCacheBackend &backend,
                                              KeyCacheState &state,
                                              const ieee80211::Mac &ap,
                                              const uint8_t key[kCcmpKeyBytes]);
    KeyCacheProgress installAr9565GroupKey(const KeyCacheBackend &backend,
                                           KeyCacheState &state, uint8_t keyId,
                                           const uint8_t key[kCcmpKeyBytes],
                                           const uint8_t keyRsc[kCcmpRscBytes]);

    // Erasure is safe only with all referencing DMA descriptors drained.
    // A failed or interrupted removal requires a full native device reset,
    // never a second installation on the ambiguous old key slot.
    KeyCacheProgress eraseAr9565GroupKey(const KeyCacheBackend &backend,
                                         KeyCacheState &state, uint8_t keyId);
    KeyCacheProgress eraseAr9565Keys(const KeyCacheBackend &backend,
                                     KeyCacheState &state);
} // namespace simpleath

#endif
