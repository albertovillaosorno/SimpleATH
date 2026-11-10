// SPDX-License-Identifier: GPL-2.0-only
// Offline register simulation only. No PCI, firmware or radio access.
#include "hardware/Ar9565KeyCache.hpp"
#include "wifi/Frames.hpp"
#include <array>
#include <cstddef>
#include <cstdint>

using namespace simpleath;

namespace
{
    constexpr uint64_t kEpoch = 17;
    constexpr uint32_t kBarLength = 0x20000U;
    constexpr uint32_t kTableStart = 0x8800U;
    constexpr size_t kSlots = 128U;
    constexpr size_t kWordsPerSlot = 8U;
    constexpr size_t kRegisters = kSlots * kWordsPerSlot;
    constexpr size_t kInitializeWrites = kRegisters;
    constexpr size_t kInitializeReads = kSlots * 3U;
    constexpr size_t kInstallWrites = 16U;
    constexpr size_t kInstallReads = 6U;
    constexpr uint32_t kCipherCcmp = 6U;
    constexpr uint32_t kCipherClear = 7U;
    constexpr size_t kTypeIndex = 5U;
    constexpr size_t kMac0Index = 6U;
    constexpr size_t kMac1Index = 7U;
    constexpr uint32_t kPairwiseMac0 = 0x19910881U;
    constexpr uint32_t kPairwiseMac1 = 0xaaa2U;
    constexpr uint32_t kGroupMac1 = 0x8000U;
    constexpr uint64_t kReceiveFloor = 0x060504030201ULL;
    constexpr uint32_t kFirstKeyWord = 0x03020100U;
    constexpr uint32_t kSecondKeyWord = 0x0504U;
    constexpr uint32_t kThirdKeyWord = 0x09080706U;
    constexpr uint32_t kFourthKeyWord = 0x0b0aU;
    constexpr uint32_t kFifthKeyWord = 0x0f0e0d0cU;
    constexpr size_t kPairwiseIndex = kCcmpPairwiseSlot * kWordsPerSlot;
    constexpr uint8_t kKeyId = 2U;
    constexpr size_t kGroupIndex = kKeyId * kWordsPerSlot;
    constexpr uint32_t kWrongType = 3U;
    constexpr uint64_t kWrongEpoch = 19;

    struct Mock
    {
            std::array<uint32_t, kRegisters> registers {};
            size_t writes = 0;
            size_t reads = 0;
            size_t permits = 0;
            size_t failWriteAt = 0;
            size_t failReadAt = 0;
            size_t revokeAt = 0;
            bool corruptType = false;
            bool forbid = false;
    };

    bool permitted(void *context, uint64_t epoch)
    {
        auto &mock = *static_cast<Mock *>(context);
        ++mock.permits;
        return epoch == kEpoch && !mock.forbid &&
               (mock.revokeAt == 0 || mock.permits < mock.revokeAt);
    }

    bool indexFor(uint32_t offset, size_t &index)
    {
        if (offset < kTableStart ||
            (offset - kTableStart) % sizeof(uint32_t) != 0U)
        {
            return false;
        }
        index = (offset - kTableStart) / sizeof(uint32_t);
        return index < kRegisters;
    }

    bool read(void *context, uint32_t offset, uint32_t *value)
    {
        auto &mock = *static_cast<Mock *>(context);
        size_t index = 0;
        ++mock.reads;
        if (value == nullptr || !indexFor(offset, index) ||
            (mock.failReadAt != 0 && mock.reads == mock.failReadAt))
        {
            return false;
        }
        *value = mock.registers.at(index);
        if (mock.corruptType && index % kWordsPerSlot == kTypeIndex)
        {
            *value = kWrongType;
        }
        return true;
    }

    bool write(void *context, uint32_t offset, const uint32_t value)
    {
        auto &mock = *static_cast<Mock *>(context);
        size_t index = 0;
        ++mock.writes;
        if (!indexFor(offset, index) ||
            (mock.failWriteAt != 0 && mock.writes == mock.failWriteAt))
        {
            return false;
        }
        mock.registers.at(index) = value;
        return true;
    }

    KeyCacheBackend backend(Mock &mock)
    {
        return {&mock, kEpoch, kBarLength, permitted, read, write};
    }

    constexpr std::array<uint8_t, kCcmpKeyBytes> kKey {
        0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U, 9U, 10U, 11U, 12U, 13U, 14U, 15U,
    };
    constexpr std::array<uint8_t, kCcmpRscBytes> kRsc {
        1U, 2U, 3U, 4U, 5U, 6U, 0U, 0U,
    };
    const ieee80211::Mac kAp {{2U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U}};
    const ieee80211::Mac kMulticast {{1U, 2U, 3U, 4U, 5U, 6U}};

    bool testLifecycle()
    {
        Mock mock {};
        const auto io = backend(mock);
        KeyCacheState state {};
        auto result = installAr9565PairwiseKey(io, state, kAp, kKey.data());
        if (result.result != KeyCacheResult::NotInitialized || mock.writes != 0)
        {
            return false;
        }
        result = initializeAr9565KeyCache(io, state);
        if (result.result != KeyCacheResult::Ok || !state.initialized ||
            result.requiresReset ||
            result.completedWrites != kInitializeWrites ||
            result.completedReads != kInitializeReads ||
            mock.registers.at(kTypeIndex) != kCipherClear)
        {
            return false;
        }
        result = initializeAr9565KeyCache(io, state);
        if (result.result != KeyCacheResult::SlotOccupied ||
            mock.writes != kInitializeWrites)
        {
            return false;
        }
        result = installAr9565PairwiseKey(io, state, kAp, kKey.data());
        if (result.result != KeyCacheResult::Ok ||
            result.completedWrites != kInstallWrites ||
            result.completedReads != kInstallReads ||
            !state.pairwiseInstalled || state.requiresReset ||
            mock.registers.at(kPairwiseIndex) != kFirstKeyWord ||
            mock.registers.at(kPairwiseIndex + 1U) != kSecondKeyWord ||
            mock.registers.at(kPairwiseIndex + 2U) != kThirdKeyWord ||
            mock.registers.at(kPairwiseIndex + 3U) != kFourthKeyWord ||
            mock.registers.at(kPairwiseIndex + 4U) != kFifthKeyWord ||
            mock.registers.at(kPairwiseIndex + kTypeIndex) != kCipherCcmp ||
            mock.registers.at(kPairwiseIndex + kMac0Index) != kPairwiseMac0 ||
            mock.registers.at(kPairwiseIndex + kMac1Index) != kPairwiseMac1)
        {
            return false;
        }
        result = installAr9565PairwiseKey(io, state, kAp, kKey.data());
        if (result.result != KeyCacheResult::SlotOccupied ||
            result.completedWrites != 0)
        {
            return false;
        }
        result =
            installAr9565GroupKey(io, state, kKeyId, kKey.data(), kRsc.data());
        if (result.result != KeyCacheResult::Ok ||
            !state.group[kKeyId].installed ||
            state.group[kKeyId].receiveFloor != kReceiveFloor ||
            mock.registers.at(kGroupIndex + kMac0Index) != 0U ||
            mock.registers.at(kGroupIndex + kMac1Index) != kGroupMac1 ||
            mock.registers.at(kGroupIndex + kTypeIndex) != kCipherCcmp)
        {
            return false;
        }
        result =
            installAr9565GroupKey(io, state, kKeyId, kKey.data(), kRsc.data());
        if (result.result != KeyCacheResult::SlotOccupied ||
            result.completedWrites != 0)
        {
            return false;
        }
        result = eraseAr9565GroupKey(io, state, kKeyId);
        if (result.result != KeyCacheResult::Ok ||
            state.group[kKeyId].installed ||
            state.group[kKeyId].receiveFloor != 0U ||
            mock.registers.at(kGroupIndex + kTypeIndex) != kCipherClear)
        {
            return false;
        }
        result = eraseAr9565Keys(io, state);
        if (result.result != KeyCacheResult::Ok || state.pairwiseInstalled ||
            state.requiresReset ||
            mock.registers.at(kPairwiseIndex + kTypeIndex) != kCipherClear ||
            mock.registers.at(kPairwiseIndex) != 0U)
        {
            return false;
        }
        result = installAr9565PairwiseKey(io, state, kAp, kKey.data());
        return result.result == KeyCacheResult::Ok;
    }

    bool testRejectsWithoutWrite()
    {
        Mock mock {};
        const auto io = backend(mock);
        KeyCacheState state {};
        auto bad = io;
        bad.barLengthBytes = kTableStart;
        if (initializeAr9565KeyCache(bad, state).result !=
                KeyCacheResult::InvalidBar ||
            mock.writes != 0)
        {
            return false;
        }
        if (initializeAr9565KeyCache(io, state).result != KeyCacheResult::Ok)
        {
            return false;
        }
        const size_t priorWrites = mock.writes;
        std::array<uint8_t, kCcmpRscBytes> badRsc = kRsc;
        badRsc.back() = 1U;
        const auto invalidAp =
            installAr9565PairwiseKey(io, state, kMulticast, kKey.data());
        const auto invalidRsc = installAr9565GroupKey(
            io, state, kKeyId, kKey.data(), badRsc.data());
        const auto invalidId = installAr9565GroupKey(io, state, kCcmpGroupSlots,
                                                     kKey.data(), kRsc.data());
        bad.barLengthBytes = kBarLength;
        bad.ownerEpoch = kWrongEpoch;
        const auto wrongOwner =
            installAr9565PairwiseKey(bad, state, kAp, kKey.data());
        return invalidAp.result == KeyCacheResult::InvalidAddress &&
               invalidRsc.result == KeyCacheResult::InvalidRsc &&
               invalidId.result == KeyCacheResult::InvalidKey &&
               wrongOwner.result == KeyCacheResult::WrongOwner &&
               mock.writes == priorWrites && !state.requiresReset;
    }

    bool testFailClosed()
    {
        Mock mock {};
        const auto io = backend(mock);
        KeyCacheState state {};
        mock.failWriteAt = 3U;
        auto result = initializeAr9565KeyCache(io, state);
        if (result.result != KeyCacheResult::WriteFailed ||
            !result.requiresReset || !state.requiresReset ||
            state.initialized || result.completedWrites != 2U ||
            initializeAr9565KeyCache(io, state).result !=
                KeyCacheResult::ResetRequired)
        {
            return false;
        }
        mock = {};
        state = {};
        if (initializeAr9565KeyCache(io, state).result != KeyCacheResult::Ok)
        {
            return false;
        }
        mock.failReadAt = mock.reads + 1U;
        result = installAr9565PairwiseKey(io, state, kAp, kKey.data());
        if (result.result != KeyCacheResult::ReadFailed ||
            !state.requiresReset || state.pairwiseInstalled)
        {
            return false;
        }
        mock = {};
        state = {};
        if (initializeAr9565KeyCache(io, state).result != KeyCacheResult::Ok)
        {
            return false;
        }
        mock.revokeAt = mock.permits + 3U;
        result = installAr9565PairwiseKey(io, state, kAp, kKey.data());
        if (result.result != KeyCacheResult::OwnershipLost ||
            !state.requiresReset || state.pairwiseInstalled)
        {
            return false;
        }
        mock = {};
        state = {};
        if (initializeAr9565KeyCache(io, state).result != KeyCacheResult::Ok)
        {
            return false;
        }
        if (installAr9565PairwiseKey(io, state, kAp, kKey.data()).result !=
            KeyCacheResult::Ok)
        {
            return false;
        }
        mock.forbid = true;
        result = eraseAr9565Keys(io, state);
        if (result.result != KeyCacheResult::OwnershipLost ||
            !result.requiresReset || !state.requiresReset ||
            state.pairwiseInstalled ||
            installAr9565PairwiseKey(io, state, kAp, kKey.data()).result !=
                KeyCacheResult::ResetRequired)
        {
            return false;
        }
        mock = {};
        state = {};
        if (initializeAr9565KeyCache(io, state).result != KeyCacheResult::Ok)
        {
            return false;
        }
        mock.corruptType = true;
        result = installAr9565PairwiseKey(io, state, kAp, kKey.data());
        return result.result == KeyCacheResult::VerifyFailed &&
               result.requiresReset && !state.pairwiseInstalled;
    }
} // namespace

int main()
{
    return testLifecycle() && testRejectsWithoutWrite() && testFailClosed() ? 0
                                                                            : 1;
}
