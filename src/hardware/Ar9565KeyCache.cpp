// AR9003 keycache register protocol from Linux ath/key.c and ath/reg.h:
// https://github.com/torvalds/linux/blob/master/drivers/net/wireless/ath/key.c
// Original reference copyright (c) 2008-2009 Atheros Communications Inc.
// Original reference copyright (c) 2010 Bruno Randolf.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#include "Ar9565KeyCache.hpp"
#include "../wifi/Frames.hpp"
#include <cstddef>
#include <cstdint>

namespace simpleath
{
    namespace
    {
        constexpr size_t kMacOctets = 6U;
        constexpr uint32_t kTableBase = 0x8800U;
        constexpr uint32_t kEntryStride = 32U;
        constexpr uint16_t kEntryCount = 128U;
        constexpr uint32_t kTableEnd =
            kTableBase + (kEntryStride * kEntryCount);
        enum class KeyOffset : uint32_t
        {
            Key0 = 0U,
            Key1 = 4U,
            Key2 = 8U,
            Key3 = 12U,
            Key4 = 16U,
            Type = 20U,
            Mac0 = 24U,
            Mac1 = 28U,
        };
        constexpr KeyOffset kKey0 = KeyOffset::Key0;
        constexpr KeyOffset kKey1 = KeyOffset::Key1;
        constexpr KeyOffset kKey2 = KeyOffset::Key2;
        constexpr KeyOffset kKey3 = KeyOffset::Key3;
        constexpr KeyOffset kKey4 = KeyOffset::Key4;
        constexpr KeyOffset kType = KeyOffset::Type;
        constexpr KeyOffset kMac0 = KeyOffset::Mac0;
        constexpr KeyOffset kMac1 = KeyOffset::Mac1;
        constexpr uint32_t kCcmp = 6U;
        constexpr uint32_t kClear = 7U;
        constexpr uint32_t kUnicastValid = 0x8000U;
        constexpr uint32_t kAddressShift = 1U;
        constexpr uint32_t kMacCarryShift = 31U;
        constexpr uint32_t kMulticastBit = 1U;

        // Fixed-size trivially copyable snapshots; no host standard library
        // containers are permitted in the Tahoe kernel translation unit.
        struct KeyBytes
        {
                uint8_t key0[4] {};
                uint8_t key1[2] {};
                uint8_t key2[4] {};
                uint8_t key3[2] {};
                uint8_t key4[4] {};
        };

        struct MacBytes
        {
                uint8_t b0 = 0;
                uint8_t b1 = 0;
                uint8_t b2 = 0;
                uint8_t b3 = 0;
                uint8_t b4 = 0;
                uint8_t b5 = 0;
        };

        struct RscBytes
        {
                uint8_t r0 = 0;
                uint8_t r1 = 0;
                uint8_t r2 = 0;
                uint8_t r3 = 0;
                uint8_t r4 = 0;
                uint8_t r5 = 0;
                uint8_t reserved0 = 0;
                uint8_t reserved1 = 0;
        };

        static_assert(sizeof(KeyBytes) == kCcmpKeyBytes,
                      "CCMP key layout must contain 16 contiguous octets");
        static_assert(sizeof(MacBytes) == kMacOctets,
                      "CCMP key MAC layout must contain six octets");
        static_assert(sizeof(RscBytes) == kCcmpRscBytes,
                      "CCMP RSC layout must contain eight octets");
        constexpr uint32_t kShift8 = 8U;
        constexpr uint32_t kShift16 = 16U;
        constexpr uint32_t kShift24 = 24U;
        constexpr uint32_t kShift32 = 32U;
        constexpr uint32_t kShift40 = 40U;

        uint32_t readHalf(const uint8_t (&bytes)[2])
        {
            return static_cast<uint32_t>(bytes[0]) |
                   (static_cast<uint32_t>(bytes[1]) << kShift8);
        }

        uint32_t readWord(const uint8_t (&bytes)[4])
        {
            return static_cast<uint32_t>(bytes[0]) |
                   (static_cast<uint32_t>(bytes[1]) << kShift8) |
                   (static_cast<uint32_t>(bytes[2]) << kShift16) |
                   (static_cast<uint32_t>(bytes[3]) << kShift24);
        }

        KeyCacheGroup *groupFor(KeyCacheState &state, uint8_t id)
        {
            switch (id)
            {
                case 0U:
                    return &state.group[0];
                case 1U:
                    return &state.group[1];
                case 2U:
                    return &state.group[2];
                case 3U:
                    return &state.group[3];
                default:
                    return nullptr;
            }
        }

        uint32_t address(uint16_t slot, KeyOffset offset)
        {
            return kTableBase + (static_cast<uint32_t>(slot) * kEntryStride) +
                   static_cast<uint32_t>(offset);
        }

        KeyCacheProgress progress(KeyCacheResult result,
                                  const KeyCacheState &state)
        {
            return {result, 0, 0, 0, state.requiresReset};
        }

        bool validBackend(const KeyCacheBackend &backend)
        {
            return backend.context != nullptr && backend.ownerEpoch != 0 &&
                   backend.permit != nullptr && backend.read32 != nullptr &&
                   backend.write32 != nullptr;
        }

        KeyCacheResult preflight(const KeyCacheBackend &backend,
                                 const KeyCacheState &state,
                                 bool requireInitialized)
        {
            if (!validBackend(backend))
            {
                return KeyCacheResult::InvalidBackend;
            }
            if (backend.barLengthBytes < kTableEnd)
            {
                return KeyCacheResult::InvalidBar;
            }
            if (state.requiresReset)
            {
                return KeyCacheResult::ResetRequired;
            }
            if (requireInitialized && !state.initialized)
            {
                return KeyCacheResult::NotInitialized;
            }
            if (state.initialized && (state.ownerContext != backend.context ||
                                      state.ownerEpoch != backend.ownerEpoch))
            {
                return KeyCacheResult::WrongOwner;
            }
            return KeyCacheResult::Ok;
        }

        bool permitted(const KeyCacheBackend &backend,
                       const KeyCacheState &state, KeyCacheProgress &out)
        {
            if (backend.permit(backend.context, backend.ownerEpoch))
            {
                return true;
            }
            out.result = KeyCacheResult::OwnershipLost;
            out.requiresReset = state.requiresReset;
            return false;
        }

        bool write(const KeyCacheBackend &backend, KeyCacheState &state,
                   KeyCacheProgress &out, uint16_t slot, KeyOffset offset,
                   uint32_t value)
        {
            if (!permitted(backend, state, out))
            {
                return false;
            }
            // A false write result may still mean that MMIO reached silicon.
            // Latch a hardware reset requirement BEFORE each write callback.
            state.requiresReset = true;
            out.requiresReset = true;
            out.lastOffset = address(slot, offset);
            if (!backend.write32(backend.context, out.lastOffset, value))
            {
                out.result = KeyCacheResult::WriteFailed;
                return false;
            }
            ++out.completedWrites;
            return true;
        }

        bool verify(const KeyCacheBackend &backend, const KeyCacheState &state,
                    KeyCacheProgress &out, uint16_t slot, KeyOffset offset,
                    uint32_t expected)
        {
            if (!permitted(backend, state, out))
            {
                return false;
            }
            out.lastOffset = address(slot, offset);
            uint32_t observed = 0;
            if (!backend.read32(backend.context, out.lastOffset, &observed))
            {
                out.result = KeyCacheResult::ReadFailed;
                return false;
            }
            ++out.completedReads;
            if (observed != expected)
            {
                out.result = KeyCacheResult::VerifyFailed;
                return false;
            }
            return true;
        }

        bool scrubSlot(const KeyCacheBackend &backend, KeyCacheState &state,
                       KeyCacheProgress &out, uint16_t slot)
        {
            // Revoke receiver lookup and cipher selection BEFORE overwriting
            // secret words. No queued descriptor may still reference the key.
            return write(backend, state, out, slot, kMac0, 0U) &&
                   write(backend, state, out, slot, kMac1, 0U) &&
                   write(backend, state, out, slot, kType, kClear) &&
                   write(backend, state, out, slot, kKey0, 0U) &&
                   write(backend, state, out, slot, kKey1, 0U) &&
                   write(backend, state, out, slot, kKey2, 0U) &&
                   write(backend, state, out, slot, kKey3, 0U) &&
                   write(backend, state, out, slot, kKey4, 0U) &&
                   verify(backend, state, out, slot, kMac0, 0U) &&
                   verify(backend, state, out, slot, kMac1, 0U) &&
                   verify(backend, state, out, slot, kType, kClear);
        }

        bool programSlot(const KeyCacheBackend &backend, KeyCacheState &state,
                         KeyCacheProgress &out, uint16_t slot,
                         const KeyBytes &key, const MacBytes &mac)
        {
            if (!scrubSlot(backend, state, out, slot))
            {
                return false;
            }
            // Paired 32-bit register writes are REQUIRED by the Atheros key
            // RAM; key1/key3 store 16 bits but must still be 32-bit writes.
            const uint32_t low = static_cast<uint32_t>(mac.b0) |
                                 (static_cast<uint32_t>(mac.b1) << kShift8) |
                                 (static_cast<uint32_t>(mac.b2) << kShift16) |
                                 (static_cast<uint32_t>(mac.b3) << kShift24);
            const uint32_t high = static_cast<uint32_t>(mac.b4) |
                                  (static_cast<uint32_t>(mac.b5) << kShift8);
            const uint32_t macLow =
                (low >> kAddressShift) | ((high & 1U) << kMacCarryShift);
            const uint32_t macHigh = (high >> kAddressShift) | kUnicastValid;
            return write(backend, state, out, slot, kKey0,
                         readWord(key.key0)) &&
                   write(backend, state, out, slot, kKey1,
                         readHalf(key.key1)) &&
                   write(backend, state, out, slot, kKey2,
                         readWord(key.key2)) &&
                   write(backend, state, out, slot, kKey3,
                         readHalf(key.key3)) &&
                   write(backend, state, out, slot, kKey4,
                         readWord(key.key4)) &&
                   write(backend, state, out, slot, kType, kCcmp) &&
                   write(backend, state, out, slot, kMac0, macLow) &&
                   write(backend, state, out, slot, kMac1, macHigh) &&
                   verify(backend, state, out, slot, kType, kCcmp) &&
                   verify(backend, state, out, slot, kMac0, macLow) &&
                   verify(backend, state, out, slot, kMac1, macHigh) &&
                   permitted(backend, state, out);
        }

        bool validAp(const MacBytes &mac)
        {
            return (static_cast<uint32_t>(mac.b0) & kMulticastBit) == 0U &&
                   (mac.b0 != 0U || mac.b1 != 0U || mac.b2 != 0U ||
                    mac.b3 != 0U || mac.b4 != 0U || mac.b5 != 0U);
        }

        uint64_t decodeRsc(const RscBytes &rsc)
        {
            return static_cast<uint64_t>(rsc.r0) |
                   (static_cast<uint64_t>(rsc.r1) << kShift8) |
                   (static_cast<uint64_t>(rsc.r2) << kShift16) |
                   (static_cast<uint64_t>(rsc.r3) << kShift24) |
                   (static_cast<uint64_t>(rsc.r4) << kShift32) |
                   (static_cast<uint64_t>(rsc.r5) << kShift40);
        }

        __attribute__((noinline, optnone)) void wipe(KeyBytes &bytes)
        {
            __builtin_memset(&bytes, 0, sizeof(bytes));
        }

        KeyCacheProgress install(const KeyCacheBackend &backend,
                                 KeyCacheState &state, uint16_t slot,
                                 const uint8_t *borrowedKey,
                                 const MacBytes &mac)
        {
            KeyCacheProgress out = progress(KeyCacheResult::Ok, state);
            KeyBytes key {};
            __builtin_memcpy(&key, borrowedKey, sizeof(key));
            const bool written =
                programSlot(backend, state, out, slot, key, mac);
            wipe(key);
            if (written)
            {
                state.requiresReset = false;
                out.requiresReset = false;
            }
            return out;
        }

        KeyCacheProgress erase(const KeyCacheBackend &backend,
                               KeyCacheState &state, uint16_t slot)
        {
            // Once erasure is attempted, a revoked gate still leaves a key
            // in device RAM. Require hardware reset rather than retrying.
            state.requiresReset = true;
            KeyCacheProgress out = progress(KeyCacheResult::Ok, state);
            if (scrubSlot(backend, state, out, slot) &&
                permitted(backend, state, out))
            {
                state.requiresReset = false;
                out.requiresReset = false;
            }
            return out;
        }
    } // namespace

    KeyCacheProgress initializeAr9565KeyCache(const KeyCacheBackend &backend,
                                              KeyCacheState &state)
    {
        KeyCacheProgress out =
            progress(preflight(backend, state, false), state);
        if (out.result != KeyCacheResult::Ok)
        {
            return out;
        }
        if (state.initialized)
        {
            out.result = KeyCacheResult::SlotOccupied;
            return out;
        }
        if (!permitted(backend, state, out))
        {
            return out;
        }
        state.ownerContext = backend.context;
        state.ownerEpoch = backend.ownerEpoch;
        for (uint16_t slot = 0; slot < kEntryCount; ++slot)
        {
            if (!scrubSlot(backend, state, out, slot))
            {
                return out;
            }
        }
        if (!permitted(backend, state, out))
        {
            return out;
        }
        state.initialized = true;
        state.requiresReset = false;
        out.requiresReset = false;
        return out;
    }

    KeyCacheProgress installAr9565PairwiseKey(const KeyCacheBackend &backend,
                                              KeyCacheState &state,
                                              const ieee80211::Mac &ap,
                                              const uint8_t key[kCcmpKeyBytes])
    {
        const auto check = preflight(backend, state, true);
        if (check != KeyCacheResult::Ok)
        {
            return progress(check, state);
        }
        if (key == nullptr)
        {
            return progress(KeyCacheResult::InvalidKey, state);
        }
        MacBytes mac {};
        __builtin_memcpy(&mac, &ap.bytes, sizeof(mac));
        if (!validAp(mac))
        {
            return progress(KeyCacheResult::InvalidAddress, state);
        }
        if (state.pairwiseInstalled)
        {
            return progress(KeyCacheResult::SlotOccupied, state);
        }
        auto out = install(backend, state, kCcmpPairwiseSlot, key, mac);
        if (out.result == KeyCacheResult::Ok)
        {
            state.pairwiseInstalled = true;
        }
        return out;
    }

    KeyCacheProgress installAr9565GroupKey(const KeyCacheBackend &backend,
                                           KeyCacheState &state, uint8_t keyId,
                                           const uint8_t key[kCcmpKeyBytes],
                                           const uint8_t keyRsc[kCcmpRscBytes])
    {
        const auto check = preflight(backend, state, true);
        if (check != KeyCacheResult::Ok)
        {
            return progress(check, state);
        }
        if (key == nullptr || keyRsc == nullptr || keyId >= kCcmpGroupSlots)
        {
            return progress(KeyCacheResult::InvalidKey, state);
        }
        RscBytes rsc {};
        __builtin_memcpy(&rsc, keyRsc, sizeof(rsc));
        if (rsc.reserved0 != 0 || rsc.reserved1 != 0)
        {
            return progress(KeyCacheResult::InvalidRsc, state);
        }
        if (!state.pairwiseInstalled)
        {
            return progress(KeyCacheResult::NotInitialized, state);
        }
        KeyCacheGroup *const group = groupFor(state, keyId);
        if (group == nullptr)
        {
            return progress(KeyCacheResult::InvalidKey, state);
        }
        if (group->installed)
        {
            return progress(KeyCacheResult::SlotOccupied, state);
        }
        const MacBytes noAddress {};
        auto out = install(backend, state, keyId, key, noAddress);
        if (out.result == KeyCacheResult::Ok)
        {
            group->receiveFloor = decodeRsc(rsc);
            group->installed = true;
        }
        return out;
    }

    KeyCacheProgress eraseAr9565GroupKey(const KeyCacheBackend &backend,
                                         KeyCacheState &state, uint8_t keyId)
    {
        const auto check = preflight(backend, state, true);
        if (check != KeyCacheResult::Ok)
        {
            return progress(check, state);
        }
        if (keyId >= kCcmpGroupSlots)
        {
            return progress(KeyCacheResult::InvalidKey, state);
        }
        KeyCacheGroup *const group = groupFor(state, keyId);
        if (group == nullptr || !group->installed)
        {
            return progress(KeyCacheResult::NotInitialized, state);
        }
        auto out = erase(backend, state, keyId);
        if (out.result == KeyCacheResult::Ok)
        {
            group->installed = false;
            group->receiveFloor = 0;
        }
        return out;
    }

    KeyCacheProgress eraseAr9565Keys(const KeyCacheBackend &backend,
                                     KeyCacheState &state)
    {
        const auto check = preflight(backend, state, true);
        if (check != KeyCacheResult::Ok)
        {
            return progress(check, state);
        }
        // An absent owner before the first write must not be reported as a
        // safely wiped keycache. This is a one-way revocation until reset.
        state.requiresReset = true;
        KeyCacheProgress out = progress(KeyCacheResult::Ok, state);
        // Revoke published software state BEFORE any potentially failing
        // hardware wipe. Native RX/TX authorization must be revoked first.
        state.pairwiseInstalled = false;
        for (auto &group : state.group)
        {
            group.installed = false;
            group.receiveFloor = 0;
        }
        for (uint16_t slot = 0; slot <= kCcmpPairwiseSlot; ++slot)
        {
            if (!scrubSlot(backend, state, out, slot))
            {
                return out;
            }
        }
        if (permitted(backend, state, out))
        {
            state.requiresReset = false;
            out.requiresReset = false;
        }
        return out;
    }
} // namespace simpleath
