//
//  NativeProfile.hpp
//  SimpleATH
//
//  Created by laobamac on 2026/11/1.
//  Copyright © 2026 laobamac. All rights reserved.
//

#ifndef SIMPLEATH_NATIVE_PROFILE_HPP
#define SIMPLEATH_NATIVE_PROFILE_HPP

#include "Payload.hpp"
#include <stddef.h>
#include <stdint.h>

namespace ath
{

    enum class SkyAPI : uint32_t
    {
        EthernetConstructor,
        EthernetDestructor,
        EthernetInit,
        EthernetFree,
        EthernetTable,
        PacketTable,
        PoolTable,
        RegisterEthernet,
        RegisterEthernetLink,
        RegisterNetworkLink,
        DeregisterEthernet,
        TxWithPool,
        TxSubmission,
        TxRequest,
        TypedNew,
        TypedDelete,
        JoinPowerTree,
        Count,
    };

    struct NativeClientProfile
    {
            uint32_t constructor;
            uint32_t destructor;
            uint32_t free;
            uint32_t meta;
            uint32_t vtable;
            uint32_t slots;
    };

    extern const NativeClientProfile nativeClientProfiles[2];

    struct SkyEntry
    {
            uint32_t index;
            uint32_t source;
    };

    struct SkyMethod
    {
            uint32_t nativeIndex;
            uint32_t oldSlot;
    };

    struct SkyCallback
    {
            uint32_t nativeSlot;
            uint32_t method;
    };

    struct SkyClass
    {
            uint32_t image;
            uint32_t vtable;
            const SkyCallback *callbacks;
            uint32_t count;
    };

    struct NativeClassGuard
    {
            uint32_t meta;
            uint32_t size;
    };

    struct NativeCodeReference
    {
            uint32_t offset;
            uint32_t target;
    };

    struct NativeLinkPattern
    {
            const uint8_t *bytes;
            const uint8_t *mask;
            uint32_t size;
            const NativeCodeReference *references;
            uint32_t referenceCount;
    };

    struct NativeSystemProfile
    {
            uint32_t kernel;
            const char *name;
            uint32_t ethernetSize;
            uint32_t poolSize;
            uint32_t ethernetSlots;
            uint32_t airPortPayloadIndex;
            uint32_t ethernetLinkSlot;
            NativeLinkPattern ethernetLinkPattern;
            const NativeVtableGuard *vtableGuards;
            uint32_t vtableGuardCount;
            const NativeClassGuard *classGuards;
            uint32_t classGuardCount;
            const SkyClass *classes;
    };

    namespace detail
    {
        inline bool rel32TargetMatches(const uint8_t *bytes,
                                       uintptr_t nextAddress,
                                       uintptr_t expectedTarget)
        {
            const uint32_t displacement =
                static_cast<uint32_t>(bytes[0]) |
                static_cast<uint32_t>(bytes[1]) << 8U |
                static_cast<uint32_t>(bytes[2]) << 16U |
                static_cast<uint32_t>(bytes[3]) << 24U;
            // Decode signed rel32 without relying on out-of-range signed casts.
            const int64_t delta =
                displacement > INT32_MAX
                    ? static_cast<int64_t>(displacement) -
                          (static_cast<int64_t>(UINT32_MAX) + 1)
                    : static_cast<int64_t>(displacement);
            if (delta < 0)
            {
                const auto backward = static_cast<uintptr_t>(-delta);
                return backward <= nextAddress &&
                       nextAddress - backward == expectedTarget;
            }
            const auto forward = static_cast<uintptr_t>(delta);
            return forward <= UINTPTR_MAX - nextAddress &&
                   nextAddress + forward == expectedTarget;
        }
    } // namespace detail

    inline uintptr_t findNativeLink(const uint8_t *text, size_t size,
                                    uintptr_t address,
                                    const NativeLinkPattern &pattern,
                                    const uintptr_t *imports,
                                    size_t importCount)
    {
        if (text == nullptr || imports == nullptr || pattern.bytes == nullptr ||
            pattern.mask == nullptr || pattern.size == 0 ||
            pattern.size > size || pattern.references == nullptr ||
            pattern.referenceCount == 0 || size > UINTPTR_MAX - address)
        {
            return 0;
        }
        uintptr_t result = 0;
        bool found = false;
        for (size_t offset = 0; offset <= size - pattern.size; ++offset)
        {
            bool matches = true;
            for (size_t i = 0; i < pattern.size; ++i)
            {
                if ((text[offset + i] & pattern.mask[i]) !=
                    (pattern.bytes[i] & pattern.mask[i]))
                {
                    matches = false;
                    break;
                }
            }
            if (!matches)
            {
                continue;
            }
            for (uint32_t i = 0; i < pattern.referenceCount; ++i)
            {
                const auto &reference = pattern.references[i];
                if (reference.target >= importCount ||
                    reference.offset > pattern.size ||
                    pattern.size - reference.offset < sizeof(int32_t))
                {
                    return 0;
                }
                const uintptr_t next =
                    address + offset + reference.offset + sizeof(int32_t);
                if (!detail::rel32TargetMatches(
                        text + offset + reference.offset, next,
                        imports[reference.target]))
                {
                    matches = false;
                    break;
                }
            }
            if (matches)
            {
                // A valid match at virtual address zero must still count.
                if (found)
                {
                    return 0;
                }
                found = true;
                result = address + offset;
            }
        }
        return result;
    }

    extern const NativeSystemProfile nativeSystems[];
    extern const uint32_t nativeSystemCount;
    extern const NativeSystemProfile *nativeSystem;

    inline const NativeSystemProfile *nativeSystemForKernel(uint32_t kernel)
    {
        for (uint32_t i = 0; i < nativeSystemCount; ++i)
        {
            if (nativeSystems[i].kernel == kernel)
            {
                return &nativeSystems[i];
            }
        }
        return nullptr;
    }

    struct SkyPatch
    {
            uint32_t offset;
            uint32_t before;
            uint32_t after;
    };

    extern const uint32_t skyAPIImports[];
    extern const SkyEntry skyLegacyEntries[];
    extern const uint32_t skyLegacySlotCount;
    extern const SkyEntry skyPacketEntries[];
    extern const uint32_t skyPacketSlotCount;
    extern uint32_t skyNativeSlotCount;
    extern const SkyMethod skyMethods[];
    extern const uint32_t skyMethodCount;
    extern const SkyClass *skyClasses;
    extern const uint32_t skyClassCount;
    extern const SkyPatch skyPacketCalls[];
    extern const uint32_t skyPacketCallCount;
    extern const uint32_t skyPacketVptrSites[];
    extern const uint32_t skyPacketVptrSiteCount;
    extern const uint32_t skyPoolTypeView;
    extern const uint32_t skyPoolMetaSizeSites[];
    extern const uint32_t skyPoolMetaSizeSiteCount;
    extern const uint32_t skyPoolVtable;
    extern const uint32_t skyPacketVtable;
    extern const SkyEntry skyPacketSubclassEntries[];
    extern const uint32_t skyPacketSubclassSlotCount;
    extern "C" const uintptr_t athSkyForwarders[];
    extern "C" const uintptr_t athSkyCallbacks[];
    extern "C" const uintptr_t athCompatibilityImports[];
    extern const uint32_t compatibilityImportCount;
    extern const char *const compatibilityImportNames[];

} // namespace ath

#endif
