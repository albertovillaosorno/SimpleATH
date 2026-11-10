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
        // Kernel-import, link-pattern and Mach-O tables are immutable but
        // externally counted. Access each requested element only after an
        // address-range check; do not perform unchecked pointer arithmetic
        // against a caller-supplied span.
        template <typename T>
        inline bool readAt(const T *base, size_t index, T &value)
        {
            if (base == nullptr || index > UINTPTR_MAX / sizeof(T))
            {
                return false;
            }
            uintptr_t address = 0;
            static_assert(sizeof(address) == sizeof(const T *),
                          "native pointer width must match kernel addresses");
            __builtin_memcpy(&address, static_cast<const void *>(&base),
                             sizeof(address));
            const size_t offset = index * sizeof(T);
            if (offset > UINTPTR_MAX - address)
            {
                return false;
            }
            address += offset;
            const T *item = nullptr;
            __builtin_memcpy(static_cast<void *>(&item), &address,
                             sizeof(address));
            __builtin_memcpy(&value, item, sizeof(value));
            return true;
        }

        inline bool copyBytesAt(const uint8_t *base, size_t offset,
                                void *destination, size_t length)
        {
            if (base == nullptr || destination == nullptr)
            {
                return false;
            }
            uintptr_t address = 0;
            static_assert(sizeof(address) == sizeof(const uint8_t *),
                          "native byte pointer must fit uintptr_t");
            __builtin_memcpy(&address, static_cast<const void *>(&base),
                             sizeof(address));
            if (offset > UINTPTR_MAX - address ||
                length > UINTPTR_MAX - address - offset)
            {
                return false;
            }
            address += offset;
            const void *first = nullptr;
            __builtin_memcpy(static_cast<void *>(&first), &address,
                             sizeof(address));
            __builtin_memcpy(destination, first, length);
            return true;
        }

        inline bool rel32TargetMatches(const uint8_t *bytes,
                                       uintptr_t nextAddress,
                                       uintptr_t expectedTarget)
        {
            uint8_t rel[sizeof(int32_t)] {};
            if (!copyBytesAt(bytes, 0, &rel[0], sizeof(rel)))
            {
                return false;
            }
            const uint32_t displacement = static_cast<uint32_t>(rel[0]) |
                                          static_cast<uint32_t>(rel[1]) << 8U |
                                          static_cast<uint32_t>(rel[2]) << 16U |
                                          static_cast<uint32_t>(rel[3]) << 24U;
            // Decode signed rel32 without out-of-range signed casts.
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

        struct LinkCandidate
        {
                const uint8_t *text;
                uintptr_t address;
                size_t offset;
        };

        enum class ReferenceMatch : uint8_t
        {
            Invalid,
            Mismatch,
            Matched,
        };

        inline ReferenceMatch verifyReferences(const LinkCandidate &candidate,
                                               const NativeLinkPattern &pattern,
                                               const uintptr_t *imports,
                                               size_t importCount)
        {
            for (uint32_t i = 0; i < pattern.referenceCount; ++i)
            {
                NativeCodeReference reference {};
                if (!readAt(pattern.references, i, reference) ||
                    reference.target >= importCount ||
                    reference.offset > pattern.size ||
                    pattern.size - reference.offset < sizeof(int32_t))
                {
                    return ReferenceMatch::Invalid;
                }
                const size_t displacementOffset =
                    candidate.offset + static_cast<size_t>(reference.offset);
                const uintptr_t next =
                    candidate.address + displacementOffset + sizeof(int32_t);
                uint8_t rel[sizeof(int32_t)] {};
                uintptr_t expected = 0;
                if (!copyBytesAt(candidate.text, displacementOffset, &rel[0],
                                 sizeof(rel)) ||
                    !readAt(imports, reference.target, expected))
                {
                    return ReferenceMatch::Invalid;
                }
                if (!rel32TargetMatches(&rel[0], next, expected))
                {
                    return ReferenceMatch::Mismatch;
                }
            }
            return ReferenceMatch::Matched;
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
                uint8_t candidate = 0;
                uint8_t mask = 0;
                uint8_t expected = 0;
                if (!detail::readAt(text, offset + i, candidate) ||
                    !detail::readAt(pattern.mask, i, mask) ||
                    !detail::readAt(pattern.bytes, i, expected))
                {
                    return 0;
                }
                if ((candidate & mask) != (expected & mask))
                {
                    matches = false;
                    break;
                }
            }
            if (!matches)
            {
                continue;
            }
            const auto referenceResult = detail::verifyReferences(
                detail::LinkCandidate {text, address, offset}, pattern, imports,
                importCount);
            if (referenceResult == detail::ReferenceMatch::Invalid)
            {
                return 0;
            }
            if (referenceResult == detail::ReferenceMatch::Mismatch)
            {
                continue;
            }
            if (matches)
            {
                // A valid match at virtual address zero still counts.
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

    // The mutable native profile selection is local to the running kernel
    // adapter, not an independently writable exported global per field.
    struct NativeRuntimeProfileState
    {
            const NativeSystemProfile *system {nullptr};
            const SkyClass *classes {nullptr};
            uint32_t slotCount {0U};
    };

    NativeRuntimeProfileState &nativeRuntimeProfileState();

    inline const NativeSystemProfile *nativeSystemForKernel(uint32_t kernel)
    {
        for (uint32_t i = 0; i < nativeSystemCount; ++i)
        {
            NativeSystemProfile candidate {};
            if (!detail::readAt(&nativeSystems[0], i, candidate))
            {
                return nullptr;
            }
            if (candidate.kernel == kernel)
            {
                uintptr_t base = 0;
                const NativeSystemProfile *const start = &nativeSystems[0];
                __builtin_memcpy(&base, static_cast<const void *>(&start),
                                 sizeof(base));
                // i is a 32-bit table index; the product fits size_t on
                // the required x86_64 target, but base addition must not wrap.
                if (static_cast<size_t>(i) * sizeof(candidate) >
                    UINTPTR_MAX - base)
                {
                    return nullptr;
                }
                const uintptr_t at =
                    base + (static_cast<size_t>(i) * sizeof(candidate));
                const NativeSystemProfile *result = nullptr;
                __builtin_memcpy(static_cast<void *>(&result), &at, sizeof(at));
                return result;
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
    extern const SkyMethod skyMethods[];
    extern const uint32_t skyMethodCount;
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
