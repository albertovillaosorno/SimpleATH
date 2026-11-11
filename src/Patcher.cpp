// Copyright:
//   - Copyright © 2026 laobamac. All rights reserved.
// SPDX-License-Identifier:
//   - LicenseRef-SimpleBCM-All-Rights-Reserved
// Confidential:
//   - false
// License-File:
//   - LICENSE-SIMPLEBCM
// Provenance:
//   - SimpleBCM v1.2.0, by laobamac; no public license grant identified
//   - Originally authored by laobamac on 2026/11/1.
//
// Boundary-Contract:
// - Owns:
//   - Native driver contracts and implementation for patcher.
// - Must-Not:
//   - Invent hardware readiness, weaken buffer bounds, or assume ABI
//     compatibility.
// - Allows:
//   - Inputs: validated register, protocol, platform, or device state from
//     callers.
//   - Outputs: bounded native transitions, messages, or explicit errors.
//   - Side effects: only the device and kernel operations owned by this module.
// - Split-When:
//   - A separate protocol stage needs independent validation and ownership.
// - Merge-When:
//   - The caller directly owns this narrow contract without reuse.
// - Summary:
//   - Native driver contracts and implementation for patcher.
// - Description:
//   - Implements or verifies the Patcher source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for patcher.

#include "Patcher.hpp"
#include "Payload.hpp"
#include <libkern/copyio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace
{
    constexpr size_t kMaximumRoutes = 16U;
    constexpr uint32_t kMinimumPrefix = 14U;
    constexpr uint32_t kMaximumPrefix = 32U;
    constexpr uint32_t kAbsoluteJumpBytes = 14U;
    constexpr uint32_t kStubAlignment = 16U;
    constexpr size_t kJumpOpcodeBytes = 6U;

    // On the supported x86_64 kernel, virtual addresses and object pointers
    // are the same width. Copy their representation rather than using a
    // cast that would also form an incompatible aliased object type.
    template <typename Pointer> uintptr_t pointerBits(Pointer pointer)
    {
        static_assert(sizeof(Pointer) == sizeof(uintptr_t),
                      "native patch address and pointer widths differ");
        uintptr_t bits = 0;
        __builtin_memcpy(&bits, static_cast<const void *>(&pointer),
                         sizeof(bits));
        return bits;
    }

    void *objectAt(uintptr_t address)
    {
        static_assert(sizeof(void *) == sizeof(uintptr_t),
                      "native patch address and pointer widths differ");
        void *pointer = nullptr;
        __builtin_memcpy(static_cast<void *>(&pointer), &address,
                         sizeof(pointer));
        return pointer;
    }

    template <typename T, size_t N> T &boundedAt(T (&items)[N], size_t index)
    {
        for (T &item : items)
        {
            if (index == 0U)
            {
                return item;
            }
            --index;
        }
        __builtin_trap(); // Caller rejects indices outside fixed capacity.
    }

    struct PlannedRoute
    {
            uintptr_t address;
            uintptr_t target;
            void *original;
            uint32_t offset;
            uint32_t prefix;
            uint32_t stubOffset;
            void *stub;
            void *stubJump;
            void *stubReturn;
            void *patch;
            void *patchTarget;
    };

    bool validBatch(const ath::LinkedImage &image,
                    const KernelPatcher::RouteBatch &batch,
                    const KernelPatcher::RouteRequest *routes)
    {
        if (!image.editable || image.payload == nullptr ||
            image.memory == nullptr || routes == nullptr || batch.count == 0U ||
            batch.count > kMaximumRoutes)
        {
            return false;
        }
        const auto &payload = *image.payload;
        const uintptr_t mappedBase = pointerBits(image.memory);
        return payload.size != 0U && payload.size <= payload.mappedSize &&
               payload.stubOffset >= payload.size &&
               payload.stubOffset <= payload.mappedSize &&
               payload.stubSize <= payload.mappedSize - payload.stubOffset &&
               image.stubUsed <= payload.stubSize && image.address != 0U &&
               image.address <= UINTPTR_MAX - payload.mappedSize &&
               mappedBase <= UINTPTR_MAX - payload.mappedSize &&
               batch.address == image.address &&
               batch.size == payload.mappedSize &&
               (payload.routeCount == 0U || payload.routes != nullptr);
    }

    bool matchingPrefix(const ath::Payload &payload, uintptr_t offset,
                        uint32_t &prefix)
    {
        bool matched = false;
        // Generated route-prefix storage is immutable, counted and bounded.
        // Verify the address range before decoding any entry.
        const size_t tableBytes =
            static_cast<size_t>(payload.routeCount) * sizeof(ath::RoutePrefix);
        if (pointerBits(payload.routes) > UINTPTR_MAX - tableBytes)
        {
            return false;
        }
        for (uint32_t i = 0; i < payload.routeCount; ++i)
        {
            ath::RoutePrefix candidate {};
            const uintptr_t entryAddress =
                pointerBits(payload.routes) +
                (static_cast<size_t>(i) * sizeof(candidate));
            __builtin_memcpy(&candidate, objectAt(entryAddress),
                             sizeof(candidate));
            if (candidate.offset == offset)
            {
                if (matched)
                {
                    return false;
                }
                matched = true;
                prefix = candidate.length;
            }
        }
        return matched && prefix >= kMinimumPrefix &&
               prefix <= kMaximumPrefix && prefix <= payload.size - offset;
    }

    bool conflicting(const KernelPatcher::RouteRequest &request,
                     uint32_t offset, uint32_t prefix,
                     const PlannedRoute (&plans)[kMaximumRoutes],
                     size_t completed)
    {
        for (size_t i = 0; i < completed; ++i)
        {
            const PlannedRoute &existing = boundedAt(plans, i);
            if (request.original() == existing.original ||
                (offset < existing.offset + existing.prefix &&
                 existing.offset < offset + prefix))
            {
                return true;
            }
        }
        return false;
    }

    bool planOne(const ath::LinkedImage &image,
                 const KernelPatcher::RouteRequest &request,
                 const PlannedRoute (&plans)[kMaximumRoutes], size_t completed,
                 uint32_t &used, PlannedRoute &out)
    {
        const auto &payload = *image.payload;
        if (request.name() == nullptr || request.target() == 0U ||
            request.original() == nullptr)
        {
            return false;
        }
        const uintptr_t location = ath::findSymbol(image, request.name());
        if (location == 0U || location < image.address)
        {
            return false;
        }
        const uintptr_t difference = location - image.address;
        if (difference >= payload.size)
        {
            return false;
        }
        uint32_t prefix = 0;
        if (!matchingPrefix(payload, difference, prefix) ||
            conflicting(request, static_cast<uint32_t>(difference), prefix,
                        plans, completed))
        {
            return false;
        }
        const uint32_t needed =
            (prefix + kAbsoluteJumpBytes + kStubAlignment - 1U) &
            ~(kStubAlignment - 1U);
        if (needed > payload.stubSize - used)
        {
            return false;
        }
        const uint32_t stubOffset = payload.stubOffset + used;
        const uintptr_t stub = pointerBits(image.memory) + stubOffset;
        out = {
            location,
            request.target(),
            request.original(),
            static_cast<uint32_t>(difference),
            prefix,
            stubOffset,
            objectAt(stub),
            objectAt(stub + prefix),
            objectAt(stub + prefix + kJumpOpcodeBytes),
            objectAt(location),
            objectAt(location + kJumpOpcodeBytes),
        };
        used += needed;
        return true;
    }

    void commitRoute(const PlannedRoute &plan)
    {
        const uint8_t jump[kJumpOpcodeBytes] = {0xFFU, 0x25U, 0, 0, 0, 0};
        memcpy(plan.stub, plan.patch, plan.prefix);
        memcpy(plan.stubJump, &jump[0], sizeof(jump));
        const uintptr_t continuation = plan.address + plan.prefix;
        memcpy(plan.stubReturn, &continuation, sizeof(continuation));
        // A saved function pointer is an opaque pointer-sized slot. Copy its
        // representation, never write through an aliasing uintptr_t pointer.
        const uintptr_t original = plan.address - plan.offset + plan.stubOffset;
        __builtin_memcpy(plan.original, &original, sizeof(original));
        memcpy(plan.patch, &jump[0], sizeof(jump));
        memcpy(plan.patchTarget, &plan.target, sizeof(plan.target));
    }
} // namespace

uintptr_t KernelPatcher::branchTarget(uintptr_t target,
                                      uintptr_t programCounter)
{
    const auto delta = static_cast<int64_t>(target - programCounter);
    return delta >= INT32_MIN && delta <= INT32_MAX
               ? target
               : ath::allocateStub(*image, target);
}

uintptr_t KernelPatcher::solveSymbol(size_t index, const char *name)
{
    if (index != KernelID)
    {
        return ath::findSymbol(*image, name);
    }
    if (strcmp(name, "_copyin") == 0)
    {
        return pointerBits(&copyin);
    }
    if (strcmp(name, "_copyout") == 0)
    {
        return pointerBits(&copyout);
    }
    return 0;
}

bool KernelPatcher::routeMultipleLong(size_t index, RouteRequest *routes,
                                      const RouteBatch &batch)
{
    static_cast<void>(index);
    // No writes to executable or caller-owned memory before the entire batch
    // has passed the snapshot, symbol and stub-capacity preflight.
    if (!validBatch(*image, batch, routes))
    {
        return false;
    }
    RouteRequest requests[kMaximumRoutes] {};
    static_assert(__is_trivially_copyable(RouteRequest),
                  "route input must be safe to snapshot byte-for-byte");
    __builtin_memcpy(&requests[0], routes, batch.count * sizeof(RouteRequest));
    PlannedRoute planned[kMaximumRoutes] {};
    uint32_t used = image->stubUsed;
    for (size_t i = 0; i < batch.count; ++i)
    {
        const RouteRequest &request = boundedAt(requests, i);
        if (!planOne(*image, request, planned, i, used, boundedAt(planned, i)))
        {
            return false;
        }
    }
    for (size_t i = 0; i < batch.count; ++i)
    {
        commitRoute(boundedAt(planned, i));
    }
    image->stubUsed = used;
    return true;
}
