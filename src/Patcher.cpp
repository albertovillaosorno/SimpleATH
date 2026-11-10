//
//  Patcher.cpp
//  SimpleATH
//
//  Created by laobamac on 2026/11/1.
//  Copyright © 2026 laobamac. All rights reserved.
//

#include "Patcher.hpp"
#include "Payload.hpp"
#include <cstddef>
#include <cstdint>
#include <libkern/copyio.h>
#include <string.h>

uintptr_t KernelPatcher::branchTarget(uintptr_t target,
                                      uintptr_t programCounter)
{
    const auto delta = static_cast<int64_t>(target - programCounter);
    return delta >= INT32_MIN && delta <= INT32_MAX
               ? target
               : ath::allocateStub(image, target);
}

uintptr_t KernelPatcher::solveSymbol(size_t index, const char *name)
{
    if (index != KernelID)
    {
        return ath::findSymbol(image, name);
    }
    if (strcmp(name, "_copyin") == 0)
    {
        return reinterpret_cast<uintptr_t>(copyin);
    }
    if (strcmp(name, "_copyout") == 0)
    {
        return reinterpret_cast<uintptr_t>(copyout);
    }
    return 0;
}

bool KernelPatcher::routeMultipleLong(size_t index, RouteRequest *routes,
                                      size_t count, uintptr_t address,
                                      size_t size)
{
    // The native caller must quiesce the executable image while patching.
    // Preflight the entire batch so a late bad route cannot leave partial
    // hooks.
    static constexpr size_t kMaximumRoutes = 16U;
    static constexpr uint32_t kMinimumPrefix = 14U;
    static constexpr uint32_t kMaximumPrefix = 32U;
    static constexpr uint32_t kAbsoluteJumpBytes = 14U;
    static constexpr uint32_t kStubAlignment = 16U;

    struct PlannedRoute
    {
            uintptr_t address;
            uint32_t offset;
            uint32_t prefix;
            uint32_t stubOffset;
    };

    static_cast<void>(index);
    if (!image.editable || (image.payload == nullptr) ||
        (image.memory == nullptr) || (routes == nullptr) || count == 0 ||
        count > kMaximumRoutes)
    {
        return false;
    }
    const auto &payload = *image.payload;
    if ((payload.size == 0U) || payload.size > payload.mappedSize ||
        payload.stubOffset < payload.size ||
        payload.stubOffset > payload.mappedSize ||
        payload.stubSize > payload.mappedSize - payload.stubOffset ||
        image.stubUsed > payload.stubSize || (image.address == 0U) ||
        image.address > UINTPTR_MAX - payload.mappedSize ||
        address != image.address || size != payload.mappedSize ||
        ((payload.routeCount != 0U) && (payload.routes == nullptr)))
    {
        return false;
    }

    PlannedRoute planned[kMaximumRoutes] {};
    uint32_t used = image.stubUsed;
    for (size_t i = 0; i < count; ++i)
    {
        if ((routes[i].name == nullptr) || (routes[i].target == 0U) ||
            (routes[i].original == nullptr))
        {
            return false;
        }
        const uintptr_t location = ath::findSymbol(image, routes[i].name);
        if ((location == 0U) || location < image.address)
        {
            return false;
        }
        const uintptr_t offset = location - image.address;
        if (offset >= payload.size)
        {
            return false;
        }
        uint32_t prefix = 0;
        bool matched = false;
        for (uint32_t j = 0; j < payload.routeCount; ++j)
        {
            if (payload.routes[j].offset == offset)
            {
                if (matched)
                {
                    return false;
                }
                matched = true;
                prefix = payload.routes[j].length;
            }
        }
        if (prefix < kMinimumPrefix || prefix > kMaximumPrefix ||
            prefix > payload.size - offset)
        {
            return false;
        }
        for (size_t j = 0; j < i; ++j)
        {
            if (routes[i].original == routes[j].original ||
                (offset < planned[j].offset + planned[j].prefix &&
                 planned[j].offset < offset + prefix))
            {
                return false;
            }
        }
        const uint32_t needed =
            (prefix + kAbsoluteJumpBytes + kStubAlignment - 1U) &
            ~(kStubAlignment - 1U);
        if (needed > payload.stubSize - used)
        {
            return false;
        }
        planned[i] = {
            location,
            static_cast<uint32_t>(offset),
            prefix,
            payload.stubOffset + used,
        };
        used += needed;
    }

    const uint8_t jump[] = {0xFFU, 0x25U, 0, 0, 0, 0};
    for (size_t i = 0; i < count; ++i)
    {
        const PlannedRoute &route = planned[i];
        uint8_t *const stub = image.memory + route.stubOffset;
        memcpy(stub, reinterpret_cast<const void *>(route.address),
               route.prefix);
        memcpy(stub + route.prefix, &jump[0], sizeof(jump));
        const uintptr_t continuation = route.address + route.prefix;
        memcpy(stub + route.prefix + sizeof(jump), &continuation,
               sizeof(continuation));
        *routes[i].original = image.address + route.stubOffset;
        memcpy(reinterpret_cast<void *>(route.address), &jump[0], sizeof(jump));
        memcpy(reinterpret_cast<void *>(route.address + sizeof(jump)),
               &routes[i].target, sizeof(uintptr_t));
    }
    image.stubUsed = used;
    return true;
}
