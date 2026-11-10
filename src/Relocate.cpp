//
//  Relocate.cpp
//  SimpleATH
//
//  Created by laobamac on 2026/11/1.
//  Copyright © 2026 laobamac. All rights reserved.
//

#include "Payload.hpp"
#include <string.h>

namespace ath
{
    namespace
    {
        bool overlapsStorage(const void *first, size_t firstLength,
                             const void *second, size_t secondLength)
        {
            if ((first == nullptr) || (second == nullptr) ||
                (firstLength == 0u) || (secondLength == 0u))
            {
                return false;
            }
            const auto left = reinterpret_cast<uintptr_t>(first);
            const auto right = reinterpret_cast<uintptr_t>(second);
            // Compare distances rather than adding potentially untrusted
            // buffer lengths to an address-sized integer.
            return left <= right ? right - left < firstLength
                                 : left - right < secondLength;
        }
    } // namespace

    uint64_t payloadChecksum(const uint8_t *bytes, size_t length)
    {
        uint64_t value = 14695981039346656037ULL;
        for (size_t i = 0; i < length; ++i)
        {
            value = (value ^ bytes[i]) * 1099511628211ULL;
        }
        return value;
    }

    bool restorePayload(LinkedImage &image)
    {
        if ((image.payload == nullptr) || (image.memory == nullptr) ||
            !image.editable || image.registered)
        {
            return false;
        }
        const auto &p = *image.payload;
        if ((p.bytes == nullptr) || (p.size == 0u) || p.size > p.bytesSize ||
            p.size > p.mappedSize || p.stubOffset < p.size ||
            p.stubOffset > p.mappedSize ||
            p.stubSize > p.mappedSize - p.stubOffset ||
            image.address > UINTPTR_MAX - p.mappedSize ||
            ((p.deltaSize != 0u) && (p.delta == nullptr)))
        {
            return false;
        }
        // Both inputs must survive copying/zeroing the destination. In
        // particular, an in-place delta is validated below, then destroyed
        // before it can be replayed, silently changing the restored image.
        // The payload metadata and image descriptor must remain intact too.
        if (overlapsStorage(image.memory, p.mappedSize, p.bytes, p.size) ||
            overlapsStorage(image.memory, p.mappedSize, p.delta, p.deltaSize) ||
            overlapsStorage(image.memory, p.mappedSize, image.payload,
                            sizeof(*image.payload)) ||
            overlapsStorage(image.memory, p.mappedSize, &image, sizeof(image)))
        {
            return false;
        }
        uint32_t position = 0;
        uint32_t end = 0;
        while (position < p.deltaSize)
        {
            if (p.deltaSize - position < 8)
            {
                return false;
            }
            uint32_t offset;
            uint32_t length;
            memcpy(&offset, p.delta + position, 4);
            memcpy(&length, p.delta + position + 4, 4);
            position += 8;
            if ((length == 0u) || offset < end || offset > p.size ||
                length > p.size - offset || length > p.deltaSize - position)
            {
                return false;
            }
            end = offset + length;
            position += length;
        }
        memcpy(image.memory, p.bytes, p.size);
        memset(image.memory + p.size, 0, p.mappedSize - p.size);
        position = 0;
        while (position < p.deltaSize)
        {
            uint32_t offset;
            uint32_t length;
            memcpy(&offset, p.delta + position, 4);
            memcpy(&length, p.delta + position + 4, 4);
            position += 8;
            memcpy(image.memory + offset, p.delta + position, length);
            position += length;
        }
        image.stubUsed = 0;
        return true;
    }

    uintptr_t findSymbol(const LinkedImage &image, const char *name)
    {
        if ((image.payload == nullptr) || (name == nullptr) ||
            ((image.payload->symbolCount != 0u) &&
             (image.payload->symbols == nullptr)) ||
            image.address > UINTPTR_MAX - image.payload->size)
        {
            return 0;
        }
        size_t begin = 0;
        size_t end = image.payload->symbolCount;
        while (begin < end)
        {
            auto middle = begin + ((end - begin) / 2);
            const auto &entry = image.payload->symbols[middle];
            if (entry.name == nullptr)
            {
                return 0;
            }
            int order = strcmp(name, entry.name);
            if (order == 0)
            {
                return entry.offset < image.payload->size
                           ? image.address + entry.offset
                           : 0;
            }
            if (order < 0)
            {
                end = middle;
            }
            else
            {
                begin = middle + 1;
            }
        }
        return 0;
    }

    uintptr_t allocateStub(LinkedImage &image, uintptr_t target)
    {
        if ((image.payload == nullptr) || (image.memory == nullptr) ||
            !image.editable)
        {
            return 0;
        }
        const auto &p = *image.payload;
        // allocateStub is also callable outside restore/relocate. A forged
        // overlapping stub offset must never overwrite live executable bytes.
        if (image.stubUsed > p.stubSize || p.stubSize - image.stubUsed < 16 ||
            p.stubOffset < p.size || p.stubOffset > p.mappedSize ||
            p.stubSize > p.mappedSize - p.stubOffset ||
            image.address > UINTPTR_MAX - p.mappedSize)
        {
            return 0;
        }
        const auto offset = p.stubOffset + image.stubUsed;
        auto *const stub = image.memory + offset;
        // Direct callers do not pass through relocateImage's alias checks.
        // Stub bytes must not corrupt owned descriptors, source templates or
        // immutable tables consulted by later relocations and restores.
        if (overlapsStorage(stub, 16, image.payload, sizeof(*image.payload)) ||
            overlapsStorage(stub, 16, &image, sizeof(image)) ||
            overlapsStorage(stub, 16, p.bytes, p.size) ||
            overlapsStorage(stub, 16, p.delta, p.deltaSize) ||
            overlapsStorage(stub, 16, p.relocations,
                            static_cast<size_t>(p.relocationCount) *
                                sizeof(Relocation)) ||
            overlapsStorage(stub, 16, p.symbolValues,
                            static_cast<size_t>(p.symbolValueCount) *
                                sizeof(uint32_t)) ||
            overlapsStorage(stub, 16, p.symbols,
                            static_cast<size_t>(p.symbolCount) *
                                sizeof(Symbol)) ||
            overlapsStorage(stub, 16, p.routes,
                            static_cast<size_t>(p.routeCount) *
                                sizeof(RoutePrefix)))
        {
            return 0;
        }
        const uint8_t jump[] = {0xFF, 0x25, 0, 0, 0, 0};
        memcpy(stub, jump, sizeof(jump));
        memcpy(stub + sizeof(jump), &target, sizeof(target));
        image.stubUsed += 16;
        return image.address + offset;
    }

    bool relocateImage(LinkedImage &image, const LinkedImage *images,
                       size_t imageCount, const uintptr_t *imports,
                       size_t importCount, const uintptr_t *compatibility,
                       size_t compatibilityCount)
    {
        if ((image.payload == nullptr) || (image.memory == nullptr) ||
            !image.editable || ((imageCount != 0u) && (images == nullptr)) ||
            ((importCount != 0u) && (imports == nullptr)) ||
            ((compatibilityCount != 0u) && (compatibility == nullptr)))
        {
            return false;
        }
        const auto &p = *image.payload;
        if (p.size > p.mappedSize || p.stubOffset < p.size ||
            p.stubOffset > p.mappedSize ||
            p.stubSize > p.mappedSize - p.stubOffset ||
            image.address > UINTPTR_MAX - p.mappedSize ||
            ((p.relocationCount != 0u) && (p.relocations == nullptr)) ||
            ((p.symbolValueCount != 0u) && (p.symbolValues == nullptr)) ||
            payloadChecksum(image.memory, p.size) != p.checksum)
        {
            return false;
        }
        // Sources for every relocation pass must stay immutable while the
        // target mapping is written. Otherwise a forged metadata table in the
        // mapping can be rewritten after checksum validation, changing later
        // offsets/targets or falsely reporting a successful relocation.
        // Relocation and symbol counts are 32-bit on this 64-bit target;
        // the caller-supplied size_t counts still need overflow bounds.
        if (imageCount > SIZE_MAX / sizeof(LinkedImage) ||
            importCount > SIZE_MAX / sizeof(uintptr_t) ||
            compatibilityCount > SIZE_MAX / sizeof(uintptr_t) ||
            overlapsStorage(image.memory, p.mappedSize, p.relocations,
                            static_cast<size_t>(p.relocationCount) *
                                sizeof(Relocation)) ||
            overlapsStorage(image.memory, p.mappedSize, p.symbolValues,
                            static_cast<size_t>(p.symbolValueCount) *
                                sizeof(uint32_t)) ||
            overlapsStorage(image.memory, p.mappedSize, images,
                            imageCount * sizeof(LinkedImage)) ||
            overlapsStorage(image.memory, p.mappedSize, imports,
                            importCount * sizeof(uintptr_t)) ||
            overlapsStorage(image.memory, p.mappedSize, compatibility,
                            compatibilityCount * sizeof(uintptr_t)) ||
            overlapsStorage(image.memory, p.mappedSize, image.payload,
                            sizeof(*image.payload)) ||
            overlapsStorage(image.memory, p.mappedSize, &image, sizeof(image)))
        {
            return false;
        }
        for (uint32_t i = 0; i < p.relocationCount; ++i)
        {
            const auto &r = p.relocations[i];
            if ((r.width != 4 && r.width != 8) || r.offset > p.size ||
                r.width > p.size - r.offset)
            {
                return false;
            }
            uintptr_t target;
            if (r.image == 255)
            {
                if (r.target >= importCount || (imports[r.target] == 0u))
                {
                    return false;
                }
                target = imports[r.target];
            }
            else if (r.image == 254)
            {
                if (r.target >= compatibilityCount ||
                    (compatibility[r.target] == 0u))
                {
                    return false;
                }
                target = compatibility[r.target];
            }
            else
            {
                if (r.image >= imageCount ||
                    (images[r.image].payload == nullptr) ||
                    (images[r.image].memory == nullptr) ||
                    r.target >= images[r.image].payload->size ||
                    images[r.image].address > UINTPTR_MAX - r.target)
                {
                    return false;
                }
                target = images[r.image].address + r.target;
            }
            // A relocation addend is signed. Wraparound could otherwise
            // manufacture a plausible but unrelated kernel pointer.
            if (r.addend < 0)
            {
                const uint64_t magnitude =
                    static_cast<uint64_t>(-(r.addend + 1)) + 1U;
                if (target < magnitude)
                {
                    return false;
                }
                target -= magnitude;
            }
            else
            {
                const uint64_t magnitude = static_cast<uint64_t>(r.addend);
                if (magnitude > UINTPTR_MAX || target > UINTPTR_MAX - magnitude)
                {
                    return false;
                }
                target += magnitude;
            }
            if (r.width == 8)
            {
                memcpy(image.memory + r.offset, &target, 8);
            }
            else
            {
                auto pc = image.address + r.offset + 4;
                int64_t delta = static_cast<int64_t>(target - pc);
                if (delta < INT32_MIN || delta > INT32_MAX)
                {
                    target = allocateStub(image, target);
                    if (target == 0u)
                    {
                        return false;
                    }
                    delta = static_cast<int64_t>(target - pc);
                    if (delta < INT32_MIN || delta > INT32_MAX)
                    {
                        return false;
                    }
                }
                int32_t value = static_cast<int32_t>(delta);
                memcpy(image.memory + r.offset, &value, 4);
            }
        }
        for (uint32_t i = 0; i < p.symbolValueCount; ++i)
        {
            auto offset = p.symbolValues[i];
            if (offset > p.size || 8 > p.size - offset)
            {
                return false;
            }
            uint64_t value;
            memcpy(&value, image.memory + offset, 8);
            if (value >= p.size)
            {
                return false;
            }
            value += image.address;
            memcpy(image.memory + offset, &value, 8);
        }
        return true;
    }

} // namespace ath
