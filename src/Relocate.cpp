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
//   - Native driver contracts and implementation for relocate.
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
//   - Native driver contracts and implementation for relocate.
// - Description:
//   - Implements or verifies the Relocate source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for relocate.

#include "Payload.hpp"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace ath
{
    namespace
    {
        // FNV-1a constants are part of the embedded payload checksum ABI.
        constexpr uint64_t kFnvOffset = 14695981039346656037ULL;
        constexpr uint64_t kFnvPrime = 1099511628211ULL;
        constexpr size_t kDeltaRecordHeaderBytes = 2U * sizeof(uint32_t);
        constexpr size_t kStubBytes = 16U;
        constexpr uint8_t kExternalImportImage = 255U;
        constexpr uint8_t kCompatibilityImportImage = 254U;
        constexpr uint8_t kRelativeRelocationWidth = 4U;
        constexpr uint8_t kAbsoluteRelocationWidth = 8U;

        // All call sites bound the offset to an existing payload allocation.
        // Reconstruct the byte address rather than forming an unchecked raw
        // pointer expression (which is not valid for unrelated kernel spans).
        template <typename T> T *byteAt(T *base, size_t offset)
        {
            static_assert(sizeof(uintptr_t) == sizeof(void *),
                          "host pointer address width");
            uintptr_t address = 0;
            __builtin_memcpy(static_cast<void *>(&address),
                             static_cast<const void *>(&base),
                             sizeof(uintptr_t));
            address += offset;
            T *result = nullptr;
            __builtin_memcpy(static_cast<void *>(&result),
                             static_cast<const void *>(&address),
                             sizeof(uintptr_t));
            return result;
        }

        template <typename T> T *elementAt(T *base, size_t index)
        {
            return byteAt(base, index * sizeof(T));
        }

        bool overlapsStorage(const void *first, size_t firstLength,
                             const void *second, size_t secondLength)
        {
            if ((first == nullptr) || (second == nullptr) ||
                (firstLength == 0U) || (secondLength == 0U))
            {
                return false;
            }
            uintptr_t left = 0;
            uintptr_t right = 0;
            static_assert(sizeof(left) == sizeof(first),
                          "payload pointer address width");
            __builtin_memcpy(static_cast<void *>(&left),
                             static_cast<const void *>(&first), sizeof(left));
            __builtin_memcpy(static_cast<void *>(&right),
                             static_cast<const void *>(&second), sizeof(right));
            // Compare distances rather than adding potentially untrusted
            // buffer lengths to an address-sized integer.
            return left <= right ? right - left < firstLength
                                 : left - right < secondLength;
        }
    } // namespace

    uint64_t payloadChecksum(const uint8_t *bytes, size_t length)
    {
        uint64_t value = kFnvOffset;
        for (size_t i = 0; i < length; ++i)
        {
            value = (value ^ *byteAt(bytes, i)) * kFnvPrime;
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
        if ((p.bytes == nullptr) || (p.size == 0U) || p.size > p.bytesSize ||
            p.size > p.mappedSize || p.stubOffset < p.size ||
            p.stubOffset > p.mappedSize ||
            p.stubSize > p.mappedSize - p.stubOffset ||
            image.address > UINTPTR_MAX - p.mappedSize ||
            ((p.deltaSize != 0U) && (p.delta == nullptr)))
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
            if (p.deltaSize - position < kDeltaRecordHeaderBytes)
            {
                return false;
            }
            uint32_t offset = 0;
            uint32_t length = 0;
            memcpy(&offset, byteAt(p.delta, position), 4);
            memcpy(&length, byteAt(p.delta, position + sizeof(uint32_t)), 4);
            position += kDeltaRecordHeaderBytes;
            if ((length == 0U) || offset < end || offset > p.size ||
                length > p.size - offset || length > p.deltaSize - position)
            {
                return false;
            }
            end = offset + length;
            position += length;
        }
        memcpy(image.memory, p.bytes, p.size);
        memset(byteAt(image.memory, p.size), 0, p.mappedSize - p.size);
        position = 0;
        while (position < p.deltaSize)
        {
            uint32_t offset = 0;
            uint32_t length = 0;
            memcpy(&offset, byteAt(p.delta, position), 4);
            memcpy(&length, byteAt(p.delta, position + sizeof(uint32_t)), 4);
            position += kDeltaRecordHeaderBytes;
            memcpy(byteAt(image.memory, offset), byteAt(p.delta, position),
                   length);
            position += length;
        }
        image.stubUsed = 0;
        return true;
    }

    uintptr_t findSymbol(const LinkedImage &image, const char *name)
    {
        if ((image.payload == nullptr) || (name == nullptr) ||
            ((image.payload->symbolCount != 0U) &&
             (image.payload->symbols == nullptr)) ||
            image.address > UINTPTR_MAX - image.payload->size)
        {
            return 0;
        }
        size_t begin = 0;
        size_t end = image.payload->symbolCount;
        while (begin < end)
        {
            const auto middle = begin + ((end - begin) / 2);
            const auto &entry = *elementAt(image.payload->symbols, middle);
            if (entry.name == nullptr)
            {
                return 0;
            }
            const int order = strcmp(name, entry.name);
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
        if (image.stubUsed > p.stubSize ||
            p.stubSize - image.stubUsed < kStubBytes || p.stubOffset < p.size ||
            p.stubOffset > p.mappedSize ||
            p.stubSize > p.mappedSize - p.stubOffset ||
            image.address > UINTPTR_MAX - p.mappedSize)
        {
            return 0;
        }
        const auto offset = p.stubOffset + image.stubUsed;
        auto *const stub = byteAt(image.memory, offset);
        // Direct callers do not pass through relocateImage's alias checks.
        // Stub bytes must not corrupt owned descriptors, source templates or
        // immutable tables consulted by later relocations and restores.
        if (overlapsStorage(stub, kStubBytes, image.payload,
                            sizeof(*image.payload)) ||
            overlapsStorage(stub, kStubBytes, &image, sizeof(image)) ||
            overlapsStorage(stub, kStubBytes, p.bytes, p.size) ||
            overlapsStorage(stub, kStubBytes, p.delta, p.deltaSize) ||
            overlapsStorage(stub, kStubBytes, p.relocations,
                            static_cast<size_t>(p.relocationCount) *
                                sizeof(Relocation)) ||
            overlapsStorage(stub, kStubBytes, p.symbolValues,
                            static_cast<size_t>(p.symbolValueCount) *
                                sizeof(uint32_t)) ||
            overlapsStorage(stub, kStubBytes, p.symbols,
                            static_cast<size_t>(p.symbolCount) *
                                sizeof(Symbol)) ||
            overlapsStorage(stub, kStubBytes, p.routes,
                            static_cast<size_t>(p.routeCount) *
                                sizeof(RoutePrefix)))
        {
            return 0;
        }
        const uint8_t jump[] = {0xFF, 0x25, 0, 0, 0, 0};
        memcpy(stub, &jump[0], sizeof(jump));
        memcpy(byteAt(stub, sizeof(jump)), &target, sizeof(target));
        image.stubUsed += kStubBytes;
        return image.address + offset;
    }

    namespace
    {
        struct RelocationSources
        {
                const LinkedImage *images;
                size_t imageCount;
                const uintptr_t *imports;
                size_t importCount;
                const uintptr_t *compatibility;
                size_t compatibilityCount;
        };

        bool validRelocationImage(const LinkedImage &image,
                                  const RelocationSources &sources)
        {
            if ((image.payload == nullptr) || (image.memory == nullptr) ||
                !image.editable ||
                ((sources.imageCount != 0U) && (sources.images == nullptr)) ||
                ((sources.importCount != 0U) && (sources.imports == nullptr)) ||
                ((sources.compatibilityCount != 0U) &&
                 (sources.compatibility == nullptr)))
            {
                return false;
            }
            const auto &p = *image.payload;
            return p.size <= p.mappedSize && p.stubOffset >= p.size &&
                   p.stubOffset <= p.mappedSize &&
                   p.stubSize <= p.mappedSize - p.stubOffset &&
                   image.address <= UINTPTR_MAX - p.mappedSize &&
                   (p.relocationCount == 0U || p.relocations != nullptr) &&
                   (p.symbolValueCount == 0U || p.symbolValues != nullptr) &&
                   payloadChecksum(image.memory, p.size) == p.checksum;
        }

        bool separatedRelocationSources(const LinkedImage &image,
                                        const RelocationSources &sources)
        {
            const auto &p = *image.payload;
            // Sources for every relocation pass must stay immutable while the
            // target mapping is written. Otherwise a forged metadata table in
            // the mapping can be rewritten after checksum validation, changing
            // later offsets/targets or falsely reporting a successful
            // relocation. Relocation and symbol counts are 32-bit on this
            // 64-bit target; the caller-supplied size_t counts still need
            // overflow bounds.
            return !(
                sources.imageCount > SIZE_MAX / sizeof(LinkedImage) ||
                sources.importCount > SIZE_MAX / sizeof(uintptr_t) ||
                sources.compatibilityCount > SIZE_MAX / sizeof(uintptr_t) ||
                overlapsStorage(image.memory, p.mappedSize, p.relocations,
                                static_cast<size_t>(p.relocationCount) *
                                    sizeof(Relocation)) ||
                overlapsStorage(image.memory, p.mappedSize, p.symbolValues,
                                static_cast<size_t>(p.symbolValueCount) *
                                    sizeof(uint32_t)) ||
                overlapsStorage(image.memory, p.mappedSize, sources.images,
                                sources.imageCount * sizeof(LinkedImage)) ||
                overlapsStorage(image.memory, p.mappedSize, sources.imports,
                                sources.importCount * sizeof(uintptr_t)) ||
                overlapsStorage(
                    image.memory, p.mappedSize, sources.compatibility,
                    sources.compatibilityCount * sizeof(uintptr_t)) ||
                overlapsStorage(image.memory, p.mappedSize, image.payload,
                                sizeof(*image.payload)) ||
                overlapsStorage(image.memory, p.mappedSize, &image,
                                sizeof(image)));
        }

        bool relocationTarget(const Relocation &r,
                              const RelocationSources &sources,
                              uintptr_t &target)
        {
            if (r.image == kExternalImportImage)
            {
                if (r.target >= sources.importCount ||
                    (*elementAt(sources.imports, r.target) == 0U))
                {
                    return false;
                }
                target = *elementAt(sources.imports, r.target);
            }
            else if (r.image == kCompatibilityImportImage)
            {
                if (r.target >= sources.compatibilityCount ||
                    (*elementAt(sources.compatibility, r.target) == 0U))
                {
                    return false;
                }
                target = *elementAt(sources.compatibility, r.target);
            }
            else
            {
                if (r.image >= sources.imageCount)
                {
                    return false;
                }
                const auto &source = *elementAt(sources.images, r.image);
                if (source.payload == nullptr || source.memory == nullptr ||
                    r.target >= source.payload->size ||
                    source.address > UINTPTR_MAX - r.target)
                {
                    return false;
                }
                target = source.address + r.target;
            }
            return true;
        }

        bool relocationAddend(const Relocation &r, uintptr_t &target)
        {
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
                const auto magnitude = static_cast<uint64_t>(r.addend);
                if (magnitude > UINTPTR_MAX || target > UINTPTR_MAX - magnitude)
                {
                    return false;
                }
                target += magnitude;
            }
            return true;
        }

        bool writeRelocation(LinkedImage &image, const Relocation &r,
                             uintptr_t target)
        {
            if (r.width == kAbsoluteRelocationWidth)
            {
                memcpy(byteAt(image.memory, r.offset), &target,
                       kAbsoluteRelocationWidth);
            }
            else
            {
                const auto pc =
                    image.address + r.offset + kRelativeRelocationWidth;
                auto delta = static_cast<int64_t>(target - pc);
                if (delta < INT32_MIN || delta > INT32_MAX)
                {
                    target = allocateStub(image, target);
                    if (target == 0U)
                    {
                        return false;
                    }
                    delta = static_cast<int64_t>(target - pc);
                    if (delta < INT32_MIN || delta > INT32_MAX)
                    {
                        return false;
                    }
                }
                const auto value = static_cast<int32_t>(delta);
                memcpy(byteAt(image.memory, r.offset), &value,
                       kRelativeRelocationWidth);
            }
            return true;
        }

        bool relocateSymbols(const LinkedImage &image)
        {
            const auto &p = *image.payload;
            for (uint32_t i = 0; i < p.symbolValueCount; ++i)
            {
                const auto offset = *elementAt(p.symbolValues, i);
                if (offset > p.size ||
                    kAbsoluteRelocationWidth > p.size - offset)
                {
                    return false;
                }
                uint64_t value = 0;
                memcpy(&value, byteAt(image.memory, offset),
                       kAbsoluteRelocationWidth);
                if (value >= p.size)
                {
                    return false;
                }
                value += image.address;
                memcpy(byteAt(image.memory, offset), &value,
                       kAbsoluteRelocationWidth);
            }
            return true;
        }
    } // namespace

    bool relocateImage(LinkedImage &image, const LinkedImage *images,
                       size_t imageCount, const uintptr_t *imports,
                       size_t importCount, const uintptr_t *compatibility,
                       size_t compatibilityCount)
    {
        const RelocationSources sources {
            images,      imageCount,    imports,
            importCount, compatibility, compatibilityCount,
        };
        if (!validRelocationImage(image, sources) ||
            !separatedRelocationSources(image, sources))
        {
            return false;
        }
        const auto &p = *image.payload;
        for (uint32_t i = 0; i < p.relocationCount; ++i)
        {
            const auto &r = *elementAt(p.relocations, i);
            if ((r.width != kRelativeRelocationWidth &&
                 r.width != kAbsoluteRelocationWidth) ||
                r.offset > p.size || r.width > p.size - r.offset)
            {
                return false;
            }
            uintptr_t target = 0;
            if (!relocationTarget(r, sources, target) ||
                !relocationAddend(r, target) ||
                !writeRelocation(image, r, target))
            {
                return false;
            }
        }
        return relocateSymbols(image);
    }

} // namespace ath
