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
//   - Native driver contracts and implementation for payload.
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
//   - Native driver contracts and implementation for payload.
// - Description:
//   - Implements or verifies the Payload source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for payload.

#ifndef SIMPLEATH_PAYLOAD_HPP
#define SIMPLEATH_PAYLOAD_HPP

#include <stddef.h>
#include <stdint.h>

namespace ath
{
    constexpr size_t kRelocationReservedBytes = 6U;

    struct Relocation
    {
            uint32_t offset;
            uint32_t target;
            int64_t addend;
            uint8_t image;
            uint8_t width;
            uint8_t reserved[kRelocationReservedBytes];
    };

    struct Symbol
    {
            const char *name;
            uint32_t offset;
    };

    struct RoutePrefix
    {
            uint32_t offset;
            uint32_t length;
    };

    struct NativeVtableGuard
    {
            uint32_t parent;
            uint32_t offset;
            uint32_t method;
    };

    // Descriptor is in-memory metadata emitted by tools/embed.py, not a
    // serialized kernel ABI. Keep pointer and integer fields grouped so the
    // compiler does not insert hidden padding between individual counters.
    struct Payload
    {
            const char *identifier;
            const char *sha256;
            const uint8_t *bytes;
            const uint8_t *delta;
            const char *plist;
            const Relocation *relocations;
            const uint32_t *symbolValues;
            const Symbol *symbols;
            const RoutePrefix *routes;
            uint64_t checksum;
            uint32_t bytesSize;
            uint32_t deltaSize;
            uint32_t size;
            uint32_t mappedSize;
            uint32_t stubOffset;
            uint32_t stubSize;
            uint32_t kmodOffset;
            uint32_t relocationCount;
            uint32_t symbolValueCount;
            uint32_t symbolCount;
            uint32_t routeCount;
    };

    struct LinkedImage
    {
            const Payload *payload;
            uint8_t *memory;
            uintptr_t address;
            uint32_t stubUsed;
            bool registered;
            bool editable;
    };

    extern const Payload payloads[3];
    extern "C" const uintptr_t athNativeImports[];
    extern const uint32_t nativeImportCount;
    extern const char *const nativeImportNames[];
    extern const NativeVtableGuard nativeVtableGuards[];
    extern const uint32_t nativeVtableGuardCount;

    bool restorePayload(LinkedImage &image);
    bool relocateImage(LinkedImage &image, const LinkedImage *images,
                       size_t imageCount, const uintptr_t *imports,
                       size_t importCount, const uintptr_t *compatibility,
                       size_t compatibilityCount);
    uintptr_t allocateStub(LinkedImage &image, uintptr_t target);
    uintptr_t findSymbol(const LinkedImage &image, const char *name);
    uint64_t payloadChecksum(const uint8_t *bytes, size_t length);

} // namespace ath

#endif
