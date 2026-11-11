// Copyright:
//   - Copyright © 2026 Alberto Villa Osorno
// SPDX-License-Identifier:
//   - MIT
// Confidential:
//   - false
// License-File:
//   - LICENSE-MIT
// Provenance:
//   - SimpleATH original; independently developed or locally authored
//
// Boundary-Contract:
// - Owns:
//   - Native driver contracts and implementation for kernel placement new.
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
//   - Native driver contracts and implementation for kernel placement new.
// - Description:
//   - Implements or verifies the KernelPlacementNew source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for kernel placement new.
#ifndef SIMPLEATH_KERNEL_PLACEMENT_NEW_HPP
#define SIMPLEATH_KERNEL_PLACEMENT_NEW_HPP

#include <stddef.h>

#if defined(__APPLE__) && defined(KERNEL)
// The kernel must not include or link libc++. This standard non-allocating
// placement form returns caller-owned storage; it never allocates or throws.
inline void *operator new(size_t, void *storage) noexcept
{
    return storage;
}
#else
// Portable host tests may use the system implementation.
#include <new>
#endif

#endif // SIMPLEATH_KERNEL_PLACEMENT_NEW_HPP
