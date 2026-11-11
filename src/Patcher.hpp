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

#ifndef SIMPLEATH_PATCHER_HPP
#define SIMPLEATH_PATCHER_HPP

#include "Payload.hpp"
#include <IOKit/IOLib.h>
#include <mach/mach_types.h>

extern "C" int version_major;
// Kernel diagnostic messages use IOLog directly in the SDK logging ABI.
#define SYSLOG(module, format, ...)                                            \
    IOLog("SimpleATH: " module " " format "\n", ##__VA_ARGS__)

template <typename T, size_t N> constexpr size_t arrsize(const T (&array)[N])
{
    static_cast<void>(array);
    return N;
}

inline unsigned getKernelVersion()
{
    return static_cast<unsigned>(version_major);
}

class KernelPatcher
{
    public:
        static constexpr size_t KernelID = static_cast<size_t>(-1);

        class RouteRequest
        {
            public:
                RouteRequest() = default;

                template <typename T>
                RouteRequest(const char *symbol, T replacement, T &saved)
                    : name_(symbol), original_(static_cast<void *>(&saved))
                {
                    static_assert(
                        sizeof(T) == sizeof(uintptr_t),
                        "x86_64 patch entry and address widths differ");
                    // Preserve the function pointer's native representation;
                    // never alias the saved function slot as uintptr_t *.
                    __builtin_memcpy(static_cast<void *>(&target_),
                                     static_cast<const void *>(&replacement),
                                     sizeof(target_));
                }

                const char *name() const
                {
                    return name_;
                }

                uintptr_t target() const
                {
                    return target_;
                }

                void *original() const
                {
                    return original_;
                }

            private:
                const char *name_ {nullptr};
                uintptr_t target_ {0U};
                void *original_ {nullptr};
        };

        explicit KernelPatcher(ath::LinkedImage &value) : image(&value)
        {
        }

        uintptr_t solveSymbol(size_t index, const char *name);
        uintptr_t branchTarget(uintptr_t target, uintptr_t programCounter);

        struct RouteBatch
        {
                size_t count;
                uintptr_t address;
                size_t size;
        };

        bool routeMultipleLong(size_t index, RouteRequest *routes,
                               const RouteBatch &batch);

        template <size_t N>
        bool routeMultipleLong(size_t index, RouteRequest (&routes)[N],
                               uintptr_t address, size_t size)
        {
            return routeMultipleLong(index, &routes[0],
                                     RouteBatch {N, address, size});
        }

        void clearError()
        {
        }

    private:
        ath::LinkedImage *image;
};

#endif
