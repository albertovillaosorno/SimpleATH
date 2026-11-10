// Copyright (c) 2026 Alberto Villa Osorno.
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
