//
//  ForwardingValidation.cpp
//  SimpleATH
//
//  Created by laobamac on 2026/11/1.
//  Copyright © 2026 laobamac. All rights reserved.
//
#include <cassert>
#include <cstdint>
#include <cstdio>

struct ForwardTarget
{
        uintptr_t function;
        void *receiver;
};

struct Pair
{
        uint64_t first, second;
};

struct Aggregate
{
        uint64_t words[32];
};

alignas(16) static uint64_t oldObject;
alignas(16) static uint64_t nativeObject;
static void *expectedReceiver;
static uintptr_t selectedTarget;
static uint32_t expectedIndex;
static bool fallback;
static unsigned retained;
static unsigned released;
static unsigned calls;

extern "C" ForwardTarget athResolveOldSkywalk(void *self, uint32_t index)
{
    assert(self == &oldObject && index == expectedIndex);
    return {selectedTarget, &nativeObject};
}

extern "C" ForwardTarget athResolveNativeSkywalk(void *self, uint32_t index)
{
    assert(self == &nativeObject && index == expectedIndex);
    if (fallback)
        return {selectedTarget, &nativeObject};
    ++retained;
    return {selectedTarget, reinterpret_cast<void *>(
                                reinterpret_cast<uintptr_t>(&oldObject) | 1)};
}

extern "C" void athReleaseNativeReceiver(uintptr_t self)
{
    if (self & 1)
    {
        assert((self & ~uintptr_t(1)) ==
               reinterpret_cast<uintptr_t>(&oldObject));
        ++released;
    }
    else
    {
        assert(self == reinterpret_cast<uintptr_t>(&nativeObject));
    }
    asm volatile("xorq %%rax, %%rax; xorq %%rdx, %%rdx" ::: "rax", "rdx", "cc");
}

static uint64_t nine(void *self, uint64_t a, uint64_t b, uint64_t c, uint64_t d,
                     uint64_t e, uint64_t f, uint64_t g, uint64_t h)
{
    assert(self == expectedReceiver);
    assert(a == 11 && b == 22 && c == 33 && d == 44 && e == 55 && f == 66 &&
           g == 77 && h == 88);
    ++calls;
    return 0xfedcba9876543210ULL;
}

static Pair six(void *self, uint64_t a, uint64_t b, uint64_t c, uint64_t d,
                uint64_t e)
{
    assert(self == expectedReceiver);
    assert(a == 11 && b == 22 && c == 33 && d == 44 && e == 55);
    ++calls;
    return {0x1234567812345678ULL, 0x9876543298765432ULL};
}

static uint64_t aggregate(void *self, Aggregate value, uint64_t after)
{
    assert(self == expectedReceiver && after == 0x44556677);
    for (unsigned i = 0; i < 32; ++i)
        assert(value.words[i] == 0x1122334455660000ULL + i);
    ++calls;
    return 0x1122334455667788ULL;
}

static int userClient(void *self, void *task, void *token, uint32_t type,
                      void *properties, void **output)
{
    assert(self == expectedReceiver);
    assert(task == reinterpret_cast<void *>(0x1000) &&
           token == reinterpret_cast<void *>(0x2000));
    assert(type == 0xabcdef12 &&
           properties == reinterpret_cast<void *>(0x3000));
    *output = reinterpret_cast<void *>(0x4000);
    ++calls;
    return 0x1234abcd;
}

// ATH_DECLARATIONS_PLACEHOLDER

int main()
{
    using Nine = uint64_t (*)(void *, uint64_t, uint64_t, uint64_t, uint64_t,
                              uint64_t, uint64_t, uint64_t, uint64_t);
    using Six =
        Pair (*)(void *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
    using Large = uint64_t (*)(void *, Aggregate, uint64_t);
    using Client = int (*)(void *, void *, void *, uint32_t, void *, void **);
    const uintptr_t forwarders[] = {ATH_FORWARDERS_PLACEHOLDER};
    const uintptr_t callbacks[] = {ATH_CALLBACKS_PLACEHOLDER};
    Aggregate value {};
    for (unsigned i = 0; i < 32; ++i)
        value.words[i] = 0x1122334455660000ULL + i;
    for (uint32_t i = 0; i < sizeof(forwarders) / sizeof(forwarders[0]); ++i)
    {
        expectedIndex = i;
        expectedReceiver = &nativeObject;
        selectedTarget = reinterpret_cast<uintptr_t>(nine);
        auto result = reinterpret_cast<Nine>(forwarders[i])(
            &oldObject, 11, 22, 33, 44, 55, 66, 77, 88);
        assert(result == 0xfedcba9876543210ULL);
        selectedTarget = reinterpret_cast<uintptr_t>(aggregate);
        assert(reinterpret_cast<Large>(forwarders[i])(
                   &oldObject, value, 0x44556677) == 0x1122334455667788ULL);
        for (unsigned inactive = 0; inactive < 2; ++inactive)
        {
            fallback = inactive != 0;
            expectedReceiver =
                fallback ? static_cast<void *>(&nativeObject) : &oldObject;
            selectedTarget = reinterpret_cast<uintptr_t>(six);
            auto pair = reinterpret_cast<Six>(callbacks[i])(&nativeObject, 11,
                                                            22, 33, 44, 55);
            assert(pair.first == 0x1234567812345678ULL &&
                   pair.second == 0x9876543298765432ULL);
            selectedTarget = reinterpret_cast<uintptr_t>(userClient);
            void *output = nullptr;
            assert(reinterpret_cast<Client>(callbacks[i])(
                       &nativeObject, reinterpret_cast<void *>(0x1000),
                       reinterpret_cast<void *>(0x2000), 0xabcdef12,
                       reinterpret_cast<void *>(0x3000),
                       &output) == 0x1234abcd);
            assert(output == reinterpret_cast<void *>(0x4000));
            assert(retained == released);
        }
    }
    printf("{\"forwardingCalls\":%u,\"retainedReceivers\":%u,"
           "\"releasedReceivers\":%u}\n",
           calls, retained, released);
}
