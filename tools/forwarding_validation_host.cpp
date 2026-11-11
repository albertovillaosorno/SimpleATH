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
//   - Host-side tooling for forwarding validation host.
// - Must-Not:
//   - Read unrelated user files, hide failures, or bypass explicit tool inputs.
// - Allows:
//   - Inputs: explicit command-line, repository, or fixture inputs.
//   - Outputs: deterministic reports, generated artifacts, or error codes.
//   - Side effects: bounded local source-analysis or developer-command
//     activity.
// - Split-When:
//   - A separate protocol stage needs independent validation and ownership.
// - Merge-When:
//   - The caller directly owns this narrow contract without reuse.
// - Summary:
//   - Host-side tooling for forwarding validation host.
// - Description:
//   - Implements or verifies the forwarding_validation_host source boundary.
// - Usage:
//   - Invoked by developers or CI with an explicit checkout context.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Host-side tooling for forwarding validation host.

#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <vector>

namespace
{
    constexpr std::size_t kAggregateWords = 32;
    constexpr std::size_t kAlignment = 16;
    constexpr uintptr_t kReceiverTag = uintptr_t {1};
    constexpr uintptr_t kTaskAddress = 0x1000;
    constexpr uintptr_t kTokenAddress = 0x2000;
    constexpr uintptr_t kPropertiesAddress = 0x3000;
    constexpr uintptr_t kOutputAddress = 0x4000;
    constexpr uint32_t kClientType = 0xabcdef12;
    constexpr int kClientResult = 0x1234abcd;
    constexpr uint64_t kNineResult = 0xfedcba9876543210ULL;
    constexpr uint64_t kPairFirst = 0x1234567812345678ULL;
    constexpr uint64_t kPairSecond = 0x9876543298765432ULL;
    constexpr uint64_t kAggregateStart = 0x1122334455660000ULL;
    constexpr uint64_t kAggregateResult = 0x1122334455667788ULL;
    constexpr uint64_t kAggregateAfter = 0x44556677;
    constexpr uint64_t kArgA = 11;
    constexpr uint64_t kArgB = 22;
    constexpr uint64_t kArgC = 33;
    constexpr uint64_t kArgD = 44;
    constexpr uint64_t kArgE = 55;
    constexpr uint64_t kArgF = 66;
    constexpr uint64_t kArgG = 77;
    constexpr uint64_t kArgH = 88;

    struct ForwardTarget
    {
            uintptr_t function;
            void *receiver;
    };

    struct Pair
    {
            uint64_t first;
            uint64_t second;
    };

    struct Aggregate
    {
            std::array<uint64_t, kAggregateWords> words;
    };

    // The fixture verifies x86_64 ABI forwarding of opaque pointers and
    // function targets. Preserve their exact bits without C++ cast aliasing.
    template <typename Destination, typename Source>
    Destination bitPattern(const Source &source)
    {
        static_assert(sizeof(Destination) == sizeof(Source),
                      "ABI values must have identical representations");
        Destination result {};
        std::memcpy(static_cast<void *>(&result),
                    static_cast<const void *>(&source), sizeof(result));
        return result;
    }

    struct FixtureState
    {
            alignas(kAlignment) uint64_t oldObject {0};
            alignas(kAlignment) uint64_t nativeObject {0};
            const void *expectedReceiver {nullptr};
            uintptr_t selectedTarget {0};
            uint32_t expectedIndex {0};
            bool fallback {false};
            unsigned int retained {0};
            unsigned int released {0};
            unsigned int calls {0};
    };

    FixtureState &state()
    {
        static FixtureState active {};
        return active;
    }

    struct Task;
    struct Token;
    struct Properties;
} // namespace

extern "C" void athProbeClobberReturns();

extern "C" ForwardTarget athResolveOldSkywalk(const void *self, uint32_t index)
{
    auto &fixture = state();
    assert(self == &fixture.oldObject && index == fixture.expectedIndex);
    return {fixture.selectedTarget, &fixture.nativeObject};
}

extern "C" ForwardTarget athResolveNativeSkywalk(const void *self,
                                                 uint32_t index)
{
    auto &fixture = state();
    assert(self == &fixture.nativeObject && index == fixture.expectedIndex);
    if (fixture.fallback)
    {
        return {fixture.selectedTarget, &fixture.nativeObject};
    }
    ++fixture.retained;
    const auto oldAddress = bitPattern<uintptr_t>(&fixture.oldObject);
    return {
        fixture.selectedTarget,
        bitPattern<void *>(oldAddress | kReceiverTag),
    };
}

extern "C" void athReleaseNativeReceiver(uintptr_t self)
{
    auto &fixture = state();
    if ((self & kReceiverTag) != 0U)
    {
        assert((self & ~kReceiverTag) ==
               bitPattern<uintptr_t>(&fixture.oldObject));
        ++fixture.released;
    }
    else
    {
        assert(self == bitPattern<uintptr_t>(&fixture.nativeObject));
    }
    // This external x86_64 fixture helper deliberately clobbers both return
    // registers, exercising aggregate/long-result preservation by trampolines.
    athProbeClobberReturns();
}

namespace
{
    uint64_t nine(const void *self, uint64_t a, uint64_t b, uint64_t c,
                  uint64_t d, uint64_t e, uint64_t f, uint64_t g, uint64_t h)
    {
        assert(self == state().expectedReceiver);
        assert(a == kArgA && b == kArgB && c == kArgC && d == kArgD &&
               e == kArgE && f == kArgF && g == kArgG && h == kArgH);
        ++state().calls;
        return kNineResult;
    }

    Pair six(const void *self, uint64_t a, uint64_t b, uint64_t c, uint64_t d,
             uint64_t e)
    {
        assert(self == state().expectedReceiver);
        assert(a == kArgA && b == kArgB && c == kArgC && d == kArgD &&
               e == kArgE);
        ++state().calls;
        return {kPairFirst, kPairSecond};
    }

    uint64_t aggregate(const void *self, Aggregate value, uint64_t after)
    {
        assert(self == state().expectedReceiver && after == kAggregateAfter);
        for (std::size_t index = 0; index < kAggregateWords; ++index)
        {
            assert(value.words.at(index) == kAggregateStart + index);
        }
        ++state().calls;
        return kAggregateResult;
    }

    int userClient(const void *self, const Task *task, const Token *token,
                   uint32_t type, const Properties *properties,
                   const void **output)
    {
        assert(self == state().expectedReceiver);
        assert(bitPattern<uintptr_t>(task) == kTaskAddress &&
               bitPattern<uintptr_t>(token) == kTokenAddress);
        assert(type == kClientType &&
               bitPattern<uintptr_t>(properties) == kPropertiesAddress);
        *output = bitPattern<const void *>(kOutputAddress);
        ++state().calls;
        return kClientResult;
    }
} // namespace

// ATH_DECLARATIONS_PLACEHOLDER

namespace
{
    void exerciseCallbacks(uintptr_t callback, FixtureState &fixture)
    {
        using Six =
            Pair (*)(void *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
        using Client =
            int (*)(void *, void *, void *, uint32_t, void *, const void **);
        for (unsigned int inactive = 0; inactive < 2U; ++inactive)
        {
            fixture.fallback = inactive != 0U;
            fixture.expectedReceiver =
                fixture.fallback ? static_cast<void *>(&fixture.nativeObject)
                                 : static_cast<void *>(&fixture.oldObject);
            fixture.selectedTarget = bitPattern<uintptr_t>(&six);
            const auto pair = bitPattern<Six>(callback)(
                &fixture.nativeObject, kArgA, kArgB, kArgC, kArgD, kArgE);
            assert(pair.first == kPairFirst && pair.second == kPairSecond);
            fixture.selectedTarget = bitPattern<uintptr_t>(&userClient);
            const void *output = nullptr;
            assert(bitPattern<Client>(callback)(
                       &fixture.nativeObject, bitPattern<void *>(kTaskAddress),
                       bitPattern<void *>(kTokenAddress), kClientType,
                       bitPattern<void *>(kPropertiesAddress),
                       &output) == kClientResult);
            assert(output == bitPattern<const void *>(kOutputAddress));
            assert(fixture.retained == fixture.released);
        }
    }

    int exerciseForwarding(const std::vector<uintptr_t> &forwarders,
                           const std::vector<uintptr_t> &callbacks)
    {
        using Nine =
            uint64_t (*)(void *, uint64_t, uint64_t, uint64_t, uint64_t,
                         uint64_t, uint64_t, uint64_t, uint64_t);
        using Large = uint64_t (*)(void *, Aggregate, uint64_t);
        if (forwarders.front() == 0 || callbacks.front() == 0 ||
            forwarders.size() != callbacks.size())
        {
            std::fputs("Generated forwarding targets required\n", stderr);
            return 2;
        }
        Aggregate value {};
        for (std::size_t index = 0; index < kAggregateWords; ++index)
        {
            value.words.at(index) = kAggregateStart + index;
        }
        for (std::size_t index = 0; index < forwarders.size(); ++index)
        {
            auto &fixture = state();
            fixture.expectedIndex = static_cast<uint32_t>(index);
            fixture.expectedReceiver = &fixture.nativeObject;
            fixture.selectedTarget = bitPattern<uintptr_t>(&nine);
            const auto result = bitPattern<Nine>(forwarders.at(index))(
                &fixture.oldObject, kArgA, kArgB, kArgC, kArgD, kArgE, kArgF,
                kArgG, kArgH);
            assert(result == kNineResult);
            fixture.selectedTarget = bitPattern<uintptr_t>(&aggregate);
            assert(bitPattern<Large>(forwarders.at(index))(
                       &fixture.oldObject, value, kAggregateAfter) ==
                   kAggregateResult);
            exerciseCallbacks(callbacks.at(index), fixture);
        }
        const auto &fixture = state();
        std::cout << "{\"forwardingCalls\":" << fixture.calls
                  << ",\"retainedReceivers\":" << fixture.retained
                  << ",\"releasedReceivers\":" << fixture.released << "}\n";
        return 0;
    }
} // namespace

int main()
{
    const std::vector<uintptr_t> forwarders {0}; // ATH_FORWARDERS_PLACEHOLDER
    const std::vector<uintptr_t> callbacks {0};  // ATH_CALLBACKS_PLACEHOLDER
    return exerciseForwarding(forwarders, callbacks);
}
