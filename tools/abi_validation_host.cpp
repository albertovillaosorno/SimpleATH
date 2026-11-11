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
//   - Originally authored by laobamac on 2026/9/5.
//
// Boundary-Contract:
// - Owns:
//   - Host-side tooling for abi validation host.
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
//   - Host-side tooling for abi validation host.
// - Description:
//   - Implements or verifies the abi_validation_host source boundary.
// - Usage:
//   - Invoked by developers or CI with an explicit checkout context.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Host-side tooling for abi validation host.


#include "HardwareIdentity.hpp"
#include "WirelessABI.hpp"
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <algorithm>
#include <assert.h>
#include <atomic>
#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <mach-o/loader.h>
#include <objc/message.h>
#include <objc/runtime.h>
#include <stdio.h>
#include <string.h>
#include <thread>
#include <vector>

static uint64_t checked;
static unsigned scanConversions;
static unsigned nativeScanRecords;
static unsigned capabilityConversions;
static unsigned nativeScanWakeups;
static unsigned associationConversions;
static unsigned nativeRoamRecords;
static unsigned availabilityConversions;
static unsigned nativeAvailabilityRecords;
static unsigned joinStatusConversions;
static unsigned nativeJoinRecords;
static uint32_t randomState = 0xB8021125;

static uint32_t randomValue()
{
    randomState ^= randomState << 13;
    randomState ^= randomState >> 17;
    randomState ^= randomState << 5;
    return randomState;
}

template <bool Sequoia> static void joinStatusVectors()
{
    constexpr auto abi = Sequoia ? ath::sequoiaABI : ath::tahoeABI;
    const uint8_t bssid[] = {2, 4, 6, 8, 10, 12};
    for (uint32_t status : {0U, 17U, 65535U})
    {
        for (uint32_t result : {0U, 1U, 2U, 9U})
        {
            uint8_t arena[abi.joinStatusSize + 16];
            memset(arena, 0xA5, sizeof(arena));
            auto output = arena + 8;
            const auto addressLength = result == 1 ? sizeof(bssid) : 0;
            assert(!ath::encodeJoinStatus(status, result, bssid, addressLength,
                                          output, abi.joinStatusSize - 1, abi));
            for (auto byte : arena)
                assert(byte == 0xA5);
            assert(ath::encodeJoinStatus(status, result, bssid, addressLength,
                                         output, abi.joinStatusSize, abi));
            uint8_t expected[abi.joinStatusSize] {};
            ath::writeUInt32(expected + (Sequoia ? 8 : 0x1B8), status);
            ath::writeUInt32(expected + (Sequoia ? 12 : 0x1BC), status);
            if (!Sequoia)
            {
                ath::writeUInt32(expected + 0x1C4, result);
                ath::writeUInt32(expected + 0x1C8, 1);
            }
            if (addressLength)
                memcpy(expected + (Sequoia ? 0 : 0x1CC), bssid, sizeof(bssid));
            assert(!memcmp(output, expected, sizeof(expected)));
            for (size_t index = 0; index < 8; ++index)
                assert(arena[index] == 0xA5 &&
                       output[abi.joinStatusSize + index] == 0xA5);
            ++joinStatusConversions;
        }
    }
    uint8_t output[abi.joinStatusSize];
    memset(output, 0xA5, sizeof(output));
    assert(
        !ath::encodeJoinStatus(0, 1, nullptr, 6, output, sizeof(output), abi));
    assert(!ath::encodeJoinStatus(0, 1, bssid, 5, output, sizeof(output), abi));
    assert(
        !ath::encodeJoinStatus(0, 1, bssid, 6, nullptr, sizeof(output), abi));
    for (auto byte : output)
        assert(byte == 0xA5);
}

template <unsigned Kernel> static void powerAvailabilityVectors()
{
    constexpr auto abi = Kernel == 23   ? ath::sonomaABI
                         : Kernel == 24 ? ath::sequoiaABI
                                        : ath::tahoeABI;
    for (uint32_t radios = 1; radios <= 4; ++radios)
    {
        for (uint32_t mask = 0; mask < (1U << radios); ++mask)
        {
            uint8_t power[ath::powerDataSize] {};
            ath::writeUInt32(power, 1);
            ath::writeUInt32(power + 4, radios);
            for (size_t index = 0; index < radios; ++index)
                ath::writeUInt32(power + 8 + 4 * index, (mask >> index) & 1);
            const std::vector<uint8_t> source(power, power + sizeof(power));
            uint8_t arena[abi.driverAvailableSize + 16];
            memset(arena, 0xA5, sizeof(arena));
            auto output = arena + 8;
            assert(!ath::encodePowerAvailability(power, sizeof(power), output,
                                                 abi.driverAvailableSize - 1,
                                                 abi));
            for (auto byte : arena)
                assert(byte == 0xA5);
            assert(ath::encodePowerAvailability(power, sizeof(power), output,
                                                abi.driverAvailableSize, abi));
            assert(ath::readUInt32(output + 8) == (mask ? 1 : 0));
            assert(ath::readUInt32(output + 0x10) ==
                   ath::powerStateAvailabilityReason);
            for (size_t index = 0; index < abi.driverAvailableSize; ++index)
                if (!(index >= 8 && index < 12) &&
                    !(index >= 0x10 && index < 0x14))
                    assert(output[index] == 0);
            for (size_t index = 0; index < 8; ++index)
                assert(arena[index] == 0xA5 &&
                       output[abi.driverAvailableSize + index] == 0xA5);
            assert(!memcmp(power, source.data(), sizeof(power)));
        }
    }
    uint8_t power[ath::powerDataSize] {};
    uint8_t output[abi.driverAvailableSize];
    memset(output, 0xA5, sizeof(output));
    assert(!ath::encodePowerAvailability(power, sizeof(power), output,
                                         sizeof(output), abi));
    ath::writeUInt32(power, 1);
    for (uint32_t radios : {0U, 5U})
    {
        ath::writeUInt32(power + 4, radios);
        assert(!ath::encodePowerAvailability(power, sizeof(power), output,
                                             sizeof(output), abi));
    }
    ath::writeUInt32(power + 4, 1);
    ath::writeUInt32(power + 8, 2);
    assert(!ath::encodePowerAvailability(power, sizeof(power), output,
                                         sizeof(output), abi));
    ath::writeUInt32(power + 8, 1);
    assert(!ath::encodePowerAvailability(power, sizeof(power) - 1, output,
                                         sizeof(output), abi));
    assert(!ath::encodePowerAvailability(power, sizeof(power) + 1, output,
                                         sizeof(output), abi));
    assert(!ath::encodePowerAvailability(nullptr, sizeof(power), output,
                                         sizeof(output), abi));
    assert(!ath::encodePowerAvailability(power, sizeof(power), nullptr,
                                         sizeof(output), abi));
    for (auto byte : output)
        assert(byte == 0xA5);
}

template <unsigned Kernel> static void availabilityVectors()
{
    constexpr auto abi = Kernel == 23   ? ath::sonomaABI
                         : Kernel == 24 ? ath::sequoiaABI
                                        : ath::tahoeABI;
    for (size_t length :
         {size_t(0), size_t(1), ath::legacyDriverAvailableSize - 1,
          ath::legacyDriverAvailableSize, ath::legacyDriverAvailableSize + 1,
          abi.driverAvailableSize, ath::maximumEventPayload})
    {
        for (uint32_t event : {9U, 37U, ath::driverAvailableEvent})
        {
            std::vector<uint8_t> source(length);
            for (auto &byte : source)
                byte = static_cast<uint8_t>(randomValue());
            auto original = source;
            const auto expected = event == 0x37 && length == 0xB8
                                      ? abi.driverAvailableSize
                                      : length;
            assert(ath::eventPayloadSize(event, length, abi) == expected);
            std::vector<uint8_t> arena(expected + 16, 0xA5);
            auto output = arena.data() + 8;
            if (expected)
            {
                assert(!ath::copyEventPayload(event, source.data(), length,
                                              output, expected - 1, abi));
                for (auto byte : arena)
                    assert(byte == 0xA5);
            }
            assert(ath::copyEventPayload(event, source.data(), length, output,
                                         expected, abi));
            if (length)
                assert(!memcmp(output, source.data(), length));
            for (size_t index = length; index < expected; ++index)
                assert(output[index] == 0);
            for (size_t index = 0; index < 8; ++index)
                assert(arena[index] == 0xA5 &&
                       output[expected + index] == 0xA5);
            assert(source == original);
            ++availabilityConversions;
        }
    }
    uint8_t output[abi.driverAvailableSize];
    memset(output, 0xA5, sizeof(output));
    assert(!ath::copyEventPayload(0x37, nullptr, 0xB8, output, sizeof(output),
                                  abi));
    assert(!ath::copyEventPayload(0x37, output, 0xB8, nullptr, sizeof(output),
                                  abi));
    assert(!ath::copyEventPayload(1, output, ath::maximumEventPayload + 1,
                                  output, sizeof(output), abi));
    for (auto byte : output)
        assert(byte == 0xA5);
}

static void nativeAvailability()
{
    auto library =
        dlopen("/System/Library/PrivateFrameworks/CoreWiFi.framework/CoreWiFi",
               RTLD_NOW | RTLD_LOCAL);
    assert(library);
    auto cls = objc_getClass("CWFDriverAvailabilityMessage");
    assert(cls);
    auto send = reinterpret_cast<id (*)(id, SEL)>(objc_msgSend);
    auto initialize = reinterpret_cast<id (*)(id, SEL, id)>(objc_msgSend);
    auto getAvailable =
        reinterpret_cast<signed char (*)(id, SEL)>(objc_msgSend);
    auto getReason = reinterpret_cast<uint32_t (*)(id, SEL)>(objc_msgSend);
    for (uint32_t available : {0U, 1U})
    {
        uint8_t legacy[ath::legacyDriverAvailableSize] {};
        uint32_t reason = 0x42;
        memcpy(legacy + 0x10, &reason, sizeof(reason));
        memcpy(legacy + 8, &available, sizeof(available));
        uint8_t converted[ath::nativeDriverAvailableSize];
        assert(ath::copyEventPayload(ath::driverAvailableEvent, legacy,
                                     sizeof(legacy), converted,
                                     sizeof(converted), ath::tahoeABI));
        auto data =
            CFDataCreate(kCFAllocatorDefault, converted, sizeof(converted));
        assert(data);
        auto message = initialize(
            send(reinterpret_cast<id>(cls), sel_registerName("alloc")),
            sel_registerName("initWithDriverAvailabiltyData:"),
            reinterpret_cast<id>(
                const_cast<void *>(static_cast<const void *>(data))));
        assert(message);
        assert(getAvailable(message, sel_registerName("available")) ==
               available);
        assert(getReason(message, sel_registerName("reason")) == reason);
        send(message, sel_registerName("release"));
        CFRelease(data);
        ++nativeAvailabilityRecords;
    }
    for (uint32_t available : {0U, 1U})
    {
        uint8_t power[ath::powerDataSize] {};
        ath::writeUInt32(power, 1);
        ath::writeUInt32(power + 4, 2);
        ath::writeUInt32(power + 12, available);
        uint8_t converted[ath::nativeDriverAvailableSize];
        assert(ath::encodePowerAvailability(power, sizeof(power), converted,
                                            sizeof(converted), ath::tahoeABI));
        auto data =
            CFDataCreate(kCFAllocatorDefault, converted, sizeof(converted));
        assert(data);
        auto message = initialize(
            send(reinterpret_cast<id>(cls), sel_registerName("alloc")),
            sel_registerName("initWithDriverAvailabiltyData:"),
            reinterpret_cast<id>(
                const_cast<void *>(static_cast<const void *>(data))));
        assert(message);
        assert(getAvailable(message, sel_registerName("available")) ==
               available);
        assert(getReason(message, sel_registerName("reason")) ==
               ath::powerStateAvailabilityReason);
        send(message, sel_registerName("release"));
        CFRelease(data);
        ++nativeAvailabilityRecords;
    }
    dlclose(library);
}

static void unhex(const char *source, uint8_t *output, size_t length)
{
    assert(strlen(source) == length * 2);
    for (size_t index = 0; index < length; ++index)
    {
        unsigned value;
        assert(sscanf(source + index * 2, "%2x", &value) == 1);
        output[index] = static_cast<uint8_t>(value);
    }
}

template <bool Sequoia>
static void associationVectorFor(const char *nativeHex, const char *legacyHex)
{
    constexpr auto abi = Sequoia ? ath::sequoiaABI : ath::tahoeABI;
    uint8_t arena[abi.associateSize + 16];
    memset(arena, 0xA5, sizeof(arena));
    auto buffer = arena + 8;
    uint8_t decoded[ath::tahoeABI.associateSize];
    unhex(nativeHex, decoded, sizeof(decoded));
    memcpy(buffer, decoded, abi.associateSize);
    uint8_t original[abi.associateSize];
    memcpy(original, buffer, sizeof(original));
    uint8_t expected[ath::legacyAssociateSize];
    unhex(legacyHex, expected, sizeof(expected));
    ath::Request request {};
    request.length = abi.associateSize;
    assert(!ath::prepareAssociate(request, buffer, abi.associateSize - 1, abi));
    assert(!memcmp(buffer, original, sizeof(original)));
    assert(ath::prepareAssociate(request, buffer, abi.associateSize, abi));
    assert(request.length == ath::legacyAssociateSize);
    assert(!memcmp(buffer, expected, sizeof(expected)));
    for (size_t offset = ath::legacyAssociateSize; offset < abi.associateSize;
         ++offset)
        assert(buffer[offset] == 0);
    for (size_t offset = 0; offset < 8; ++offset)
        assert(arena[offset] == 0xA5 &&
               buffer[abi.associateSize + offset] == 0xA5);
    for (size_t field : {size_t(8), size_t(12), size_t(0x206)})
    {
        memcpy(buffer, original, sizeof(original));
        if (field == 0x206)
            buffer[field] = 4;
        else
            buffer[field + 2] = 1;
        uint8_t rejected[abi.associateSize];
        memcpy(rejected, buffer, sizeof(rejected));
        request.length = abi.associateSize;
        assert(!ath::prepareAssociate(request, buffer, abi.associateSize, abi));
        assert(!memcmp(buffer, rejected, sizeof(rejected)));
    }
    ++associationConversions;
}

static void associationVector(const char *nativeHex, const char *legacyHex)
{
    associationVectorFor<false>(nativeHex, legacyHex);
    associationVectorFor<true>(nativeHex, legacyHex);
}

static void associationVectors()
{
    associationVector(
        "010000000200000001000000000000000d00000053696d706c6542434d2d4142490000"
        "0000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "000000020000000000000000",
        "0100000002000100000000000d00000053696d706c6542434d2d414249000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "00");
    associationVector(
        "010000000200000001000000080000000d00000053696d706c6542434d2d4142490000"
        "0000000000000000000000000000000000000000000000000001000000"
        "120000000a0000000000000053696d706c6542434d2d4142492d4f6e6c790000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000160030140100000fac040100000fac04010000"
        "0fac028000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000020000000b7594b71ca9b7d"
        "c3afce7ed1f4f2cbbd35ee6c9a499455ecb17ff92626b58ffd04000040"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "000000020000000000000000",
        "0100000002000100080000000d00000053696d706c6542434d2d414249000000000000"
        "0000000000000000000000000000000000000000000100000012000000"
        "0a0000000000000053696d706c6542434d2d4142492d4f6e6c79000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000160030140100000fac040100000fac040100000fac0280"
        "0000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000020000000b7594b71ca9b7dc3afce7e"
        "d1f4f2cbbd35ee6c9a499455ecb17ff92626b58ffd0400004000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "00");
}

static void decode(uint8_t *ring, size_t capacity, ath::EventState &state,
                   const std::vector<uint8_t> &expected)
{
    uint32_t read = state.read;
    while (capacity - read < 48 ||
           *reinterpret_cast<uint32_t *>(ring + read) == 0x50)
        read = (read + 4) % capacity;
    ath::EventHeader header;
    memcpy(&header, ring + read, sizeof(header));
    assert(header.status == 0x57 && header.event == 1);
    assert(header.length == expected.size());
    assert(header.padding == (4 - expected.size() % 4) % 4);
    assert(strcmp(header.interfaceName, "en0") == 0);
    assert(header.seconds == 123 && header.microseconds == 456);
    for (size_t j = 0; j < expected.size(); ++j)
        assert(ring[(read + 48 + j) % capacity] == expected[j]);
    state.read = static_cast<uint32_t>(
        (read + 48 + header.length + header.padding) % capacity);
    assert(state.read == state.write);
    ++checked;
}

template <unsigned Kernel> static void boundaries()
{
    constexpr auto abi = Kernel == 23   ? ath::sonomaABI
                         : Kernel == 24 ? ath::sequoiaABI
                                        : ath::tahoeABI;
    for (uint8_t mask :
         {uint8_t(0), uint8_t(0x3F), uint8_t(0x40), uint8_t(0xFF)})
    {
        uint8_t arena[abi.capabilitySize + 16];
        memset(arena, 0xA5, sizeof(arena));
        auto buffer = arena + 8;
        buffer[ath::scanCompletionCapabilityByte] = mask;
        uint8_t original[ath::legacyCapabilitySize];
        memcpy(original, buffer, sizeof(original));
        ath::Request request {};
        request.length = ath::legacyCapabilitySize;
        assert(!ath::expandCapabilities(request, buffer, abi.capabilitySize - 1,
                                        abi, true));
        assert(ath::expandCapabilities(request, buffer, abi.capabilitySize, abi,
                                       true));
        assert(request.length == abi.capabilitySize);
        for (size_t index = 0; index < ath::legacyCapabilitySize; ++index)
            assert(buffer[index] ==
                   (index == ath::scanCompletionCapabilityByte
                        ? (original[index] | ath::scanCompletionCapabilityMask)
                        : original[index]));
        for (size_t index = ath::legacyCapabilitySize;
             index < abi.capabilitySize; ++index)
            assert(buffer[index] == 0);
        for (size_t index = 0; index < 8; ++index)
            assert(arena[index] == 0xA5 &&
                   buffer[abi.capabilitySize + index] == 0xA5);
        ++capabilityConversions;
    }
    for (uint16_t capacity : {uint16_t(0), uint16_t(1), uint16_t(0x400),
                              uint16_t(0x800), uint16_t(0xFFFF)})
    {
        uint8_t arena[abi.scanResultSize + 16];
        memset(arena, 0xA5, sizeof(arena));
        auto buffer = arena + 8;
        memcpy(buffer + ath::scanIELengthOffset, &capacity, sizeof(capacity));
        ath::Request request {};
        request.length = abi.scanResultSize;
        assert(!ath::prepareScanResult(request, buffer, abi.scanResultSize - 1,
                                       abi));
        assert(
            ath::prepareScanResult(request, buffer, abi.scanResultSize, abi));
        assert(request.length == ath::legacyScanResultSize);
        uint16_t limited;
        memcpy(&limited, buffer + ath::scanIELengthOffset, sizeof(limited));
        assert(limited ==
               std::min(capacity, uint16_t(ath::legacyScanIECapacity)));
        uint8_t original[ath::legacyScanResultSize];
        memcpy(original, buffer, sizeof(original));
        assert(!ath::expandScanResult(request, buffer, abi.scanResultSize - 1,
                                      abi));
        assert(ath::expandScanResult(request, buffer, abi.scanResultSize, abi));
        assert(request.length == abi.scanResultSize);
        assert(!memcmp(original, buffer, sizeof(original)));
        for (size_t offset = sizeof(original); offset < abi.scanResultSize;
             ++offset)
            assert(buffer[offset] == 0);
        for (size_t offset = 0; offset < 8; ++offset)
            assert(arena[offset] == 0xA5 &&
                   buffer[abi.scanResultSize + offset] == 0xA5);
        ++scanConversions;
    }
    for (int32_t value : {INT32_MIN, -1, 0, 1, 0x12345678, INT32_MAX})
    {
        ath::Request request {};
        request.value = value;
        request.length = 32;
        uint8_t bytes[8];
        memset(bytes, 0xA5, sizeof(bytes));
        assert(ath::encodeScalarResult(request, bytes, sizeof(bytes)));
        int32_t decoded;
        memcpy(&decoded, bytes, sizeof(decoded));
        assert(decoded == value && request.length == 4);
        for (size_t i = 4; i < sizeof(bytes); ++i)
            assert(bytes[i] == 0xA5);
        request.length = 3;
        assert(!ath::encodeScalarResult(request, bytes, sizeof(bytes)));
    }
    alignas(8) uint8_t arena[0x4000 + 16];
    auto ring = arena + 8;
    for (size_t capacity : {size_t(4096), size_t(16384)})
    {
        for (uint32_t offset = 0; offset < capacity; offset += 4)
        {
            for (size_t length : {size_t(0), size_t(1), size_t(3), size_t(4),
                                  size_t(37), size_t(1023), size_t(4080)})
            {
                memset(arena, 0xA5, sizeof(arena));
                ath::EventState state {offset, offset, 0};
                uint32_t write = offset;
                uint16_t sequence = 65535;
                std::vector<uint8_t> payload(length);
                for (size_t i = 0; i < length; ++i)
                    payload[i] = static_cast<uint8_t>(i * 7);
                auto result = ath::EventRing::append(
                    ring, capacity, &state, write, sequence, "en0", 1,
                    payload.data(), payload.size(),
                    ath::EventTimestamp {123, 456});
                if (48 + length + 3 >= capacity)
                {
                    assert(result == ath::RingResult::Full);
                }
                else if (result == ath::RingResult::Written)
                {
                    decode(ring, capacity, state, payload);
                    assert(sequence == 0);
                }
                else
                {
                    assert(capacity == 4096 && length == 4080);
                }
                for (size_t i = 0; i < 8; ++i)
                {
                    assert(arena[i] == 0xA5);
                    assert(ring[capacity + i] == 0xA5);
                }
            }
        }
    }
    ath::EventState state {};
    uint32_t write = 0;
    uint16_t sequence = 0;
    const auto before = state;
    assert(ath::EventRing::append(
               ring, 16384, &state, write, sequence, "en0", 1, nullptr, 4097,
               ath::EventTimestamp {0, 0}) == ath::RingResult::Invalid);
    assert(memcmp(&state, &before, sizeof(state)) == 0);
    state.read = 3;
    assert(ath::EventRing::append(ring, 16384, &state, write, sequence, "en0",
                                  1, nullptr, 0, ath::EventTimestamp {0, 0}) ==
           ath::RingResult::Invalid);
    ath::EventFilter filter {};
    assert(!ath::eventFilterAccepts(filter, 1) &&
           !ath::eventFilterAccepts(filter, 248) &&
           !ath::eventFilterAccepts(filter, 249));
    filter.bitmap[0] = 1;
    filter.bitmap[30] = 0x80;
    assert(ath::eventFilterAccepts(filter, 1) &&
           ath::eventFilterAccepts(filter, 248) &&
           !ath::eventFilterAccepts(filter, 2) &&
           !ath::eventFilterAccepts(filter, 249));
}

static void concurrent()
{
    alignas(8) uint8_t ring[0x4000] {};
    ath::EventState state {};
    constexpr uint32_t total = 100000;
    std::thread producer(
        [&]
        {
            uint32_t write = 0;
            uint16_t sequence = 0;
            for (uint32_t n = 0; n < total; ++n)
            {
                const size_t length = randomValue() % 1024;
                std::vector<uint8_t> payload(length, static_cast<uint8_t>(n));
                for (;;)
                {
                    auto result = ath::EventRing::append(
                        ring, sizeof(ring), &state, write, sequence, "en0",
                        n + 1, payload.data(), length,
                        ath::EventTimestamp {length, n});
                    assert(result != ath::RingResult::Invalid);
                    if (result == ath::RingResult::Written)
                        break;
                    std::this_thread::yield();
                }
            }
        });
    std::thread consumer(
        [&]
        {
            uint32_t read = 0;
            for (uint32_t n = 0; n < total;)
            {
                if (read == __atomic_load_n(&state.write, __ATOMIC_ACQUIRE))
                {
                    std::this_thread::yield();
                    continue;
                }
                if (sizeof(ring) - read < 48 ||
                    *reinterpret_cast<uint32_t *>(ring + read) == 0x50)
                {
                    read = (read + 4) % sizeof(ring);
                    __atomic_store_n(&state.read, read, __ATOMIC_RELEASE);
                    continue;
                }
                ath::EventHeader header;
                memcpy(&header, ring + read, sizeof(header));
                assert(header.status == 0x57 && header.event == n + 1);
                assert(header.seconds == header.length &&
                       header.microseconds == n);
                for (size_t i = 0; i < header.length; ++i)
                    assert(ring[(read + 48 + i) % sizeof(ring)] ==
                           static_cast<uint8_t>(n));
                read =
                    (read + 48 + header.length + header.padding) % sizeof(ring);
                __atomic_store_n(&state.read, read, __ATOMIC_RELEASE);
                ++n;
            }
        });
    producer.join();
    consumer.join();
    assert(state.read == state.write);
    checked += total;
}

struct NativeResult
{
        const uint8_t *expected;
        size_t length;
        unsigned calls;
        uint32_t event;
};

static void callback(int status, void *, uint32_t event, const void *payload,
                     size_t length, void *reference)
{
    auto result = static_cast<NativeResult *>(reference);
    assert(status == 0 && event == result->event);
    assert(length == std::min(result->length, size_t(4080)));
    if (length)
        assert(memcmp(payload, result->expected, length) == 0);
    ++result->calls;
}

template <typename T> static void field(uint8_t *object, size_t offset, T value)
{
    memcpy(object + offset, &value, sizeof(value));
}

static char nativeUUID[37] = "unavailable";

static unsigned nativeConsumer()
{
    auto library =
        dlopen("/System/Library/PrivateFrameworks/IO80211.framework/IO80211",
               RTLD_NOW | RTLD_LOCAL);
    assert(library);
    auto open =
        reinterpret_cast<int (*)(void **)>(dlsym(library, "Apple80211Open"));
    auto close =
        reinterpret_cast<int (*)(void *)>(dlsym(library, "Apple80211Close"));
    assert(open && close);
    Dl_info info {};
    assert(dladdr(reinterpret_cast<void *>(open), &info));
    auto header = static_cast<const mach_header_64 *>(info.dli_fbase);
    auto command = reinterpret_cast<const uint8_t *>(header + 1);
    for (uint32_t i = 0; i < header->ncmds; ++i)
    {
        auto load = reinterpret_cast<const load_command *>(command);
        if (load->cmd == LC_UUID)
        {
            auto u = reinterpret_cast<const uuid_command *>(load)->uuid;
            snprintf(nativeUUID, sizeof(nativeUUID),
                     "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%"
                     "02X%02X%02X",
                     u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9],
                     u[10], u[11], u[12], u[13], u[14], u[15]);
        }
        command += load->cmdsize;
    }
    // These optional native-consumer fixtures use private function layouts.
    // A different framework can still build; do not call an unfamiliar layout.
    if (strcmp(nativeUUID, "A7A35846-4067-3182-B70E-F7477FBC32BD"))
    {
        fprintf(stderr, "Native consumer skipped: framework UUID has no "
                        "executable fixture.\n");
        dlclose(library);
        return 0;
    }
    auto address = reinterpret_cast<const uint8_t *>(header) + 0x32B7A;
    auto scanAddress = reinterpret_cast<const uint8_t *>(header) + 0x6D4F;
    auto roamAddress = reinterpret_cast<const uint8_t *>(header) + 0x37432;
    static const uint8_t guard[] = {
        0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54,
        0x53, 0x48, 0x81, 0xEC, 0x08, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x05, 0x33};
    static const uint8_t scanGuard[] = {
        0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55,
        0x41, 0x54, 0x53, 0x48, 0x81, 0xEC, 0xD8, 0x00, 0x00, 0x00};
    static const uint8_t roamGuard[] = {0x55, 0x48, 0x89, 0xE5, 0x41, 0x57,
                                        0x41, 0x56, 0x41, 0x55, 0x41, 0x54,
                                        0x53, 0x48, 0x83, 0xEC, 0x28};
    if (memcmp(address, guard, sizeof(guard)) ||
        memcmp(scanAddress, scanGuard, sizeof(scanGuard)) ||
        memcmp(roamAddress, roamGuard, sizeof(roamGuard)))
    {
        fprintf(stderr, "Native private-consumer fixtures skipped: "
                        "unrecognized function layout.\n");
        dlclose(library);
        return 0;
    }
    auto consume =
        reinterpret_cast<void (*)(void *, uint32_t, const uint64_t *,
                                  uint32_t)>(const_cast<uint8_t *>(address));
    void *opaque = nullptr;
    assert(open(&opaque) == 0 && opaque);
    auto context = static_cast<uint8_t *>(opaque);
    auto port = IONotificationPortCreate(kIOMainPortDefault);
    assert(port);
    field(context, 0x17C, IONotificationPortGetMachPort(port));
    field(context, 0x198, port);
    field(context, 0x33, uint8_t(1));
    field(context, 0x34, uint8_t(1));
    field(context, 0x48, callback);
    memcpy(context + 4, "en0", 4);
    alignas(8) uint8_t ring[0x4000] {};
    ath::EventState state {};
    field(context, 0x1A0, ring + 0);
    field(context, 0x1A8, size_t(sizeof(ring)));
    field(context, 0x1B0, &state);
    unsigned count = 0;
    for (uint32_t offset :
         {0U, 4U, 12288U, 16284U, 16332U, 16336U, 16340U, 16380U})
    {
        for (size_t length :
             {size_t(0), size_t(1), size_t(3), size_t(4), size_t(37),
              size_t(1024), size_t(4080), size_t(4096)})
        {
            memset(ring, 0, sizeof(ring));
            state = {offset, offset, 0};
            uint32_t write = offset;
            uint16_t sequence = 65535;
            std::vector<uint8_t> payload(length);
            for (size_t i = 0; i < length; ++i)
                payload[i] = static_cast<uint8_t>(i * 13);
            NativeResult result {payload.data(), length, 0, 1};
            field(context, 0x50, &result);
            assert(ath::EventRing::append(ring, sizeof(ring), &state, write,
                                          sequence, "en0", 1, payload.data(),
                                          length,
                                          ath::EventTimestamp {123, 456}) ==
                   ath::RingResult::Written);
            consume(opaque, ath::eventNotification, nullptr, 0);
            assert(state.read == write);
            assert(result.calls == 1);
            ++count;
        }
    }
    auto semaphore = dispatch_semaphore_create(0);
    assert(semaphore);
    field(context, 0x98, semaphore);
    for (uint32_t offset : {0U, 4U, 16332U, 16336U, 16380U})
    {
        for (size_t length : {size_t(0), sizeof(uint32_t)})
        {
            memset(ring, 0, sizeof(ring));
            state = {offset, offset, 0};
            uint32_t write = offset;
            uint16_t sequence = 0;
            uint32_t status = 0;
            auto payload = reinterpret_cast<const uint8_t *>(&status);
            NativeResult result {payload, length, 0, ath::scanDoneEvent};
            field(context, 0x50, &result);
            assert(ath::EventRing::append(ring, sizeof(ring), &state, write,
                                          sequence, "en0", ath::scanDoneEvent,
                                          payload, length,
                                          ath::EventTimestamp {123, 456}) ==
                   ath::RingResult::Written);
            consume(opaque, ath::eventNotification, nullptr, 0);
            assert(state.read == write && result.calls == 1);
            assert(dispatch_semaphore_wait(semaphore, DISPATCH_TIME_NOW) == 0);
            assert(dispatch_semaphore_wait(semaphore, DISPATCH_TIME_NOW) != 0);
            ++nativeScanWakeups;
        }
    }
    field(context, 0x98, static_cast<void *>(nullptr));
    dispatch_release(semaphore);
    for (uint32_t offset : {0U, 4U, 16332U, 16336U, 16380U})
    {
        for (uint32_t available : {0U, 1U})
        {
            uint8_t legacy[ath::legacyDriverAvailableSize] {};
            memcpy(legacy + 8, &available, sizeof(available));
            uint8_t payload[ath::nativeDriverAvailableSize];
            assert(ath::copyEventPayload(ath::driverAvailableEvent, legacy,
                                         sizeof(legacy), payload,
                                         sizeof(payload), ath::tahoeABI));
            memset(ring, 0, sizeof(ring));
            state = {offset, offset, 0};
            uint32_t write = offset;
            uint16_t sequence = 0;
            NativeResult result {payload, sizeof(payload), 0,
                                 ath::driverAvailableEvent};
            field(context, 0x50, &result);
            assert(ath::EventRing::append(
                       ring, sizeof(ring), &state, write, sequence, "en0",
                       ath::driverAvailableEvent, payload, sizeof(payload),
                       ath::EventTimestamp {123, 456}) ==
                   ath::RingResult::Written);
            consume(opaque, ath::eventNotification, nullptr, 0);
            assert(state.read == write && result.calls == 1);
            ++nativeAvailabilityRecords;
        }
    }
    for (uint32_t offset : {0U, 4U, 15868U, 16336U, 16380U})
    {
        for (uint32_t status : {0U, 17U})
        {
            uint8_t payload[ath::tahoeABI.joinStatusSize];
            const uint8_t bssid[] = {2, 4, 6, 8, 10, 12};
            assert(ath::encodeJoinStatus(status, status ? 2 : 1, bssid,
                                         status ? 0 : 6, payload,
                                         sizeof(payload), ath::tahoeABI));
            memset(ring, 0, sizeof(ring));
            state = {offset, offset, 0};
            uint32_t write = offset;
            uint16_t sequence = 0;
            NativeResult result {payload, sizeof(payload), 0,
                                 ath::associationDoneEvent};
            field(context, 0x50, &result);
            assert(ath::EventRing::append(
                       ring, sizeof(ring), &state, write, sequence, "en0",
                       ath::associationDoneEvent, payload, sizeof(payload),
                       ath::EventTimestamp {123, 456}) ==
                   ath::RingResult::Written);
            consume(opaque, ath::eventNotification, nullptr, 0);
            assert(state.read == write && result.calls == 1);
            ++nativeJoinRecords;
        }
    }
    field(context, 0x17C, uint32_t(0));
    field(context, 0x198, static_cast<void *>(nullptr));
    field(context, 0x1A0, static_cast<void *>(nullptr));
    field(context, 0x1B0, static_cast<void *>(nullptr));
    field(context, 0x48, static_cast<void *>(nullptr));
    field(context, 0x50, static_cast<void *>(nullptr));
    IONotificationPortDestroy(port);
    assert(close(opaque) == 0);
    using Parse = int (*)(void *, void *, CFMutableArrayRef, CFMutableArrayRef,
                          void *, int, int, int, int, int, int);
    auto parse = reinterpret_cast<Parse>(const_cast<uint8_t *>(scanAddress));
    opaque = nullptr;
    assert(open(&opaque) == 0 && opaque);
    for (uint16_t ieLength : {uint16_t(0), uint16_t(32), uint16_t(0x400)})
    {
        uint8_t record[ath::tahoeABI.scanResultSize] {};
        field(record, 0, uint32_t(1));
        field(record, 4, uint32_t(1));
        field(record, 8, uint32_t(1));
        field(record, 12, uint32_t(0x80));
        field(record, 0x16, int16_t(-55));
        field(record, 0x18, uint16_t(100));
        field(record, 0x1A, uint16_t(1));
        record[0x1C] = 2;
        record[0x21] = 1;
        record[0x60] = 3;
        memcpy(record + 0x61, "SBC", 3);
        field(record, ath::scanIELengthOffset, ieLength);
        ath::Request request {};
        request.length = ath::tahoeABI.scanResultSize;
        assert(ath::prepareScanResult(request, record, sizeof(record),
                                      ath::tahoeABI));
        assert(ath::expandScanResult(request, record, sizeof(record),
                                     ath::tahoeABI));
        auto first = CFArrayCreateMutable(nullptr, 0, &kCFTypeArrayCallBacks);
        auto second = CFArrayCreateMutable(nullptr, 0, &kCFTypeArrayCallBacks);
        assert(first && second);
        assert(parse(opaque, record, first, second, nullptr, 0, 0, 1, 0, 0,
                     0) == 0);
        assert(CFArrayGetCount(first) == 1 && CFArrayGetCount(second) == 1);
        CFRelease(first);
        CFRelease(second);
        ++nativeScanRecords;
    }
    assert(close(opaque) == 0);
    using ParseRoam = void (*)(int, const void *, CFMutableDictionaryRef);
    auto parseRoam =
        reinterpret_cast<ParseRoam>(const_cast<uint8_t *>(roamAddress));
    const char *roamVectors[] = {
        "01000000020000000100000080ffffffb5800abf0000000000000000030046000a0001"
        "000a000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000",
        "01000000040000000100000080ffffffb5800abf0000000000000000030046000a0001"
        "000a000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000"};
    for (auto vector : roamVectors)
    {
        uint8_t legacy[ath::legacyRoamBandSize];
        unhex(vector, legacy, sizeof(legacy));
        uint8_t arena[ath::nativeRoamBandSize + 16];
        memset(arena, 0xA5, sizeof(arena));
        auto native = arena + 8;
        ath::Request request {};
        request.length = ath::legacyRoamBandSize;
        assert(!ath::expandRoamBand(request, legacy, sizeof(legacy), native,
                                    ath::nativeRoamBandSize - 1));
        assert(ath::expandRoamBand(request, legacy, sizeof(legacy), native,
                                   ath::nativeRoamBandSize));
        auto dictionary = CFDictionaryCreateMutable(
            nullptr, 0, &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks);
        parseRoam(0, native, dictionary);
        assert(CFDictionaryGetCount(dictionary) == 3);
        CFRelease(dictionary);
        uint8_t recovered[ath::legacyRoamBandSize];
        assert(ath::prepareRoamBand(request, recovered, sizeof(recovered),
                                    native, ath::nativeRoamBandSize));
        assert(!memcmp(recovered, legacy, sizeof(legacy)));
        for (size_t offset = 0; offset < 8; ++offset)
            assert(arena[offset] == 0xA5 &&
                   native[ath::nativeRoamBandSize + offset] == 0xA5);
        ++nativeRoamRecords;
    }
    dlclose(library);
    return count;
}

static void sonomaVectors()
{
    constexpr auto abi = ath::sonomaABI;
    assert(ath::userABIForKernel(23)->kernel == 23);
    assert(abi.backend == ath::AirPortBackend::Original &&
           abi.selectorCount == 7);
    assert(abi.joinEventPolicy == ath::JoinEventPolicy::Passthrough);
    assert(abi.roamProfileSize == 0x7C && abi.scanMultipleSize == 0x14E0);
    assert(abi.scanResultSize == 0x4CC && abi.capabilitySize == 16 &&
           abi.associateSize == 0x358);
    for (uint16_t auth :
         {uint16_t(0), uint16_t(1), uint16_t(8), uint16_t(0xFFFF)})
    {
        for (uint8_t count :
             {uint8_t(0), uint8_t(1), uint8_t(3), uint8_t(4), uint8_t(255)})
        {
            uint8_t arena[0x358 + 16];
            memset(arena, 0xA5, sizeof(arena));
            auto buffer = arena + 8;
            for (size_t index = 0; index < 0x358; ++index)
                buffer[index] = static_cast<uint8_t>(randomValue());
            memcpy(buffer + 6, &auth, 2);
            memcpy(buffer + 8, &auth, 2);
            buffer[0x202] = count;
            uint8_t original[sizeof(arena)];
            memcpy(original, arena, sizeof(arena));
            ath::Request request {};
            request.length = 0x358;
            assert(!ath::prepareAssociate(request, buffer, 0x357, abi));
            assert(request.length == 0x358 &&
                   !memcmp(arena, original, sizeof(arena)));
            assert(ath::prepareAssociate(request, buffer, 0x358, abi) ==
                   (count <= 3));
            assert(request.length == (count <= 3 ? 0x224U : 0x358U));
            assert(!memcmp(arena, original, sizeof(arena)));
            if (count <= 3)
                ++associationConversions;
        }
    }
    uint8_t join[0x98];
    memset(join, 0xA5, sizeof(join));
    assert(!ath::encodeJoinStatus(0, 1, nullptr, 0, join, sizeof(join), abi));
    for (auto byte : join)
        assert(byte == 0xA5);
    assert(ath::copyEventPayload(9, nullptr, 0, nullptr, 0, abi));
    assert(ath::eventPayloadSize(9, 0, abi) == 0);
    alignas(8) uint8_t ring[4096] {};
    ath::EventState state {};
    uint32_t write = 0;
    uint16_t sequence = 0;
    assert(ath::EventRing::append(
               ring, sizeof(ring), &state, write, sequence, "en0", 9, nullptr,
               0, ath::EventTimestamp {1, 2}) == ath::RingResult::Written);
    const auto header = reinterpret_cast<const ath::EventHeader *>(ring);
    assert(header->event == 9 && header->length == 0 &&
           header->status == 0x57 && write == 0x30);
}

static void scanMultipleVectors()
{
    for (const auto &abi : {ath::sonomaABI, ath::sequoiaABI, ath::tahoeABI})
    {
        for (unsigned mutation = 0; mutation < 6; ++mutation)
        {
            std::vector<uint8_t> arena(abi.scanMultipleSize + 16, 0xA5);
            auto buffer = arena.data() + 8;
            memset(buffer, 0, abi.scanMultipleSize);
            ath::writeUInt32(buffer, mutation == 1 ? 2 : 1);
            ath::writeUInt32(buffer + 8, mutation == 2 ? 11 : 10);
            ath::writeUInt32(buffer + 0x19C, mutation == 3 ? 17 : 16);
            ath::writeUInt32(buffer + 0x210, mutation == 4 ? 401 : 400);
            for (size_t index = 0; index < 10; ++index)
                ath::writeUInt32(buffer + 0x10 + index * 0x28,
                                 mutation == 5 ? 33 : 32);
            auto original = arena;
            ath::Request request {};
            request.length = static_cast<uint32_t>(abi.scanMultipleSize);
            assert(!ath::prepareScanMultiple(request, buffer,
                                             abi.scanMultipleSize - 1, abi));
            assert(arena == original && request.length == abi.scanMultipleSize);
            assert(ath::prepareScanMultiple(request, buffer,
                                            abi.scanMultipleSize,
                                            abi) == (mutation == 0));
            assert(arena == original);
            assert(request.length ==
                   (mutation ? abi.scanMultipleSize : 0x14E0));
            request.length = static_cast<uint32_t>(abi.scanMultipleSize - 1);
            assert(!ath::prepareScanMultiple(request, buffer,
                                             abi.scanMultipleSize, abi));
            assert(arena == original);
        }
    }
}

static void profileBoundaries()
{
    assert(!ath::userABIForKernel(22) && !ath::userABIForKernel(26));
    assert(ath::userABIForKernel(24)->kernel == 24 &&
           ath::userABIForKernel(25)->kernel == 25);
    assert(ath::sequoiaABI.filterMonitorEvents == 0 &&
           ath::tahoeABI.filterMonitorEvents == 564);
    for (const auto &abi : {ath::sonomaABI, ath::sequoiaABI, ath::tahoeABI})
    {
        std::vector<uint8_t> buffer(abi.scanResultSize + 8, 0xA5);
        ath::Request request {};
        request.length =
            static_cast<uint32_t>(abi.kernel == 24 ? 0x8E0 : 0x8D8);
        assert(!ath::prepareScanResult(request, buffer.data(), buffer.size(),
                                       abi));
        request.length =
            static_cast<uint32_t>(abi.kernel == 24 ? 0x38C : 0x384);
        assert(
            !ath::prepareAssociate(request, buffer.data(), buffer.size(), abi));
        for (auto byte : buffer)
            assert(byte == 0xA5);
        for (bool scanEvents : {false, true})
        {
            memset(buffer.data(), 0, buffer.size());
            buffer[0] = 0x81;
            request.length = ath::legacyCapabilitySize;
            assert(ath::expandCapabilities(request, buffer.data(),
                                           buffer.size(), abi, scanEvents));
            assert(request.length == abi.capabilitySize && buffer[0] == 0x81);
            assert(buffer[5] == (scanEvents ? 0x40 : 0));
            for (size_t i = 12; i < abi.capabilitySize; ++i)
                assert(buffer[i] == 0);
        }
    }
}

static void hardwareIdentityVectors()
{
    const char raw[] =
        "vendorid: 0x14e4\ndeviceid: 0x4353\nradiorev: 0xb2056000\n"
        "chipnum: 0xa8d8\nchiprev: 0x1\nboardid: 0xe9\nboardvendor: 0x106b\n";
    ath::HardwareIdentity identity {};
    assert(ath::decodeHardwareIdentity(raw, sizeof(raw) - 1, identity));
    assert(identity.vendor == 0x14e4 && identity.device == 0x4353 &&
           identity.chip == 43224);
    assert(identity.board == 0xe9 && identity.boardVendor == 0x106b);
    uint32_t value = 0x12345678;
    const char overflow[] = "vendorid: 0x1000014e4";
    assert(!ath::hardwareValue(overflow, sizeof(overflow) - 1, "vendorid: 0x",
                               value));
    assert(value == 0x12345678);
    const char invalid[] = "vendorid: 0x14g4";
    assert(!ath::hardwareValue(invalid, sizeof(invalid) - 1, "vendorid: 0x",
                               value));
    assert(!ath::decodeHardwareIdentity(nullptr, 1, identity));
    assert(!ath::decodeHardwareIdentity(raw, 2049, identity));
    const char prefix[] = "xvendorid: 0x14e4";
    assert(
        !ath::hardwareValue(prefix, sizeof(prefix) - 1, "vendorid: 0x", value));
    for (size_t length = 0; length < sizeof(raw) - 7; ++length)
    {
        assert(!ath::decodeHardwareIdentity(raw, length, identity));
    }
    char description[96];
    snprintf(description, sizeof(description), "AirPort Extreme (0x%X, 0x%X)",
             identity.vendor, identity.board);
    assert(!strcmp(description, "AirPort Extreme (0x14E4, 0xE9)"));
}

int main()
{
    hardwareIdentityVectors();
    profileBoundaries();
    boundaries<23>();
    boundaries<24>();
    boundaries<25>();
    availabilityVectors<23>();
    availabilityVectors<24>();
    availabilityVectors<25>();
    joinStatusVectors<false>();
    joinStatusVectors<true>();
    powerAvailabilityVectors<23>();
    powerAvailabilityVectors<24>();
    powerAvailabilityVectors<25>();
    sonomaVectors();
    scanMultipleVectors();
    nativeAvailability();
    associationVectors();
    concurrent();
    const auto native = nativeConsumer();
    printf("{\"ringRecords\":%llu,\"nativeConsumerRecords\":%u,"
           "\"scalarValueEncodings\":6,\"scanResultConversions\":%u,"
           "\"nativeScanConsumerRecords\":%u,\"capabilityConversions\":%u,"
           "\"nativeScanWakeups\":%u,\"associationConversions\":%u,"
           "\"nativeRoamRecords\":%u,\"availabilityConversions\":%u,"
           "\"nativeAvailabilityRecords\":%u,\"joinStatusConversions\":%u,"
           "\"nativeJoinRecords\":%u,\"nativeUUID\":\"%s\"}\n",
           checked, native, scanConversions, nativeScanRecords,
           capabilityConversions, nativeScanWakeups, associationConversions,
           nativeRoamRecords, availabilityConversions,
           nativeAvailabilityRecords, joinStatusConversions, nativeJoinRecords,
           nativeUUID);
}
