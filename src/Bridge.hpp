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
//   - Originally authored by laobamac on 2026/9/19.
//
// Boundary-Contract:
// - Owns:
//   - Native driver contracts and implementation for bridge.
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
//   - Native driver contracts and implementation for bridge.
// - Description:
//   - Implements or verifies the Bridge source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for bridge.

#ifndef SIMPLEATH_BRIDGE_HPP
#define SIMPLEATH_BRIDGE_HPP

#include "Patcher.hpp"
#include "WirelessABI.hpp"
#include <IOKit/IOService.h>
#include <stddef.h>
#include <stdint.h>

class ATH80211UserClient;

namespace ath
{
    constexpr size_t kInterfaceNameCapacity = 16;
    constexpr size_t kSelectorCount = 9;

    enum class InterfaceKind : uint8_t
    {
        Classic,
        Virtual,
        Skywalk,
    };

    struct Endpoint
    {
            IOService *interface;
            IOService *controller;
            InterfaceKind kind;
            char name[kInterfaceNameCapacity];
    };

    struct AvailabilityEvent
    {
            uint64_t seconds;
            uint64_t microseconds;
            uint32_t length;
            uint8_t payload[nativeDriverAvailableSize];
    };

    struct Counters
    {
            uint64_t opens;
            uint64_t denied;
            uint64_t commands;
            uint64_t errors;
            uint64_t events;
            uint64_t dropped;
            uint64_t notifications;
            uint64_t notificationErrors;
            uint64_t scanRecords;
            uint64_t scanDoneEvents;
            uint64_t scanDoneRecords;
            uint64_t associationRequests;
            uint64_t associationAccepted;
            uint64_t availabilityEvents;
            uint64_t availabilityReplays;
            uint64_t associationEvents;
            uint64_t associationEventConversions;
            uint64_t associationEventReadErrors;
            uint64_t powerAvailabilityEvents;
            uint32_t lastAssociationEventLength;
            uint32_t lastAssociationEventReadResult;
            uint32_t lastAvailabilityReadResult;
            uint64_t selectors[kSelectorCount];
            uint32_t lastRequest;
            uint32_t lastResult;
            uint32_t lastAssociationResult;
    };

    extern Counters counters;

    class Bridge
    {
        public:
            static void initialize();
            static void trackController(IOService *controller);
            static void enableNativeSkywalk();
            static bool ready();
            static const UserABI &abi();
            static uint64_t copyAvailability(const Endpoint &endpoint,
                                             AvailabilityEvent &event);
            static int refreshAvailability(const Endpoint &endpoint);
            static bool isScalarGet(uint32_t request);
            static bool identify(IOService *interface, InterfaceKind kind,
                                 Endpoint &endpoint);
            static bool addClient(ATH80211UserClient *client);
            static void removeClient(ATH80211UserClient *client);
            static int command(const Endpoint &endpoint, bool set,
                               LegacyRequest &request, void *shadow,
                               size_t size);
            static void publish(IOService *service);
            static bool prepareImage(LinkedImage &image, size_t index);
            static void disable(const char *reason);

        private:
            static void patchImage(KernelPatcher &patcher, size_t index,
                                   mach_vm_address_t address, size_t size);
    };

} // namespace ath

#endif
