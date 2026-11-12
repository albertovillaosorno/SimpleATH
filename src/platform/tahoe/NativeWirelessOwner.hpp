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
//   - Native driver contracts and implementation for native wireless owner.
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
//   - Native driver contracts and implementation for native wireless owner.
// - Description:
//   - Implements or verifies the NativeWirelessOwner source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for native wireless owner.
#ifndef SIMPLEATH_TAHOE_NATIVE_WIRELESS_OWNER_HPP
#define SIMPLEATH_TAHOE_NATIVE_WIRELESS_OWNER_HPP

#include "../../wifi/LegacyScanBridge.hpp"
#include "NativeWirelessEpoch.hpp"
#include "TahoeJoinSession.hpp"
#include <IOKit/IOReturn.h>
#include <IOKit/IOWorkLoop.h>
#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    namespace tahoe
    {
        // Queried through IOService::callPlatformFunction. The callback table
        // is copied into the native controller; its provider is retained until
        // unsubscribe() completes. Never expose a borrowed DMA/engine pointer.
        constexpr char kWirelessOwnerFunction[] = "SimpleATHWirelessOwnerV5";
        constexpr uint32_t kWirelessOwnerAbi = 5;
        constexpr size_t kWirelessMacBytes = 6;
        constexpr size_t kWirelessSsidBytes = 32;
        constexpr size_t kWirelessCcmpKeyBytes = 16;
        constexpr size_t kWirelessPmkBytes = 32;

        struct WirelessSnapshot
        {
                uint64_t epoch;
                uint64_t associationGeneration;
                uint64_t joinRequestId;
                NativeJoinPhase joinPhase;
                IOReturn joinStatus;
                bool associatedBeaconObserved;
                ieee80211::NativeBssSnapshot associatedBss;
                bool signalMeasured;
                uint8_t permanentMac[kWirelessMacBytes];
                uint8_t currentMac[kWirelessMacBytes];
                uint8_t bssid[kWirelessMacBytes];
                uint8_t ssid[kWirelessSsidBytes];
                uint8_t ssidLength;
                uint8_t channel;
                int8_t rssiDbm;
                int8_t noiseDbm;
                char country[3];
                bool radioAvailable;
                bool powered;
                bool scanning;
                bool associated;
                bool controlledPortOpen;
                bool rfKillBlocked;
        };

        struct NativeConnectRequest
        {
                uint64_t epoch;
                uint64_t requestId;
                uint8_t bssid[kWirelessMacBytes];
                uint8_t ssid[kWirelessSsidBytes];
                uint8_t ssidLength;
                uint8_t channel;
                // WCL supplies the PMK; the physical owner exclusively runs
                // WPA2 M1..M4 and installs keys before opening the data port.
                bool wpa2Personal;
                uint8_t pmk[kWirelessPmkBytes];
        };

        inline void clearConnectRequest(NativeConnectRequest &request)
        {
            for (volatile uint8_t &byte : request.pmk)
            {
                byte = 0;
            }
            request.epoch = request.requestId = 0;
        }

        struct NativeCcmpKey
        {
                uint8_t material[kWirelessCcmpKeyBytes];
                uint8_t peer[kWirelessMacBytes];
                uint8_t keyId;
                uint64_t receivePacketNumber;
                bool pairwise;
                bool remove;
        };

        // An authorization applies to exactly one physical association, not
        // whatever join happens to own the same PCI device when the owner gate
        // finally executes. Even a rollback is scoped to this identity.
        struct NativePortRequest
        {
                uint64_t epoch;
                uint64_t joinRequestId;
                uint64_t associationGeneration;
                bool open;
        };

        struct WirelessOwnerV5
        {
                uint32_t abiVersion;
                uint32_t structureBytes;
                void *context;
                // These callbacks synchronously enter the provider's gate.
                // No callback may call into the native controller's gate.
                IOReturn (*snapshot)(void *, WirelessSnapshot *);
                IOReturn (*setPower)(void *, bool on);
                IOReturn (*setMac)(void *,
                                   const uint8_t address[kWirelessMacBytes]);
                IOReturn (*beginScan)(void *, uint64_t *generation);
                IOReturn (*cancelScan)(void *, uint64_t generation);
                IOReturn (*nextBss)(void *, uint64_t generation,
                                    ieee80211::NativeBssSnapshot *);
                IOReturn (*connect)(void *, const NativeConnectRequest *);
                IOReturn (*disconnect)(void *, uint16_t reason);
                IOReturn (*installKey)(void *, const NativeCcmpKey *);
                IOReturn (*authorizePort)(void *, const NativePortRequest *);
                // Borrowed packet bytes are copied before returning success;
                // caller retains its OS packet on queue-full/error.
                IOReturn (*transmitEthernet)(void *, const uint8_t *, size_t);
                // notify() and receive() must copy/queue work without entering
                // the native controller's gate while the provider gate is held.
                // ScanFinished carries the completed bridge generation;
                // all other notifications carry generation zero.
                // A failed subscribe must leave no live callbacks behind;
                // successful unsubscribe joins all in-flight callbacks.
                IOReturn (*subscribe)(void *, void *observer,
                                      void (*notify)(void *, WirelessEvent,
                                                     uint64_t epoch,
                                                     uint64_t generation),
                                      void (*receive)(void *, uint64_t epoch,
                                                      uint64_t association,
                                                      const uint8_t *, size_t));
                void (*unsubscribe)(void *, void *observer);
        };
    } // namespace tahoe
} // namespace simpleath
#endif
