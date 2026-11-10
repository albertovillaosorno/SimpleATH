// Copyright (c) 2026 SimpleATH contributors.
#ifndef SIMPLEATH_TAHOE_NATIVE_WIRELESS_OWNER_HPP
#define SIMPLEATH_TAHOE_NATIVE_WIRELESS_OWNER_HPP

#include "../../wifi/LegacyScanBridge.hpp"
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
        constexpr char kWirelessOwnerFunction[] = "SimpleATHWirelessOwnerV1";
        constexpr uint32_t kWirelessOwnerAbi = 1;
        constexpr size_t kWirelessMacBytes = 6;
        constexpr size_t kWirelessSsidBytes = 32;
        constexpr size_t kWirelessCcmpKeyBytes = 16;

        enum class WirelessEvent : uint32_t
        {
            RadioChanged,
            ScanFinished,
            AssociationChanged,
            LinkChanged,
            TransmitAvailable,
            ProviderStopped,
        };

        struct WirelessSnapshot
        {
                uint64_t epoch;
                uint64_t associationGeneration;
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
                uint8_t bssid[kWirelessMacBytes];
                uint8_t ssid[kWirelessSsidBytes];
                uint8_t ssidLength;
                uint8_t channel;
                // Native OS owns WPA2 supplication. Key material arrives only
                // through the explicit CCMP install operation below.
                bool wpa2Personal;
        };

        struct NativeCcmpKey
        {
                uint8_t material[kWirelessCcmpKeyBytes];
                uint8_t peer[kWirelessMacBytes];
                uint8_t keyId;
                uint64_t receivePacketNumber;
                bool pairwise;
                bool remove;
        };

        struct WirelessOwnerV1
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
                IOReturn (*authorizePort)(void *, bool open);
                // Borrowed packet bytes are copied before returning success;
                // caller retains its OS packet on queue-full/error.
                IOReturn (*transmitEthernet)(void *, const uint8_t *, size_t);
                // notify() and receive() must copy/queue work without entering
                // the native controller's gate while the provider gate is held.
                // A failed subscribe must leave no live callbacks behind;
                // successful unsubscribe joins all in-flight callbacks.
                IOReturn (*subscribe)(void *, void *observer,
                                      void (*notify)(void *, WirelessEvent,
                                                     uint64_t epoch),
                                      void (*receive)(void *, const uint8_t *,
                                                      size_t));
                void (*unsubscribe)(void *, void *observer);
        };
    } // namespace tahoe
} // namespace simpleath
#endif
