// SPDX-License-Identifier: AGPL-3.0-only
#ifndef SIMPLEATH_LE_DISCOVERY_HPP
#define SIMPLEATH_LE_DISCOVERY_HPP

#include "UsbBytes.hpp"
#include "UsbHci.hpp"
#include <cstddef>
#include <cstdint>

namespace simpleath
{
    constexpr size_t kLeLegacyAdvertisingBytes = 31U;
    constexpr size_t kLeAddressBytes = 6U;

    enum class LeScanPhase : uint8_t
    {
        Idle,
        AwaitParameters,
        AwaitEnable,
        Scanning,
        AwaitDisable,
        Faulted,
    };

    enum class LeDiscoveryResult : uint8_t
    {
        Ok,
        Ignored,
        InvalidArgument,
        Busy,
        NotScanning,
        OwnershipLost,
        TransportFailed,
        ControllerRejected,
        CommandCreditUnavailable,
        MalformedEvent,
        DeliveryFailed,
        Faulted,
    };

    struct LeLegacyAdvertisement
    {
            UsbBytes<uint8_t, kLeAddressBytes> address {};
            UsbBytes<uint8_t, kLeLegacyAdvertisingBytes> data {};
            size_t dataBytes {};
            uint8_t eventType {};
            uint8_t addressType {};
            int8_t rssi {};
    };

    struct LeDiscoveryOwner
    {
            void *context;
            uint64_t epoch;
            bool (*permit)(void *context, uint64_t epoch);
            // The callback receives a bounded COPY (not a USB DMA pointer).
            // Neither this callback nor LE scans establish a macOS Bluetooth
            // service, AirDrop discovery, or independent HCI ownership.
            bool (*onAdvertisement)(void *context, uint64_t epoch,
                                    const LeLegacyAdvertisement &advertisement);
    };

    struct LeDiscoveryState
    {
            uint64_t epoch {};
            LeScanPhase phase {LeScanPhase::Idle};
            bool stopRequested {};
    };

    // The native Bluetooth HCI owner serializes all calls. It must arbitrate
    // exclusive LE scan procedure ownership with the macOS Bluetooth stack;
    // this component never runs a parallel controller-side scan. The caller
    // supplies the same live USB-HCI session and epoch on EVERY operation.
    // interval/window are HCI 0.625ms units: 4..0x4000, window <= interval.
    // This issues passive LE Set Scan Parameters then waits for controller
    // Command Complete before sending LE Set Scan Enable. No ready state is
    // inferred from a successful USB transfer alone. A zero controller HCI
    // command credit is a fault requiring the owning USB service to recover.
    LeDiscoveryResult beginLePassiveScan(LeDiscoveryState &state,
                                         UsbHciState &transport,
                                         const UsbHciHostCallbacks &host,
                                         const LeDiscoveryOwner &owner,
                                         uint16_t interval, uint16_t window);

    // An outstanding enable may complete after a stop request; the state
    // machine then sends a real disable and waits for its acknowledgment.
    LeDiscoveryResult endLeScan(LeDiscoveryState &state, UsbHciState &transport,
                                const UsbHciHostCallbacks &host,
                                const LeDiscoveryOwner &owner);

    // Feed COMPLETE reassembled HCI events from receiveUsbHciEvent's owner
    // callback. The ordinary macOS host still owns HCI event dispatch.
    LeDiscoveryResult acceptLeHciEvent(LeDiscoveryState &state,
                                       UsbHciState &transport,
                                       const UsbHciHostCallbacks &host,
                                       const LeDiscoveryOwner &owner,
                                       const uint8_t *event, size_t bytes);

    // Call before USB detach/sleep/reset; invalidates all old epoch state.
    // Revocation alone does not guarantee controller scanning is disabled;
    // the native owner must reset/quiesce the USB function on abrupt loss.
    void revokeLeDiscovery(LeDiscoveryState &state);
} // namespace simpleath
#endif
