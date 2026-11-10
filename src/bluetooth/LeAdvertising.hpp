// HCI LE legacy non-connectable advertising on an exclusively owned USB HCI
// session. This does not register a macOS Bluetooth host, AirDrop or AWDL.
#ifndef SIMPLEATH_LE_ADVERTISING_HPP
#define SIMPLEATH_LE_ADVERTISING_HPP

#include "UsbBytes.hpp"
#include "UsbHci.hpp"
#include <cstddef>
#include <cstdint>

namespace simpleath
{
    constexpr size_t kLeAdvertisingDataBytes = 31U;

    enum class LeAdvertisingPhase : uint8_t
    {
        Idle,
        AwaitParameters,
        AwaitData,
        AwaitEnable,
        Advertising,
        AwaitDisable,
        Faulted,
    };

    enum class LeAdvertisingResult : uint8_t
    {
        Ok,
        Ignored,
        InvalidArgument,
        Unauthorized,
        Busy,
        NotAdvertising,
        OwnershipLost,
        TransportFailed,
        ControllerRejected,
        CommandCreditUnavailable,
        MalformedEvent,
        Faulted,
    };

    struct LeAdvertisingOwner
    {
            void *context;
            uint64_t epoch;
            bool (*permit)(void *context, uint64_t epoch);
            // The native Bluetooth host stack must authorize exclusive LE
            // advertising control, the actual AD bytes, use of the public
            // Bluetooth address, channel/privacy policy and interval. This
            // permission is NOT implied by having a physical USB pipe.
            bool (*authorize)(void *context, uint64_t epoch,
                              const uint8_t *advertisingData, size_t bytes,
                              uint16_t minimumInterval);
    };

    struct LeAdvertisingState
    {
            UsbBytes<uint8_t, kLeAdvertisingDataBytes> data {};
            uint64_t epoch {};
            size_t dataBytes {};
            uint16_t interval {};
            LeAdvertisingPhase phase {LeAdvertisingPhase::Idle};
            bool stopRequested {};
    };

    // Legacy LE Set Advertising Parameters/Data/Enable; ADV_NONCONN_IND,
    // public address, all three advertising channels, no scan responses.
    // Interval is in 0.625ms units; non-connectable minimum is 0x00a0 and
    // maximum 0x4000. The 1..31 bytes must contain complete AD structures.
    // Never start concurrent discovery or advertising behind the macOS host
    // controller's back: it must arbitrate LE procedures and authorize data.
    // Controller Command Complete is required after each operation; Command
    // Status rejection or zero credits faults the procedure. This producer
    // alone makes NO claim that AirDrop peers can discover this computer.
    LeAdvertisingResult beginLeAdvertising(LeAdvertisingState &state,
                                           UsbHciState &transport,
                                           const UsbHciHostCallbacks &host,
                                           const LeAdvertisingOwner &owner,
                                           const uint8_t *data, size_t bytes,
                                           uint16_t interval);

    // Cancellation during setup prevents enable. Cancellation after enable
    // is acknowledged sends the actual disable and awaits confirmation.
    LeAdvertisingResult endLeAdvertising(LeAdvertisingState &state,
                                         UsbHciState &transport,
                                         const UsbHciHostCallbacks &host,
                                         const LeAdvertisingOwner &owner);

    // Consume complete HCI events from the same native USB event dispatcher.
    LeAdvertisingResult
    acceptLeAdvertisingEvent(LeAdvertisingState &state, UsbHciState &transport,
                             const UsbHciHostCallbacks &host,
                             const LeAdvertisingOwner &owner,
                             const uint8_t *event, size_t bytes);

    // Before disconnect/sleep/USB reset; revokes borrowed AD bytes and the
    // session epoch. Abrupt revoke alone cannot turn off RF advertising:
    // the native owner must quiesce or reset the physical controller.
    void revokeLeAdvertising(LeAdvertisingState &state);
} // namespace simpleath
#endif
