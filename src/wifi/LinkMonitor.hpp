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
//   - Native driver contracts and implementation for link monitor.
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
//   - Native driver contracts and implementation for link monitor.
// - Description:
//   - Implements or verifies the LinkMonitor source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for link monitor.

// Connection loss, beacon miss and bounded reconnection scheduling.
// This is a software state machine: it cannot move the radio to a channel,
// connect to a new BSSID, or authorize unverified 802.11 management frames.
#ifndef SIMPLEATH_WIFI_LINK_MONITOR_HPP
#define SIMPLEATH_WIFI_LINK_MONITOR_HPP

#include "Frames.hpp"
#include <stdint.h>

namespace simpleath
{
    namespace ieee80211
    {

        enum class LinkMonitorResult : uint8_t
        {
            Ok,
            NotAssociated,
            AlreadyMonitoring,
            InvalidMac,
            InvalidBeaconInterval,
            UnverifiedFrame,
            InvalidFrame,
            ForeignAccessPoint,
            RejectedUnprotectedManagement,
            InvalidClock,
            NoStateChange,
            InvalidArgument,
        };

        enum class LinkState : uint8_t
        {
            Idle,
            Associated,
            ReconnectPending,
            RadioUnavailable,
        };

        enum class LinkLoss : uint8_t
        {
            None,
            BeaconTimeout,
            Deauthentication,
            Disassociation,
            RadioStopped,
            DriverSuspend,
        };

        struct LinkSnapshot
        {
                LinkState state;
                LinkLoss reason;
                uint16_t ieeeReasonCode;
                Mac station;
                Mac bssid;
                uint64_t lastBeaconMs;
                uint64_t lostAtMs;
                uint64_t nextReconnectAtMs;
                uint32_t acceptedBeacons;
                uint8_t reconnectAttempts;
                bool pmfNegotiated;
                bool networkInterfaceReady;
        };

        struct LinkStartConfig
        {
                uint16_t beaconIntervalTu;
                uint64_t nowMs;
                bool pmfNegotiated;
                bool interfaceReady;
        };

        class LinkMonitor
        {
            public:
                LinkMonitor();
                void clear();

                // Call only after a validated association; WPA2 keys may
                // still be pending and interfaceReady must then be false.
                // The station and BSSID must be distinct unicast identities.
                // Borrowed MACs overlapping this monitor's retained snapshot
                // are rejected without resetting current reconnect state.
                // This class never claims native operations have occurred.
                LinkMonitorResult started(const Mac &station, const Mac &bssid,
                                          const LinkStartConfig &config);
                // A liveness refresh requires infrastructure beacon/probe
                // metadata matching the associated beacon interval.
                LinkMonitorResult
                observeManagement(const uint8_t *frame, size_t frameLength,
                                  uint64_t nowMs, bool fcsVerified,
                                  bool protectedMicAndPnVerified);
                LinkMonitorResult observeTimeout(uint64_t nowMs);
                // Stop all reconnect scheduling on radio power-down or
                // suspend, including an already pending link-loss retry.
                // Only a subsequent actual association via started() can
                // restore Associated. Native owner must reauthorize PHY,
                // regulatory and keys before calling started().
                void radioUnavailable(uint64_t nowMs, bool suspend);
                // Explicit scheduling only. There is no timer, hardware or OS
                // callback.
                bool reconnectDue(uint64_t nowMs) const;
                bool acknowledgeReconnectAttempt(uint64_t nowMs);

                const LinkSnapshot &status() const
                {
                    return status_;
                }

            private:
                struct FrameTiming
                {
                        size_t frameLength;
                        uint64_t nowMs;
                };

                struct DisconnectionEvidence
                {
                        const uint8_t *frame;
                        size_t frameLength;
                        uint64_t nowMs;
                        bool protectedMicAndPnVerified;
                };

                struct LinkLossDetails
                {
                        uint16_t code;
                        uint64_t nowMs;
                };

                LinkMonitorResult observeBeacon(const uint8_t *frame,
                                                const FrameTiming &timing);
                LinkMonitorResult
                observeDisconnection(const Frame &header,
                                     const DisconnectionEvidence &evidence);
                void lost(LinkLoss reason, const LinkLossDetails &details);
                uint64_t beaconDeadlineMs() const;
                static bool isBroadcastOrStation(const Mac &address,
                                                 const Mac &station);

                LinkSnapshot status_;
                uint16_t beaconIntervalTu_ {0};
        };

    } // namespace ieee80211
} // namespace simpleath
#endif
