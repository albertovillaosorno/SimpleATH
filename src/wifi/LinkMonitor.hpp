// SPDX-License-Identifier: AGPL-3.0-only
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
            InvalidArgument
        };

        enum class LinkState : uint8_t
        {
            Idle,
            Associated,
            ReconnectPending,
            RadioUnavailable
        };

        enum class LinkLoss : uint8_t
        {
            None,
            BeaconTimeout,
            Deauthentication,
            Disassociation,
            RadioStopped,
            DriverSuspend
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
                                          uint16_t beaconIntervalTu,
                                          uint64_t nowMs, bool pmfNegotiated,
                                          bool interfaceReady);
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
                void lost(LinkLoss reason, uint16_t code, uint64_t nowMs);
                uint64_t beaconDeadlineMs() const;
                static bool isBroadcastOrStation(const Mac &address,
                                                 const Mac &station);

                LinkSnapshot status_;
                uint16_t beaconIntervalTu_;
        };

    } // namespace ieee80211
} // namespace simpleath
#endif
