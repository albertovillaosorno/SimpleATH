// SPDX-License-Identifier: AGPL-3.0-only
#include "LinkMonitor.hpp"

namespace simpleath
{
    namespace ieee80211
    {
        namespace
        {
            constexpr uint8_t kMissedBeacons = 10;
            constexpr uint64_t kMinimumTimeoutMs = 1200;
            constexpr uint64_t kMaximumTimeoutMs = 30000;
            constexpr uint64_t kBaseRetryMs = 500;
            constexpr uint64_t kMaximumRetryMs = 16000;

            bool overlapsStorage(const void *first, size_t firstBytes,
                                 const void *second, size_t secondBytes)
            {
                const auto a = reinterpret_cast<uintptr_t>(first);
                const auto b = reinterpret_cast<uintptr_t>(second);
                return a <= b ? b - a < firstBytes : a - b < secondBytes;
            }

            uint16_t readLittle16(const uint8_t *bytes)
            {
                return static_cast<uint16_t>(bytes[0]) |
                       static_cast<uint16_t>(static_cast<uint16_t>(bytes[1])
                                             << 8u);
            }

            uint64_t saturatingAdd(uint64_t left, uint64_t right)
            {
                const uint64_t max = ~static_cast<uint64_t>(0);
                return left > max - right ? max : left + right;
            }
        } // namespace

        LinkMonitor::LinkMonitor() : status_ {}, beaconIntervalTu_(0)
        {
            status_.state = LinkState::Idle;
        }

        void LinkMonitor::clear()
        {
            status_ = {};
            status_.state = LinkState::Idle;
            beaconIntervalTu_ = 0;
        }

        LinkMonitorResult
        LinkMonitor::started(const Mac &station, const Mac &bssid,
                             uint16_t beaconIntervalTu, uint64_t nowMs,
                             bool pmfNegotiated, bool interfaceReady)
        {
            // A reconnect may borrow the prior snapshot by reference. Its
            // fields are destroyed by status_ = {}, so reject those aliases
            // before even validating the MACs or replacing retained state.
            if (overlapsStorage(&station, sizeof(station), this,
                                sizeof(*this)) ||
                overlapsStorage(&bssid, sizeof(bssid), this, sizeof(*this)))
                return LinkMonitorResult::InvalidArgument;
            if (status_.state == LinkState::Associated)
                return LinkMonitorResult::AlreadyMonitoring;
            if (!validStationMac(station) || !validStationMac(bssid) ||
                sameMac(station, bssid))
                return LinkMonitorResult::InvalidMac;
            if (beaconIntervalTu == 0)
                return LinkMonitorResult::InvalidBeaconInterval;
            status_ = {};
            status_.state = LinkState::Associated;
            status_.station = station;
            status_.bssid = bssid;
            status_.lastBeaconMs = nowMs;
            status_.pmfNegotiated = pmfNegotiated;
            status_.networkInterfaceReady = interfaceReady;
            beaconIntervalTu_ = beaconIntervalTu;
            return LinkMonitorResult::Ok;
        }

        bool LinkMonitor::isBroadcastOrStation(const Mac &address,
                                               const Mac &station)
        {
            uint8_t combined = 0;
            for (size_t i = 0; i < 6; ++i)
                combined |= static_cast<uint8_t>(address.bytes[i] ^ 0xffu);
            return combined == 0 || sameMac(address, station);
        }

        uint64_t LinkMonitor::beaconDeadlineMs() const
        {
            // A beacon interval is measured in 1024-microsecond time units.
            // The interval is 16-bit and the multiplier is fixed, so no
            // overflow.
            const uint64_t microseconds =
                static_cast<uint64_t>(beaconIntervalTu_) * 1024u *
                kMissedBeacons;
            uint64_t ms = (microseconds + 999u) / 1000u;
            if (ms < kMinimumTimeoutMs)
                ms = kMinimumTimeoutMs;
            if (ms > kMaximumTimeoutMs)
                ms = kMaximumTimeoutMs;
            return ms;
        }

        void LinkMonitor::lost(LinkLoss reason, uint16_t code, uint64_t nowMs)
        {
            status_.state = LinkState::ReconnectPending;
            status_.reason = reason;
            status_.ieeeReasonCode = code;
            status_.lostAtMs = nowMs;
            status_.reconnectAttempts = 0;
            status_.nextReconnectAtMs = saturatingAdd(nowMs, kBaseRetryMs);
            status_.networkInterfaceReady = false;
        }

        LinkMonitorResult
        LinkMonitor::observeManagement(const uint8_t *frame, size_t frameLength,
                                       uint64_t nowMs, bool fcsVerified,
                                       bool protectedMicAndPnVerified)
        {
            if (status_.state != LinkState::Associated)
                return LinkMonitorResult::NotAssociated;
            // A management frame must not borrow this monitor's retained
            // state. Link loss or beacon reception would otherwise overwrite
            // that source storage while processing the same RX callback.
            if (frame && frameLength &&
                overlapsStorage(frame, frameLength, this, sizeof(*this)))
                return LinkMonitorResult::InvalidArgument;
            if (!fcsVerified)
                return LinkMonitorResult::UnverifiedFrame;
            if (nowMs < status_.lastBeaconMs)
                return LinkMonitorResult::InvalidClock;

            Frame header {};
            if (parseFrame(frame, frameLength, header) != Result::Ok ||
                header.type != FrameType::Management)
                return LinkMonitorResult::InvalidFrame;
            if (!sameMac(header.source, status_.bssid) ||
                !sameMac(header.bssid, status_.bssid) ||
                !isBroadcastOrStation(header.destination, status_.station))
                return LinkMonitorResult::ForeignAccessPoint;

            if (header.subtype == 8 || header.subtype == 5)
            {
                // Beacons/probe responses update liveness only after full
                // parsing.
                Beacon beacon {};
                if (parseBeacon(frame, frameLength, beacon) != Result::Ok ||
                    !beacon.infrastructure || beacon.intervalTu == 0 ||
                    beacon.intervalTu != beaconIntervalTu_)
                    return LinkMonitorResult::InvalidFrame;
                // A parsed foreign/IBSS/zero-interval advertisement must not
                // keep a previously associated infrastructure link alive.
                // A changed beacon cadence requires association renegotiation.
                status_.lastBeaconMs = nowMs;
                if (status_.acceptedBeacons != 0xffffffffu)
                    ++status_.acceptedBeacons;
                return LinkMonitorResult::Ok;
            }
            if (header.subtype == 12 || header.subtype == 10)
            {
                if (frameLength < header.headerLength + 2)
                    return LinkMonitorResult::InvalidFrame;
                // A Protected bit is meaningful for robust management only
                // after PMF negotiation. An Open/non-PMF link must not trust
                // a stale or forged caller assertion of MIC/PN verification.
                if (header.protectedFrame && !status_.pmfNegotiated)
                    return LinkMonitorResult::InvalidFrame;
                if (status_.pmfNegotiated &&
                    (!header.protectedFrame || !protectedMicAndPnVerified))
                    return LinkMonitorResult::RejectedUnprotectedManagement;
                if (header.protectedFrame && !protectedMicAndPnVerified)
                    return LinkMonitorResult::UnverifiedFrame;
                const uint16_t reason =
                    readLittle16(frame + header.headerLength);
                if (reason == 0)
                    return LinkMonitorResult::InvalidFrame;
                lost(header.subtype == 12 ? LinkLoss::Deauthentication
                                          : LinkLoss::Disassociation,
                     reason, nowMs);
                return LinkMonitorResult::Ok;
            }
            return LinkMonitorResult::NoStateChange;
        }

        LinkMonitorResult LinkMonitor::observeTimeout(uint64_t nowMs)
        {
            if (status_.state != LinkState::Associated)
                return LinkMonitorResult::NotAssociated;
            if (nowMs < status_.lastBeaconMs)
                return LinkMonitorResult::InvalidClock;
            if (nowMs - status_.lastBeaconMs <= beaconDeadlineMs())
                return LinkMonitorResult::NoStateChange;
            lost(LinkLoss::BeaconTimeout, 0, nowMs);
            return LinkMonitorResult::Ok;
        }

        void LinkMonitor::radioUnavailable(uint64_t nowMs, bool suspend)
        {
            // A stopped radio cannot perform an automatic reconnect.
            // Revoke any pending retry, previous association identity and
            // link-state claims until an actual new association begins.
            status_ = {};
            status_.state = LinkState::RadioUnavailable;
            status_.reason =
                suspend ? LinkLoss::DriverSuspend : LinkLoss::RadioStopped;
            status_.lostAtMs = nowMs;
            beaconIntervalTu_ = 0;
        }

        bool LinkMonitor::reconnectDue(uint64_t nowMs) const
        {
            return status_.state == LinkState::ReconnectPending &&
                   nowMs >= status_.nextReconnectAtMs;
        }

        bool LinkMonitor::acknowledgeReconnectAttempt(uint64_t nowMs)
        {
            if (!reconnectDue(nowMs))
                return false;
            if (status_.reconnectAttempts < 0xffu)
                ++status_.reconnectAttempts;
            const uint8_t exponent =
                status_.reconnectAttempts < 5 ? status_.reconnectAttempts : 5;
            uint64_t delay = kBaseRetryMs << exponent;
            if (delay > kMaximumRetryMs)
                delay = kMaximumRetryMs;
            status_.nextReconnectAtMs = saturatingAdd(nowMs, delay);
            return true;
        }

    } // namespace ieee80211
} // namespace simpleath
