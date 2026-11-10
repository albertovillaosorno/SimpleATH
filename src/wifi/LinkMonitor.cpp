// SPDX-License-Identifier: AGPL-3.0-only
#include "LinkMonitor.hpp"
#include "Frames.hpp"

#include <cstddef>
#include <cstdint>

namespace simpleath
{
    namespace ieee80211
    {
        namespace
        {
            uintptr_t pointerAddress(const void *pointer)
            {
                static_assert(sizeof(uintptr_t) == sizeof(pointer),
                              "host pointer must fit an address-sized integer");
                uintptr_t address = 0;
                __builtin_memcpy(&address, static_cast<const void *>(&pointer),
                                 sizeof(pointer));
                return address;
            }

            constexpr uint8_t kMissedBeacons = 10;
            constexpr uint32_t kBitsPerByte = 8;
            constexpr uint64_t kMicrosPerBeaconTu = 1024;
            constexpr uint64_t kMicrosPerMillisecond = 1000;
            constexpr uint8_t kMaximumRetryExponent = 5;
            constexpr uint8_t kMaximumRetryAttempts = 0xff;
            constexpr uint8_t kBroadcastOctet = 0xff;
            constexpr uint8_t kBeaconSubtype = 8;
            constexpr uint8_t kProbeResponseSubtype = 5;
            constexpr uint8_t kDeauthenticationSubtype = 12;
            constexpr uint8_t kDisassociationSubtype = 10;
            constexpr uint64_t kMinimumTimeoutMs = 1200;
            constexpr uint64_t kMaximumTimeoutMs = 30000;
            constexpr uint64_t kBaseRetryMs = 500;
            constexpr uint64_t kMaximumRetryMs = 16000;

            bool overlapsStorage(const void *first, size_t firstBytes,
                                 const void *second, size_t secondBytes)
            {
                if (first == nullptr || second == nullptr || firstBytes == 0 ||
                    secondBytes == 0)
                {
                    return false;
                }
                const uintptr_t firstAddress = pointerAddress(first);
                const uintptr_t secondAddress = pointerAddress(second);
                return firstAddress <= secondAddress
                           ? secondAddress - firstAddress < firstBytes
                           : firstAddress - secondAddress < secondBytes;
            }

            uint16_t readLittle16(const uint8_t *bytes)
            {
                uint8_t octets[2] {};
                __builtin_memcpy(&octets[0], bytes, sizeof(octets));
                return static_cast<uint16_t>(octets[0]) |
                       static_cast<uint16_t>(static_cast<uint16_t>(octets[1])
                                             << kBitsPerByte);
            }

            uint64_t saturatingAdd(uint64_t left, uint64_t right)
            {
                const uint64_t max = ~static_cast<uint64_t>(0);
                return left > max - right ? max : left + right;
            }
        } // namespace

        LinkMonitor::LinkMonitor() : status_ {}
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
            {
                return LinkMonitorResult::InvalidArgument;
            }
            if (status_.state == LinkState::Associated)
            {
                return LinkMonitorResult::AlreadyMonitoring;
            }
            if (!validStationMac(station) || !validStationMac(bssid) ||
                sameMac(station, bssid))
            {
                return LinkMonitorResult::InvalidMac;
            }
            if (beaconIntervalTu == 0)
            {
                return LinkMonitorResult::InvalidBeaconInterval;
            }
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
            for (const uint8_t octet : address.bytes)
            {
                combined |= static_cast<uint8_t>(octet ^ kBroadcastOctet);
            }
            return combined == 0 || sameMac(address, station);
        }

        uint64_t LinkMonitor::beaconDeadlineMs() const
        {
            // A beacon interval is measured in 1024-microsecond time units.
            // The interval is 16-bit and the multiplier is fixed, so no
            // overflow.
            const uint64_t microseconds =
                static_cast<uint64_t>(beaconIntervalTu_) * kMicrosPerBeaconTu *
                kMissedBeacons;
            const uint64_t ms = (microseconds + kMicrosPerMillisecond - 1) /
                                kMicrosPerMillisecond;
            if (ms < kMinimumTimeoutMs)
            {
                return kMinimumTimeoutMs;
            }
            return ms > kMaximumTimeoutMs ? kMaximumTimeoutMs : ms;
        }

        void LinkMonitor::lost(LinkLoss reason, const LinkLossDetails &details)
        {
            const uint16_t code = details.code;
            const uint64_t nowMs = details.nowMs;
            status_.state = LinkState::ReconnectPending;
            status_.reason = reason;
            status_.ieeeReasonCode = code;
            status_.lostAtMs = nowMs;
            status_.reconnectAttempts = 0;
            status_.nextReconnectAtMs = saturatingAdd(nowMs, kBaseRetryMs);
            status_.networkInterfaceReady = false;
        }

        LinkMonitorResult LinkMonitor::observeBeacon(const uint8_t *frame,
                                                     const FrameTiming &timing)
        {
            const size_t frameLength = timing.frameLength;
            const uint64_t nowMs = timing.nowMs;
            // Beacons/probe responses update liveness only after full
            // parsing.
            Beacon beacon {};
            if (parseBeacon(frame, frameLength, beacon) != Result::Ok ||
                !beacon.infrastructure || beacon.intervalTu == 0 ||
                beacon.intervalTu != beaconIntervalTu_)
            {
                return LinkMonitorResult::InvalidFrame;
            }
            // A parsed foreign/IBSS/zero-interval advertisement must not
            // keep a previously associated infrastructure link alive.
            // A changed beacon cadence requires association renegotiation.
            status_.lastBeaconMs = nowMs;
            if (status_.acceptedBeacons != UINT32_MAX)
            {
                ++status_.acceptedBeacons;
            }
            return LinkMonitorResult::Ok;
        }

        LinkMonitorResult
        LinkMonitor::observeDisconnection(const Frame &header,
                                          const DisconnectionEvidence &evidence)
        {
            const uint8_t *const frame = evidence.frame;
            const size_t frameLength = evidence.frameLength;
            const uint64_t nowMs = evidence.nowMs;
            const bool protectedMicAndPnVerified =
                evidence.protectedMicAndPnVerified;
            if (frameLength < header.headerLength + 2)
            {
                return LinkMonitorResult::InvalidFrame;
            }
            // A Protected bit is meaningful for robust management only
            // after PMF negotiation. An Open/non-PMF link must not trust
            // a stale or forged caller assertion of MIC/PN verification.
            if (header.protectedFrame && !status_.pmfNegotiated)
            {
                return LinkMonitorResult::InvalidFrame;
            }
            if (status_.pmfNegotiated &&
                (!header.protectedFrame || !protectedMicAndPnVerified))
            {
                return LinkMonitorResult::RejectedUnprotectedManagement;
            }
            if (header.protectedFrame && !protectedMicAndPnVerified)
            {
                return LinkMonitorResult::UnverifiedFrame;
            }
            const uint16_t reason = readLittle16(frame + header.headerLength);
            if (reason == 0)
            {
                return LinkMonitorResult::InvalidFrame;
            }
            // A deauthentication/disassociation body begins with the
            // two-octet reason code and may contain optional IEs. A
            // truncated or overlong IE tail cannot authorize tearing
            // down the selected link, even with a verified FCS.
            Elements extensions(frame + header.headerLength + 2,
                                frameLength - header.headerLength - 2);
            Element extension {};
            for (;;)
            {
                const CursorStatus next = extensions.next(extension);
                if (next == CursorStatus::End)
                {
                    break;
                }
                if (next == CursorStatus::Truncated)
                {
                    return LinkMonitorResult::InvalidFrame;
                }
            }
            lost(header.subtype == kDeauthenticationSubtype
                     ? LinkLoss::Deauthentication
                     : LinkLoss::Disassociation,
                 LinkLossDetails {reason, nowMs});
            return LinkMonitorResult::Ok;
        }

        LinkMonitorResult
        LinkMonitor::observeManagement(const uint8_t *frame, size_t frameLength,
                                       uint64_t nowMs, bool fcsVerified,
                                       bool protectedMicAndPnVerified)
        {
            if (status_.state != LinkState::Associated)
            {
                return LinkMonitorResult::NotAssociated;
            }
            // A management frame must not borrow this monitor's retained
            // state. Link loss or beacon reception would otherwise overwrite
            // that source storage while processing the same RX callback.
            if (frame != nullptr && frameLength != 0 &&
                overlapsStorage(frame, frameLength, this, sizeof(*this)))
            {
                return LinkMonitorResult::InvalidArgument;
            }
            if (!fcsVerified)
            {
                return LinkMonitorResult::UnverifiedFrame;
            }
            if (nowMs < status_.lastBeaconMs)
            {
                return LinkMonitorResult::InvalidClock;
            }

            if (frame == nullptr)
            {
                return LinkMonitorResult::InvalidFrame;
            }
            Frame header {};
            if (parseFrame(frame, frameLength, header) != Result::Ok ||
                header.type != FrameType::Management)
            {
                return LinkMonitorResult::InvalidFrame;
            }
            if (!sameMac(header.source, status_.bssid) ||
                !sameMac(header.bssid, status_.bssid) ||
                !isBroadcastOrStation(header.destination, status_.station))
            {
                return LinkMonitorResult::ForeignAccessPoint;
            }

            if (header.subtype == kBeaconSubtype ||
                header.subtype == kProbeResponseSubtype)
            {
                return observeBeacon(frame, FrameTiming {frameLength, nowMs});
            }
            if (header.subtype == kDeauthenticationSubtype ||
                header.subtype == kDisassociationSubtype)
            {
                return observeDisconnection(header,
                                            DisconnectionEvidence {
                                                frame,
                                                frameLength,
                                                nowMs,
                                                protectedMicAndPnVerified,
                                            });
            }
            return LinkMonitorResult::NoStateChange;
        }

        LinkMonitorResult LinkMonitor::observeTimeout(uint64_t nowMs)
        {
            if (status_.state != LinkState::Associated)
            {
                return LinkMonitorResult::NotAssociated;
            }
            if (nowMs < status_.lastBeaconMs)
            {
                return LinkMonitorResult::InvalidClock;
            }
            if (nowMs - status_.lastBeaconMs <= beaconDeadlineMs())
            {
                return LinkMonitorResult::NoStateChange;
            }
            lost(LinkLoss::BeaconTimeout, LinkLossDetails {0, nowMs});
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
            {
                return false;
            }
            if (status_.reconnectAttempts < kMaximumRetryAttempts)
            {
                ++status_.reconnectAttempts;
            }
            const uint8_t exponent =
                status_.reconnectAttempts > kMaximumRetryExponent
                    ? kMaximumRetryExponent
                    : status_.reconnectAttempts;
            const uint64_t unclampedDelay = kBaseRetryMs << exponent;
            const uint64_t delay = unclampedDelay > kMaximumRetryMs
                                       ? kMaximumRetryMs
                                       : unclampedDelay;
            status_.nextReconnectAtMs = saturatingAdd(nowMs, delay);
            return true;
        }

    } // namespace ieee80211
} // namespace simpleath
