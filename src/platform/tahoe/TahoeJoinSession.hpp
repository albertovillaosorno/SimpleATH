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
//   - Native driver contracts and implementation for tahoe join session.
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
//   - Native driver contracts and implementation for tahoe join session.
// - Description:
//   - Implements or verifies the TahoeJoinSession source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for tahoe join session.

// Native join progress, independent of IOKit and borrowed credential storage.
#ifndef SIMPLEATH_TAHOE_JOIN_SESSION_HPP
#define SIMPLEATH_TAHOE_JOIN_SESSION_HPP

#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace simpleath
{
    namespace tahoe
    {
        constexpr size_t kJoinMacBytes = 6U;

        enum class NativeJoinPhase : uint8_t
        {
            Idle,
            Authenticating,
            Associating,
            Handshaking,
            Ready,
            Failed,
        };

        struct JoinObservation
        {
                uint64_t epoch {0};
                uint64_t requestId {0};
                uint64_t associationGeneration {0};
                uint8_t bssid[kJoinMacBytes] {};
                NativeJoinPhase phase {NativeJoinPhase::Idle};
                int32_t status {0};
                bool associated {false};
                bool controlledPortOpen {false};
                bool beaconObserved {false};
        };

        enum JoinNotice : uint32_t
        {
            NoJoinNotice = 0,
            AssociationNotice = 1U,
            BeaconNotice = 2U,
            SupplicantNotice = 4U,
            ConnectionNotice = 8U,
            FailureNotice = 16U,
            DisconnectionNotice = 32U,
        };

        // One native join owns one provider epoch/request and one successful
        // association generation. No PMK or borrowed native request is
        // retained.
        class JoinSession final
        {
            public:
                bool begin(uint64_t epoch, uint64_t requestId,
                           const uint8_t bssid[kJoinMacBytes], bool wpa2)
                {
                    if (active_ || epoch == 0 || requestId == 0 ||
                        bssid == nullptr)
                    {
                        return false;
                    }
                    uint8_t candidate[kJoinMacBytes] {};
                    memcpy(&candidate[0], bssid, sizeof(candidate));
                    uint8_t aggregate = 0;
                    for (const uint8_t byte : candidate)
                    {
                        aggregate |= byte;
                    }
                    if (aggregate == 0 || (candidate[0] & 1U) != 0)
                    {
                        return false;
                    }
                    reset();
                    epoch_ = epoch;
                    requestId_ = requestId;
                    memcpy(&bssid_[0], &candidate[0], sizeof(bssid_));
                    wpa2_ = wpa2;
                    active_ = true;
                    return true;
                }

                uint32_t observe(const JoinObservation &value)
                {
                    if (!active_)
                    {
                        return NoJoinNotice;
                    }
                    if (value.epoch != epoch_ ||
                        value.requestId != requestId_ || value.status != 0 ||
                        value.phase == NativeJoinPhase::Failed ||
                        value.phase == NativeJoinPhase::Idle)
                    {
                        return lose();
                    }
                    if (!value.associated)
                    {
                        return associationSeen_ ? lose() : NoJoinNotice;
                    }
                    if (value.associationGeneration == 0 ||
                        memcmp(&bssid_[0], &value.bssid[0], sizeof(bssid_)) !=
                            0 ||
                        (value.phase != NativeJoinPhase::Handshaking &&
                         value.phase != NativeJoinPhase::Ready) ||
                        (associationSeen_ &&
                         value.associationGeneration != generation_))
                    {
                        return lose();
                    }
                    uint32_t notices = NoJoinNotice;
                    if (!associationSeen_)
                    {
                        generation_ = value.associationGeneration;
                        associationSeen_ = true;
                        notices |= AssociationNotice;
                    }
                    if (value.beaconObserved && !beaconSeen_)
                    {
                        beaconSeen_ = true;
                        notices |= BeaconNotice;
                    }
                    const bool ready = value.controlledPortOpen &&
                                       value.phase == NativeJoinPhase::Ready;
                    if (ready && wpa2_ && !keysSeen_)
                    {
                        keysSeen_ = true;
                        notices |= SupplicantNotice;
                    }
                    if (ready && beaconSeen_ && !connected_)
                    {
                        connected_ = true;
                        notices |= ConnectionNotice;
                    }
                    return notices;
                }

                uint32_t lose()
                {
                    if (!active_)
                    {
                        return NoJoinNotice;
                    }
                    const uint32_t notice =
                        connected_ ? DisconnectionNotice : FailureNotice;
                    active_ = false;
                    return notice;
                }

                void reset()
                {
                    epoch_ = requestId_ = generation_ = 0;
                    memset(&bssid_[0], 0, sizeof(bssid_));
                    wpa2_ = active_ = associationSeen_ = beaconSeen_ =
                        keysSeen_ = connected_ = false;
                }

                bool active() const
                {
                    return active_;
                }

                bool pending() const
                {
                    return active_ && !connected_;
                }

                // OS link getters must not accept an unrelated or retired
                // physical association merely because its port is open.
                // Read only while the owning InfraProtocol gate is held.
                bool connectedTo(const JoinObservation &value) const
                {
                    return active_ && connected_ && generation_ != 0 &&
                           value.epoch == epoch_ &&
                           value.requestId == requestId_ &&
                           value.associationGeneration == generation_ &&
                           memcmp(&bssid_[0], &value.bssid[0],
                                  sizeof(bssid_)) == 0 &&
                           value.status == 0 &&
                           value.phase == NativeJoinPhase::Ready &&
                           value.associated && value.controlledPortOpen &&
                           value.beaconObserved;
                }

                bool beaconObserved() const
                {
                    return beaconSeen_;
                }

                bool wpa2() const
                {
                    return wpa2_;
                }

                const uint8_t *bssid() const
                {
                    return &bssid_[0];
                }

            private:
                uint64_t epoch_ {0};
                uint64_t requestId_ {0};
                uint64_t generation_ {0};
                uint8_t bssid_[kJoinMacBytes] {};
                bool wpa2_ {false};
                bool active_ {false};
                bool associationSeen_ {false};
                bool beaconSeen_ {false};
                bool keysSeen_ {false};
                bool connected_ {false};
        };
    } // namespace tahoe
} // namespace simpleath
#endif
