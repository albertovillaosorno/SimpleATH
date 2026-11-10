// WCL event envelopes; offsets checked against native 25G332 consumers.
#ifndef SIMPLEATH_TAHOE_JOIN_EVENTS_HPP
#define SIMPLEATH_TAHOE_JOIN_EVENTS_HPP

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "bluetooth/UsbBytes.hpp"

namespace simpleath
{
    namespace tahoe
    {
        constexpr unsigned int kWclSupplicantEvent = 76;
        constexpr unsigned int kWclDeauthEvent = 203;
        constexpr unsigned int kWclAssociationEvent = 211;
        constexpr unsigned int kWclFirstBeaconEvent = 212;
        constexpr unsigned int kWclConnectionEvent = 213;
        constexpr unsigned int kWclJoinAbortEvent = 214;
        constexpr unsigned int kWclLinkEvent = 216;
        constexpr size_t kWclConnectionEventBytes = 0xa4U;
        constexpr size_t kWclMacAddressBytes = 6U;
        constexpr size_t kWclSupplicantEventBytes = 0x28U;
        constexpr size_t kWclDeauthEventBytes = 0x14U;
        constexpr size_t kWclAssociationEventBytes = 0x1cU;
        constexpr size_t kWclBeaconEventBytes = 0x14U;
        constexpr size_t kWclLinkEventBytes = 0x10U;
        constexpr size_t kWclStatusOffset = 8U;
        constexpr size_t kWclLinkStateOffset = 6U;
        constexpr size_t kWclDeauthBssidOffset = 10U;
        constexpr size_t kWclAssociationBssidOffset = 5U;
        constexpr size_t kWclCommonBssidOffset = 4U;
        constexpr size_t kWclAssociationStatusOffset = 20U;
        constexpr size_t kWclCommonStatusOffset = 12U;

        struct JoinEventOutcome
        {
                int32_t driverStatus;
                uint16_t reason;
        };

        template <typename T>
        inline void joinEventValue(uint8_t *bytes, size_t offset, T value)
        {
            memcpy(simpleath::usbByteOffset(bytes, offset), &value,
                   sizeof(value));
        }

        // A native event may announce only observed provider progress. This
        // encoder just writes the native envelope; it cannot authorize a port.
        inline size_t encodeJoinEvent(unsigned int message,
                                      const uint8_t bssid[kWclMacAddressBytes],
                                      const JoinEventOutcome &outcome, bool up,
                                      uint8_t *out, size_t capacity)
        {
            size_t length = 0;
            switch (message)
            {
                case kWclSupplicantEvent:
                    length = kWclSupplicantEventBytes;
                    break;
                case kWclDeauthEvent:
                    length = kWclDeauthEventBytes;
                    break;
                case kWclAssociationEvent:
                    length = kWclAssociationEventBytes;
                    break;
                case kWclFirstBeaconEvent:
                    length = kWclBeaconEventBytes;
                    break;
                case kWclConnectionEvent:
                    length = kWclConnectionEventBytes;
                    break;
                case kWclLinkEvent:
                    length = kWclLinkEventBytes;
                    break;
                default:
                    return 0;
            }
            if (out == nullptr || bssid == nullptr || capacity < length)
            {
                return 0;
            }
            uint8_t address[kWclMacAddressBytes] {};
            memcpy(&address[0U], bssid, sizeof(address));
            memset(out, 0, length);
            if (message == kWclSupplicantEvent)
            {
                joinEventValue<uint32_t>(out, 0, 1);
                joinEventValue<int32_t>(out, kWclStatusOffset,
                                        outcome.driverStatus);
            }
            else if (message == kWclLinkEvent)
            {
                memcpy(out, &address[0U], sizeof(address));
                *simpleath::usbByteOffset(out, kWclLinkStateOffset) =
                    up ? 1U : 0U;
                joinEventValue<uint32_t>(out, kWclStatusOffset, outcome.reason);
            }
            else if (message == kWclDeauthEvent)
            {
                joinEventValue<int32_t>(out, 0, outcome.driverStatus);
                joinEventValue<uint16_t>(out, kWclStatusOffset, outcome.reason);
                memcpy(simpleath::usbByteOffset(out, kWclDeauthBssidOffset),
                       &address[0U], sizeof(address));
            }
            else
            {
                joinEventValue<uint16_t>(out, 0,
                                         outcome.driverStatus == 0 ? 0 : 1);
                joinEventValue<uint16_t>(out, 2, outcome.reason);
                const bool association = message == kWclAssociationEvent;
                memcpy(simpleath::usbByteOffset(
                           out, association ? kWclAssociationBssidOffset
                                            : kWclCommonBssidOffset),
                       &address[0U], sizeof(address));
                joinEventValue<int32_t>(out,
                                        association
                                            ? kWclAssociationStatusOffset
                                            : kWclCommonStatusOffset,
                                        outcome.driverStatus);
            }
            return length;
        }
    } // namespace tahoe
} // namespace simpleath
#endif
