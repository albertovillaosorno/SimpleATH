// WCL event envelopes; offsets checked against native 25G332 consumers.
#ifndef SIMPLEATH_TAHOE_JOIN_EVENTS_HPP
#define SIMPLEATH_TAHOE_JOIN_EVENTS_HPP

#include <stddef.h>
#include <stdint.h>
#include <string.h>

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
        constexpr size_t kWclConnectionEventBytes = 0xa4;

        template <typename T>
        inline void joinEventValue(uint8_t *bytes, size_t offset, T value)
        {
            memcpy(bytes + offset, &value, sizeof(value));
        }

        // A native event may announce only observed provider progress. This
        // encoder just writes the native envelope; it cannot authorize a port.
        inline size_t encodeJoinEvent(unsigned int message,
                                      const uint8_t bssid[6],
                                      int32_t driverStatus, uint16_t reason,
                                      bool up, uint8_t *out, size_t capacity)
        {
            size_t length = 0;
            switch (message)
            {
                case kWclSupplicantEvent:
                    length = 0x28;
                    break;
                case kWclDeauthEvent:
                    length = 0x14;
                    break;
                case kWclAssociationEvent:
                    length = 0x1c;
                    break;
                case kWclFirstBeaconEvent:
                    length = 0x14;
                    break;
                case kWclConnectionEvent:
                    length = 0xa4;
                    break;
                case kWclLinkEvent:
                    length = 0x10;
                    break;
                default:
                    return 0;
            }
            if (out == nullptr || bssid == nullptr || capacity < length)
            {
                return 0;
            }
            uint8_t address[6] {};
            memcpy(address, bssid, sizeof(address));
            memset(out, 0, length);
            if (message == kWclSupplicantEvent)
            {
                joinEventValue<uint32_t>(out, 0, 1);
                joinEventValue<int32_t>(out, 8, driverStatus);
            }
            else if (message == kWclLinkEvent)
            {
                memcpy(out, address, sizeof(address));
                out[6] = up ? 1U : 0U;
                joinEventValue<uint32_t>(out, 8, reason);
            }
            else if (message == kWclDeauthEvent)
            {
                joinEventValue<int32_t>(out, 0, driverStatus);
                joinEventValue<uint16_t>(out, 8, reason);
                memcpy(out + 10, address, sizeof(address));
            }
            else
            {
                joinEventValue<uint16_t>(out, 0, driverStatus == 0 ? 0 : 1);
                joinEventValue<uint16_t>(out, 2, reason);
                const bool association = message == kWclAssociationEvent;
                memcpy(out + (association ? 5U : 4U), address, sizeof(address));
                joinEventValue<int32_t>(out, association ? 20U : 12U,
                                        driverStatus);
            }
            return length;
        }
    } // namespace tahoe
} // namespace simpleath
#endif
