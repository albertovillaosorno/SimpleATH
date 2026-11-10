// SPDX-License-Identifier: AGPL-3.0-only
// Bounded AWDL action-frame ingress. No native peer or AirDrop readiness.
#ifndef SIMPLEATH_AWDL_ACTION_HPP
#define SIMPLEATH_AWDL_ACTION_HPP

#include "Frames.hpp"
#include <cstddef>
#include <cstdint>

namespace simpleath
{
    namespace ieee80211
    {
        // AWDL vendor-specific management action-frame syntax (not peer
        // authentication, a radio schedule or AirDrop readiness). The native
        // RX owner must validate FCS/length and retain a stable frame buffer
        // until all TLV payload views have been consumed. No FCS is included.
        struct AwdlAction
        {
                Frame header {};
                uint8_t version {};
                uint8_t subtype {};
                uint32_t phyTransmitUsec {};
                uint32_t targetTransmitUsec {};
                size_t tlvOffset {};
                size_t tlvCount {};
        };

        struct AwdlTlv
        {
                uint8_t type {};
                uint16_t length {};
                // Borrowed pointer, valid only while the RX input is stable.
                const uint8_t *data {};
        };

        enum class AwdlTlvStatus : uint8_t
        {
            Element,
            End,
            Truncated,
        };

        class AwdlTlvs
        {
            public:
                AwdlTlvs(const uint8_t *bytes, size_t length);
                // End or Truncated revokes any prior borrowed payload view.
                AwdlTlvStatus next(AwdlTlv &out);

            private:
                const uint8_t *bytes_;
                size_t length_;
                size_t offset_ {};
        };

        // Only a verified, decrypted-on-air, FCS-stripped 802.11 MPDU may
        // enter this parser. It recognizes the Apple AWDL LLC/SNAP header
        // and IPv6 EtherType; no IPv6 data is delivered to macOS here.
        struct AwdlIpv6Data
        {
                Frame header {};
                uint16_t sequence {};
                size_t ipv6Offset {};
                size_t ipv6Bytes {};
        };

        // A complete single-MSDU, unprotected AWDL data frame with no
        // fragmentation and exact IPv6 payload-length accounting. This
        // value snapshot does not authenticate peers or create an AWDL link.
        Result parseAwdlIpv6Data(const uint8_t *bytes, size_t length,
                                 AwdlIpv6Data &out);

        // Bounded AWDL IPv6 data MPDU serialization for an independently
        // authorized peer/channel. Produces an FCS-free 802.11 MPDU, not a
        // Bluetooth, AWDL scheduling, association or native OS transport.
        // The payload must be an entire IPv6 packet with an exact 16-bit
        // IPv6 payload length. The caller owns sequence generation and must
        // separately prove radio, regulatory and peer/TX authorization.
        struct AwdlIpv6Tx
        {
                Mac source {};
                Mac destination {};
                uint16_t macSequence {};
                uint16_t awdlSequence {};
                bool qos {};
                const uint8_t *ipv6 {};
                size_t ipv6Bytes {};
        };

        // On an ordinary error written is cleared and output is untouched.
        // Aliasing any input/output or output/count storage is rejected
        // before modifying either. Hardware owns FCS generation.
        Result makeAwdlIpv6Data(const AwdlIpv6Tx &request, uint8_t *output,
                                size_t capacity, size_t &written);

        // Checks 802.11 action subtype, Apple AWDL BSSID/OUI and version,
        // then validates the entire bounded little-endian TLV stream before
        // publishing a value snapshot. Unknown TLV types remain opaque.
        Result parseAwdlAction(const uint8_t *bytes, size_t length,
                               AwdlAction &out);

    } // namespace ieee80211
} // namespace simpleath

#endif
