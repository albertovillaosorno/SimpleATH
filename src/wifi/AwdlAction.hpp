// SPDX-License-Identifier: AGPL-3.0-only
// Bounded AWDL action-frame ingress. No native peer or AirDrop readiness.
#ifndef SIMPLEATH_AWDL_ACTION_HPP
#define SIMPLEATH_AWDL_ACTION_HPP

#include "Frames.hpp"
#include "bluetooth/UsbBytes.hpp"
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

        // Outbound PSF (subtype 0) or MIF (subtype 3) envelope. Semantic
        // election/channel/synchronization TLVs must come from an authorized
        // native AWDL scheduler, not from this byte serializer. The entire
        // opaque TLV stream must be structurally valid before any output.
        struct AwdlActionTx
        {
                Mac source {};
                Mac destination {};
                uint16_t macSequence {};
                uint8_t subtype {};
                uint32_t phyTransmitUsec {};
                uint32_t targetTransmitUsec {};
                const uint8_t *tlvs {};
                size_t tlvBytes {};
        };

        // Generates a complete FCS-free vendor action MPDU. No radio TX,
        // synchronization, peer election or AirDrop authorization is implied.
        // Alias rejection preserves both the caller's input and output.
        Result makeAwdlAction(const AwdlActionTx &request, uint8_t *output,
                              size_t capacity, size_t &written);

        // A compact, copied MIF snapshot. Only slots whose peer actually
        // advertises the 2.4 GHz AWDL social channel 6 are exposed; this
        // is evidence of peer intent, NOT a radio/channel TX grant.
        struct AwdlNeighbor
        {
                Mac source {};
                Mac syncMaster {};
                Mac electionMaster {};
                uint8_t version {};
                uint8_t deviceClass {};
                uint16_t awPeriodTu {};
                uint16_t txDownCounterTu {};
                uint16_t nextAwSequence {};
                uint16_t channelSixSlots {};
                uint32_t masterMetric {};
                uint32_t masterCounter {};
                uint32_t ownMetric {};
                uint32_t ownCounter {};
                uint64_t lastHeardMs {};
        };

        // At most 16 peers; no allocation, OS side effects, hardware access
        // or autonomous timers. The owner must supply a monotonic clock and
        // FCS-verified RX buffers from the current radio epoch, call clear()
        // on reset/suspend, and independently authorize every real TX window.
        // Only structurally complete MIFs with nonzero Version, Sync,
        // Election-v2 and Channel Sequence TLVs establish peer eligibility.
        // PSFs never create peers. Valid IPv6 data may refresh existing ones.
        class AwdlNeighbors
        {
            public:
                static constexpr size_t kCapacity = 16U;
                static constexpr uint64_t kExpiryMs = 5000U;

                Result observeMif(uint64_t nowMs, const uint8_t *frame,
                                  size_t bytes);
                Result observeIpv6(uint64_t nowMs, const uint8_t *frame,
                                   size_t bytes);
                bool find(const Mac &source, uint64_t nowMs,
                          AwdlNeighbor &out) const;
                void expire(uint64_t nowMs);
                void clear();

            private:
                struct Entry
                {
                        AwdlNeighbor neighbor {};
                        bool occupied {};
                };

                UsbBytes<Entry, kCapacity> entries_ {};
                uint64_t lastClockMs_ {};
                bool clockInitialized_ {};
        };

        // Checks 802.11 action subtype, Apple AWDL BSSID/OUI and version,
        // then validates the entire bounded little-endian TLV stream before
        // publishing a value snapshot. Unknown TLV types remain opaque.
        Result parseAwdlAction(const uint8_t *bytes, size_t length,
                               AwdlAction &out);

    } // namespace ieee80211
} // namespace simpleath

#endif
