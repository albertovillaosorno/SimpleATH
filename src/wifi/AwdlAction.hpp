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

        // Construct the four independently documented required MIF TLVs in
        // canonical simple channel-sequence encoding. All election, clock,
        // channel and metric values MUST be supplied from a genuine native
        // owner; this serializer performs no peer election or RF work.
        // Only channel-six slots are represented: other slots encode zero,
        // never an invented 5-GHz capability for the AR9565.
        struct AwdlLocalMifTx
        {
                Mac source {};
                Mac syncMaster {};
                Mac electionMaster {};
                uint16_t macSequence {};
                uint16_t txDownCounterTu {};
                uint16_t nextAwSequence {};
                uint16_t channelSixSlots {};
                uint32_t phyTransmitUsec {};
                uint32_t targetTransmitUsec {};
                uint32_t masterMetric {};
                uint32_t masterCounter {};
                uint32_t ownMetric {};
                uint32_t ownCounter {};
        };

        // Encodes an FCS-free broadcast MIF using the known v1 Mac device
        // class. Rejects input/output and output/count aliasing before any
        // caller mutation. This is NOT permission to publish a live MIF.
        Result makeAwdlChannelSixMif(const AwdlLocalMifTx &request,
                                     uint8_t *output, size_t capacity,
                                     size_t &written);

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
                // 12-bit source MAC sequence of the most recent MIF. A
                // repeated or stale MIF must not refresh radio timing.
                uint16_t macSequence {};
                uint16_t channelSixSlots {};
                uint32_t masterMetric {};
                uint32_t masterCounter {};
                uint32_t ownMetric {};
                uint32_t ownCounter {};
                uint64_t lastHeardMs {};
                // RX data refreshes lastHeardMs, never this MIF phase anchor.
                uint64_t lastMifMs {};
        };

        // At most 16 peers; no allocation, OS side effects, hardware access
        // or autonomous timers. The owner must supply a monotonic clock and
        // FCS-verified RX buffers from the current radio epoch, call clear()
        // on reset/suspend, and independently authorize every real TX window.
        // Only structurally complete MIFs with nonzero Version, Sync,
        // Election-v2 and Channel Sequence TLVs establish peer eligibility.
        // PSFs never create peers. Valid IPv6 data may refresh existing ones.
        // Replayed, duplicate or half-range-ambiguous MIF MAC or AWDL
        // IPv6 data sequence values cannot renew their respective leases.
        // This is freshness bookkeeping, NOT peer authentication or replay
        // protection for delivered AirDrop traffic.
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
                        // Data has its own 16-bit AWDL sequence space, not
                        // the 12-bit management MAC sequence. Retain this
                        // across later MIF updates for the same peer.
                        uint16_t lastIpv6Sequence {};
                        bool ipv6SequenceSeen {};
                        bool occupied {};
                };

                UsbBytes<Entry, kCapacity> entries_ {};
                uint64_t lastClockMs_ {};
                bool clockInitialized_ {};
        };

        // A conservative, read-only candidate for a unicast AWDL channel-6
        // availability window. The native owner must capture mifRxUsec at
        // the hardware-stamped MIF RX boundary, in the same monotonic clock
        // domain as nowUsec, compensating for PHY and callback latency. It
        // must separately verify master election/synchronization, real
        // channel tune, regulatory permission, coexistence, native AWDL
        // ownership, peer trust and TX airtime. This result is NEVER a grant
        // to transmit, schedule a channel change or advertise AirDrop.
        struct AwdlRendezvousRequest
        {
                uint64_t mifRxUsec {};
                uint64_t nowUsec {};
                uint32_t frameAirtimeUsec {};
        };

        struct AwdlRendezvousWindow
        {
                uint16_t awSequence {};
                uint8_t channelSlot {};
                uint32_t remainingEawUsec {};
                // Zero for a current candidate, otherwise bounded lead time.
                uint32_t waitUsec {};
        };

        enum class AwdlRendezvousStatus : uint8_t
        {
            Candidate,
            InvalidInput,
            StaleSync,
            PeerOffChannel,
            GuardInterval,
            NoSharedWindow,
        };

        // The peer's last MIF clock milliseconds MUST match mifRxUsec / 1000;
        // data RX can extend lifetime but cannot refresh the MIF phase.
        // Each channel slot is a 64-TU extended availability window (EAW)
        // spanning four 16-TU AWs. The synchronization counter is the TU
        // remaining until the NEXT EAW boundary, from 1 through 64.
        // The first and last 3 TU of each EAW are unicast guard periods.
        // Aliasing the output to either input is rejected without mutation.
        AwdlRendezvousStatus
        planAwdlChannelSixRendezvous(const AwdlNeighbor &peer,
                                     const AwdlRendezvousRequest &request,
                                     AwdlRendezvousWindow &out);

        // Find the next complete channel-six unicast opportunity, including
        // a currently usable window. Search no further than one 16-slot
        // channel-sequence cycle and never past the five-second MIF anchor.
        // waitUsec describes the first usable time in the selected EAW,
        // after the initial guard; remainingEawUsec is measured there.
        // No local radio or channel reservation follows from this candidate.
        AwdlRendezvousStatus
        planNextAwdlChannelSixRendezvous(const AwdlNeighbor &peer,
                                         const AwdlRendezvousRequest &request,
                                         AwdlRendezvousWindow &out);

        // Match independently observed local and peer channel-six schedules.
        // The native owner supplies both hardware-stamped MIF phase anchors
        // in one monotonic clock domain (local TX and peer RX respectively),
        // plus its actual upcoming frame airtime. Neither peer-only presence
        // nor local channel-six availability can establish an overlap.
        struct AwdlSharedRendezvousRequest
        {
                uint64_t localMifUsec {};
                uint64_t peerMifUsec {};
                uint64_t nowUsec {};
                uint32_t frameAirtimeUsec {};
        };

        struct AwdlSharedRendezvousWindow
        {
                uint16_t localAwSequence {};
                uint16_t peerAwSequence {};
                uint8_t localChannelSlot {};
                uint8_t peerChannelSlot {};
                uint32_t waitUsec {};
                // Time until either end-guard or MIF expiry, from start.
                uint32_t usableUsec {};
        };

        // Check at most two windows per 64-TU EAW during both five-second
        // anchors; never schedule beyond the earlier expiry. All returned
        // windows have at least frameAirtimeUsec within BOTH three-TU guards.
        // No device/radio/channel reservation, peer trust, RF power approval,
        // Bluetooth coexistence or macOS AirDrop authorization is granted.
        // Aliased output is rejected without mutating the caller's inputs.
        AwdlRendezvousStatus planSharedAwdlChannelSixRendezvous(
            const AwdlNeighbor &local, const AwdlNeighbor &peer,
            const AwdlSharedRendezvousRequest &request,
            AwdlSharedRendezvousWindow &out);

        // Checks 802.11 action subtype, Apple AWDL BSSID/OUI and version,
        // then validates the entire bounded little-endian TLV stream before
        // publishing a value snapshot. Unknown TLV types remain opaque.
        Result parseAwdlAction(const uint8_t *bytes, size_t length,
                               AwdlAction &out);

    } // namespace ieee80211
} // namespace simpleath

#endif
