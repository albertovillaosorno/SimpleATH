// SPDX-License-Identifier: AGPL-3.0-only
#include "DataFrames.hpp"
#include "Frames.hpp"

#include <cstddef>
#include <cstdint>

namespace simpleath
{
    namespace ieee80211
    {
        static constexpr uint8_t K_QOS_SUBTYPE = 8;
        static constexpr uint8_t K_AMSDU_PRESENT = 0x80;
        static constexpr uint8_t K_SNAP_SAP = 0xaa;
        static constexpr uint8_t K_SNAP_CONTROL = 0x03;
        static constexpr size_t K_SNAP_CONTROL_OFFSET = 2;
        static constexpr uint8_t K_BRIDGE_TUNNEL_OUI_LAST = 0xf8;
        static constexpr uint16_t K_ETHERNET_II_MIN = 0x0600;
        static constexpr uint16_t K_ETHERTYPE_AARP = 0x80f3;
        static constexpr uint16_t K_ETHERTYPE_IPX = 0x8137;
        static constexpr size_t K_BASE_80211_HEADER_BYTES = 24;
        static constexpr size_t K_FOURTH_ADDRESS_BYTES = 6;
        static constexpr size_t K_QOS_CONTROL_BYTES = 2;
        static constexpr size_t K_FCS_BYTES = 4;
        static constexpr size_t K_MAX_MPDU_BYTES_INCLUDING_FCS = 2346;
        static constexpr size_t K_LLC_SNAP_BYTES = 8;
        static constexpr uint32_t K_BITS_PER_BYTE = 8;

        static bool overlaps(const void *const first_buffer, size_t first_bytes,
                             const void *const second_buffer,
                             size_t second_bytes)
        {
            if (first_buffer == nullptr || second_buffer == nullptr ||
                first_bytes == 0 || second_bytes == 0)
            {
                return false;
            }
            const auto first = reinterpret_cast<uintptr_t>(first_buffer);
            const auto second = reinterpret_cast<uintptr_t>(second_buffer);
            return first <= second ? second - first < first_bytes
                                   : first - second < second_bytes;
        }

        Result decodeLlcData(const uint8_t *const frame, size_t frame_bytes,
                             bool contains_fcs,
                             bool verified_decryption_and_mic, Msdu &out)
        {
            // A malformed output reference can point into the DMA-backed
            // frame. Never clear it and destroy RX evidence before parsing.
            if (overlaps(&out, sizeof(out), frame, frame_bytes))
            {
                return Result::OverlappingBuffers;
            }
            // Never leave a borrowed pointer from a previously accepted RX
            // buffer accessible after an ordinary failed parse.
            out = {};
            Frame header {};
            const Result result = parseFrame(frame, frame_bytes, header);
            if (result != Result::Ok)
            {
                return result;
            }
            if (header.type != FrameType::Data)
            {
                return Result::UnsupportedFrame;
            }
            // This non-aggregating data path shares the 2346-byte on-air
            // MPDU ceiling used by station TX. A DMA buffer without its FCS
            // may contain at most 2342 bytes. Reject oversized RX before
            // borrowing a payload pointer for native Ethernet delivery.
            if (frame_bytes > K_MAX_MPDU_BYTES_INCLUDING_FCS -
                                  (contains_fcs ? 0U : K_FCS_BYTES))
            {
                return Result::InvalidFrame;
            }
            // Only ordinary and QoS Data MSDUs have a reviewed payload
            // contract. Null-data and contention-free poll/ACK variants are
            // not ordinary Ethernet-II data for this station decoder.
            // A-MSDU and fragmentation need separate, bounded reassembly.
            if ((header.subtype != 0U && header.subtype != K_QOS_SUBTYPE) ||
                header.fragment != 0 || header.moreFragments)
            {
                return Result::UnsupportedFrame;
            }
            if (header.protectedFrame && !verified_decryption_and_mic)
            {
                return Result::InvalidSecurity;
            }
            if ((header.subtype & K_QOS_SUBTYPE) != 0)
            {
                // IEEE 802.11 QoS control bit 7 marks an A-MSDU. Subframes need
                // separate length/padding validation before they can be
                // delivered.
                const size_t qos_offset =
                    K_BASE_80211_HEADER_BYTES + (header.toDs && header.fromDs
                                                     ? K_FOURTH_ADDRESS_BYTES
                                                     : 0U);
                if (frame_bytes < qos_offset + K_QOS_CONTROL_BYTES)
                {
                    return Result::Truncated;
                }
                if ((frame[qos_offset] & K_AMSDU_PRESENT) != 0)
                {
                    return Result::UnsupportedFrame;
                }
            }
            if (contains_fcs)
            {
                if (frame_bytes < header.headerLength + K_FCS_BYTES)
                {
                    return Result::Truncated;
                }
                frame_bytes -= K_FCS_BYTES;
            }
            if (frame_bytes - header.headerLength < K_LLC_SNAP_BYTES)
            {
                return Result::Truncated;
            }
            const uint8_t *const llc = frame + header.headerLength;
            if (llc[0] != K_SNAP_SAP || llc[1] != K_SNAP_SAP ||
                llc[K_SNAP_CONTROL_OFFSET] != K_SNAP_CONTROL)
            {
                return Result::UnsupportedFrame;
            }
            const bool standard_snap =
                llc[3] == 0 && llc[4] == 0 && llc[5] == 0;
            const bool bridge_tunnel_snap = llc[3] == 0 && llc[4] == 0 &&
                                            llc[5] == K_BRIDGE_TUNNEL_OUI_LAST;
            if (!standard_snap && !bridge_tunnel_snap)
            {
                return Result::UnsupportedFrame;
            }
            const uint16_t ether_type =
                static_cast<uint16_t>(static_cast<uint16_t>(llc[6])
                                      << K_BITS_PER_BYTE) |
                static_cast<uint16_t>(llc[7]);
            if (ether_type < K_ETHERNET_II_MIN)
            {
                return Result::InvalidFrame;
            }
            // IEEE 802.1H reserves the bridge-tunnel SNAP OUI for Ethernet-II
            // AARP/IPX. The ordinary RFC 1042 form for these EtherTypes must
            // be kept as 802.3 LLC rather than misreported as Ethernet-II.
            if (standard_snap && (ether_type == K_ETHERTYPE_AARP ||
                                  ether_type == K_ETHERTYPE_IPX))
            {
                return Result::UnsupportedFrame;
            }
            // The protected bit and decrypted payload are NOT evidence that a
            // key is authorized; the platform must prove decrypt+MIC+PN before
            // passing true.
            Msdu data {};
            data.destination = header.destination;
            data.source = header.source;
            data.etherType = ether_type;
            data.payload = llc + K_LLC_SNAP_BYTES;
            data.payloadLength =
                frame_bytes - header.headerLength - K_LLC_SNAP_BYTES;
            data.protectedFrame = header.protectedFrame;
            data.qosFrame = (header.subtype & K_QOS_SUBTYPE) != 0;
            out = data;
            return Result::Ok;
        }

    } // namespace ieee80211
} // namespace simpleath
