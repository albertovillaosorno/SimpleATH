// SPDX-License-Identifier: AGPL-3.0-only
#include "DataFrames.hpp"

namespace simpleath
{
    namespace ieee80211
    {

        Result decodeLlcData(const uint8_t *frame, size_t frameBytes,
                             bool containsFcs, bool verifiedDecryptionAndMic,
                             Msdu &out)
        {
            Frame header {};
            const Result result = parseFrame(frame, frameBytes, header);
            if (result != Result::Ok)
                return result;
            if (header.type != FrameType::Data)
                return Result::UnsupportedFrame;
            // A-MSDU and fragmentation need separate, bounded reassembly.
            if ((header.subtype & 0x4u) != 0 || header.fragment != 0 ||
                header.moreFragments)
                return Result::UnsupportedFrame;
            if (header.protectedFrame && !verifiedDecryptionAndMic)
                return Result::InvalidSecurity;
            if ((header.subtype & 0x8u) != 0)
            {
                // IEEE 802.11 QoS control bit 7 marks an A-MSDU. Subframes need
                // separate length/padding validation before they can be
                // delivered.
                const size_t qosOffset =
                    24u + (header.toDs && header.fromDs ? 6u : 0u);
                if (frameBytes < qosOffset + 2u)
                    return Result::Truncated;
                if ((frame[qosOffset] & 0x80u) != 0)
                    return Result::UnsupportedFrame;
            }
            if (containsFcs)
            {
                if (frameBytes < header.headerLength + 4)
                    return Result::Truncated;
                frameBytes -= 4;
            }
            if (frameBytes - header.headerLength < 8)
                return Result::Truncated;
            const uint8_t *llc = frame + header.headerLength;
            if (llc[0] != 0xaau || llc[1] != 0xaau || llc[2] != 0x03u)
                return Result::UnsupportedFrame;
            const bool standardSnap = llc[3] == 0 && llc[4] == 0 && llc[5] == 0;
            const bool bridgeTunnelSnap =
                llc[3] == 0 && llc[4] == 0 && llc[5] == 0xf8u;
            if (!standardSnap && !bridgeTunnelSnap)
                return Result::UnsupportedFrame;
            const uint16_t etherType =
                static_cast<uint16_t>(static_cast<uint16_t>(llc[6]) << 8u) |
                static_cast<uint16_t>(llc[7]);
            if (etherType < 0x0600u)
                return Result::InvalidFrame;
            // The protected bit and decrypted payload are NOT evidence that a
            // key is authorized; the platform must prove decrypt+MIC+PN before
            // passing true.
            Msdu data {};
            data.destination = header.destination;
            data.source = header.source;
            data.etherType = etherType;
            data.payload = llc + 8;
            data.payloadLength = frameBytes - header.headerLength - 8;
            data.protectedFrame = header.protectedFrame;
            data.qosFrame = (header.subtype & 0x8u) != 0;
            out = data;
            return Result::Ok;
        }

    } // namespace ieee80211
} // namespace simpleath
