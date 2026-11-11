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
//   - Offline regressions for bounded open data-fragment RX reassembly.
// - Must-Not:
//   - Claim physical FCS, radio or cryptographic verification from fixtures.
// - Allows:
//   - Inputs: synthetic fragment streams and isolated WifiEngine state.
//   - Outputs: deterministic parser and engine verdicts.
//   - Side effects: test-local memory only.
// - Split-When:
//   - A physical owner needs independent hardware and concurrency tests.
// - Merge-When:
//   - The portable fragment receiver is directly exercised here.
// - Summary:
//   - Exercises order, expiry, spoofing, bounds and open-station delivery.
// - Description:
//   - C++14/17 offline data fragmentation contract.
// - Usage:
//   - Executed by tools/validate.py --tests.
// - Defaults:
//   - Unverified and incomplete input must never emit payloads.
//
// Module: Synthetic 802.11 open data fragment reassembly regressions.
#include "wifi/DataReassembly.hpp"
#include "wifi/WifiEngine.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace
{
    using namespace simpleath::ieee80211;
    // Literal test vector wire bytes. They do not set regulatory policy.
    // NOLINTBEGIN(*avoid-magic-numbers,readability-magic-numbers)
    constexpr std::array<uint8_t, 6> kAp {{2, 17, 34, 51, 68, 85}};
    constexpr std::array<uint8_t, 6> kSta {{2, 102, 119, 136, 153, 170}};

    void addresses(uint8_t *frame, const uint8_t *dest)
    {
        std::memcpy(frame + 4, dest, 6);
        std::memcpy(frame + 10, kAp.data(), 6);
        std::memcpy(frame + 16, kAp.data(), 6);
    }

    std::vector<uint8_t> dataFrame(bool qos = false)
    {
        const size_t header = qos ? 26U : 24U;
        std::vector<uint8_t> bytes(header + 11U, 0);
        bytes[0] = qos ? 0x88U : 0x08U;
        bytes[1] = 0x02U;
        bytes[22] = 0x30U;
        bytes[23] = 0x12U;
        addresses(bytes.data(), kSta.data());
        if (qos)
        {
            bytes[24] = 3; // QoS traffic identifier.
        }
        bytes[header] = 0xaaU;
        bytes[header + 1U] = 0xaaU;
        bytes[header + 2U] = 3U;
        bytes[header + 6U] = 0x08U;
        bytes[header + 7U] = 0x00U;
        bytes[header + 8U] = 0x45U;
        bytes[header + 9U] = 1U;
        bytes[header + 10U] = 2U;
        return bytes;
    }

    std::vector<uint8_t> fragment(const std::vector<uint8_t> &source,
                                  size_t firstPayload, size_t count,
                                  uint8_t fragmentIndex, bool more)
    {
        const size_t header = source[0] == 0x88U ? 26U : 24U;
        std::vector<uint8_t> bytes(source.begin(), source.begin() + header);
        bytes.insert(bytes.end(), source.begin() + header + firstPayload,
                     source.begin() + header + firstPayload + count);
        bytes[1] = more ? 0x06U : 0x02U;
        bytes[22] = static_cast<uint8_t>((source[22] & 0xf0U) | fragmentIndex);
        return bytes;
    }

    int dataContract()
    {
        const auto source = dataFrame();
        auto first = fragment(source, 0, 5, 0, true);
        auto last = fragment(source, 5, 6, 1, false);
        DataReassembly receiver;
        DataFrameView view {};
        if (receiver.ingest(first.data(), first.size(), 10, view) !=
                DataFragmentResult::Pending ||
            view.bytes != nullptr || view.length != 0U)
        {
            return __LINE__;
        }
        // Retry bit can differ between individual fragments.
        last[1] |= 0x08U;
        if (receiver.ingest(last.data(), last.size(), 11, view) !=
                DataFragmentResult::Complete ||
            view.length != source.size() ||
            std::memcmp(view.bytes, source.data(), source.size()) != 0 ||
            view.bytes == source.data())
        {
            return __LINE__;
        }
        if (receiver.ingest(last.data(), last.size(), 12, view) !=
                DataFragmentResult::Rejected ||
            view.bytes != nullptr)
        {
            return __LINE__;
        }
        if (receiver.ingest(first.data(), first.size(), 20, view) !=
            DataFragmentResult::Pending)
        {
            return __LINE__;
        }
        last[10] ^= 1U;
        if (receiver.ingest(last.data(), last.size(), 21, view) !=
                DataFragmentResult::Rejected ||
            receiver.ingest(last.data(), last.size(), 22, view) !=
                DataFragmentResult::Rejected)
        {
            return __LINE__;
        }
        last[10] ^= 1U;
        if (receiver.ingest(first.data(), first.size(), 30, view) !=
                DataFragmentResult::Pending ||
            receiver.ingest(last.data(), last.size(), 531, view) !=
                DataFragmentResult::Rejected)
        {
            return __LINE__;
        }
        if (receiver.ingest(first.data(), first.size(), 540, view) !=
                DataFragmentResult::Pending ||
            receiver.ingest(last.data(), last.size(), 539, view) !=
                DataFragmentResult::Rejected)
        {
            return __LINE__;
        }
        last[22] = 2U;
        if (receiver.ingest(first.data(), first.size(), 550, view) !=
                DataFragmentResult::Pending ||
            receiver.ingest(last.data(), last.size(), 551, view) !=
                DataFragmentResult::Rejected)
        {
            return __LINE__;
        }
        last[22] = 1U;
        first[1] |= 0x40U;
        if (receiver.ingest(first.data(), first.size(), 560, view) !=
            DataFragmentResult::Rejected)
        {
            return __LINE__;
        }
        first[1] &= 0xbfU;
        if (receiver.ingest(first.data(), first.size(), 570, view) !=
            DataFragmentResult::Pending)
        {
            return __LINE__;
        }
        receiver.clear();
        if (receiver.ingest(last.data(), last.size(), 571, view) !=
            DataFragmentResult::Rejected)
        {
            return __LINE__;
        }
        auto oversized = dataFrame();
        oversized.resize(kDataReassembledBytes + 1U, 0U);
        if (receiver.ingest(oversized.data(), oversized.size(), 580, view) !=
            DataFragmentResult::Rejected)
        {
            return __LINE__;
        }
        // A late fragment must not be appended past the full MPDU capacity.
        std::vector<uint8_t> full(kDataReassembledBytes, 0U);
        std::memcpy(full.data(), source.data(), 24);
        full[1] = 0x06U;
        if (receiver.ingest(full.data(), full.size(), 600, view) !=
                DataFragmentResult::Pending ||
            receiver.ingest(last.data(), last.size(), 601, view) !=
                DataFragmentResult::Rejected)
        {
            return __LINE__;
        }
        // An output view forged to alias the packet cannot erase wire bytes.
        alignas(DataFrameView) std::array<uint8_t, 64> aliased {};
        std::memcpy(aliased.data(), first.data(), first.size());
        auto *overlap = reinterpret_cast<DataFrameView *>(aliased.data());
        if (receiver.ingest(aliased.data(), first.size(), 610, *overlap) !=
                DataFragmentResult::Rejected ||
            std::memcmp(aliased.data(), first.data(), first.size()) != 0)
        {
            return __LINE__;
        }
        const auto qos = dataFrame(true);
        auto qosStart = fragment(qos, 0, 8, 0, true);
        auto qosEnd = fragment(qos, 8, 3, 1, false);
        if (receiver.ingest(qosStart.data(), qosStart.size(), 620, view) !=
            DataFragmentResult::Pending)
        {
            return __LINE__;
        }
        qosEnd[24] = 4U;
        if (receiver.ingest(qosEnd.data(), qosEnd.size(), 621, view) !=
            DataFragmentResult::Rejected)
        {
            return __LINE__;
        }
        qosEnd[24] = 3U;
        if (receiver.ingest(qosStart.data(), qosStart.size(), 630, view) !=
                DataFragmentResult::Pending ||
            receiver.ingest(qosEnd.data(), qosEnd.size(), 631, view) !=
                DataFragmentResult::Complete ||
            view.length != qos.size() ||
            std::memcmp(view.bytes, qos.data(), qos.size()) != 0)
        {
            return __LINE__;
        }
        return 0;
    }

    uint32_t nextMalformedByte(uint32_t &seed)
    {
        // Reproducible, bounded byte-stream fuzzing; not a cryptographic RNG.
        seed ^= seed << 13U;
        seed ^= seed >> 17U;
        seed ^= seed << 5U;
        return seed;
    }

    int malformedFuzzContract()
    {
        DataReassembly receiver;
        DataFrameView view {};
        uint32_t seed = 0x9565a55aU;
        uint64_t time = 0U;
        // Include truncated, maximal and over-limit lengths, both ordinary
        // and QoS data framing, arbitrary address/sequence flags, and random
        // payloads. Every output must remain bounded and all rejected/pending
        // states must revoke borrowed payload views.
        for (size_t trial = 0; trial < 20000U; ++trial)
        {
            const size_t length =
                static_cast<size_t>(nextMalformedByte(seed) % 2400U);
            std::vector<uint8_t> frame(length, 0U);
            for (auto &octet : frame)
            {
                octet = static_cast<uint8_t>(nextMalformedByte(seed));
            }
            if (length >= 2U && trial % 3U != 0U)
            {
                frame[0] = trial % 2U == 0U ? 0x08U : 0x88U;
                frame[1] = static_cast<uint8_t>(frame[1] &
                                                static_cast<uint8_t>(0x4eU));
                frame[1] |= 0x02U; // FromDS infrastructure data.
            }
            if (trial % 11U == 0U && time != 0U)
            {
                --time; // Reject a backwards fragment clock.
            }
            else
            {
                time += static_cast<uint64_t>(trial % 7U);
            }
            const auto result =
                receiver.ingest(frame.data(), frame.size(), time, view);
            if (result == DataFragmentResult::Complete)
            {
                Frame canonical {};
                if (view.bytes == nullptr || view.length == 0U ||
                    view.length > kDataReassembledBytes ||
                    parseFrame(view.bytes, view.length, canonical) !=
                        Result::Ok ||
                    canonical.type != FrameType::Data ||
                    canonical.moreFragments || canonical.fragment != 0U)
                {
                    return __LINE__;
                }
            }
            else if (view.bytes != nullptr || view.length != 0U)
            {
                return __LINE__;
            }
        }
        receiver.clear();
        return 0;
    }

    std::array<uint8_t, 49> beacon()
    {
        std::array<uint8_t, 49> frame {};
        frame[0] = 0x80U;
        std::memset(frame.data() + 4, 0xff, 6);
        addresses(frame.data(), kAp.data());
        std::memset(frame.data() + 4, 0xff, 6);
        frame[32] = 100;
        frame[34] = 1;
        frame[36] = 0;
        frame[37] = 4;
        std::memcpy(frame.data() + 38, "Test", 4);
        frame[42] = 1;
        frame[43] = 2;
        frame[44] = 0x82;
        frame[45] = 0x84;
        frame[46] = 3;
        frame[47] = 1;
        frame[48] = 6;
        return frame;
    }

    int engineContract()
    {
        static WifiEngine engine;
        engine.clear();
        const InputTrust trust {true, true, true, false};
        const InputTrust unverified {true, true, false, false};
        uint8_t out[512] {};
        EngineAction action {};
        auto observed = beacon();
        if (engine.startScan(true, true) != EngineResult::Ok ||
            engine.acceptRx(observed.data(), observed.size(), trust, {-41, 100},
                            out, sizeof(out), action) != EngineResult::Ok)
        {
            return __LINE__;
        }
        const Mac station {{2, 102, 119, 136, 153, 170}};
        const uint8_t ssid[] {'T', 'e', 's', 't'};
        if (engine.chooseNetwork(station, ssid, sizeof(ssid), 6, true, false,
                                 nullptr) != EngineResult::Ok ||
            engine.requestAuthentication(10, out, sizeof(out), action) !=
                EngineResult::Ok)
        {
            return __LINE__;
        }
        std::array<uint8_t, 30> auth {};
        auth[0] = 0xb0U;
        addresses(auth.data(), kSta.data());
        auth[26] = 2U;
        if (engine.acceptRx(auth.data(), auth.size(), trust, {0, 110}, out,
                            sizeof(out), action) != EngineResult::Ok)
        {
            return __LINE__;
        }
        std::array<uint8_t, 34> assoc {};
        assoc[0] = 0x10U;
        addresses(assoc.data(), kSta.data());
        assoc[24] = 1;
        assoc[28] = 1;
        assoc[29] = 0xc0U;
        assoc[30] = 1;
        assoc[31] = 2;
        assoc[32] = 0x82;
        assoc[33] = 0x84;
        if (engine.acceptRx(assoc.data(), assoc.size(), trust, {0, 120}, out,
                            sizeof(out), action) != EngineResult::Ok ||
            engine.stationState() != StationState::AssociatedOpen)
        {
            return __LINE__;
        }
        const auto canonical = dataFrame();
        auto first = fragment(canonical, 0, 5, 0, true);
        auto last = fragment(canonical, 5, 6, 1, false);
        if (engine.acceptRx(first.data(), first.size(), trust, {-40, 130}, out,
                            sizeof(out), action) != EngineResult::NoAction ||
            action.kind != ActionKind::None)
        {
            return __LINE__;
        }
        // A foreign AP with an otherwise valid FCS must not evict a
        // fragment sequence already started by the associated AP.
        auto foreign = first;
        foreign[10] ^= 1U;
        if (engine.acceptRx(foreign.data(), foreign.size(), trust, {-40, 130},
                            out, sizeof(out),
                            action) != EngineResult::InvalidReceivedFrame ||
            action.kind != ActionKind::None)
        {
            return __LINE__;
        }
        if (engine.acceptRx(last.data(), last.size(), trust, {-40, 131}, out,
                            sizeof(out), action) != EngineResult::Ok ||
            action.kind != ActionKind::ReceivedPayload ||
            action.receivedPayloadBytes != 3U ||
            std::memcmp(action.receivedPayload,
                        canonical.data() + canonical.size() - 3U, 3U) != 0 ||
            action.etherType != 0x0800U)
        {
            return __LINE__;
        }
        // Native queueReceived must publish the Ethernet identities from
        // the completed and address-checked MSDU, not parse the final DMA
        // fragment as a stand-alone 802.11 data frame (which is invalid).
        if (std::memcmp(action.receivedDestination.bytes, kSta.data(),
                        kSta.size()) != 0 ||
            std::memcmp(action.receivedSource.bytes, kAp.data(), kAp.size()) !=
                0)
        {
            return __LINE__;
        }
        Msdu accepted {};
        accepted.destination = action.receivedDestination;
        accepted.source = action.receivedSource;
        accepted.etherType = action.etherType;
        accepted.payload = action.receivedPayload;
        accepted.payloadLength = action.receivedPayloadBytes;
        std::array<uint8_t, 32> ethernet {};
        size_t written = 0;
        if (encodeReceivedEthernet(accepted, ethernet.data(), ethernet.size(),
                                   written) != Result::Ok ||
            written != 17U ||
            std::memcmp(ethernet.data(), kSta.data(), kSta.size()) != 0 ||
            std::memcmp(ethernet.data() + 6U, kAp.data(), kAp.size()) != 0 ||
            ethernet[12] != 0x08U || ethernet[13] != 0x00U ||
            std::memcmp(ethernet.data() + 14U, canonical.data() + 32U, 3U) != 0)
        {
            return __LINE__;
        }
        // The source frame supplied at completion contained only the LAST
        // fragment and cannot itself be interpreted as an LLC/SNAP MSDU.
        Msdu forbidden {};
        if (decodeLlcData(last.data(), last.size(), false, false, forbidden) ==
            Result::Ok)
        {
            return __LINE__;
        }

        // The reconstructed MPDU consumes one sequence number only once.
        if (engine.acceptRx(first.data(), first.size(), trust, {-40, 132}, out,
                            sizeof(out), action) != EngineResult::NoAction ||
            engine.acceptRx(last.data(), last.size(), trust, {-40, 133}, out,
                            sizeof(out), action) != EngineResult::NoAction ||
            action.kind != ActionKind::None)
        {
            return __LINE__;
        }
        // Native DMA retains a verified four-byte FCS on *each* fragment;
        // none of those bytes may leak into the reconstructed Ethernet MSDU.
        const InputTrust includesFcs {true, true, true, false, true};
        auto qos = dataFrame(true);
        qos[22] = 0x50U; // New sequence, independent QoS TID 3.
        auto qosStart = fragment(qos, 0, 8, 0, true);
        auto qosEnd = fragment(qos, 8, 3, 1, false);
        qosStart.insert(qosStart.end(), {0xfaU, 0xfbU, 0xfcU, 0xfdU});
        qosEnd.insert(qosEnd.end(), {0xeaU, 0xebU, 0xecU, 0xedU});
        if (engine.acceptRx(qosStart.data(), qosStart.size(), includesFcs,
                            {-40, 134}, out, sizeof(out),
                            action) != EngineResult::NoAction ||
            engine.acceptRx(qosEnd.data(), qosEnd.size(), includesFcs,
                            {-40, 135}, out, sizeof(out),
                            action) != EngineResult::Ok ||
            action.kind != ActionKind::ReceivedPayload ||
            action.receivedPayloadBytes != 3U || action.etherType != 0x0800U ||
            std::memcmp(action.receivedPayload, qos.data() + qos.size() - 3U,
                        3U) != 0 ||
            std::memcmp(action.receivedSource.bytes, kAp.data(), kAp.size()) !=
                0 ||
            std::memcmp(action.receivedDestination.bytes, kSta.data(),
                        kSta.size()) != 0)
        {
            return __LINE__;
        }
        // A malformed retained-FCS layout must invalidate an earlier stream.
        auto fcsFirst = first;
        auto fcsLast = last;
        fcsFirst[22] = 0x40U;
        fcsLast[22] = 0x41U;
        if (engine.acceptRx(fcsFirst.data(), fcsFirst.size(), trust, {-40, 136},
                            out, sizeof(out),
                            action) != EngineResult::NoAction ||
            engine.acceptRx(fcsFirst.data(), 3U, includesFcs, {-40, 137}, out,
                            sizeof(out),
                            action) != EngineResult::InvalidReceivedFrame ||
            engine.acceptRx(fcsLast.data(), fcsLast.size(), trust, {-40, 138},
                            out, sizeof(out),
                            action) != EngineResult::InvalidReceivedFrame)
        {
            return __LINE__;
        }
        // Revoked FCS trust must invalidate any pending partial payload.
        first[22] = 0x40U;
        last[22] = 0x41U;
        if (engine.acceptRx(first.data(), first.size(), trust, {-40, 140}, out,
                            sizeof(out), action) != EngineResult::NoAction ||
            engine.acceptRx(last.data(), last.size(), unverified, {-40, 141},
                            out, sizeof(out),
                            action) != EngineResult::InvalidInput ||
            engine.acceptRx(last.data(), last.size(), trust, {-40, 142}, out,
                            sizeof(out),
                            action) != EngineResult::InvalidReceivedFrame)
        {
            return __LINE__;
        }
        // WPA2-style protected fragments can never be treated as plaintext.
        first[1] |= 0x40U;
        if (engine.acceptRx(first.data(), first.size(), trust, {-40, 150}, out,
                            sizeof(out),
                            action) != EngineResult::InvalidReceivedFrame)
        {
            return __LINE__;
        }
        return 0;
    }

    // NOLINTEND(*avoid-magic-numbers,readability-magic-numbers)
} // namespace

int main()
{
    const int data = dataContract();
    if (data != 0)
    {
        return data;
    }
    const int fuzz = malformedFuzzContract();
    return fuzz != 0 ? fuzz : engineContract();
}
