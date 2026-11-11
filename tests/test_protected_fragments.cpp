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
//   - Offline CCMP fragment MIC/PN and station reassembly regressions.
// - Must-Not:
//   - Claim physical FCS verification or native radio operation.
// - Allows:
//   - Inputs: independent synthetic keys and on-air byte sequences.
//   - Outputs: authentication, pending and native-payload gate verdicts.
//   - Side effects: isolated host-test state only.
// - Split-When:
//   - Native hardware can provide actual RX/FCS evidence.
// - Merge-When:
//   - This receive contract is covered by a larger source fixture.
// - Summary:
//   - Proves fragments are individually authenticated before publication.
// - Description:
//   - Exercises per-fragment PN, MIC, GTK selection, timeouts and FCS.
// - Usage:
//   - Run by tools/validate.py --tests, not by live driver hardware.
// - Defaults:
//   - No unverified or partially reassembled MSDU can escape.
//
// Module: Synthetic WPA2 CCMP fragment receive admission.
#include "wifi/DataPath.hpp"
#include "wifi/crypto/Ccmp.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace
{
    using namespace simpleath::ieee80211;
    using namespace simpleath::ieee80211::crypto;
    // Synthetic exact 802.11 header, key and LLC/SNAP wire octets.
    // NOLINTBEGIN(*avoid-magic-numbers,readability-magic-numbers)
    constexpr uint64_t kEpoch = 8300U;
    constexpr std::array<uint8_t, 16U> kKey {{
        0U,
        1U,
        2U,
        3U,
        4U,
        5U,
        6U,
        7U,
        8U,
        9U,
        10U,
        11U,
        12U,
        13U,
        14U,
        15U,
    }};
    constexpr std::array<uint8_t, 6U> kAp {{
        0x02U,
        0x11U,
        0x22U,
        0x33U,
        0x44U,
        0x55U,
    }};
    constexpr std::array<uint8_t, 6U> kStation {{
        0x02U,
        0x66U,
        0x77U,
        0x88U,
        0x99U,
        0xaaU,
    }};
    constexpr std::array<uint8_t, 11U> kData {{
        'h',
        'e',
        'l',
        'l',
        'o',
        ' ',
        'w',
        'o',
        'r',
        'l',
        'd',
    }};
    constexpr size_t kHeaderBytes = 24U;
    constexpr size_t kCcmpKeyIdByte = kHeaderBytes + 3U;
    constexpr size_t kFcsBytes = 4U;

    LinkContext associated()
    {
        LinkContext link {};
        std::memcpy(link.station.bytes, kStation.data(), kStation.size());
        std::memcpy(link.bssid.bytes, kAp.data(), kAp.size());
        link.security = LinkSecurity::Wpa2Ccmp;
        link.associated = true;
        link.rfReady = true;
        link.channelPermitted = true;
        link.pairwiseAndGroupKeysInstalled = true;
        return link;
    }

    std::vector<uint8_t> plain(bool group, bool qos = false)
    {
        const size_t header = qos ? 26U : kHeaderBytes;
        std::vector<uint8_t> result(header + 8U + kData.size(), 0U);
        result[0U] = qos ? 0x88U : 0x08U;
        if (qos)
        {
            result[24U] = 3U; // QoS traffic identifier.
        }
        result[1U] = 0x02U; // AP -> station, unprotected for TX encoder.
        result[22U] = 0x30U;
        result[23U] = 0x12U;
        std::memcpy(result.data() + 4U, kStation.data(), kStation.size());
        if (group)
        {
            std::memset(result.data() + 4U, 0xff, kStation.size());
        }
        std::memcpy(result.data() + 10U, kAp.data(), kAp.size());
        std::memcpy(result.data() + 16U, kAp.data(), kAp.size());
        const uint8_t snap[8U] {
            0xaaU, 0xaaU, 0x03U, 0U, 0U, 0U, 0x08U, 0U,
        };
        std::memcpy(result.data() + header, snap, sizeof(snap));
        std::memcpy(result.data() + header + sizeof(snap), kData.data(),
                    kData.size());
        return result;
    }

    std::vector<uint8_t> fragment(const std::vector<uint8_t> &source,
                                  size_t offset, size_t length, uint8_t index,
                                  bool more)
    {
        const size_t header = source[0U] == 0x88U ? 26U : kHeaderBytes;
        std::vector<uint8_t> result(source.begin(), source.begin() + header);
        result.insert(result.end(), source.begin() + header + offset,
                      source.begin() + header + offset + length);
        result[1U] = more ? 0x06U : 0x02U;
        result[22U] = static_cast<uint8_t>((source[22U] & 0xf0U) | index);
        return result;
    }

    std::vector<uint8_t> encrypt(CcmpSession &tx,
                                 const std::vector<uint8_t> &source)
    {
        std::array<uint8_t, kCcmpMaximumMpduBytes> wire {};
        size_t count = 0U;
        if (tx.protect(kEpoch, source.data(), source.size(), wire.data(),
                       wire.size(), count, true) != CcmpResult::Ok)
        {
            return {};
        }
        std::vector<uint8_t> result(wire.begin(), wire.begin() + count);
        result.insert(result.end(), {0xf1U, 0xf2U, 0xf3U, 0xf4U});
        return result;
    }

    DataPathResult ingest(ProtectedFragmentStream &fragments, CcmpSession &rx,
                          const std::vector<uint8_t> &wire, uint64_t now,
                          std::array<uint8_t, kCcmpMaximumMpduBytes> &scratch,
                          Msdu &msdu, bool trust = true)
    {
        const auto link = associated();
        return inspectProtectedFragmentStationRx(
            link, wire.data(), wire.size(), true, trust, rx, kEpoch, fragments,
            now, scratch.data(), scratch.size(), msdu);
    }

    bool validMsdu(const Msdu &msdu)
    {
        return msdu.etherType == 0x0800U &&
               msdu.payloadLength == kData.size() && msdu.payload != nullptr &&
               std::memcmp(msdu.payload, kData.data(), kData.size()) == 0 &&
               std::memcmp(msdu.destination.bytes, kStation.data(),
                           kStation.size()) == 0;
    }

    int authenticatedFragments()
    {
        CcmpSession tx {};
        CcmpSession rx {};
        if (tx.install(kKey.data(), kAp.data(), 0U, kEpoch, 0U, 0U) !=
                CcmpResult::Ok ||
            rx.install(kKey.data(), kAp.data(), 0U, kEpoch, 0U, 0U) !=
                CcmpResult::Ok)
        {
            return __LINE__;
        }
        const auto input = plain(false);
        const auto first = fragment(input, 0U, 9U, 0U, true);
        const auto last = fragment(input, 9U, 10U, 1U, false);
        std::array<uint8_t, kCcmpMaximumMpduBytes> output {};
        size_t written = 999U;
        // Nonfragmented callers must opt in, and no PN is consumed on deny.
        if (tx.protect(kEpoch, first.data(), first.size(), output.data(),
                       output.size(),
                       written) != CcmpResult::UnsupportedFrame ||
            written != 999U || tx.lastTransmittedPn() != 0U)
        {
            return __LINE__;
        }
        const auto firstWire = encrypt(tx, first);
        const auto lastWire = encrypt(tx, last);
        if (firstWire.empty() || lastWire.empty() ||
            tx.lastTransmittedPn() != 2U)
        {
            return __LINE__;
        }
        ProtectedFragmentStream fragments {};
        Msdu msdu {};
        if (rx.unprotect(kEpoch, firstWire.data(), firstWire.size() - kFcsBytes,
                         output.data(), output.size(),
                         written) != CcmpResult::UnsupportedFrame ||
            rx.receiveFloor() != 0U ||
            ingest(fragments, rx, firstWire, 100U, output, msdu) !=
                DataPathResult::PendingFragments ||
            msdu.payload != nullptr || rx.receiveFloor() != 1U)
        {
            return __LINE__;
        }
        auto damaged = lastWire;
        damaged[damaged.size() - kFcsBytes - 1U] ^= 0x80U; // Corrupt MIC.
        if (ingest(fragments, rx, damaged, 101U, output, msdu) !=
                DataPathResult::UnverifiedDecryption ||
            msdu.payload != nullptr || rx.receiveFloor() != 1U ||
            ingest(fragments, rx, lastWire, 102U, output, msdu) !=
                DataPathResult::Ok ||
            !validMsdu(msdu) || rx.receiveFloor() != 2U)
        {
            return __LINE__;
        }
        if (ingest(fragments, rx, firstWire, 103U, output, msdu) !=
                DataPathResult::UnverifiedDecryption ||
            msdu.payload != nullptr || fragments.pending)
        {
            return __LINE__;
        }
        return 0;
    }

    int groupZeroUnfragmented()
    {
        CcmpSession tx {};
        CcmpSession gtkZero {};
        if (tx.install(kKey.data(), kAp.data(), 0U, kEpoch, 0U, 0U) !=
                CcmpResult::Ok ||
            gtkZero.install(kKey.data(), kAp.data(), 0U, kEpoch, 0U, 0U) !=
                CcmpResult::Ok)
        {
            return __LINE__;
        }
        const auto wire = encrypt(tx, plain(true));
        if (wire.empty())
        {
            return __LINE__;
        }
        std::array<uint8_t, kCcmpMaximumMpduBytes> scratch {};
        Msdu msdu {};
        const auto link = associated();
        if (inspectProtectedStationRx(
                link, wire.data(), wire.size(), true, true, gtkZero, kEpoch,
                scratch.data(), scratch.size(), msdu) != DataPathResult::Ok ||
            msdu.payload == nullptr || msdu.payloadLength != kData.size() ||
            std::memcmp(msdu.payload, kData.data(), kData.size()) != 0 ||
            gtkZero.receiveFloor() != 1U)
        {
            return __LINE__;
        }
        if (inspectProtectedStationRx(link, wire.data(), wire.size(), true,
                                      true, gtkZero, kEpoch, scratch.data(),
                                      scratch.size(), msdu) !=
                DataPathResult::UnverifiedDecryption ||
            msdu.payload != nullptr || gtkZero.receiveFloor() != 1U)
        {
            return __LINE__;
        }
        return 0;
    }

    int groupKeyIsolation()
    {
        CcmpSession tx {};
        CcmpSession groupOne {};
        CcmpSession groupTwo {};
        if (tx.install(kKey.data(), kAp.data(), 0U, kEpoch, 0U, 0U) !=
                CcmpResult::Ok ||
            groupOne.install(kKey.data(), kAp.data(), 1U, kEpoch, 0U, 0U) !=
                CcmpResult::Ok ||
            groupTwo.install(kKey.data(), kAp.data(), 2U, kEpoch, 0U, 0U) !=
                CcmpResult::Ok)
        {
            return __LINE__;
        }
        const auto source = plain(true);
        auto first = encrypt(tx, fragment(source, 0U, 10U, 0U, true));
        auto last = encrypt(tx, fragment(source, 10U, 9U, 1U, false));
        if (first.empty() || last.empty())
        {
            return __LINE__;
        }
        first[kCcmpKeyIdByte] = 0x60U; // GTK slot 1.
        last[kCcmpKeyIdByte] = 0xa0U;  // GTK slot 2, same key, valid MIC.
        ProtectedFragmentStream fragments {};
        std::array<uint8_t, kCcmpMaximumMpduBytes> scratch {};
        Msdu msdu {};
        if (ingest(fragments, groupOne, first, 10U, scratch, msdu) !=
                DataPathResult::PendingFragments ||
            ingest(fragments, groupTwo, last, 11U, scratch, msdu) !=
                DataPathResult::MalformedFrame ||
            msdu.payload != nullptr || !fragments.pending ||
            fragments.keyId != 1U)
        {
            return __LINE__;
        }
        // Key ID bits are not CCMP AAD, so the same ciphertext authenticates
        // under the original GTK session. It must complete *only* that key.
        last[kCcmpKeyIdByte] = 0x60U;
        const auto admitted =
            ingest(fragments, groupOne, last, 12U, scratch, msdu);
        return admitted == DataPathResult::Ok &&
                       msdu.payloadLength == kData.size() &&
                       std::memcmp(msdu.payload, kData.data(), kData.size()) ==
                           0 &&
                       !fragments.pending
                   ? 0
                   : __LINE__;
    }

    int invalidTrustRevokesStream()
    {
        CcmpSession tx {};
        CcmpSession rx {};
        if (tx.install(kKey.data(), kAp.data(), 0U, kEpoch, 0U, 0U) !=
                CcmpResult::Ok ||
            rx.install(kKey.data(), kAp.data(), 0U, kEpoch, 0U, 0U) !=
                CcmpResult::Ok)
        {
            return __LINE__;
        }
        const auto input = plain(false);
        const auto first = encrypt(tx, fragment(input, 0U, 9U, 0U, true));
        const auto last = encrypt(tx, fragment(input, 9U, 10U, 1U, false));
        ProtectedFragmentStream fragments {};
        std::array<uint8_t, kCcmpMaximumMpduBytes> scratch {};
        Msdu msdu {};
        if (ingest(fragments, rx, first, 10U, scratch, msdu) !=
                DataPathResult::PendingFragments ||
            ingest(fragments, rx, last, 11U, scratch, msdu, false) !=
                DataPathResult::InvalidRxStatus ||
            fragments.pending ||
            ingest(fragments, rx, last, 12U, scratch, msdu) !=
                DataPathResult::MalformedFrame ||
            msdu.payload != nullptr)
        {
            return __LINE__;
        }
        return 0;
    }

    int qosAndExpiry()
    {
        CcmpSession tx {};
        CcmpSession rx {};
        if (tx.install(kKey.data(), kAp.data(), 0U, kEpoch, 0U, 0U) !=
                CcmpResult::Ok ||
            rx.install(kKey.data(), kAp.data(), 0U, kEpoch, 0U, 0U) !=
                CcmpResult::Ok)
        {
            return __LINE__;
        }
        const auto input = plain(false, true);
        const auto first = encrypt(tx, fragment(input, 0U, 9U, 0U, true));
        const auto last = encrypt(tx, fragment(input, 9U, 10U, 1U, false));
        if (first.empty() || last.empty())
        {
            return __LINE__;
        }
        ProtectedFragmentStream fragments {};
        std::array<uint8_t, kCcmpMaximumMpduBytes> scratch {};
        Msdu msdu {};
        if (ingest(fragments, rx, first, 100U, scratch, msdu) !=
                DataPathResult::PendingFragments ||
            rx.receiveFloor() != 1U || msdu.payload != nullptr)
        {
            return __LINE__;
        }
        // Both More-Fragments and Sequence Control fragment index are in the
        // CCMP AAD. A third party cannot change either after authentication.
        auto changedMore = last;
        changedMore[1U] ^= 0x04U;
        auto changedIndex = last;
        changedIndex[22U] ^= 0x02U;
        if (ingest(fragments, rx, changedMore, 101U, scratch, msdu) !=
                DataPathResult::UnverifiedDecryption ||
            ingest(fragments, rx, changedIndex, 102U, scratch, msdu) !=
                DataPathResult::UnverifiedDecryption ||
            rx.receiveFloor() != 1U || !fragments.pending ||
            ingest(fragments, rx, last, 103U, scratch, msdu) !=
                DataPathResult::Ok ||
            !validMsdu(msdu) || rx.receiveFloor() != 2U)
        {
            return __LINE__;
        }

        // A cryptographically valid late final fragment still cannot revive
        // a stream whose monotonic reassembly deadline has passed.
        CcmpSession lateTx {};
        CcmpSession lateRx {};
        if (lateTx.install(kKey.data(), kAp.data(), 0U, kEpoch, 0U, 0U) !=
                CcmpResult::Ok ||
            lateRx.install(kKey.data(), kAp.data(), 0U, kEpoch, 0U, 0U) !=
                CcmpResult::Ok)
        {
            return __LINE__;
        }
        const auto lateFirst =
            encrypt(lateTx, fragment(input, 0U, 9U, 0U, true));
        const auto lateLast =
            encrypt(lateTx, fragment(input, 9U, 10U, 1U, false));
        if (ingest(fragments, lateRx, lateFirst, 200U, scratch, msdu) !=
                DataPathResult::PendingFragments ||
            ingest(fragments, lateRx, lateLast, 701U, scratch, msdu) !=
                DataPathResult::MalformedFrame ||
            msdu.payload != nullptr || fragments.pending)
        {
            return __LINE__;
        }
        return 0;
    }

    // NOLINTEND(*avoid-magic-numbers,readability-magic-numbers)
} // namespace

int main()
{
    const int plain = authenticatedFragments();
    if (plain != 0)
    {
        return plain % 251 + 1;
    }
    const int groupZero = groupZeroUnfragmented();
    if (groupZero != 0)
    {
        return groupZero % 251 + 1;
    }
    const int group = groupKeyIsolation();
    if (group != 0)
    {
        return group % 251 + 1;
    }
    const int trust = invalidTrustRevokesStream();
    if (trust != 0)
    {
        return trust % 251 + 1;
    }
    const int qos = qosAndExpiry();
    return qos != 0 ? qos % 251 + 1 : 0;
}
