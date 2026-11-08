// SPDX-License-Identifier: AGPL-3.0-only
#include "Frames.hpp"

#include <cstddef>
#include <cstdint>

namespace simpleath
{
    namespace ieee80211
    {
        static uint16_t read16(const uint8_t *p)
        {
            return static_cast<uint16_t>(p[0]) |
                   static_cast<uint16_t>(static_cast<uint16_t>(p[1]) << 8u);
        }

        static uint64_t read64(const uint8_t *p)
        {
            uint64_t result = 0;
            for (size_t i = 0; i < 8; ++i)
                result |= static_cast<uint64_t>(p[i]) << (8u * i);
            return result;
        }

        static void write16(uint8_t *p, uint16_t value)
        {
            p[0] = static_cast<uint8_t>(value);
            p[1] = static_cast<uint8_t>(value >> 8u);
        }

        static void copy_bytes(uint8_t *dest, const uint8_t *source,
                               size_t size)
        {
            for (size_t i = 0; i < size; ++i)
                dest[i] = source[i];
        }

        static Mac address(const uint8_t *p)
        {
            Mac out {};
            copy_bytes(out.bytes, p, 6);
            return out;
        }

        static bool suite(const uint8_t *p, uint8_t id)
        {
            return p[0] == 0x00 && p[1] == 0x0f && p[2] == 0xac && p[3] == id;
        }

        // A serializer must not clear or overwrite the caller's borrowed
        // identity, SSID, network snapshot, or byte-count reference.
        // Subtraction avoids overflow when a caller supplies a large capacity.
        static bool overlaps(const void *firstBuffer, size_t firstBytes,
                             const void *secondBuffer, size_t secondBytes)
        {
            if (!firstBuffer || !secondBuffer || !firstBytes || !secondBytes)
                return false;
            const auto first = reinterpret_cast<uintptr_t>(firstBuffer);
            const auto second = reinterpret_cast<uintptr_t>(secondBuffer);
            return first <= second ? second - first < firstBytes
                                   : first - second < secondBytes;
        }

        static bool aliasesSerializedInput(const uint8_t *output,
                                           size_t capacity, size_t &written,
                                           const void *input, size_t inputBytes)
        {
            return overlaps(output, capacity, &written, sizeof(written)) ||
                   overlaps(output, capacity, input, inputBytes) ||
                   overlaps(&written, sizeof(written), input, inputBytes);
        }

        static bool all_zero(const Mac &mac)
        {
            uint8_t aggregate = 0;
            for (uint8_t byte : mac.bytes)
                aggregate |= byte;
            return aggregate == 0;
        }

        static const uint8_t K_BROADCAST[6] = {0xff, 0xff, 0xff,
                                               0xff, 0xff, 0xff};
        static const uint8_t K_RATES[8] = {0x82, 0x84, 0x8b, 0x96,
                                           0x0c, 0x12, 0x18, 0x24};
        static const uint8_t K_EXTENDED_RATES[4] = {0x30, 0x48, 0x60, 0x6c};

        // Offer only local legacy PHY rates also advertised by the selected
        // AP. Preserve the AP's basic-rate markers. A basic rate unknown to
        // the AR9565 cannot be negotiated, even when optional rates overlap.
        // The probe request may advertise the full local set independently.
        static bool selectAssociationRates(const Beacon &network,
                                           uint8_t (&selected)[12],
                                           size_t &selectedCount)
        {
            selectedCount = 0;
            if (network.rateCount == 0 ||
                network.rateCount > sizeof(network.rates))
                return false;
            for (size_t i = 0; i < network.rateCount; ++i)
            {
                const uint8_t rate = network.rates[i];
                const uint8_t phyRate = rate & 0x7fu;
                if (phyRate == 0)
                    return false;
                bool available = false;
                for (uint8_t known : K_RATES)
                    available |= (known & 0x7fu) == phyRate;
                for (uint8_t known : K_EXTENDED_RATES)
                    available |= (known & 0x7fu) == phyRate;
                if (!available)
                {
                    if ((rate & 0x80u) != 0)
                        return false;
                    continue;
                }
                bool duplicate = false;
                for (size_t j = 0; j < selectedCount; ++j)
                {
                    if ((selected[j] & 0x7fu) == phyRate)
                    {
                        // A later duplicate marked basic must not lose that
                        // mandatory bit when we collapse duplicate PHY rates.
                        selected[j] |= rate & 0x80u;
                        duplicate = true;
                        break;
                    }
                }
                if (!duplicate)
                    selected[selectedCount++] = rate;
            }
            return selectedCount != 0;
        }

        static size_t associationRateIeBytes(size_t selectedCount)
        {
            // Two bytes for Supported Rates, plus Extended Supported Rates
            // only when more than eight local/AP rates are negotiated.
            return 2u + selectedCount + (selectedCount > 8 ? 2u : 0u);
        }

        size_t associationRequestLength(const Beacon &network)
        {
            uint8_t selected[12] {};
            size_t selectedCount = 0;
            if (network.ssidLength == 0 ||
                network.ssidLength > sizeof(network.ssid) ||
                !selectAssociationRates(network, selected, selectedCount))
                return 0;
            return 28u + 2u + network.ssidLength +
                   associationRateIeBytes(selectedCount) +
                   (network.rsn.security == Security::Wpa2Personal ? 22u : 0u);
        }

        bool associationRateSupported(const Beacon &network, uint8_t rateCode)
        {
            uint8_t selected[12] {};
            size_t selectedCount = 0;
            if ((rateCode & 0x7fu) == 0 ||
                !selectAssociationRates(network, selected, selectedCount))
                return false;
            for (size_t i = 0; i < selectedCount; ++i)
                if ((selected[i] & 0x7fu) == (rateCode & 0x7fu))
                    return true;
            return false;
        }

        bool sameMac(const Mac &left, const Mac &right)
        {
            uint8_t difference = 0;
            for (size_t index = 0; index < 6; ++index)
                difference |= static_cast<uint8_t>(left.bytes[index] ^
                                                   right.bytes[index]);
            return difference == 0;
        }

        bool validStationMac(const Mac &mac)
        {
            return !all_zero(mac) && (mac.bytes[0] & 1u) == 0;
        }

        Result parseFrame(const uint8_t *bytes, size_t length, Frame &out)
        {
            // Never overwrite a borrowed RX frame through the result object.
            // Revoke a previously accepted header on any ordinary rejection.
            if (overlaps(&out, sizeof(out), bytes, length))
                return Result::OverlappingBuffers;
            out = {};
            if (!bytes)
                return Result::NullBuffer;
            if (length < 2)
                return Result::Truncated;
            const uint16_t control = read16(bytes);
            if ((control & 0x3u) != 0)
                return Result::UnsupportedFrame;

            const FrameType type =
                static_cast<FrameType>((control >> 2u) & 0x3u);
            const uint8_t subtype =
                static_cast<uint8_t>((control >> 4u) & 0xfu);
            const bool toDs = (control & 0x0100u) != 0;
            const bool fromDs = (control & 0x0200u) != 0;
            const bool ordered = (control & 0x8000u) != 0;
            if (type == FrameType::Control || type == FrameType::Extension)
                return Result::UnsupportedFrame;
            if (type == FrameType::Management &&
                (toDs || fromDs || ordered || (control & 0x0400u) != 0))
                return Result::UnsupportedFrame;

            size_t headerLength = 24;
            if (type == FrameType::Data)
            {
                if (toDs && fromDs)
                    headerLength += 6;
                if ((subtype & 0x8u) != 0)
                {
                    headerLength += 2; // QoS control.
                    if (ordered)
                        headerLength += 4; // HT control.
                }
            }
            if (length < headerLength)
                return Result::Truncated;
            // Management reassembly is not implemented: neither an initial
            // More Fragments frame nor a later nonzero fragment can be
            // interpreted as a complete beacon or handshake response.
            if (type == FrameType::Management &&
                (read16(bytes + 22) & 0x000fu) != 0)
                return Result::UnsupportedFrame;
            Frame parsed {};
            parsed.type = type;
            parsed.subtype = subtype;
            parsed.protectedFrame = (control & 0x4000u) != 0;
            parsed.moreFragments = (control & 0x0400u) != 0;
            parsed.toDs = toDs;
            parsed.fromDs = fromDs;
            const uint16_t sequenceControl = read16(bytes + 22);
            parsed.sequence = sequenceControl >> 4u;
            parsed.fragment = static_cast<uint8_t>(sequenceControl & 0xfu);
            parsed.headerLength = headerLength;
            parsed.destination = address(bytes + 4);
            parsed.source = address(bytes + 10);
            parsed.bssid = address(bytes + 16);
            if (type == FrameType::Data)
            {
                if (fromDs && !toDs)
                {
                    parsed.destination = address(bytes + 4);
                    parsed.bssid = address(bytes + 10);
                    parsed.source = address(bytes + 16);
                }
                else if (toDs && !fromDs)
                {
                    parsed.bssid = address(bytes + 4);
                    parsed.source = address(bytes + 10);
                    parsed.destination = address(bytes + 16);
                }
                else if (toDs && fromDs)
                {
                    parsed.destination = address(bytes + 16);
                    parsed.source = address(bytes + 24);
                    parsed.bssid =
                        {}; // WDS has no BSSID in standard three addresses.
                }
            }
            out = parsed;
            return Result::Ok;
        }

        Elements::Elements(const uint8_t *data, size_t length)
            : data_(data), length_(length), offset_(0)
        {
        }

        CursorStatus Elements::next(Element &out)
        {
            // Reject forged aliases before clearing a previously borrowed
            // element. An output inside the cursor or RX frame would corrupt
            // parser state or the bytes still needed by a later iteration.
            if (overlaps(&out, sizeof(out), this, sizeof(*this)) ||
                overlaps(&out, sizeof(out), data_, length_))
                return CursorStatus::Truncated;
            // End and malformed elements revoke pointers to earlier RX bytes.
            // Never expose a previously accepted element after failed advance.
            out = {};
            if (offset_ == length_)
                return CursorStatus::End;
            if (!data_ || length_ - offset_ < 2)
                return CursorStatus::Truncated;
            const uint8_t id = data_[offset_];
            const uint8_t size = data_[offset_ + 1];
            if (static_cast<size_t>(size) > length_ - offset_ - 2)
                return CursorStatus::Truncated;
            out = {id, data_ + offset_ + 2, size};
            offset_ += static_cast<size_t>(size) + 2;
            return CursorStatus::Element;
        }

        Result parseRsn(const uint8_t *data, size_t length, Rsn &out)
        {
            // Preserve borrowed input on detectable aliases, but revoke a
            // previous security verdict on every ordinary parse failure.
            // A caller must never reuse WPA2 authorization after bad RSNE.
            if (overlaps(&out, sizeof(out), data, length))
                return Result::OverlappingBuffers;
            out = {};
            out.security = Security::UnsupportedRsn;
            if (!data)
                return Result::NullBuffer;
            // RSN version(2), group suite(4), pairwise count(2), suites,
            // AKM count(2), suites, optional RSN capabilities(2).
            if (length < 2 + 4 + 2 + 4 + 2 + 4)
                return Result::InvalidSecurity;
            size_t offset = 0;
            if (read16(data) != 1)
                return Result::InvalidSecurity;
            offset += 2;
            const bool groupCcmp = suite(data + offset, 4);
            offset += 4;
            const uint16_t pairwiseCount = read16(data + offset);
            offset += 2;
            if (pairwiseCount == 0 || pairwiseCount > 32 ||
                static_cast<size_t>(pairwiseCount) * 4 > length - offset)
                return Result::InvalidSecurity;
            Rsn parsed {};
            parsed.present = true;
            parsed.groupCcmp = groupCcmp;
            for (uint16_t n = 0; n < pairwiseCount; ++n, offset += 4)
            {
                parsed.pairwiseCcmp |= suite(data + offset, 4);
                parsed.pairwiseTkip |= suite(data + offset, 2);
            }
            if (length - offset < 2)
                return Result::InvalidSecurity;
            const uint16_t akmCount = read16(data + offset);
            offset += 2;
            if (akmCount == 0 || akmCount > 32 ||
                static_cast<size_t>(akmCount) * 4 > length - offset)
                return Result::InvalidSecurity;
            for (uint16_t n = 0; n < akmCount; ++n, offset += 4)
            {
                parsed.akmEnterprise |= suite(data + offset, 1);
                parsed.akmPsk |= suite(data + offset, 2);
                parsed.akmSae |= suite(data + offset, 8);
            }
            if (length - offset == 1)
                return Result::InvalidSecurity;
            if (length - offset >= 2)
            {
                const uint16_t capabilities = read16(data + offset);
                parsed.pmfRequired = (capabilities & 0x0040u) != 0;
                parsed.pmfCapable = (capabilities & 0x0080u) != 0;
                if (parsed.pmfRequired && !parsed.pmfCapable)
                    return Result::InvalidSecurity;
                offset += 2;
            }
            // Optional PMKID count and PMKIDs, then optional group management
            // suite.
            if (length - offset != 0)
            {
                if (length - offset < 2)
                    return Result::InvalidSecurity;
                const uint16_t pmkidCount = read16(data + offset);
                offset += 2;
                if (static_cast<size_t>(pmkidCount) > (length - offset) / 16)
                    return Result::InvalidSecurity;
                offset += static_cast<size_t>(pmkidCount) * 16;
                if (length - offset == 4)
                    offset += 4;
                if (offset != length)
                    return Result::InvalidSecurity;
            }
            parsed.valid = true;
            parsed.security = Security::UnsupportedRsn;
            // The supported WPA2-PSK station requires CCMP for both group
            // and pairwise traffic. Do not advertise a mixed-mode or unknown
            // group cipher as joinable WPA2-Personal during scanning.
            if (parsed.groupCcmp && parsed.pairwiseCcmp && parsed.akmPsk &&
                !parsed.pmfRequired)
                parsed.security = Security::Wpa2Personal;
            else if (parsed.pairwiseCcmp && parsed.akmEnterprise)
                parsed.security = Security::Wpa2Enterprise;
            else if (parsed.pairwiseCcmp && parsed.akmSae && parsed.pmfCapable)
                parsed.security = Security::Wpa3Personal;
            out = parsed;
            return Result::Ok;
        }

        Result parseBeacon(const uint8_t *frame, size_t length, Beacon &out)
        {
            // Refuse aliases before touching the borrowed frame, and never
            // expose stale BSSID, SSID or WPA2 policy after a rejected beacon.
            if (overlaps(&out, sizeof(out), frame, length))
                return Result::OverlappingBuffers;
            out = {};
            out.rsn.security = Security::UnsupportedRsn;
            Frame header {};
            Result result = parseFrame(frame, length, header);
            if (result != Result::Ok)
                return result;
            if (header.type != FrameType::Management ||
                (header.subtype != 8 && header.subtype != 5))
                return Result::UnsupportedFrame;
            // Only a directly transmitted infrastructure BSS is supported;
            // nontransmitted/multiple-BSSID profiles need separate parsing.
            if (header.protectedFrame || !validStationMac(header.source) ||
                !sameMac(header.source, header.bssid))
                return Result::InvalidFrame;
            // IEEE 802.11 Beacons are broadcast advertisements. A directed
            // Probe Response can be unicast, but a unicast/multicast Beacon
            // must not enter the scan cache as a legitimate BSS discovery.
            if (header.subtype == 8)
            {
                for (const uint8_t octet : header.destination.bytes)
                    if (octet != 0xffu)
                        return Result::InvalidFrame;
            }
            if (length - header.headerLength < 12)
                return Result::Truncated;
            const uint8_t *fixed = frame + header.headerLength;
            Beacon parsed {};
            parsed.bssid = header.bssid;
            parsed.timestamp = read64(fixed);
            parsed.intervalTu = read16(fixed + 8);
            parsed.capabilities = read16(fixed + 10);
            // ESS and IBSS advertise different BSS types. Accepting both
            // as infrastructure can poison scan selection with a forged BSS.
            if ((parsed.capabilities & 0x0003u) == 0x0003u)
                return Result::InvalidFrame;
            parsed.infrastructure = (parsed.capabilities & 1u) != 0;
            parsed.hiddenSsid = true;
            parsed.rsn.security = (parsed.capabilities & 0x10u) != 0
                                      ? Security::LegacyProtected
                                      : Security::Open;

            Elements cursor(fixed + 12, length - header.headerLength - 12);
            Element element {};
            bool seenSsid = false, seenRsn = false, seenDs = false;
            bool seenRates = false, seenExtendedRates = false;
            bool seenHtCapabilities = false, seenHtOperation = false;
            uint8_t dsChannel = 0, htPrimaryChannel = 0;
            for (;;)
            {
                const CursorStatus next = cursor.next(element);
                if (next == CursorStatus::End)
                    break;
                if (next == CursorStatus::Truncated)
                    return Result::InvalidElement;
                if (element.id == 0)
                {
                    if (seenSsid || element.length > 32)
                        return Result::InvalidElement;
                    seenSsid = true;
                    parsed.ssidLength = element.length;
                    // Some APs hide a name with an all-zero, fixed-length
                    // SSID IE instead of an empty IE. Only a nonzero octet
                    // makes the advertised name visible.
                    parsed.hiddenSsid = true;
                    for (size_t i = 0; i < element.length; ++i)
                    {
                        parsed.ssid[i] = element.data[i];
                        if (element.data[i] != 0)
                            parsed.hiddenSsid = false;
                    }
                }
                else if (element.id == 1 || element.id == 50)
                {
                    // The basic-rate flag (MSB) must be carried to the macOS
                    // network stack, not interpreted as part of the rate
                    // number.
                    const bool base = element.id == 1;
                    if ((base && seenRates) || (!base && seenExtendedRates) ||
                        element.length == 0 || (base && element.length > 8) ||
                        static_cast<size_t>(parsed.rateCount) + element.length >
                            sizeof(parsed.rates))
                        return Result::InvalidElement;
                    for (size_t i = 0; i < element.length; ++i)
                        if ((element.data[i] & 0x7fu) == 0)
                            return Result::InvalidElement;
                    if (base)
                        seenRates = true;
                    else
                        seenExtendedRates = true;
                    for (size_t i = 0; i < element.length; ++i)
                        parsed.rates[parsed.rateCount++] = element.data[i];
                }
                else if (element.id == 3)
                {
                    if (seenDs || element.length != 1)
                        return Result::InvalidElement;
                    seenDs = true;
                    dsChannel = element.data[0];
                    if (dsChannel == 0 || dsChannel > 14)
                        return Result::InvalidElement;
                    parsed.channel = dsChannel;
                }
                else if (element.id == 45)
                {
                    if (seenHtCapabilities || element.length != 26)
                        return Result::InvalidElement;
                    seenHtCapabilities = true;
                    parsed.htSupported = true;
                    const uint16_t htCapabilities = read16(element.data);
                    parsed.ht40Allowed = (htCapabilities & 0x2u) != 0;
                }
                else if (element.id == 48)
                {
                    if (seenRsn || (parsed.capabilities & 0x10u) == 0)
                        return Result::InvalidSecurity;
                    seenRsn = true;
                    result = parseRsn(element.data, element.length, parsed.rsn);
                    if (result != Result::Ok)
                        return result;
                    // Keep the exact validated IE byte-for-byte for native scan
                    // reporting. This is received data, not a trusted
                    // association IE.
                    parsed.rsnIe[0] = element.id;
                    parsed.rsnIe[1] = element.length;
                    for (size_t i = 0; i < element.length; ++i)
                        parsed.rsnIe[i + 2] = element.data[i];
                    parsed.rsnIeLength =
                        static_cast<uint16_t>(element.length + 2u);
                }
                else if (element.id == 61)
                {
                    // HT Operation must be complete and its advertised
                    // primary channel must agree with the DS parameter set,
                    // regardless of the order of the two elements.
                    if (seenHtOperation || element.length != 22)
                        return Result::InvalidElement;
                    seenHtOperation = true;
                    htPrimaryChannel = element.data[0];
                    if (htPrimaryChannel == 0 || htPrimaryChannel > 14)
                        return Result::InvalidElement;
                    if (!seenDs)
                        parsed.channel = htPrimaryChannel;
                }
            }
            if (!seenSsid || !seenRates ||
                (seenDs && seenHtOperation && dsChannel != htPrimaryChannel))
                return Result::InvalidElement;
            out = parsed;
            return Result::Ok;
        }

        Result makeProbeRequest(const Mac &station, const uint8_t *ssid,
                                size_t ssidLength, uint16_t sequence,
                                uint8_t *output, size_t capacity,
                                size_t &written)
        {
            if (aliasesSerializedInput(output, capacity, written, &station,
                                       sizeof(station)) ||
                aliasesSerializedInput(output, capacity, written, ssid,
                                       ssidLength))
                return Result::OverlappingBuffers;
            if (!output)
            {
                written = 0;
                return Result::NullBuffer;
            }
            written = 0;
            if (!validStationMac(station))
                return Result::InvalidAddress;
            if (ssidLength > 32 || (ssidLength && !ssid))
                return Result::InvalidSsid;
            const size_t needed = 24 + 2 + ssidLength + 2 + 8 + 2 + 4;
            if (capacity < needed)
                return Result::BufferTooSmall;
            for (size_t i = 0; i < needed; ++i)
                output[i] = 0;
            write16(output, 0x0040u); // Management: probe request.
            copy_bytes(output + 4, K_BROADCAST, 6);
            copy_bytes(output + 10, station.bytes, 6);
            copy_bytes(output + 16, K_BROADCAST, 6);
            write16(output + 22,
                    static_cast<uint16_t>((sequence & 0xfffu) << 4u));
            size_t offset = 24;
            output[offset++] = 0;
            output[offset++] = static_cast<uint8_t>(ssidLength);
            if (ssidLength)
                copy_bytes(output + offset, ssid, ssidLength);
            offset += ssidLength;
            output[offset++] = 1;
            output[offset++] = 8;
            copy_bytes(output + offset, K_RATES, 8);
            offset += 8;
            output[offset++] = 50;
            output[offset++] = 4;
            copy_bytes(output + offset, K_EXTENDED_RATES, 4);
            offset += 4;
            written = offset;
            return Result::Ok;
        }

        Result makeOpenAuthenticationRequest(const Mac &station,
                                             const Mac &bssid,
                                             uint16_t sequence, uint8_t *output,
                                             size_t capacity, size_t &written)
        {
            if (aliasesSerializedInput(output, capacity, written, &station,
                                       sizeof(station)) ||
                aliasesSerializedInput(output, capacity, written, &bssid,
                                       sizeof(bssid)))
                return Result::OverlappingBuffers;
            if (!output)
            {
                written = 0;
                return Result::NullBuffer;
            }
            written = 0;
            // These public serializers do not require Station::select.
            // An infrastructure station cannot authenticate to itself.
            if (!validStationMac(station) || !validStationMac(bssid) ||
                sameMac(station, bssid))
                return Result::InvalidAddress;
            constexpr size_t needed =
                24 + 6; // Fixed auth algorithm/sequence/status.
            if (capacity < needed)
                return Result::BufferTooSmall;
            for (size_t i = 0; i < needed; ++i)
                output[i] = 0;
            write16(output, 0x00b0u); // Management: authentication.
            copy_bytes(output + 4, bssid.bytes, 6);
            copy_bytes(output + 10, station.bytes, 6);
            copy_bytes(output + 16, bssid.bytes, 6);
            write16(output + 22,
                    static_cast<uint16_t>((sequence & 0xfffu) << 4u));
            write16(output + 24, 0); // Open-system authentication algorithm.
            write16(output + 26, 1); // Transaction sequence 1.
            write16(output + 28, 0);
            written = needed;
            return Result::Ok;
        }

        Result makeAssociationRequest(const Mac &station, const Beacon &network,
                                      uint16_t sequence, uint8_t *output,
                                      size_t capacity, size_t &written)
        {
            if (aliasesSerializedInput(output, capacity, written, &station,
                                       sizeof(station)) ||
                aliasesSerializedInput(output, capacity, written, &network,
                                       sizeof(network)))
                return Result::OverlappingBuffers;
            if (!output)
            {
                written = 0;
                return Result::NullBuffer;
            }
            written = 0;
            // Reject a forged station identity matching the destination AP
            // before creating a management frame on the caller's behalf.
            if (!validStationMac(station) || !validStationMac(network.bssid) ||
                sameMac(station, network.bssid))
                return Result::InvalidAddress;
            // Public callers can manufacture Beacon metadata without parsing
            // it. The BSS must advertise ESS, not IBSS or contradictory modes.
            if ((network.capabilities & 0x0003u) != 0x0001u)
                return Result::InvalidFrame;
            if (network.ssidLength == 0 || network.ssidLength > 32 ||
                !network.infrastructure || network.hiddenSsid)
                return Result::InvalidSsid;
            // An all-zero fixed-length SSID is also hidden. Even a forged
            // Beacon with its hidden flag cleared must not cause a silent
            // association request for an unknown network name.
            bool hasVisibleByte = false;
            for (size_t i = 0; i < network.ssidLength; ++i)
                hasVisibleByte |= network.ssid[i] != 0;
            if (!hasVisibleByte)
                return Result::InvalidSsid;

            const bool secure = network.rsn.security == Security::Wpa2Personal;
            if (network.rsn.security != Security::Open && !secure)
                return Result::InvalidSecurity;
            // Public callers need not have used parseBeacon/Station::select.
            // Do not silently downgrade a privacy BSS to Open, or advertise
            // WPA2 based on forged suite flags rather than a validated RSNE.
            if (!secure && ((network.capabilities & 0x10u) != 0 ||
                            network.rsn.present || network.rsnIeLength != 0))
                return Result::InvalidSecurity;
            if (secure)
            {
                if ((network.capabilities & 0x10u) == 0 ||
                    !network.rsn.present || !network.rsn.valid ||
                    !network.rsn.pairwiseCcmp || !network.rsn.groupCcmp ||
                    !network.rsn.akmPsk || network.rsn.pmfRequired ||
                    network.rsnIeLength < 20 ||
                    network.rsnIeLength > sizeof(network.rsnIe) ||
                    network.rsnIe[0] != 48 ||
                    static_cast<size_t>(network.rsnIe[1]) + 2 !=
                        network.rsnIeLength)
                    return Result::InvalidSecurity;
                Rsn validated {};
                if (parseRsn(network.rsnIe + 2, network.rsnIeLength - 2,
                             validated) != Result::Ok ||
                    validated.security != Security::Wpa2Personal ||
                    validated.pmfRequired || !validated.groupCcmp ||
                    !validated.pairwiseCcmp || !validated.akmPsk)
                    return Result::InvalidSecurity;
            }
            uint8_t selectedRates[12] {};
            size_t selectedCount = 0;
            if (!selectAssociationRates(network, selectedRates, selectedCount))
                return Result::InvalidElement;
            const size_t needed = 28u + 2u + network.ssidLength +
                                  associationRateIeBytes(selectedCount) +
                                  (secure ? 22u : 0u);
            if (capacity < needed)
                return Result::BufferTooSmall;
            for (size_t i = 0; i < needed; ++i)
                output[i] = 0;
            write16(output, 0x0000u); // Management: association request.
            copy_bytes(output + 4, network.bssid.bytes, 6);
            copy_bytes(output + 10, station.bytes, 6);
            copy_bytes(output + 16, network.bssid.bytes, 6);
            write16(output + 22,
                    static_cast<uint16_t>((sequence & 0xfffu) << 4u));
            write16(output + 24,
                    static_cast<uint16_t>(1u | (secure ? 0x10u : 0u)));
            write16(output + 26, 10); // Listen interval in beacon units.
            size_t offset = 28;
            output[offset++] = 0;
            output[offset++] = network.ssidLength;
            copy_bytes(output + offset, network.ssid, network.ssidLength);
            offset += network.ssidLength;
            const size_t baseCount = selectedCount > 8 ? 8u : selectedCount;
            output[offset++] = 1;
            output[offset++] = static_cast<uint8_t>(baseCount);
            copy_bytes(output + offset, selectedRates, baseCount);
            offset += baseCount;
            if (selectedCount > baseCount)
            {
                output[offset++] = 50;
                output[offset++] =
                    static_cast<uint8_t>(selectedCount - baseCount);
                copy_bytes(output + offset, selectedRates + baseCount,
                           selectedCount - baseCount);
                offset += selectedCount - baseCount;
            }
            if (secure)
            {
                // Version 1, CCMP group/pairwise, PSK AKM, no negotiated PMF.
                constexpr uint8_t rsn[] = {
                    0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f,
                    0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x00, 0x00};
                output[offset++] = 48;
                output[offset++] = sizeof(rsn);
                copy_bytes(output + offset, rsn, sizeof(rsn));
                offset += sizeof(rsn);
            }
            written = offset;
            return Result::Ok;
        }

        Result parseAuthenticationResponse(const uint8_t *bytes, size_t length,
                                           const Mac &station, const Mac &bssid,
                                           uint16_t &statusCode)
        {
            if (overlaps(&statusCode, sizeof(statusCode), bytes, length) ||
                overlaps(&statusCode, sizeof(statusCode), &station,
                         sizeof(station)) ||
                overlaps(&statusCode, sizeof(statusCode), &bssid,
                         sizeof(bssid)))
                return Result::OverlappingBuffers;
            // Caller-provided association identities are not trusted merely
            // because the incoming MAC header matches their bytes.
            if (!validStationMac(station) || !validStationMac(bssid) ||
                sameMac(station, bssid))
                return Result::InvalidAddress;
            Frame parsed {};
            Result result = parseFrame(bytes, length, parsed);
            if (result != Result::Ok)
                return result;
            if (parsed.type != FrameType::Management || parsed.subtype != 11 ||
                !sameMac(parsed.source, bssid) ||
                !sameMac(parsed.bssid, bssid) ||
                !sameMac(parsed.destination, station) || parsed.protectedFrame)
                return Result::InvalidFrame;
            if (length - parsed.headerLength < 6)
                return Result::Truncated;
            const uint8_t *body = bytes + parsed.headerLength;
            if (read16(body) != 0 || read16(body + 2) != 2)
                return Result::UnsupportedFrame;
            statusCode = read16(body + 4);
            return Result::Ok;
        }

        Result parseAssociationResponse(const uint8_t *bytes, size_t length,
                                        const Mac &station, const Mac &bssid,
                                        uint16_t &statusCode,
                                        uint16_t &associationId)
        {
            if (overlaps(&statusCode, sizeof(statusCode), &associationId,
                         sizeof(associationId)) ||
                overlaps(&statusCode, sizeof(statusCode), bytes, length) ||
                overlaps(&associationId, sizeof(associationId), bytes,
                         length) ||
                overlaps(&statusCode, sizeof(statusCode), &station,
                         sizeof(station)) ||
                overlaps(&associationId, sizeof(associationId), &station,
                         sizeof(station)) ||
                overlaps(&statusCode, sizeof(statusCode), &bssid,
                         sizeof(bssid)) ||
                overlaps(&associationId, sizeof(associationId), &bssid,
                         sizeof(bssid)))
                return Result::OverlappingBuffers;
            // Caller-provided association identities are not trusted merely
            // because the incoming MAC header matches their bytes.
            if (!validStationMac(station) || !validStationMac(bssid) ||
                sameMac(station, bssid))
                return Result::InvalidAddress;
            Frame parsed {};
            Result result = parseFrame(bytes, length, parsed);
            if (result != Result::Ok)
                return result;
            if (parsed.type != FrameType::Management || parsed.subtype != 1 ||
                !sameMac(parsed.source, bssid) ||
                !sameMac(parsed.bssid, bssid) ||
                !sameMac(parsed.destination, station) || parsed.protectedFrame)
                return Result::InvalidFrame;
            if (length - parsed.headerLength < 6)
                return Result::Truncated;
            const uint8_t *body = bytes + parsed.headerLength;
            const uint16_t capabilities = read16(body);
            const uint16_t status = read16(body + 2);
            // An infrastructure station cannot accept a successful IBSS or
            // non-ESS response even when its AID and rate IEs look valid.
            if (status == 0 && ((capabilities & 0x0001u) == 0 ||
                                (capabilities & 0x0002u) != 0))
                return Result::InvalidFrame;
            const uint16_t rawAid = read16(body + 4);
            const uint16_t aid = static_cast<uint16_t>(rawAid & 0x3fffu);
            if (status == 0 &&
                ((rawAid & 0xc000u) != 0xc000u || aid == 0 || aid > 2007))
                return Result::InvalidFrame;

            // A successful Association Response carries a Supported Rates
            // element. Validate its complete IE list before treating the
            // status and AID as accepted; a six-byte fixed body alone is not
            // enough to establish usable negotiated BSS rates.
            Elements cursor(body + 6, length - parsed.headerLength - 6);
            Element element {};
            bool seenRates = false;
            bool seenExtendedRates = false;
            for (;;)
            {
                const CursorStatus next = cursor.next(element);
                if (next == CursorStatus::End)
                    break;
                if (next == CursorStatus::Truncated)
                    return Result::InvalidElement;
                if (element.id != 1 && element.id != 50)
                    continue;
                const bool base = element.id == 1;
                if ((base && seenRates) || (!base && seenExtendedRates) ||
                    element.length == 0 || (base && element.length > 8))
                    return Result::InvalidElement;
                for (size_t i = 0; i < element.length; ++i)
                    if ((element.data[i] & 0x7fu) == 0)
                        return Result::InvalidElement;
                if (base)
                    seenRates = true;
                else
                    seenExtendedRates = true;
            }
            if (status == 0 && !seenRates)
                return Result::InvalidElement;
            statusCode = status;
            associationId = status == 0 ? aid : 0;
            return Result::Ok;
        }

    } // namespace ieee80211
} // namespace simpleath
