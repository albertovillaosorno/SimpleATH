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
//   - Native driver contracts and implementation for frames.
// - Must-Not:
//   - Invent hardware readiness, weaken buffer bounds, or assume ABI
//     compatibility.
// - Allows:
//   - Inputs: validated register, protocol, platform, or device state from
//     callers.
//   - Outputs: bounded native transitions, messages, or explicit errors.
//   - Side effects: only the device and kernel operations owned by this module.
// - Split-When:
//   - A separate protocol stage needs independent validation and ownership.
// - Merge-When:
//   - The caller directly owns this narrow contract without reuse.
// - Summary:
//   - Native driver contracts and implementation for frames.
// - Description:
//   - Implements or verifies the Frames source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for frames.

#include "Frames.hpp"

#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    namespace ieee80211
    {
        static constexpr uint32_t kBitsPerByte = 8;

        // The callers establish each frame/IE capacity before dereferencing.
        // Byte-span addresses are computed without C++ out-of-range pointer
        // additions, including when checking adversarial frame lengths.
        template <typename Byte>
        static Byte *byteOffset(Byte *base, size_t offset)
        {
            static_assert(sizeof(base) == sizeof(uintptr_t),
                          "frame pointer and address widths must match");
            if (base == nullptr)
            {
                return nullptr;
            }
            uintptr_t address = 0;
            __builtin_memcpy(&address, static_cast<const void *>(&base),
                             sizeof(address));
            if (offset > UINTPTR_MAX - address)
            {
                return nullptr;
            }
            address += offset;
            Byte *result = nullptr;
            __builtin_memcpy(static_cast<void *>(&result), &address,
                             sizeof(result));
            return result;
        }

        static uintptr_t addressOf(const void *pointer)
        {
            static_assert(sizeof(pointer) == sizeof(uintptr_t),
                          "frame pointer and address widths must match");
            uintptr_t address = 0;
            __builtin_memcpy(&address, static_cast<const void *>(&pointer),
                             sizeof(pointer));
            return address;
        }

        template <typename T, size_t N>
        static T &elementAt(T (&array)[N], size_t index)
        {
            for (T &entry : array)
            {
                if (index == 0U)
                {
                    return entry;
                }
                --index;
            }
            __builtin_trap(); // Each caller validated the corresponding count.
        }

        // Bind fixed-size octet arrays by reference before handing a bounded
        // pointer to byte-span APIs; array-to-pointer decay is never implicit.
        template <typename Byte, size_t N>
        static Byte *arrayData(Byte (&bytes)[N])
        {
            return &bytes[0];
        }

        // IEEE 802.11 rate, regulatory and management bit contracts.
        static constexpr uint8_t kRateValueMask = 0x7fU;
        static constexpr uint8_t kBasicRateFlag = 0x80U;
        static constexpr uint16_t kPrivacyCapabilityBit = 0x10U;
        static constexpr uint16_t kMoreFragmentsBit = 0x0400U;
        static constexpr uint8_t kRsnOuiMiddleOctet = 0x0fU;
        static constexpr uint8_t kRsnOuiLastOctet = 0xacU;
        static constexpr uint8_t kCckOnlyChannel = 14U;
        static constexpr size_t kCckRateCount = 4;
        static constexpr size_t kTimestampBytes = 8;
        static constexpr size_t kLegacyRateCount = 8;
        static constexpr size_t kExtendedRateCount = 4;
        static constexpr size_t kMaximumLegacyMpduBytesIncludingFcs = 2346;
        // IEEE 802.11-2020 management header fields and IE identifiers.
        static constexpr size_t kManagementHeaderBytes = 24U;
        static constexpr size_t kMacDestinationOffset = 4U;
        static constexpr size_t kMacSourceOffset = 10U;
        static constexpr size_t kMacBssidOffset = 16U;
        static constexpr size_t kMacSequenceOffset = 22U;
        static constexpr size_t kWdsAddressOffset = 24U;
        static constexpr size_t kWdsExtraAddressBytes = kMacAddressBytes;
        static constexpr size_t kQosControlBytes = 2U;
        static constexpr size_t kHtControlBytes = 4U;
        static constexpr size_t kFixedBeaconBytes = 12U;
        static constexpr size_t kBeaconIntervalOffset = 8U;
        static constexpr size_t kBeaconCapabilitiesOffset = 10U;
        static constexpr size_t kResponseFixedBytes = 6U;
        static constexpr size_t kAuthSequenceOffset = 2U;
        static constexpr size_t kAuthStatusOffset = 4U;
        static constexpr size_t kSequenceControlShift = 4U;
        static constexpr uint16_t kSequenceNumberMask = 0x0fffU;
        static constexpr uint16_t kFragmentNumberMask = 0x000fU;
        static constexpr uint16_t kProtectedFrameBit = 0x4000U;
        static constexpr uint16_t kQosDataSubtypeBit = 0x8U;
        static constexpr uint8_t kBeaconSubtype = 8U;
        static constexpr uint8_t kProbeResponseSubtype = 5U;
        static constexpr uint8_t kAssocResponseSubtype = 1U;
        static constexpr uint8_t kAuthResponseSubtype = 11U;
        static constexpr uint8_t kBroadcastOctet = 0xffU;
        static constexpr uint8_t kSsidElementId = 0U;
        static constexpr uint8_t kSupportedRatesElementId = 1U;
        static constexpr uint8_t kDsParameterElementId = 3U;
        static constexpr uint8_t kHtCapabilitiesElementId = 45U;
        static constexpr uint8_t kRsnElementId = 48U;
        static constexpr uint8_t kExtendedRatesElementId = 50U;
        static constexpr uint8_t kHtOperationElementId = 61U;
        static constexpr uint8_t kVendorSpecificElementId = 221U;
        static constexpr uint8_t kHtCapabilitiesBytes = 26U;
        static constexpr uint8_t kHtOperationBytes = 22U;
        static constexpr uint8_t kFixedRsnIeBytes = 22U;
        static constexpr uint8_t kMinimumRsnIeBytes = 20U;
        static constexpr size_t kRsnIeHeaderBytes = 2U;
        static constexpr uint8_t kSaeSuiteId = 8U;
        static constexpr uint16_t kPmfRequiredBit = 0x0040U;
        static constexpr uint16_t kPmfCapableBit = 0x0080U;
        static constexpr size_t kMaximumSuiteCount = 32U;
        static constexpr size_t kPmkidBytes = 16U;
        static constexpr uint16_t kAssociationAidValidBits = 0xc000U;
        static constexpr uint16_t kAssociationAidMask = 0x3fffU;
        static constexpr uint16_t kAssociationAidMax = 2007U;
        static constexpr uint16_t kProbeRequestControl = 0x0040U;
        static constexpr uint16_t kAuthenticationControl = 0x00b0U;
        static constexpr uint16_t kDefaultListenIntervalTu = 10U;

        static uint16_t readLittle16(const uint8_t *bytes)
        {
            return static_cast<uint16_t>((*byteOffset(bytes, 0))) |
                   static_cast<uint16_t>(
                       static_cast<uint16_t>((*byteOffset(bytes, 1)))
                       << kBitsPerByte);
        }

        static uint64_t readLittle64(const uint8_t *bytes)
        {
            uint64_t result = 0;
            for (size_t i = 0; i < kTimestampBytes; ++i)
            {
                result |= static_cast<uint64_t>((*byteOffset(bytes, i)))
                          << (kBitsPerByte * i);
            }
            return result;
        }

        static void writeLittle16(uint8_t *bytes, uint16_t value)
        {
            (*byteOffset(bytes, 0)) = static_cast<uint8_t>(value);
            (*byteOffset(bytes, 1)) =
                static_cast<uint8_t>(value >> kBitsPerByte);
        }

        static void copyBytes(uint8_t *dest, const uint8_t *source, size_t size)
        {
            for (size_t i = 0; i < size; ++i)
            {
                (*byteOffset(dest, i)) = (*byteOffset(source, i));
            }
        }

        static Mac readMacAddress(const uint8_t *bytes)
        {
            Mac out {};
            copyBytes(arrayData(out.bytes), bytes, kMacAddressBytes);
            return out;
        }

        static bool matchesSuite(const uint8_t *bytes, uint8_t id)
        {
            return (*byteOffset(bytes, 0)) == 0x00 &&
                   (*byteOffset(bytes, 1)) == kRsnOuiMiddleOctet &&
                   (*byteOffset(bytes, 2)) == kRsnOuiLastOctet &&
                   (*byteOffset(bytes, 3)) == id;
        }

        // A serializer must not clear or overwrite the caller's borrowed
        // identity, SSID, network snapshot, or byte-count reference.
        // Subtraction avoids overflow when a caller supplies a large capacity.
        static bool overlaps(const void *firstBuffer, size_t firstBytes,
                             const void *secondBuffer, size_t secondBytes)
        {
            if (firstBuffer == nullptr || secondBuffer == nullptr ||
                firstBytes == 0 || secondBytes == 0)
            {
                return false;
            }
            const auto first = addressOf(firstBuffer);
            const auto second = addressOf(secondBuffer);
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

        static bool allZero(const Mac &mac)
        {
            uint8_t aggregate = 0;
            for (const uint8_t byte : mac.bytes)
            {
                aggregate |= byte;
            }
            return aggregate == 0;
        }

        static constexpr uint8_t kBroadcastAddress[kMacAddressBytes] = {
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        };
        static constexpr uint8_t kLegacyRates[kLegacyRateCount] = {
            0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24,
        };
        static constexpr uint8_t kExtendedRates[kExtendedRateCount] = {
            0x30,
            0x48,
            0x60,
            0x6c,
        };

        static constexpr size_t kMaxLocalRates =
            sizeof(kLegacyRates) + sizeof(kExtendedRates);

        static bool localPhyRateAvailable(const Beacon &network,
                                          uint8_t phyRate)
        {
            // Channel 14 cannot transmit OFDM or negotiated HT rates.
            const size_t baseRateCount = network.channel == kCckOnlyChannel
                                             ? kCckRateCount
                                             : kLegacyRateCount;
            for (size_t index = 0; index < baseRateCount; ++index)
            {
                if ((elementAt(kLegacyRates, index) & kRateValueMask) ==
                    phyRate)
                {
                    return true;
                }
            }
            if (network.channel != kCckOnlyChannel)
            {
                for (const uint8_t known : kExtendedRates)
                {
                    if ((known & kRateValueMask) == phyRate)
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        // Offer only local legacy PHY rates also advertised by the selected
        // AP. Preserve the AP's basic-rate markers. A basic rate unknown to
        // the AR9565 cannot be negotiated, even when optional rates overlap.
        // The probe request may advertise the full local set independently.
        static bool selectAssociationRates(const Beacon &network,
                                           uint8_t (&selected)[kMaxLocalRates],
                                           size_t &selectedCount)
        {
            selectedCount = 0;
            if (network.rateCount == 0 ||
                network.rateCount > sizeof(network.rates))
            {
                return false;
            }
            for (size_t i = 0; i < network.rateCount; ++i)
            {
                const uint8_t rate = elementAt(network.rates, i);
                const uint8_t phyRate = rate & kRateValueMask;
                if (phyRate == 0)
                {
                    return false;
                }
                // Japan's channel 14 is 802.11b/CCK-only. Do not let
                // the ordinary 2.4-GHz OFDM table make an otherwise
                // untransmittable BSS look joinable. An unsupported *basic*
                // rate must reject the BSS; optional rates can be omitted.
                const bool available = localPhyRateAvailable(network, phyRate);
                if (!available)
                {
                    if ((rate & kBasicRateFlag) != 0)
                    {
                        return false;
                    }
                    continue;
                }
                bool duplicate = false;
                for (size_t j = 0; j < selectedCount; ++j)
                {
                    if ((elementAt(selected, j) & kRateValueMask) == phyRate)
                    {
                        // A later duplicate marked basic must not lose that
                        // mandatory bit when we collapse duplicate PHY rates.
                        elementAt(selected, j) = static_cast<uint8_t>(
                            static_cast<uint32_t>(elementAt(selected, j)) |
                            (static_cast<uint32_t>(rate) & kBasicRateFlag));
                        duplicate = true;
                        break;
                    }
                }
                if (!duplicate)
                {
                    elementAt(selected, selectedCount++) = rate;
                }
            }
            return selectedCount != 0;
        }

        static size_t associationRateIeBytes(size_t selectedCount)
        {
            // Two bytes for Supported Rates, plus Extended Supported Rates
            // only when more than eight local/AP rates are negotiated.
            return 2U + selectedCount +
                   (selectedCount > kLegacyRateCount ? 2U : 0U);
        }

        // Public association APIs also accept caller-built Beacon values.
        // Do not size or serialize association TX to an AP without a usable
        // beacon cadence and an explicitly known 2.4-GHz primary channel.
        static bool validAssociationCadenceAndChannel(const Beacon &network)
        {
            return network.intervalTu != 0 && network.channel >= 1U &&
                   network.channel <= kCckOnlyChannel &&
                   // Even a forged public Beacon snapshot must not advertise
                   // HT on channel 14, where the PHY is legacy CCK only.
                   (network.channel != kCckOnlyChannel ||
                    (!network.htSupported && !network.ht40Allowed));
        }

        // Both public preflight sizing and serialization must use exactly the
        // same BSS admission checks. Otherwise a malformed source-built
        // Beacon can be reported as joinable even though no association
        // request can actually be sent for it.
        static Result validateAssociationBeacon(const Beacon &network)
        {
            if (!validStationMac(network.bssid))
            {
                return Result::InvalidAddress;
            }
            if (!validAssociationCadenceAndChannel(network) ||
                (network.capabilities & 0x0003U) != 0x0001U)
            {
                return Result::InvalidFrame;
            }
            if (network.ssidLength == 0 || network.ssidLength > kMaxSsidBytes ||
                !network.infrastructure || network.hiddenSsid)
            {
                return Result::InvalidSsid;
            }
            bool hasVisibleByte = false;
            for (size_t i = 0; i < network.ssidLength; ++i)
            {
                hasVisibleByte |=
                    (*byteOffset(arrayData(network.ssid), i)) != 0;
            }
            if (!hasVisibleByte)
            {
                return Result::InvalidSsid;
            }

            const bool secure = network.rsn.security == Security::Wpa2Personal;
            if (network.rsn.security != Security::Open && !secure)
            {
                return Result::InvalidSecurity;
            }
            if (!secure)
            {
                return ((network.capabilities & kPrivacyCapabilityBit) != 0 ||
                        network.rsn.present || network.rsnIeLength != 0)
                           ? Result::InvalidSecurity
                           : Result::Ok;
            }
            if ((network.capabilities & kPrivacyCapabilityBit) == 0 ||
                !network.rsn.present || !network.rsn.valid ||
                !network.rsn.pairwiseCcmp || !network.rsn.groupCcmp ||
                !network.rsn.akmPsk || network.rsn.pmfRequired ||
                network.rsnIeLength < kMinimumRsnIeBytes ||
                network.rsnIeLength > sizeof(network.rsnIe) ||
                network.rsnIe[0] != kRsnElementId ||
                static_cast<size_t>(network.rsnIe[1]) + 2 !=
                    network.rsnIeLength)
            {
                return Result::InvalidSecurity;
            }
            Rsn validated {};
            if (parseRsn(byteOffset(&network.rsnIe[0], 2U),
                         network.rsnIeLength - 2, validated) != Result::Ok ||
                validated.security != Security::Wpa2Personal ||
                validated.pmfRequired || !validated.groupCcmp ||
                !validated.pairwiseCcmp || !validated.akmPsk)
            {
                return Result::InvalidSecurity;
            }
            return Result::Ok;
        }

        size_t associationRequestLength(const Beacon &network)
        {
            uint8_t selected[kMaxLocalRates] {};
            size_t selectedCount = 0;
            if (validateAssociationBeacon(network) != Result::Ok ||
                !selectAssociationRates(network, selected, selectedCount))
            {
                return 0;
            }
            return kManagementHeaderBytes + kAuthStatusOffset +
                   kRsnIeHeaderBytes + network.ssidLength +
                   associationRateIeBytes(selectedCount) +
                   (network.rsn.security == Security::Wpa2Personal
                        ? kFixedRsnIeBytes
                        : 0U);
        }

        bool associationRateSupported(const Beacon &network, uint8_t rateCode)
        {
            uint8_t selected[kMaxLocalRates] {};
            size_t selectedCount = 0;
            if ((rateCode & kRateValueMask) == 0 ||
                !selectAssociationRates(network, selected, selectedCount))
            {
                return false;
            }
            for (size_t i = 0; i < selectedCount; ++i)
            {
                if ((elementAt(selected, i) & kRateValueMask) ==
                    (rateCode & kRateValueMask))
                {
                    return true;
                }
            }
            return false;
        }

        bool sameMac(const Mac &left, const Mac &right)
        {
            uint8_t difference = 0;
            for (size_t index = 0; index < kMacAddressBytes; ++index)
            {
                difference |= static_cast<uint8_t>(
                    (*byteOffset(arrayData(left.bytes), index)) ^
                    (*byteOffset(arrayData(right.bytes), index)));
            }
            return difference == 0;
        }

        bool validStationMac(const Mac &address)
        {
            return !allZero(address) &&
                   ((elementAt(address.bytes, 0U) & 1U) == 0U);
        }

        static void decodeFrameAddresses(const uint8_t *bytes, Frame &parsed)
        {
            parsed.destination =
                readMacAddress(byteOffset(bytes, kMacDestinationOffset));
            parsed.source = readMacAddress(byteOffset(bytes, kMacSourceOffset));
            parsed.bssid = readMacAddress(byteOffset(bytes, kMacBssidOffset));
            if (parsed.type == FrameType::Data)
            {
                if (parsed.fromDs && !parsed.toDs)
                {
                    parsed.destination = readMacAddress(
                        byteOffset(bytes, kMacDestinationOffset));
                    parsed.bssid =
                        readMacAddress(byteOffset(bytes, kMacSourceOffset));
                    parsed.source =
                        readMacAddress(byteOffset(bytes, kMacBssidOffset));
                }
                else if (parsed.toDs && !parsed.fromDs)
                {
                    parsed.bssid = readMacAddress(
                        byteOffset(bytes, kMacDestinationOffset));
                    parsed.source =
                        readMacAddress(byteOffset(bytes, kMacSourceOffset));
                    parsed.destination =
                        readMacAddress(byteOffset(bytes, kMacBssidOffset));
                }
                else if (parsed.toDs && parsed.fromDs)
                {
                    parsed.destination =
                        readMacAddress(byteOffset(bytes, kMacBssidOffset));
                    parsed.source =
                        readMacAddress(byteOffset(bytes, kWdsAddressOffset));
                    parsed.bssid =
                        {}; // WDS has no BSSID in standard three addresses.
                }
            }
        }

        Result parseFrame(const uint8_t *bytes, size_t length, Frame &out)
        {
            // Never overwrite a borrowed RX frame through the result object.
            // Revoke a previously accepted header on any ordinary rejection.
            if (overlaps(&out, sizeof(out), bytes, length))
            {
                return Result::OverlappingBuffers;
            }
            out = {};
            if (bytes == nullptr)
            {
                return Result::NullBuffer;
            }
            if (length < 2)
            {
                return Result::Truncated;
            }
            const uint16_t control = readLittle16(bytes);
            if ((control & 0x3U) != 0)
            {
                return Result::UnsupportedFrame;
            }

            const auto type = static_cast<FrameType>(
                (static_cast<uint32_t>(control) >> 2U) & 0x3U);
            const auto subtype = static_cast<uint8_t>(
                (static_cast<uint32_t>(control) >> 4U) & 0xfU);
            const bool toDs = (control & 0x0100U) != 0;
            const bool fromDs = (control & 0x0200U) != 0;
            const bool ordered = (control & 0x8000U) != 0;
            if (type == FrameType::Control || type == FrameType::Extension)
            {
                return Result::UnsupportedFrame;
            }
            if (type == FrameType::Management &&
                (toDs || fromDs || ordered ||
                 (control & kMoreFragmentsBit) != 0))
            {
                return Result::UnsupportedFrame;
            }
            // Management frames are never A-MPDU payloads. Reject an RX
            // length above the legacy on-air MPDU ceiling before IE walking.
            if (type == FrameType::Management &&
                length > kMaximumLegacyMpduBytesIncludingFcs)
            {
                return Result::InvalidFrame;
            }

            size_t headerLength = kManagementHeaderBytes;
            if (type == FrameType::Data)
            {
                if (toDs && fromDs)
                {
                    headerLength += kWdsExtraAddressBytes;
                }
                if ((subtype & kQosDataSubtypeBit) != 0)
                {
                    headerLength += kQosControlBytes; // QoS control.
                    if (ordered)
                    {
                        headerLength += kHtControlBytes; // HT control.
                    }
                }
            }
            if (length < headerLength)
            {
                return Result::Truncated;
            }
            // A caller must explicitly reassemble validated management
            // fragments before parsing. This standalone parser rejects a
            // partial header/body, regardless of fragment sequence.
            if (type == FrameType::Management &&
                (readLittle16(byteOffset(bytes, kMacSequenceOffset)) &
                 kFragmentNumberMask) != 0)
            {
                return Result::UnsupportedFrame;
            }
            Frame parsed {};
            parsed.type = type;
            parsed.subtype = subtype;
            parsed.protectedFrame = (control & kProtectedFrameBit) != 0;
            parsed.moreFragments = (control & kMoreFragmentsBit) != 0;
            parsed.toDs = toDs;
            parsed.fromDs = fromDs;
            const uint16_t sequenceControl =
                readLittle16(byteOffset(bytes, kMacSequenceOffset));
            parsed.sequence = sequenceControl >> kSequenceControlShift;
            parsed.fragment =
                static_cast<uint8_t>(sequenceControl & kFragmentNumberMask);
            parsed.headerLength = headerLength;
            decodeFrameAddresses(bytes, parsed);
            out = parsed;
            return Result::Ok;
        }

        Elements::Elements(const uint8_t *data, size_t length)
            : data_(data), length_(length)
        {
        }

        CursorStatus Elements::next(Element &out)
        {
            // Reject forged aliases before clearing a previously borrowed
            // element. An output inside the cursor or RX frame would corrupt
            // parser state or the bytes still needed by a later iteration.
            if (overlaps(&out, sizeof(out), this, sizeof(*this)) ||
                overlaps(&out, sizeof(out), data_, length_))
            {
                return CursorStatus::Truncated;
            }
            // End and malformed elements revoke pointers to earlier RX bytes.
            // Never expose a previously accepted element after failed advance.
            out = {};
            if (offset_ == length_)
            {
                return CursorStatus::End;
            }
            if ((data_ == nullptr) || length_ - offset_ < 2)
            {
                return CursorStatus::Truncated;
            }
            const uint8_t id = (*byteOffset(data_, offset_));
            const uint8_t size = (*byteOffset(data_, offset_ + 1U));
            if (static_cast<size_t>(size) > length_ - offset_ - 2)
            {
                return CursorStatus::Truncated;
            }
            out = {id, byteOffset(data_, offset_ + 2U), size};
            offset_ += static_cast<size_t>(size) + 2;
            return CursorStatus::Element;
        }

        static bool parseRsnOptionalTail(const uint8_t *data, size_t length,
                                         size_t offset, Rsn &parsed)
        {
            if (length - offset == 1)
            {
                return false;
            }
            if (length - offset >= 2)
            {
                const uint16_t capabilities =
                    readLittle16(byteOffset(data, offset));
                parsed.pmfRequired = (capabilities & kPmfRequiredBit) != 0;
                parsed.pmfCapable = (capabilities & kPmfCapableBit) != 0;
                if (parsed.pmfRequired && !parsed.pmfCapable)
                {
                    return false;
                }
                offset += 2;
            }
            // Optional PMKID count and PMKIDs, then optional group management
            // suite.
            if (length - offset != 0)
            {
                if (length - offset < 2)
                {
                    return false;
                }
                const uint16_t pmkidCount =
                    readLittle16(byteOffset(data, offset));
                offset += 2;
                if (static_cast<size_t>(pmkidCount) >
                    (length - offset) / kPmkidBytes)
                {
                    return false;
                }
                offset += static_cast<size_t>(pmkidCount) * kPmkidBytes;
                if (length - offset == 4)
                {
                    offset += 4;
                }
                if (offset != length)
                {
                    return false;
                }
            }
            return true;
        }

        Result parseRsn(const uint8_t *data, size_t length, Rsn &out)
        {
            // Preserve borrowed input on detectable aliases, but revoke a
            // previous security verdict on every ordinary parse failure.
            // A caller must never reuse WPA2 authorization after bad RSNE.
            if (overlaps(&out, sizeof(out), data, length))
            {
                return Result::OverlappingBuffers;
            }
            out = {};
            out.security = Security::UnsupportedRsn;
            if (data == nullptr)
            {
                return Result::NullBuffer;
            }
            // RSN version(2), group suite(4), pairwise count(2), suites,
            // AKM count(2), suites, optional RSN capabilities(2).
            if (length < 2 + 4 + 2 + 4 + 2 + 4)
            {
                return Result::InvalidSecurity;
            }
            size_t offset = 0;
            if (readLittle16(data) != 1)
            {
                return Result::InvalidSecurity;
            }
            offset += 2;
            const bool groupCcmp = matchesSuite(byteOffset(data, offset), 4);
            offset += 4;
            const uint16_t pairwiseCount =
                readLittle16(byteOffset(data, offset));
            offset += 2;
            if (pairwiseCount == 0 || pairwiseCount > kMaximumSuiteCount ||
                static_cast<size_t>(pairwiseCount) * 4 > length - offset)
            {
                return Result::InvalidSecurity;
            }
            Rsn parsed {};
            parsed.present = true;
            parsed.groupCcmp = groupCcmp;
            for (uint16_t n = 0; n < pairwiseCount; ++n, offset += 4)
            {
                parsed.pairwiseCcmp |=
                    matchesSuite(byteOffset(data, offset), 4);
                parsed.pairwiseTkip |=
                    matchesSuite(byteOffset(data, offset), 2);
            }
            if (length - offset < 2)
            {
                return Result::InvalidSecurity;
            }
            const uint16_t akmCount = readLittle16(byteOffset(data, offset));
            offset += 2;
            if (akmCount == 0 || akmCount > kMaximumSuiteCount ||
                static_cast<size_t>(akmCount) * 4 > length - offset)
            {
                return Result::InvalidSecurity;
            }
            for (uint16_t n = 0; n < akmCount; ++n, offset += 4)
            {
                parsed.akmEnterprise |=
                    matchesSuite(byteOffset(data, offset), 1);
                parsed.akmPsk |= matchesSuite(byteOffset(data, offset), 2);
                parsed.akmSae |=
                    matchesSuite(byteOffset(data, offset), kSaeSuiteId);
            }
            if (!parseRsnOptionalTail(data, length, offset, parsed))
            {
                return Result::InvalidSecurity;
            }
            parsed.valid = true;
            parsed.security = Security::UnsupportedRsn;
            // The supported WPA2-PSK station requires CCMP for both group
            // and pairwise traffic. Do not advertise a mixed-mode or unknown
            // group cipher as joinable WPA2-Personal during scanning.
            if (parsed.groupCcmp && parsed.pairwiseCcmp && parsed.akmPsk &&
                !parsed.pmfRequired)
            {
                parsed.security = Security::Wpa2Personal;
            }
            else if (parsed.pairwiseCcmp && parsed.akmEnterprise)
            {
                parsed.security = Security::Wpa2Enterprise;
            }
            else if (parsed.pairwiseCcmp && parsed.akmSae && parsed.pmfCapable)
            {
                parsed.security = Security::Wpa3Personal;
            }
            out = parsed;
            return Result::Ok;
        }

        namespace
        {
            struct BeaconElementState
            {
                    bool seenSsid {};
                    bool seenRsn {};
                    bool seenDs {};
                    bool seenRates {};
                    bool seenExtendedRates {};
                    bool seenHtCapabilities {};
                    bool seenHtOperation {};
                    uint8_t dsChannel {};
                    uint8_t htPrimaryChannel {};
            };
        } // namespace

        static Result readBeaconSsid(const Element &element, Beacon &parsed,
                                     BeaconElementState &state)
        {
            if (state.seenSsid || element.length > kMaxSsidBytes)
            {
                return Result::InvalidElement;
            }
            state.seenSsid = true;
            parsed.ssidLength = element.length;
            // A fixed-length, all-zero SSID is still hidden.
            parsed.hiddenSsid = true;
            for (size_t index = 0; index < element.length; ++index)
            {
                const uint8_t octet = *byteOffset(element.data, index);
                *byteOffset(arrayData(parsed.ssid), index) = octet;
                if (octet != 0U)
                {
                    parsed.hiddenSsid = false;
                }
            }
            return Result::Ok;
        }

        static Result readBeaconRates(const Element &element, Beacon &parsed,
                                      BeaconElementState &state)
        {
            const bool base = element.id == kSupportedRatesElementId;
            if ((base && state.seenRates) ||
                (!base && state.seenExtendedRates) || element.length == 0U ||
                (base && element.length > kLegacyRateCount) ||
                static_cast<size_t>(parsed.rateCount) + element.length >
                    sizeof(parsed.rates))
            {
                return Result::InvalidElement;
            }
            // Preserve basic-rate flag while rejecting a zero PHY rate.
            for (size_t index = 0; index < element.length; ++index)
            {
                if ((*byteOffset(element.data, index) & kRateValueMask) == 0U)
                {
                    return Result::InvalidElement;
                }
            }
            if (base)
            {
                state.seenRates = true;
            }
            else
            {
                state.seenExtendedRates = true;
            }
            for (size_t index = 0; index < element.length; ++index)
            {
                elementAt(parsed.rates, parsed.rateCount++) =
                    *byteOffset(element.data, index);
            }
            return Result::Ok;
        }

        static Result readBeaconDs(const Element &element, Beacon &parsed,
                                   BeaconElementState &state)
        {
            if (state.seenDs || element.length != 1U)
            {
                return Result::InvalidElement;
            }
            if (element.data == nullptr)
            {
                return Result::InvalidElement;
            }
            state.seenDs = true;
            state.dsChannel = *element.data;
            if (state.dsChannel == 0U || state.dsChannel > kCckOnlyChannel)
            {
                return Result::InvalidElement;
            }
            parsed.channel = state.dsChannel;
            return Result::Ok;
        }

        static Result readBeaconHtCapabilities(const Element &element,
                                               Beacon &parsed,
                                               BeaconElementState &state)
        {
            if (state.seenHtCapabilities ||
                element.length != kHtCapabilitiesBytes)
            {
                return Result::InvalidElement;
            }
            state.seenHtCapabilities = true;
            parsed.htSupported = true;
            parsed.ht40Allowed = (readLittle16(element.data) & 0x2U) != 0U;
            return Result::Ok;
        }

        static Result readBeaconRsn(const Element &element, Beacon &parsed,
                                    BeaconElementState &state)
        {
            if (state.seenRsn ||
                (parsed.capabilities & kPrivacyCapabilityBit) == 0U)
            {
                return Result::InvalidSecurity;
            }
            state.seenRsn = true;
            const Result result =
                parseRsn(element.data, element.length, parsed.rsn);
            if (result != Result::Ok)
            {
                return result;
            }
            // Copy the validated wire IE without reconstructing its suites.
            elementAt(parsed.rsnIe, 0U) = element.id;
            elementAt(parsed.rsnIe, 1U) = element.length;
            for (size_t index = 0; index < element.length; ++index)
            {
                elementAt(parsed.rsnIe, index + kRsnIeHeaderBytes) =
                    *byteOffset(element.data, index);
            }
            parsed.rsnIeLength =
                static_cast<uint16_t>(element.length + kRsnIeHeaderBytes);
            return Result::Ok;
        }

        static Result readBeaconHtOperation(const Element &element,
                                            Beacon &parsed,
                                            BeaconElementState &state)
        {
            if (state.seenHtOperation || element.length != kHtOperationBytes)
            {
                return Result::InvalidElement;
            }
            if (element.data == nullptr)
            {
                return Result::InvalidElement;
            }
            state.seenHtOperation = true;
            state.htPrimaryChannel = *element.data;
            if (state.htPrimaryChannel == 0U ||
                state.htPrimaryChannel > kCckOnlyChannel)
            {
                return Result::InvalidElement;
            }
            if (!state.seenDs)
            {
                parsed.channel = state.htPrimaryChannel;
            }
            return Result::Ok;
        }

        static Result readBeaconElements(const uint8_t *elements, size_t length,
                                         Beacon &parsed)
        {
            Elements cursor(elements, length);
            BeaconElementState state {};
            Element element {};
            for (;;)
            {
                const CursorStatus next = cursor.next(element);
                if (next == CursorStatus::End)
                {
                    break;
                }
                if (next == CursorStatus::Truncated)
                {
                    return Result::InvalidElement;
                }
                Result result = Result::Ok;
                switch (element.id)
                {
                    case kSsidElementId:
                        result = readBeaconSsid(element, parsed, state);
                        break;
                    case kSupportedRatesElementId:
                    case kExtendedRatesElementId:
                        result = readBeaconRates(element, parsed, state);
                        break;
                    case kDsParameterElementId:
                        result = readBeaconDs(element, parsed, state);
                        break;
                    case kHtCapabilitiesElementId:
                        result =
                            readBeaconHtCapabilities(element, parsed, state);
                        break;
                    case kRsnElementId:
                        result = readBeaconRsn(element, parsed, state);
                        break;
                    case kHtOperationElementId:
                        result = readBeaconHtOperation(element, parsed, state);
                        break;
                    default:
                        break;
                }
                if (result != Result::Ok)
                {
                    return result;
                }
            }
            if (!state.seenSsid || !state.seenRates ||
                (state.seenDs && state.seenHtOperation &&
                 state.dsChannel != state.htPrimaryChannel))
            {
                return Result::InvalidElement;
            }
            return Result::Ok;
        }

        Result parseBeacon(const uint8_t *frame, size_t length, Beacon &out)
        {
            // Refuse aliases before touching the borrowed frame, and never
            // expose stale BSSID, SSID or WPA2 policy after a rejected beacon.
            if (overlaps(&out, sizeof(out), frame, length))
            {
                return Result::OverlappingBuffers;
            }
            out = {};
            out.rsn.security = Security::UnsupportedRsn;
            Frame header {};
            Result result = parseFrame(frame, length, header);
            if (result != Result::Ok)
            {
                return result;
            }
            if (header.type != FrameType::Management ||
                (header.subtype != kBeaconSubtype &&
                 header.subtype != kProbeResponseSubtype))
            {
                return Result::UnsupportedFrame;
            }
            // Only a directly transmitted infrastructure BSS is supported;
            // nontransmitted/multiple-BSSID profiles need separate parsing.
            if (header.protectedFrame || !validStationMac(header.source) ||
                !sameMac(header.source, header.bssid))
            {
                return Result::InvalidFrame;
            }
            // IEEE 802.11 Beacons are broadcast advertisements. A directed
            // Probe Response can be unicast, but a unicast/multicast Beacon
            // must not enter the scan cache as a legitimate BSS discovery.
            if (header.subtype == kBeaconSubtype)
            {
                for (const uint8_t octet : header.destination.bytes)
                {
                    if (octet != kBroadcastOctet)
                    {
                        return Result::InvalidFrame;
                    }
                }
            }
            if (length - header.headerLength < kFixedBeaconBytes)
            {
                return Result::Truncated;
            }
            const uint8_t *fixed = byteOffset(frame, header.headerLength);
            Beacon parsed {};
            parsed.bssid = header.bssid;
            parsed.timestamp = readLittle64(fixed);
            parsed.intervalTu =
                readLittle16(byteOffset(fixed, kBeaconIntervalOffset));
            parsed.capabilities =
                readLittle16(byteOffset(fixed, kBeaconCapabilitiesOffset));
            // A zero beacon interval cannot describe a usable AP, even if
            // its otherwise valid SSID and RSNE might look joinable. Reject
            // this fixed-field error at the shared Beacon/Probe Response
            // parser boundary, not only in individual scan consumers.
            // ESS and IBSS advertise different BSS types. Accepting both
            // as infrastructure can poison scan selection with a forged BSS.
            if (parsed.intervalTu == 0 ||
                (parsed.capabilities & 0x0003U) == 0x0003U)
            {
                return Result::InvalidFrame;
            }
            parsed.infrastructure = (parsed.capabilities & 1U) != 0;
            parsed.hiddenSsid = true;
            parsed.rsn.security =
                (parsed.capabilities & kPrivacyCapabilityBit) != 0
                    ? Security::LegacyProtected
                    : Security::Open;

            result = readBeaconElements(
                byteOffset(fixed, kFixedBeaconBytes),
                length - header.headerLength - kFixedBeaconBytes, parsed);
            if (result != Result::Ok)
            {
                return result;
            }
            out = parsed;
            return Result::Ok;
        }

        // ABI-stable public frame serializer: the two integral parameters
        // are positional in Frames.hpp and every existing native caller.
        // NOLINTBEGIN(bugprone-easily-swappable-parameters)
        Result makeProbeRequest(const Mac &station, const uint8_t *ssid,
                                size_t ssidLength, uint16_t sequence,
                                uint8_t *output, size_t capacity,
                                size_t &written)
        {
            if (aliasesSerializedInput(output, capacity, written, &station,
                                       sizeof(station)) ||
                aliasesSerializedInput(output, capacity, written, ssid,
                                       ssidLength))
            {
                return Result::OverlappingBuffers;
            }
            if (output == nullptr)
            {
                written = 0;
                return Result::NullBuffer;
            }
            written = 0;
            if (!validStationMac(station))
            {
                return Result::InvalidAddress;
            }
            if (ssidLength > kMaxSsidBytes ||
                ((ssidLength != 0U) && (ssid == nullptr)))
            {
                return Result::InvalidSsid;
            }
            const size_t needed = kManagementHeaderBytes + kRsnIeHeaderBytes +
                                  ssidLength + kRsnIeHeaderBytes +
                                  kLegacyRateCount + kRsnIeHeaderBytes +
                                  kExtendedRateCount;
            if (capacity < needed)
            {
                return Result::BufferTooSmall;
            }
            for (size_t i = 0; i < needed; ++i)
            {
                (*byteOffset(output, i)) = 0;
            }
            writeLittle16(output,
                          kProbeRequestControl); // Management: probe request.
            copyBytes(byteOffset(output, kMacDestinationOffset),
                      arrayData(kBroadcastAddress), kMacAddressBytes);
            copyBytes(byteOffset(output, kMacSourceOffset),
                      arrayData(station.bytes), kMacAddressBytes);
            copyBytes(byteOffset(output, kMacBssidOffset),
                      arrayData(kBroadcastAddress), kMacAddressBytes);
            writeLittle16(
                byteOffset(output, kMacSequenceOffset),
                static_cast<uint16_t>(
                    (static_cast<uint32_t>(sequence) & kSequenceNumberMask)
                    << kSequenceControlShift));
            size_t offset = kManagementHeaderBytes;
            (*byteOffset(output, offset++)) = 0;
            (*byteOffset(output, offset++)) = static_cast<uint8_t>(ssidLength);
            if (ssidLength != 0U)
            {
                copyBytes(byteOffset(output, offset), ssid, ssidLength);
            }
            offset += ssidLength;
            (*byteOffset(output, offset++)) = 1;
            (*byteOffset(output, offset++)) = kLegacyRateCount;
            copyBytes(byteOffset(output, offset), arrayData(kLegacyRates),
                      sizeof(kLegacyRates));
            offset += kLegacyRateCount;
            (*byteOffset(output, offset++)) = kExtendedRatesElementId;
            (*byteOffset(output, offset++)) = 4;
            copyBytes(byteOffset(output, offset), arrayData(kExtendedRates),
                      sizeof(kExtendedRates));
            offset += 4;
            written = offset;
            return Result::Ok;
        }

        // NOLINTEND(bugprone-easily-swappable-parameters)
        Result makeOpenAuthenticationRequest(const Mac &station,
                                             const Mac &bssid,
                                             uint16_t sequence, uint8_t *output,
                                             size_t capacity, size_t &written)
        {
            if (aliasesSerializedInput(output, capacity, written, &station,
                                       sizeof(station)) ||
                aliasesSerializedInput(output, capacity, written, &bssid,
                                       sizeof(bssid)))
            {
                return Result::OverlappingBuffers;
            }
            if (output == nullptr)
            {
                written = 0;
                return Result::NullBuffer;
            }
            written = 0;
            // These public serializers do not require Station::select.
            // An infrastructure station cannot authenticate to itself.
            if (!validStationMac(station) || !validStationMac(bssid) ||
                sameMac(station, bssid))
            {
                return Result::InvalidAddress;
            }
            constexpr size_t needed =
                kManagementHeaderBytes +
                kResponseFixedBytes; // Fixed auth algorithm/sequence/status.
            if (capacity < needed)
            {
                return Result::BufferTooSmall;
            }
            for (size_t i = 0; i < needed; ++i)
            {
                (*byteOffset(output, i)) = 0;
            }
            writeLittle16(
                output, kAuthenticationControl); // Management: authentication.
            copyBytes(byteOffset(output, kMacDestinationOffset),
                      arrayData(bssid.bytes), kMacAddressBytes);
            copyBytes(byteOffset(output, kMacSourceOffset),
                      arrayData(station.bytes), kMacAddressBytes);
            copyBytes(byteOffset(output, kMacBssidOffset),
                      arrayData(bssid.bytes), kMacAddressBytes);
            writeLittle16(
                byteOffset(output, kMacSequenceOffset),
                static_cast<uint16_t>(
                    (static_cast<uint32_t>(sequence) & kSequenceNumberMask)
                    << kSequenceControlShift));
            writeLittle16(byteOffset(output, kManagementHeaderBytes),
                          0); // Open-system authentication algorithm.
            writeLittle16(byteOffset(output, kManagementHeaderBytes +
                                                 kAuthSequenceOffset),
                          1); // Transaction sequence 1.
            writeLittle16(
                byteOffset(output, kManagementHeaderBytes + kAuthStatusOffset),
                0);
            written = needed;
            return Result::Ok;
        }

        Result makeDisassociationRequest(const Mac &station, const Mac &bssid,
                                         DisassociationParameters fields,
                                         uint8_t *output, size_t capacity,
                                         size_t &written)
        {
            if (aliasesSerializedInput(output, capacity, written, &station,
                                       sizeof(station)) ||
                aliasesSerializedInput(output, capacity, written, &bssid,
                                       sizeof(bssid)))
            {
                return Result::OverlappingBuffers;
            }
            if (output == nullptr)
            {
                written = 0;
                return Result::NullBuffer;
            }
            written = 0;
            if (!validStationMac(station) || !validStationMac(bssid) ||
                sameMac(station, bssid))
            {
                return Result::InvalidAddress;
            }
            if (fields.reason == 0)
            {
                return Result::InvalidFrame;
            }

            // All fields are byte arrays: the fixed management layout has no
            // padding or unaligned accesses. Copy only after every validation
            // so rejected inputs leave borrowed destination bytes untouched.
            struct DisassociationWire
            {
                    uint8_t frameControl[2];
                    uint8_t duration[2];
                    uint8_t destination[kMacAddressBytes];
                    uint8_t source[kMacAddressBytes];
                    uint8_t bssid[kMacAddressBytes];
                    uint8_t sequence[2];
                    uint8_t reason[2];
            };

            constexpr uint8_t kFrameControl = 0xa0U;
            constexpr uint32_t kSequenceMask = 0x0fffU;
            constexpr uint32_t kFragmentShift = 4;
            constexpr size_t kManagementBytes = 26;
            static_assert(sizeof(DisassociationWire) == kManagementBytes,
                          "disassociation frame must be 26 octets");
            if (capacity < sizeof(DisassociationWire))
            {
                return Result::BufferTooSmall;
            }
            DisassociationWire frame {};
            frame.frameControl[0] = kFrameControl;
            __builtin_memcpy(&frame.destination[0],
                             &(*byteOffset(arrayData(bssid.bytes), 0)),
                             sizeof(frame.destination));
            __builtin_memcpy(&(*byteOffset(arrayData(frame.source), 0)),
                             &(*byteOffset(arrayData(station.bytes), 0)),
                             sizeof(frame.source));
            __builtin_memcpy(&frame.bssid[0],
                             &(*byteOffset(arrayData(bssid.bytes), 0)),
                             sizeof(frame.bssid));
            const uint32_t sequenceField =
                (static_cast<uint32_t>(fields.sequence) & kSequenceMask)
                << kFragmentShift;
            frame.sequence[0] = static_cast<uint8_t>(sequenceField);
            frame.sequence[1] =
                static_cast<uint8_t>(sequenceField >> kBitsPerByte);
            frame.reason[0] = static_cast<uint8_t>(fields.reason);
            frame.reason[1] =
                static_cast<uint8_t>(fields.reason >> kBitsPerByte);
            __builtin_memcpy(output, &frame, sizeof(frame));
            written = sizeof(frame);
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
            {
                return Result::OverlappingBuffers;
            }
            if (output == nullptr)
            {
                written = 0;
                return Result::NullBuffer;
            }
            written = 0;
            // Reject a forged station identity matching the destination AP
            // before creating a management frame on the caller's behalf.
            if (!validStationMac(station) || sameMac(station, network.bssid))
            {
                return Result::InvalidAddress;
            }
            const Result admission = validateAssociationBeacon(network);
            if (admission != Result::Ok)
            {
                return admission;
            }
            const bool secure = network.rsn.security == Security::Wpa2Personal;
            uint8_t selectedRates[kMaxLocalRates] {};
            size_t selectedCount = 0;
            if (!selectAssociationRates(network, selectedRates, selectedCount))
            {
                return Result::InvalidElement;
            }
            const size_t needed = kManagementHeaderBytes + kAuthStatusOffset +
                                  kRsnIeHeaderBytes + network.ssidLength +
                                  associationRateIeBytes(selectedCount) +
                                  (secure ? kFixedRsnIeBytes : 0U);
            if (capacity < needed)
            {
                return Result::BufferTooSmall;
            }
            for (size_t i = 0; i < needed; ++i)
            {
                (*byteOffset(output, i)) = 0;
            }
            writeLittle16(output, 0x0000U); // Management: association request.
            copyBytes(byteOffset(output, kMacDestinationOffset),
                      arrayData(network.bssid.bytes), kMacAddressBytes);
            copyBytes(byteOffset(output, kMacSourceOffset),
                      arrayData(station.bytes), kMacAddressBytes);
            copyBytes(byteOffset(output, kMacBssidOffset),
                      arrayData(network.bssid.bytes), kMacAddressBytes);
            writeLittle16(
                byteOffset(output, kMacSequenceOffset),
                static_cast<uint16_t>(
                    (static_cast<uint32_t>(sequence) & kSequenceNumberMask)
                    << kSequenceControlShift));
            writeLittle16(byteOffset(output, kManagementHeaderBytes),
                          static_cast<uint16_t>(
                              1U | (secure ? kPrivacyCapabilityBit : 0U)));
            writeLittle16(
                byteOffset(output,
                           kManagementHeaderBytes + kAuthSequenceOffset),
                kDefaultListenIntervalTu); // Listen interval in beacon units.
            size_t offset = kManagementHeaderBytes + kAuthStatusOffset;
            (*byteOffset(output, offset++)) = 0;
            (*byteOffset(output, offset++)) = network.ssidLength;
            copyBytes(byteOffset(output, offset), arrayData(network.ssid),
                      network.ssidLength);
            offset += network.ssidLength;
            const size_t baseCount = selectedCount > kLegacyRateCount
                                         ? kLegacyRateCount
                                         : selectedCount;
            (*byteOffset(output, offset++)) = 1;
            (*byteOffset(output, offset++)) = static_cast<uint8_t>(baseCount);
            copyBytes(byteOffset(output, offset), arrayData(selectedRates),
                      baseCount);
            offset += baseCount;
            if (selectedCount > baseCount)
            {
                (*byteOffset(output, offset++)) = kExtendedRatesElementId;
                (*byteOffset(output, offset++)) =
                    static_cast<uint8_t>(selectedCount - baseCount);
                copyBytes(byteOffset(output, offset),
                          byteOffset(&selectedRates[0], baseCount),
                          selectedCount - baseCount);
                offset += selectedCount - baseCount;
            }
            if (secure)
            {
                // Version 1, CCMP group/pairwise, PSK AKM, no negotiated PMF.
                constexpr uint8_t rsn[] = {
                    0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f,
                    0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x00, 0x00,
                };
                (*byteOffset(output, offset++)) = kRsnElementId;
                (*byteOffset(output, offset++)) = sizeof(rsn);
                copyBytes(byteOffset(output, offset), arrayData(rsn),
                          sizeof(rsn));
                offset += sizeof(rsn);
            }
            written = offset;
            return Result::Ok;
        }

        Result parseAddbaRequest(const uint8_t *frame, size_t length,
                                 AddbaRequest &out)
        {
            if (overlaps(&out, sizeof(out), frame, length))
            {
                return Result::OverlappingBuffers;
            }
            out = {};
            Frame parsed {};
            const auto result = parseFrame(frame, length, parsed);
            if (result != Result::Ok)
            {
                return result;
            }
            // Action subtype 13, BlockAck category 3 and ADDBA request 0.
            // No protected action frame is accepted without a verified PMF
            // session; our supported associations do not negotiate PMF.
            constexpr uint8_t kActionSubtype = 13U;
            constexpr uint8_t kBlockAckCategory = 3U;
            constexpr uint8_t kAddbaRequestAction = 0U;
            constexpr size_t kAddbaBodyBytes = 9U;
            if (parsed.type != FrameType::Management ||
                parsed.subtype != kActionSubtype || parsed.protectedFrame ||
                parsed.fragment != 0U || parsed.moreFragments)
            {
                return Result::UnsupportedFrame;
            }
            if (length < parsed.headerLength + kAddbaBodyBytes)
            {
                return Result::Truncated;
            }
            if (length != parsed.headerLength + kAddbaBodyBytes)
            {
                return Result::InvalidFrame;
            }
            const auto *body = byteOffset(frame, parsed.headerLength);
            if ((*byteOffset(body, 0)) != kBlockAckCategory ||
                (*byteOffset(body, 1)) != kAddbaRequestAction)
            {
                return Result::UnsupportedFrame;
            }
            const uint16_t parameters = readLittle16(byteOffset(body, 3));
            const uint16_t start = readLittle16(byteOffset(body, 7));
            constexpr uint16_t kBufferShift = 6U;
            constexpr uint16_t kBufferMask = 0x03ffU;
            constexpr uint16_t kTidShift = 2U;
            constexpr uint16_t kTidMask = 0x0fU;
            // A zero BA window cannot be negotiated. Starting sequence
            // control reserves the low four fragment bits as zero.
            const auto window = static_cast<uint16_t>(
                (parameters >> kBufferShift) & kBufferMask);
            if (window == 0U || (start & kFragmentNumberMask) != 0U)
            {
                return Result::InvalidFrame;
            }
            out.header = parsed;
            out.dialogToken = *byteOffset(body, 2);
            out.amsduPermitted = (parameters & 1U) != 0U;
            out.immediate = (parameters & 2U) != 0U;
            out.tid =
                static_cast<uint8_t>((parameters >> kTidShift) & kTidMask);
            out.bufferSize = window;
            out.timeoutTu = readLittle16(byteOffset(body, 5));
            out.startingSequence =
                static_cast<uint16_t>(start >> kSequenceControlShift);
            return Result::Ok;
        }

        Result makeAddbaDecline(const Mac &station, const Mac &bssid,
                                const AddbaRequest &request, uint16_t sequence,
                                uint8_t *output, size_t capacity,
                                size_t &written)
        {
            if (aliasesSerializedInput(output, capacity, written, &station,
                                       sizeof(station)) ||
                aliasesSerializedInput(output, capacity, written, &bssid,
                                       sizeof(bssid)) ||
                aliasesSerializedInput(output, capacity, written, &request,
                                       sizeof(request)))
            {
                return Result::OverlappingBuffers;
            }
            written = 0;
            if (output == nullptr)
            {
                return Result::NullBuffer;
            }
            if (!validStationMac(station) || !validStationMac(bssid) ||
                sameMac(station, bssid))
            {
                return Result::InvalidAddress;
            }
            if (sequence > kSequenceNumberMask || request.tid > 15U ||
                request.bufferSize == 0U || request.bufferSize > 1023U ||
                request.startingSequence > kSequenceNumberMask ||
                !sameMac(request.header.source, bssid) ||
                !sameMac(request.header.bssid, bssid) ||
                !sameMac(request.header.destination, station) ||
                request.header.protectedFrame || request.header.moreFragments ||
                request.header.fragment != 0U || request.header.toDs ||
                request.header.fromDs ||
                request.header.headerLength != kManagementHeaderBytes ||
                request.header.type != FrameType::Management ||
                request.header.subtype != 13U)
            {
                return Result::InvalidFrame;
            }
            constexpr size_t kDeclineBytes = kManagementHeaderBytes + 9U;
            if (capacity < kDeclineBytes)
            {
                return Result::BufferTooSmall;
            }
            // Snapshot all the needed values before writing caller storage;
            // neither destination nor counts alias any identity/parsed input.
            for (size_t i = 0; i < kDeclineBytes; ++i)
            {
                *byteOffset(output, i) = 0U;
            }
            constexpr uint16_t kManagementActionControl = 0x00d0U;
            constexpr uint16_t kRequestDeclined = 37U;
            constexpr uint8_t kBlockAckCategory = 3U;
            constexpr uint8_t kAddbaResponseAction = 1U;
            writeLittle16(output, kManagementActionControl);
            copyBytes(byteOffset(output, kMacDestinationOffset),
                      arrayData(bssid.bytes), kMacAddressBytes);
            copyBytes(byteOffset(output, kMacSourceOffset),
                      arrayData(station.bytes), kMacAddressBytes);
            copyBytes(byteOffset(output, kMacBssidOffset),
                      arrayData(bssid.bytes), kMacAddressBytes);
            writeLittle16(
                byteOffset(output, kMacSequenceOffset),
                static_cast<uint16_t>(sequence << kSequenceControlShift));
            auto *body = byteOffset(output, kManagementHeaderBytes);
            *byteOffset(body, 0) = kBlockAckCategory;
            *byteOffset(body, 1) = kAddbaResponseAction;
            *byteOffset(body, 2) = request.dialogToken;
            writeLittle16(byteOffset(body, 3), kRequestDeclined);
            // Mirror TID/window with immediate policy and A-MSDU disabled;
            // refusal must not announce any negotiated A-MPDU capability.
            const auto parameters = static_cast<uint16_t>(
                (static_cast<uint16_t>(request.bufferSize) << 6U) |
                (static_cast<uint16_t>(request.tid) << 2U) | 2U);
            writeLittle16(byteOffset(body, 5), parameters);
            writeLittle16(byteOffset(body, 7), request.timeoutTu);
            written = kDeclineBytes;
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
            {
                return Result::OverlappingBuffers;
            }
            // A rejected response must not leave a previous status=0 success
            // available for a caller to interpret as authenticated.
            statusCode = UINT16_MAX;
            // Caller-provided association identities are not trusted merely
            // because the incoming MAC header matches their bytes.
            if (!validStationMac(station) || !validStationMac(bssid) ||
                sameMac(station, bssid))
            {
                return Result::InvalidAddress;
            }
            Frame parsed {};
            const Result result = parseFrame(bytes, length, parsed);
            if (result != Result::Ok)
            {
                return result;
            }
            if (parsed.type != FrameType::Management ||
                parsed.subtype != kAuthResponseSubtype ||
                !sameMac(parsed.source, bssid) ||
                !sameMac(parsed.bssid, bssid) ||
                !sameMac(parsed.destination, station) || parsed.protectedFrame)
            {
                return Result::InvalidFrame;
            }
            if (length - parsed.headerLength < kResponseFixedBytes)
            {
                return Result::Truncated;
            }
            // Open System transaction 2 carries six fixed body bytes.
            // IEEE 802.11 also permits optional vendor-specific elements.
            // Validate the complete suffix without treating it as an auth
            // extension or rejecting legitimate vendor IEs outright.
            Elements extensions(
                byteOffset(bytes, parsed.headerLength + kResponseFixedBytes),
                length - parsed.headerLength - kResponseFixedBytes);
            Element extension {};
            for (;;)
            {
                const CursorStatus next = extensions.next(extension);
                if (next == CursorStatus::End)
                {
                    break;
                }
                if (next != CursorStatus::Element ||
                    extension.id != kVendorSpecificElementId ||
                    extension.length < 3)
                {
                    return Result::InvalidElement;
                }
            }
            const uint8_t *body = byteOffset(bytes, parsed.headerLength);
            if (readLittle16(body) != 0 ||
                readLittle16(byteOffset(body, 2)) != 2)
            {
                return Result::UnsupportedFrame;
            }
            statusCode = readLittle16(byteOffset(body, 4));
            return Result::Ok;
        }

        namespace
        {
            struct AssociationRateElements
            {
                    const uint8_t *body;
                    size_t bodyBytes;
                    uint16_t status;
            };
        } // namespace

        static Result
        checkAssociationResponseRates(const AssociationRateElements &input)
        {
            Elements cursor(byteOffset(input.body, kResponseFixedBytes),
                            input.bodyBytes - kResponseFixedBytes);
            Element element {};
            bool seenRates = false;
            bool seenExtendedRates = false;
            for (;;)
            {
                const CursorStatus next = cursor.next(element);
                if (next == CursorStatus::End)
                {
                    break;
                }
                if (next == CursorStatus::Truncated)
                {
                    return Result::InvalidElement;
                }
                if (element.id != kSupportedRatesElementId &&
                    element.id != kExtendedRatesElementId)
                {
                    continue;
                }
                const bool base = element.id == kSupportedRatesElementId;
                if ((base && seenRates) || (!base && seenExtendedRates) ||
                    element.length == 0 ||
                    (base && element.length > kLegacyRateCount))
                {
                    return Result::InvalidElement;
                }
                for (size_t i = 0; i < element.length; ++i)
                {
                    if (((*byteOffset(element.data, i)) & kRateValueMask) == 0)
                    {
                        return Result::InvalidElement;
                    }
                }
                if (base)
                {
                    seenRates = true;
                }
                else
                {
                    seenExtendedRates = true;
                }
            }
            if (input.status == 0 && !seenRates)
            {
                return Result::InvalidElement;
            }
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
            {
                return Result::OverlappingBuffers;
            }
            // Revoke a previous successful AID/status on any ordinary parse
            // failure, while preserving all input on an alias rejection.
            statusCode = UINT16_MAX;
            associationId = 0;
            // Caller-provided association identities are not trusted merely
            // because the incoming MAC header matches their bytes.
            if (!validStationMac(station) || !validStationMac(bssid) ||
                sameMac(station, bssid))
            {
                return Result::InvalidAddress;
            }
            Frame parsed {};
            const Result result = parseFrame(bytes, length, parsed);
            if (result != Result::Ok)
            {
                return result;
            }
            if (parsed.type != FrameType::Management ||
                parsed.subtype != kAssocResponseSubtype ||
                !sameMac(parsed.source, bssid) ||
                !sameMac(parsed.bssid, bssid) ||
                !sameMac(parsed.destination, station) || parsed.protectedFrame)
            {
                return Result::InvalidFrame;
            }
            if (length - parsed.headerLength < kResponseFixedBytes)
            {
                return Result::Truncated;
            }
            const uint8_t *body = byteOffset(bytes, parsed.headerLength);
            const uint16_t capabilities = readLittle16(body);
            const uint16_t status = readLittle16(byteOffset(body, 2));
            // An infrastructure station cannot accept a successful IBSS or
            // non-ESS response even when its AID and rate IEs look valid.
            if (status == 0 && ((capabilities & 0x0001U) == 0 ||
                                (capabilities & 0x0002U) != 0))
            {
                return Result::InvalidFrame;
            }
            const uint16_t rawAid = readLittle16(byteOffset(body, 4));
            const auto aid =
                static_cast<uint16_t>(rawAid & kAssociationAidMask);
            if (status == 0 && ((rawAid & kAssociationAidValidBits) !=
                                    kAssociationAidValidBits ||
                                aid == 0 || aid > kAssociationAidMax))
            {
                return Result::InvalidFrame;
            }

            // A successful Association Response carries a Supported Rates
            // element. Validate its complete IE list before treating the
            // status and AID as accepted; a six-byte fixed body alone is not
            // enough to establish usable negotiated BSS rates.
            const Result rates = checkAssociationResponseRates(
                {body, length - parsed.headerLength, status});
            if (rates != Result::Ok)
            {
                return rates;
            }
            statusCode = status;
            associationId = status == 0 ? aid : 0;
            return Result::Ok;
        }

    } // namespace ieee80211
} // namespace simpleath
