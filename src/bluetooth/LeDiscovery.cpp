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
//   - Native driver contracts and implementation for le discovery.
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
//   - Native driver contracts and implementation for le discovery.
// - Description:
//   - Implements or verifies the LeDiscovery source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for le discovery.

#include "LeDiscovery.hpp"
#include "UsbBytes.hpp"
#include "UsbHci.hpp"

#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    namespace
    {
        constexpr uint8_t kCommandComplete = 0x0eU;
        constexpr uint8_t kCommandStatus = 0x0fU;
        constexpr uint8_t kLeMetaEvent = 0x3eU;
        constexpr uint8_t kLegacyAdvertisingReport = 0x02U;
        constexpr uint16_t kLeSetScanParameters = 0x200bU;
        constexpr uint16_t kLeSetScanEnable = 0x200cU;
        constexpr uint16_t kMinScanDuration = 0x0004U;
        constexpr uint16_t kMaxScanDuration = 0x4000U;
        constexpr size_t kEventHeader = 2U;
        constexpr size_t kScanParamsBytes = 10U;
        constexpr size_t kScanEnableBytes = 5U;
        constexpr size_t kCommandCompleteBytes = 6U;
        constexpr size_t kCommandStatusBytes = 6U;
        constexpr size_t kStatusEventStatusOffset = 2U;
        constexpr size_t kStatusEventCreditsOffset = 3U;
        constexpr size_t kStatusEventOpcodeOffset = 4U;
        constexpr size_t kCommandStatusOffset = 5U;
        constexpr size_t kAdvertDataLengthOffset = 8U;
        constexpr size_t kAdvertisingHeaderBytes = 2U;
        constexpr size_t kReportHeaderBytes = 9U;
        constexpr unsigned kBitsPerByte = 8U;
        constexpr uint8_t kManufacturerAdType = 0xffU;
        constexpr uint8_t kAppleCompanyLow = 0x4cU;
        constexpr uint8_t kAppleCompanyHigh = 0x00U;
        constexpr uint8_t kAirDropTlvType = 0x05U;
        constexpr uint8_t kAirDropLegacyVersion = 1U;
        constexpr uint8_t kAirDropRotatingVersion = 3U;
        constexpr uint8_t kAirDropRotatingMarker = 0x40U;
        constexpr size_t kManufacturerPrefixBytes = 3U;
        constexpr size_t kAirDropPayloadBytes = 18U;
        constexpr size_t kAirDropVersionOffset = 8U;
        constexpr size_t kAirDropHashesOffset = 9U;
        constexpr size_t kAirDropTrailingReservedOffset = 17U;
        constexpr size_t kAirDropPrefixBytes = 8U;
        constexpr size_t kAirDropRotatingTagOffset = 1U;
        constexpr size_t kAirDropRotatingTagBytes = 3U;
        constexpr size_t kAirDropTrailingPrefixOffset = 4U;

        bool overlaps(const void *first, size_t firstBytes, const void *second,
                      size_t secondBytes)
        {
            if (first == nullptr || second == nullptr || firstBytes == 0U ||
                secondBytes == 0U)
            {
                return false;
            }
            uintptr_t a = 0U;
            uintptr_t b = 0U;
            static_assert(sizeof(a) == sizeof(first), "pointer width");
            __builtin_memcpy(&a, static_cast<const void *>(&first), sizeof(a));
            __builtin_memcpy(&b, static_cast<const void *>(&second), sizeof(b));
            return a <= b ? b - a < firstBytes : a - b < secondBytes;
        }

        bool allZero(const uint8_t *bytes, size_t length)
        {
            for (size_t index = 0U; index < length; ++index)
            {
                if (*usbByteOffset(bytes, index) != 0U)
                {
                    return false;
                }
            }
            return true;
        }

        // Decode a complete 18-byte Apple AirDrop TLV into temporary,
        // untrusted data. Fail before copying the private contact hashes.
        LeAirDropStatus decodeAirDrop(const uint8_t *payload, size_t bytes,
                                      LeAirDropHint &candidate)
        {
            if (bytes != kAirDropPayloadBytes)
            {
                return LeAirDropStatus::Malformed;
            }
            const uint8_t version =
                *usbByteOffset(payload, kAirDropVersionOffset);
            if (version != kAirDropLegacyVersion &&
                version != kAirDropRotatingVersion)
            {
                return LeAirDropStatus::UnsupportedVersion;
            }
            const bool validPrefix =
                version == kAirDropLegacyVersion
                    ? allZero(payload, kAirDropPrefixBytes)
                    : *payload == kAirDropRotatingMarker &&
                          allZero(usbByteOffset(payload,
                                                kAirDropTrailingPrefixOffset),
                                  kAirDropVersionOffset -
                                      kAirDropTrailingPrefixOffset);
            if (!validPrefix ||
                *usbByteOffset(payload, kAirDropTrailingReservedOffset) != 0U)
            {
                return LeAirDropStatus::Malformed;
            }
            candidate.version = version;
            if (version == kAirDropRotatingVersion)
            {
                for (size_t index = 0U; index < kAirDropRotatingTagBytes;
                     ++index)
                {
                    candidate.rotatingTag.at(index) = *usbByteOffset(
                        payload, kAirDropRotatingTagOffset + index);
                }
            }
            for (size_t index = 0U; index < kAirDropContactHashBytes; ++index)
            {
                candidate.contactHashes.at(index) =
                    *usbByteOffset(payload, kAirDropHashesOffset + index);
            }
            return LeAirDropStatus::Found;
        }

        LeAirDropStatus parseAppleTlvs(const uint8_t *data, size_t start,
                                       size_t end, LeAirDropHint &candidate,
                                       bool &found)
        {
            size_t offset = start;
            while (offset < end)
            {
                if (end - offset < 2U)
                {
                    return LeAirDropStatus::Malformed;
                }
                const uint8_t type = *usbByteOffset(data, offset);
                const size_t payloadBytes = *usbByteOffset(data, offset + 1U);
                offset += 2U;
                if (payloadBytes > end - offset)
                {
                    return LeAirDropStatus::Malformed;
                }
                if (type == kAirDropTlvType)
                {
                    if (found)
                    {
                        return LeAirDropStatus::Malformed;
                    }
                    const LeAirDropStatus decoded = decodeAirDrop(
                        usbByteOffset(data, offset), payloadBytes, candidate);
                    if (decoded != LeAirDropStatus::Found)
                    {
                        return decoded;
                    }
                    found = true;
                }
                offset += payloadBytes;
            }
            return LeAirDropStatus::Absent;
        }

        void clearDiscovery(LeDiscoveryState &state)
        {
            const uint64_t next = state.generation == UINT64_MAX
                                      ? UINT64_MAX
                                      : state.generation + 1U;
            state = {};
            state.generation = next;
        }

        bool authorized(const LeDiscoveryState &state,
                        const UsbHciState &transport,
                        const UsbHciHostCallbacks &host,
                        const LeDiscoveryOwner &owner)
        {
            const uint64_t epoch = state.epoch;
            const uint64_t generation = transport.generation;
            const uint64_t scanGeneration = state.generation;
            const LeScanPhase phase = state.phase;
            if (owner.context == nullptr || owner.permit == nullptr ||
                owner.onAdvertisement == nullptr || owner.epoch != epoch ||
                host.ownerEpoch != epoch || !transport.attached ||
                transport.epoch != epoch || transport.faulted ||
                !owner.permit(owner.context, epoch))
            {
                return false;
            }
            // Authorization is an external callback. It may retire the scan,
            // start a nested procedure, or replace the USB session before
            // returning true; no old caller may act on its cached rights.
            return state.epoch == epoch && state.phase == phase &&
                   state.generation == scanGeneration && transport.attached &&
                   !transport.faulted && transport.epoch == epoch &&
                   transport.generation == generation;
        }

        LeDiscoveryResult sendEnable(UsbHciState &transport,
                                     const UsbHciHostCallbacks &host,
                                     bool enable)
        {
            const uint8_t command[kScanEnableBytes] = {
                0x0cU, 0x20U, 0x02U, static_cast<uint8_t>(enable ? 1U : 0U),
                0x00U,
            };
            return sendUsbHciCommand(transport, host, &command[0U],
                                     kScanEnableBytes) == UsbHciStatus::Ok
                       ? LeDiscoveryResult::Ok
                       : LeDiscoveryResult::TransportFailed;
        }

        LeDiscoveryResult fault(LeDiscoveryState &state,
                                LeDiscoveryResult result)
        {
            state.phase = LeScanPhase::Faulted;
            return result;
        }

        // A controller Command Complete can arrive inside the USB OUT
        // callback. Only an acknowledged inline disable may retire Idle;
        // arbitrary owner revocation or USB replacement cannot be reported
        // as a successful scan transition.
        LeDiscoveryResult sendPendingEnable(LeDiscoveryState &state,
                                            UsbHciState &transport,
                                            const UsbHciHostCallbacks &host,
                                            bool enable)
        {
            const uint64_t epoch = state.epoch;
            const uint64_t generation = transport.generation;
            const uint64_t scanGeneration = state.generation;
            const LeDiscoveryResult sent = sendEnable(transport, host, enable);
            const bool inlineDisable = !enable &&
                                       state.phase == LeScanPhase::Idle &&
                                       sent == LeDiscoveryResult::Ok &&
                                       !transport.commandWindow.pending;
            if (transport.generation != generation ||
                ((state.epoch != epoch || state.generation != scanGeneration) &&
                 !inlineDisable) ||
                (enable && state.phase == LeScanPhase::AwaitParameters) ||
                (enable && state.phase == LeScanPhase::Idle &&
                 transport.commandWindow.pending))
            {
                return LeDiscoveryResult::OwnershipLost;
            }
            if (sent != LeDiscoveryResult::Ok)
            {
                return fault(state, LeDiscoveryResult::TransportFailed);
            }
            return state.phase == LeScanPhase::Faulted
                       ? LeDiscoveryResult::Faulted
                       : LeDiscoveryResult::Ok;
        }

        LeDiscoveryResult completeCommand(LeDiscoveryState &state,
                                          UsbHciState &transport,
                                          const UsbHciHostCallbacks &host,
                                          const uint8_t *event)
        {
            const uint32_t opcode =
                static_cast<uint32_t>(*usbByteOffset(event, 3U)) |
                (static_cast<uint32_t>(*usbByteOffset(event, 4U))
                 << kBitsPerByte);
            const bool expectedParameters =
                state.phase == LeScanPhase::AwaitParameters &&
                opcode == kLeSetScanParameters;
            const bool expectedEnable =
                (state.phase == LeScanPhase::AwaitEnable ||
                 state.phase == LeScanPhase::AwaitDisable) &&
                opcode == kLeSetScanEnable;
            if (!expectedParameters && !expectedEnable)
            {
                return LeDiscoveryResult::Ignored;
            }
            if (*usbByteOffset(event, kCommandStatusOffset) != 0U)
            {
                return fault(state, LeDiscoveryResult::ControllerRejected);
            }
            // HCI Command Complete reports how many commands may be sent.
            // Without a credit, do not issue enable/disable speculatively.
            if (*usbByteOffset(event, 2U) == 0U)
            {
                return fault(state,
                             LeDiscoveryResult::CommandCreditUnavailable);
            }
            if (expectedParameters)
            {
                if (state.stopRequested)
                {
                    clearDiscovery(state);
                    return LeDiscoveryResult::Ok;
                }
                state.phase = LeScanPhase::AwaitEnable;
                // A nested controller rejection still propagates as Faulted.
                return sendPendingEnable(state, transport, host, true);
            }
            if (state.phase == LeScanPhase::AwaitDisable)
            {
                clearDiscovery(state);
                return LeDiscoveryResult::Ok;
            }
            if (state.stopRequested)
            {
                state.phase = LeScanPhase::AwaitDisable;
                return sendPendingEnable(state, transport, host, false);
            }
            state.phase = LeScanPhase::Scanning;
            return LeDiscoveryResult::Ok;
        }

        LeDiscoveryResult completeStatus(LeDiscoveryState &state,
                                         const uint8_t *event, size_t bytes)
        {
            // Failed HCI commands may complete with Command Status rather
            // than Command Complete. If we ignore a rejection, the scan can
            // remain stuck awaiting an acknowledgment that will never come.
            if (bytes != kCommandStatusBytes)
            {
                return fault(state, LeDiscoveryResult::MalformedEvent);
            }
            const uint32_t opcode =
                static_cast<uint32_t>(
                    *usbByteOffset(event, kStatusEventOpcodeOffset)) |
                (static_cast<uint32_t>(
                     *usbByteOffset(event, kStatusEventOpcodeOffset + 1U))
                 << kBitsPerByte);
            const bool pendingParameters =
                state.phase == LeScanPhase::AwaitParameters &&
                opcode == kLeSetScanParameters;
            const bool pendingEnable =
                (state.phase == LeScanPhase::AwaitEnable ||
                 state.phase == LeScanPhase::AwaitDisable) &&
                opcode == kLeSetScanEnable;
            if (!pendingParameters && !pendingEnable)
            {
                return LeDiscoveryResult::Ignored;
            }
            if (*usbByteOffset(event, kStatusEventStatusOffset) != 0U)
            {
                return fault(state, LeDiscoveryResult::ControllerRejected);
            }
            if (*usbByteOffset(event, kStatusEventCreditsOffset) == 0U)
            {
                return fault(state,
                             LeDiscoveryResult::CommandCreditUnavailable);
            }
            // A successful Command Status is only preliminary. Do not claim
            // scanning/disabled until the matching Command Complete arrives.
            return LeDiscoveryResult::Ignored;
        }

        // An AD structure starts with its size (type byte + payload), not
        // including the size octet itself. A zero size may terminate the
        // data with zero padding; nonzero bytes after it are malformed.
        // Check these boundaries before publishing any report in the event.
        bool validLegacyAd(const uint8_t *data, size_t bytes)
        {
            size_t cursor = 0U;
            while (cursor < bytes)
            {
                const size_t field = *usbByteOffset(data, cursor);
                if (field == 0U)
                {
                    while (cursor < bytes)
                    {
                        if (*usbByteOffset(data, cursor) != 0U)
                        {
                            return false;
                        }
                        ++cursor;
                    }
                    return true;
                }
                if (field > bytes - cursor - 1U)
                {
                    return false;
                }
                cursor += field + 1U;
            }
            return true;
        }

        // Validate ALL reports before delivery, avoiding partial consumption
        // of one malformed controller event. Legacy HCI advertising reports
        // have at most 31 AD bytes; extended events are not interpreted.
        bool validReports(const uint8_t *event, size_t bytes)
        {
            if (bytes < kEventHeader + kAdvertisingHeaderBytes)
            {
                return false;
            }
            size_t offset = kEventHeader + kAdvertisingHeaderBytes;
            const size_t count = *usbByteOffset(event, 3U);
            if (count == 0U)
            {
                return false;
            }
            for (size_t index = 0U; index < count; ++index)
            {
                if (bytes - offset < kReportHeaderBytes)
                {
                    return false;
                }
                const uint8_t kind = *usbByteOffset(event, offset);
                const uint8_t addressType = *usbByteOffset(event, offset + 1U);
                const size_t length =
                    *usbByteOffset(event, offset + kAdvertDataLengthOffset);
                if (kind > 4U || addressType > 1U ||
                    length > kLeLegacyAdvertisingBytes ||
                    bytes - offset - kReportHeaderBytes < length + 1U ||
                    !validLegacyAd(
                        usbByteOffset(event, offset + kReportHeaderBytes),
                        length))
                {
                    return false;
                }
                offset += kReportHeaderBytes + length + 1U;
            }
            return offset == bytes;
        }

        LeDiscoveryResult dispatchAirDropHint(
            const LeDiscoveryState &state, const UsbHciState &transport,
            const UsbHciHostCallbacks &host, const LeDiscoveryOwner &owner,
            const LeLegacyAdvertisement &report, uint64_t reportEpoch)
        {
            const auto callback = owner.onAirDropHint;
            if (callback == nullptr)
            {
                return LeDiscoveryResult::Ok;
            }
            LeAirDropHint hint {};
            if (parseLeAirDropHint(report, hint) != LeAirDropStatus::Found)
            {
                return LeDiscoveryResult::Ok;
            }
            // Ordinary Bluetooth event delivery precedes any optional
            // AirDrop hint. No hint may activate an AWDL or OS host procedure.
            const uint64_t reportGeneration = state.generation;
            const bool delivered = callback(owner.context, reportEpoch, hint);
            if (state.generation != reportGeneration ||
                state.epoch != reportEpoch ||
                state.phase == LeScanPhase::Idle ||
                state.phase == LeScanPhase::AwaitDisable || state.stopRequested)
            {
                return LeDiscoveryResult::Ok;
            }
            if (!delivered)
            {
                return LeDiscoveryResult::DeliveryFailed;
            }
            if (state.phase != LeScanPhase::Scanning)
            {
                return LeDiscoveryResult::Faulted;
            }
            return authorized(state, transport, host, owner)
                       ? LeDiscoveryResult::Ok
                       : LeDiscoveryResult::OwnershipLost;
        }

        LeDiscoveryResult dispatchReports(const LeDiscoveryState &state,
                                          const UsbHciState &transport,
                                          const UsbHciHostCallbacks &host,
                                          const LeDiscoveryOwner &owner,
                                          const uint8_t *event, size_t bytes)
        {
            if (!validReports(event, bytes))
            {
                return LeDiscoveryResult::MalformedEvent;
            }
            size_t offset = kEventHeader + kAdvertisingHeaderBytes;
            const size_t count = *usbByteOffset(event, 3U);
            for (size_t index = 0U; index < count; ++index)
            {
                if (!authorized(state, transport, host, owner))
                {
                    return LeDiscoveryResult::OwnershipLost;
                }
                LeLegacyAdvertisement report {};
                report.eventType = *usbByteOffset(event, offset);
                report.addressType = *usbByteOffset(event, offset + 1U);
                for (size_t address = 0U; address < kLeAddressBytes; ++address)
                {
                    report.address.at(address) =
                        *usbByteOffset(event, offset + 2U + address);
                }
                report.dataBytes =
                    *usbByteOffset(event, offset + kAdvertDataLengthOffset);
                for (size_t payload = 0U; payload < report.dataBytes; ++payload)
                {
                    report.data.at(payload) = *usbByteOffset(
                        event, offset + kReportHeaderBytes + payload);
                }
                report.rssi = static_cast<int8_t>(*usbByteOffset(
                    event, offset + kReportHeaderBytes + report.dataBytes));
                offset += kReportHeaderBytes + report.dataBytes + 1U;
                // A passive scan never solicits SCAN_RSP. Even if another
                // controller user emits one unexpectedly, do not attribute
                // the response to our passive discovery procedure.
                if (report.eventType == 4U && !state.active)
                {
                    continue;
                }
                const uint64_t reportEpoch = state.epoch;
                const uint64_t reportGeneration = state.generation;
                const bool delivered =
                    owner.onAdvertisement(owner.context, reportEpoch, report);
                // A callback may quiesce the old USB function and attach a
                // new physical owner before it returns. Neither a rejected
                // old delivery nor the rest of this batch may fault or leak
                // into that successor's discovery session.
                if (state.generation != reportGeneration ||
                    state.epoch != reportEpoch ||
                    state.phase == LeScanPhase::Idle ||
                    state.phase == LeScanPhase::AwaitDisable ||
                    state.stopRequested)
                {
                    return LeDiscoveryResult::Ok;
                }
                if (!delivered)
                {
                    return LeDiscoveryResult::DeliveryFailed;
                }
                if (state.phase != LeScanPhase::Scanning)
                {
                    return LeDiscoveryResult::Faulted;
                }
                if (!authorized(state, transport, host, owner))
                {
                    return LeDiscoveryResult::OwnershipLost;
                }
                const LeDiscoveryResult hintResult = dispatchAirDropHint(
                    state, transport, host, owner, report, reportEpoch);
                if (hintResult != LeDiscoveryResult::Ok)
                {
                    return hintResult;
                }
                // The optional AirDrop observer is another borrowed host
                // callback. Even when it reports success (or its stale
                // failure was ignored), it may have replaced the scan with
                // the same epoch and phase. Stop this old multi-report batch.
                if (state.generation != reportGeneration ||
                    state.epoch != reportEpoch ||
                    state.phase == LeScanPhase::Idle ||
                    state.phase == LeScanPhase::AwaitDisable ||
                    state.stopRequested)
                {
                    return LeDiscoveryResult::Ok;
                }
            }
            return LeDiscoveryResult::Ok;
        }

        LeDiscoveryResult beginLegacyScan(LeDiscoveryState &state,
                                          UsbHciState &transport,
                                          const UsbHciHostCallbacks &host,
                                          const LeDiscoveryOwner &owner,
                                          uint16_t interval, uint16_t window,
                                          bool active)
        {
            if (interval < kMinScanDuration || interval > kMaxScanDuration ||
                window < kMinScanDuration || window > interval ||
                owner.epoch == 0U || owner.context == nullptr ||
                owner.permit == nullptr || owner.onAdvertisement == nullptr)
            {
                return LeDiscoveryResult::InvalidArgument;
            }
            if (state.phase != LeScanPhase::Idle)
            {
                return LeDiscoveryResult::Busy;
            }
            if (state.generation == UINT64_MAX)
            {
                return LeDiscoveryResult::Faulted;
            }
            const uint64_t priorGeneration = state.generation;
            if (!transport.attached || transport.faulted ||
                transport.epoch != host.ownerEpoch ||
                host.ownerEpoch != owner.epoch ||
                !owner.permit(owner.context, owner.epoch))
            {
                return LeDiscoveryResult::OwnershipLost;
            }
            // permit() can synchronously detach/rebind the USB transport or
            // start a nested scan while our initial checks are suspended.
            // A revoked physical transport cannot be used for HCI commands.
            if (!transport.attached || transport.faulted ||
                transport.epoch != host.ownerEpoch ||
                host.ownerEpoch != owner.epoch)
            {
                return LeDiscoveryResult::OwnershipLost;
            }
            // Do not overwrite a nested procedure or send its second command.
            if (state.phase != LeScanPhase::Idle)
            {
                return LeDiscoveryResult::Busy;
            }
            if (state.generation != priorGeneration)
            {
                return LeDiscoveryResult::OwnershipLost;
            }
            // HCI LE Set Scan Parameters (0x200b): passive or active, public
            // address, unfiltered. Active requests already passed an explicit
            // host privacy/procedure authorization callback.
            const uint8_t command[kScanParamsBytes] = {
                0x0bU,
                0x20U,
                0x07U,
                static_cast<uint8_t>(active ? 1U : 0U),
                static_cast<uint8_t>(interval & 0xffU),
                static_cast<uint8_t>(interval >> kBitsPerByte),
                static_cast<uint8_t>(window & 0xffU),
                static_cast<uint8_t>(window >> kBitsPerByte),
                0x00U,
                0x00U,
            };
            clearDiscovery(state);
            const uint64_t scanGeneration = state.generation;
            state.epoch = owner.epoch;
            state.active = active;
            state.phase = LeScanPhase::AwaitParameters;
            const uint64_t sessionGeneration = transport.generation;
            const UsbHciStatus sent = sendUsbHciCommand(
                transport, host, &command[0U], kScanParamsBytes);
            if (state.epoch != owner.epoch ||
                state.generation != scanGeneration ||
                transport.generation != sessionGeneration ||
                state.phase == LeScanPhase::Idle)
            {
                return LeDiscoveryResult::OwnershipLost;
            }
            if (sent != UsbHciStatus::Ok)
            {
                return fault(state, LeDiscoveryResult::TransportFailed);
            }
            if (state.phase == LeScanPhase::Faulted)
            {
                return LeDiscoveryResult::Faulted;
            }
            const LeScanPhase afterSendPhase = state.phase;
            const bool stillPermitted =
                authorized(state, transport, host, owner);
            if (state.epoch != owner.epoch || state.phase != afterSendPhase ||
                state.generation != scanGeneration ||
                transport.generation != sessionGeneration)
            {
                return LeDiscoveryResult::OwnershipLost;
            }
            if (!stillPermitted)
            {
                return fault(state, LeDiscoveryResult::OwnershipLost);
            }
            return LeDiscoveryResult::Ok;
        }

    } // namespace

    LeAirDropStatus parseLeAirDropHint(const LeLegacyAdvertisement &advert,
                                       LeAirDropHint &out)
    {
        if (overlaps(&advert, sizeof(advert), &out, sizeof(out)))
        {
            return LeAirDropStatus::OverlappingBuffers;
        }
        out = {};
        if (advert.dataBytes > kLeLegacyAdvertisingBytes ||
            advert.addressType > 1U || advert.eventType > 4U)
        {
            return LeAirDropStatus::InvalidArgument;
        }
        const uint8_t *const data = advert.data.data();
        LeAirDropHint candidate {};
        bool found = false;
        size_t offset = 0U;
        while (offset < advert.dataBytes)
        {
            const size_t length = *usbByteOffset(data, offset);
            if (length == 0U)
            {
                if (!allZero(usbByteOffset(data, offset),
                             advert.dataBytes - offset))
                {
                    return LeAirDropStatus::Malformed;
                }
                break;
            }
            if (length > advert.dataBytes - offset - 1U)
            {
                return LeAirDropStatus::Malformed;
            }
            const size_t end = offset + length + 1U;
            if (length >= kManufacturerPrefixBytes &&
                *usbByteOffset(data, offset + 1U) == kManufacturerAdType &&
                *usbByteOffset(data, offset + 2U) == kAppleCompanyLow &&
                *usbByteOffset(data, offset + 3U) == kAppleCompanyHigh)
            {
                const LeAirDropStatus status =
                    parseAppleTlvs(data, offset + 1U + kManufacturerPrefixBytes,
                                   end, candidate, found);
                if (status != LeAirDropStatus::Absent)
                {
                    return status;
                }
            }
            offset = end;
        }
        if (!found)
        {
            return LeAirDropStatus::Absent;
        }
        candidate.address = advert.address;
        candidate.addressType = advert.addressType;
        candidate.rssi = advert.rssi;
        out = candidate;
        return LeAirDropStatus::Found;
    }

    LeDiscoveryResult beginLePassiveScan(LeDiscoveryState &state,
                                         UsbHciState &transport,
                                         const UsbHciHostCallbacks &host,
                                         const LeDiscoveryOwner &owner,
                                         uint16_t interval, uint16_t window)
    {
        return beginLegacyScan(state, transport, host, owner, interval, window,
                               false);
    }

    LeDiscoveryResult beginLeActiveScan(LeDiscoveryState &state,
                                        UsbHciState &transport,
                                        const UsbHciHostCallbacks &host,
                                        const LeDiscoveryOwner &owner,
                                        uint16_t interval, uint16_t window,
                                        LeActiveScanAuthorization authorize)
    {
        if (authorize == nullptr)
        {
            return LeDiscoveryResult::InvalidArgument;
        }
        if (state.phase != LeScanPhase::Idle)
        {
            return LeDiscoveryResult::Busy;
        }
        if (interval < kMinScanDuration || interval > kMaxScanDuration ||
            window < kMinScanDuration || window > interval ||
            owner.epoch == 0U || owner.context == nullptr ||
            owner.permit == nullptr || owner.onAdvertisement == nullptr)
        {
            return LeDiscoveryResult::InvalidArgument;
        }
        const uint64_t priorGeneration = state.generation;
        if (!transport.attached || transport.faulted ||
            transport.epoch != host.ownerEpoch ||
            host.ownerEpoch != owner.epoch ||
            !owner.permit(owner.context, owner.epoch))
        {
            return LeDiscoveryResult::OwnershipLost;
        }
        // A revoked USB owner cannot authorize active controller RF work.
        if (!transport.attached || transport.faulted ||
            transport.epoch != host.ownerEpoch ||
            host.ownerEpoch != owner.epoch)
        {
            return LeDiscoveryResult::OwnershipLost;
        }
        // A nested passive scan may have started during permit(). Do not
        // even invoke the active-radio policy callback for a procedure that
        // no longer owns an Idle controller.
        if (state.phase != LeScanPhase::Idle)
        {
            return LeDiscoveryResult::Busy;
        }
        if (state.generation != priorGeneration)
        {
            return LeDiscoveryResult::OwnershipLost;
        }
        if (!authorize(owner.context, owner.epoch, interval, window))
        {
            return LeDiscoveryResult::Unauthorized;
        }
        // A policy callback can revoke USB ownership or reset the scan
        // state. Recheck both before sending an active RF command.
        if (state.generation != priorGeneration &&
            state.phase == LeScanPhase::Idle)
        {
            return LeDiscoveryResult::OwnershipLost;
        }
        return beginLegacyScan(state, transport, host, owner, interval, window,
                               true);
    }

    LeDiscoveryResult endLeScan(LeDiscoveryState &state, UsbHciState &transport,
                                const UsbHciHostCallbacks &host,
                                const LeDiscoveryOwner &owner)
    {
        if (state.phase == LeScanPhase::Idle)
        {
            return LeDiscoveryResult::NotScanning;
        }
        if (state.phase == LeScanPhase::Faulted)
        {
            return LeDiscoveryResult::Faulted;
        }
        const uint64_t requestEpoch = state.epoch;
        const uint64_t requestSerial = state.generation;
        const uint64_t requestGeneration = transport.generation;
        const LeScanPhase requestPhase = state.phase;
        const bool permitted = authorized(state, transport, host, owner);
        if (state.epoch != requestEpoch || state.phase != requestPhase ||
            state.generation != requestSerial ||
            transport.generation != requestGeneration)
        {
            return LeDiscoveryResult::OwnershipLost;
        }
        if (!permitted)
        {
            return fault(state, LeDiscoveryResult::OwnershipLost);
        }
        if (state.phase == LeScanPhase::AwaitDisable)
        {
            return LeDiscoveryResult::Busy;
        }
        if (state.phase == LeScanPhase::AwaitParameters ||
            state.phase == LeScanPhase::AwaitEnable)
        {
            state.stopRequested = true;
            return LeDiscoveryResult::Ok;
        }
        state.phase = LeScanPhase::AwaitDisable;
        const LeDiscoveryResult sent = sendEnable(transport, host, false);
        if (state.phase == LeScanPhase::Idle && sent == LeDiscoveryResult::Ok &&
            !transport.commandWindow.pending &&
            transport.generation == requestGeneration)
        {
            // An inline HCI Command Complete may retire the scan while the
            // USB submit frame is unwinding. This is a real ACK, not a lost
            // epoch. An unacknowledged disable never grants that result.
            return LeDiscoveryResult::Ok;
        }
        if (state.epoch != requestEpoch || state.generation != requestSerial ||
            transport.generation != requestGeneration)
        {
            return LeDiscoveryResult::OwnershipLost;
        }
        if (sent != LeDiscoveryResult::Ok)
        {
            return fault(state, LeDiscoveryResult::TransportFailed);
        }
        if (state.phase == LeScanPhase::Faulted)
        {
            return LeDiscoveryResult::Faulted;
        }
        // Inline disable completion can legitimately clear the epoch.
        if (state.phase == LeScanPhase::Idle)
        {
            return LeDiscoveryResult::Ok;
        }
        const LeScanPhase afterSendPhase = state.phase;
        const bool stillPermitted = authorized(state, transport, host, owner);
        if (state.epoch != requestEpoch || state.phase != afterSendPhase ||
            state.generation != requestSerial ||
            transport.generation != requestGeneration)
        {
            return LeDiscoveryResult::OwnershipLost;
        }
        if (!stillPermitted)
        {
            return fault(state, LeDiscoveryResult::OwnershipLost);
        }
        return LeDiscoveryResult::Ok;
    }

    LeDiscoveryResult acceptLeHciEvent(LeDiscoveryState &state,
                                       UsbHciState &transport,
                                       const UsbHciHostCallbacks &host,
                                       const LeDiscoveryOwner &owner,
                                       const uint8_t *event, size_t bytes)
    {
        if (state.phase == LeScanPhase::Idle)
        {
            return LeDiscoveryResult::Ignored;
        }
        if (state.phase == LeScanPhase::Faulted)
        {
            return LeDiscoveryResult::Faulted;
        }
        const uint64_t ingressEpoch = state.epoch;
        const uint64_t ingressSerial = state.generation;
        const uint64_t ingressGeneration = transport.generation;
        const LeScanPhase ingressPhase = state.phase;
        const bool permitted = authorized(state, transport, host, owner);
        if (state.epoch != ingressEpoch || state.phase != ingressPhase ||
            state.generation != ingressSerial ||
            transport.generation != ingressGeneration)
        {
            return LeDiscoveryResult::OwnershipLost;
        }
        if (!permitted)
        {
            return fault(state, LeDiscoveryResult::OwnershipLost);
        }
        if (event == nullptr || bytes < kEventHeader ||
            bytes > kUsbHciMaxEventBytes ||
            bytes !=
                static_cast<size_t>(*usbByteOffset(event, 1U)) + kEventHeader)
        {
            return fault(state, LeDiscoveryResult::MalformedEvent);
        }
        const uint8_t type = *usbByteOffset(event, 0U);
        if (type == kCommandComplete)
        {
            if (bytes < kCommandCompleteBytes)
            {
                return fault(state, LeDiscoveryResult::MalformedEvent);
            }
            const uint32_t opcode =
                static_cast<uint32_t>(*usbByteOffset(event, 3U)) |
                (static_cast<uint32_t>(*usbByteOffset(event, 4U))
                 << kBitsPerByte);
            if (opcode != kLeSetScanParameters && opcode != kLeSetScanEnable)
            {
                return LeDiscoveryResult::Ignored;
            }
            if (bytes != kCommandCompleteBytes)
            {
                return fault(state, LeDiscoveryResult::MalformedEvent);
            }
            return completeCommand(state, transport, host, event);
        }
        if (type == kCommandStatus)
        {
            return completeStatus(state, event, bytes);
        }
        if (type != kLeMetaEvent || bytes < 4U ||
            *usbByteOffset(event, 2U) != kLegacyAdvertisingReport)
        {
            return LeDiscoveryResult::Ignored;
        }
        if (state.phase != LeScanPhase::Scanning || state.stopRequested)
        {
            return LeDiscoveryResult::Ignored;
        }
        const LeDiscoveryResult result =
            dispatchReports(state, transport, host, owner, event, bytes);
        if (result != LeDiscoveryResult::Ok &&
            (state.epoch != ingressEpoch || state.phase != ingressPhase ||
             state.generation != ingressSerial ||
             transport.generation != ingressGeneration))
        {
            return LeDiscoveryResult::OwnershipLost;
        }
        return result == LeDiscoveryResult::Ok ? result : fault(state, result);
    }

    void revokeLeDiscovery(LeDiscoveryState &state)
    {
        clearDiscovery(state);
    }
} // namespace simpleath
