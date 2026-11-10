// SPDX-License-Identifier: AGPL-3.0-only
#include "LeDiscovery.hpp"
#include "UsbBytes.hpp"
#include "UsbHci.hpp"

#include <cstddef>
#include <cstdint>

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

        bool authorized(const LeDiscoveryState &state,
                        const UsbHciState &transport,
                        const UsbHciHostCallbacks &host,
                        const LeDiscoveryOwner &owner)
        {
            return owner.context != nullptr && owner.permit != nullptr &&
                   owner.onAdvertisement != nullptr &&
                   owner.epoch == state.epoch &&
                   host.ownerEpoch == state.epoch && transport.attached &&
                   transport.epoch == state.epoch && !transport.faulted &&
                   owner.permit(owner.context, state.epoch);
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
                    state = {};
                    return LeDiscoveryResult::Ok;
                }
                state.phase = LeScanPhase::AwaitEnable;
                if (sendEnable(transport, host, true) != LeDiscoveryResult::Ok)
                {
                    return fault(state, LeDiscoveryResult::TransportFailed);
                }
                return LeDiscoveryResult::Ok;
            }
            if (state.phase == LeScanPhase::AwaitDisable)
            {
                state = {};
                return LeDiscoveryResult::Ok;
            }
            if (state.stopRequested)
            {
                state.phase = LeScanPhase::AwaitDisable;
                if (sendEnable(transport, host, false) != LeDiscoveryResult::Ok)
                {
                    return fault(state, LeDiscoveryResult::TransportFailed);
                }
                return LeDiscoveryResult::Ok;
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
                    bytes - offset - kReportHeaderBytes < length + 1U)
                {
                    return false;
                }
                offset += kReportHeaderBytes + length + 1U;
            }
            return offset == bytes;
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
                if (!owner.onAdvertisement(owner.context, state.epoch, report))
                {
                    return LeDiscoveryResult::DeliveryFailed;
                }
                if (!authorized(state, transport, host, owner))
                {
                    return LeDiscoveryResult::OwnershipLost;
                }
            }
            return LeDiscoveryResult::Ok;
        }
    } // namespace

    LeDiscoveryResult beginLePassiveScan(LeDiscoveryState &state,
                                         UsbHciState &transport,
                                         const UsbHciHostCallbacks &host,
                                         const LeDiscoveryOwner &owner,
                                         uint16_t interval, uint16_t window)
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
        if (!transport.attached || transport.faulted ||
            transport.epoch != host.ownerEpoch ||
            host.ownerEpoch != owner.epoch ||
            !owner.permit(owner.context, owner.epoch))
        {
            return LeDiscoveryResult::OwnershipLost;
        }
        // HCI LE Set Scan Parameters (0x200b): passive, public address,
        // unfiltered. The native owner must have already determined that
        // these privacy/advertising policies are permitted by the OS.
        const uint8_t command[kScanParamsBytes] = {
            0x0bU,
            0x20U,
            0x07U,
            0x00U,
            static_cast<uint8_t>(interval & 0xffU),
            static_cast<uint8_t>(interval >> kBitsPerByte),
            static_cast<uint8_t>(window & 0xffU),
            static_cast<uint8_t>(window >> kBitsPerByte),
            0x00U,
            0x00U,
        };
        state.epoch = owner.epoch;
        state.phase = LeScanPhase::AwaitParameters;
        if (sendUsbHciCommand(transport, host, &command[0U],
                              kScanParamsBytes) != UsbHciStatus::Ok)
        {
            return fault(state, LeDiscoveryResult::TransportFailed);
        }
        if (!authorized(state, transport, host, owner))
        {
            return fault(state, LeDiscoveryResult::OwnershipLost);
        }
        return LeDiscoveryResult::Ok;
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
        if (!authorized(state, transport, host, owner))
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
        if (sendEnable(transport, host, false) != LeDiscoveryResult::Ok)
        {
            return fault(state, LeDiscoveryResult::TransportFailed);
        }
        if (!authorized(state, transport, host, owner))
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
        if (!authorized(state, transport, host, owner))
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
        return result == LeDiscoveryResult::Ok ? result : fault(state, result);
    }

    void revokeLeDiscovery(LeDiscoveryState &state)
    {
        state = {};
    }
} // namespace simpleath
