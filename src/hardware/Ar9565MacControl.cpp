// Copyright:
//   - Original Atheros / Qualcomm Atheros copyright holders
// SPDX-License-Identifier:
//   - ISC
// Confidential:
//   - false
// License-File:
//   - LICENSE-ISC
// Provenance:
//   - Linux ath9k-derived material; preserve original in-file notices and
//     source hashes
//
// Boundary-Contract:
// - Owns:
//   - Native driver contracts and implementation for ar9565 mac control.
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
//   - Native driver contracts and implementation for ar9565 mac control.
// - Description:
//   - Implements or verifies the Ar9565MacControl source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for ar9565 mac control.

/*
 * Copyright (c) 2008-2011 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
// AR9565 register protocol derived from pinned ath9k mac.c/reg.h.
#include "Ar9565MacControl.hpp"
#include "Ar9565Core.hpp"
#include <stdint.h>

namespace simpleath
{
    namespace
    {
        constexpr uint32_t kInterruptEnable = 0x0024;
        constexpr uint32_t kSyncInterruptEnable = 0x402c;
        constexpr uint32_t kReceiveControl = 0x0008;
        constexpr uint32_t kReceiveDisable = 0x20;
        constexpr uint32_t kReceiveEnableMask = 0x0c;
        constexpr uint32_t kTransmitDisable = 0x0880;
        constexpr uint32_t kTransmitEnable = 0x0840;
        constexpr uint32_t kAllTransmitQueues = 0x3ff;
        constexpr uint32_t kDiagnosticControl = 0x8048;
        constexpr uint32_t kStationIdLow = 0x8000;
        constexpr uint32_t kStationIdHigh = 0x8004;
        constexpr uint32_t kStationMacHighMask = 0x0000ffffU;
        constexpr uint32_t kBssidIdLow = 0x8008;
        constexpr uint32_t kBssidIdHigh = 0x800c;
        constexpr uint16_t kMaximumAssociationAid = 2007U;
        constexpr uint32_t kAssociationAidShift = 16U;
        constexpr uint32_t kBssidMaskLow = 0x80e0;
        constexpr uint32_t kBssidMaskHigh = 0x80e4;
        constexpr uint32_t kExactBssidMaskLow = UINT32_MAX;
        constexpr uint32_t kExactBssidMaskHigh = 0x0000ffffU;
        constexpr uint32_t kBlockReceiveAndResponses = 0x02000026;
        constexpr uint32_t kObserveBus = 0x806c;
        constexpr uint32_t kReceiveState = 0x01f00000;
        constexpr uint32_t kRtcShutdown = 1;
        constexpr uint32_t kRtcSleep = 4;
        constexpr uint32_t kRtcWakeup = 8;
        constexpr unsigned int kMaximumWaitPolls = 1000U;
        constexpr uint32_t kPollIntervalMicros = 10U;

        bool read(const RegisterBus &bus, uint32_t offset, uint32_t &value)
        {
            return bus.read32(bus.context, offset, &value) &&
                   value != UINT32_MAX;
        }

        bool programExactBssidMask(const RegisterBus &bus, uint64_t epoch,
                                   bool (*permit)(void *, uint64_t),
                                   MacIdentityProgress &result)
        {
            // Default to an exact BSSID mask before any later association or
            // automatic MAC response. The all-ones low word is legal data, not
            // the missing-BAR read sentinel used for ordinary registers.
            result.result = MacIdentityResult::OwnershipLost;
            if (!permit(bus.context, epoch))
            {
                return false;
            }
            result.result = MacIdentityResult::WriteFailed;
            if (!bus.write32(bus.context, kBssidMaskLow, kExactBssidMaskLow))
            {
                return false;
            }
            ++result.completedWrites;
            result.result = MacIdentityResult::OwnershipLost;
            if (!permit(bus.context, epoch))
            {
                return false;
            }
            result.result = MacIdentityResult::WriteFailed;
            if (!bus.write32(bus.context, kBssidMaskHigh, kExactBssidMaskHigh))
            {
                return false;
            }
            ++result.completedWrites;
            result.result = MacIdentityResult::OwnershipLost;
            if (!permit(bus.context, epoch))
            {
                return false;
            }
            uint32_t maskLow = 0;
            result.result = MacIdentityResult::ReadFailed;
            // 0xffffffff is the correct exact-match mask; only this offset
            // intentionally bypasses read()'s all-ones floating-BAR heuristic.
            if (!bus.read32(bus.context, kBssidMaskLow, &maskLow))
            {
                return false;
            }
            result.result = MacIdentityResult::OwnershipLost;
            if (!permit(bus.context, epoch))
            {
                return false;
            }
            uint32_t maskHigh = 0;
            result.result = MacIdentityResult::ReadFailed;
            if (!read(bus, kBssidMaskHigh, maskHigh))
            {
                return false;
            }
            result.result = MacIdentityResult::ReadbackMismatch;
            return maskLow == kExactBssidMaskLow &&
                   maskHigh == kExactBssidMaskHigh;
        }

        bool validBackend(const RegisterBus &bus,
                          void (*delayMicros)(void *, uint32_t))
        {
            return bus.context != nullptr && bus.read32 != nullptr &&
                   bus.write32 != nullptr && delayMicros != nullptr &&
                   bus.barLengthBytes >= kObserveBus + sizeof(uint32_t);
        }
    } // namespace

    MacReceiveOnlyResult verifyAr9565ReceiveOnlyAutoResponsesDisabled(
        const RegisterBus &supplied, uint64_t epoch,
        bool (*permit)(void *, uint64_t))
    {
        constexpr uint32_t kSelfGeneratedMask = 0x832c;
        const RegisterBus bus = supplied;
        if (bus.context == nullptr || bus.read32 == nullptr ||
            permit == nullptr || epoch == 0)
        {
            return MacReceiveOnlyResult::InvalidBackend;
        }
        if (bus.barLengthBytes < kSelfGeneratedMask + sizeof(uint32_t))
        {
            return MacReceiveOnlyResult::InvalidBar;
        }
        if (!permit(bus.context, epoch))
        {
            return MacReceiveOnlyResult::OwnershipLost;
        }
        uint32_t mask = UINT32_MAX;
        // A floating BAR read of all ones is never a valid zero mask.
        if (!bus.read32(bus.context, kSelfGeneratedMask, &mask) ||
            mask == UINT32_MAX)
        {
            return MacReceiveOnlyResult::ReadFailed;
        }
        if (!permit(bus.context, epoch))
        {
            return MacReceiveOnlyResult::OwnershipLost;
        }
        return mask == 0 ? MacReceiveOnlyResult::Ok
                         : MacReceiveOnlyResult::AutoResponsesEnabled;
    }

    MacIdentityProgress
    programAr9565StationMac(const RegisterBus &supplied,
                            const uint8_t mac[kPermanentMacBytes],
                            uint64_t epoch, bool (*permit)(void *, uint64_t))
    {
        MacIdentityProgress result {};
        const RegisterBus bus = supplied;
        if (bus.context == nullptr || bus.read32 == nullptr ||
            bus.write32 == nullptr || permit == nullptr || epoch == 0 ||
            bus.barLengthBytes < kBssidMaskHigh + sizeof(uint32_t))
        {
            return result;
        }
        result.result = MacIdentityResult::InvalidMac;
        if (!validatePermanentMac(mac))
        {
            return result;
        }
        // Capture the entire identity before invoking owner callbacks; a
        // borrowed address must never change partway through programming.
        uint8_t station[kPermanentMacBytes] {};
        __builtin_memcpy(&station[0], mac, sizeof(station));
        const uint32_t low = static_cast<uint32_t>(station[0]) |
                             (static_cast<uint32_t>(station[1]) << 8U) |
                             (static_cast<uint32_t>(station[2]) << 16U) |
                             (static_cast<uint32_t>(station[3]) << 24U);
        const uint32_t high = static_cast<uint32_t>(station[4]) |
                              (static_cast<uint32_t>(station[5]) << 8U);
        result.result = MacIdentityResult::OwnershipLost;
        if (!permit(bus.context, epoch))
        {
            return result;
        }
        uint32_t originalHigh = 0;
        result.result = MacIdentityResult::ReadFailed;
        if (!read(bus, kStationIdHigh, originalHigh))
        {
            return result;
        }
        const uint32_t updatedHigh =
            (originalHigh & ~kStationMacHighMask) | high;
        result.result = MacIdentityResult::OwnershipLost;
        if (!permit(bus.context, epoch))
        {
            return result;
        }
        result.result = MacIdentityResult::WriteFailed;
        result.requiresReset = true;
        if (!bus.write32(bus.context, kStationIdLow, low))
        {
            return result;
        }
        ++result.completedWrites;
        result.result = MacIdentityResult::OwnershipLost;
        if (!permit(bus.context, epoch))
        {
            return result;
        }
        result.result = MacIdentityResult::WriteFailed;
        if (!bus.write32(bus.context, kStationIdHigh, updatedHigh))
        {
            return result;
        }
        ++result.completedWrites;
        uint32_t checkLow = 0;
        uint32_t checkHigh = 0;
        result.result = MacIdentityResult::OwnershipLost;
        if (!permit(bus.context, epoch))
        {
            return result;
        }
        result.result = MacIdentityResult::ReadFailed;
        if (!read(bus, kStationIdLow, checkLow))
        {
            return result;
        }
        // Both readback MMIO accesses independently require the active
        // owner. A provider may disappear between these two callbacks.
        result.result = MacIdentityResult::OwnershipLost;
        if (!permit(bus.context, epoch))
        {
            return result;
        }
        result.result = MacIdentityResult::ReadFailed;
        if (!read(bus, kStationIdHigh, checkHigh))
        {
            return result;
        }
        result.result = MacIdentityResult::ReadbackMismatch;
        if (checkLow != low || checkHigh != updatedHigh)
        {
            return result;
        }
        if (!programExactBssidMask(bus, epoch, permit, result))
        {
            return result;
        }
        result.result = MacIdentityResult::OwnershipLost;
        if (!permit(bus.context, epoch))
        {
            return result;
        }
        result.result = MacIdentityResult::Ok;
        result.requiresReset = false;
        return result;
    }

    namespace
    {
        MacIdentityProgress
        writeAssociationIdentity(const RegisterBus &supplied, uint32_t low,
                                 uint32_t high, uint64_t epoch,
                                 bool (*permit)(void *, uint64_t))
        {
            MacIdentityProgress result {};
            const RegisterBus bus = supplied;
            if (bus.context == nullptr || bus.read32 == nullptr ||
                bus.write32 == nullptr || permit == nullptr || epoch == 0 ||
                bus.barLengthBytes < kBssidIdHigh + sizeof(uint32_t))
            {
                return result;
            }
            result.result = MacIdentityResult::OwnershipLost;
            if (!permit(bus.context, epoch))
            {
                return result;
            }
            result.result = MacIdentityResult::WriteFailed;
            // A write callback may report failure after the PCI posted write.
            result.requiresReset = true;
            if (!bus.write32(bus.context, kBssidIdLow, low))
            {
                return result;
            }
            ++result.completedWrites;
            result.result = MacIdentityResult::OwnershipLost;
            if (!permit(bus.context, epoch))
            {
                return result;
            }
            result.result = MacIdentityResult::WriteFailed;
            if (!bus.write32(bus.context, kBssidIdHigh, high))
            {
                return result;
            }
            ++result.completedWrites;
            result.result = MacIdentityResult::OwnershipLost;
            if (!permit(bus.context, epoch))
            {
                return result;
            }
            uint32_t observedLow = 0;
            result.result = MacIdentityResult::ReadFailed;
            if (!read(bus, kBssidIdLow, observedLow))
            {
                return result;
            }
            result.result = MacIdentityResult::OwnershipLost;
            if (!permit(bus.context, epoch))
            {
                return result;
            }
            uint32_t observedHigh = 0;
            result.result = MacIdentityResult::ReadFailed;
            if (!read(bus, kBssidIdHigh, observedHigh))
            {
                return result;
            }
            result.result = MacIdentityResult::ReadbackMismatch;
            if (observedLow != low || observedHigh != high)
            {
                return result;
            }
            result.result = MacIdentityResult::OwnershipLost;
            if (!permit(bus.context, epoch))
            {
                return result;
            }
            result.result = MacIdentityResult::Ok;
            result.requiresReset = false;
            return result;
        }
    } // namespace

    MacIdentityProgress programAr9565AssociationBssid(
        const RegisterBus &supplied, const uint8_t bssid[kPermanentMacBytes],
        uint16_t aid, uint64_t epoch, bool (*permit)(void *, uint64_t))
    {
        const RegisterBus bus = supplied;
        MacIdentityProgress result {};
        if (bus.context == nullptr || bus.read32 == nullptr ||
            bus.write32 == nullptr || permit == nullptr || epoch == 0 ||
            bus.barLengthBytes < kBssidIdHigh + sizeof(uint32_t))
        {
            return result;
        }
        result.result = MacIdentityResult::InvalidMac;
        if (!validatePermanentMac(bssid) || aid > kMaximumAssociationAid)
        {
            return result;
        }
        // Snapshot the BSSID before any caller callback can mutate it.
        uint8_t selected[kPermanentMacBytes] {};
        __builtin_memcpy(&selected[0], bssid, sizeof(selected));
        const uint32_t low = static_cast<uint32_t>(selected[0]) |
                             (static_cast<uint32_t>(selected[1]) << 8U) |
                             (static_cast<uint32_t>(selected[2]) << 16U) |
                             (static_cast<uint32_t>(selected[3]) << 24U);
        const uint32_t high =
            static_cast<uint32_t>(selected[4]) |
            (static_cast<uint32_t>(selected[5]) << 8U) |
            (static_cast<uint32_t>(aid) << kAssociationAidShift);
        return writeAssociationIdentity(bus, low, high, epoch, permit);
    }

    MacIdentityProgress
    clearAr9565AssociationBssid(const RegisterBus &supplied, uint64_t epoch,
                                bool (*permit)(void *, uint64_t))
    {
        // Clearing is an explicit state transition, not a BSSID of all zero.
        // Reuse the same checked, post-write readback and owner-epoch gate.
        return writeAssociationIdentity(supplied, 0U, 0U, epoch, permit);
    }

    MacStopResult quiesceAr9565Mac(const RegisterBus &supplied,
                                   void (*delayMicros)(void *, uint32_t))
    {
        const RegisterBus bus = supplied;
        if (!validBackend(bus, delayMicros))
        {
            return MacStopResult::InvalidBackend;
        }
        uint32_t rtc = 0;
        if (!read(bus, kRtcStatusRegister, rtc))
        {
            return MacStopResult::ReadFailed;
        }
        rtc &= kRtcStatusMask;
        if (rtc != kRtcShutdown && rtc != kRtcSleep && rtc != kRtcOn &&
            rtc != kRtcWakeup)
        {
            return MacStopResult::UnknownRtcState;
        }
        if (!bus.write32(bus.context, kSyncInterruptEnable, 0))
        {
            return MacStopResult::WriteFailed;
        }
        // RTC shutdown/sleep cannot run MAC queues. Never touch sleeping MAC
        // registers. The caller bootstraps RTC, then quiesces again while on.
        if (rtc == kRtcShutdown || rtc == kRtcSleep)
        {
            return MacStopResult::Ok;
        }
        for (unsigned int poll = 0;
             rtc == kRtcWakeup && poll < kMaximumWaitPolls; ++poll)
        {
            delayMicros(bus.context, kPollIntervalMicros);
            if (!read(bus, kRtcStatusRegister, rtc))
            {
                return MacStopResult::ReadFailed;
            }
            rtc &= kRtcStatusMask;
        }
        if (rtc == kRtcWakeup)
        {
            return MacStopResult::Timeout;
        }
        if (rtc == kRtcShutdown || rtc == kRtcSleep)
        {
            return MacStopResult::Ok;
        }
        if (rtc != kRtcOn)
        {
            return MacStopResult::UnknownRtcState;
        }
        uint32_t diagnostic = 0;
        if (!read(bus, kDiagnosticControl, diagnostic))
        {
            return MacStopResult::ReadFailed;
        }
        if (!bus.write32(bus.context, kInterruptEnable, 0) ||
            !bus.write32(bus.context, kDiagnosticControl,
                         diagnostic | kBlockReceiveAndResponses) ||
            !bus.write32(bus.context, kReceiveControl, kReceiveDisable) ||
            !bus.write32(bus.context, kTransmitDisable, kAllTransmitQueues))
        {
            return MacStopResult::WriteFailed;
        }
        for (unsigned int poll = 0; poll < kMaximumWaitPolls; ++poll)
        {
            uint32_t rx = 0;
            uint32_t tx = 0;
            uint32_t observe = 0;
            if (!read(bus, kReceiveControl, rx) ||
                !read(bus, kTransmitEnable, tx) ||
                !read(bus, kObserveBus, observe))
            {
                return MacStopResult::ReadFailed;
            }
            if (((rx & kReceiveEnableMask) == 0U) &&
                ((tx & kAllTransmitQueues) == 0U) &&
                ((observe & kReceiveState) == 0U))
            {
                return MacStopResult::Ok;
            }
            delayMicros(bus.context, kPollIntervalMicros);
        }
        return MacStopResult::Timeout;
    }
} // namespace simpleath
