// SPDX-License-Identifier: GPL-2.0-only
// Linux ath9k v6.12 ar9003_eeprom.c: ar9003_hw_internal_regulator_apply,
// ar9003_phy.h: AR_PHY_PMU1(AR_SREV_9565) and AR_PHY_PMU1_PWD.
/*
 * Copyright (c) 2010-2011 Atheros Communications Inc.
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
#include "Ar9565Regulator.hpp"
#include "Ar9565Calibration.hpp"
#include "Ar9565Eeprom.hpp"
#include "Ar9565RfIni.hpp"
#include <cstddef>
#include <cstdint>

namespace simpleath
{
    namespace
    {
        constexpr uint32_t kAr9565Pmu1 = 0x16340;
        constexpr uint32_t kAr9565Xtal = 0x16298;
        constexpr uint32_t kFeatureTuningCaps = 0x40;
        constexpr size_t kTuningCapsOffset = 40;
        constexpr uint32_t kCapMask = 0x7f;
        constexpr uint32_t kCapInField = 0x7f000000;
        constexpr uint32_t kCapOutField = 0x00fe0000;
        constexpr uint32_t kCapInShift = 24;
        constexpr uint32_t kCapOutShift = 17;
        constexpr uint32_t kPmu1PowerDown = 0x1;
        constexpr uint32_t kFeatureRegulator = 0x10;
        constexpr size_t kFeatureEnableOffset = 42;
        constexpr size_t kSwregOffset = 49;
        constexpr uint32_t kByteBits = 8;
        constexpr uint32_t kHalfwordBits = 16;
        constexpr uint32_t kThreeByteBits = 24;
        constexpr uint8_t kOneChain = 1;

        bool allowed(const RfIniBackend &io, RegulatorProgress &status)
        {
            if (io.permitWrite(io.context, io.ownerEpoch))
            {
                return true;
            }
            status.result = RegulatorResult::OwnershipLost;
            return false;
        }
    } // namespace

    RegulatorProgress
    configureAr9565InternalRegulator(const EepromImage &image,
                                     const RegulatorEvidence &evidence,
                                     const RxAgcBackend &backend)
    {
        RegulatorProgress status {
            RegulatorResult::InvalidBackend, 0, 0, 0, false,
        };
        const RxAgcBackend stable = backend;
        const RfIniBackend &io = stable.io;
        if (io.context == nullptr || io.ownerEpoch == 0 ||
            io.permitWrite == nullptr || io.write32 == nullptr ||
            stable.read32 == nullptr)
        {
            return status;
        }
        BoardDataSummary board {};
        status.result = RegulatorResult::InvalidBoard;
        if (!image.restored || image.appliedBlocks == 0 ||
            summarizeBoardData(image, board) != EepromResult::Ok ||
            board.txChainMask != kOneChain || board.rxChainMask != kOneChain ||
            !board.calibrationPierBinsPlausible)
        {
            return status;
        }
        status.result = RegulatorResult::MissingAuthority;
        if (!evidence.physicalBoardVerified ||
            !evidence.macAndAutomaticTxQuiesced)
        {
            return status;
        }
        status.result = RegulatorResult::InvalidBar;
        if (io.barLengthBytes < kAr9565Pmu1 + sizeof(uint32_t))
        {
            return status;
        }
        const bool useSwreg =
            (image.bytes[kFeatureEnableOffset] & kFeatureRegulator) != 0;
        const uint32_t swreg =
            static_cast<uint32_t>(image.bytes[kSwregOffset]) |
            (static_cast<uint32_t>(image.bytes[kSwregOffset + 1])
             << kByteBits) |
            (static_cast<uint32_t>(image.bytes[kSwregOffset + 2])
             << kHalfwordBits) |
            (static_cast<uint32_t>(image.bytes[kSwregOffset + 3])
             << kThreeByteBits);
        status.result = RegulatorResult::OwnershipLost;
        if (!allowed(io, status))
        {
            return status;
        }
        // The PMU1_PWD field shares the swreg register. In the external
        // regulator branch ath9k sets only bit0; internal regulator applies
        // the WHOLE physical board word (not synthesized defaults).
        uint32_t previous = 0;
        if (!stable.read32(io.context, kAr9565Pmu1, &previous))
        {
            status.result = RegulatorResult::ReadFailed;
            return status;
        }
        ++status.completedReads;
        const uint32_t expected =
            useSwreg ? swreg : (previous | kPmu1PowerDown);
        if (!allowed(io, status))
        {
            return status;
        }
        status.programmedPmu1 = expected;
        // MMIO may have posted even on callback failure. Never retry a
        // partial power transaction without native reset.
        status.requiresReset = true;
        if (!io.write32(io.context, kAr9565Pmu1, expected))
        {
            status.result = RegulatorResult::WriteFailed;
            return status;
        }
        ++status.completedWrites;
        if (!allowed(io, status))
        {
            return status;
        }
        uint32_t observed = 0;
        if (!stable.read32(io.context, kAr9565Pmu1, &observed))
        {
            status.result = RegulatorResult::ReadFailed;
            return status;
        }
        ++status.completedReads;
        if (observed != expected)
        {
            status.result = RegulatorResult::ReadbackMismatch;
            return status;
        }
        if (!allowed(io, status))
        {
            return status;
        }
        status.result = RegulatorResult::Ok;
        status.requiresReset = false;
        return status;
    }

    XtalTuneProgress
    configureAr9565XtalCapacitors(const EepromImage &image,
                                  const RegulatorEvidence &evidence,
                                  const RxAgcBackend &backend)
    {
        XtalTuneProgress status {
            RegulatorResult::InvalidBackend, 0, 0, 0, false,
        };
        const RxAgcBackend stable = backend;
        const RfIniBackend &io = stable.io;
        if (io.context == nullptr || io.ownerEpoch == 0 ||
            io.permitWrite == nullptr || io.write32 == nullptr ||
            stable.read32 == nullptr)
        {
            return status;
        }
        BoardDataSummary board {};
        status.result = RegulatorResult::InvalidBoard;
        if (!image.restored || image.appliedBlocks == 0 ||
            summarizeBoardData(image, board) != EepromResult::Ok ||
            board.txChainMask != kOneChain || board.rxChainMask != kOneChain ||
            !board.calibrationPierBinsPlausible)
        {
            return status;
        }
        status.result = RegulatorResult::MissingAuthority;
        if (!evidence.physicalBoardVerified ||
            !evidence.macAndAutomaticTxQuiesced)
        {
            return status;
        }
        status.result = RegulatorResult::InvalidBar;
        if (io.barLengthBytes < kAr9565Xtal + sizeof(uint32_t))
        {
            return status;
        }
        if ((image.bytes[kFeatureEnableOffset] & kFeatureTuningCaps) == 0)
        {
            // No EEPROM XTAL tuning: keep factory PLL analog state.
            status.result = RegulatorResult::Ok;
            return status;
        }
        const uint32_t cap = image.bytes[kTuningCapsOffset] & kCapMask;
        status.result = RegulatorResult::OwnershipLost;
        if (!io.permitWrite(io.context, io.ownerEpoch))
        {
            return status;
        }
        uint32_t previous = 0;
        if (!stable.read32(io.context, kAr9565Xtal, &previous))
        {
            status.result = RegulatorResult::ReadFailed;
            return status;
        }
        ++status.completedReads;
        const uint32_t expected = (previous & ~(kCapInField | kCapOutField)) |
                                  (cap << kCapInShift) | (cap << kCapOutShift);
        if (!io.permitWrite(io.context, io.ownerEpoch))
        {
            return status;
        }
        status.programmedXtal = expected;
        status.requiresReset = true;
        if (!io.write32(io.context, kAr9565Xtal, expected))
        {
            status.result = RegulatorResult::WriteFailed;
            return status;
        }
        ++status.completedWrites;
        if (!io.permitWrite(io.context, io.ownerEpoch))
        {
            return status;
        }
        uint32_t observed = 0;
        if (!stable.read32(io.context, kAr9565Xtal, &observed))
        {
            status.result = RegulatorResult::ReadFailed;
            return status;
        }
        ++status.completedReads;
        if ((observed & (kCapInField | kCapOutField)) !=
            (expected & (kCapInField | kCapOutField)))
        {
            status.result = RegulatorResult::ReadbackMismatch;
            return status;
        }
        if (!io.permitWrite(io.context, io.ownerEpoch))
        {
            return status;
        }
        status.result = RegulatorResult::Ok;
        status.requiresReset = false;
        return status;
    }
} // namespace simpleath
