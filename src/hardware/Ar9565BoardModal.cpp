// SPDX-License-Identifier: GPL-2.0-only
// Hardware layout/algorithm: Linux ath9k ar9003_eeprom.c
// ar9003_hw_ant_ctrl_apply(), ar9003_hw_atten_apply() and ar9003_phy.h.
/*
 * Copyright (c) 2010-2011 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.
 */
#include "Ar9565BoardModal.hpp"
#include "Ar9565Calibration.hpp"
#include "Ar9565Eeprom.hpp"
#include "Ar9565InitCatalog.hpp"
#include "Ar9565RfIni.hpp"
#include <cstddef>
#include <cstdint>

namespace simpleath
{
    namespace
    {
        // Packed AR9300 v2 modalHeader2G starts at byte 53. The offsets below
        // were checked against struct ar9300_modal_eep_header in ath9k.
        constexpr size_t kSpdtOffset = 114;
        constexpr size_t kAttenuationOffset = 67;
        constexpr size_t kXpaBiasOffset = 95;
        constexpr size_t kMarginOffset = 70;
        constexpr uint32_t kEightBits = 8;
        constexpr uint32_t kSpdtMask = 0xfff;
        constexpr uint32_t kSpdtShift = 4;
        constexpr uint32_t kSpdtField = 0x0000fff0;
        constexpr uint32_t kSpdtEnable = 1;
        constexpr uint32_t kAntennaCommonField = 0x00ffffff;
        constexpr uint32_t kAntennaChainField = 0xfff;
        constexpr uint32_t kExtAttenField = 0x3f;
        constexpr uint32_t kExtMarginField = 0x1f000;
        constexpr uint32_t kExtMarginShift = 12;
        constexpr uint32_t kPhySwitchCom = 0xa288;
        constexpr uint32_t kPhySwitchCom2 = 0xa28c;
        constexpr uint32_t kPhySwitchChain0 = 0xa284;
        constexpr uint32_t kPhyExtAtten0 = 0x9e18;
        constexpr uint32_t kPhyXpaBiasTop = 0x1628c;
        constexpr uint32_t kPhyXpaBiasMask = 0x300;
        constexpr uint32_t kPhyXpaBiasShift = 8;
        constexpr uint32_t kPhyGlbControl = 0x20044;
        constexpr uint32_t kMcGainControl = 0x9e28;
        constexpr uint32_t kCckDetect = 0x9fc0;
        constexpr uint32_t kPhyRestart = 0x9e24;
        constexpr uint32_t kBtCoexLnaDiversity = 0x1a64;
        constexpr uint32_t kGainDivField = 0x7e000000;
        constexpr uint32_t kGainDivShift = 25;
        constexpr uint32_t kGainLnaDiv = 0x01000000;
        constexpr uint32_t kGainRxProtection = 0x00800000;
        constexpr uint32_t kCckFastDiversity = 0x2000;
        constexpr uint32_t kPhyRestartM2Flag = 0x00200000;
        constexpr uint32_t kBtForceLnaDiversity = 0x00008000;
        constexpr uint8_t kExpectedChainMask = 1;
        constexpr uint8_t kExpectedAntennaOverride = 0xc9;
        constexpr uint32_t kDiversitySettings = 0x3f;
        constexpr uint32_t kEnableDiversityBit = 0x40;
        constexpr uint32_t kEnableFastDiversityBit = 0x80;

        struct RegisterMask
        {
                uint32_t offset;
                uint32_t mask;
                uint32_t bits;
        };

        bool fitsBar(uint32_t length, uint32_t offset)
        {
            return length >= sizeof(uint32_t) &&
                   offset <= length - sizeof(uint32_t);
        }

        bool permit(const RfIniBackend &io, BoardModalProgress &progress)
        {
            if (io.permitWrite(io.context, io.ownerEpoch))
            {
                return true;
            }
            progress.result = BoardModalResult::OwnershipLost;
            return false;
        }

        bool writeMasked(const RxAgcBackend &backend,
                         BoardModalProgress &progress,
                         const RegisterMask &operation)
        {
            const RfIniBackend &io = backend.io;
            progress.lastOffset = operation.offset;
            if (!permit(io, progress))
            {
                return false;
            }
            uint32_t before = 0;
            if (!backend.read32(io.context, operation.offset, &before))
            {
                progress.result = BoardModalResult::ReadFailed;
                return false;
            }
            ++progress.completedReads;
            const uint32_t desired =
                (before & ~operation.mask) | (operation.bits & operation.mask);
            if (!permit(io, progress))
            {
                return false;
            }
            // Once an MMIO callback has been called, even a reported failure
            // can have reached silicon. Retain the sticky reset obligation.
            progress.requiresReset = true;
            if (!io.write32(io.context, operation.offset, desired))
            {
                progress.result = BoardModalResult::WriteFailed;
                return false;
            }
            ++progress.completedWrites;
            if (!permit(io, progress))
            {
                return false;
            }
            uint32_t observed = 0;
            if (!backend.read32(io.context, operation.offset, &observed))
            {
                progress.result = BoardModalResult::ReadFailed;
                return false;
            }
            ++progress.completedReads;
            if ((observed & operation.mask) != (desired & operation.mask))
            {
                progress.result = BoardModalResult::ReadbackMismatch;
                return false;
            }
            return true;
        }
    } // namespace

    BoardModalProgress programAr9565BoardModal2G(
        const EepromImage &image, const CalibrationAndRegulatory &authorization,
        BoardModalDiversity diversity, const RxAgcBackend &backend)
    {
        BoardModalProgress progress {
            BoardModalResult::InvalidBackend, 0, 0, 0, false,
        };
        const RxAgcBackend stable = backend;
        const RfIniBackend &io = stable.io;
        if (io.context == nullptr || io.ownerEpoch == 0 ||
            io.permitWrite == nullptr || io.write32 == nullptr ||
            stable.read32 == nullptr)
        {
            return progress;
        }
        progress.result = BoardModalResult::InvalidBoard;
        BoardDataSummary board {};
        if (!image.restored || image.appliedBlocks == 0 ||
            summarizeBoardData(image, board) != EepromResult::Ok ||
            board.rxChainMask != kExpectedChainMask ||
            board.txChainMask != kExpectedChainMask ||
            !board.calibrationPierBinsPlausible ||
            board.ar9565AntennaDiversity != kExpectedAntennaOverride ||
            (diversity != BoardModalDiversity::WlanOnly &&
             diversity != BoardModalDiversity::SharedWithBluetooth))
        {
            return progress;
        }
        // No implicit TX, regulatory or Bluetooth permission. Provenance and
        // policy are established by the live owner, never from NVM parsing.
        progress.result = BoardModalResult::MissingAuthorization;
        if (authorization.use != RadioInitialization::ReceiveOnly ||
            !radioInitializationAuthorized(authorization))
        {
            return progress;
        }
        progress.result = BoardModalResult::InvalidBar;
        if (!fitsBar(io.barLengthBytes, kPhyGlbControl) ||
            !fitsBar(io.barLengthBytes, kPhySwitchCom) ||
            !fitsBar(io.barLengthBytes, kPhyExtAtten0) ||
            !fitsBar(io.barLengthBytes, kPhyXpaBiasTop) ||
            !fitsBar(io.barLengthBytes, kBtCoexLnaDiversity))
        {
            return progress;
        }

        const auto switchComSpdt = static_cast<uint16_t>(
            static_cast<uint32_t>(image.bytes[kSpdtOffset]) |
            (static_cast<uint32_t>(image.bytes[kSpdtOffset + 1])
             << kEightBits));
        const uint32_t attenuation = image.bytes[kAttenuationOffset];
        const uint32_t margin = image.bytes[kMarginOffset];
        const uint32_t xpaBias = image.bytes[kXpaBiasOffset];
        if (attenuation > kExtAttenField ||
            margin > (kExtMarginField >> kExtMarginShift) ||
            xpaBias > (kPhyXpaBiasMask >> kPhyXpaBiasShift))
        {
            progress.result = BoardModalResult::InvalidBoard;
            return progress;
        }

        const bool shared =
            diversity == BoardModalDiversity::SharedWithBluetooth;
        const uint32_t antenna = board.ar9565AntennaDiversity;
        const uint32_t gainFields =
            ((antenna & kDiversitySettings) << kGainDivShift) |
            (shared && (antenna & kEnableDiversityBit) != 0
                 ? kGainLnaDiv | kGainRxProtection
                 : 0U);
        const uint32_t fastDiversity =
            (shared || (antenna & kEnableFastDiversityBit) != 0)
                ? kCckFastDiversity
                : 0U;
        const RegisterMask operations[] {
            {
                kPhySwitchCom,
                kAntennaCommonField,
                board.antennaControlCommon,
            },
            {
                kPhySwitchCom2,
                kAntennaCommonField,
                board.antennaControlCommon2,
            },
            {
                kPhySwitchChain0,
                kAntennaChainField,
                board.antennaControlChain0,
            },
            {
                kPhyGlbControl,
                kSpdtField | kSpdtEnable,
                ((static_cast<uint32_t>(switchComSpdt) & kSpdtMask)
                 << kSpdtShift) |
                    kSpdtEnable,
            },
            {
                kPhyExtAtten0,
                kExtAttenField | kExtMarginField,
                attenuation | (margin << kExtMarginShift),
            },
            {kPhyXpaBiasTop, kPhyXpaBiasMask, xpaBias << kPhyXpaBiasShift},
            {
                kMcGainControl,
                kGainDivField | kGainLnaDiv | kGainRxProtection,
                gainFields,
            },
            {kCckDetect, kCckFastDiversity, fastDiversity},
            {
                kPhyRestart,
                kPhyRestartM2Flag,
                shared ? kPhyRestartM2Flag : 0U,
            },
            {
                kBtCoexLnaDiversity,
                kBtForceLnaDiversity,
                shared ? kBtForceLnaDiversity : 0U,
            },
        };

        progress.result = BoardModalResult::OwnershipLost;
        for (const RegisterMask &operation : operations)
        {
            if (!writeMasked(stable, progress, operation))
            {
                return progress;
            }
        }
        if (!permit(io, progress))
        {
            return progress;
        }
        progress.result = BoardModalResult::Ok;
        progress.requiresReset = false;
        return progress;
    }
} // namespace simpleath
