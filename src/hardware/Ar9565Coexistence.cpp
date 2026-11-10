// Hardware register provenance: Linux v6.12 ath9k reg_mci.h,
// ar9003_mci.c ar9003_mci_stop_bt() and ar9003_mci_2g5g_switch().
/*
 * Copyright (c) 2015 Qualcomm Atheros Inc.
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
#include "Ar9565Coexistence.hpp"
#include "Ar9565Calibration.hpp"
#include "Ar9565Eeprom.hpp"
#include "Ar9565RfIni.hpp"
#include <stdint.h>

namespace simpleath
{
    namespace
    {
        // MCI must not be started without programmed GPM/scheduler DMA,
        // interrupts, a negotiated antenna architecture and live BT owner.
        // Shared-DMA staging leaves MCI disabled and every IRQ masked.
        constexpr uint32_t kSelfGeneratedMask = 0x832c;
        constexpr uint32_t kMciInterruptEnable = 0x182c;
        constexpr uint32_t kMciScheduleAddress = 0x1818;
        constexpr uint32_t kMciGpmAddress = 0x1820;
        constexpr uint32_t kMciGpmEntries = 0x1824;
        constexpr uint32_t kMciModeEnable = 0x4U;
        constexpr uint32_t kMciDmaAlignmentMask = 0xfU;
        constexpr uint32_t kMciReceiveMessageEnable = 0x183c;
        constexpr uint32_t kMciRemoteCpuInterruptEnable = 0x1834;
        constexpr uint32_t kMciTransmitControl = 0x1810;
        constexpr uint32_t kMciDisableLnaUpdate = 0x4;
        constexpr uint32_t kBtCoexistenceControl = 0x18ac;
        constexpr uint32_t kBtCoexistenceControl2 = 0x1948;
        constexpr uint32_t kBtTransmitChainMask = 0x00380000;
        constexpr uint32_t kBtRxDeweight = 0x00400000;
        constexpr uint32_t kGlobalControl = 0x20044;
        constexpr uint32_t kBtOwnsSpdt = 0x2;
        constexpr uint32_t kBtLnaDiversity = 0x1a64;
        constexpr uint32_t kBtForceLnaDiversity = 0x8000;
        constexpr uint32_t kPhyRestart = 0x9e24;
        constexpr uint32_t kPhyRestartDiversityM2Flag = 0x00200000;
        constexpr uint8_t kSingleChain = 1;

        struct RegisterOperation
        {
                uint32_t offset;
                uint32_t mask;
                uint32_t value;
        };

        bool permit(const RfIniBackend &io, CoexistenceProgress &status)
        {
            if (io.permitWrite(io.context, io.ownerEpoch))
            {
                return true;
            }
            status.result = CoexistenceResult::OwnershipLost;
            return false;
        }

        bool apply(const RxAgcBackend &backend, CoexistenceProgress &status,
                   const RegisterOperation &operation)
        {
            const RfIniBackend &io = backend.io;
            status.lastOffset = operation.offset;
            if (!permit(io, status))
            {
                return false;
            }
            uint32_t previous = 0;
            if (!backend.read32(io.context, operation.offset, &previous))
            {
                status.result = CoexistenceResult::ReadFailed;
                return false;
            }
            ++status.completedReads;
            const uint32_t next = (previous & ~operation.mask) |
                                  (operation.value & operation.mask);
            if (!permit(io, status))
            {
                return false;
            }
            status.requiresReset = true;
            if (!io.write32(io.context, operation.offset, next))
            {
                status.result = CoexistenceResult::WriteFailed;
                return false;
            }
            ++status.completedWrites;
            if (!permit(io, status))
            {
                return false;
            }
            uint32_t observed = 0;
            if (!backend.read32(io.context, operation.offset, &observed))
            {
                status.result = CoexistenceResult::ReadFailed;
                return false;
            }
            ++status.completedReads;
            if ((observed & operation.mask) != (next & operation.mask))
            {
                status.result = CoexistenceResult::ReadbackMismatch;
                return false;
            }
            return true;
        }
    } // namespace

    CoexistenceProgress stageAr9565SharedMciDma(
        const BoardDataSummary &board, const SharedMciEvidence &evidence,
        const SharedMciDmaBuffers &buffers, const RxAgcBackend &backend)
    {
        CoexistenceProgress progress {
            CoexistenceResult::InvalidBackend, 0, 0, 0, false,
        };
        const RxAgcBackend stable = backend;
        const RfIniBackend &io = stable.io;
        if (io.context == nullptr || io.ownerEpoch == 0 ||
            io.permitWrite == nullptr || io.write32 == nullptr ||
            stable.read32 == nullptr)
        {
            return progress;
        }
        progress.result = CoexistenceResult::InvalidBoard;
        if (board.eepromVersion != 2 || board.txChainMask != kSingleChain ||
            board.rxChainMask != kSingleChain ||
            !board.calibrationPierBinsPlausible)
        {
            return progress;
        }
        progress.result = CoexistenceResult::MissingIsolation;
        if (!evidence.physicallyVerifiedBoard || !evidence.bluetoothHostOwned ||
            !evidence.coexistenceAndAntennaLease ||
            !evidence.macAndAutoResponsesQuiesced ||
            !evidence.mciEngineQuiesced || !evidence.initializedCoherentDma)
        {
            return progress;
        }
        // Linux ath_mci_setup allocates one contiguous coherent region and
        // programs schedule at its base, GPM at +256 bytes, 16 entries.
        // Require those exact physical lengths/ordering; never publish
        // guessed IOVAs or the CPU's virtual addresses to the silicon.
        progress.result = CoexistenceResult::InvalidDma;
        if (buffers.scheduleBytes != kAr9565MciScheduleBytes ||
            buffers.gpmBytes != kAr9565MciGpmBytes ||
            buffers.gpmEntries != kAr9565MciGpmEntries ||
            buffers.scheduleBusAddress == 0 ||
            (buffers.scheduleBusAddress & kMciDmaAlignmentMask) != 0 ||
            buffers.scheduleBusAddress >
                UINT32_MAX - (kAr9565MciScheduleBytes + kAr9565MciGpmBytes) ||
            buffers.gpmBusAddress !=
                buffers.scheduleBusAddress + kAr9565MciScheduleBytes)
        {
            return progress;
        }
        progress.result = CoexistenceResult::InvalidBar;
        if (io.barLengthBytes < kSelfGeneratedMask + sizeof(uint32_t))
        {
            return progress;
        }
        // Source: Linux ath9k ar9003_mci_reset and reg_mci.h. Disable
        // automatic responses and MCI message delivery BEFORE changing the
        // DMA registers. MCI stays OFF; the later live-BT handshake/reset
        // path must explicitly enable it after validating arbitration.
        const RegisterOperation operations[] {
            {kSelfGeneratedMask, 0xffffffffU, 0U},
            {kMciInterruptEnable, 0xffffffffU, 0U},
            {kMciReceiveMessageEnable, 0xffffffffU, 0U},
            {kMciRemoteCpuInterruptEnable, 0xffffffffU, 0U},
            {kBtCoexistenceControl, kMciModeEnable, 0U},
            {kMciGpmAddress, 0xffffffffU, buffers.gpmBusAddress},
            {kMciGpmEntries, 0xffffffffU, buffers.gpmEntries},
            {kMciScheduleAddress, 0xffffffffU, buffers.scheduleBusAddress},
        };
        progress.result = CoexistenceResult::OwnershipLost;
        for (const RegisterOperation &operation : operations)
        {
            if (!apply(stable, progress, operation))
            {
                return progress;
            }
        }
        if (!permit(io, progress))
        {
            return progress;
        }
        progress.result = CoexistenceResult::Ok;
        progress.requiresReset = false;
        return progress;
    }

    CoexistenceProgress
    parkAr9565WlanOnlyCoexistence(const BoardDataSummary &board,
                                  const WlanOnlyCoexistenceEvidence &evidence,
                                  const RxAgcBackend &backend)
    {
        CoexistenceProgress progress {
            CoexistenceResult::InvalidBackend, 0, 0, 0, false,
        };
        const RxAgcBackend stable = backend;
        const RfIniBackend &io = stable.io;
        if (io.context == nullptr || io.ownerEpoch == 0 ||
            io.permitWrite == nullptr || io.write32 == nullptr ||
            stable.read32 == nullptr)
        {
            return progress;
        }
        progress.result = CoexistenceResult::InvalidBoard;
        if (board.eepromVersion != 2 || board.txChainMask != kSingleChain ||
            board.rxChainMask != kSingleChain ||
            !board.calibrationPierBinsPlausible)
        {
            return progress;
        }
        progress.result = CoexistenceResult::MissingIsolation;
        if (!evidence.physicallyVerifiedBoard ||
            !evidence.bluetoothAbsentOrQuiesced ||
            !evidence.exclusiveWlanAntennaLease ||
            !evidence.macAndAutoResponsesQuiesced)
        {
            return progress;
        }
        // Last register in this phase is GLB_CONTROL at BAR 0x20044.
        progress.result = CoexistenceResult::InvalidBar;
        if (io.barLengthBytes < kGlobalControl + sizeof(uint32_t))
        {
            return progress;
        }
        // The order matters: no autonomous TX before disabling MCI control.
        // Clear ONLY known MCI/BT fields, preserving unrelated register bits.
        // Never disable the PCI master IRQ here: that belongs to NativeQueues.
        const RegisterOperation operations[] {
            {kSelfGeneratedMask, 0xffffffffU, 0U},
            {kMciInterruptEnable, 0xffffffffU, 0U},
            {kMciReceiveMessageEnable, 0xffffffffU, 0U},
            {kMciRemoteCpuInterruptEnable, 0xffffffffU, 0U},
            {kBtCoexistenceControl, 0xffffffffU, 0U},
            {kBtCoexistenceControl2, kBtTransmitChainMask | kBtRxDeweight, 0U},
            {kMciTransmitControl, kMciDisableLnaUpdate, kMciDisableLnaUpdate},
            {kGlobalControl, kBtOwnsSpdt, 0U},
            {kBtLnaDiversity, kBtForceLnaDiversity, 0U},
            {kPhyRestart, kPhyRestartDiversityM2Flag, 0U},
        };
        progress.result = CoexistenceResult::OwnershipLost;
        for (const RegisterOperation &operation : operations)
        {
            if (!apply(stable, progress, operation))
            {
                return progress;
            }
        }
        if (!permit(io, progress))
        {
            return progress;
        }
        progress.result = CoexistenceResult::Ok;
        progress.requiresReset = false;
        return progress;
    }
} // namespace simpleath
