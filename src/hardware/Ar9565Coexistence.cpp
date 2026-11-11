// Hardware register provenance: Linux v6.12 ath9k reg_mci.h,
// ar9003_mci.c ar9003_mci_stop_bt() and ar9003_mci_2g5g_switch().
/*
 * Copyright (c) 2008-2011 Atheros Communications Inc.
 * Copyright (c) 2010-2011 Atheros Communications Inc.
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
#include <stddef.h>
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
        constexpr uint32_t kBtCoexistenceControl3 = 0x1a60;
        constexpr uint32_t kPcuMisc = 0x8120;
        constexpr uint32_t kBtLnaTimeout = 0x1940;
        constexpr uint32_t kMciMessageAttributes = 0x1814;
        constexpr uint32_t kMciCommand2 = 0x1808;
        constexpr uint32_t kMciInterruptRaw = 0x1828;
        constexpr uint32_t kMciReceiveMessageRaw = 0x1838;
        constexpr uint32_t kMciCommand0 = 0x1800U;
        constexpr uint32_t kMciTxPayload0 = 0x1898U;
        constexpr uint32_t kMciReceiveStatus = 0x1844U;
        constexpr uint32_t kMciRemoteSleep = 0x00001000U;
        constexpr uint32_t kMciSent = 0x00000001U;
        constexpr uint32_t kMciMessageFailure = 0x000001b0U;
        constexpr uint32_t kMciTransmitStatusMask =
            kMciSent | kMciMessageFailure;
        constexpr uint32_t kMciGpmCommand = 0x00001080U;
        constexpr uint32_t kMciCoexAgent = 0x0cU;
        constexpr uint32_t kMciStatusQueryOpcode = 2U;
        constexpr uint32_t kMciBluetoothInformationMask = 3U;
        constexpr uint32_t kMciStatusQueryShift = 16U;
        constexpr uint32_t kMciOpcodeShift = 8U;
        constexpr uint32_t kMciTransmitPollMicros = 500U;
        constexpr uint32_t kMciPayloadWordBytes = 4U;
        constexpr uint32_t kMciTransmitPointerShift = 16U;
        constexpr uint32_t kMciInterruptRxMessage = 0x00000200U;
        constexpr uint32_t kMciReceiveGpmMessage = 0x00000100U;
        constexpr uint32_t kMciReceiveRemoteReset = 0x00000001U;
        constexpr uint32_t kMciReceiveReqWake = 0x00001000U;
        constexpr uint32_t kMciErrorMask = 0x800001bcU;
        constexpr uint32_t kMciInvalidReadValue = 0xdeadbeefU;
        constexpr uint32_t kMciResetTx = 0x1U;
        constexpr uint32_t kMciResetRx = 0x2U;
        constexpr uint32_t kMciGpmConfiguredLengthMask = 0x0000ffffU;
        constexpr uint32_t kBtTxChainMask = 0x00380000U;
        constexpr uint32_t kBtAntennaPreventsRx = 0x00100000U;
        constexpr uint32_t kBtLnaTimeoutMask = 0x003fffffU;
        constexpr uint32_t kBtContInfoTimeoutMask = 0x00000fffU;
        constexpr uint32_t kMciMessageAttributesValue = 0xe8010000U;
        constexpr uint32_t kBtSharedRxChain = 0x00000200U;
        constexpr uint32_t kBtMciBaseMode = 0x00000003U;
        constexpr uint32_t kBtSharedPaAndLna = 0x00000018U;
        constexpr uint32_t kBtOneAntenna = 0x00000080U;
        constexpr uint32_t kBtTwoAntennas = 0x00000100U;
        constexpr uint32_t kBtOneTxChain = 0x00080000U;
        constexpr uint32_t kBtLnaTimeoutValue = 0x0003d090U;
        constexpr uint32_t kBtContInfoTimeoutValue = 20U;
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

        bool validSharedDma(const SharedMciDmaBuffers &buffers)
        {
            return buffers.scheduleBytes == kAr9565MciScheduleBytes &&
                   buffers.gpmBytes == kAr9565MciGpmBytes &&
                   buffers.gpmEntries == kAr9565MciGpmEntries &&
                   buffers.scheduleBusAddress != 0U &&
                   (buffers.scheduleBusAddress & kMciDmaAlignmentMask) == 0U &&
                   buffers.scheduleBusAddress <=
                       UINT32_MAX -
                           (kAr9565MciScheduleBytes + kAr9565MciGpmBytes) &&
                   buffers.gpmBusAddress ==
                       buffers.scheduleBusAddress + kAr9565MciScheduleBytes;
        }

        bool permit(const RfIniBackend &io, CoexistenceProgress &status)
        {
            if (io.permitWrite(io.context, io.ownerEpoch))
            {
                return true;
            }
            status.result = CoexistenceResult::OwnershipLost;
            return false;
        }

        bool observe(const RxAgcBackend &backend, CoexistenceProgress &status,
                     const RegisterOperation &expected)
        {
            status.lastOffset = expected.offset;
            if (!permit(backend.io, status))
            {
                return false;
            }
            uint32_t actual = 0U;
            if (!backend.read32(backend.io.context, expected.offset, &actual))
            {
                status.result = CoexistenceResult::ReadFailed;
                return false;
            }
            ++status.completedReads;
            if ((actual & expected.mask) != (expected.value & expected.mask))
            {
                status.result = CoexistenceResult::ReadbackMismatch;
                return false;
            }
            return true;
        }

        bool readMciPendingRaw(const RxAgcBackend &backend,
                               CoexistenceProgress &status, uint32_t address,
                               uint32_t &value)
        {
            status.lastOffset = address;
            if (!permit(backend.io, status))
            {
                return false;
            }
            if (!backend.read32(backend.io.context, address, &value))
            {
                // An unreadable live MCI interrupt status is not idle.
                status.result = CoexistenceResult::ReadFailed;
                status.requiresReset = true;
                return false;
            }
            ++status.completedReads;
            if (value == kMciInvalidReadValue || value == UINT32_MAX)
            {
                status.result = CoexistenceResult::ReadbackMismatch;
                status.requiresReset = true;
                return false;
            }
            return true;
        }

        bool acknowledgeMciPendingRaw(const RxAgcBackend &backend,
                                      CoexistenceProgress &status,
                                      uint32_t address, uint32_t bits)
        {
            if (bits == 0U)
            {
                return true;
            }
            const RfIniBackend &io = backend.io;
            status.lastOffset = address;
            if (!permit(io, status))
            {
                return false;
            }
            status.requiresReset = true;
            if (!io.write32(io.context, address, bits))
            {
                status.result = CoexistenceResult::WriteFailed;
                return false;
            }
            ++status.completedWrites;
            if (!permit(io, status))
            {
                return false;
            }
            uint32_t after = 0U;
            if (!backend.read32(io.context, address, &after))
            {
                status.result = CoexistenceResult::ReadFailed;
                return false;
            }
            ++status.completedReads;
            if ((after & bits) != 0U)
            {
                status.result = CoexistenceResult::ReadbackMismatch;
                return false;
            }
            return true;
        }

        bool pulseMciReset(const RxAgcBackend &backend,
                           CoexistenceProgress &status, uint32_t bit)
        {
            const RfIniBackend &io = backend.io;
            status.lastOffset = kMciCommand2;
            if (!permit(io, status))
            {
                return false;
            }
            uint32_t original = 0U;
            if (!backend.read32(io.context, kMciCommand2, &original))
            {
                status.result = CoexistenceResult::ReadFailed;
                return false;
            }
            ++status.completedReads;
            if ((original & (kMciResetTx | kMciResetRx)) != 0U)
            {
                status.result = CoexistenceResult::ReadbackMismatch;
                return false;
            }
            if (!permit(io, status))
            {
                return false;
            }
            status.requiresReset = true;
            if (!io.write32(io.context, kMciCommand2, original | bit))
            {
                status.result = CoexistenceResult::WriteFailed;
                return false;
            }
            ++status.completedWrites;
            if (!permit(io, status))
            {
                return false;
            }
            io.delayMicros(io.context, 1U);
            if (!permit(io, status))
            {
                return false;
            }
            if (!io.write32(io.context, kMciCommand2, original))
            {
                status.result = CoexistenceResult::WriteFailed;
                return false;
            }
            ++status.completedWrites;
            return observe(backend, status,
                           {kMciCommand2, kMciResetTx | kMciResetRx, 0U});
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

        bool validMciTransmitLease(const SharedMciEvidence &evidence,
                                   const MciGpmCursor &cursor,
                                   const MciCoexTransmitEvidence &transmit,
                                   uint64_t epoch)
        {
            return evidence.physicallyVerifiedBoard &&
                   evidence.bluetoothHostOwned &&
                   evidence.coexistenceAndAntennaLease &&
                   evidence.macAndAutoResponsesQuiesced &&
                   evidence.initializedCoherentDma &&
                   transmit.bluetoothAwakeFromHost &&
                   transmit.exclusiveMciCommandLease &&
                   transmit.noOutstandingMciCommands && cursor.attached &&
                   cursor.ownerEpoch == epoch &&
                   cursor.nextIndex < kAr9565MciGpmEntries;
        }

        bool writeMciCoexCommand(const RxAgcBackend &stable,
                                 CoexistenceProgress &progress,
                                 MciCoexQuery query)
        {
            const RfIniBackend &io = stable.io;
            // Linux ath9k ar9003_mci_send_message: four little-endian GPM
            // payload words, followed by AR_MCI_COMMAND0 (header 0x80, len 16).
            // Version query opcode 0, status query opcode 2. Its bitmap asks
            // Bluetooth for ALL_INFO and physical antenna topology, not a
            // locally invented response or readiness grant.
            const uint32_t word =
                kMciCoexAgent |
                ((query == MciCoexQuery::BluetoothStatus ? kMciStatusQueryOpcode
                                                         : 0U)
                 << kMciOpcodeShift) |
                ((query == MciCoexQuery::BluetoothStatus
                      ? kMciBluetoothInformationMask
                      : 0U)
                 << kMciStatusQueryShift);
            for (uint32_t index = 0U; index < 4U; ++index)
            {
                progress.lastOffset =
                    kMciTxPayload0 + (index * kMciPayloadWordBytes);
                if (!permit(io, progress))
                {
                    return false;
                }
                progress.requiresReset = true;
                if (!io.write32(io.context, progress.lastOffset,
                                index == 1U ? word : 0U))
                {
                    progress.result = CoexistenceResult::WriteFailed;
                    return false;
                }
                ++progress.completedWrites;
                // The command register must never latch a partial/stale
                // payload. Drain each posted TX word and verify it before
                // allowing the MCI engine to transmit.
                if (!permit(io, progress))
                {
                    return false;
                }
                uint32_t observed = 0U;
                if (!stable.read32(io.context, progress.lastOffset, &observed))
                {
                    progress.result = CoexistenceResult::ReadFailed;
                    return false;
                }
                ++progress.completedReads;
                if (observed != (index == 1U ? word : 0U))
                {
                    progress.result = CoexistenceResult::ReadbackMismatch;
                    return false;
                }
            }
            progress.lastOffset = kMciCommand0;
            if (!permit(io, progress))
            {
                return false;
            }
            if (!io.write32(io.context, kMciCommand0, kMciGpmCommand))
            {
                progress.result = CoexistenceResult::WriteFailed;
                return false;
            }
            ++progress.completedWrites;
            return true;
        }

        bool waitMciCoexCommand(const RxAgcBackend &stable,
                                CoexistenceProgress &progress)
        {
            const RfIniBackend &io = stable.io;
            uint32_t raw = 0U;
            uint32_t receiveStatus = 0U;
            for (uint32_t index = 0U; index < kMciTransmitPollMicros; ++index)
            {
                if (!readMciPendingRaw(stable, progress, kMciInterruptRaw, raw))
                {
                    return false;
                }
                const uint32_t commandStatus = raw & kMciTransmitStatusMask;
                if (commandStatus != 0U)
                {
                    if (!acknowledgeMciPendingRaw(
                            stable, progress, kMciInterruptRaw, commandStatus))
                    {
                        return false;
                    }
                    if ((commandStatus & kMciMessageFailure) != 0U)
                    {
                        progress.result = CoexistenceResult::MessageRejected;
                        return false;
                    }
                    if (!readMciPendingRaw(stable, progress, kMciReceiveStatus,
                                           receiveStatus))
                    {
                        return false;
                    }
                    if ((receiveStatus & kMciRemoteSleep) != 0U ||
                        !permit(io, progress))
                    {
                        progress.result = CoexistenceResult::MissingIsolation;
                        return false;
                    }
                    progress.result = CoexistenceResult::Ok;
                    progress.requiresReset = false;
                    return true;
                }
                if (!permit(io, progress))
                {
                    return false;
                }
                io.delayMicros(io.context, 1U);
            }
            progress.result = CoexistenceResult::TimedOut;
            return false;
        }

        bool readMciOrRevoke(const RxAgcBackend &backend,
                             CoexistenceProgress &progress,
                             MciGpmCursor &cursor, uint32_t address,
                             uint32_t &value)
        {
            if (readMciPendingRaw(backend, progress, address, value))
            {
                return true;
            }
            if (progress.requiresReset)
            {
                cursor.attached = false;
            }
            return false;
        }

        bool acknowledgeMciOrRevoke(const RxAgcBackend &backend,
                                    CoexistenceProgress &progress,
                                    MciGpmCursor &cursor, uint32_t mask)
        {
            if (acknowledgeMciPendingRaw(backend, progress, kMciInterruptRaw,
                                         mask))
            {
                return true;
            }
            if (progress.requiresReset)
            {
                cursor.attached = false;
            }
            return false;
        }

        bool submitMciOrRevoke(const RxAgcBackend &backend,
                               CoexistenceProgress &progress,
                               MciGpmCursor &cursor, MciCoexQuery query)
        {
            if (writeMciCoexCommand(backend, progress, query) &&
                waitMciCoexCommand(backend, progress))
            {
                // Synchronous MMIO/BT callbacks may revoke the cursor during
                // command completion without changing the owner epoch. Never
                // publish success for a detached or replaced GPM owner.
                if (cursor.attached &&
                    cursor.ownerEpoch == backend.io.ownerEpoch)
                {
                    return true;
                }
                progress.result = CoexistenceResult::OwnershipLost;
                progress.requiresReset = true;
            }
            if (progress.requiresReset)
            {
                // A caller ignoring requiresReset cannot reuse this cursor.
                cursor.attached = false;
            }
            return false;
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
        if (!validSharedDma(buffers))
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

    CoexistenceProgress stageAr9565SharedMciAntenna(
        const BoardDataSummary &board, const SharedMciEvidence &evidence,
        const SharedMciDmaBuffers &buffers,
        const SharedMciAntennaSelection &antenna, const RxAgcBackend &backend)
    {
        CoexistenceProgress progress {
            CoexistenceResult::InvalidBackend, 0, 0, 0, false,
        };
        const RxAgcBackend stable = backend;
        const RfIniBackend &io = stable.io;
        if (io.context == nullptr || io.ownerEpoch == 0U ||
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
            !evidence.mciEngineQuiesced || !evidence.initializedCoherentDma ||
            !antenna.physicallyVerifiedTopology ||
            antenna.topology == SharedMciAntennaTopology::Unknown)
        {
            return progress;
        }
        progress.result = CoexistenceResult::InvalidDma;
        if (!validSharedDma(buffers))
        {
            return progress;
        }
        progress.result = CoexistenceResult::InvalidBar;
        if (io.barLengthBytes < kGlobalControl + sizeof(uint32_t))
        {
            return progress;
        }
        // The same live owner must still observe exactly the disabled,
        // DMA-staged controller. A prior successful stage return is not a
        // substitute for checking the actual registers in this epoch.
        const RegisterOperation staged[] {
            {kSelfGeneratedMask, 0xffffffffU, 0U},
            {kMciInterruptEnable, 0xffffffffU, 0U},
            {kMciReceiveMessageEnable, 0xffffffffU, 0U},
            {kMciRemoteCpuInterruptEnable, 0xffffffffU, 0U},
            {kBtCoexistenceControl, kMciModeEnable, 0U},
            {kMciGpmAddress, 0xffffffffU, buffers.gpmBusAddress},
            {kMciGpmEntries, kMciGpmConfiguredLengthMask, buffers.gpmEntries},
            {kMciScheduleAddress, 0xffffffffU, buffers.scheduleBusAddress},
        };
        progress.result = CoexistenceResult::OwnershipLost;
        for (const RegisterOperation &expected : staged)
        {
            if (!observe(stable, progress, expected))
            {
                return progress;
            }
        }
        const bool oneShared =
            antenna.topology == SharedMciAntennaTopology::OneSharedPaAndLna;
        if (!oneShared &&
            antenna.topology != SharedMciAntennaTopology::TwoIndependent)
        {
            progress.result = CoexistenceResult::MissingIsolation;
            return progress;
        }
        // Pinned Linux ath9k ar9003_mci_set_btcoex_ctrl_9565_{1,2}ANT
        // and ar9003_mci_reset. Do not enable MCI mode or interrupts here:
        // RX/TX reset, Bluetooth GPM negotiation and power-policy ownership
        // must occur later, under the same independently verified lease.
        const RegisterOperation operations[] {
            {
                kBtCoexistenceControl2,
                kBtTxChainMask | kBtRxDeweight,
                oneShared ? kBtOneTxChain : 0U,
            },
            {
                kBtCoexistenceControl,
                0xffffffffU,
                kBtMciBaseMode | kBtSharedRxChain |
                    (oneShared ? kBtSharedPaAndLna | kBtOneAntenna
                               : kBtTwoAntennas),
            },
            {kGlobalControl, 0x1U, 0x1U},
            {
                kBtCoexistenceControl3,
                kBtContInfoTimeoutMask,
                kBtContInfoTimeoutValue,
            },
            {kPcuMisc, kBtAntennaPreventsRx, 0U},
            {kBtLnaTimeout, kBtLnaTimeoutMask, kBtLnaTimeoutValue},
            {
                kMciMessageAttributes,
                0xffffffffU,
                kMciMessageAttributesValue,
            },
            {
                kMciTransmitControl,
                kMciDisableLnaUpdate,
                oneShared ? 0U : kMciDisableLnaUpdate,
            },
        };
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
    resetAr9565SharedMciRxTx(const BoardDataSummary &board,
                             const SharedMciEvidence &evidence,
                             const SharedMciDmaBuffers &buffers,
                             const SharedMciAntennaSelection &antenna,
                             const SharedMciResetEvidence &resetEvidence,
                             const RxAgcBackend &backend, MciGpmCursor &cursor)
    {
        CoexistenceProgress progress {
            CoexistenceResult::InvalidBackend, 0, 0, 0, false,
        };
        const RxAgcBackend stable = backend;
        const RfIniBackend &io = stable.io;
        if (io.context == nullptr || io.ownerEpoch == 0U ||
            io.permitWrite == nullptr || io.write32 == nullptr ||
            io.delayMicros == nullptr || stable.read32 == nullptr)
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
        const bool oneShared =
            antenna.topology == SharedMciAntennaTopology::OneSharedPaAndLna;
        progress.result = CoexistenceResult::MissingIsolation;
        if (!evidence.physicallyVerifiedBoard || !evidence.bluetoothHostOwned ||
            !evidence.coexistenceAndAntennaLease ||
            !evidence.macAndAutoResponsesQuiesced ||
            !evidence.mciEngineQuiesced || !evidence.initializedCoherentDma ||
            !antenna.physicallyVerifiedTopology ||
            (!oneShared &&
             antenna.topology != SharedMciAntennaTopology::TwoIndependent) ||
            !resetEvidence.bluetoothControllerQuiesced ||
            !resetEvidence.pendingGpmTrafficSettled)
        {
            return progress;
        }
        progress.result = CoexistenceResult::InvalidDma;
        if (!validSharedDma(buffers))
        {
            return progress;
        }
        progress.result = CoexistenceResult::InvalidBar;
        if (io.barLengthBytes < kGlobalControl + sizeof(uint32_t))
        {
            return progress;
        }
        // Verify physical DMA and AR9565 antenna stage were both completed
        // and remain quiesced. Nothing is trusted from the caller's old
        // result value, and every read checks the live owner epoch.
        const RegisterOperation expected[] {
            {kSelfGeneratedMask, 0xffffffffU, 0U},
            {kMciInterruptEnable, 0xffffffffU, 0U},
            {kMciReceiveMessageEnable, 0xffffffffU, 0U},
            {kMciRemoteCpuInterruptEnable, 0xffffffffU, 0U},
            {
                kBtCoexistenceControl,
                0xffffffffU,
                kBtMciBaseMode | kBtSharedRxChain |
                    (oneShared ? kBtSharedPaAndLna | kBtOneAntenna
                               : kBtTwoAntennas),
            },
            {
                kBtCoexistenceControl2,
                kBtTxChainMask | kBtRxDeweight,
                oneShared ? kBtOneTxChain : 0U,
            },
            {kGlobalControl, 0x1U, 0x1U},
            {kMciMessageAttributes, 0xffffffffU, kMciMessageAttributesValue},
            {
                kMciTransmitControl,
                kMciDisableLnaUpdate,
                oneShared ? 0U : kMciDisableLnaUpdate,
            },
            {kMciGpmAddress, 0xffffffffU, buffers.gpmBusAddress},
            {kMciGpmEntries, kMciGpmConfiguredLengthMask, buffers.gpmEntries},
            {kMciScheduleAddress, 0xffffffffU, buffers.scheduleBusAddress},
        };
        progress.result = CoexistenceResult::OwnershipLost;
        for (const RegisterOperation &item : expected)
        {
            if (!observe(stable, progress, item))
            {
                return progress;
            }
        }
        // All preflight checks succeeded. From the first write onward, any
        // old GPM view is invalid, including when the new reset fails.
        cursor = {};
        if (!apply(stable, progress,
                   {kBtCoexistenceControl, kMciModeEnable, kMciModeEnable}))
        {
            return progress;
        }
        if (!pulseMciReset(stable, progress, kMciResetTx) ||
            !pulseMciReset(stable, progress, kMciResetRx))
        {
            return progress;
        }
        progress.lastOffset = kMciGpmEntries;
        if (!permit(io, progress))
        {
            return progress;
        }
        uint32_t head = 0U;
        if (!stable.read32(io.context, kMciGpmEntries, &head))
        {
            progress.result = CoexistenceResult::ReadFailed;
            return progress;
        }
        ++progress.completedReads;
        MciGpmCursor fresh {};
        if (attachAr9565MciGpm(io.ownerEpoch, head, fresh) !=
            MciGpmResult::Empty)
        {
            progress.result = CoexistenceResult::InvalidGpm;
            return progress;
        }
        if (!permit(io, progress))
        {
            return progress;
        }
        cursor = fresh;
        progress.result = CoexistenceResult::Ok;
        progress.requiresReset = false;
        return progress;
    }

    CoexistenceProgress sendAr9565MciCoexQuery(
        const BoardDataSummary &board, const SharedMciEvidence &evidence,
        const SharedMciDmaBuffers &buffers, MciGpmCursor &cursor,
        const MciCoexTransmitEvidence &transmit, MciCoexQuery query,
        const RxAgcBackend &backend)
    {
        CoexistenceProgress progress {
            CoexistenceResult::InvalidBackend, 0, 0, 0, false,
        };
        const RxAgcBackend stable = backend;
        const RfIniBackend &io = stable.io;
        if (io.context == nullptr || io.ownerEpoch == 0U ||
            io.permitWrite == nullptr || io.write32 == nullptr ||
            io.delayMicros == nullptr || stable.read32 == nullptr)
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
        if (!validMciTransmitLease(evidence, cursor, transmit, io.ownerEpoch))
        {
            return progress;
        }
        progress.result = CoexistenceResult::InvalidGpm;
        if (query != MciCoexQuery::Version &&
            query != MciCoexQuery::BluetoothStatus)
        {
            return progress;
        }
        progress.result = CoexistenceResult::InvalidDma;
        if (!validSharedDma(buffers))
        {
            return progress;
        }
        progress.result = CoexistenceResult::InvalidBar;
        if (io.barLengthBytes < kSelfGeneratedMask + sizeof(uint32_t))
        {
            return progress;
        }
        const RegisterOperation expected[] {
            {kSelfGeneratedMask, 0xffffffffU, 0U},
            {kMciInterruptEnable, 0xffffffffU, 0U},
            {kMciReceiveMessageEnable, 0xffffffffU, 0U},
            {kMciRemoteCpuInterruptEnable, 0xffffffffU, 0U},
            {kBtCoexistenceControl, kMciModeEnable, kMciModeEnable},
            {kMciGpmAddress, 0xffffffffU, buffers.gpmBusAddress},
            {kMciGpmEntries, kMciGpmConfiguredLengthMask, buffers.gpmEntries},
            {kMciScheduleAddress, 0xffffffffU, buffers.scheduleBusAddress},
        };
        progress.result = CoexistenceResult::OwnershipLost;
        for (const RegisterOperation &check : expected)
        {
            if (!observe(stable, progress, check))
            {
                return progress;
            }
        }
        uint32_t receiveStatus = 0U;
        if (!readMciOrRevoke(stable, progress, cursor, kMciReceiveStatus,
                             receiveStatus))
        {
            return progress;
        }
        progress.result = CoexistenceResult::MissingIsolation;
        if ((receiveStatus & kMciRemoteSleep) != 0U)
        {
            return progress;
        }
        uint32_t currentGpm = 0U;
        if (!readMciOrRevoke(stable, progress, cursor, kMciGpmEntries,
                             currentGpm))
        {
            return progress;
        }
        progress.result = CoexistenceResult::InvalidGpm;
        if ((currentGpm & kMciGpmConfiguredLengthMask) != buffers.gpmEntries ||
            (currentGpm >> kMciTransmitPointerShift) >= buffers.gpmEntries)
        {
            return progress;
        }
        uint32_t raw = 0U;
        if (!readMciOrRevoke(stable, progress, cursor, kMciInterruptRaw, raw))
        {
            return progress;
        }
        // Clear ONLY old command completion/failure W1C bits. Any other
        // interrupt remains pending for the independent RX/MCI consumer.
        if (!acknowledgeMciOrRevoke(stable, progress, cursor,
                                    raw & kMciTransmitStatusMask))
        {
            return progress;
        }
        if (!submitMciOrRevoke(stable, progress, cursor, query))
        {
            return progress;
        }
        return progress;
    }

    MciPendingInterrupts pollAr9565MciPendingInterrupts(
        const SharedMciEvidence &evidence, const SharedMciDmaBuffers &buffers,
        const MciGpmCursor &cursor, const RxAgcBackend &backend)
    {
        MciPendingInterrupts result {};
        result.progress.result = CoexistenceResult::InvalidBackend;
        const RxAgcBackend stable = backend;
        const RfIniBackend &io = stable.io;
        if (io.context == nullptr || io.ownerEpoch == 0U ||
            io.permitWrite == nullptr || io.write32 == nullptr ||
            stable.read32 == nullptr)
        {
            return result;
        }
        result.progress.result = CoexistenceResult::MissingIsolation;
        if (!evidence.physicallyVerifiedBoard || !evidence.bluetoothHostOwned ||
            !evidence.coexistenceAndAntennaLease ||
            !evidence.macAndAutoResponsesQuiesced ||
            !evidence.initializedCoherentDma || !cursor.attached ||
            cursor.ownerEpoch != io.ownerEpoch ||
            cursor.nextIndex >= kAr9565MciGpmEntries)
        {
            return result;
        }
        result.progress.result = CoexistenceResult::InvalidDma;
        if (!validSharedDma(buffers))
        {
            return result;
        }
        result.progress.result = CoexistenceResult::InvalidBar;
        if (io.barLengthBytes < kSelfGeneratedMask + sizeof(uint32_t))
        {
            return result;
        }
        const RegisterOperation expected[] {
            {kSelfGeneratedMask, 0xffffffffU, 0U},
            {kMciInterruptEnable, 0xffffffffU, 0U},
            {kMciReceiveMessageEnable, 0xffffffffU, 0U},
            {kMciRemoteCpuInterruptEnable, 0xffffffffU, 0U},
            {kBtCoexistenceControl, kMciModeEnable, kMciModeEnable},
            {kMciGpmAddress, 0xffffffffU, buffers.gpmBusAddress},
            {kMciGpmEntries, kMciGpmConfiguredLengthMask, buffers.gpmEntries},
            {kMciScheduleAddress, 0xffffffffU, buffers.scheduleBusAddress},
        };
        result.progress.result = CoexistenceResult::OwnershipLost;
        for (const RegisterOperation &item : expected)
        {
            if (!observe(stable, result.progress, item))
            {
                return result;
            }
        }
        uint32_t rawMessage = 0U;
        uint32_t rawInterrupt = 0U;
        if (!readMciPendingRaw(stable, result.progress, kMciReceiveMessageRaw,
                               rawMessage) ||
            !readMciPendingRaw(stable, result.progress, kMciInterruptRaw,
                               rawInterrupt))
        {
            return result;
        }
        // Device RAW registers are W1C, never RMW. The owner checks each
        // acknowledgement and readback before declaring the snapshot valid.
        if (!acknowledgeMciPendingRaw(stable, result.progress,
                                      kMciReceiveMessageRaw, rawMessage) ||
            !acknowledgeMciPendingRaw(stable, result.progress, kMciInterruptRaw,
                                      rawInterrupt) ||
            !permit(io, result.progress))
        {
            return result;
        }
        // Only publish a copied status after both W1C acknowledgements
        // succeeded. Failed/revoked acknowledgements return no actionable
        // GPM or Bluetooth status, regardless of the speculative snapshot.
        result.rawMessageInterrupt = rawMessage;
        result.rawInterrupt = rawInterrupt;
        result.gpmNotification = (rawMessage & kMciReceiveGpmMessage) != 0U &&
                                 (rawInterrupt & kMciInterruptRxMessage) != 0U;
        result.bluetoothRenegotiationRequired =
            (rawMessage & (kMciReceiveRemoteReset | kMciReceiveReqWake)) != 0U;
        result.hardwareFault = (rawInterrupt & kMciErrorMask) != 0U;
        result.progress.result = CoexistenceResult::Ok;
        result.progress.requiresReset = result.hardwareFault;
        return result;
    }

    namespace
    {
        constexpr uint16_t kMciGpmReservedPointer = 0xffffU;
        constexpr uint8_t kMciGpmReservedType = 0xfeU;
        constexpr size_t kMciGpmEntryBytes = kAr9565MciGpmMessageBytes;
        constexpr size_t kMciGpmTypeByte = 4U;
        constexpr size_t kMciGpmOpcodeByte = 5U;
        constexpr uint32_t kMciGpmLengthMask = 0xffffU;
        constexpr uint32_t kMciGpmPointerShift = 16U;
        constexpr size_t kCoexMajorByte = 6U;
        constexpr size_t kCoexMinorByte = 7U;
        constexpr size_t kCoexStatusTypeByte = 6U;
        constexpr size_t kCoexStatusHandleByte = 7U;
        constexpr size_t kCoexStatusStateByte = 8U;
        constexpr size_t kCoexSequence0 = 12U;
        constexpr size_t kCoexSequence1 = 13U;
        constexpr size_t kCoexSequence2 = 14U;
        constexpr size_t kCoexSequence3 = 15U;
        constexpr uint32_t kCoexSequenceShift1 = 8U;
        constexpr uint32_t kCoexSequenceShift2 = 16U;
        constexpr uint32_t kCoexSequenceShift3 = 24U;
        constexpr uint8_t kCoexProfileMax = 7U;
        constexpr uint8_t kCoexStatusHandleMax = 8U;
        constexpr uint8_t kCoexOpcodeVersionQuery = 0U;
        constexpr uint8_t kCoexOpcodeVersionResponse = 1U;
        constexpr uint8_t kCoexOpcodeStatusQuery = 2U;
        constexpr uint8_t kCoexOpcodeProfileInfo = 5U;
        constexpr uint8_t kCoexOpcodeStatusUpdate = 6U;

        bool validGpmRegister(uint32_t gpmRegister)
        {
            const uint32_t entries = gpmRegister & kMciGpmLengthMask;
            const uint32_t writePointer = gpmRegister >> kMciGpmPointerShift;
            return entries == kAr9565MciGpmEntries &&
                   writePointer < kAr9565MciGpmEntries &&
                   writePointer != kMciGpmReservedPointer;
        }

        // Comparing numeric pointer values is safe even when the memory
        // spans are distinct objects. Never subtract unrelated C++ pointers.
        bool overlapsGpm(const void *a, size_t aBytes, const void *b,
                         size_t bBytes)
        {
            if (a == nullptr || b == nullptr || aBytes == 0U || bBytes == 0U)
            {
                return false;
            }
            uintptr_t left = 0U;
            uintptr_t right = 0U;
            static_assert(sizeof(left) == sizeof(a), "pointer width");
            __builtin_memcpy(&left, static_cast<const void *>(&a),
                             sizeof(left));
            __builtin_memcpy(&right, static_cast<const void *>(&b),
                             sizeof(right));
            return left <= right ? right - left < aBytes
                                 : left - right < bBytes;
        }

        const uint8_t *gpmSlot(const uint8_t *ring, size_t index)
        {
            // Only called after the full 16x16 ring and index were bounded.
            // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            return ring + (index * kMciGpmEntryBytes);
        }
    } // namespace

    MciGpmDiagnostic inspectAr9565MciGpm(uint64_t ownerEpoch,
                                         const MciGpmCursor &cursor,
                                         const MciGpmMessage &message)
    {
        MciGpmDiagnostic diagnostic {};
        diagnostic.kind = MciGpmDiagnosticKind::OwnershipLost;
        if (ownerEpoch == 0U || !cursor.attached ||
            cursor.ownerEpoch != ownerEpoch ||
            cursor.nextIndex >= kAr9565MciGpmEntries)
        {
            return diagnostic;
        }
        diagnostic.kind = MciGpmDiagnosticKind::InvalidPayload;
        if (message.type != message.payload[kMciGpmTypeByte] ||
            message.opcode != message.payload[kMciGpmOpcodeByte])
        {
            return diagnostic;
        }
        diagnostic.kind = MciGpmDiagnosticKind::Unrelated;
        if (message.type != kMciCoexAgent)
        {
            return diagnostic;
        }
        // Linux ath9k ar9003_mci_process_gpm_extra / ath_mci_msg.
        // These MCI opcode interpretations are diagnostics ONLY, never
        // evidence that a sent query has been answered or that BT is ready.
        switch (message.opcode)
        {
            case kCoexOpcodeVersionQuery: // MCI_GPM_COEX_VERSION_QUERY
                diagnostic.kind = MciGpmDiagnosticKind::PeerVersionQuery;
                break;
            case kCoexOpcodeVersionResponse: // MCI_GPM_COEX_VERSION_RESPONSE
                diagnostic.kind =
                    MciGpmDiagnosticKind::BluetoothVersionResponse;
                diagnostic.versionMajor = message.payload[kCoexMajorByte];
                diagnostic.versionMinor = message.payload[kCoexMinorByte];
                break;
            case kCoexOpcodeStatusQuery: // MCI_GPM_COEX_STATUS_QUERY
                diagnostic.kind = MciGpmDiagnosticKind::PeerStatusQuery;
                break;
            case kCoexOpcodeProfileInfo: // MCI_GPM_COEX_BT_PROFILE_INFO
                diagnostic.profileType = message.payload[kCoexStatusTypeByte];
                if (diagnostic.profileType == 0U ||
                    diagnostic.profileType >= kCoexProfileMax)
                {
                    diagnostic = {};
                    diagnostic.kind = MciGpmDiagnosticKind::InvalidPayload;
                    return diagnostic;
                }
                diagnostic.linkId = message.payload[kCoexStatusHandleByte];
                diagnostic.kind = MciGpmDiagnosticKind::BluetoothProfileNotice;
                break;
            case kCoexOpcodeStatusUpdate: // MCI_GPM_COEX_BT_STATUS_UPDATE
                // ath_mci_process_status accepts only eight host profile
                // handles; link-status messages are informational, never
                // authority to alter the host radio priority state here.
                if (message.payload[kCoexStatusTypeByte] > 1U ||
                    message.payload[kCoexStatusStateByte] > 1U ||
                    (message.payload[kCoexStatusTypeByte] == 0U &&
                     message.payload[kCoexStatusHandleByte] >=
                         kCoexStatusHandleMax))
                {
                    diagnostic.kind = MciGpmDiagnosticKind::InvalidPayload;
                    return diagnostic;
                }
                diagnostic.kind = MciGpmDiagnosticKind::BluetoothStatusNotice;
                diagnostic.isLinkStatus =
                    message.payload[kCoexStatusTypeByte] != 0U;
                diagnostic.linkId = message.payload[kCoexStatusHandleByte];
                diagnostic.isCritical =
                    message.payload[kCoexStatusStateByte] != 0U;
                diagnostic.sequence =
                    static_cast<uint32_t>(message.payload[kCoexSequence0]) |
                    (static_cast<uint32_t>(message.payload[kCoexSequence1])
                     << kCoexSequenceShift1) |
                    (static_cast<uint32_t>(message.payload[kCoexSequence2])
                     << kCoexSequenceShift2) |
                    (static_cast<uint32_t>(message.payload[kCoexSequence3])
                     << kCoexSequenceShift3);
                break;
            default:
                break;
        }
        return diagnostic;
    }

    MciGpmResult attachAr9565MciGpm(uint64_t ownerEpoch, uint32_t gpmRegister,
                                    MciGpmCursor &cursor)
    {
        if (ownerEpoch == 0U)
        {
            return MciGpmResult::InvalidArgument;
        }
        if (!validGpmRegister(gpmRegister))
        {
            return MciGpmResult::InvalidRegister;
        }
        cursor = {
            ownerEpoch,
            static_cast<uint16_t>(gpmRegister >> kMciGpmPointerShift),
            true,
        };
        return MciGpmResult::Empty;
    }

    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    MciGpmResult nextAr9565MciGpm(uint64_t ownerEpoch, uint32_t gpmRegister,
                                  const uint8_t *synchronizedRing,
                                  size_t ringBytes, MciGpmCursor &cursor,
                                  MciGpmMessage &out)
    {
        if (overlapsGpm(&cursor, sizeof(cursor), &out, sizeof(out)) ||
            overlapsGpm(synchronizedRing, ringBytes, &cursor, sizeof(cursor)) ||
            overlapsGpm(synchronizedRing, ringBytes, &out, sizeof(out)) ||
            synchronizedRing == nullptr || ringBytes != kAr9565MciGpmBytes)
        {
            return MciGpmResult::InvalidArgument;
        }
        if (!cursor.attached)
        {
            return MciGpmResult::NotAttached;
        }
        if (ownerEpoch == 0U || ownerEpoch != cursor.ownerEpoch)
        {
            return MciGpmResult::OwnershipLost;
        }
        if (!validGpmRegister(gpmRegister) ||
            cursor.nextIndex >= kAr9565MciGpmEntries)
        {
            return MciGpmResult::InvalidRegister;
        }
        const auto head =
            static_cast<uint16_t>(gpmRegister >> kMciGpmPointerShift);
        uint16_t readIndex = cursor.nextIndex;
        while (readIndex != head)
        {
            // Snapshot the complete shared-DMA entry before advancing the
            // cursor. Never expose a borrowed DMA pointer to a BT consumer.
            MciGpmMessage candidate {};
            __builtin_memcpy(&candidate.payload[0],
                             gpmSlot(synchronizedRing, readIndex),
                             sizeof(candidate.payload));
            candidate.type = candidate.payload[kMciGpmTypeByte];
            candidate.opcode = candidate.payload[kMciGpmOpcodeByte];
            readIndex =
                static_cast<uint16_t>((readIndex + 1U) % kAr9565MciGpmEntries);
            if (candidate.type != kMciGpmReservedType)
            {
                out = candidate;
                cursor.nextIndex = readIndex;
                return MciGpmResult::Message;
            }
        }
        cursor.nextIndex = readIndex;
        out = {};
        return MciGpmResult::Empty;
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
