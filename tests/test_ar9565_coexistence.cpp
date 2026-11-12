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
//   - Offline regression cases for ar9565 coexistence.
// - Must-Not:
//   - Require physical hardware, mutate installed drivers, or suppress
//     failures.
// - Allows:
//   - Inputs: isolated fixtures and reproducible source-under-test inputs.
//   - Outputs: assertions and observable regression verdicts.
//   - Side effects: test-local temporary files and bounded subprocesses only.
// - Split-When:
//   - A separate protocol stage needs independent validation and ownership.
// - Merge-When:
//   - The caller directly owns this narrow contract without reuse.
// - Summary:
//   - Offline regression cases for ar9565 coexistence.
// - Description:
//   - Implements or verifies the test_ar9565_coexistence source boundary.
// - Usage:
//   - Executed by offline host test discovery or the native test harness.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Offline regression cases for ar9565 coexistence.

// Synthetic AR9565 MCI register model; not a real Bluetooth or PCI device.
#include "hardware/Ar9565Calibration.hpp"
#include "hardware/Ar9565Coexistence.hpp"
#include "hardware/Ar9565Eeprom.hpp"
#include <array>
#include <cstddef>
#include <cstdint>

using namespace simpleath;

namespace
{
    constexpr uint64_t kEpoch = 99;
    constexpr uint32_t kBar = 0x24000;
    constexpr uint32_t kSeed = 0xffffffffU;
    constexpr size_t kSteps = 10;
    constexpr size_t kTotalRegisters = 26;
    constexpr size_t kSharedMciStageSteps = 8;
    constexpr size_t kSharedAntennaStageSteps = 8;
    constexpr uint32_t kMciScheduleAddress = 0x1818;
    constexpr uint32_t kMciGpmAddress = 0x1820;
    constexpr uint32_t kMciGpmEntries = 0x1824;
    constexpr uint32_t kMciCommand0 = 0x1800;
    constexpr uint32_t kMciCommand2 = 0x1808;
    constexpr uint32_t kMciReceiveStatus = 0x1844;
    constexpr uint32_t kMciTxPayload0 = 0x1898;
    constexpr uint32_t kMciGpmQueryCommand = 0x1080;
    constexpr uint32_t kMciCommandDone = 0x1U;
    constexpr uint32_t kMciCommandFailed = 0x80U;
    constexpr uint32_t kMciBtAsleep = 0x1000U;
    constexpr uint32_t kMciStatusPayload = 0x0003020cU;
    constexpr uint32_t kMciVersionPayload = 0x0cU;
    constexpr uint32_t kMciInterruptRaw = 0x1828;
    constexpr uint32_t kMciReceiveMessageRaw = 0x1838;
    constexpr uint32_t kMciGpmReceived = 0x00000100U;
    constexpr uint32_t kMciRxMessageInterrupt = 0x00000200U;
    constexpr uint32_t kMciRemoteReset = 0x00000001U;
    constexpr uint32_t kMciHardwareFault = 0x00000100U;
    constexpr uint32_t kResetTx = 1U;
    constexpr uint32_t kResetRx = 2U;
    constexpr uint32_t kFinalWritePointer = 5U;
    constexpr uint32_t kPhysicalScheduleAddress = 0x00100000U;
    constexpr uint32_t kInvalidGpmOffset = 16U;
    constexpr uint32_t kMciEnableBit = 0x4U;
    constexpr uint32_t kInvalidOverflowOffset = 15U;
    constexpr uint16_t kShortGpmEntries = 15U;
    constexpr size_t kRevokeAfter = 3;
    constexpr size_t kFailSecondWrite = 2;
    constexpr size_t kFailSecondReadback = 4;
    constexpr uint32_t kGlobal = 0x20044;
    constexpr uint32_t kMciControl = 0x18ac;
    constexpr uint32_t kMciInterrupt = 0x182c;
    constexpr uint32_t kMciMessageInterrupt = 0x183c;
    constexpr uint32_t kMciRemoteInterrupt = 0x1834;
    constexpr uint32_t kBtControl2 = 0x1948;
    constexpr uint32_t kBtControl3 = 0x1a60;
    constexpr uint32_t kPcuMisc = 0x8120;
    constexpr uint32_t kLnaTimeout = 0x1940;
    constexpr uint32_t kMciAttributes = 0x1814;
    constexpr uint32_t kOneAntennaMode = 0x29bU;
    constexpr uint32_t kTwoAntennaMode = 0x303U;
    constexpr uint32_t kOneAntennaTxChain = 0x00080000U;
    constexpr uint32_t kTxChainAndRxDeweight = 0x00780000U;
    constexpr uint32_t kAntennaPreventsRx = 0x00100000U;
    constexpr uint32_t kLnaTimeoutMask = 0x003fffffU;
    constexpr uint32_t kLnaTimeoutValue = 0x0003d090U;
    constexpr uint32_t kMciAttributeValue = 0xe8010000U;
    constexpr uint32_t kMciTransmitControl = 0x1810;
    constexpr uint32_t kBtLnaControl = 0x1a64;
    constexpr uint32_t kPhyRestart = 0x9e24;
    constexpr uint32_t kBtOwnsSpdt = 0x2U;
    constexpr uint32_t kDisableLnaUpdate = 0x4U;
    constexpr size_t kMciControlIndex = 4;
    constexpr size_t kMciTransmitIndex = 6;
    constexpr size_t kGlobalIndex = 7;
    constexpr uint32_t kSelfGen = 0x832c;
    constexpr int kFailedSuccess = 1;
    constexpr int kFailedAdmission = 2;
    constexpr int kFailedBackend = 3;
    constexpr int kFailedErrorPaths = 4;
    constexpr int kFailedSharedMci = 5;
    constexpr int kFailedGpm = 6;
    constexpr int kFailedAntenna = 7;
    constexpr int kFailedMciReset = 8;
    constexpr int kFailedMciInterrupt = 9;
    constexpr int kFailedMciTransmit = 10;
    constexpr int kFailedGpmDiagnostic = 11;

    struct Register
    {
            uint32_t address;
            uint32_t bits;
    };

    struct Mock
    {
            std::array<Register, kTotalRegisters> registers {
                {
                    {kSelfGen, kSeed},
                    {kMciInterrupt, kSeed},
                    {kMciMessageInterrupt, kSeed},
                    {kMciRemoteInterrupt, kSeed},
                    {kMciControl, kSeed},
                    {kBtControl2, kSeed},
                    {kMciTransmitControl, kSeed & ~kDisableLnaUpdate},
                    {kGlobal, kSeed},
                    {kBtLnaControl, kSeed},
                    {kPhyRestart, kSeed},
                    {kMciScheduleAddress, kSeed},
                    {kMciGpmAddress, kSeed},
                    {kMciGpmEntries, kSeed},
                    {kBtControl3, kSeed},
                    {kPcuMisc, kSeed},
                    {kLnaTimeout, kSeed},
                    {kMciAttributes, kSeed},
                    {kMciCommand2, 0U},
                    {kMciInterruptRaw, 0U},
                    {kMciReceiveMessageRaw, 0U},
                    {kMciCommand0, 0U},
                    {kMciReceiveStatus, 0U},
                    {kMciTxPayload0, 0U},
                    {kMciTxPayload0 + 4U, 0U},
                    {kMciTxPayload0 + 8U, 0U},
                    {kMciTxPayload0 + 12U, 0U},
                },
            };
            std::array<uint32_t, kTotalRegisters> writeOrder {};
            std::array<uint32_t, kTotalRegisters> writeValues {};
            size_t delays {};
            bool invalidateGpmAfterReset {};
            bool finishMciCommand {true};
            bool failMciCommand {};
            bool bluetoothSleepsAfterCommand {};
            MciGpmCursor *revokeCursorAtCommand {};
            MciGpmCursor *moveCursorAtCommand {};
            MciGpmCursor *moveCursorAtInterruptRead {};
            MciGpmCursor *moveCursorAtMessageRead {};
            size_t writes {};
            size_t reads {};
            size_t permits {};
            size_t revokeAfter {};
            size_t failWrite {};
            size_t failRead {};
            size_t skipWrite {};
            bool active {true};
    };

    Register *find(Mock &mock, uint32_t offset)
    {
        for (auto &reg : mock.registers)
        {
            if (reg.address == offset)
            {
                return &reg;
            }
        }
        return nullptr;
    }

    bool permit(void *context, uint64_t epoch)
    {
        auto &mock = *static_cast<Mock *>(context);
        ++mock.permits;
        return epoch == kEpoch && mock.active &&
               (mock.revokeAfter == 0 || mock.writes < mock.revokeAfter);
    }

    bool read(void *context, uint32_t offset, uint32_t *out)
    {
        auto &mock = *static_cast<Mock *>(context);
        ++mock.reads;
        if (mock.reads == mock.failRead || out == nullptr)
        {
            return false;
        }
        const Register *reg = find(mock, offset);
        if (reg == nullptr)
        {
            return false;
        }
        *out = reg->bits;
        if (offset == kMciReceiveMessageRaw &&
            mock.moveCursorAtMessageRead != nullptr)
        {
            auto *const cursor = mock.moveCursorAtMessageRead;
            cursor->nextIndex = static_cast<uint16_t>((cursor->nextIndex + 1U) %
                                                      kAr9565MciGpmEntries);
            mock.moveCursorAtMessageRead = nullptr;
        }
        if (offset == kMciInterruptRaw &&
            mock.moveCursorAtInterruptRead != nullptr)
        {
            auto *const cursor = mock.moveCursorAtInterruptRead;
            cursor->nextIndex = static_cast<uint16_t>((cursor->nextIndex + 1U) %
                                                      kAr9565MciGpmEntries);
            mock.moveCursorAtInterruptRead = nullptr;
        }
        return true;
    }

    template <typename RegisterAddress, typename RegisterValue>
    bool write(void *context, RegisterAddress address, RegisterValue bits)
    {
        auto &mock = *static_cast<Mock *>(context);
        ++mock.writes;
        if (mock.writes <= mock.writeOrder.size())
        {
            mock.writeOrder.at(mock.writes - 1) = address;
            mock.writeValues.at(mock.writes - 1) = bits;
        }
        if (mock.writes == mock.failWrite)
        {
            return false;
        }
        Register *reg = find(mock, address);
        if (reg == nullptr)
        {
            return false;
        }
        if (mock.writes != mock.skipWrite)
        {
            if (address == kMciInterruptRaw || address == kMciReceiveMessageRaw)
            {
                reg->bits &= ~bits; // Device W1C, not a normal register.
            }
            else
            {
                reg->bits = bits;
            }
        }
        if (address == kMciCommand0 && bits == kMciGpmQueryCommand)
        {
            if (mock.finishMciCommand)
            {
                find(mock, kMciInterruptRaw)->bits |=
                    mock.failMciCommand ? kMciCommandFailed : kMciCommandDone;
            }
            if (mock.bluetoothSleepsAfterCommand)
            {
                find(mock, kMciReceiveStatus)->bits |= kMciBtAsleep;
            }
            if (mock.revokeCursorAtCommand != nullptr)
            {
                mock.revokeCursorAtCommand->attached = false;
            }
            if (mock.moveCursorAtCommand != nullptr)
            {
                mock.moveCursorAtCommand->nextIndex =
                    (mock.moveCursorAtCommand->nextIndex + 1U) %
                    kAr9565MciGpmEntries;
            }
        }
        if (mock.invalidateGpmAfterReset && address == kMciCommand2 &&
            bits == 0U && mock.writes == 5U)
        {
            find(mock, kMciGpmEntries)->bits |= 0xffff0000U;
        }
        return true;
    }

    void delay(void *context, uint32_t micros)
    {
        auto &mock = *static_cast<Mock *>(context);
        if (micros == 1U)
        {
            ++mock.delays;
        }
    }

    RxAgcBackend io(Mock &mock)
    {
        return {
            {
                &mock,
                kEpoch,
                kBar,
                permit,
                write<uint32_t, uint32_t>,
                delay,
            },
            read,
        };
    }

    BoardDataSummary board()
    {
        BoardDataSummary result {};
        result.eepromVersion = 2;
        result.txChainMask = 1;
        result.rxChainMask = 1;
        result.calibrationPierBinsPlausible = true;
        return result;
    }

    SharedMciEvidence sharedAuthorized()
    {
        return {true, true, true, true, true, true};
    }

    SharedMciDmaBuffers sharedBuffers()
    {
        return {
            kPhysicalScheduleAddress,
            kPhysicalScheduleAddress + kAr9565MciScheduleBytes,
            kAr9565MciScheduleBytes,
            kAr9565MciGpmBytes,
            kAr9565MciGpmEntries,
        };
    }

    bool sharedMciTests()
    {
        const BoardDataSummary physicalBoard = board();
        const SharedMciEvidence valid = sharedAuthorized();
        const SharedMciDmaBuffers dma = sharedBuffers();
        {
            Mock mock {};
            const CoexistenceProgress result =
                stageAr9565SharedMciDma(physicalBoard, valid, dma, io(mock));
            const std::array<uint32_t, kSharedMciStageSteps> expectedOrder {
                kSelfGen,
                kMciInterrupt,
                kMciMessageInterrupt,
                kMciRemoteInterrupt,
                kMciControl,
                kMciGpmAddress,
                kMciGpmEntries,
                kMciScheduleAddress,
            };
            bool correctOrder = true;
            for (size_t i = 0; i < expectedOrder.size(); ++i)
            {
                correctOrder = correctOrder &&
                               mock.writeOrder.at(i) == expectedOrder.at(i);
            }
            if (!correctOrder || result.result != CoexistenceResult::Ok ||
                result.requiresReset ||
                result.completedWrites != kSharedMciStageSteps ||
                result.completedReads != kSharedMciStageSteps * 2 ||
                find(mock, kMciScheduleAddress)->bits !=
                    kPhysicalScheduleAddress ||
                find(mock, kMciGpmAddress)->bits != dma.gpmBusAddress ||
                find(mock, kMciGpmEntries)->bits != kAr9565MciGpmEntries ||
                find(mock, kMciControl)->bits != (kSeed & ~kMciEnableBit) ||
                find(mock, kMciInterrupt)->bits != 0 ||
                find(mock, kSelfGen)->bits != 0)
            {
                return false;
            }
        }
        {
            Mock mock {};
            auto invalid = valid;
            invalid.bluetoothHostOwned = false;
            if (stageAr9565SharedMciDma(physicalBoard, invalid, dma, io(mock))
                        .result != CoexistenceResult::MissingIsolation ||
                mock.writes != 0)
            {
                return false;
            }
            invalid = valid;
            invalid.initializedCoherentDma = false;
            if (stageAr9565SharedMciDma(physicalBoard, invalid, dma, io(mock))
                        .result != CoexistenceResult::MissingIsolation ||
                mock.writes != 0)
            {
                return false;
            }
        }
        {
            Mock mock {};
            auto bad = dma;
            bad.gpmBusAddress += kInvalidGpmOffset;
            if (stageAr9565SharedMciDma(physicalBoard, valid, bad, io(mock))
                        .result != CoexistenceResult::InvalidDma ||
                mock.writes != 0)
            {
                return false;
            }
            bad = dma;
            bad.scheduleBusAddress = UINT32_MAX - kInvalidOverflowOffset;
            bad.gpmBusAddress =
                bad.scheduleBusAddress + kAr9565MciScheduleBytes;
            if (stageAr9565SharedMciDma(physicalBoard, valid, bad, io(mock))
                        .result != CoexistenceResult::InvalidDma ||
                mock.writes != 0)
            {
                return false;
            }
            bad = dma;
            bad.gpmEntries = kShortGpmEntries;
            if (stageAr9565SharedMciDma(physicalBoard, valid, bad, io(mock))
                        .result != CoexistenceResult::InvalidDma ||
                mock.writes != 0)
            {
                return false;
            }
            auto shortBar = io(mock);
            shortBar.io.barLengthBytes = kSelfGen;
            if (stageAr9565SharedMciDma(physicalBoard, valid, dma, shortBar)
                        .result != CoexistenceResult::InvalidBar ||
                mock.writes != 0)
            {
                return false;
            }
        }
        {
            Mock mock {};
            mock.revokeAfter = 3;
            const auto status =
                stageAr9565SharedMciDma(physicalBoard, valid, dma, io(mock));
            if (status.result != CoexistenceResult::OwnershipLost ||
                !status.requiresReset || mock.writes != 3)
            {
                return false;
            }
        }
        {
            Mock mock {};
            mock.skipWrite = 1;
            const auto status =
                stageAr9565SharedMciDma(physicalBoard, valid, dma, io(mock));
            if (status.result != CoexistenceResult::ReadbackMismatch ||
                !status.requiresReset || mock.writes != 1)
            {
                return false;
            }
        }
        return true;
    }

    bool sharedAntennaTests()
    {
        const auto physicalBoard = board();
        const auto physicalDma = sharedBuffers();
        const auto evidence = sharedAuthorized();
        const SharedMciAntennaSelection one {
            SharedMciAntennaTopology::OneSharedPaAndLna,
            true,
        };
        const SharedMciAntennaSelection two {
            SharedMciAntennaTopology::TwoIndependent,
            true,
        };
        const std::array<uint32_t, kSharedAntennaStageSteps> expectedOrder {
            kBtControl2, kMciControl, kGlobal,        kBtControl3,
            kPcuMisc,    kLnaTimeout, kMciAttributes, kMciTransmitControl,
        };
        for (const auto &topology : {one, two})
        {
            Mock mock {};
            if (stageAr9565SharedMciDma(physicalBoard, evidence, physicalDma,
                                        io(mock))
                    .result != CoexistenceResult::Ok)
            {
                return false;
            }
            // The hardware owns the upper write-pointer half of GPM_1.
            // It is not an MCI ring-size mismatch after DMA staging.
            find(mock, kMciGpmEntries)->bits |= 0x00020000U;
            mock.writes = mock.reads = mock.permits = 0U;
            const auto result = stageAr9565SharedMciAntenna(
                physicalBoard, evidence, physicalDma, topology, io(mock));
            if (result.result != CoexistenceResult::Ok ||
                result.requiresReset ||
                result.completedWrites != kSharedAntennaStageSteps ||
                result.completedReads !=
                    kSharedMciStageSteps + kSharedAntennaStageSteps * 2U ||
                mock.writes != kSharedAntennaStageSteps ||
                find(mock, kMciInterrupt)->bits != 0U ||
                find(mock, kSelfGen)->bits != 0U ||
                find(mock, kGlobal)->bits != kSeed ||
                find(mock, kPcuMisc)->bits != (kSeed & ~kAntennaPreventsRx) ||
                find(mock, kLnaTimeout)->bits !=
                    ((kSeed & ~kLnaTimeoutMask) | kLnaTimeoutValue) ||
                find(mock, kBtControl3)->bits != ((kSeed & ~0xfffU) | 20U) ||
                find(mock, kMciAttributes)->bits != kMciAttributeValue)
            {
                return false;
            }
            for (size_t index = 0; index < expectedOrder.size(); ++index)
            {
                if (mock.writeOrder.at(index) != expectedOrder.at(index))
                {
                    return false;
                }
            }
            const bool shared = topology.topology ==
                                SharedMciAntennaTopology::OneSharedPaAndLna;
            if (find(mock, kMciControl)->bits !=
                    (shared ? kOneAntennaMode : kTwoAntennaMode) ||
                find(mock, kBtControl2)->bits !=
                    ((kSeed & ~kTxChainAndRxDeweight) |
                     (shared ? kOneAntennaTxChain : 0U)) ||
                find(mock, kMciTransmitControl)->bits !=
                    (shared ? (kSeed & ~kDisableLnaUpdate) : kSeed))
            {
                return false;
            }
        }
        {
            Mock mock {};
            // Without a complete staged ring, or with a stale DMA address,
            // no part of the live antenna configuration may be published.
            if (stageAr9565SharedMciAntenna(physicalBoard, evidence,
                                            physicalDma, one, io(mock))
                        .result != CoexistenceResult::ReadbackMismatch ||
                mock.writes != 0U)
            {
                return false;
            }
            if (stageAr9565SharedMciDma(physicalBoard, evidence, physicalDma,
                                        io(mock))
                    .result != CoexistenceResult::Ok)
            {
                return false;
            }
            mock.writes = 0;
            auto badDma = physicalDma;
            badDma.gpmBusAddress += kInvalidGpmOffset;
            if (stageAr9565SharedMciAntenna(physicalBoard, evidence, badDma,
                                            one, io(mock))
                        .result != CoexistenceResult::InvalidDma ||
                mock.writes != 0U)
            {
                return false;
            }
            auto unsupported = one;
            unsupported.physicallyVerifiedTopology = false;
            if (stageAr9565SharedMciAntenna(physicalBoard, evidence,
                                            physicalDma, unsupported, io(mock))
                        .result != CoexistenceResult::MissingIsolation ||
                mock.writes != 0U)
            {
                return false;
            }
            unsupported = one;
            unsupported.topology = SharedMciAntennaTopology::Unknown;
            if (stageAr9565SharedMciAntenna(physicalBoard, evidence,
                                            physicalDma, unsupported, io(mock))
                        .result != CoexistenceResult::MissingIsolation ||
                mock.writes != 0U)
            {
                return false;
            }
            auto stale = evidence;
            stale.coexistenceAndAntennaLease = false;
            if (stageAr9565SharedMciAntenna(physicalBoard, stale, physicalDma,
                                            one, io(mock))
                        .result != CoexistenceResult::MissingIsolation ||
                mock.writes != 0U)
            {
                return false;
            }
            auto shortBar = io(mock);
            shortBar.io.barLengthBytes = kGlobal;
            if (stageAr9565SharedMciAntenna(physicalBoard, evidence,
                                            physicalDma, one, shortBar)
                        .result != CoexistenceResult::InvalidBar ||
                mock.writes != 0U)
            {
                return false;
            }
        }
        for (size_t changed = 0; changed < 3U; ++changed)
        {
            Mock mock {};
            if (stageAr9565SharedMciDma(physicalBoard, evidence, physicalDma,
                                        io(mock))
                    .result != CoexistenceResult::Ok)
            {
                return false;
            }
            mock.writes = mock.reads = mock.permits = 0U;
            const uint32_t offset = changed == 0U   ? kSelfGen
                                    : changed == 1U ? kMciInterrupt
                                                    : kMciScheduleAddress;
            find(mock, offset)->bits ^= 0x1U;
            const auto result = stageAr9565SharedMciAntenna(
                physicalBoard, evidence, physicalDma, one, io(mock));
            if (result.result != CoexistenceResult::ReadbackMismatch ||
                result.requiresReset || mock.writes != 0U)
            {
                return false;
            }
        }
        for (size_t scenario = 0; scenario < 4U; ++scenario)
        {
            Mock mock {};
            if (stageAr9565SharedMciDma(physicalBoard, evidence, physicalDma,
                                        io(mock))
                    .result != CoexistenceResult::Ok)
            {
                return false;
            }
            mock.writes = mock.reads = mock.permits = 0U;
            if (scenario == 0U)
            {
                mock.failRead = 1U; // Preflight cannot modify hardware.
            }
            else if (scenario == 1U)
            {
                mock.failRead = 12U; // Second register readback failed.
            }
            else if (scenario == 2U)
            {
                mock.failWrite = 2U;
            }
            else
            {
                mock.revokeAfter = 3U;
            }
            const auto result = stageAr9565SharedMciAntenna(
                physicalBoard, evidence, physicalDma, one, io(mock));
            const auto expected = scenario < 2U ? CoexistenceResult::ReadFailed
                                  : scenario == 2U
                                      ? CoexistenceResult::WriteFailed
                                      : CoexistenceResult::OwnershipLost;
            if (result.result != expected ||
                result.requiresReset != (scenario != 0U) ||
                mock.writes != (scenario == 0U   ? 0U
                                : scenario == 1U ? 2U
                                : scenario == 2U ? 2U
                                                 : 3U))
            {
                return false;
            }
        }
        return true;
    }

    bool sharedMciResetTests()
    {
        const auto physicalBoard = board();
        const auto evidence = sharedAuthorized();
        const auto physicalDma = sharedBuffers();
        const SharedMciResetEvidence resetReady {true, true};
        const SharedMciAntennaSelection topologyOne {
            SharedMciAntennaTopology::OneSharedPaAndLna,
            true,
        };
        const SharedMciAntennaSelection topologyTwo {
            SharedMciAntennaTopology::TwoIndependent,
            true,
        };
        for (const auto &topology : {topologyOne, topologyTwo})
        {
            Mock mock {};
            if (stageAr9565SharedMciDma(physicalBoard, evidence, physicalDma,
                                        io(mock))
                        .result != CoexistenceResult::Ok ||
                stageAr9565SharedMciAntenna(physicalBoard, evidence,
                                            physicalDma, topology, io(mock))
                        .result != CoexistenceResult::Ok)
            {
                return false;
            }
            find(mock, kMciGpmEntries)->bits =
                (kFinalWritePointer << 16U) | kAr9565MciGpmEntries;
            mock.writes = mock.reads = mock.permits = mock.delays = 0U;
            MciGpmCursor cursor {kEpoch - 1U, 11U, true};
            const auto result = resetAr9565SharedMciRxTx(
                physicalBoard, evidence, physicalDma, topology, resetReady,
                io(mock), cursor);
            if (result.result != CoexistenceResult::Ok ||
                result.requiresReset || result.completedWrites != 5U ||
                mock.writes != 5U || mock.delays != 2U || !cursor.attached ||
                cursor.ownerEpoch != kEpoch ||
                cursor.nextIndex != kFinalWritePointer ||
                find(mock, kMciControl)->bits !=
                    ((topology.topology ==
                              SharedMciAntennaTopology::OneSharedPaAndLna
                          ? kOneAntennaMode
                          : kTwoAntennaMode) |
                     kMciEnableBit) ||
                find(mock, kMciCommand2)->bits != 0U ||
                find(mock, kMciInterrupt)->bits != 0U ||
                find(mock, kSelfGen)->bits != 0U ||
                mock.writeOrder.at(0U) != kMciControl ||
                mock.writeOrder.at(1U) != kMciCommand2 ||
                mock.writeOrder.at(2U) != kMciCommand2 ||
                mock.writeOrder.at(3U) != kMciCommand2 ||
                mock.writeOrder.at(4U) != kMciCommand2 ||
                mock.writeValues.at(1U) != kResetTx ||
                mock.writeValues.at(2U) != 0U ||
                mock.writeValues.at(3U) != kResetRx ||
                mock.writeValues.at(4U) != 0U)
            {
                return false;
            }
        }
        {
            Mock mock {};
            MciGpmCursor cursor {kEpoch - 1U, 7U, true};
            if (resetAr9565SharedMciRxTx(physicalBoard, evidence, physicalDma,
                                         topologyOne, resetReady, io(mock),
                                         cursor)
                        .result != CoexistenceResult::ReadbackMismatch ||
                mock.writes != 0U || cursor.nextIndex != 7U)
            {
                return false;
            }
            if (stageAr9565SharedMciDma(physicalBoard, evidence, physicalDma,
                                        io(mock))
                        .result != CoexistenceResult::Ok ||
                stageAr9565SharedMciAntenna(physicalBoard, evidence,
                                            physicalDma, topologyOne, io(mock))
                        .result != CoexistenceResult::Ok)
            {
                return false;
            }
            mock.writes = mock.reads = mock.permits = 0U;
            const SharedMciResetEvidence denied {false, true};
            if (resetAr9565SharedMciRxTx(physicalBoard, evidence, physicalDma,
                                         topologyOne, denied, io(mock), cursor)
                        .result != CoexistenceResult::MissingIsolation ||
                mock.writes != 0U || cursor.nextIndex != 7U)
            {
                return false;
            }
            auto missingDelay = io(mock);
            missingDelay.io.delayMicros = nullptr;
            if (resetAr9565SharedMciRxTx(physicalBoard, evidence, physicalDma,
                                         topologyOne, resetReady, missingDelay,
                                         cursor)
                        .result != CoexistenceResult::InvalidBackend ||
                mock.writes != 0U)
            {
                return false;
            }
            find(mock, kMciInterrupt)->bits = 1U;
            if (resetAr9565SharedMciRxTx(physicalBoard, evidence, physicalDma,
                                         topologyOne, resetReady, io(mock),
                                         cursor)
                        .result != CoexistenceResult::ReadbackMismatch ||
                mock.writes != 0U || cursor.nextIndex != 7U)
            {
                return false;
            }
        }
        for (size_t scenario = 0U; scenario < 4U; ++scenario)
        {
            Mock mock {};
            if (stageAr9565SharedMciDma(physicalBoard, evidence, physicalDma,
                                        io(mock))
                        .result != CoexistenceResult::Ok ||
                stageAr9565SharedMciAntenna(physicalBoard, evidence,
                                            physicalDma, topologyOne, io(mock))
                        .result != CoexistenceResult::Ok)
            {
                return false;
            }
            mock.writes = mock.reads = mock.permits = 0U;
            if (scenario == 0U)
            {
                mock.failWrite = 2U;
            }
            else if (scenario == 1U)
            {
                mock.revokeAfter = 2U;
            }
            else if (scenario == 2U)
            {
                mock.invalidateGpmAfterReset = true;
            }
            else
            {
                mock.failRead = 1U;
            }
            MciGpmCursor cursor {kEpoch - 1U, 7U, true};
            const auto result = resetAr9565SharedMciRxTx(
                physicalBoard, evidence, physicalDma, topologyOne, resetReady,
                io(mock), cursor);
            const auto expected =
                scenario == 0U   ? CoexistenceResult::WriteFailed
                : scenario == 1U ? CoexistenceResult::OwnershipLost
                : scenario == 2U ? CoexistenceResult::InvalidGpm
                                 : CoexistenceResult::ReadFailed;
            if (result.result != expected ||
                result.requiresReset != (scenario != 3U) ||
                cursor.attached == (scenario != 3U) ||
                (scenario == 3U && cursor.nextIndex != 7U))
            {
                return false;
            }
        }
        return true;
    }

    bool sharedGpmDiagnosticTests()
    {
        constexpr uint8_t kAgent = 0x0cU;
        constexpr size_t kTypeField = 4U;
        constexpr size_t kOpcodeField = 5U;
        constexpr size_t kDataField0 = 6U;
        constexpr size_t kDataField1 = 7U;
        constexpr size_t kDataField2 = 8U;
        constexpr size_t kSequence0 = 12U;
        constexpr size_t kSequence1 = 13U;
        constexpr size_t kSequence2 = 14U;
        constexpr size_t kSequence3 = 15U;
        const MciGpmCursor active {kEpoch, 4U, true};
        const auto make = [&](uint8_t type, uint8_t opcode)
        {
            MciGpmMessage frame {};
            frame.type = type;
            frame.opcode = opcode;
            frame.payload[kTypeField] = type;
            frame.payload[kOpcodeField] = opcode;
            return frame;
        };
        {
            const auto frame = make(kAgent, 0U);
            if (inspectAr9565MciGpm(kEpoch, active, frame).kind !=
                MciGpmDiagnosticKind::PeerVersionQuery)
            {
                return false;
            }
            const auto status = make(kAgent, 2U);
            if (inspectAr9565MciGpm(kEpoch, active, status).kind !=
                MciGpmDiagnosticKind::PeerStatusQuery)
            {
                return false;
            }
        }
        {
            auto frame = make(kAgent, 1U);
            frame.payload[kDataField0] = 3U;
            frame.payload[kDataField1] = 7U;
            const auto notice = inspectAr9565MciGpm(kEpoch, active, frame);
            if (notice.kind != MciGpmDiagnosticKind::BluetoothVersionResponse ||
                notice.versionMajor != 3U || notice.versionMinor != 7U ||
                notice.isCritical || notice.isLinkStatus ||
                notice.sequence != 0U)
            {
                return false;
            }
        }
        {
            auto frame = make(kAgent, 5U);
            frame.payload[kDataField0] = 6U;
            frame.payload[kDataField1] = 2U;
            const auto notice = inspectAr9565MciGpm(kEpoch, active, frame);
            if (notice.kind != MciGpmDiagnosticKind::BluetoothProfileNotice ||
                notice.profileType != 6U || notice.linkId != 2U)
            {
                return false;
            }
        }
        {
            auto frame = make(kAgent, 6U);
            frame.payload[kDataField0] = 0U;
            frame.payload[kDataField1] = 7U;
            frame.payload[kDataField2] = 1U;
            frame.payload[kSequence0] = 0x12U;
            frame.payload[kSequence1] = 0x34U;
            frame.payload[kSequence2] = 0x56U;
            frame.payload[kSequence3] = 0x78U;
            const auto notice = inspectAr9565MciGpm(kEpoch, active, frame);
            if (notice.kind != MciGpmDiagnosticKind::BluetoothStatusNotice ||
                notice.isLinkStatus || !notice.isCritical ||
                notice.linkId != 7U || notice.sequence != 0x78563412U)
            {
                return false;
            }
            frame.payload[kDataField0] = 1U;
            frame.payload[kDataField1] = 0xffU;
            const auto link = inspectAr9565MciGpm(kEpoch, active, frame);
            if (link.kind != MciGpmDiagnosticKind::BluetoothStatusNotice ||
                !link.isLinkStatus || link.linkId != 0xffU)
            {
                return false;
            }
        }
        for (size_t scenario = 0U; scenario < 8U; ++scenario)
        {
            auto frame = make(kAgent, 6U);
            frame.payload[kDataField0] = 0U;
            frame.payload[kDataField1] = 7U;
            frame.payload[kDataField2] = 1U;
            auto cursor = active;
            uint64_t epoch = kEpoch;
            if (scenario == 0U)
            {
                frame.payload[kDataField0] = 2U;
            }
            else if (scenario == 1U)
            {
                frame.payload[kDataField1] = 8U;
            }
            else if (scenario == 2U)
            {
                frame.payload[kDataField2] = 2U;
            }
            else if (scenario == 3U)
            {
                frame.payload[kOpcodeField] = 0xffU;
            }
            else if (scenario == 4U)
            {
                frame.type = 0xfeU;
            }
            else if (scenario == 5U)
            {
                cursor.ownerEpoch++;
            }
            else if (scenario == 6U)
            {
                epoch = 0U;
            }
            else
            {
                cursor.attached = false;
            }
            const auto diagnostic = inspectAr9565MciGpm(epoch, cursor, frame);
            const auto expected = scenario < 5U
                                      ? MciGpmDiagnosticKind::InvalidPayload
                                      : MciGpmDiagnosticKind::OwnershipLost;
            if (diagnostic.kind != expected || diagnostic.versionMajor != 0U ||
                diagnostic.linkId != 0U || diagnostic.sequence != 0U ||
                diagnostic.isCritical || diagnostic.isLinkStatus)
            {
                return false;
            }
        }
        {
            auto frame = make(kAgent, 5U);
            frame.payload[kDataField0] = 0U;
            if (inspectAr9565MciGpm(kEpoch, active, frame).kind !=
                MciGpmDiagnosticKind::InvalidPayload)
            {
                return false;
            }
            frame.payload[kDataField0] = 7U;
            if (inspectAr9565MciGpm(kEpoch, active, frame).kind !=
                MciGpmDiagnosticKind::InvalidPayload)
            {
                return false;
            }
        }
        if (inspectAr9565MciGpm(kEpoch, active, make(0xfeU, 1U)).kind !=
                MciGpmDiagnosticKind::Unrelated ||
            inspectAr9565MciGpm(kEpoch, active, make(kAgent, 0xffU)).kind !=
                MciGpmDiagnosticKind::Unrelated)
        {
            return false;
        }
        // Exercise the real copied GPM ring cursor before classification.
        // A subsequent DMA buffer mutation must not affect the diagnostic.
        {
            constexpr uint32_t kGpmRegisterZero = kAr9565MciGpmEntries;
            constexpr uint32_t kGpmRegisterOne =
                (1U << 16U) | kAr9565MciGpmEntries;
            std::array<uint8_t, kAr9565MciGpmBytes> ring {};
            ring.fill(0xfeU);
            MciGpmCursor cursor {};
            if (attachAr9565MciGpm(kEpoch, kGpmRegisterZero, cursor) !=
                MciGpmResult::Empty)
            {
                return false;
            }
            ring.at(kTypeField) = kAgent;
            ring.at(kOpcodeField) = 1U;
            ring.at(kDataField0) = 3U;
            ring.at(kDataField1) = 4U;
            MciGpmMessage copied {};
            if (nextAr9565MciGpm(kEpoch, kGpmRegisterOne, ring.data(),
                                 ring.size(), cursor,
                                 copied) != MciGpmResult::Message)
            {
                return false;
            }
            ring.at(kDataField0) = 0xffU;
            ring.at(kDataField1) = 0xffU;
            const auto diagnostic = inspectAr9565MciGpm(kEpoch, cursor, copied);
            if (diagnostic.kind !=
                    MciGpmDiagnosticKind::BluetoothVersionResponse ||
                diagnostic.versionMajor != 3U ||
                diagnostic.versionMinor != 4U || cursor.nextIndex != 1U)
            {
                return false;
            }
        }
        return true;
    }

    bool sharedMciTransmitTests()
    {
        const auto physicalBoard = board();
        const auto evidence = sharedAuthorized();
        const auto dma = sharedBuffers();
        const SharedMciAntennaSelection topology {
            SharedMciAntennaTopology::OneSharedPaAndLna,
            true,
        };
        const SharedMciResetEvidence resetLease {true, true};
        const MciCoexTransmitEvidence transmitLease {true, true, true};
        const auto prepare = [&](Mock &mock, MciGpmCursor &cursor)
        {
            if (stageAr9565SharedMciDma(physicalBoard, evidence, dma, io(mock))
                        .result != CoexistenceResult::Ok ||
                stageAr9565SharedMciAntenna(physicalBoard, evidence, dma,
                                            topology, io(mock))
                        .result != CoexistenceResult::Ok)
            {
                return false;
            }
            find(mock, kMciGpmEntries)->bits =
                (kFinalWritePointer << 16U) | kAr9565MciGpmEntries;
            if (resetAr9565SharedMciRxTx(physicalBoard, evidence, dma, topology,
                                         resetLease, io(mock), cursor)
                    .result != CoexistenceResult::Ok)
            {
                return false;
            }
            mock.writes = mock.reads = mock.permits = mock.delays = 0U;
            return true;
        };
        for (const auto query :
             {MciCoexQuery::Version, MciCoexQuery::BluetoothStatus})
        {
            Mock mock {};
            MciGpmCursor cursor {};
            if (!prepare(mock, cursor))
            {
                return false;
            }
            // An unrelated GPM receive notification must NOT be cleared by
            // TX W1C. A stale command completion must be acknowledged first.
            find(mock, kMciInterruptRaw)->bits =
                kMciCommandDone | kMciRxMessageInterrupt;
            const auto result =
                sendAr9565MciCoexQuery(physicalBoard, evidence, dma, cursor,
                                       transmitLease, query, io(mock));
            if (result.result != CoexistenceResult::Ok ||
                result.requiresReset || result.completedWrites != 7U ||
                mock.writes != 7U ||
                mock.writeOrder.at(0U) != kMciInterruptRaw ||
                mock.writeOrder.at(1U) != kMciTxPayload0 ||
                mock.writeOrder.at(2U) != kMciTxPayload0 + 4U ||
                mock.writeOrder.at(3U) != kMciTxPayload0 + 8U ||
                mock.writeOrder.at(4U) != kMciTxPayload0 + 12U ||
                mock.writeOrder.at(5U) != kMciCommand0 ||
                mock.writeOrder.at(6U) != kMciInterruptRaw ||
                find(mock, kMciCommand0)->bits != kMciGpmQueryCommand ||
                find(mock, kMciTxPayload0 + 4U)->bits !=
                    (query == MciCoexQuery::Version ? kMciVersionPayload
                                                    : kMciStatusPayload) ||
                find(mock, kMciTxPayload0)->bits != 0U ||
                find(mock, kMciTxPayload0 + 8U)->bits != 0U ||
                find(mock, kMciTxPayload0 + 12U)->bits != 0U ||
                find(mock, kMciInterruptRaw)->bits != kMciRxMessageInterrupt ||
                !cursor.attached || cursor.ownerEpoch != kEpoch)
            {
                return false;
            }
        }
        // All preflight failures must prevent any command MMIO.
        for (size_t scenario = 0U; scenario < 11U; ++scenario)
        {
            Mock mock {};
            MciGpmCursor cursor {};
            if (!prepare(mock, cursor))
            {
                return false;
            }
            auto lease = transmitLease;
            auto current = cursor;
            auto configuredIo = io(mock);
            auto bus = dma;
            auto claims = evidence;
            auto chosen = MciCoexQuery::Version;
            if (scenario == 0U)
            {
                lease.bluetoothAwakeFromHost = false;
            }
            else if (scenario == 1U)
            {
                lease.exclusiveMciCommandLease = false;
            }
            else if (scenario == 2U)
            {
                lease.noOutstandingMciCommands = false;
            }
            else if (scenario == 3U)
            {
                current.ownerEpoch++;
            }
            else if (scenario == 4U)
            {
                bus.gpmBusAddress++;
            }
            else if (scenario == 5U)
            {
                configuredIo.io.barLengthBytes = kMciTxPayload0;
            }
            else if (scenario == 6U)
            {
                find(mock, kMciReceiveStatus)->bits = kMciBtAsleep;
            }
            else if (scenario == 7U)
            {
                find(mock, kMciInterrupt)->bits = 1U;
            }
            else if (scenario == 8U)
            {
                claims.bluetoothHostOwned = false;
            }
            else
            {
                chosen = static_cast<MciCoexQuery>(0xffU);
            }
            const auto result =
                sendAr9565MciCoexQuery(physicalBoard, claims, bus, current,
                                       lease, chosen, configuredIo);
            const auto expected =
                scenario < 4U || scenario == 6U || scenario == 8U
                    ? CoexistenceResult::MissingIsolation
                : scenario == 4U ? CoexistenceResult::InvalidDma
                : scenario == 5U ? CoexistenceResult::InvalidBar
                : scenario == 7U ? CoexistenceResult::ReadbackMismatch
                                 : CoexistenceResult::InvalidGpm;
            if (result.result != expected || result.requiresReset ||
                !current.attached || mock.writes != 0U)
            {
                return false;
            }
        }
        for (size_t scenario = 0U; scenario < 11U; ++scenario)
        {
            Mock mock {};
            MciGpmCursor cursor {};
            if (!prepare(mock, cursor))
            {
                return false;
            }
            if (scenario == 0U)
            {
                mock.finishMciCommand = false;
            }
            else if (scenario == 1U)
            {
                mock.failMciCommand = true;
            }
            else if (scenario == 2U)
            {
                mock.failWrite = 2U;
            }
            else if (scenario == 3U)
            {
                mock.revokeAfter = 2U;
            }
            else if (scenario == 4U)
            {
                mock.bluetoothSleepsAfterCommand = true;
            }
            else if (scenario == 5U)
            {
                // W1C for SW_MSG_DONE is accepted but hardware never clears.
                mock.skipWrite = 6U;
            }
            else if (scenario == 6U)
            {
                mock.failRead = 11U;
            }
            else if (scenario == 7U)
            {
                // A stale command completion must be acknowledged before
                // writing payload, and a failed acknowledge cannot proceed.
                find(mock, kMciInterruptRaw)->bits = kMciCommandDone;
                mock.skipWrite = 1U;
            }
            else if (scenario == 8U)
            {
                // Refuse TX if the posted nonzero GPM type/opcode word did
                // not really reach hardware; never issue COMMAND0.
                mock.skipWrite = 2U;
            }
            else if (scenario == 9U)
            {
                // The hardware send completes, but the MCI/GPM owner is
                // synchronously replaced while handling COMMAND0.
                mock.revokeCursorAtCommand = &cursor;
            }
            else
            {
                // A same-epoch reattach advances the ring pointer without
                // detaching: still must not grant old command success.
                mock.moveCursorAtCommand = &cursor;
            }
            const auto result = sendAr9565MciCoexQuery(
                physicalBoard, evidence, dma, cursor, transmitLease,
                MciCoexQuery::BluetoothStatus, io(mock));
            const auto expected =
                scenario == 0U   ? CoexistenceResult::TimedOut
                : scenario == 1U ? CoexistenceResult::MessageRejected
                : scenario == 2U ? CoexistenceResult::WriteFailed
                : scenario == 3U ? CoexistenceResult::OwnershipLost
                : scenario == 4U ? CoexistenceResult::MissingIsolation
                : scenario == 5U ? CoexistenceResult::ReadbackMismatch
                : scenario == 6U ? CoexistenceResult::ReadFailed
                : scenario >= 9U ? CoexistenceResult::OwnershipLost
                                 : CoexistenceResult::ReadbackMismatch;
            if (result.result != expected || !result.requiresReset ||
                cursor.attached || (scenario == 7U && mock.writes != 1U) ||
                (scenario == 0U && mock.delays != 500U) ||
                (scenario == 8U && find(mock, kMciCommand0)->bits != 0U))
            {
                return false;
            }
            // Even if callers ignore requiresReset, detachment must deny
            // another command without any new MMIO or hidden send.
            const size_t priorWrites = mock.writes;
            const auto rejected = sendAr9565MciCoexQuery(
                physicalBoard, evidence, dma, cursor, transmitLease,
                MciCoexQuery::Version, io(mock));
            if (rejected.result != CoexistenceResult::MissingIsolation ||
                rejected.requiresReset || mock.writes != priorWrites)
            {
                return false;
            }
        }
        // A callback changing the same-epoch GPM pointer during the
        // pre-send RAW read must not reach TX_PAYLOAD or COMMAND0.
        {
            Mock mock {};
            MciGpmCursor cursor {};
            if (!prepare(mock, cursor))
            {
                return false;
            }
            mock.moveCursorAtInterruptRead = &cursor;
            const auto result = sendAr9565MciCoexQuery(
                physicalBoard, evidence, dma, cursor, transmitLease,
                MciCoexQuery::BluetoothStatus, io(mock));
            if (result.result != CoexistenceResult::OwnershipLost ||
                !result.requiresReset || cursor.attached ||
                find(mock, kMciCommand0)->bits != 0U || mock.writes != 0U)
            {
                return false;
            }
        }
        // Fail-closed RAW status reads revoke a cursor; observing BT sleep
        // is a clean preflight denial and preserves it.
        for (size_t scenario = 0U; scenario < 3U; ++scenario)
        {
            Mock mock {};
            MciGpmCursor cursor {};
            if (!prepare(mock, cursor))
            {
                return false;
            }
            if (scenario == 0U)
            {
                mock.failRead = 9U;
            }
            else if (scenario == 1U)
            {
                find(mock, kMciInterruptRaw)->bits = 0xdeadbeefU;
            }
            else
            {
                find(mock, kMciReceiveStatus)->bits = kMciBtAsleep;
            }
            const auto result = sendAr9565MciCoexQuery(
                physicalBoard, evidence, dma, cursor, transmitLease,
                MciCoexQuery::Version, io(mock));
            const auto expected = scenario == 0U ? CoexistenceResult::ReadFailed
                                  : scenario == 1U
                                      ? CoexistenceResult::ReadbackMismatch
                                      : CoexistenceResult::MissingIsolation;
            if (result.result != expected || mock.writes != 0U ||
                result.requiresReset != (scenario != 2U) ||
                cursor.attached != (scenario == 2U))
            {
                return false;
            }
        }
        return true;
    }

    bool sharedMciInterruptTests()
    {
        const auto physicalBoard = board();
        const auto evidence = sharedAuthorized();
        const auto dma = sharedBuffers();
        const SharedMciAntennaSelection topology {
            SharedMciAntennaTopology::OneSharedPaAndLna,
            true,
        };
        const SharedMciResetEvidence btQuiesced {true, true};
        const auto prepare = [&](Mock &mock, MciGpmCursor &cursor)
        {
            const auto stage =
                stageAr9565SharedMciDma(physicalBoard, evidence, dma, io(mock));
            const auto antennas = stageAr9565SharedMciAntenna(
                physicalBoard, evidence, dma, topology, io(mock));
            const auto reset =
                resetAr9565SharedMciRxTx(physicalBoard, evidence, dma, topology,
                                         btQuiesced, io(mock), cursor);
            mock.writes = mock.reads = mock.permits = 0U;
            return stage.result == CoexistenceResult::Ok &&
                   antennas.result == CoexistenceResult::Ok &&
                   reset.result == CoexistenceResult::Ok;
        };
        {
            Mock mock {};
            MciGpmCursor cursor {};
            if (!prepare(mock, cursor))
            {
                return false;
            }
            find(mock, kMciReceiveMessageRaw)->bits =
                kMciGpmReceived | kMciRemoteReset;
            find(mock, kMciInterruptRaw)->bits = kMciRxMessageInterrupt;
            const auto result =
                pollAr9565MciPendingInterrupts(evidence, dma, cursor, io(mock));
            if (result.progress.result != CoexistenceResult::Ok ||
                result.progress.requiresReset ||
                result.progress.completedWrites != 2U ||
                !result.gpmNotification ||
                !result.bluetoothRenegotiationRequired ||
                result.hardwareFault ||
                result.rawInterrupt != kMciRxMessageInterrupt ||
                result.rawMessageInterrupt !=
                    (kMciGpmReceived | kMciRemoteReset) ||
                mock.writes != 2U ||
                mock.writeOrder.at(0) != kMciReceiveMessageRaw ||
                mock.writeOrder.at(1) != kMciInterruptRaw ||
                find(mock, kMciReceiveMessageRaw)->bits != 0U ||
                find(mock, kMciInterruptRaw)->bits != 0U ||
                find(mock, kMciInterrupt)->bits != 0U ||
                find(mock, kSelfGen)->bits != 0U || !cursor.attached ||
                cursor.ownerEpoch != kEpoch)
            {
                return false;
            }
            const auto idle =
                pollAr9565MciPendingInterrupts(evidence, dma, cursor, io(mock));
            if (idle.progress.result != CoexistenceResult::Ok ||
                idle.progress.completedWrites != 0U || idle.gpmNotification ||
                idle.hardwareFault || idle.bluetoothRenegotiationRequired)
            {
                return false;
            }
        }
        {
            Mock mock {};
            MciGpmCursor cursor {};
            if (!prepare(mock, cursor))
            {
                return false;
            }
            find(mock, kMciReceiveMessageRaw)->bits =
                kMciGpmReceived | kMciRemoteReset;
            find(mock, kMciInterruptRaw)->bits =
                kMciHardwareFault | kMciRxMessageInterrupt;
            const auto result =
                pollAr9565MciPendingInterrupts(evidence, dma, cursor, io(mock));
            if (result.progress.result != CoexistenceResult::Ok ||
                !result.hardwareFault || !result.progress.requiresReset ||
                result.gpmNotification ||
                result.bluetoothRenegotiationRequired || cursor.attached)
            {
                return false;
            }
            // A caller that discards requiresReset must not be able to send
            // another MCI command with the poisoned attached cursor.
            const auto previousWrites = mock.writes;
            const MciCoexTransmitEvidence transmitLease {true, true, true};
            const auto replay = sendAr9565MciCoexQuery(
                physicalBoard, evidence, dma, cursor, transmitLease,
                MciCoexQuery::Version, io(mock));
            if (replay.result != CoexistenceResult::MissingIsolation ||
                replay.requiresReset || mock.writes != previousWrites)
            {
                return false;
            }
            auto stale = cursor;
            stale.ownerEpoch = kEpoch + 1U;
            if (pollAr9565MciPendingInterrupts(evidence, dma, stale, io(mock))
                    .progress.result != CoexistenceResult::MissingIsolation)
            {
                return false;
            }
        }
        for (size_t scenario = 0U; scenario < 7U; ++scenario)
        {
            Mock mock {};
            MciGpmCursor cursor {};
            if (!prepare(mock, cursor))
            {
                return false;
            }
            if (scenario == 0U)
            {
                find(mock, kMciReceiveMessageRaw)->bits = 0xdeadbeefU;
            }
            else if (scenario == 1U)
            {
                find(mock, kMciInterrupt)->bits = 0x1U;
            }
            else
            {
                find(mock, kMciReceiveMessageRaw)->bits = kMciGpmReceived;
                if (scenario == 2U)
                {
                    mock.failWrite = 1U;
                }
                else if (scenario == 3U)
                {
                    mock.skipWrite = 1U;
                }
                else if (scenario == 4U)
                {
                    mock.revokeAfter = 1U;
                }
                else if (scenario == 5U)
                {
                    // Acknowledge RX_MSG successfully, then fail the RAW
                    // status acknowledgement. Never leak the first event.
                    find(mock, kMciInterruptRaw)->bits = kMciRxMessageInterrupt;
                    mock.failWrite = 2U;
                }
                else
                {
                    // After eight preflight reads, the first RAW status
                    // read fails. This cannot be considered an idle device.
                    mock.failRead = 9U;
                }
            }
            const auto result =
                pollAr9565MciPendingInterrupts(evidence, dma, cursor, io(mock));
            const auto expected =
                scenario < 2U    ? CoexistenceResult::ReadbackMismatch
                : scenario == 2U ? CoexistenceResult::WriteFailed
                : scenario == 3U ? CoexistenceResult::ReadbackMismatch
                : scenario == 4U ? CoexistenceResult::OwnershipLost
                : scenario == 5U ? CoexistenceResult::WriteFailed
                                 : CoexistenceResult::ReadFailed;
            if (result.progress.result != expected ||
                (scenario < 2U && mock.writes != 0U) ||
                !result.progress.requiresReset || cursor.attached ||
                cursor.ownerEpoch != kEpoch || result.gpmNotification ||
                result.bluetoothRenegotiationRequired || result.hardwareFault ||
                result.rawMessageInterrupt != 0U || result.rawInterrupt != 0U)
            {
                return false;
            }
        }
        // A callback switching GPM consumer after the first RAW read must
        // stop even before the next RAW read or any W1C acknowledgement.
        {
            Mock mock {};
            MciGpmCursor cursor {};
            if (!prepare(mock, cursor))
            {
                return false;
            }
            find(mock, kMciReceiveMessageRaw)->bits = kMciGpmReceived;
            find(mock, kMciInterruptRaw)->bits = kMciRxMessageInterrupt;
            const auto oldIndex = cursor.nextIndex;
            mock.moveCursorAtMessageRead = &cursor;
            const auto result =
                pollAr9565MciPendingInterrupts(evidence, dma, cursor, io(mock));
            if (result.progress.result != CoexistenceResult::OwnershipLost ||
                !result.progress.requiresReset || mock.reads != 9U ||
                mock.writes != 0U || result.rawInterrupt != 0U ||
                result.gpmNotification || !cursor.attached ||
                cursor.nextIndex == oldIndex)
            {
                return false;
            }
        }
        // The native GPM callback may consume or replace the cursor while
        // reading the second RAW status. Do not acknowledge or publish a
        // snapshot for the old consumer or overwrite the changed cursor.
        {
            Mock mock {};
            MciGpmCursor cursor {};
            if (!prepare(mock, cursor))
            {
                return false;
            }
            find(mock, kMciReceiveMessageRaw)->bits = kMciGpmReceived;
            find(mock, kMciInterruptRaw)->bits = kMciRxMessageInterrupt;
            const auto oldIndex = cursor.nextIndex;
            mock.moveCursorAtInterruptRead = &cursor;
            const auto result =
                pollAr9565MciPendingInterrupts(evidence, dma, cursor, io(mock));
            if (result.progress.result != CoexistenceResult::OwnershipLost ||
                !result.progress.requiresReset || mock.writes != 0U ||
                result.gpmNotification || result.hardwareFault ||
                result.rawInterrupt != 0U || !cursor.attached ||
                cursor.nextIndex == oldIndex)
            {
                return false;
            }
        }
        return true;
    }

    bool sharedGpmTests()
    {
        constexpr uint32_t kRingEntries = 16U;
        constexpr uint32_t kPointerShift = 16U;
        constexpr size_t kMessageBytes = 16U;
        constexpr uint8_t kReserved = 0xfeU;
        const auto reg = [](uint32_t writePointer)
        {
            return (writePointer << kPointerShift) | kRingEntries;
        };
        std::array<uint8_t, kAr9565MciGpmBytes> ring {};
        ring.fill(kReserved);
        MciGpmCursor cursor {};
        MciGpmMessage message {};
        if (nextAr9565MciGpm(kEpoch, reg(14U), ring.data(), ring.size(), cursor,
                             message) != MciGpmResult::NotAttached ||
            attachAr9565MciGpm(kEpoch, reg(14U), cursor) !=
                MciGpmResult::Empty ||
            cursor.nextIndex != 14U || !cursor.attached)
        {
            return false;
        }
        // Existing data before the initial live write pointer is stale.
        ring.at(2U * kMessageBytes + 4U) = 0x0cU;
        ring.at(14U * kMessageBytes + 4U) = 0x0cU;
        ring.at(14U * kMessageBytes + 5U) = 0x31U;
        ring.at(14U * kMessageBytes + 0U) = 0xa1U;
        ring.at(0U * kMessageBytes + 4U) = 0x0cU;
        ring.at(0U * kMessageBytes + 5U) = 0x42U;
        ring.at(0U * kMessageBytes + 15U) = 0xb2U;
        // Hardware advanced 14 -> 15 (recycled) -> 0 -> 1; a read
        // must deliver oldest-to-newest, skipping the reserved slot.
        if (nextAr9565MciGpm(kEpoch, reg(1U), ring.data(), ring.size(), cursor,
                             message) != MciGpmResult::Message ||
            message.type != 0x0cU || message.opcode != 0x31U ||
            message.payload[0] != 0xa1U || cursor.nextIndex != 15U)
        {
            return false;
        }
        ring.at(14U * kMessageBytes) = 0U; // Already copied, not borrowed.
        if (message.payload[0] != 0xa1U ||
            nextAr9565MciGpm(kEpoch, reg(1U), ring.data(), ring.size(), cursor,
                             message) != MciGpmResult::Message ||
            message.opcode != 0x42U || message.payload[15] != 0xb2U ||
            cursor.nextIndex != 1U)
        {
            return false;
        }
        if (nextAr9565MciGpm(kEpoch, reg(1U), ring.data(), ring.size(), cursor,
                             message) != MciGpmResult::Empty ||
            message.type != 0U || cursor.nextIndex != 1U)
        {
            return false;
        }
        // An invalid register or different owner cannot change the cursor,
        // and bad buffer spans may never be accessed.
        cursor.nextIndex = 3U;
        message.opcode = 0x99U;
        const auto invalid = reg(1U) ^ 1U;
        if (nextAr9565MciGpm(kEpoch + 1U, reg(1U), ring.data(), ring.size(),
                             cursor, message) != MciGpmResult::OwnershipLost ||
            nextAr9565MciGpm(kEpoch, invalid, ring.data(), ring.size(), cursor,
                             message) != MciGpmResult::InvalidRegister ||
            nextAr9565MciGpm(kEpoch, reg(0xffffU), ring.data(), ring.size(),
                             cursor,
                             message) != MciGpmResult::InvalidRegister ||
            nextAr9565MciGpm(kEpoch, reg(1U), ring.data(), ring.size() - 1U,
                             cursor,
                             message) != MciGpmResult::InvalidArgument ||
            nextAr9565MciGpm(kEpoch, reg(1U), nullptr, ring.size(), cursor,
                             message) != MciGpmResult::InvalidArgument ||
            cursor.nextIndex != 3U || message.opcode != 0x99U)
        {
            return false;
        }
        // A stale register must not roll an active session back to index 0.
        if (attachAr9565MciGpm(kEpoch, reg(0xffffU), cursor) !=
                MciGpmResult::InvalidRegister ||
            attachAr9565MciGpm(0U, reg(1U), cursor) !=
                MciGpmResult::InvalidArgument ||
            cursor.nextIndex != 3U)
        {
            return false;
        }
        // Output must be disjoint from the DMA region, never an alias.
        // Deliberately overlap the ring and output to verify early rejection.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        auto *alias = reinterpret_cast<MciGpmMessage *>(ring.data());
        if (nextAr9565MciGpm(kEpoch, reg(1U), ring.data(), ring.size(), cursor,
                             *alias) != MciGpmResult::InvalidArgument ||
            cursor.nextIndex != 3U)
        {
            return false;
        }
        // Resynchronize after MCI RX reset in a new native epoch; old head
        // may never authorize a message from the successor's shared ring.
        if (attachAr9565MciGpm(kEpoch + 1U, reg(1U), cursor) !=
                MciGpmResult::Empty ||
            nextAr9565MciGpm(kEpoch, reg(2U), ring.data(), ring.size(), cursor,
                             message) != MciGpmResult::OwnershipLost)
        {
            return false;
        }
        return true;
    }

    bool sharedGpmBatchTests()
    {
        const auto physicalBoard = board();
        const auto evidence = sharedAuthorized();
        const auto dma = sharedBuffers();
        const SharedMciAntennaSelection topology {
            SharedMciAntennaTopology::OneSharedPaAndLna,
            true,
        };
        const SharedMciResetEvidence btQuiesced {true, true};
        Mock mock {};
        MciGpmCursor cursor {};
        if (stageAr9565SharedMciDma(physicalBoard, evidence, dma, io(mock))
                    .result != CoexistenceResult::Ok ||
            stageAr9565SharedMciAntenna(physicalBoard, evidence, dma, topology,
                                        io(mock))
                    .result != CoexistenceResult::Ok)
        {
            return false;
        }
        constexpr uint32_t kPointerShift = 16U;
        constexpr size_t kEntryBytes = kAr9565MciGpmMessageBytes;
        constexpr size_t kTypeField = 4U;
        constexpr size_t kOpcodeField = 5U;
        constexpr uint8_t kAgent = 0x0cU;
        const auto reg = [](uint32_t index)
        {
            return (index << kPointerShift) | kAr9565MciGpmEntries;
        };
        find(mock, kMciGpmEntries)->bits = reg(14U);
        if (resetAr9565SharedMciRxTx(physicalBoard, evidence, dma, topology,
                                     btQuiesced, io(mock), cursor)
                    .result != CoexistenceResult::Ok ||
            cursor.nextIndex != 14U)
        {
            return false;
        }
        // A real owner would synchronize this 16x16 coherent-DMA view and
        // snapshot the head while retaining its exclusive IRQ/MCI lease.
        std::array<uint8_t, kAr9565MciGpmBytes> ring {};
        ring.fill(0xfeU);
        ring.at(14U * kEntryBytes + kTypeField) = kAgent;
        ring.at(14U * kEntryBytes + kOpcodeField) = 1U;
        ring.at(14U * kEntryBytes) = 0x55U;
        ring.at(kTypeField) = kAgent;
        ring.at(kOpcodeField) = 6U;
        ring.at(kEntryBytes - 1U) = 0xa5U;
        find(mock, kMciGpmEntries)->bits = reg(1U);
        find(mock, kMciReceiveMessageRaw)->bits = kMciGpmReceived;
        find(mock, kMciInterruptRaw)->bits = kMciRxMessageInterrupt;
        const auto notification =
            pollAr9565MciPendingInterrupts(evidence, dma, cursor, io(mock));
        if (notification.progress.result != CoexistenceResult::Ok ||
            notification.progress.requiresReset ||
            !notification.gpmNotification ||
            notification.ownerEpoch != kEpoch ||
            find(mock, kMciReceiveMessageRaw)->bits != 0U)
        {
            return false;
        }
        MciGpmBatch batch {};
        batch.count = 7U;
        batch.messages[0].opcode = 0x99U;
        if (collectAr9565MciGpmBatch(notification, kEpoch, reg(1U), ring.data(),
                                     ring.size(), cursor,
                                     batch) != MciGpmResult::Message ||
            cursor.nextIndex != 1U || batch.count != 2U ||
            batch.messages[0].type != kAgent ||
            batch.messages[0].opcode != 1U ||
            batch.messages[0].payload[0] != 0x55U ||
            batch.messages[1].opcode != 6U ||
            batch.messages[1].payload[kEntryBytes - 1U] != 0xa5U)
        {
            return false;
        }
        ring.at(14U * kEntryBytes) = 0U;
        if (batch.messages[0].payload[0] != 0x55U)
        {
            return false;
        }
        // An IRQ can report a GPM notification with no remaining data: the
        // result is an empty copy, never a stale previous message batch.
        if (collectAr9565MciGpmBatch(notification, kEpoch, reg(1U), ring.data(),
                                     ring.size(), cursor,
                                     batch) != MciGpmResult::Empty ||
            cursor.nextIndex != 1U || batch.count != 0U ||
            batch.messages[0].type != 0U)
        {
            return false;
        }
        // A full-but-not-overwritten ring can contain 15 pending entries.
        // Copy all of them without losing the 15th or indexing a 16th.
        std::array<uint8_t, kAr9565MciGpmBytes> nearFullRing {};
        nearFullRing.fill(0xfeU);
        for (size_t index = 1U; index < kAr9565MciGpmEntries; ++index)
        {
            nearFullRing.at(index * kEntryBytes + kTypeField) = kAgent;
            nearFullRing.at(index * kEntryBytes + kOpcodeField) =
                static_cast<uint8_t>(index);
        }
        MciGpmCursor nearFullCursor {kEpoch, 1U, true};
        if (collectAr9565MciGpmBatch(notification, kEpoch, reg(0U),
                                     nearFullRing.data(), nearFullRing.size(),
                                     nearFullCursor,
                                     batch) != MciGpmResult::Message ||
            nearFullCursor.nextIndex != 0U ||
            batch.count != kAr9565MciGpmEntries - 1U)
        {
            return false;
        }
        for (size_t index = 0U; index < batch.count; ++index)
        {
            if (batch.messages[index].opcode != index + 1U)
            {
                return false;
            }
        }
        nearFullRing.fill(0xfeU);
        nearFullCursor = {kEpoch, 1U, true};
        if (collectAr9565MciGpmBatch(notification, kEpoch, reg(0U),
                                     nearFullRing.data(), nearFullRing.size(),
                                     nearFullCursor,
                                     batch) != MciGpmResult::Empty ||
            nearFullCursor.nextIndex != 0U || batch.count != 0U)
        {
            return false;
        }
        // The batch is backed by real writable memory. Its object bytes
        // still cannot also masquerade as the coherent GPM input region.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        const auto *overlappingRing = reinterpret_cast<const uint8_t *>(&batch);
        nearFullCursor = {kEpoch, 1U, true};
        batch.count = 5U;
        batch.messages[0].opcode = 0x99U;
        if (collectAr9565MciGpmBatch(notification, kEpoch, reg(0U),
                                     overlappingRing, kAr9565MciGpmBytes,
                                     nearFullCursor,
                                     batch) != MciGpmResult::InvalidArgument ||
            nearFullCursor.nextIndex != 1U || batch.count != 5U ||
            batch.messages[0].opcode != 0x99U)
        {
            return false;
        }
        // Rejected notifications, pointer, epoch or buffer must NOT expose
        // even a prefix of ring data or advance the caller's live cursor.
        for (size_t scenario = 0U; scenario < 10U; ++scenario)
        {
            MciGpmCursor old = cursor;
            old.nextIndex = 14U;
            MciGpmBatch output {};
            output.count = 3U;
            output.messages[0].opcode = 0x99U;
            MciPendingInterrupts event = notification;
            uint64_t epoch = kEpoch;
            uint32_t head = reg(1U);
            size_t bytes = ring.size();
            const uint8_t *region = ring.data();
            if (scenario == 0U)
            {
                event.progress.result = CoexistenceResult::ReadFailed;
            }
            else if (scenario == 1U)
            {
                event.progress.requiresReset = true;
            }
            else if (scenario == 2U)
            {
                event.hardwareFault = true;
            }
            else if (scenario == 3U)
            {
                event.gpmNotification = false;
            }
            else if (scenario == 4U)
            {
                event.ownerEpoch++;
            }
            else if (scenario == 5U)
            {
                epoch++;
            }
            else if (scenario == 6U)
            {
                head ^= 1U;
            }
            else if (scenario == 7U)
            {
                bytes--;
            }
            else if (scenario == 8U)
            {
                region = nullptr;
            }
            else
            {
                old.attached = false;
            }
            const auto result = collectAr9565MciGpmBatch(
                event, epoch, head, region, bytes, old, output);
            const auto expected =
                scenario < 4U    ? MciGpmResult::UnverifiedInterrupt
                : scenario < 6U  ? MciGpmResult::OwnershipLost
                : scenario == 6U ? MciGpmResult::InvalidRegister
                : scenario < 9U  ? MciGpmResult::InvalidArgument
                                 : MciGpmResult::NotAttached;
            if (result != expected || output.count != 3U ||
                output.messages[0].opcode != 0x99U || old.nextIndex != 14U ||
                old.attached != (scenario != 9U))
            {
                return false;
            }
        }
        return true;
    }

    WlanOnlyCoexistenceEvidence authorized()
    {
        return {true, true, true, true};
    }
} // namespace

int main()
{
    BoardDataSummary selection = board();
    WlanOnlyCoexistenceEvidence evidence = authorized();
    {
        Mock mock {};
        const CoexistenceProgress status =
            parkAr9565WlanOnlyCoexistence(selection, evidence, io(mock));
        if (status.result != CoexistenceResult::Ok || status.requiresReset ||
            status.completedWrites != kSteps ||
            status.completedReads != kSteps * 2 ||
            mock.registers.front().bits != 0 ||
            mock.registers.at(kMciControlIndex).bits != 0 ||
            (mock.registers.at(kGlobalIndex).bits & kBtOwnsSpdt) != 0 ||
            mock.registers.at(kMciTransmitIndex).bits != kSeed)
        {
            // The TX-control register retains every existing bit and sets
            // its disable-LNA-update bit (deliberately cleared initially).
            return kFailedSuccess;
        }
    }
    {
        Mock mock {};
        evidence.bluetoothAbsentOrQuiesced = false;
        if (parkAr9565WlanOnlyCoexistence(selection, evidence, io(mock))
                    .result != CoexistenceResult::MissingIsolation ||
            mock.writes != 0)
        {
            return kFailedAdmission;
        }
        evidence = authorized();
        selection.rxChainMask = 3;
        if (parkAr9565WlanOnlyCoexistence(selection, evidence, io(mock))
                    .result != CoexistenceResult::InvalidBoard ||
            mock.writes != 0)
        {
            return kFailedAdmission;
        }
        selection = board();
        auto badBar = io(mock);
        badBar.io.barLengthBytes = kGlobal;
        if (parkAr9565WlanOnlyCoexistence(selection, evidence, badBar).result !=
                CoexistenceResult::InvalidBar ||
            mock.writes != 0)
        {
            return kFailedBackend;
        }
    }
    const std::array<CoexistenceResult, 4> failures {
        {
            CoexistenceResult::WriteFailed,
            CoexistenceResult::ReadFailed,
            CoexistenceResult::ReadbackMismatch,
            CoexistenceResult::OwnershipLost,
        },
    };
    for (const CoexistenceResult failure : failures)
    {
        Mock mock {};
        if (failure == CoexistenceResult::WriteFailed)
        {
            mock.failWrite = kFailSecondWrite;
        }
        if (failure == CoexistenceResult::ReadFailed)
        {
            mock.failRead = kFailSecondReadback;
        }
        if (failure == CoexistenceResult::ReadbackMismatch)
        {
            mock.skipWrite = 1;
        }
        if (failure == CoexistenceResult::OwnershipLost)
        {
            mock.revokeAfter = kRevokeAfter;
        }
        const CoexistenceProgress result =
            parkAr9565WlanOnlyCoexistence(selection, evidence, io(mock));
        if (result.result != failure || !result.requiresReset ||
            mock.writes == 0)
        {
            return kFailedErrorPaths;
        }
    }
    if (!sharedMciTests())
    {
        return kFailedSharedMci;
    }
    if (!sharedAntennaTests())
    {
        return kFailedAntenna;
    }
    if (!sharedMciResetTests())
    {
        return kFailedMciReset;
    }
    if (!sharedMciTransmitTests())
    {
        return kFailedMciTransmit;
    }
    if (!sharedGpmDiagnosticTests())
    {
        return kFailedGpmDiagnostic;
    }
    if (!sharedMciInterruptTests())
    {
        return kFailedMciInterrupt;
    }
    if (!sharedGpmTests() || !sharedGpmBatchTests())
    {
        return kFailedGpm;
    }
    return 0;
}
