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
    constexpr size_t kTotalRegisters = 20;
    constexpr size_t kSharedMciStageSteps = 8;
    constexpr size_t kSharedAntennaStageSteps = 8;
    constexpr uint32_t kMciScheduleAddress = 0x1818;
    constexpr uint32_t kMciGpmAddress = 0x1820;
    constexpr uint32_t kMciGpmEntries = 0x1824;
    constexpr uint32_t kMciCommand2 = 0x1808;
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
                },
            };
            std::array<uint32_t, kTotalRegisters> writeOrder {};
            std::array<uint32_t, kTotalRegisters> writeValues {};
            size_t delays {};
            bool invalidateGpmAfterReset {};
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
            find(mock, kMciReceiveMessageRaw)->bits = kMciGpmReceived;
            find(mock, kMciInterruptRaw)->bits = kMciHardwareFault;
            const auto result =
                pollAr9565MciPendingInterrupts(evidence, dma, cursor, io(mock));
            if (result.progress.result != CoexistenceResult::Ok ||
                !result.hardwareFault || !result.progress.requiresReset ||
                result.gpmNotification || result.bluetoothRenegotiationRequired)
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
                result.progress.requiresReset != (scenario != 1U) ||
                !cursor.attached || cursor.ownerEpoch != kEpoch ||
                result.gpmNotification ||
                result.bluetoothRenegotiationRequired || result.hardwareFault ||
                result.rawMessageInterrupt != 0U || result.rawInterrupt != 0U)
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
    if (!sharedMciInterruptTests())
    {
        return kFailedMciInterrupt;
    }
    if (!sharedGpmTests())
    {
        return kFailedGpm;
    }
    return 0;
}
