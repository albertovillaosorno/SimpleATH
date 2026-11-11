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
    constexpr size_t kTotalRegisters = 13;
    constexpr size_t kSharedMciStageSteps = 8;
    constexpr uint32_t kMciScheduleAddress = 0x1818;
    constexpr uint32_t kMciGpmAddress = 0x1820;
    constexpr uint32_t kMciGpmEntries = 0x1824;
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
                },
            };
            std::array<uint32_t, kTotalRegisters> writeOrder {};
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
            reg->bits = bits;
        }
        return true;
    }

    void delay(void * /*context*/, uint32_t /*micros*/)
    {
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
    if (!sharedGpmTests())
    {
        return kFailedGpm;
    }
    return 0;
}
