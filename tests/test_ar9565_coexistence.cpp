// SPDX-License-Identifier: AGPL-3.0-only
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

    struct Register
    {
            uint32_t address;
            uint32_t bits;
    };

    struct Mock
    {
            std::array<Register, kSteps> registers {
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
                },
            };
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
    return 0;
}
