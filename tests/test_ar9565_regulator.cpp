// SPDX-License-Identifier: GPL-2.0-only
// Synthetic EEPROM + PMU MMIO model. No real RF/hardware/device.
#include "hardware/Ar9565Calibration.hpp"
#include "hardware/Ar9565Eeprom.hpp"
#include "hardware/Ar9565Regulator.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>

using namespace simpleath;

namespace
{
    constexpr uint64_t kEpoch = 15;
    constexpr uint32_t kPmu1 = 0x16340;
    constexpr uint32_t kXtal = 0x16298;
    constexpr uint32_t kCapMask = 0x7f;
    constexpr uint32_t kCapInShift = 24;
    constexpr uint32_t kCapOutShift = 17;
    constexpr uint32_t kCapInField = 0x7f000000;
    constexpr uint32_t kCapOutField = 0x00fe0000;
    constexpr uint8_t kTuningFeature = 0x40;
    constexpr uint8_t kTuningValue = 0x5a;
    constexpr size_t kTuningValueOffset = 40;
    constexpr int kBadTuning = 5;
    constexpr uint32_t kBar = 0x20000;
    constexpr uint32_t kInitial = 0xa0;
    constexpr uint32_t kSwreg = 0x12345678;
    constexpr uint8_t kRegulatorEnable = 0x10;
    constexpr size_t kEnableOffset = 42;
    constexpr size_t kMacOffset = 2;
    constexpr size_t kChainMaskOffset = 32;
    constexpr size_t kOpFlagsOffset = 33;
    constexpr uint8_t kChainMask = 0x11;
    constexpr uint8_t kOpFlags = 0x02;
    constexpr std::array<uint8_t, 6> kPhysicalTestMac {
        {
            0x02,
            0x04,
            0x06,
            0x08,
            0x0a,
            0x0c,
        },
    };
    constexpr uint32_t kEightBits = 8;
    constexpr uint32_t kSixteenBits = 16;
    constexpr uint32_t kTwentyFourBits = 24;
    constexpr size_t kSwregOffset = 49;
    constexpr size_t kPier0 = 138;
    constexpr size_t kPier1 = 139;
    constexpr size_t kPier2 = 140;
    constexpr uint8_t kPierBin0 = 112;
    constexpr uint8_t kPierBin1 = 137;
    constexpr uint8_t kPierBin2 = 162;
    constexpr int kBadSuccess = 1;
    constexpr int kBadDenial = 2;
    constexpr int kBadFailure = 3;
    constexpr int kBadBar = 4;

    struct Mock
    {
            uint32_t pmu1 = kInitial;
            uint32_t xtal = kInitial;
            size_t reads {};
            size_t writes {};
            size_t permits {};
            bool powered {true};
            bool failRead {false};
            bool failWrite {false};
            bool skipWrite {false};
            bool revokeAfterWrite {false};
    };

    bool permit(void *context, uint64_t epoch)
    {
        auto &mock = *static_cast<Mock *>(context);
        ++mock.permits;
        return mock.powered && epoch == kEpoch &&
               (!mock.revokeAfterWrite || mock.writes == 0);
    }

    bool read(void *context, uint32_t offset, uint32_t *result)
    {
        auto &mock = *static_cast<Mock *>(context);
        ++mock.reads;
        if (mock.failRead || (offset != kPmu1 && offset != kXtal) ||
            result == nullptr)
        {
            return false;
        }
        *result = offset == kPmu1 ? mock.pmu1 : mock.xtal;
        return true;
    }

    template <typename Address, typename Value>
    bool write(void *context, Address offset, Value value)
    {
        auto &mock = *static_cast<Mock *>(context);
        ++mock.writes;
        if (mock.failWrite || (offset != kPmu1 && offset != kXtal))
        {
            return false;
        }
        if (!mock.skipWrite)
        {
            if (offset == kPmu1)
            {
                mock.pmu1 = value;
            }
            else
            {
                mock.xtal = value;
            }
        }
        return true;
    }

    void delay(void * /*context*/, uint32_t /*micros*/)
    {
    }

    RxAgcBackend backend(Mock &mock)
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

    EepromImage image()
    {
        EepromImage result {};
        result.restored = true;
        result.appliedBlocks = 1;
        result.bytes[0] = 2;
        std::memcpy(static_cast<void *>(&result.bytes[kMacOffset]),
                    kPhysicalTestMac.data(), kPhysicalTestMac.size());
        result.bytes[kChainMaskOffset] = kChainMask;
        result.bytes[kOpFlagsOffset] = kOpFlags;
        result.bytes[kPier0] = kPierBin0;
        result.bytes[kPier1] = kPierBin1;
        result.bytes[kPier2] = kPierBin2;
        return result;
    }

    RegulatorEvidence authorized()
    {
        return {true, true};
    }

    int testTuningCaps(EepromImage board, RegulatorEvidence evidence)
    {
        // EEPROM may disable tuning caps; untouched XTAL means no guessed
        // analog values. Bit6 selects identical input/output caps, preserving
        // other bits.
        {
            Mock mock {};
            const XtalTuneProgress untuned =
                configureAr9565XtalCapacitors(board, evidence, backend(mock));
            if (untuned.result != RegulatorResult::Ok ||
                untuned.requiresReset || mock.writes != 0 || mock.reads != 0)
            {
                return kBadTuning;
            }
            board.bytes[kEnableOffset] = kTuningFeature;
            board.bytes[kTuningValueOffset] = kTuningValue;
            const XtalTuneProgress tuned =
                configureAr9565XtalCapacitors(board, evidence, backend(mock));
            const uint32_t cap = kTuningValue & kCapMask;
            const uint32_t expected =
                (kInitial & ~(kCapInField | kCapOutField)) |
                (cap << kCapInShift) | (cap << kCapOutShift);
            if (tuned.result != RegulatorResult::Ok || tuned.requiresReset ||
                tuned.completedWrites != 1 || tuned.completedReads != 2 ||
                tuned.programmedXtal != expected || mock.xtal != expected ||
                mock.pmu1 != kInitial)
            {
                return kBadTuning;
            }
        }
        {
            Mock mock {};
            auto tooShort = backend(mock);
            tooShort.io.barLengthBytes = kXtal;
            if (configureAr9565XtalCapacitors(board, evidence, tooShort)
                        .result != RegulatorResult::InvalidBar ||
                mock.writes != 0)
            {
                return kBadTuning;
            }
            mock.skipWrite = true;
            const XtalTuneProgress mismatch =
                configureAr9565XtalCapacitors(board, evidence, backend(mock));
            if (mismatch.result != RegulatorResult::ReadbackMismatch ||
                !mismatch.requiresReset || mock.writes != 1)
            {
                return kBadTuning;
            }
        }
        {
            Mock mock {};
            mock.revokeAfterWrite = true;
            const XtalTuneProgress revoked =
                configureAr9565XtalCapacitors(board, evidence, backend(mock));
            if (revoked.result != RegulatorResult::OwnershipLost ||
                !revoked.requiresReset || mock.writes != 1)
            {
                return kBadTuning;
            }
        }
        return 0;
    }
} // namespace

int main()
{
    EepromImage board = image();
    RegulatorEvidence evidence = authorized();
    {
        Mock mock {};
        const RegulatorProgress status =
            configureAr9565InternalRegulator(board, evidence, backend(mock));
        if (status.result != RegulatorResult::Ok || status.requiresReset ||
            mock.pmu1 != (kInitial | 1U) || status.completedWrites != 1 ||
            status.completedReads != 2)
        {
            return kBadSuccess;
        }
    }
    {
        Mock mock {};
        board.bytes[kEnableOffset] = kRegulatorEnable;
        board.bytes[kSwregOffset] = static_cast<uint8_t>(kSwreg);
        board.bytes[kSwregOffset + 1] =
            static_cast<uint8_t>(kSwreg >> kEightBits);
        board.bytes[kSwregOffset + 2] =
            static_cast<uint8_t>(kSwreg >> kSixteenBits);
        board.bytes[kSwregOffset + 3] =
            static_cast<uint8_t>(kSwreg >> kTwentyFourBits);
        const RegulatorProgress status =
            configureAr9565InternalRegulator(board, evidence, backend(mock));
        if (status.result != RegulatorResult::Ok || status.requiresReset ||
            mock.pmu1 != kSwreg || status.programmedPmu1 != kSwreg)
        {
            return kBadSuccess;
        }
    }
    {
        Mock mock {};
        evidence.physicalBoardVerified = false;
        if (configureAr9565InternalRegulator(board, evidence, backend(mock))
                    .result != RegulatorResult::MissingAuthority ||
            mock.writes != 0)
        {
            return kBadDenial;
        }
        evidence = authorized();
        board.bytes[kPier2] = board.bytes[kPier1];
        if (configureAr9565InternalRegulator(board, evidence, backend(mock))
                    .result != RegulatorResult::InvalidBoard ||
            mock.writes != 0)
        {
            return kBadDenial;
        }
        board = image();
        auto invalidBar = backend(mock);
        invalidBar.io.barLengthBytes = kPmu1;
        if (configureAr9565InternalRegulator(board, evidence, invalidBar)
                    .result != RegulatorResult::InvalidBar ||
            mock.writes != 0)
        {
            return kBadBar;
        }
    }
    for (const unsigned failed : {1U, 2U, 3U, 4U})
    {
        Mock mock {};
        mock.failWrite = failed == 1U;
        mock.skipWrite = failed == 2U;
        mock.revokeAfterWrite = failed == 3U;
        mock.failRead = failed == 4U;
        if (failed == 4U)
        {
            mock.pmu1 = kInitial;
        }
        const RegulatorProgress status =
            configureAr9565InternalRegulator(board, evidence, backend(mock));
        if (failed == 4U)
        {
            if (status.result != RegulatorResult::ReadFailed ||
                status.requiresReset || mock.writes != 0)
            {
                return kBadFailure;
            }
        }
        else if (status.result == RegulatorResult::Ok ||
                 !status.requiresReset || mock.writes != 1)
        {
            return kBadFailure;
        }
    }
    const int tuneResult = testTuningCaps(board, evidence);
    if (tuneResult != 0)
    {
        return tuneResult;
    }
    return 0;
}
