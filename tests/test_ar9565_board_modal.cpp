// Synthetic IOKit-independent MMIO model; never uses a real device.
#include "hardware/Ar9565BoardModal.hpp"
#include "hardware/Ar9565Calibration.hpp"
#include "hardware/Ar9565Eeprom.hpp"
#include "hardware/Ar9565InitCatalog.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

using namespace simpleath;

namespace
{
    constexpr size_t kSecondPierOffset = 139;
    constexpr size_t kThirdPierOffset = 140;
    constexpr uint8_t kThirdPierBin = 162;
    constexpr size_t kAttenuationMarginOffset = 70;
    constexpr uint8_t kInvalidMargin = 0xff;
    constexpr uint32_t kCommonMask = 0x00ffffff;
    constexpr uint32_t kChainMask = 0x00000fff;
    constexpr uint32_t kSpdtTestMask = 0x0000fff1;
    constexpr uint32_t kAttenTestMask = 0x0001f03f;
    constexpr uint32_t kXpaTestMask = 0x00000300;
    constexpr uint32_t kGainTestMask = 0x7f800000;
    constexpr uint32_t kSpdtTestShift = 4;
    constexpr uint32_t kAttenTestShift = 12;
    constexpr uint32_t kXpaTestShift = 8;
    constexpr int kSuccessMismatchExit = 1;
    constexpr int kAuthorizationExit = 2;
    constexpr int kInvalidPierExit = 3;
    constexpr int kInvalidMarginExit = 4;
    constexpr int kFaultsExit = 5;
    constexpr int kInvalidBarExit = 6;
    constexpr size_t kRegisterCount = 10;
    constexpr uint64_t kEpoch = 45;
    constexpr uint32_t kAvailableBar = 0x24000;
    constexpr uint32_t kOriginal = 0xf0000000;
    constexpr uint32_t kSwitchCommon = 0xa288;
    constexpr uint32_t kSwitchCommon2 = 0xa28c;
    constexpr uint32_t kSwitchChain = 0xa284;
    constexpr uint32_t kGlb = 0x20044;
    constexpr uint32_t kAtten = 0x9e18;
    constexpr uint32_t kXpaBias = 0x1628c;
    constexpr uint32_t kMcGain = 0x9e28;
    constexpr uint32_t kCck = 0x9fc0;
    constexpr uint32_t kRestart = 0x9e24;
    constexpr uint32_t kBtLna = 0x1a64;
    constexpr uint32_t kExpectedCommon = 0x123456;
    constexpr uint32_t kExpectedCommon2 = 0x12345;
    constexpr uint32_t kExpectedChain = 0x150;
    constexpr uint32_t kExpectedSpdt = 0x321;
    constexpr uint32_t kExpectedAtten = 0x07;
    constexpr uint32_t kExpectedMargin = 0x09;
    constexpr uint32_t kExpectedXpaBias = 0x02;
    constexpr uint32_t kExpectedGain = 0x12000000;
    constexpr uint32_t kExpectedProtectedGain = 0x13800000;
    constexpr uint32_t kExpectedFastDiv = 0x2000;
    constexpr uint32_t kExpectedRestart = 0x00200000;
    constexpr uint32_t kExpectedForcedLna = 0x00008000;
    constexpr size_t kBusyAtThirdWrite = 3;
    constexpr size_t kFailSecondWrite = 2;
    constexpr size_t kFailSecondRead = 2;
    constexpr size_t kMutateOnFirstWrite = 1;

    struct Register
    {
            uint32_t offset;
            uint32_t value;
    };

    struct Fake
    {
            std::array<Register, kRegisterCount> registers {
                {
                    {kSwitchCommon, kOriginal},
                    {kSwitchCommon2, kOriginal},
                    {kSwitchChain, kOriginal},
                    {kGlb, kOriginal},
                    {kAtten, kOriginal},
                    {kXpaBias, kOriginal},
                    {kMcGain, kOriginal},
                    {kCck, kOriginal},
                    {kRestart, kOriginal},
                    {kBtLna, kOriginal},
                },
            };
            size_t reads {};
            size_t writes {};
            size_t permits {};
            size_t revokeAfterWrites {};
            size_t failReadAt {};
            size_t failWriteAt {};
            size_t suppressWriteAt {};
            bool powered {true};
    };

    Register *find(Fake &fake, uint32_t offset)
    {
        for (auto &entry : fake.registers)
        {
            if (entry.offset == offset)
            {
                return &entry;
            }
        }
        return nullptr;
    }

    bool permit(void *context, uint64_t epoch)
    {
        auto &fake = *static_cast<Fake *>(context);
        ++fake.permits;
        return epoch == kEpoch && fake.powered &&
               (fake.revokeAfterWrites == 0 ||
                fake.writes < fake.revokeAfterWrites);
    }

    bool read(void *context, uint32_t offset, uint32_t *out)
    {
        auto &fake = *static_cast<Fake *>(context);
        ++fake.reads;
        if (fake.failReadAt == fake.reads || out == nullptr)
        {
            return false;
        }
        const Register *entry = find(fake, offset);
        if (entry == nullptr)
        {
            return false;
        }
        *out = entry->value;
        return true;
    }

    template <typename RegisterOffset, typename RegisterValue>
    bool write(void *context, RegisterOffset offset, RegisterValue value)
    {
        auto &fake = *static_cast<Fake *>(context);
        ++fake.writes;
        if (fake.failWriteAt == fake.writes)
        {
            return false;
        }
        Register *entry = find(fake, offset);
        if (entry == nullptr)
        {
            return false;
        }
        if (fake.suppressWriteAt != fake.writes)
        {
            entry->value = value;
        }
        return true;
    }

    void delay(void * /*unusedContext*/, uint32_t /*unusedMicros*/)
    {
    }

    RxAgcBackend backend(Fake &fake)
    {
        return {
            {
                &fake,
                kEpoch,
                kAvailableBar,
                permit,
                write<uint32_t, uint32_t>,
                delay,
            },
            read,
        };
    }

    CalibrationAndRegulatory allowed()
    {
        CalibrationAndRegulatory a {};
        a.eepromContentsVerified = true;
        a.boardAntennaConfigurationVerified = true;
        a.channelPermitted = true;
        a.radioKillUnblocked = true;
        a.coexistenceConfigurationVerified = true;
        a.use = RadioInitialization::ReceiveOnly;
        return a;
    }

    EepromImage syntheticBoard()
    {
        EepromImage image {};
        image.restored = true;
        image.appliedBlocks = 1;

        struct ImageByte
        {
                size_t offset;
                uint8_t value;
        };

        constexpr std::array<ImageByte, 26> kImageBytes {
            {
                {0, 2},
                {1, 3},
                {2, 0x02},
                {3, 0x11},
                {4, 0x22},
                {5, 0x33},
                {6, 0x44},
                {7, 0x55},
                {32, 0x11},
                {33, 0x02},
                {53, 0x56},
                {54, 0x34},
                {55, 0x12},
                {57, 0x45},
                {58, 0x23},
                {59, 0x01},
                {61, 0x50},
                {62, 0x01},
                {67, kExpectedAtten},
                {70, kExpectedMargin},
                {95, kExpectedXpaBias},
                {114, 0x21},
                {115, 0x03},
                {138, 112},
                {139, 137},
                {kThirdPierOffset, kThirdPierBin},
            },
        };
        std::array<uint8_t, kAr9300EepromImageBytes> packed {};
        for (const auto &entry : kImageBytes)
        {
            packed.at(entry.offset) = entry.value;
        }
        std::memcpy(static_cast<void *>(&image.bytes[0]), packed.data(),
                    sizeof(image.bytes));
        return image;
    }

    bool checked(const Fake &fake, BoardModalDiversity mode)
    {
        const bool shared = mode == BoardModalDiversity::SharedWithBluetooth;
        const auto value = [&](uint32_t offset) -> uint32_t
        {
            for (const auto &entry : fake.registers)
            {
                if (entry.offset == offset)
                {
                    return entry.value;
                }
            }
            return 0;
        };
        return (value(kSwitchCommon) & kCommonMask) == kExpectedCommon &&
               (value(kSwitchCommon2) & kCommonMask) == kExpectedCommon2 &&
               (value(kSwitchChain) & kChainMask) == kExpectedChain &&
               (value(kGlb) & kSpdtTestMask) ==
                   ((kExpectedSpdt << kSpdtTestShift) | 1U) &&
               (value(kAtten) & kAttenTestMask) ==
                   ((kExpectedMargin << kAttenTestShift) | kExpectedAtten) &&
               (value(kXpaBias) & kXpaTestMask) ==
                   (kExpectedXpaBias << kXpaTestShift) &&
               (value(kMcGain) & kGainTestMask) ==
                   (shared ? kExpectedProtectedGain : kExpectedGain) &&
               (value(kCck) & kExpectedFastDiv) == kExpectedFastDiv &&
               (value(kRestart) & kExpectedRestart) ==
                   (shared ? kExpectedRestart : 0U) &&
               (value(kBtLna) & kExpectedForcedLna) ==
                   (shared ? kExpectedForcedLna : 0U);
    }
} // namespace

int main()
{
    EepromImage image = syntheticBoard();
    CalibrationAndRegulatory authority = allowed();
    for (const BoardModalDiversity mode : {
             BoardModalDiversity::WlanOnly,
             BoardModalDiversity::SharedWithBluetooth,
         })
    {
        Fake fake {};
        const BoardModalProgress result =
            programAr9565BoardModal2G(image, authority, mode, backend(fake));
        if (result.result != BoardModalResult::Ok || result.requiresReset ||
            result.completedWrites != kRegisterCount ||
            result.completedReads != kRegisterCount * 2 || !checked(fake, mode))
        {
            return kSuccessMismatchExit;
        }
    }
    // Refuse all unverified board, epoch and policy stages before writes.
    {
        Fake fake {};
        authority.coexistenceConfigurationVerified = false;
        if (programAr9565BoardModal2G(
                image, authority, BoardModalDiversity::WlanOnly, backend(fake))
                    .result != BoardModalResult::MissingAuthorization ||
            fake.writes != 0)
        {
            return kAuthorizationExit;
        }
        authority = allowed();
        image.bytes[kThirdPierOffset] = image.bytes[kSecondPierOffset];
        if (programAr9565BoardModal2G(
                image, authority, BoardModalDiversity::WlanOnly, backend(fake))
                    .result != BoardModalResult::InvalidBoard ||
            fake.writes != 0)
        {
            return kInvalidPierExit;
        }
        image = syntheticBoard();
        image.bytes[kAttenuationMarginOffset] = kInvalidMargin;
        if (programAr9565BoardModal2G(
                image, authority, BoardModalDiversity::WlanOnly, backend(fake))
                    .result != BoardModalResult::InvalidBoard ||
            fake.writes != 0)
        {
            return kInvalidMarginExit;
        }
    }
    image = syntheticBoard();
    {
        Fake fake {};
        auto io = backend(fake);
        io.io.barLengthBytes = kGlb;
        if (programAr9565BoardModal2G(image, authority,
                                      BoardModalDiversity::WlanOnly, io)
                    .result != BoardModalResult::InvalidBar ||
            fake.writes != 0)
        {
            return kInvalidBarExit;
        }
    }
    // Every callback ambiguity is sticky reset, never a stale success.
    const std::array<BoardModalResult, 4> failures {
        {
            BoardModalResult::WriteFailed,
            BoardModalResult::ReadFailed,
            BoardModalResult::ReadbackMismatch,
            BoardModalResult::OwnershipLost,
        },
    };
    for (const BoardModalResult failure : failures)
    {
        Fake fake {};
        if (failure == BoardModalResult::WriteFailed)
        {
            fake.failWriteAt = kFailSecondWrite;
        }
        if (failure == BoardModalResult::ReadFailed)
        {
            fake.failReadAt = kFailSecondRead + 1;
        }
        if (failure == BoardModalResult::ReadbackMismatch)
        {
            fake.suppressWriteAt = kMutateOnFirstWrite;
        }
        if (failure == BoardModalResult::OwnershipLost)
        {
            fake.revokeAfterWrites = kBusyAtThirdWrite;
        }
        const BoardModalProgress progress = programAr9565BoardModal2G(
            image, authority, BoardModalDiversity::WlanOnly, backend(fake));
        if (progress.result != failure || !progress.requiresReset ||
            fake.writes == 0)
        {
            return kFaultsExit;
        }
    }
    return 0;
}
