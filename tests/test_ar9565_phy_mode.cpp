// SPDX-License-Identifier: GPL-2.0-only
// Synthetic AR9565 channel-width PHY/MAC mode and guarded MMIO test.
#include "hardware/Ar9565Calibration.hpp"
#include "hardware/Ar9565Channel.hpp"
#include "hardware/Ar9565Core.hpp"
#include "hardware/Ar9565InitCatalog.hpp"
#include "hardware/Ar9565PhyMode.hpp"
#include <array>
#include <cstddef>
#include <cstdint>

using namespace simpleath;

namespace
{
    enum class TestFailure : int
    {
        Ht20 = 1,
        Ht40Plus = 2,
        Ht40Minus = 3,
        Japan = 4,
        Invalid = 5,
        Auth = 6,
        Bar = 7,
        Write = 8,
        Read = 9,
        Revoked = 10,
        Mismatch = 11,
    };
    constexpr uint64_t kEpoch = 73;
    constexpr uint32_t kBar = 0x12000;
    constexpr uint32_t kPhyModeRegister = 0xa204;
    constexpr uint32_t kMacModeRegister = 0x8318;
    constexpr uint32_t kGtxToRegister = 0x64;
    constexpr uint32_t kCstRegister = 0x6c;
    constexpr uint32_t kReservedPhy = 0xc0000000;
    constexpr uint32_t kReservedMac = 0xdead0000;
    constexpr uint32_t kMask = 0x7ff;
    constexpr uint32_t kHt = 0x40;
    constexpr uint32_t kShortGi = 0x80;
    constexpr uint32_t kFirstHtTraining = 0x200;
    constexpr uint32_t kDynamic = 4;
    constexpr uint32_t kPrimaryBelow = 0x10;
    constexpr uint32_t kTimerMask = 0xffff0000;
    constexpr uint32_t kInitialTxCounter = 0x55;
    constexpr uint32_t kInitialCarrierCounter = 0xaa;
    constexpr uint32_t kExpectedTxTimeout = 25;
    constexpr uint32_t kExpectedCarrierTimeout = 15;
    constexpr uint32_t kTimerShift = 16;
    constexpr uint8_t kChannel6 = 6;
    constexpr uint8_t kChannel2 = 2;
    constexpr uint8_t kChannel10 = 10;
    constexpr uint8_t kChannel14 = 14;
    constexpr uint8_t kInvalidSecondary = 9;
    constexpr size_t kReads = 8;
    constexpr size_t kWrites = 4;
    constexpr size_t kRevokeAfterFirstWrite = 1;

    struct Mock
    {
            std::array<uint32_t, kBar / sizeof(uint32_t)> words {};
            size_t reads {};
            size_t writes {};
            uint32_t rejectReadOffset {};
            uint32_t rejectWriteOffset {};
            uint32_t distortOffset {};
            bool powered {true};
            bool revokeAfterFirst {};
    };

    bool permit(void *context, uint64_t epoch)
    {
        const auto &mock = *static_cast<Mock *>(context);
        return mock.powered && epoch == kEpoch;
    }

    bool read(void *context, uint32_t offset, uint32_t *value)
    {
        auto &mock = *static_cast<Mock *>(context);
        ++mock.reads;
        if (offset >= kBar || (offset & 3U) != 0 || value == nullptr ||
            offset == mock.rejectReadOffset)
        {
            return false;
        }
        *value = mock.words.at(offset / sizeof(uint32_t));
        if (offset == mock.distortOffset && mock.reads % 2U == 0U)
        {
            *value ^= kHt;
        }
        return true;
    }

    bool write(void *context, uint32_t offset, uint32_t value)
    {
        auto &mock = *static_cast<Mock *>(context);
        ++mock.writes;
        if (offset >= kBar || offset == mock.rejectWriteOffset)
        {
            return false;
        }
        mock.words.at(offset / sizeof(uint32_t)) = value;
        if (mock.revokeAfterFirst && mock.writes == kRevokeAfterFirstWrite)
        {
            mock.powered = false;
        }
        return true;
    }

    void delay(void * /*unusedContext*/, uint32_t /*unusedMicros*/)
    {
    }

    RxAgcBackend backend(Mock &mock, uint32_t barLength = kBar)
    {
        return {{&mock, kEpoch, barLength, permit, write, delay}, read};
    }

    CalibrationAndRegulatory authorized(bool japan = false)
    {
        CalibrationAndRegulatory policy {};
        policy.eepromContentsVerified = true;
        policy.boardAntennaConfigurationVerified = true;
        policy.channelPermitted = true;
        policy.radioKillUnblocked = true;
        policy.coexistenceConfigurationVerified = true;
        policy.localCountryRulesAvailable = japan;
        policy.use = RadioInitialization::ReceiveOnly;
        return policy;
    }

    RfChannelRequest request(uint8_t primary, ChannelWidth width,
                             uint8_t secondary = 0)
    {
        Channel control {};
        (void)mapChannel(primary, control);
        return {
            Revision::V1_1,
            control,
            width,
            secondary,
            RfReferenceClock::Crystal40Mhz,
        };
    }

    void seed(Mock &mock)
    {
        mock.words.at(kPhyModeRegister / sizeof(uint32_t)) =
            kReservedPhy | kMask;
        mock.words.at(kMacModeRegister / sizeof(uint32_t)) = kReservedMac | 1U;
        mock.words.at(kGtxToRegister / sizeof(uint32_t)) = kInitialTxCounter;
        mock.words.at(kCstRegister / sizeof(uint32_t)) = kInitialCarrierCounter;
    }

    bool success(Mock &mock, RfChannelRequest channel,
                 CalibrationAndRegulatory permission, uint32_t wantedPhy,
                 uint32_t joined)
    {
        seed(mock);
        const auto result =
            programAr9565ReceiveOnlyPhyMode(channel, permission, backend(mock));
        return result.result == PhyModeResult::Ok && !result.requiresReset &&
               result.completedReads == kReads &&
               result.completedWrites == kWrites && mock.reads == kReads &&
               mock.writes == kWrites &&
               mock.words.at(kPhyModeRegister / sizeof(uint32_t)) ==
                   (kReservedPhy | wantedPhy) &&
               mock.words.at(kMacModeRegister / sizeof(uint32_t)) ==
                   (kReservedMac | joined) &&
               (mock.words.at(kGtxToRegister / sizeof(uint32_t)) &
                kTimerMask) == (kExpectedTxTimeout << kTimerShift) &&
               (mock.words.at(kCstRegister / sizeof(uint32_t)) & kTimerMask) ==
                   (kExpectedCarrierTimeout << kTimerShift);
    }

    int checkModes()
    {
        Mock normal {};
        if (!success(normal, request(kChannel6, ChannelWidth::Ht20),
                     authorized(), kHt | kShortGi | kFirstHtTraining, 0))
        {
            return static_cast<int>(TestFailure::Ht20);
        }
        Mock plus {};
        if (!success(plus, request(kChannel6, ChannelWidth::Ht40, kChannel10),
                     authorized(),
                     kHt | kShortGi | kFirstHtTraining | kDynamic |
                         kPrimaryBelow,
                     1))
        {
            return static_cast<int>(TestFailure::Ht40Plus);
        }
        Mock minus {};
        if (!success(minus, request(kChannel6, ChannelWidth::Ht40, kChannel2),
                     authorized(), kHt | kShortGi | kFirstHtTraining | kDynamic,
                     1))
        {
            return static_cast<int>(TestFailure::Ht40Minus);
        }
        Mock japan {};
        if (!success(japan, request(kChannel14, ChannelWidth::Ht20),
                     authorized(true), 0, 0))
        {
            return static_cast<int>(TestFailure::Japan);
        }
        return 0;
    }

    int checkRejects()
    {
        Mock invalid {};
        const auto malformed =
            request(kChannel6, ChannelWidth::Ht40, kInvalidSecondary);
        if (programAr9565ReceiveOnlyPhyMode(malformed, authorized(),
                                            backend(invalid))
                    .result != PhyModeResult::InvalidChannel ||
            invalid.writes != 0)
        {
            return static_cast<int>(TestFailure::Invalid);
        }
        auto denied = authorized();
        denied.radioKillUnblocked = false;
        if (programAr9565ReceiveOnlyPhyMode(
                request(kChannel6, ChannelWidth::Ht20), denied,
                backend(invalid))
                    .result != PhyModeResult::MissingAuthorization ||
            invalid.writes != 0)
        {
            return static_cast<int>(TestFailure::Auth);
        }
        if (programAr9565ReceiveOnlyPhyMode(
                request(kChannel6, ChannelWidth::Ht20), authorized(),
                backend(invalid, kPhyModeRegister))
                    .result != PhyModeResult::InvalidBar ||
            invalid.writes != 0)
        {
            return static_cast<int>(TestFailure::Bar);
        }
        return 0;
    }

    int checkFaults()
    {
        Mock failedWrite {};
        failedWrite.rejectWriteOffset = kPhyModeRegister;
        const auto writeFailure = programAr9565ReceiveOnlyPhyMode(
            request(kChannel6, ChannelWidth::Ht20), authorized(),
            backend(failedWrite));
        if (writeFailure.result != PhyModeResult::WriteFailed ||
            !writeFailure.requiresReset || failedWrite.writes != 1)
        {
            return static_cast<int>(TestFailure::Write);
        }
        Mock failedRead {};
        failedRead.rejectReadOffset = kMacModeRegister;
        const auto readFailure = programAr9565ReceiveOnlyPhyMode(
            request(kChannel6, ChannelWidth::Ht20), authorized(),
            backend(failedRead));
        if (readFailure.result != PhyModeResult::ReadFailed ||
            !readFailure.requiresReset || failedRead.writes != 1)
        {
            return static_cast<int>(TestFailure::Read);
        }
        Mock revoked {};
        revoked.revokeAfterFirst = true;
        const auto lost = programAr9565ReceiveOnlyPhyMode(
            request(kChannel6, ChannelWidth::Ht20), authorized(),
            backend(revoked));
        if (lost.result != PhyModeResult::OwnershipLost ||
            !lost.requiresReset || revoked.writes != 1)
        {
            return static_cast<int>(TestFailure::Revoked);
        }
        Mock distorted {};
        distorted.distortOffset = kPhyModeRegister;
        const auto mismatch = programAr9565ReceiveOnlyPhyMode(
            request(kChannel6, ChannelWidth::Ht20), authorized(),
            backend(distorted));
        if (mismatch.result != PhyModeResult::ReadbackMismatch ||
            !mismatch.requiresReset || distorted.writes != 1)
        {
            return static_cast<int>(TestFailure::Mismatch);
        }
        return 0;
    }
} // namespace

int main()
{
    const int modes = checkModes();
    if (modes != 0)
    {
        return modes;
    }
    const int preflight = checkRejects();
    return preflight == 0 ? checkFaults() : preflight;
}
