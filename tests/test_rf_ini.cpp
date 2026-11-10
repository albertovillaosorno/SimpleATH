// SPDX-License-Identifier: GPL-2.0-only
// Synthetic owner and MMIO writer: no radio, PCI, DMA or TX is touched.
#include "hardware/Ar9565Core.hpp"
#include "hardware/Ar9565InitCatalog.hpp"
#include "hardware/Ar9565RfIni.hpp"
#include <cstddef>
#include <cstdint>

using namespace simpleath;

namespace
{
    constexpr uint64_t kOwnerEpoch = 7U;
    constexpr uint8_t kTestChannel = 6U;
    constexpr uint32_t kValidBarBytes = 0x20000U;
    constexpr uint32_t kTooSmallBarBytes = 0x1000U;
    constexpr size_t kWriteDelayInterval = 32U;

    // Report the failing source line with a nonzero process exit code,
    // including if the line number eventually becomes a multiple of 256.
    int failureAtLine(unsigned line)
    {
        return static_cast<int>(line | 1U);
    }

    struct Mock
    {
            bool allowed = true;
            size_t writes = 0;
            size_t delays = 0;
            size_t failAfter = 0;
            uint32_t firstOffset = 0;
            uint32_t lastOffset = 0;
    };

    bool permit(void *context, uint64_t epoch)
    {
        return static_cast<Mock *>(context)->allowed && epoch == kOwnerEpoch;
    }

    bool write(void *context, uint32_t offset, uint32_t /*value*/)
    {
        auto &mock = *static_cast<Mock *>(context);
        if (mock.failAfter != 0U && mock.writes >= mock.failAfter)
        {
            return false;
        }
        if (mock.writes == 0U)
        {
            mock.firstOffset = offset;
        }
        mock.lastOffset = offset;
        ++mock.writes;
        return true;
    }

    void delay(void *context, uint32_t micros)
    {
        if (micros == 1U)
        {
            ++static_cast<Mock *>(context)->delays;
        }
    }
} // namespace

int main()
{
    Channel channel {};
    if (mapChannel(kTestChannel, channel) != Result::Ok)
    {
        return failureAtLine(__LINE__);
    }
    const CalibrationAndRegulatory trusted {
        true, true, true, true,
        true, true, true, RadioInitialization::TransmitReceive,
    };
    RegisterRecipe recipe {};
    if (createInitRecipe(Revision::V1_1, channel, ChannelWidth::Ht20,
                         TxGainProfile::LowOb, RxGainProfile::Standard, trusted,
                         recipe) != Result::Ok)
    {
        return failureAtLine(__LINE__);
    }
    Mock mock {};
    const RfIniBackend backend {
        &mock, kOwnerEpoch, kValidBarBytes, permit, write, delay,
    };
    auto progress = applyAr9565RfIni(recipe, trusted, backend);
    if (progress.result != RfIniResult::Ok || progress.requiresReset ||
        progress.completedWrites != recipe.registerWrites ||
        progress.completedPhases != recipe.count ||
        mock.writes != recipe.registerWrites ||
        mock.delays != recipe.registerWrites / kWriteDelayInterval)
    {
        return failureAtLine(__LINE__);
    }
    mock = {};
    mock.allowed = false;
    progress = applyAr9565RfIni(recipe, trusted, backend);
    if (progress.result != RfIniResult::OwnershipLost || mock.writes != 0U ||
        progress.requiresReset)
    {
        return failureAtLine(__LINE__);
    }
    mock = {};
    mock.failAfter = 1;
    progress = applyAr9565RfIni(recipe, trusted, backend);
    if (progress.result != RfIniResult::WriteFailed ||
        !progress.requiresReset || progress.completedWrites != 1 ||
        mock.writes != 1)
    {
        return failureAtLine(__LINE__);
    }
    mock = {};
    auto forged = recipe;
    forged.phases[0].count++;
    progress = applyAr9565RfIni(forged, trusted, backend);
    if (progress.result != RfIniResult::InvalidRecipe || mock.writes != 0U)
    {
        return failureAtLine(__LINE__);
    }
    mock = {};
    auto small = backend;
    small.barLengthBytes = kTooSmallBarBytes;
    progress = applyAr9565RfIni(recipe, trusted, small);
    if (progress.result != RfIniResult::InvalidRecipe || mock.writes != 0U)
    {
        return failureAtLine(__LINE__);
    }
    mock = {};
    auto untrusted = trusted;
    untrusted.radioKillUnblocked = false;
    progress = applyAr9565RfIni(recipe, untrusted, backend);
    if (progress.result != RfIniResult::InvalidRecipe || mock.writes != 0U)
    {
        return failureAtLine(__LINE__);
    }
    mock = {};
    auto receive = trusted;
    receive.use = RadioInitialization::ReceiveOnly;
    receive.txPowerLimitsVerified = false;
    receive.localCountryRulesAvailable = false;
    RegisterRecipe passive {};
    if (createInitRecipe(Revision::V1_1, channel, ChannelWidth::Ht20,
                         TxGainProfile::LowOb, RxGainProfile::Standard, receive,
                         passive) != Result::Ok)
    {
        return failureAtLine(__LINE__);
    }
    progress = applyAr9565RfIni(passive, receive, backend);
    if (progress.result != RfIniResult::Ok || passive.regulatoryAuthorized ||
        mock.writes != passive.registerWrites)
    {
        return failureAtLine(__LINE__);
    }
    receive.use = RadioInitialization::TransmitReceive;
    mock = {};
    progress = applyAr9565RfIni(passive, receive, backend);
    if (progress.result != RfIniResult::InvalidRecipe || mock.writes != 0U)
    {
        return failureAtLine(__LINE__);
    }
    return 0;
}
