// SPDX-License-Identifier: AGPL-3.0-only
// Synthetic owner and MMIO writer: no radio, PCI, DMA or TX is touched.
#include "hardware/Ar9565RfIni.hpp"
#include <cstddef>
#include <cstdint>

using namespace simpleath;

namespace
{
    struct Mock
    {
            bool allowed = true;
            size_t writes = 0;
            size_t delays = 0;
            size_t failAfter = 0;
            uint32_t firstOffset = 0;
            uint32_t lastOffset = 0;
    };

    bool permit(void *p, uint64_t epoch)
    {
        return static_cast<Mock *>(p)->allowed && epoch == 7;
    }

    bool write(void *p, uint32_t offset, uint32_t)
    {
        auto &m = *static_cast<Mock *>(p);
        if (m.failAfter && m.writes >= m.failAfter)
            return false;
        if (!m.writes)
            m.firstOffset = offset;
        m.lastOffset = offset;
        ++m.writes;
        return true;
    }

    void delay(void *p, uint32_t micros)
    {
        if (micros == 1)
            ++static_cast<Mock *>(p)->delays;
    }
} // namespace

int main()
{
    Channel channel {};
    if (mapChannel(6, channel) != Result::Ok)
        return 1;
    const CalibrationAndRegulatory trusted {true, true, true, true,
                                            true, true, true};
    RegisterRecipe recipe {};
    if (createInitRecipe(Revision::V1_1, channel, ChannelWidth::Ht20,
                         TxGainProfile::LowOb, RxGainProfile::Standard, trusted,
                         recipe) != Result::Ok)
        return 2;
    Mock mock {};
    const RfIniBackend backend {&mock, 7, 0x20000, permit, write, delay};
    auto progress = applyAr9565RfIni(recipe, trusted, backend);
    if (progress.result != RfIniResult::Ok || progress.requiresReset ||
        progress.completedWrites != recipe.registerWrites ||
        progress.completedPhases != recipe.count ||
        mock.writes != recipe.registerWrites ||
        mock.delays != recipe.registerWrites / 32)
        return 3;
    mock = {};
    mock.allowed = false;
    progress = applyAr9565RfIni(recipe, trusted, backend);
    if (progress.result != RfIniResult::OwnershipLost || mock.writes ||
        progress.requiresReset)
        return 4;
    mock = {};
    mock.failAfter = 1;
    progress = applyAr9565RfIni(recipe, trusted, backend);
    if (progress.result != RfIniResult::WriteFailed ||
        !progress.requiresReset || progress.completedWrites != 1 ||
        mock.writes != 1)
        return 5;
    mock = {};
    auto forged = recipe;
    forged.phases[0].count++;
    progress = applyAr9565RfIni(forged, trusted, backend);
    if (progress.result != RfIniResult::InvalidRecipe || mock.writes)
        return 6;
    mock = {};
    auto small = backend;
    small.barLengthBytes = 0x1000;
    progress = applyAr9565RfIni(recipe, trusted, small);
    if (progress.result != RfIniResult::InvalidRecipe || mock.writes)
        return 7;
    mock = {};
    auto untrusted = trusted;
    untrusted.radioKillUnblocked = false;
    progress = applyAr9565RfIni(recipe, untrusted, backend);
    if (progress.result != RfIniResult::InvalidRecipe || mock.writes)
        return 8;
    mock = {};
    auto receive = trusted;
    receive.use = RadioInitialization::ReceiveOnly;
    receive.txPowerLimitsVerified = false;
    receive.localCountryRulesAvailable = false;
    RegisterRecipe passive {};
    if (createInitRecipe(Revision::V1_1, channel, ChannelWidth::Ht20,
                         TxGainProfile::LowOb, RxGainProfile::Standard, receive,
                         passive) != Result::Ok)
        return 9;
    progress = applyAr9565RfIni(passive, receive, backend);
    if (progress.result != RfIniResult::Ok || passive.regulatoryAuthorized ||
        mock.writes != passive.registerWrites)
        return 10;
    receive.use = RadioInitialization::TransmitReceive;
    mock = {};
    progress = applyAr9565RfIni(passive, receive, backend);
    if (progress.result != RfIniResult::InvalidRecipe || mock.writes)
        return 11;
    return 0;
}
