// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Alberto Villa Osorno.
// All registers, time and ownership are synthetic callbacks; no device I/O.
#include "hardware/Ar9565NvmReader.hpp"

namespace
{
    struct FakeNvm
    {
            uint32_t statusReads = 0;
            uint32_t registerReads = 0;
            uint32_t finalStatus = 0x3412;
            uint32_t firstStatus = 0;
            uint32_t clockReads = 0;
            uint32_t ownerChecks = 0;
            bool backwards = false;
            bool d0 = true;
    };

    bool owned(void *context)
    {
        auto &fake = *static_cast<FakeNvm *>(context);
        ++fake.ownerChecks;
        return fake.d0;
    }

    bool read(void *context, uint32_t offset, uint32_t *value)
    {
        auto &fake = *static_cast<FakeNvm *>(context);
        ++fake.registerReads;
        switch (offset)
        {
            case simpleath::kRevisionRegister:
                *value = (static_cast<uint32_t>(simpleath::kMacFamily) << 12) |
                         0xffu;
                break;
            case simpleath::kRtcStatusRegister:
                *value = simpleath::kRtcOn;
                break;
            case 0x2000: // EEPROM trigger window.
                *value = 0;
                break;
            case 0x4084: // Ready sample followed by payload/status re-read.
                *value = ++fake.statusReads == 1 ? fake.firstStatus
                                                 : fake.finalStatus;
                break;
            default:
                return false;
        }
        return true;
    }

    uint64_t clock(void *context)
    {
        auto &fake = *static_cast<FakeNvm *>(context);
        ++fake.clockReads;
        return fake.backwards && fake.clockReads > 1 ? 99 : 100;
    }

    void delay(void *, uint32_t)
    {
    }

    simpleath::NvmResult capture(FakeNvm &fake, uint8_t (&bytes)[2],
                                 simpleath::NvmReadStatus &status)
    {
        const simpleath::NvmReadBackend backend {&fake, owned, read,
                                                 clock, delay, 0x16000};
        const simpleath::Identity identity {simpleath::kPciVendor,
                                            simpleath::kPciDevice, 0, 0, false};
        return simpleath::captureAr9565Nvm(backend, identity,
                                           simpleath::NvmSource::Eeprom, bytes,
                                           sizeof(bytes), status);
    }
} // namespace

int main()
{
    using simpleath::NvmResult;
    FakeNvm fake {};
    uint8_t bytes[2] {0xaa, 0xaa};
    simpleath::NvmReadStatus status {};
    if (capture(fake, bytes, status) != NvmResult::Ok ||
        !status.captureComplete || status.bytesAcquired != sizeof(bytes) ||
        fake.statusReads != 2 || bytes[0] != 0x12 || bytes[1] != 0x34)
        return 1;
    const uint32_t faults[] = {0x80000, 0x40000, 0x10000, 0x20000, 0xffffffffu};
    const NvmResult expected[] = {
        NvmResult::StorageAbsent, NvmResult::ProtectedAccess,
        NvmResult::UnstableStatus, NvmResult::UnstableStatus,
        NvmResult::RegisterReadFailed};
    for (size_t i = 0; i < sizeof(faults) / sizeof(faults[0]); ++i)
    {
        fake = {};
        fake.finalStatus = faults[i];
        bytes[0] = bytes[1] = 0xaa;
        if (capture(fake, bytes, status) != expected[i] ||
            status.captureComplete || fake.statusReads != 2 || bytes[0] ||
            bytes[1])
            return 2;
    }
    // Protected or absent access at the FIRST status sample is terminal:
    // neither fault may be polled until a timeout or read as payload.
    const uint32_t earlyFaults[] = {0x40000, 0x80000};
    const NvmResult earlyExpected[] = {NvmResult::ProtectedAccess,
                                       NvmResult::StorageAbsent};
    for (size_t i = 0; i < sizeof(earlyFaults) / sizeof(earlyFaults[0]); ++i)
    {
        fake = {};
        fake.firstStatus = earlyFaults[i];
        bytes[0] = bytes[1] = 0xaa;
        if (capture(fake, bytes, status) != earlyExpected[i] ||
            fake.statusReads != 1 || status.polls != 1 ||
            status.captureComplete || bytes[0] || bytes[1])
            return 3;
    }
    fake = {};
    fake.backwards = true;
    bytes[0] = bytes[1] = 0xaa;
    if (capture(fake, bytes, status) != NvmResult::InvalidClock ||
        status.captureComplete || bytes[0] || bytes[1])
        return 4;
    // A revoked owner must be checked before the clock is ever called.
    // Even a monotonic timer callback can require the owner's live context.
    fake = {};
    fake.d0 = false;
    bytes[0] = bytes[1] = 0xaa;
    if (capture(fake, bytes, status) != NvmResult::SessionUnavailable ||
        fake.ownerChecks != 1 || fake.clockReads != 0 ||
        fake.registerReads != 0 || status.captureComplete || bytes[0] ||
        bytes[1])
        return 5;
    return 0;
}
