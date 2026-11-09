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
            uint32_t clocksAfterRevocation = 0;
            uint32_t delaysAfterRevocation = 0;
            uint32_t readsAfterRevocation = 0;
            uint32_t clocksAfterFirstStatus = 0;
            bool triggerSeen = false;
            bool revokeAfterTriggerTimestamp = false;
            bool revokeDuringWaitTimestamp = false;
            bool revokeDuringFirstBudgetClock = false;
            bool revokeAfterFinalPayloadCheck = false;
            uint32_t finalPayloadOwnerChecks = 0;
            simpleath::NvmReadStatus *poisonStatus = nullptr;
            simpleath::NvmReadBackend *poisonBackend = nullptr;
            bool backwards = false;
            bool d0 = true;
    };

    bool owned(void *context)
    {
        auto &fake = *static_cast<FakeNvm *>(context);
        ++fake.ownerChecks;
        if (fake.revokeAfterFinalPayloadCheck && fake.statusReads == 2 &&
            ++fake.finalPayloadOwnerChecks == 2)
        {
            // The last payload read's post-clock gate still reports true,
            // then D0 disappears before captured bytes are published.
            fake.d0 = false;
            return true;
        }
        return fake.d0;
    }

    // Deliberately does not dereference the forged opaque context. A pointer
    // into borrowed callback/identity storage must be rejected even when this
    // provider would otherwise fail harmlessly.
    bool neverOwned(void *)
    {
        return false;
    }

    bool failingRead(void *, uint32_t, uint32_t *)
    {
        return false;
    }

    bool read(void *context, uint32_t offset, uint32_t *value)
    {
        auto &fake = *static_cast<FakeNvm *>(context);
        ++fake.registerReads;
        if (!fake.d0)
            ++fake.readsAfterRevocation;
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
                fake.triggerSeen = true;
                break;
            case 0x4084: // Ready sample followed by payload/status re-read.
                *value = ++fake.statusReads == 1 ? fake.firstStatus
                                                 : fake.finalStatus;
                if (fake.statusReads == 2 && fake.poisonStatus)
                    fake.poisonStatus->bytesAcquired = 2;
                if (fake.statusReads == 1 && fake.poisonBackend)
                    fake.poisonBackend->read32 = failingRead;
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
        if (!fake.d0)
            ++fake.clocksAfterRevocation;
        if (fake.revokeDuringFirstBudgetClock && fake.clockReads == 2)
        {
            // Capture construction consumed clock sample one. The first
            // read() budget consumes sample two, which may revoke the owner.
            fake.revokeDuringFirstBudgetClock = false;
            fake.d0 = false;
        }
        if (fake.triggerSeen && fake.revokeAfterTriggerTimestamp)
        {
            // The post-trigger timestamp itself revokes ownership. The wait
            // loop must preflight its next clock rather than trust this one.
            fake.revokeAfterTriggerTimestamp = false;
            fake.d0 = false;
        }
        if (fake.statusReads == 1 && fake.revokeDuringWaitTimestamp &&
            ++fake.clocksAfterFirstStatus == 2)
        {
            // The clock itself revokes D0 after the post-read budget clock;
            // the wait loop must not call a delay on the revoked provider.
            fake.revokeDuringWaitTimestamp = false;
            fake.d0 = false;
        }
        return fake.backwards && fake.clockReads > 1 ? 99 : 100;
    }

    void delay(void *context, uint32_t)
    {
        auto &fake = *static_cast<FakeNvm *>(context);
        if (!fake.d0)
            ++fake.delaysAfterRevocation;
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

    // The post-trigger timestamp can revoke its owner after the read's last
    // successful D0 preflight. The next timer call checks ownership anew.
    fake = {};
    fake.revokeAfterTriggerTimestamp = true;
    bytes[0] = bytes[1] = 0xaa;
    if (capture(fake, bytes, status) != NvmResult::SessionUnavailable ||
        !fake.triggerSeen || fake.clocksAfterRevocation != 0 ||
        fake.statusReads != 0 || status.captureComplete || bytes[0] || bytes[1])
        return 6;

    // The clock may revoke the owner during the busy-status timestamp. Do not
    // invoke even a bounded delay callback with that invalidated context.
    fake = {};
    fake.firstStatus = 0x10000;
    fake.revokeDuringWaitTimestamp = true;
    bytes[0] = bytes[1] = 0xaa;
    if (capture(fake, bytes, status) != NvmResult::SessionUnavailable ||
        fake.statusReads != 1 || fake.clocksAfterFirstStatus != 2 ||
        fake.delaysAfterRevocation != 0 || status.captureComplete || bytes[0] ||
        bytes[1])
        return 7;

    // A monotonic time callback can revoke D0 during the first read budget.
    // It is not safe to read even the silicon revision register afterward.
    fake = {};
    fake.revokeDuringFirstBudgetClock = true;
    bytes[0] = bytes[1] = 0xaa;
    if (capture(fake, bytes, status) != NvmResult::SessionUnavailable ||
        fake.clockReads != 2 || fake.registerReads != 0 ||
        fake.readsAfterRevocation != 0 || status.captureComplete || bytes[0] ||
        bytes[1])
        return 8;
    // The last payload read may finish its post-clock D0 check and copy its
    // bytes while the provider loses power. A direct caller must not receive
    // captureComplete or retained data without a fresh publication gate.
    fake = {};
    fake.revokeAfterFinalPayloadCheck = true;
    bytes[0] = bytes[1] = 0xaa;
    if (capture(fake, bytes, status) != NvmResult::SessionUnavailable ||
        fake.d0 || fake.finalPayloadOwnerChecks != 3 ||
        fake.readsAfterRevocation || fake.clocksAfterRevocation ||
        status.captureComplete || bytes[0] || bytes[1] ||
        status.bytesAcquired != sizeof(bytes))
        return 11;

    // Opaque callback state must not be borrowed from the callback table or
    // from the physical PCI identity. An owner callback is allowed to mutate
    // its context; invoking one with either borrowed input risks corrupting
    // subsequent function calls or the identity being validated.
    const simpleath::Identity identity {simpleath::kPciVendor,
                                        simpleath::kPciDevice, 0, 0, false};
    simpleath::NvmReadBackend aliasedBackend {nullptr, neverOwned, read,
                                              clock,   delay,      0x16000};
    aliasedBackend.context = &aliasedBackend;
    bytes[0] = bytes[1] = 0xa5;
    status.result = NvmResult::Ok;
    if (simpleath::captureAr9565Nvm(
            aliasedBackend, identity, simpleath::NvmSource::Eeprom, bytes,
            sizeof(bytes), status) != NvmResult::InvalidArgument ||
        status.result != NvmResult::Ok || bytes[0] != 0xa5 || bytes[1] != 0xa5)
        return 9;
    simpleath::Identity mutableIdentity = identity;
    aliasedBackend.context = &mutableIdentity;
    if (simpleath::captureAr9565Nvm(
            aliasedBackend, mutableIdentity, simpleath::NvmSource::Eeprom,
            bytes, sizeof(bytes), status) != NvmResult::InvalidArgument ||
        status.result != NvmResult::Ok || bytes[0] != 0xa5 || bytes[1] != 0xa5)
        return 10;
    // Callback retaining separate status pointer cannot redirect copied bytes
    // outside the declared output length or forge the acquired byte count.
    fake = {};
    fake.poisonStatus = &status;
    simpleath::NvmReadBackend safeBackend {&fake, owned, read,
                                           clock, delay, 0x16000};
    uint8_t guarded[4] {0xff, 0xff, 0xa5, 0x5a};
    if (simpleath::captureAr9565Nvm(safeBackend, identity,
                                    simpleath::NvmSource::Eeprom, guarded, 2,
                                    status) != NvmResult::Ok ||
        !status.captureComplete || status.bytesAcquired != 2 ||
        guarded[0] != 0x12 || guarded[1] != 0x34 || guarded[2] != 0xa5 ||
        guarded[3] != 0x5a)
        return 12;

    // A callback's separately retained pointer to the input table cannot
    // silently redirect the next MMIO read to a different function.
    fake = {};
    fake.poisonBackend = &safeBackend;
    safeBackend = {&fake, owned, read, clock, delay, 0x16000};
    uint8_t words[2] {};
    if (simpleath::captureAr9565Nvm(safeBackend, identity,
                                    simpleath::NvmSource::Eeprom, words,
                                    sizeof(words), status) != NvmResult::Ok ||
        !status.captureComplete || status.bytesAcquired != 2 ||
        words[0] != 0x12 || words[1] != 0x34 ||
        safeBackend.read32 != failingRead)
        return 13;
    return 0;
}
