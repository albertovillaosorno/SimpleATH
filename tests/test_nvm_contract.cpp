// Copyright:
//   - Copyright © 2026 Alberto Villa Osorno
// SPDX-License-Identifier:
//   - MIT
// Confidential:
//   - false
// License-File:
//   - LICENSE-MIT
// Provenance:
//   - SimpleATH original; independently developed or locally authored
//
// Boundary-Contract:
// - Owns:
//   - Offline regression cases for nvm contract.
// - Must-Not:
//   - Require physical hardware, mutate installed drivers, or suppress
//     failures.
// - Allows:
//   - Inputs: isolated fixtures and reproducible source-under-test inputs.
//   - Outputs: assertions and observable regression verdicts.
//   - Side effects: test-local temporary files and bounded subprocesses only.
// - Split-When:
//   - A separate protocol stage needs independent validation and ownership.
// - Merge-When:
//   - The caller directly owns this narrow contract without reuse.
// - Summary:
//   - Offline regression cases for nvm contract.
// - Description:
//   - Implements or verifies the test_nvm_contract source boundary.
// - Usage:
//   - Executed by offline host test discovery or the native test harness.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Offline regression cases for nvm contract.
// All registers, time and ownership are synthetic callbacks; no device I/O.
#include "hardware/Ar9565Core.hpp"
#include "hardware/Ar9565NvmReader.hpp"
#include <array>
#include <cstddef>
#include <cstdint>

namespace
{
    constexpr uint32_t kNvmGoodWord = 0x3412U;
    constexpr uint32_t kNvmLowByte = 0x12U;
    constexpr uint32_t kNvmHighByte = 0x34U;
    constexpr uint32_t kReadEepromTrigger = 0x2000U;
    constexpr uint32_t kReadEepromStatus = 0x4084U;
    constexpr uint32_t kNativeBarBytes = 0x16000U;
    constexpr uint32_t kRevisionShift = 12U;
    constexpr uint32_t kRevisionMask = 0xffU;
    constexpr uint32_t kNvmBusy = 0x10000U;
    constexpr uint32_t kNvmUnstableStatus = 0x20000U;
    constexpr uint32_t kNvmProtected = 0x40000U;
    constexpr uint32_t kNvmAbsent = 0x80000U;
    constexpr uint32_t kNvmInvalidStatus = 0xffffffffU;
    constexpr uint64_t kRollbackTimestamp = 99U;
    constexpr uint64_t kForwardTimestamp = 100U;
    constexpr uint8_t kFillByte = 0xaaU;
    constexpr uint8_t kSentinel = 0xa5U;
    constexpr uint8_t kTrailingByte = 0x5aU;
    constexpr uint8_t kGuardByte = 0xffU;
    constexpr size_t kWordBytes = 2U;
    constexpr int kRevokeAtStartFailed = 5;
    constexpr int kRevokeAfterTriggerFailed = 6;
    constexpr int kRevokeDuringWaitFailed = 7;
    constexpr int kRevokeDuringBudgetFailed = 8;
    constexpr int kBackendAliasFailed = 9;
    constexpr int kIdentityAliasFailed = 10;
    constexpr int kRevokeAtPublicationFailed = 11;
    constexpr int kPoisonedStatusFailed = 12;
    constexpr int kPoisonedBackendFailed = 13;

    struct FakeNvm
    {
            uint32_t statusReads = 0;
            uint32_t registerReads = 0;
            uint32_t finalStatus = kNvmGoodWord;
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
    bool neverOwned(void * /*unused*/)
    {
        return false;
    }

    bool failingRead(void * /*unused*/, uint32_t /*unused*/,
                     uint32_t * /*unused*/)
    {
        return false;
    }

    bool read(void *context, uint32_t offset, uint32_t *value)
    {
        auto &fake = *static_cast<FakeNvm *>(context);
        ++fake.registerReads;
        if (!fake.d0)
        {
            ++fake.readsAfterRevocation;
        }
        switch (offset)
        {
            case simpleath::kRevisionRegister:
                *value = (static_cast<uint32_t>(simpleath::kMacFamily)
                          << kRevisionShift) |
                         kRevisionMask;
                break;
            case simpleath::kRtcStatusRegister:
                *value = simpleath::kRtcOn;
                break;
            case kReadEepromTrigger: // EEPROM trigger window.
                *value = 0;
                fake.triggerSeen = true;
                break;
            case kReadEepromStatus: // Ready sample followed by payload/status
                                    // re-read.
                *value = ++fake.statusReads == 1 ? fake.firstStatus
                                                 : fake.finalStatus;
                if (fake.statusReads == 2 && (fake.poisonStatus != nullptr))
                {
                    fake.poisonStatus->bytesAcquired = 2;
                }
                if (fake.statusReads == 1 && (fake.poisonBackend != nullptr))
                {
                    fake.poisonBackend->read32 = failingRead;
                }
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
        {
            ++fake.clocksAfterRevocation;
        }
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
        return fake.backwards && fake.clockReads > 1 ? kRollbackTimestamp
                                                     : kForwardTimestamp;
    }

    void delay(void *context, uint32_t /*unused*/)
    {
        auto &fake = *static_cast<FakeNvm *>(context);
        if (!fake.d0)
        {
            ++fake.delaysAfterRevocation;
        }
    }

    simpleath::NvmResult capture(FakeNvm &fake,
                                 std::array<uint8_t, kWordBytes> &bytes,
                                 simpleath::NvmReadStatus &status)
    {
        const simpleath::NvmReadBackend backend {
            &fake, owned, read, clock, delay, kNativeBarBytes,
        };
        const simpleath::Identity identity {
            simpleath::kPciVendor, simpleath::kPciDevice, 0, 0, false,
        };
        return simpleath::captureAr9565Nvm(backend, identity,
                                           simpleath::NvmSource::Eeprom,
                                           bytes.data(), bytes.size(), status);
    }

    bool rejectFinalFaults(FakeNvm &fake,
                           std::array<uint8_t, kWordBytes> &bytes,
                           simpleath::NvmReadStatus &status)
    {
        using simpleath::NvmResult;
        constexpr std::array<uint32_t, 5U> faults {
            kNvmAbsent,         kNvmProtected,     kNvmBusy,
            kNvmUnstableStatus, kNvmInvalidStatus,
        };
        constexpr std::array<NvmResult, 5U> expected {
            NvmResult::StorageAbsent,      NvmResult::ProtectedAccess,
            NvmResult::UnstableStatus,     NvmResult::UnstableStatus,
            NvmResult::RegisterReadFailed,
        };
        for (size_t i = 0; i < faults.size(); ++i)
        {
            fake = {};
            fake.finalStatus = faults.at(i);
            bytes.fill(kFillByte);
            if (capture(fake, bytes, status) != expected.at(i) ||
                status.captureComplete || fake.statusReads != 2 ||
                (bytes.at(0U) != 0U) || (bytes.at(1U) != 0U))
            {
                return false;
            }
        }
        return true;
    }

    bool rejectEarlyFaults(FakeNvm &fake,
                           std::array<uint8_t, kWordBytes> &bytes,
                           simpleath::NvmReadStatus &status)
    {
        using simpleath::NvmResult;
        // Protected or absent access at the FIRST status sample is terminal:
        // neither fault may be polled until a timeout or read as payload.
        constexpr std::array<uint32_t, 2U> earlyFaults {
            kNvmProtected,
            kNvmAbsent,
        };
        constexpr std::array<NvmResult, 2U> earlyExpected {
            NvmResult::ProtectedAccess,
            NvmResult::StorageAbsent,
        };
        for (size_t i = 0; i < earlyFaults.size(); ++i)
        {
            fake = {};
            fake.firstStatus = earlyFaults.at(i);
            bytes.fill(kFillByte);
            if (capture(fake, bytes, status) != earlyExpected.at(i) ||
                fake.statusReads != 1 || status.polls != 1 ||
                status.captureComplete || (bytes.at(0U) != 0U) ||
                (bytes.at(1U) != 0U))
            {
                return false;
            }
        }
        return true;
    }

} // namespace

int main()
{
    using simpleath::NvmResult;
    FakeNvm fake {};
    std::array<uint8_t, kWordBytes> bytes {kFillByte, kFillByte};
    simpleath::NvmReadStatus status {};
    if (capture(fake, bytes, status) != NvmResult::Ok ||
        !status.captureComplete || status.bytesAcquired != bytes.size() ||
        fake.statusReads != 2 || bytes.at(0U) != kNvmLowByte ||
        bytes.at(1U) != kNvmHighByte)
    {
        return 1;
    }
    if (!rejectFinalFaults(fake, bytes, status))
    {
        return 2;
    }
    if (!rejectEarlyFaults(fake, bytes, status))
    {
        return 3;
    }
    fake = {};
    fake.backwards = true;
    bytes.fill(kFillByte);
    if (capture(fake, bytes, status) != NvmResult::InvalidClock ||
        status.captureComplete || (bytes.at(0U) != 0U) || (bytes.at(1U) != 0U))
    {
        return 4;
    }
    // A revoked owner must be checked before the clock is ever called.
    // Even a monotonic timer callback can require the owner's live context.
    fake = {};
    fake.d0 = false;
    bytes.fill(kFillByte);
    if (capture(fake, bytes, status) != NvmResult::SessionUnavailable ||
        fake.ownerChecks != 1 || fake.clockReads != 0 ||
        fake.registerReads != 0 || status.captureComplete ||
        (bytes.at(0U) != 0U) || (bytes.at(1U) != 0U))
    {
        return kRevokeAtStartFailed;
    }

    // The post-trigger timestamp can revoke its owner after the read's last
    // successful D0 preflight. The next timer call checks ownership anew.
    fake = {};
    fake.revokeAfterTriggerTimestamp = true;
    bytes.fill(kFillByte);
    if (capture(fake, bytes, status) != NvmResult::SessionUnavailable ||
        !fake.triggerSeen || fake.clocksAfterRevocation != 0 ||
        fake.statusReads != 0 || status.captureComplete ||
        (bytes.at(0U) != 0U) || (bytes.at(1U) != 0U))
    {
        return kRevokeAfterTriggerFailed;
    }

    // The clock may revoke the owner during the busy-status timestamp. Do not
    // invoke even a bounded delay callback with that invalidated context.
    fake = {};
    fake.firstStatus = kNvmBusy;
    fake.revokeDuringWaitTimestamp = true;
    bytes.fill(kFillByte);
    if (capture(fake, bytes, status) != NvmResult::SessionUnavailable ||
        fake.statusReads != 1 || fake.clocksAfterFirstStatus != 2 ||
        fake.delaysAfterRevocation != 0 || status.captureComplete ||
        (bytes.at(0U) != 0U) || (bytes.at(1U) != 0U))
    {
        return kRevokeDuringWaitFailed;
    }

    // A monotonic time callback can revoke D0 during the first read budget.
    // It is not safe to read even the silicon revision register afterward.
    fake = {};
    fake.revokeDuringFirstBudgetClock = true;
    bytes.fill(kFillByte);
    if (capture(fake, bytes, status) != NvmResult::SessionUnavailable ||
        fake.clockReads != 2 || fake.registerReads != 0 ||
        fake.readsAfterRevocation != 0 || status.captureComplete ||
        (bytes.at(0U) != 0U) || (bytes.at(1U) != 0U))
    {
        return kRevokeDuringBudgetFailed;
    }
    // The last payload read may finish its post-clock D0 check and copy its
    // bytes while the provider loses power. A direct caller must not receive
    // captureComplete or retained data without a fresh publication gate.
    fake = {};
    fake.revokeAfterFinalPayloadCheck = true;
    bytes.fill(kFillByte);
    if (capture(fake, bytes, status) != NvmResult::SessionUnavailable ||
        fake.d0 || fake.finalPayloadOwnerChecks != 3 ||
        (fake.readsAfterRevocation != 0U) ||
        (fake.clocksAfterRevocation != 0U) || status.captureComplete ||
        (bytes.at(0U) != 0U) || (bytes.at(1U) != 0U) ||
        status.bytesAcquired != bytes.size())
    {
        return kRevokeAtPublicationFailed;
    }

    // Opaque callback state must not be borrowed from the callback table or
    // from the physical PCI identity. An owner callback is allowed to mutate
    // its context; invoking one with either borrowed input risks corrupting
    // subsequent function calls or the identity being validated.
    const simpleath::Identity identity {
        simpleath::kPciVendor, simpleath::kPciDevice, 0, 0, false,
    };
    simpleath::NvmReadBackend aliasedBackend {
        nullptr, neverOwned, read, clock, delay, kNativeBarBytes,
    };
    aliasedBackend.context = &aliasedBackend;
    bytes.fill(kSentinel);
    status.result = NvmResult::Ok;
    if (simpleath::captureAr9565Nvm(
            aliasedBackend, identity, simpleath::NvmSource::Eeprom,
            bytes.data(), bytes.size(), status) != NvmResult::InvalidArgument ||
        status.result != NvmResult::Ok || bytes.at(0U) != kSentinel ||
        bytes.at(1U) != kSentinel)
    {
        return kBackendAliasFailed;
    }
    simpleath::Identity mutableIdentity = identity;
    aliasedBackend.context = &mutableIdentity;
    if (simpleath::captureAr9565Nvm(
            aliasedBackend, mutableIdentity, simpleath::NvmSource::Eeprom,
            bytes.data(), bytes.size(), status) != NvmResult::InvalidArgument ||
        status.result != NvmResult::Ok || bytes.at(0U) != kSentinel ||
        bytes.at(1U) != kSentinel)
    {
        return kIdentityAliasFailed;
    }
    // Callback retaining separate status pointer cannot redirect copied bytes
    // outside the declared output length or forge the acquired byte count.
    fake = {};
    fake.poisonStatus = &status;
    simpleath::NvmReadBackend safeBackend {
        &fake, owned, read, clock, delay, kNativeBarBytes,
    };
    std::array<uint8_t, 4U> guarded {
        kGuardByte,
        kGuardByte,
        kSentinel,
        kTrailingByte,
    };
    if (simpleath::captureAr9565Nvm(
            safeBackend, identity, simpleath::NvmSource::Eeprom, guarded.data(),
            kWordBytes, status) != NvmResult::Ok ||
        !status.captureComplete || status.bytesAcquired != 2 ||
        guarded.at(0U) != kNvmLowByte || guarded.at(1U) != kNvmHighByte ||
        guarded.at(2U) != kSentinel || guarded.at(3U) != kTrailingByte)
    {
        return kPoisonedStatusFailed;
    }

    // A callback's separately retained pointer to the input table cannot
    // silently redirect the next MMIO read to a different function.
    fake = {};
    fake.poisonBackend = &safeBackend;
    safeBackend = {&fake, owned, read, clock, delay, kNativeBarBytes};
    std::array<uint8_t, kWordBytes> words {};
    if (simpleath::captureAr9565Nvm(safeBackend, identity,
                                    simpleath::NvmSource::Eeprom, words.data(),
                                    words.size(), status) != NvmResult::Ok ||
        !status.captureComplete || status.bytesAcquired != 2 ||
        words.at(0U) != kNvmLowByte || words.at(1U) != kNvmHighByte ||
        safeBackend.read32 != failingRead)
    {
        return kPoisonedBackendFailed;
    }
    return 0;
}
