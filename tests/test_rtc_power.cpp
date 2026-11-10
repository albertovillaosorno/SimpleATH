// Copyright (c) 2026 Alberto Villa Osorno.
// Synthetic RTC owner/clock/MMIO callbacks only; never touches hardware.
#include "hardware/Ar9565Core.hpp"
#include "hardware/Ar9565RtcPower.hpp"
#include <cstdint>

using namespace simpleath;

namespace
{
    constexpr uint64_t kInitialMicros = 100U;
    constexpr uint32_t kProviderToken = 0x1234U;
    constexpr uint32_t kAlternateProviderToken = 0x4321U;
    constexpr uint32_t kInitialWorkaround = 0x1000U;
    constexpr uint32_t kResetPollBudget = 0x8000U;
    constexpr uint32_t kRevisionShift = 12U;
    constexpr uint32_t kOriginalRevision = 0xffU;
    constexpr uint32_t kWorkaroundEnableBit = 22U;
    constexpr uint32_t kForceWakeRegister = 0x704cU;
    constexpr uint32_t kRtcControlRegister = 0x7000U;
    constexpr uint32_t kRtcResetRegister = 0x7040U;
    constexpr uint32_t kSyncCauseRegister = 0x4028U;
    constexpr uint32_t kResetControlRegister = 0x4000U;
    constexpr uint64_t kResetTimeoutDeadline = 250100U;

    // Preserve distinct original exit codes for each offline scenario.
    enum class Failure : int
    {
        BootstrapRequired = 1,
        BootstrapSucceeded = 2,
        EnsureAwake = 3,
        WarmReset = 4,
        ColdReset = 5,
        EpochRequiresBootstrap = 6,
        Rebootstrap = 7,
        ProviderChanged = 8,
        AccessRevoked = 9,
        ShortDelay = 10,
        ResetTimeout = 11,
        WakeTimeout = 12,
        ClockRollback = 13,
        CoexistenceUnavailable = 14,
        RevocationAfterWrite = 15,
        UnsupportedIdentity = 16,
        BackendAlias = 17,
        IdentityAlias = 18,
        RecoveryAfterAlias = 19,
        InitialOwnerRevoked = 20,
        StaleEpoch = 21,
        ClockRevocation = 22,
        FinalStatusRevocation = 23,
        InitialBootstrap = 24,
        RetireReadiness = 25,
        RejectStaleWarmReset = 26,
        RebootstrapAfterLoss = 27,
        WarmupBeforeClockLoss = 28,
        ClockLossAfterBootstrap = 29,
        CallbackRedirection = 30,
    };

    struct FakeRtcState
    {
            uint64_t time = kInitialMicros;
            uint64_t epoch = 1;
            uint64_t token = kProviderToken;
            uint32_t workaround = kInitialWorkaround;
            uint32_t forceWake = 0;
            uint32_t control = 0;
            uint32_t rtcStatus = kRtcOn;
            bool alive = true;
            bool shortDelay = false;
            bool stuckReset = false;
            bool stuckWake = false;
            bool backwardOnRevision = false;
            bool revokeAfterFirstWrite = false;
            bool revokeOnSecondClock = false;
            bool revokeAfterFinalStatusCheck = false;
            bool finalStatusRead = false;
            unsigned finalStatusOwnerChecks = 0;
            bool sawColdReset = false;
            bool retargetCallbacksOnRevision = false;
            RtcPowerBackend *borrowedCallbacks = nullptr;
            unsigned hijackedWrites = 0;
            unsigned readAttempts = 0;
            unsigned reads = 0;
            unsigned writes = 0;
            unsigned delays = 0;
            unsigned clocks = 0;
    };

    struct FakeRtc : FakeRtcState
    {
            static FakeRtc &get(void *context)
            {
                return *static_cast<FakeRtc *>(context);
            }

            static bool canReset(void *context, uint64_t ownerEpoch)
            {
                auto &self = get(context);
                if (self.revokeAfterFinalStatusCheck && self.finalStatusRead &&
                    ++self.finalStatusOwnerChecks == 2)
                {
                    // The last post-read ownership check can succeed just
                    // before the provider is revoked during publication.
                    self.alive = false;
                    return true;
                }
                return self.alive && self.epoch == ownerEpoch;
            }

            static bool redirectedWrite(void *context, uint32_t /*unused*/,
                                        uint32_t /*unused*/)
            {
                ++get(context).hijackedWrites;
                return false;
            }

            static bool read32(void *context, uint32_t offset, uint32_t *value)
            {
                auto &self = get(context);
                ++self.readAttempts;
                if (!self.alive || (value == nullptr))
                {
                    return false;
                }
                ++self.reads;
                switch (offset)
                {
                    case kRevisionRegister:
                        *value = (static_cast<uint32_t>(kMacFamily)
                                  << kRevisionShift) |
                                 kOriginalRevision;
                        if (self.backwardOnRevision)
                        {
                            --self.time;
                        }
                        if (self.retargetCallbacksOnRevision &&
                            (self.borrowedCallbacks != nullptr))
                        {
                            self.borrowedCallbacks->ownerEpoch = self.epoch + 1;
                            self.borrowedCallbacks->write32 = redirectedWrite;
                        }
                        return true;
                    case kWorkaroundRegister:
                        *value = self.workaround;
                        return true;
                    case kRtcStatusRegister:
                        *value = self.stuckWake ? 1U : self.rtcStatus;
                        // The bootstrap's last WA write precedes the final
                        // RTC_STATUS read, with no more MMIO before success.
                        if (self.revokeAfterFinalStatusCheck &&
                            ((self.workaround & (1U << kWorkaroundEnableBit)) !=
                             0U))
                        {
                            self.finalStatusRead = true;
                        }
                        return true;
                    case kForceWakeRegister: // AR_RTC_FORCE_WAKE
                        *value = self.forceWake;
                        return true;
                    case kRtcControlRegister: // AR_RTC_RC
                        *value = self.stuckReset ? 3U : self.control;
                        return true;
                    case kSyncCauseRegister: // AR_INTR_SYNC_CAUSE
                        *value = 0;
                        return true;
                    default:
                        return false;
                }
            }

            struct WriteRequest
            {
                    uint32_t offset;
                    uint32_t value;
            };

            static bool applyWrite(FakeRtc &self, WriteRequest request)
            {
                if (!self.alive)
                {
                    return false;
                }
                ++self.writes;
                if (self.revokeAfterFirstWrite)
                {
                    self.alive = false; // Provider vanishes mid-operation.
                }
                switch (request.offset)
                {
                    case kWorkaroundRegister:
                        self.workaround = request.value;
                        return true;
                    case kForceWakeRegister:
                        self.forceWake = request.value;
                        return true;
                    case kRtcResetRegister: // AR_RTC_RESET
                        return request.value <= 1;
                    case kRtcControlRegister:
                        self.sawColdReset =
                            self.sawColdReset || request.value == 3U;
                        self.control = request.value;
                        return true;
                    case kResetControlRegister: // AR_RC
                        return request.value == 0;
                    default:
                        return false;
                }
            }

            // The production callback ABI has two adjacent 32-bit words;
            // combine them at the boundary before interpreting either one.
            static bool write32(void *context, uint32_t offset, uint32_t value)
            {
                return applyWrite(get(context), {offset, value});
            }

            static uint64_t nowMicros(void *context)
            {
                auto &self = get(context);
                ++self.clocks;
                if (self.revokeOnSecondClock && self.clocks == 2)
                {
                    self.alive = false;
                }
                return self.time;
            }

            static void delayMicros(void *context, uint32_t micros)
            {
                auto &self = get(context);
                ++self.delays;
                self.time += self.shortDelay ? micros - 1U : micros;
            }

            RtcPowerBackend backend()
            {
                return {
                    this,    token,     epoch,       canReset,         read32,
                    write32, nowMicros, delayMicros, kResetPollBudget, false,
                    nullptr, nullptr,
                };
            }
    };

    constexpr Identity kPhysical {kPciVendor, kPciDevice, 0, 0, false};

    int runBootstrapLifecycle()
    {
        {
            FakeRtc fake {};
            RtcPowerContext context {};
            RtcPowerStatus status {};
            auto backend = fake.backend();
            if (transitionAr9565Rtc(backend, kPhysical,
                                    RtcOperation::EnsureAwake, context,
                                    status) != RtcResult::BootstrapRequired ||
                (fake.reads != 0U) || (fake.writes != 0U) ||
                context.bootstrapCompleted)
            {
                return static_cast<int>(Failure::BootstrapRequired);
            }
            if (transitionAr9565Rtc(backend, kPhysical,
                                    RtcOperation::BootstrapPowerOn, context,
                                    status) != RtcResult::Ok ||
                !status.rtcAwake || !status.resetCompleted ||
                !status.boardStateInvalidated || !context.bootstrapCompleted ||
                context.bootstrapEpoch != 1 ||
                context.providerToken != fake.token ||
                context.workaroundValue != fake.workaround ||
                (fake.workaround & (1U << kWorkaroundEnableBit)) == 0 ||
                (fake.writes == 0U) || (fake.delays == 0U))
            {
                return static_cast<int>(Failure::BootstrapSucceeded);
            }
            if (transitionAr9565Rtc(backend, kPhysical,
                                    RtcOperation::EnsureAwake, context,
                                    status) != RtcResult::Ok ||
                !status.rtcAwake || !context.bootstrapCompleted)
            {
                return static_cast<int>(Failure::EnsureAwake);
            }
            if (transitionAr9565Rtc(backend, kPhysical, RtcOperation::WarmReset,
                                    context, status) != RtcResult::Ok ||
                !status.resetCompleted || fake.sawColdReset)
            {
                return static_cast<int>(Failure::WarmReset);
            }
            if (transitionAr9565Rtc(backend, kPhysical, RtcOperation::ColdReset,
                                    context, status) != RtcResult::Ok ||
                !status.resetCompleted || !fake.sawColdReset)
            {
                return static_cast<int>(Failure::ColdReset);
            }
            fake.epoch = 2;
            backend.ownerEpoch = 2;
            const unsigned oldWrites = fake.writes;
            if (transitionAr9565Rtc(backend, kPhysical, RtcOperation::WarmReset,
                                    context,
                                    status) != RtcResult::BootstrapRequired ||
                context.bootstrapCompleted || (context.bootstrapEpoch != 0U) ||
                fake.writes != oldWrites)
            {
                return static_cast<int>(Failure::EpochRequiresBootstrap);
            }
            if (transitionAr9565Rtc(backend, kPhysical,
                                    RtcOperation::BootstrapPowerOn, context,
                                    status) != RtcResult::Ok ||
                !context.bootstrapCompleted || context.bootstrapEpoch != 2)
            {
                return static_cast<int>(Failure::Rebootstrap);
            }
            const unsigned beforeProviderWrites = fake.writes;
            const unsigned beforeProviderReads = fake.reads;
            backend.providerToken = kAlternateProviderToken;
            if (transitionAr9565Rtc(backend, kPhysical, RtcOperation::WarmReset,
                                    context,
                                    status) != RtcResult::ProviderChanged ||
                fake.writes != beforeProviderWrites ||
                fake.reads != beforeProviderReads)
            {
                return static_cast<int>(Failure::ProviderChanged);
            }
            backend.providerToken = fake.token;
            fake.alive = false;
            if (transitionAr9565Rtc(backend, kPhysical, RtcOperation::WarmReset,
                                    context,
                                    status) != RtcResult::AccessRevoked ||
                (status.writes != 0U) || status.boardStateInvalidated)
            {
                return static_cast<int>(Failure::AccessRevoked);
            }
        }
        return 0;
    }

    int runResetRejections()
    {
        {
            FakeRtc fake {};
            fake.shortDelay = true;
            RtcPowerContext context {};
            RtcPowerStatus status {};
            const auto backend = fake.backend();
            if (transitionAr9565Rtc(backend, kPhysical,
                                    RtcOperation::BootstrapPowerOn, context,
                                    status) != RtcResult::DelayTooShort ||
                !status.boardStateInvalidated || context.bootstrapCompleted ||
                (fake.writes == 0U) || (fake.delays == 0U))
            {
                return static_cast<int>(Failure::ShortDelay);
            }
        }
        {
            FakeRtc fake {};
            fake.stuckReset = true;
            RtcPowerContext context {};
            RtcPowerStatus status {};
            const auto backend = fake.backend();
            if (transitionAr9565Rtc(backend, kPhysical,
                                    RtcOperation::BootstrapPowerOn, context,
                                    status) != RtcResult::ResetTimeout ||
                status.resetCompleted || !status.boardStateInvalidated ||
                context.bootstrapCompleted || fake.time > kResetTimeoutDeadline)
            {
                return static_cast<int>(Failure::ResetTimeout);
            }
        }
        {
            FakeRtc fake {};
            fake.stuckWake = true;
            RtcPowerContext context {};
            RtcPowerStatus status {};
            const auto backend = fake.backend();
            if (transitionAr9565Rtc(backend, kPhysical,
                                    RtcOperation::BootstrapPowerOn, context,
                                    status) != RtcResult::WakeTimeout ||
                status.resetCompleted || !status.boardStateInvalidated ||
                context.bootstrapCompleted || fake.time > kResetTimeoutDeadline)
            {
                return static_cast<int>(Failure::WakeTimeout);
            }
        }
        {
            FakeRtc fake {};
            fake.backwardOnRevision = true;
            RtcPowerContext context {};
            RtcPowerStatus status {};
            const auto backend = fake.backend();
            if (transitionAr9565Rtc(backend, kPhysical,
                                    RtcOperation::BootstrapPowerOn, context,
                                    status) != RtcResult::InvalidClock ||
                (status.writes != 0U) || status.boardStateInvalidated)
            {
                return static_cast<int>(Failure::ClockRollback);
            }
        }
        {
            FakeRtc fake {};
            RtcPowerContext context {};
            RtcPowerStatus status {};
            auto backend = fake.backend();
            backend.mciEnabled = true;
            if (transitionAr9565Rtc(
                    backend, kPhysical, RtcOperation::BootstrapPowerOn, context,
                    status) != RtcResult::CoexistenceUnavailable ||
                (fake.reads != 0U) || (fake.writes != 0U))
            {
                return static_cast<int>(Failure::CoexistenceUnavailable);
            }
        }
        return 0;
    }

    int runOwnerAliasRejections()
    {
        {
            FakeRtc fake {};
            fake.revokeAfterFirstWrite = true;
            RtcPowerContext context {};
            RtcPowerStatus status {};
            const auto backend = fake.backend();
            if (transitionAr9565Rtc(backend, kPhysical,
                                    RtcOperation::BootstrapPowerOn, context,
                                    status) != RtcResult::AccessRevoked ||
                fake.writes != 1 || !status.boardStateInvalidated ||
                context.bootstrapCompleted || status.rtcAwake)
            {
                return static_cast<int>(Failure::RevocationAfterWrite);
            }
        }
        {
            FakeRtc fake {};
            RtcPowerContext context {};
            RtcPowerStatus status {};
            const auto backend = fake.backend();
            const Identity spoofed {kPciVendor, kPciDevice, 0, 0, true};
            if (transitionAr9565Rtc(backend, spoofed,
                                    RtcOperation::BootstrapPowerOn, context,
                                    status) != RtcResult::UnsupportedIdentity ||
                (fake.reads != 0U) || (fake.writes != 0U))
            {
                return static_cast<int>(Failure::UnsupportedIdentity);
            }
        }
        {
            // An opaque callback may not reinterpret the retained callback
            // table or physical PCI identity as FakeRtc and subsequently change
            // them. Reject before clearing status or touching MMIO/time
            // callbacks.
            FakeRtc fake {};
            RtcPowerContext context {};
            RtcPowerStatus status {};
            status.lastRegister = kProviderToken;
            auto backend = fake.backend();
            backend.context = &backend;
            if (transitionAr9565Rtc(backend, kPhysical,
                                    RtcOperation::BootstrapPowerOn, context,
                                    status) != RtcResult::InvalidArgument ||
                status.lastRegister != kProviderToken || (fake.writes != 0U) ||
                (fake.reads != 0U) || context.workaroundCaptured)
            {
                return static_cast<int>(Failure::BackendAlias);
            }
            Identity physical = kPhysical;
            backend.context = &physical;
            if (transitionAr9565Rtc(backend, physical,
                                    RtcOperation::BootstrapPowerOn, context,
                                    status) != RtcResult::InvalidArgument ||
                status.lastRegister != kProviderToken || (fake.writes != 0U) ||
                (fake.reads != 0U) || physical.vendorId != kPciVendor ||
                physical.deviceId != kPciDevice)
            {
                return static_cast<int>(Failure::IdentityAlias);
            }
            // Rejection does not poison a legitimate callback on the same
            // object.
            backend.context = &fake;
            if (transitionAr9565Rtc(backend, physical,
                                    RtcOperation::BootstrapPowerOn, context,
                                    status) != RtcResult::Ok ||
                !context.bootstrapCompleted || !status.resetCompleted)
            {
                return static_cast<int>(Failure::RecoveryAfterAlias);
            }
        }
        return 0;
    }

    int runOwnershipRevocations()
    {
        {
            // The reset capability can be revoked before bootstrap begins. Its
            // first clock sample may rely on the same live provider allocation;
            // reject before reading that sample or touching BAR callbacks.
            FakeRtc fake {};
            fake.alive = false;
            RtcPowerContext context {};
            RtcPowerStatus status {};
            const auto backend = fake.backend();
            if (transitionAr9565Rtc(backend, kPhysical,
                                    RtcOperation::BootstrapPowerOn, context,
                                    status) != RtcResult::AccessRevoked ||
                (fake.clocks != 0U) || (fake.reads != 0U) ||
                (fake.writes != 0U) || status.boardStateInvalidated ||
                context.workaroundCaptured)
            {
                return static_cast<int>(Failure::InitialOwnerRevoked);
            }

            // A stale/reset epoch is also not authorization to consult the
            // clock.
            fake.alive = true;
            fake.epoch = 2;
            if (transitionAr9565Rtc(backend, kPhysical,
                                    RtcOperation::BootstrapPowerOn, context,
                                    status) != RtcResult::AccessRevoked ||
                (fake.clocks != 0U) || (fake.reads != 0U) ||
                (fake.writes != 0U) || status.boardStateInvalidated ||
                context.workaroundCaptured)
            {
                return static_cast<int>(Failure::StaleEpoch);
            }
        }
        {
            // The clock callback can itself revoke the underlying PCI owner.
            // Checking canReset before that callback is insufficient: no stale
            // MMIO read may be attempted after the revocation.
            FakeRtc fake {};
            fake.revokeOnSecondClock = true;
            RtcPowerContext context {};
            RtcPowerStatus status {};
            const auto backend = fake.backend();
            if (transitionAr9565Rtc(backend, kPhysical,
                                    RtcOperation::BootstrapPowerOn, context,
                                    status) != RtcResult::AccessRevoked ||
                fake.clocks != 2 || fake.readAttempts != 0 ||
                (fake.reads != 0U) || (fake.writes != 0U) ||
                status.boardStateInvalidated || context.workaroundCaptured)
            {
                return static_cast<int>(Failure::ClockRevocation);
            }
        }
        {
            // Ownership may disappear immediately after the last successful
            // post-read gate but before readiness is written into the context.
            // The public API must not publish a valid bootstrap in that window.
            FakeRtc fake {};
            fake.revokeAfterFinalStatusCheck = true;
            RtcPowerContext context {};
            RtcPowerStatus status {};
            const auto backend = fake.backend();
            if (transitionAr9565Rtc(backend, kPhysical,
                                    RtcOperation::BootstrapPowerOn, context,
                                    status) != RtcResult::AccessRevoked ||
                fake.alive || fake.finalStatusOwnerChecks != 3 ||
                !status.boardStateInvalidated || status.rtcAwake ||
                context.bootstrapCompleted || (context.bootstrapEpoch != 0U) ||
                !status.resetCompleted)
            {
                return static_cast<int>(Failure::FinalStatusRevocation);
            }
        }
        return 0;
    }

    int runRecoveryAndCallbacks()
    {
        {
            // After a successful bootstrap, a pre-MMIO loss of the reset owner
            // must retire readiness. Even if a faulty provider returns to the
            // same token/epoch, a stale WarmReset cannot skip rebootstrap.
            FakeRtc fake {};
            RtcPowerContext context {};
            RtcPowerStatus status {};
            const auto backend = fake.backend();
            if (transitionAr9565Rtc(backend, kPhysical,
                                    RtcOperation::BootstrapPowerOn, context,
                                    status) != RtcResult::Ok ||
                !context.bootstrapCompleted)
            {
                return static_cast<int>(Failure::InitialBootstrap);
            }
            const unsigned priorWrites = fake.writes;
            fake.alive = false;
            if (transitionAr9565Rtc(backend, kPhysical,
                                    RtcOperation::EnsureAwake, context,
                                    status) != RtcResult::AccessRevoked ||
                status.boardStateInvalidated || fake.writes != priorWrites ||
                context.bootstrapCompleted || (context.bootstrapEpoch != 0U))
            {
                return static_cast<int>(Failure::RetireReadiness);
            }
            fake.alive = true;
            if (transitionAr9565Rtc(backend, kPhysical, RtcOperation::WarmReset,
                                    context,
                                    status) != RtcResult::BootstrapRequired ||
                fake.writes != priorWrites)
            {
                return static_cast<int>(Failure::RejectStaleWarmReset);
            }
            if (transitionAr9565Rtc(backend, kPhysical,
                                    RtcOperation::BootstrapPowerOn, context,
                                    status) != RtcResult::Ok ||
                !context.bootstrapCompleted)
            {
                return static_cast<int>(Failure::RebootstrapAfterLoss);
            }
        }
        {
            // Revocation during the clock callback, before the first MMIO read,
            // is equally disqualifying even though no register was written.
            FakeRtc fake {};
            RtcPowerContext context {};
            RtcPowerStatus status {};
            const auto backend = fake.backend();
            if (transitionAr9565Rtc(backend, kPhysical,
                                    RtcOperation::BootstrapPowerOn, context,
                                    status) != RtcResult::Ok)
            {
                return static_cast<int>(Failure::WarmupBeforeClockLoss);
            }
            const unsigned beforeReads = fake.reads;
            const unsigned beforeWrites = fake.writes;
            fake.clocks = 0;
            fake.revokeOnSecondClock = true;
            if (transitionAr9565Rtc(backend, kPhysical,
                                    RtcOperation::EnsureAwake, context,
                                    status) != RtcResult::AccessRevoked ||
                fake.reads != beforeReads || fake.writes != beforeWrites ||
                status.boardStateInvalidated || context.bootstrapCompleted ||
                (context.bootstrapEpoch != 0U))
            {
                return static_cast<int>(Failure::ClockLossAfterBootstrap);
            }
        }
        {
            // A callback retaining the caller's table cannot redirect the
            // in-flight epoch or MMIO writer after the first revision read.
            FakeRtc fake {};
            RtcPowerContext context {};
            RtcPowerStatus status {};
            auto backend = fake.backend();
            fake.borrowedCallbacks = &backend;
            fake.retargetCallbacksOnRevision = true;
            if (transitionAr9565Rtc(backend, kPhysical,
                                    RtcOperation::BootstrapPowerOn, context,
                                    status) != RtcResult::Ok ||
                !context.bootstrapCompleted || !status.resetCompleted ||
                fake.hijackedWrites != 0 || fake.writes == 0 ||
                backend.ownerEpoch != fake.epoch + 1 ||
                backend.write32 != FakeRtc::redirectedWrite)
            {
                return static_cast<int>(Failure::CallbackRedirection);
            }
        }
        return 0;
    }

} // namespace

int main()
{
    const int runBootstrapLifecycleResult = runBootstrapLifecycle();
    if (runBootstrapLifecycleResult != 0)
    {
        return runBootstrapLifecycleResult;
    }
    const int runResetRejectionsResult = runResetRejections();
    if (runResetRejectionsResult != 0)
    {
        return runResetRejectionsResult;
    }
    const int runOwnerAliasRejectionsResult = runOwnerAliasRejections();
    if (runOwnerAliasRejectionsResult != 0)
    {
        return runOwnerAliasRejectionsResult;
    }
    const int runOwnershipRevocationsResult = runOwnershipRevocations();
    if (runOwnershipRevocationsResult != 0)
    {
        return runOwnershipRevocationsResult;
    }
    const int runRecoveryAndCallbacksResult = runRecoveryAndCallbacks();
    if (runRecoveryAndCallbacksResult != 0)
    {
        return runRecoveryAndCallbacksResult;
    }
    return 0;
}
