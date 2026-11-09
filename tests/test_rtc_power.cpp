// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Alberto Villa Osorno.
// Synthetic RTC owner/clock/MMIO callbacks only; never touches hardware.
#include "hardware/Ar9565RtcPower.hpp"

using namespace simpleath;

namespace
{
    struct FakeRtc
    {
            uint64_t time = 100;
            uint64_t epoch = 1;
            uint64_t token = 0x1234u;
            uint32_t workaround = 0x1000u;
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

            static bool redirectedWrite(void *context, uint32_t, uint32_t)
            {
                ++get(context).hijackedWrites;
                return false;
            }

            static bool read32(void *context, uint32_t offset, uint32_t *value)
            {
                auto &self = get(context);
                ++self.readAttempts;
                if (!self.alive || !value)
                    return false;
                ++self.reads;
                switch (offset)
                {
                    case kRevisionRegister:
                        *value =
                            (static_cast<uint32_t>(kMacFamily) << 12u) | 0xffu;
                        if (self.backwardOnRevision)
                            --self.time;
                        if (self.retargetCallbacksOnRevision &&
                            self.borrowedCallbacks)
                        {
                            self.borrowedCallbacks->ownerEpoch = self.epoch + 1;
                            self.borrowedCallbacks->write32 = redirectedWrite;
                        }
                        return true;
                    case kWorkaroundRegister:
                        *value = self.workaround;
                        return true;
                    case kRtcStatusRegister:
                        *value = self.stuckWake ? 1u : self.rtcStatus;
                        // The bootstrap's last WA write precedes the final
                        // RTC_STATUS read, with no more MMIO before success.
                        if (self.revokeAfterFinalStatusCheck &&
                            (self.workaround & (1u << 22u)))
                            self.finalStatusRead = true;
                        return true;
                    case 0x704c: // AR_RTC_FORCE_WAKE
                        *value = self.forceWake;
                        return true;
                    case 0x7000: // AR_RTC_RC
                        *value = self.stuckReset ? 3u : self.control;
                        return true;
                    case 0x4028: // AR_INTR_SYNC_CAUSE
                        *value = 0;
                        return true;
                    default:
                        return false;
                }
            }

            static bool write32(void *context, uint32_t offset, uint32_t value)
            {
                auto &self = get(context);
                if (!self.alive)
                    return false;
                ++self.writes;
                if (self.revokeAfterFirstWrite)
                    self.alive = false; // Provider vanishes mid-operation.
                switch (offset)
                {
                    case kWorkaroundRegister:
                        self.workaround = value;
                        return true;
                    case 0x704c:
                        self.forceWake = value;
                        return true;
                    case 0x7040: // AR_RTC_RESET
                        return value <= 1;
                    case 0x7000:
                        self.sawColdReset = self.sawColdReset || value == 3u;
                        self.control = value;
                        return true;
                    case 0x4000: // AR_RC
                        return value == 0;
                    default:
                        return false;
                }
            }

            static uint64_t nowMicros(void *context)
            {
                auto &self = get(context);
                ++self.clocks;
                if (self.revokeOnSecondClock && self.clocks == 2)
                    self.alive = false;
                return self.time;
            }

            static void delayMicros(void *context, uint32_t micros)
            {
                auto &self = get(context);
                ++self.delays;
                self.time += self.shortDelay ? micros - 1u : micros;
            }

            RtcPowerBackend backend()
            {
                return {this,    token,   epoch,     canReset,
                        read32,  write32, nowMicros, delayMicros,
                        0x8000u, false,   nullptr,   nullptr};
            }
    };

    constexpr Identity kPhysical {kPciVendor, kPciDevice, 0, 0, false};
} // namespace

int main()
{
    {
        FakeRtc fake {};
        RtcPowerContext context {};
        RtcPowerStatus status {};
        auto backend = fake.backend();
        if (transitionAr9565Rtc(backend, kPhysical, RtcOperation::EnsureAwake,
                                context,
                                status) != RtcResult::BootstrapRequired ||
            fake.reads || fake.writes || context.bootstrapCompleted)
            return 1;
        if (transitionAr9565Rtc(backend, kPhysical,
                                RtcOperation::BootstrapPowerOn, context,
                                status) != RtcResult::Ok ||
            !status.rtcAwake || !status.resetCompleted ||
            !status.boardStateInvalidated || !context.bootstrapCompleted ||
            context.bootstrapEpoch != 1 ||
            context.providerToken != fake.token ||
            context.workaroundValue != fake.workaround ||
            (fake.workaround & (1u << 22u)) == 0 || !fake.writes ||
            !fake.delays)
            return 2;
        if (transitionAr9565Rtc(backend, kPhysical, RtcOperation::EnsureAwake,
                                context, status) != RtcResult::Ok ||
            !status.rtcAwake || !context.bootstrapCompleted)
            return 3;
        if (transitionAr9565Rtc(backend, kPhysical, RtcOperation::WarmReset,
                                context, status) != RtcResult::Ok ||
            !status.resetCompleted || fake.sawColdReset)
            return 4;
        if (transitionAr9565Rtc(backend, kPhysical, RtcOperation::ColdReset,
                                context, status) != RtcResult::Ok ||
            !status.resetCompleted || !fake.sawColdReset)
            return 5;
        fake.epoch = 2;
        backend.ownerEpoch = 2;
        const unsigned oldWrites = fake.writes;
        if (transitionAr9565Rtc(backend, kPhysical, RtcOperation::WarmReset,
                                context,
                                status) != RtcResult::BootstrapRequired ||
            context.bootstrapCompleted || context.bootstrapEpoch ||
            fake.writes != oldWrites)
            return 6;
        if (transitionAr9565Rtc(backend, kPhysical,
                                RtcOperation::BootstrapPowerOn, context,
                                status) != RtcResult::Ok ||
            !context.bootstrapCompleted || context.bootstrapEpoch != 2)
            return 7;
        const unsigned beforeProviderWrites = fake.writes;
        const unsigned beforeProviderReads = fake.reads;
        backend.providerToken = 0x4321;
        if (transitionAr9565Rtc(backend, kPhysical, RtcOperation::WarmReset,
                                context,
                                status) != RtcResult::ProviderChanged ||
            fake.writes != beforeProviderWrites ||
            fake.reads != beforeProviderReads)
            return 8;
        backend.providerToken = fake.token;
        fake.alive = false;
        if (transitionAr9565Rtc(backend, kPhysical, RtcOperation::WarmReset,
                                context, status) != RtcResult::AccessRevoked ||
            status.writes || status.boardStateInvalidated)
            return 9;
    }
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
            !fake.writes || !fake.delays)
            return 10;
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
            context.bootstrapCompleted || fake.time > 250100)
            return 11;
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
            context.bootstrapCompleted || fake.time > 250100)
            return 12;
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
            status.writes || status.boardStateInvalidated)
            return 13;
    }
    {
        FakeRtc fake {};
        RtcPowerContext context {};
        RtcPowerStatus status {};
        auto backend = fake.backend();
        backend.mciEnabled = true;
        if (transitionAr9565Rtc(backend, kPhysical,
                                RtcOperation::BootstrapPowerOn, context,
                                status) != RtcResult::CoexistenceUnavailable ||
            fake.reads || fake.writes)
            return 14;
    }
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
            return 15;
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
            fake.reads || fake.writes)
            return 16;
    }
    {
        // An opaque callback may not reinterpret the retained callback table
        // or physical PCI identity as FakeRtc and subsequently change them.
        // Reject before clearing status or touching MMIO/time callbacks.
        FakeRtc fake {};
        RtcPowerContext context {};
        RtcPowerStatus status {};
        status.lastRegister = 0x1234;
        auto backend = fake.backend();
        backend.context = &backend;
        if (transitionAr9565Rtc(backend, kPhysical,
                                RtcOperation::BootstrapPowerOn, context,
                                status) != RtcResult::InvalidArgument ||
            status.lastRegister != 0x1234 || fake.writes || fake.reads ||
            context.workaroundCaptured)
            return 17;
        Identity physical = kPhysical;
        backend.context = &physical;
        if (transitionAr9565Rtc(backend, physical,
                                RtcOperation::BootstrapPowerOn, context,
                                status) != RtcResult::InvalidArgument ||
            status.lastRegister != 0x1234 || fake.writes || fake.reads ||
            physical.vendorId != kPciVendor || physical.deviceId != kPciDevice)
            return 18;
        // Rejection does not poison a legitimate callback on the same object.
        backend.context = &fake;
        if (transitionAr9565Rtc(backend, physical,
                                RtcOperation::BootstrapPowerOn, context,
                                status) != RtcResult::Ok ||
            !context.bootstrapCompleted || !status.resetCompleted)
            return 19;
    }
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
            fake.clocks || fake.reads || fake.writes ||
            status.boardStateInvalidated || context.workaroundCaptured)
            return 20;

        // A stale/reset epoch is also not authorization to consult the clock.
        fake.alive = true;
        fake.epoch = 2;
        if (transitionAr9565Rtc(backend, kPhysical,
                                RtcOperation::BootstrapPowerOn, context,
                                status) != RtcResult::AccessRevoked ||
            fake.clocks || fake.reads || fake.writes ||
            status.boardStateInvalidated || context.workaroundCaptured)
            return 21;
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
            fake.clocks != 2 || fake.readAttempts != 0 || fake.reads ||
            fake.writes || status.boardStateInvalidated ||
            context.workaroundCaptured)
            return 22;
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
            context.bootstrapCompleted || context.bootstrapEpoch ||
            !status.resetCompleted)
            return 23;
    }
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
            return 24;
        const unsigned priorWrites = fake.writes;
        fake.alive = false;
        if (transitionAr9565Rtc(backend, kPhysical, RtcOperation::EnsureAwake,
                                context, status) != RtcResult::AccessRevoked ||
            status.boardStateInvalidated || fake.writes != priorWrites ||
            context.bootstrapCompleted || context.bootstrapEpoch)
            return 25;
        fake.alive = true;
        if (transitionAr9565Rtc(backend, kPhysical, RtcOperation::WarmReset,
                                context,
                                status) != RtcResult::BootstrapRequired ||
            fake.writes != priorWrites)
            return 26;
        if (transitionAr9565Rtc(backend, kPhysical,
                                RtcOperation::BootstrapPowerOn, context,
                                status) != RtcResult::Ok ||
            !context.bootstrapCompleted)
            return 27;
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
            return 28;
        const unsigned beforeReads = fake.reads;
        const unsigned beforeWrites = fake.writes;
        fake.clocks = 0;
        fake.revokeOnSecondClock = true;
        if (transitionAr9565Rtc(backend, kPhysical, RtcOperation::EnsureAwake,
                                context, status) != RtcResult::AccessRevoked ||
            fake.reads != beforeReads || fake.writes != beforeWrites ||
            status.boardStateInvalidated || context.bootstrapCompleted ||
            context.bootstrapEpoch)
            return 29;
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
            return 30;
    }
    return 0;
}
