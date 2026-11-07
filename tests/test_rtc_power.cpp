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
            bool sawColdReset = false;
            unsigned reads = 0;
            unsigned writes = 0;
            unsigned delays = 0;

            static FakeRtc &get(void *context)
            {
                return *static_cast<FakeRtc *>(context);
            }

            static bool canReset(void *context, uint64_t ownerEpoch)
            {
                auto &self = get(context);
                return self.alive && self.epoch == ownerEpoch;
            }

            static bool read32(void *context, uint32_t offset, uint32_t *value)
            {
                auto &self = get(context);
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
                        return true;
                    case kWorkaroundRegister:
                        *value = self.workaround;
                        return true;
                    case kRtcStatusRegister:
                        *value = self.stuckWake ? 1u : self.rtcStatus;
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
                return get(context).time;
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
    return 0;
}
