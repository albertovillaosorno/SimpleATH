// SPDX-License-Identifier: AGPL-3.0-only
/*
 * Copyright (c) 2008-2011 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
// Pinned Linux references (protocol/constants only; no Linux objects linked):
// hw.c:  8d06b4a22733dedd2d2a46247128f254b9345efae659de14189a8c2c0fd4731f
// hw.h:  95498a7e664cf66e99edcdfa9225a147ec4bb77b0458bfb726b5b0c26c1ebe85
// reg.h: 629a6df177d63b2a99202ab97a3641c488b5f1ac738f6f15612c7b4ebacebade
#include "Ar9565RtcPower.hpp"

namespace simpleath
{
    namespace
    {
        constexpr uint32_t kHostReset = 0x4000, kHostInterface = 0x100;
        constexpr uint32_t kSyncCause = 0x4028, kSyncEnable = 0x402c,
                           kSyncTimeouts = 0x3000;
        constexpr uint32_t kRtcControl = 0x7000, kRtcReset = 0x7040,
                           kForceWake = 0x704c;
        constexpr uint32_t kWorkaroundWake = (1U << 14) | (1U << 17);
        constexpr uint32_t kAr9565Workaround = 1U << 22;
        constexpr uint64_t kOperationMicros = 250000;

        // Reject overlapping caller-owned objects before clearing status.
        // Difference-based arithmetic avoids overflow at address-space limits.
        bool overlaps(const void *a, size_t aBytes, const void *b,
                      size_t bBytes)
        {
            const auto first = reinterpret_cast<uintptr_t>(a);
            const auto second = reinterpret_cast<uintptr_t>(b);
            return first <= second ? second - first < aBytes
                                   : first - second < bBytes;
        }

        class RtcRun final
        {
            public:
                RtcRun(const RtcPowerBackend &backend, RtcPowerContext &context,
                       RtcPowerStatus &status)
                    : b_(backend), c_(context), s_(status),
                      started_(backend.nowMicros(backend.context)),
                      previous_(started_)
                {
                }

                RtcResult check()
                {
                    if (!b_.canReset(b_.context, b_.ownerEpoch))
                    {
                        return RtcResult::AccessRevoked;
                    }
                    const uint64_t now = b_.nowMicros(b_.context);
                    // The clock provider may itself revoke the PCI mapping.
                    // Do not grant an MMIO read/write from the pre-clock
                    // ownership check alone.
                    if (!b_.canReset(b_.context, b_.ownerEpoch))
                    {
                        return RtcResult::AccessRevoked;
                    }
                    if (now < previous_)
                    {
                        return RtcResult::InvalidClock;
                    }
                    previous_ = now;
                    return now - started_ >= kOperationMicros
                               ? RtcResult::OperationTimeout
                               : RtcResult::Ok;
                }

                RtcResult read(uint32_t reg, uint32_t &value)
                {
                    RtcResult result = check();
                    if (result != RtcResult::Ok)
                    {
                        return result;
                    }
                    if (!inBar(reg) ||
                        (reg != kRevisionRegister &&
                         reg != kWorkaroundRegister &&
                         reg != kRtcStatusRegister && reg != kForceWake &&
                         reg != kRtcControl && reg != kSyncCause))
                    {
                        return RtcResult::InvalidRegister;
                    }
                    ++s_.reads;
                    s_.lastRegister = reg;
                    s_.lastValue = 0;
                    if (!b_.read32(b_.context, reg, &value) ||
                        value == 0xffffffffU)
                    {
                        return RtcResult::ReadFailed;
                    }
                    s_.lastValue = value;
                    return check();
                }

                RtcResult write(uint32_t reg, uint32_t value)
                {
                    RtcResult result = check();
                    if (result != RtcResult::Ok)
                    {
                        return result;
                    }
                    if (!inBar(reg) ||
                        (reg != kWorkaroundRegister && reg != kForceWake &&
                         reg != kRtcReset && reg != kRtcControl &&
                         reg != kSyncEnable && reg != kHostReset))
                    {
                        return RtcResult::InvalidRegister;
                    }
                    s_.boardStateInvalidated = true;
                    s_.lastRegister = reg;
                    s_.lastValue = value;
                    ++s_.writes;
                    if (!b_.write32(b_.context, reg, value))
                    {
                        return RtcResult::WriteFailed;
                    }
                    return check();
                }

                RtcResult delay(uint32_t micros)
                {
                    RtcResult result = check();
                    if (result != RtcResult::Ok)
                    {
                        return result;
                    }
                    const uint64_t before = previous_;
                    b_.delayMicros(b_.context, micros);
                    result = check();
                    if (result != RtcResult::Ok)
                    {
                        return result;
                    }
                    // A monotonic clock alone does not prove the reset pulse
                    // was held long enough. The callback must not return early.
                    return previous_ - before >= micros
                               ? RtcResult::Ok
                               : RtcResult::DelayTooShort;
                }

                RtcResult workaround()
                {
                    RtcResult result =
                        write(kWorkaroundRegister, c_.workaroundValue);
                    return result == RtcResult::Ok ? delay(10) : result;
                }

                RtcResult wait(uint32_t reg, uint32_t mask, uint32_t expected,
                               uint32_t budget, uint32_t interval,
                               RtcResult timeout)
                {
                    const RtcResult checked = check();
                    if (checked != RtcResult::Ok)
                    {
                        return checked;
                    }
                    const uint64_t start = previous_;
                    for (uint32_t attempt = 0; attempt <= budget / interval;
                         ++attempt)
                    {
                        if (++s_.polls > 21000)
                        {
                            return RtcResult::OperationTimeout;
                        }
                        uint32_t value = 0;
                        RtcResult result = read(reg, value);
                        if (result != RtcResult::Ok)
                        {
                            return result;
                        }
                        if (previous_ - start >= budget)
                        {
                            return timeout;
                        }
                        if ((value & mask) == expected)
                        {
                            return RtcResult::Ok;
                        }
                        if (attempt == budget / interval)
                        {
                            break;
                        }
                        result = delay(interval);
                        if (result != RtcResult::Ok)
                        {
                            return result;
                        }
                    }
                    return timeout;
                }

                RtcResult macReset(bool cold)
                {
                    RtcResult result = workaround();
                    if (result != RtcResult::Ok)
                    {
                        return result;
                    }
                    result = write(kForceWake, 3);
                    if (result != RtcResult::Ok)
                    {
                        return result;
                    }
                    uint32_t cause = 0;
                    result = read(kSyncCause, cause);
                    if (result != RtcResult::Ok)
                    {
                        return result;
                    }
                    if ((cause & kSyncTimeouts) != 0U)
                    {
                        result = write(kSyncEnable, 0);
                        if (result != RtcResult::Ok)
                        {
                            return result;
                        }
                        result = write(kHostReset, kHostInterface);
                        if (result != RtcResult::Ok)
                        {
                            return result;
                        }
                    }
                    if (b_.mciEnabled)
                    {
                        if (!b_.beforeMacReset(b_.context))
                        {
                            return RtcResult::CoexistenceUnavailable;
                        }
                        result = check();
                        if (result != RtcResult::Ok)
                        {
                            return result;
                        }
                    }
                    result = write(kRtcControl, cold ? 3 : 1);
                    if (result != RtcResult::Ok)
                    {
                        return result;
                    }
                    result = delay(50); // AR9565 is AR9003; exclude unrelated
                                        // SoC/DMA-halt recipes.
                    if (result != RtcResult::Ok)
                    {
                        return result;
                    }
                    result = write(kRtcControl, 0);
                    if (result != RtcResult::Ok)
                    {
                        return result;
                    }
                    result = wait(kRtcControl, 3, 0, 100000, 10,
                                  RtcResult::ResetTimeout);
                    if (result != RtcResult::Ok)
                    {
                        return result;
                    }
                    result = write(kHostReset, 0);
                    if (result == RtcResult::Ok)
                    {
                        s_.resetCompleted = true;
                    }
                    return result;
                }

                RtcResult powerOn()
                {
                    c_.bootstrapCompleted = false;
                    c_.bootstrapEpoch = 0;
                    RtcResult result = workaround();
                    if (result != RtcResult::Ok)
                    {
                        return result;
                    }
                    result = write(kForceWake, 3);
                    if (result != RtcResult::Ok)
                    {
                        return result;
                    }
                    result = write(kRtcReset, 0);
                    if (result != RtcResult::Ok)
                    {
                        return result;
                    }
                    result = delay(2);
                    if (result != RtcResult::Ok)
                    {
                        return result;
                    }
                    result = write(kRtcReset, 1);
                    if (result != RtcResult::Ok)
                    {
                        return result;
                    }
                    result = wait(kRtcStatusRegister, kRtcStatusMask, kRtcOn,
                                  100000, 10, RtcResult::WakeTimeout);
                    if (result != RtcResult::Ok)
                    {
                        return result;
                    }
                    result = macReset(false);
                    if (result != RtcResult::Ok)
                    {
                        return result;
                    }
                    c_.workaroundValue |= kAr9565Workaround;
                    return write(kWorkaroundRegister, c_.workaroundValue);
                }

                RtcResult awake()
                {
                    RtcResult result = workaround();
                    if (result != RtcResult::Ok)
                    {
                        return result;
                    }
                    uint32_t rtc = 0;
                    result = read(kRtcStatusRegister, rtc);
                    if (result != RtcResult::Ok)
                    {
                        return result;
                    }
                    if ((rtc & kRtcStatusMask) == 1)
                    {
                        result = powerOn();
                        if (result != RtcResult::Ok)
                        {
                            return result;
                        }
                    }
                    // Reassert force wake every 50 us, as ath9k does, at most
                    // 200 times.
                    for (uint32_t attempt = 0; attempt < 200; ++attempt)
                    {
                        uint32_t force = 0;
                        result = read(kForceWake, force);
                        if (result != RtcResult::Ok)
                        {
                            return result;
                        }
                        result = write(kForceWake, force | 1U);
                        if (result != RtcResult::Ok)
                        {
                            return result;
                        }
                        result = delay(50);
                        if (result != RtcResult::Ok)
                        {
                            return result;
                        }
                        ++s_.polls;
                        result = read(kRtcStatusRegister, rtc);
                        if (result != RtcResult::Ok)
                        {
                            return result;
                        }
                        if ((rtc & kRtcStatusMask) == kRtcOn)
                        {
                            return RtcResult::Ok;
                        }
                    }
                    return RtcResult::WakeTimeout;
                }

            private:
                bool inBar(uint32_t reg) const
                {
                    return ((reg & 3U) == 0U) && reg <= b_.barLengthBytes &&
                           b_.barLengthBytes - reg >= 4;
                }

                const RtcPowerBackend &b_;
                RtcPowerContext &c_;
                RtcPowerStatus &s_;
                uint64_t started_, previous_;
        };
    } // namespace

    RtcResult transitionAr9565Rtc(const RtcPowerBackend &backend,
                                  const Identity &identity,
                                  RtcOperation operation,
                                  RtcPowerContext &context,
                                  RtcPowerStatus &status)
    {
        // Do not write even an error code through an aliased output: that
        // could corrupt a function pointer, retained context, or identity
        // before the input validation and any ownership callback runs.
        if (overlaps(&status, sizeof(status), &context, sizeof(context)) ||
            overlaps(&status, sizeof(status), &backend, sizeof(backend)) ||
            overlaps(&status, sizeof(status), &identity, sizeof(identity)) ||
            overlaps(&context, sizeof(context), &backend, sizeof(backend)) ||
            overlaps(&context, sizeof(context), &identity, sizeof(identity)) ||
            ((backend.context != nullptr) &&
             (overlaps(&status, sizeof(status), backend.context, 1) ||
              overlaps(&context, sizeof(context), backend.context, 1) ||
              overlaps(&backend, sizeof(backend), backend.context, 1) ||
              overlaps(&identity, sizeof(identity), backend.context, 1))))
        {
            return RtcResult::InvalidArgument;
        }
        // A callback may retain and alter the caller's table mid-transition.
        // Keep the validated routing and epoch fixed for this entire run.
        const RtcPowerBackend stableBackend = backend;
        status = {};
        if ((stableBackend.context == nullptr) ||
            (stableBackend.providerToken == 0U) ||
            (stableBackend.ownerEpoch == 0U) ||
            (stableBackend.canReset == nullptr) ||
            (stableBackend.read32 == nullptr) ||
            (stableBackend.write32 == nullptr) ||
            (stableBackend.nowMicros == nullptr) ||
            (stableBackend.delayMicros == nullptr) ||
            stableBackend.barLengthBytes < kForceWake + 4 ||
            (operation != RtcOperation::BootstrapPowerOn &&
             operation != RtcOperation::EnsureAwake &&
             operation != RtcOperation::WarmReset &&
             operation != RtcOperation::ColdReset))
        {
            return status.result = RtcResult::InvalidArgument;
        }
        if (stableBackend.mciEnabled &&
            ((stableBackend.beforeMacReset == nullptr) ||
             (stableBackend.afterRtcAwake == nullptr)))
        {
            return status.result = RtcResult::CoexistenceUnavailable;
        }
        // A caller-supplied context must be either fresh or a coherent
        // snapshot captured for a previous transition. Never honor a forged
        // bootstrap flag or reuse an incomplete provider snapshot.
        if ((!context.workaroundCaptured &&
             ((context.providerToken != 0U) || (context.srev != 0U) ||
              (context.workaroundValue != 0U) || context.bootstrapCompleted ||
              (context.bootstrapEpoch != 0U))) ||
            (context.workaroundCaptured &&
             ((context.providerToken == 0U) || (context.srev == 0U) ||
              context.bootstrapCompleted != (context.bootstrapEpoch != 0))))
        {
            return status.result = RtcResult::InvalidArgument;
        }
        if (!isSupportedPci(identity.vendorId, identity.deviceId) ||
            identity.spoofPossible)
        {
            return status.result = RtcResult::UnsupportedIdentity;
        }
        if (context.workaroundCaptured &&
            context.providerToken != stableBackend.providerToken)
        {
            return status.result = RtcResult::ProviderChanged;
        }
        // Retain the original WA capture for this provider, but never carry
        // reset readiness across a different D0/ownership generation.
        if (context.bootstrapCompleted &&
            context.bootstrapEpoch != stableBackend.ownerEpoch)
        {
            context.bootstrapCompleted = false;
            context.bootstrapEpoch = 0;
        }
        if (!context.bootstrapCompleted &&
            operation != RtcOperation::BootstrapPowerOn)
        {
            return status.result = RtcResult::BootstrapRequired;
        }
        // A failed active operation cannot retain a prior bootstrap claim,
        // even when power vanished before the first MMIO write. Otherwise a
        // stale same-token/epoch retry could skip the mandatory reset.
        const auto revokeReady = [&context, &status](RtcResult failure)
        {
            context.bootstrapCompleted = false;
            context.bootstrapEpoch = 0;
            return status.result = failure;
        };
        // RtcRun samples the first timestamp in its constructor. The clock
        // may share the PCI owner's memory, so check the live epoch BEFORE
        // invoking it rather than relying only on RtcRun::check() later.
        if (!stableBackend.canReset(stableBackend.context,
                                    stableBackend.ownerEpoch))
        {
            return revokeReady(RtcResult::AccessRevoked);
        }
        RtcRun run(stableBackend, context, status);
        uint32_t srev = 0;
        RtcResult result = run.read(kRevisionRegister, srev);
        if (result != RtcResult::Ok)
        {
            return revokeReady(result);
        }
        if (decodeRevision(srev, status.silicon) != Result::Ok)
        {
            return revokeReady(RtcResult::UnsupportedSilicon);
        }
        if (context.workaroundCaptured && context.srev != srev)
        {
            return revokeReady(RtcResult::ProviderChanged);
        }
        if (!context.workaroundCaptured)
        {
            uint32_t workaround = 0;
            result = run.read(kWorkaroundRegister, workaround);
            if (result != RtcResult::Ok)
            {
                return revokeReady(result);
            }
            context.providerToken = stableBackend.providerToken;
            context.srev = srev;
            context.workaroundValue = workaround | kWorkaroundWake;
            context.workaroundCaptured = true;
        }
        if (operation == RtcOperation::BootstrapPowerOn)
        {
            result = run.powerOn();
        }
        else if (operation == RtcOperation::EnsureAwake)
        {
            result = run.awake();
        }
        else
        {
            result = run.macReset(operation == RtcOperation::ColdReset);
        }
        if (result == RtcResult::Ok && operation != RtcOperation::EnsureAwake)
        {
            uint32_t rtc = 0;
            result = run.read(kRtcStatusRegister, rtc);
            if (result == RtcResult::Ok && (rtc & kRtcStatusMask) != kRtcOn)
            {
                result = RtcResult::WakeTimeout;
            }
        }
        if (result == RtcResult::Ok && stableBackend.mciEnabled)
        {
            if (!stableBackend.afterRtcAwake(stableBackend.context))
            {
                result = RtcResult::CoexistenceUnavailable;
            }
            else
            {
                result = run.check();
            }
        }
        // A final RTC read/awake callback can pass its post-operation gate
        // while D0 ownership is revoked before bootstrap/readiness is
        // published. A new capability check must precede all success state.
        if (result == RtcResult::Ok)
        {
            result = run.check();
        }
        if (result == RtcResult::Ok && !context.bootstrapCompleted)
        {
            // Commit readiness only after RTC status and MCI callbacks have
            // succeeded. This also covers EnsureAwake after RTC shutdown.
            context.bootstrapEpoch = stableBackend.ownerEpoch;
            context.bootstrapCompleted = true;
        }
        if (result != RtcResult::Ok)
        {
            return revokeReady(result);
        }
        status.rtcAwake = true;
        return status.result = RtcResult::Ok;
    }

} // namespace simpleath
