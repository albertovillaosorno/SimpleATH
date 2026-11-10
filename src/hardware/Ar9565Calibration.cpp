// SPDX-License-Identifier: AGPL-3.0-only
// Register sequence and hardware algorithm provenance (ath9k):
/*
 * Copyright (c) 2010-2011 Atheros Communications Inc.
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
#include "Ar9565Calibration.hpp"
#include "Ar9565Channel.hpp"
#include "Ar9565Core.hpp"
#include "Ar9565InitCatalog.hpp"
#include <cstddef>
#include <cstdint>

namespace simpleath
{
    namespace
    {
        // ath9k ar9003_calib.c: ar9003_hw_init_cal_pcoem / AGC wait;
        // ath9k ar9003_phy.h and reg.h (AR9300 SM base 0xa200).
        // ar9003_calib.c ar9003_hw_setup_calibration(), iqcal_collect(),
        // iqcalibrate(); ar9003_phy.h AR_CHAN_BASE and correction masks.
        constexpr uint32_t kIqTiming = 0x980c;
        constexpr uint32_t kIqCalMode = 0xa2c8;
        constexpr uint32_t kIqMeasI = 0x98c0;
        constexpr uint32_t kIqMeasQ = 0x98c4;
        constexpr uint32_t kIqMeasCorr = 0x98c8;
        constexpr uint32_t kIqCorrection = 0x98dc;
        constexpr uint32_t kIqTimingLogMask = 0xf000;
        constexpr uint32_t kIqTimingLogMax = 0xa000;
        constexpr uint32_t kIqTimingDoCal = 0x10000;
        constexpr uint32_t kIqCalModeIq = 0;
        constexpr uint32_t kIqCorrectionMask = 0x3fff;
        constexpr uint32_t kIqCorrectionEnable = 0x4000;
        constexpr uint32_t kIqCoefMask = 0x7f;
        constexpr uint32_t kIqCoefShift = 7;
        constexpr int64_t kIqMaximumCoefficient = 63;
        constexpr uint64_t kIqDenominatorScale = 256;
        constexpr uint64_t kIqQPowerScale = 64;
        constexpr uint64_t kIqSignBit = 0x80000000ULL;
        constexpr uint64_t kIqMagnitudeModulus = 0x100000000ULL;
        constexpr uint32_t kAgcControl = 0xa2c4;
        constexpr uint32_t kCarrierLeakControl = 0xa2d8;
        constexpr uint32_t kTxIqControl = 0xa5c4;
        constexpr uint32_t kAgcCal = 0x1;
        constexpr uint32_t kAgcOffset = 0x800;
        constexpr uint32_t kAgcTxFilter = 0x10000;
        constexpr uint32_t kAgcPeakDetector = 0x100000;
        constexpr uint32_t kCarrierLeakEnable = 0x2;
        constexpr uint32_t kTxIqEnable = 0x80000000;
        constexpr uint32_t kPollingMicros = 10;
        constexpr size_t kMaximumPolls = 100000 / kPollingMicros;
        constexpr uint8_t kChannel14 = 14;
        constexpr uint8_t kHt40Separation = 4;

        bool validChannel(const RfChannelRequest &request)
        {
            if (request.silicon != Revision::V1_0 &&
                request.silicon != Revision::V1_0_1 &&
                request.silicon != Revision::V1_1)
            {
                return false;
            }
            if (request.referenceClock != RfReferenceClock::Crystal25Mhz &&
                request.referenceClock != RfReferenceClock::Crystal40Mhz)
            {
                return false;
            }
            Channel channel {};
            if (mapChannel(request.control.number, channel) != Result::Ok ||
                channel.centerMhz != request.control.centerMhz ||
                channel.requiresJapanAuthorization !=
                    request.control.requiresJapanAuthorization)
            {
                return false;
            }
            if (request.width == ChannelWidth::Ht20)
            {
                return request.secondary == 0;
            }
            if (request.width != ChannelWidth::Ht40 ||
                request.control.number == kChannel14 ||
                request.secondary == kChannel14)
            {
                return false;
            }
            Channel secondary {};
            if (mapChannel(request.secondary, secondary) != Result::Ok)
            {
                return false;
            }
            const int delta = static_cast<int>(request.control.number) -
                              static_cast<int>(request.secondary);
            return delta == kHt40Separation || delta == -kHt40Separation;
        }

        bool validBackend(const RxAgcBackend &backend)
        {
            const auto &io = backend.io;
            return io.context != nullptr && io.ownerEpoch != 0 &&
                   io.permitWrite != nullptr && io.write32 != nullptr &&
                   io.delayMicros != nullptr && backend.read32 != nullptr;
        }

        bool permit(const RfIniBackend &io, RxAgcProgress &progress)
        {
            if (io.permitWrite(io.context, io.ownerEpoch))
            {
                return true;
            }
            progress.result = RxAgcResult::OwnershipLost;
            return false;
        }

        bool read(const RxAgcBackend &backend, RxAgcProgress &progress,
                  uint32_t address, uint32_t &value)
        {
            const auto &io = backend.io;
            if (!permit(io, progress))
            {
                return false;
            }
            progress.lastOffset = address;
            if (!backend.read32(io.context, address, &value))
            {
                progress.result = RxAgcResult::ReadFailed;
                return false;
            }
            ++progress.completedReads;
            return true;
        }

        bool write(const RfIniBackend &io, RxAgcProgress &progress,
                   uint32_t address, uint32_t value)
        {
            if (!permit(io, progress))
            {
                return false;
            }
            progress.lastOffset = address;
            // A false write return does not prove that hardware ignored it.
            progress.requiresReset = true;
            if (!io.write32(io.context, address, value))
            {
                progress.result = RxAgcResult::WriteFailed;
                return false;
            }
            ++progress.completedWrites;
            return true;
        }

        void poll(const RxAgcBackend &backend, RxAgcProgress &progress)
        {
            const auto &io = backend.io;
            for (size_t i = 0; i < kMaximumPolls; ++i)
            {
                uint32_t status = 0;
                if (!read(backend, progress, kAgcControl, status))
                {
                    return;
                }
                ++progress.polls;
                if ((status & kAgcCal) == 0)
                {
                    if (permit(io, progress))
                    {
                        progress.result = RxAgcResult::Ok;
                        progress.requiresReset = false;
                    }
                    return;
                }
                if (i + 1 < kMaximumPolls)
                {
                    io.delayMicros(io.context, kPollingMicros);
                }
            }
            progress.result = RxAgcResult::Timeout;
        }

        class RxIqIo
        {
            public:
                RxIqIo(const RxAgcBackend &backend, RxIqProgress &progress)
                    : backend_(&backend), progress_(&progress)
                {
                }

                bool permit()
                {
                    if (backend_->io.permitWrite(backend_->io.context,
                                                 backend_->io.ownerEpoch))
                    {
                        return true;
                    }
                    progress_->result = RxIqResult::OwnershipLost;
                    return false;
                }

                bool read(uint32_t offset, uint32_t &value)
                {
                    if (!permit())
                    {
                        return false;
                    }
                    if (!backend_->read32(backend_->io.context, offset, &value))
                    {
                        progress_->result = RxIqResult::ReadFailed;
                        return false;
                    }
                    ++progress_->completedReads;
                    return true;
                }

                bool write(uint32_t offset, uint32_t value)
                {
                    if (!permit())
                    {
                        return false;
                    }
                    // Even a failed MMIO callback may have issued the write.
                    progress_->requiresReset = true;
                    if (!backend_->io.write32(backend_->io.context, offset,
                                              value))
                    {
                        progress_->result = RxIqResult::WriteFailed;
                        return false;
                    }
                    ++progress_->completedWrites;
                    return true;
                }

                bool waitComplete()
                {
                    for (size_t count = 0; count < kMaximumPolls; ++count)
                    {
                        uint32_t timing = 0;
                        if (!read(kIqTiming, timing))
                        {
                            return false;
                        }
                        ++progress_->polls;
                        if ((timing & kIqTimingDoCal) == 0)
                        {
                            return permit();
                        }
                        if (count + 1 < kMaximumPolls)
                        {
                            backend_->io.delayMicros(backend_->io.context,
                                                     kPollingMicros);
                        }
                    }
                    progress_->result = RxIqResult::Timeout;
                    return false;
                }

            private:
                const RxAgcBackend *backend_;
                RxIqProgress *progress_;
        };

        struct RxIqMeasurements
        {
                uint32_t powerI;
                uint32_t powerQ;
                uint32_t correlation;
        };

        bool calculateIq(const RxIqMeasurements &sample, RxIqProgress &progress)
        {
            const uint64_t denominatorI =
                (static_cast<uint64_t>(sample.powerI / 2) +
                 (sample.powerQ / 2)) /
                kIqDenominatorScale;
            const uint64_t denominatorQ = sample.powerQ / kIqQPowerScale;
            if (denominatorI == 0 || denominatorQ == 0)
            {
                progress.result = RxIqResult::InvalidMeasurement;
                return false;
            }
            // Two's-complement magnitude handling in unsigned arithmetic.
            const bool negative = sample.correlation > kIqSignBit;
            const uint64_t magnitude =
                negative ? kIqMagnitudeModulus - sample.correlation
                         : sample.correlation;
            auto coefficientI = static_cast<int64_t>(magnitude / denominatorI);
            const auto coefficientQ =
                static_cast<int64_t>(sample.powerI / denominatorQ) -
                static_cast<int64_t>(kIqQPowerScale);
            if (!negative)
            {
                coefficientI = -coefficientI;
            }
            // ath9k refuses a saturated +/-63 coefficient on AR9565.
            // Reject rather than clamp and publish an unusable calibration.
            if (coefficientI >= kIqMaximumCoefficient ||
                coefficientI <= -kIqMaximumCoefficient ||
                coefficientQ >= kIqMaximumCoefficient ||
                coefficientQ <= -kIqMaximumCoefficient)
            {
                progress.result = RxIqResult::InvalidMeasurement;
                return false;
            }
            progress.iCorrection = static_cast<int16_t>(coefficientI);
            progress.qCorrection = static_cast<int16_t>(coefficientQ);
            return true;
        }

    } // namespace

    RxAgcProgress
    runAr9565RxAgcCalibration(const RfChannelRequest &request,
                              const CalibrationAndRegulatory &authorization,
                              const RxAgcBackend &backend)
    {
        RxAgcProgress progress {RxAgcResult::InvalidBackend, 0, 0, 0, 0, false};
        const RxAgcBackend stable = backend;
        const RfChannelRequest channel = request;
        const CalibrationAndRegulatory permissions = authorization;
        if (!validBackend(stable))
        {
            return progress;
        }
        progress.result = RxAgcResult::InvalidChannel;
        if (!validChannel(channel))
        {
            return progress;
        }
        progress.result = RxAgcResult::MissingAuthorization;
        if (permissions.use != RadioInitialization::ReceiveOnly ||
            !radioInitializationAuthorized(permissions))
        {
            return progress;
        }
        const RfIniBackend &io = stable.io;
        progress.result = RxAgcResult::InvalidBar;
        if (io.barLengthBytes < kTxIqControl + sizeof(uint32_t))
        {
            return progress;
        }
        uint32_t agc = 0;
        uint32_t txIq = 0;
        uint32_t carrierLeak = 0;
        if (!read(stable, progress, kAgcControl, agc) ||
            !read(stable, progress, kTxIqControl, txIq) ||
            !read(stable, progress, kCarrierLeakControl, carrierLeak))
        {
            return progress;
        }
        progress.result = RxAgcResult::AlreadyBusy;
        if ((agc & kAgcCal) != 0)
        {
            return progress;
        }
        if (!write(io, progress, kTxIqControl, txIq & ~kTxIqEnable) ||
            !write(io, progress, kCarrierLeakControl,
                   carrierLeak & ~kCarrierLeakEnable) ||
            !write(io, progress, kAgcControl,
                   (agc | kAgcOffset | kAgcCal) &
                       ~(kAgcTxFilter | kAgcPeakDetector)))
        {
            return progress;
        }
        // Hardware must deassert AGC.CAL on completion. A bounded wait
        // never establishes PHY or regulatory readiness by itself.
        poll(stable, progress);
        return progress;
    }

    RxIqProgress
    runAr9565RxIqCalibration(const RfChannelRequest &request,
                             const CalibrationAndRegulatory &authorization,
                             const RxAgcBackend &backend)
    {
        RxIqProgress progress {
            RxIqResult::InvalidBackend, 0, 0, 0, 0, 0, false,
        };
        const RxAgcBackend stable = backend;
        const RfChannelRequest channel = request;
        const CalibrationAndRegulatory permissions = authorization;
        if (!validBackend(stable))
        {
            return progress;
        }
        progress.result = RxIqResult::InvalidChannel;
        if (!validChannel(channel))
        {
            return progress;
        }
        progress.result = RxIqResult::MissingAuthorization;
        if (permissions.use != RadioInitialization::ReceiveOnly ||
            !radioInitializationAuthorized(permissions))
        {
            return progress;
        }
        progress.result = RxIqResult::InvalidBar;
        if (stable.io.barLengthBytes < kIqCalMode + sizeof(uint32_t))
        {
            return progress;
        }
        RxIqIo io(stable, progress);
        uint32_t timing = 0;
        uint32_t priorCorrection = 0;
        if (!io.read(kIqTiming, timing) ||
            !io.read(kIqCorrection, priorCorrection))
        {
            return progress;
        }
        progress.result = RxIqResult::AlreadyBusy;
        if ((timing & kIqTimingDoCal) != 0)
        {
            return progress;
        }
        const uint32_t configuredTiming =
            (timing & ~kIqTimingLogMask) | kIqTimingLogMax;
        if (!io.write(kIqTiming, configuredTiming) ||
            !io.write(kIqCalMode, kIqCalModeIq) ||
            !io.write(kIqTiming, configuredTiming | kIqTimingDoCal) ||
            !io.waitComplete())
        {
            return progress;
        }
        RxIqMeasurements measured {};
        if (!io.read(kIqMeasI, measured.powerI) ||
            !io.read(kIqMeasQ, measured.powerQ) ||
            !io.read(kIqMeasCorr, measured.correlation) ||
            !calculateIq(measured, progress))
        {
            return progress;
        }
        const uint32_t iBits =
            static_cast<uint32_t>(progress.iCorrection) & kIqCoefMask;
        const uint32_t qBits =
            static_cast<uint32_t>(progress.qCorrection) & kIqCoefMask;
        const uint32_t correction =
            (priorCorrection & ~(kIqCorrectionMask | kIqCorrectionEnable)) |
            (iBits << kIqCoefShift) | qBits | kIqCorrectionEnable;
        if (!io.write(kIqCorrection, correction) || !io.permit())
        {
            return progress;
        }
        progress.result = RxIqResult::Ok;
        progress.requiresReset = false;
        return progress;
    }
} // namespace simpleath
