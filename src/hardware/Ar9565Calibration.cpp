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
        // Linux ath9k calib.c: ath9k_hw_start_nfcal(false),
        // ar9003_phy.c: ar9003_hw_do_getnf(), AR9565 2.4 GHz NF limits;
        // ar9003_phy.h: AR_PHY_CCA_0 / AR_PHY_EXT_CCA.
        // ath9k ar9003_phy.c: ar9003_hw_set_chain_masks(). RX-only uses
        // a zero SELFGEN mask, rather than Linux's normal TX-enabled mask.
        constexpr uint32_t kRxChainmaskRegister = 0xa2a0;
        constexpr uint32_t kCalibrationChainmaskRegister = 0xa2c0;
        constexpr uint32_t kSelfGeneratedChainmaskRegister = 0x832c;
        constexpr uint32_t kSingleRxChain = 1;
        constexpr uint32_t kNoAutoTransmit = 0;
        // ath9k hw.c: ath9k_hw_cfg_gpio_input/gpio_get, gpio.c:
        // ath_is_rfkill_set; reg.h: AR_GPIO_OE_OUT, AR_GPIO_IN and
        // AR9565_GPIO_MASK (14 valid pins). Never use AR_GPIO_IN_OUT for 9565.
        constexpr uint32_t kRfKillDirection = 0x4050;
        constexpr uint32_t kRfKillInput = 0x404c;
        constexpr uint8_t kRfKillPins = 14;
        constexpr uint32_t kRfKillDirectionWidth = 2;
        constexpr uint32_t kRfKillDirectionMask = 0x3;
        constexpr uint32_t kRfKillSettleMicros = 100;
        constexpr uint32_t kNoiseCal = 0x2;
        constexpr uint32_t kNoiseEnable = 0x8000;
        constexpr uint32_t kNoiseNoUpdate = 0x20000;
        constexpr uint32_t kNoisePrimaryCca = 0x9e1c;
        constexpr uint32_t kNoiseExtensionCca = 0x9830;
        constexpr uint32_t kNoisePrimaryShift = 20;
        constexpr uint32_t kNoiseExtensionShift = 16;
        constexpr uint32_t kNoiseMask = 0x1ff;
        constexpr uint32_t kNoiseSign = 0x100;
        constexpr int32_t kNoiseSignModulus = 0x200;
        constexpr int16_t kNoiseMinimum = -127;
        constexpr int16_t kNoiseMaximum = -60;
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

        bool validRfKillBackend(const RfKillBackend &backend)
        {
            return backend.context != nullptr && backend.ownerEpoch != 0 &&
                   backend.permitMmio != nullptr && backend.read32 != nullptr &&
                   backend.write32 != nullptr && backend.delayMicros != nullptr;
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

        class RxNoiseIo
        {
            public:
                RxNoiseIo(const RxAgcBackend &backend,
                          RxNoiseProgress &progress)
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
                    progress_->result = RxNoiseResult::OwnershipLost;
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
                        progress_->result = RxNoiseResult::ReadFailed;
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
                    // A false callback can follow an actual device write.
                    progress_->requiresReset = true;
                    if (!backend_->io.write32(backend_->io.context, offset,
                                              value))
                    {
                        progress_->result = RxNoiseResult::WriteFailed;
                        return false;
                    }
                    ++progress_->completedWrites;
                    return true;
                }

                bool awaitCompletion()
                {
                    for (size_t count = 0; count < kMaximumPolls; ++count)
                    {
                        uint32_t agc = 0;
                        if (!read(kAgcControl, agc))
                        {
                            return false;
                        }
                        ++progress_->polls;
                        if ((agc & kNoiseCal) == 0)
                        {
                            return permit();
                        }
                        if (count + 1 < kMaximumPolls)
                        {
                            backend_->io.delayMicros(backend_->io.context,
                                                     kPollingMicros);
                        }
                    }
                    progress_->result = RxNoiseResult::Timeout;
                    return false;
                }

            private:
                const RxAgcBackend *backend_;
                RxNoiseProgress *progress_;
        };

        int16_t decodeNoise(uint32_t value, uint32_t shift)
        {
            const uint32_t raw = (value >> shift) & kNoiseMask;
            const int32_t signedValue =
                (raw & kNoiseSign) != 0
                    ? static_cast<int32_t>(raw) - kNoiseSignModulus
                    : static_cast<int32_t>(raw);
            return static_cast<int16_t>(signedValue);
        }

        bool validNoise(int16_t sample)
        {
            return sample >= kNoiseMinimum && sample <= kNoiseMaximum;
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

    RxNoiseProgress runAr9565RxNoiseFloorCalibration(
        const RfChannelRequest &request,
        const CalibrationAndRegulatory &authorization,
        const RxAgcBackend &backend)
    {
        RxNoiseProgress progress {
            RxNoiseResult::InvalidBackend, 0, 0, 0, 0, 0, false, false,
        };
        const RxAgcBackend stable = backend;
        const RfChannelRequest channel = request;
        const CalibrationAndRegulatory permissions = authorization;
        if (!validBackend(stable))
        {
            return progress;
        }
        progress.result = RxNoiseResult::InvalidChannel;
        if (!validChannel(channel))
        {
            return progress;
        }
        progress.result = RxNoiseResult::MissingAuthorization;
        if (permissions.use != RadioInitialization::ReceiveOnly ||
            !radioInitializationAuthorized(permissions))
        {
            return progress;
        }
        progress.result = RxNoiseResult::InvalidBar;
        if (stable.io.barLengthBytes < kAgcControl + sizeof(uint32_t))
        {
            return progress;
        }
        RxNoiseIo io(stable, progress);
        uint32_t agc = 0;
        if (!io.read(kAgcControl, agc))
        {
            return progress;
        }
        progress.result = RxNoiseResult::AlreadyBusy;
        if ((agc & (kAgcCal | kNoiseCal)) != 0)
        {
            return progress;
        }
        const uint32_t start = agc | kNoiseEnable | kNoiseNoUpdate | kNoiseCal;
        if (!io.write(kAgcControl, start) || !io.awaitCompletion())
        {
            return progress;
        }
        uint32_t control = 0;
        if (!io.read(kNoisePrimaryCca, control))
        {
            return progress;
        }
        progress.controlDbm = decodeNoise(control, kNoisePrimaryShift);
        progress.result = RxNoiseResult::InvalidMeasurement;
        if (!validNoise(progress.controlDbm))
        {
            return progress;
        }
        if (channel.width == ChannelWidth::Ht40)
        {
            uint32_t extension = 0;
            if (!io.read(kNoiseExtensionCca, extension))
            {
                return progress;
            }
            progress.extensionDbm =
                decodeNoise(extension, kNoiseExtensionShift);
            if (!validNoise(progress.extensionDbm))
            {
                return progress;
            }
            progress.hasExtension = true;
        }
        if (!io.permit())
        {
            return progress;
        }
        progress.result = RxNoiseResult::Ok;
        progress.requiresReset = false;
        return progress;
    }

    RxChainsProgress configureAr9565ReceiveOnlyChains(
        const Ar9565BoardChainMasks &board,
        const CalibrationAndRegulatory &authorization,
        const RxAgcBackend &backend)
    {
        RxChainsProgress progress {
            RxChainsResult::InvalidBackend, 0, 0, 0, false,
        };
        const RxAgcBackend stable = backend;
        const CalibrationAndRegulatory permissions = authorization;
        if (!validBackend(stable))
        {
            return progress;
        }
        progress.result = RxChainsResult::InvalidBoard;
        if (board.rx != kSingleRxChain || board.tx != kSingleRxChain)
        {
            return progress;
        }
        progress.result = RxChainsResult::MissingAuthorization;
        if (permissions.use != RadioInitialization::ReceiveOnly ||
            !radioInitializationAuthorized(permissions))
        {
            return progress;
        }
        progress.result = RxChainsResult::InvalidBar;
        if (stable.io.barLengthBytes <
            kCalibrationChainmaskRegister + sizeof(uint32_t))
        {
            return progress;
        }
        const auto &io = stable.io;

        // Do not assume no automatic TX while the owner has not quiesced
        // the MAC; permitWrite must verify the real RX/TX quiescence gate.
        struct RegisterStep
        {
                uint32_t offset;
                uint32_t value;
        };

        const RegisterStep steps[] = {
            {kSelfGeneratedChainmaskRegister, kNoAutoTransmit},
            {kRxChainmaskRegister, kSingleRxChain},
            {kCalibrationChainmaskRegister, kSingleRxChain},
        };
        for (const auto &step : steps)
        {
            progress.result = RxChainsResult::OwnershipLost;
            if (!io.permitWrite(io.context, io.ownerEpoch))
            {
                return progress;
            }
            progress.lastOffset = step.offset;
            progress.requiresReset = true;
            progress.result = RxChainsResult::WriteFailed;
            if (!io.write32(io.context, step.offset, step.value))
            {
                return progress;
            }
            ++progress.completedWrites;
            progress.result = RxChainsResult::OwnershipLost;
            if (!io.permitWrite(io.context, io.ownerEpoch))
            {
                return progress;
            }
            uint32_t observed = 0;
            progress.result = RxChainsResult::ReadFailed;
            if (!stable.read32(io.context, step.offset, &observed))
            {
                return progress;
            }
            ++progress.completedReads;
            progress.result = RxChainsResult::ReadbackMismatch;
            if (observed != step.value)
            {
                return progress;
            }
        }
        progress.result = RxChainsResult::OwnershipLost;
        if (!io.permitWrite(io.context, io.ownerEpoch))
        {
            return progress;
        }
        progress.result = RxChainsResult::Ok;
        progress.requiresReset = false;
        return progress;
    }

    RxCalibrationWorkflowProgress runAr9565ReceiveOnlyCalibration(
        const RfChannelRequest &request, const Ar9565BoardChainMasks &board,
        const CalibrationAndRegulatory &authorization,
        const RxAgcBackend &backend)
    {
        RxCalibrationWorkflowProgress progress {
            RxCalibrationPhase::ChainMasks,
            {RxChainsResult::InvalidBackend, 0, 0, 0, false},
            {RxAgcResult::InvalidBackend, 0, 0, 0, 0, false},
            {RxIqResult::InvalidBackend, 0, 0, 0, 0, 0, false},
            {RxNoiseResult::InvalidBackend, 0, 0, 0, 0, 0, false, false},
            false,
        };
        progress.chains =
            configureAr9565ReceiveOnlyChains(board, authorization, backend);
        progress.requiresReset = progress.chains.requiresReset;
        if (progress.chains.result != RxChainsResult::Ok)
        {
            return progress;
        }
        // Even if a subsequent stage rejects before touching the BAR, the
        // earlier successful writes have changed the PHY state. Require
        // owner reset on ANY downstream failure, including epoch loss.
        progress.requiresReset = true;
        progress.phase = RxCalibrationPhase::AgcOffset;
        progress.agc =
            runAr9565RxAgcCalibration(request, authorization, backend);
        if (progress.agc.result != RxAgcResult::Ok)
        {
            return progress;
        }
        progress.phase = RxCalibrationPhase::IqCorrection;
        progress.iq = runAr9565RxIqCalibration(request, authorization, backend);
        if (progress.iq.result != RxIqResult::Ok)
        {
            return progress;
        }
        progress.phase = RxCalibrationPhase::NoiseFloor;
        progress.noise =
            runAr9565RxNoiseFloorCalibration(request, authorization, backend);
        if (progress.noise.result != RxNoiseResult::Ok)
        {
            return progress;
        }
        progress.phase = RxCalibrationPhase::Completed;
        progress.requiresReset = false;
        return progress;
    }

    RfKillProgress sampleAr9565RfKill(const RfKillBoardConfiguration &board,
                                      const RfKillBackend &backend)
    {
        RfKillProgress result {
            RfKillResult::InvalidBackend, true, 0, 0, 0, false,
        };
        const RfKillBackend stable = backend;
        const RfKillBoardConfiguration config = board;
        if (!validRfKillBackend(stable))
        {
            return result;
        }
        result.result = RfKillResult::NotConfigured;
        if (!config.configured)
        {
            return result;
        }
        result.result = RfKillResult::InvalidGpio;
        if (config.gpio >= kRfKillPins)
        {
            return result;
        }
        result.result = RfKillResult::InvalidBar;
        if (stable.barLengthBytes < kRfKillDirection + sizeof(uint32_t))
        {
            return result;
        }
        result.gpio = config.gpio;
        const auto permit = [&]
        {
            if (stable.permitMmio(stable.context, stable.ownerEpoch))
            {
                return true;
            }
            result.result = RfKillResult::OwnershipLost;
            return false;
        };
        const auto read = [&](uint32_t offset, uint32_t &value)
        {
            if (!permit())
            {
                return false;
            }
            if (!stable.read32(stable.context, offset, &value))
            {
                result.result = RfKillResult::ReadFailed;
                return false;
            }
            ++result.completedReads;
            return true;
        };
        uint32_t direction = 0;
        if (!read(kRfKillDirection, direction))
        {
            return result;
        }
        const uint32_t mask =
            kRfKillDirectionMask
            << (static_cast<uint32_t>(config.gpio) * kRfKillDirectionWidth);
        const uint32_t inputDirection = direction & ~mask;
        if (inputDirection != direction)
        {
            if (!permit())
            {
                return result;
            }
            result.requiresReset = true;
            result.result = RfKillResult::WriteFailed;
            if (!stable.write32(stable.context, kRfKillDirection,
                                inputDirection))
            {
                return result;
            }
            ++result.completedWrites;
        }
        uint32_t observed = 0;
        if (!read(kRfKillDirection, observed))
        {
            return result;
        }
        result.result = RfKillResult::ReadbackMismatch;
        if (observed != inputDirection)
        {
            return result;
        }
        uint32_t first = 0;
        uint32_t second = 0;
        if (!read(kRfKillInput, first) || !permit())
        {
            return result;
        }
        stable.delayMicros(stable.context, kRfKillSettleMicros);
        if (!read(kRfKillInput, second) || !permit())
        {
            return result;
        }
        const uint32_t bit = uint32_t {1} << config.gpio;
        result.result = RfKillResult::Unstable;
        if (((first ^ second) & bit) != 0)
        {
            return result;
        }
        const bool levelHigh = (second & bit) != 0;
        result.hardwareBlocked = levelHigh == config.activeHigh;
        result.requiresReset = false;
        result.result = result.hardwareBlocked ? RfKillResult::Blocked
                                               : RfKillResult::Unblocked;
        return result;
    }

} // namespace simpleath
