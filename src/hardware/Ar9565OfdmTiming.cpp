// Copyright:
//   - Original Atheros / Qualcomm Atheros copyright holders
// SPDX-License-Identifier:
//   - ISC
// Confidential:
//   - false
// License-File:
//   - LICENSE-ISC
// Provenance:
//   - Linux ath9k-derived material; preserve original in-file notices and
//     source hashes
//
// Boundary-Contract:
// - Owns:
//   - Native driver contracts and implementation for ar9565 ofdm timing.
// - Must-Not:
//   - Invent hardware readiness, weaken buffer bounds, or assume ABI
//     compatibility.
// - Allows:
//   - Inputs: validated register, protocol, platform, or device state from
//     callers.
//   - Outputs: bounded native transitions, messages, or explicit errors.
//   - Side effects: only the device and kernel operations owned by this module.
// - Split-When:
//   - A separate protocol stage needs independent validation and ownership.
// - Merge-When:
//   - The caller directly owns this narrow contract without reuse.
// - Summary:
//   - Native driver contracts and implementation for ar9565 ofdm timing.
// - Description:
//   - Implements or verifies the Ar9565OfdmTiming source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for ar9565 ofdm timing.

// Algorithm: Linux ath9k v6.12 ar9003_phy.c and hw.c; register fields:
// ar9003_phy.h. Qualcomm/Atheros source licensed under the ISC notice.
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
#include "Ar9565OfdmTiming.hpp"
#include "Ar9565Calibration.hpp"
#include "Ar9565Channel.hpp"
#include "Ar9565Core.hpp"
#include "Ar9565InitCatalog.hpp"
#include "Ar9565RfIni.hpp"
#include <stdint.h>

namespace simpleath
{
    namespace
    {
        constexpr uint32_t kPhyTiming3 = 0x9808;
        constexpr uint32_t kPhySgiDelta = 0x9c14;
        constexpr uint32_t kTiming3Mantissa = 0xfffe0000;
        constexpr uint32_t kTiming3Exponent = 0x0001e000;
        constexpr uint32_t kSgiMantissa = 0x0007fff0;
        constexpr uint32_t kSgiExponent = 0x0000000f;
        constexpr uint32_t kTiming3MantissaShift = 17;
        constexpr uint32_t kTiming3ExponentShift = 13;
        constexpr uint32_t kSgiMantissaShift = 4;
        constexpr uint32_t kCoefScaleShift = 24;
        constexpr uint32_t kMaxBitShift = 31;
        constexpr uint32_t kHardwareClockScaled = 0x64000000;
        constexpr uint32_t kSgiRatioNumerator = 9;
        constexpr uint32_t kSgiRatioDenominator = 10;
        constexpr uint8_t kJapanChannel = 14;
        constexpr int kHt40ChannelSeparation = 4;
        constexpr uint16_t kMantissaMax = 0x7fff;
        constexpr uint8_t kExponentMax = 15;

        struct Slope
        {
                uint16_t mantissa;
                uint8_t exponent;
        };

        struct RegisterWrite
        {
                uint32_t offset;
                uint32_t mask;
                uint32_t desiredFields;
        };

        bool fitsBar(uint32_t length, uint32_t offset)
        {
            return length >= sizeof(uint32_t) &&
                   offset <= length - sizeof(uint32_t);
        }

        bool synthesizerCenter(const RfChannelRequest &request,
                               uint16_t &center)
        {
            if ((request.silicon != Revision::V1_0 &&
                 request.silicon != Revision::V1_0_1 &&
                 request.silicon != Revision::V1_1) ||
                (request.referenceClock != RfReferenceClock::Crystal25Mhz &&
                 request.referenceClock != RfReferenceClock::Crystal40Mhz))
            {
                return false;
            }
            Channel canonical {};
            if (mapChannel(request.control.number, canonical) != Result::Ok ||
                request.control.centerMhz != canonical.centerMhz ||
                request.control.requiresJapanAuthorization !=
                    canonical.requiresJapanAuthorization)
            {
                return false;
            }
            if (request.width == ChannelWidth::Ht20 && request.secondary == 0)
            {
                center = canonical.centerMhz;
                return true;
            }
            if (request.width != ChannelWidth::Ht40 || request.secondary == 0 ||
                request.control.number == kJapanChannel ||
                request.secondary == kJapanChannel)
            {
                return false;
            }
            Channel secondary {};
            if (mapChannel(request.secondary, secondary) != Result::Ok)
            {
                return false;
            }
            const int separation = static_cast<int>(request.secondary) -
                                   static_cast<int>(request.control.number);
            if (separation != kHt40ChannelSeparation &&
                separation != -kHt40ChannelSeparation)
            {
                return false;
            }
            center = static_cast<uint16_t>(
                (canonical.centerMhz + secondary.centerMhz) / 2U);
            return true;
        }

        // Exact integer rounding/normalization used by ath9k. Bounds are
        // checked before shifts and field truncation (not implicit masking).
        bool calculateSlope(uint32_t scaled, Slope &out)
        {
            if (scaled == 0)
            {
                return false;
            }
            uint32_t leading = kMaxBitShift;
            while (leading > 0 && ((scaled >> leading) & 1U) == 0)
            {
                --leading;
            }
            // ath9k: coef_exp = 14 - (leading - COEF_SCALE_S).
            const int normalized = 14 - (static_cast<int>(leading) -
                                         static_cast<int>(kCoefScaleShift));
            const int shift = static_cast<int>(kCoefScaleShift) - normalized;
            const int exponent = normalized - 16;
            if (shift < 1 || shift > static_cast<int>(kMaxBitShift) ||
                exponent < 0 || exponent > kExponentMax)
            {
                return false;
            }
            const auto safeShift = static_cast<uint32_t>(shift);
            const uint32_t rounding = 1U << (safeShift - 1U);
            if (scaled > UINT32_MAX - rounding)
            {
                return false;
            }
            const uint32_t mantissa = (scaled + rounding) >> safeShift;
            if (mantissa > kMantissaMax)
            {
                return false;
            }
            out = {
                static_cast<uint16_t>(mantissa),
                static_cast<uint8_t>(exponent),
            };
            return true;
        }

        bool permit(const RfIniBackend &io, OfdmTimingProgress &progress)
        {
            if (io.permitWrite(io.context, io.ownerEpoch))
            {
                return true;
            }
            progress.result = OfdmTimingResult::OwnershipLost;
            progress.requiresReset =
                progress.requiresReset || progress.completedWrites != 0;
            return false;
        }

        bool writeSlope(const RxAgcBackend &backend,
                        OfdmTimingProgress &progress,
                        const RegisterWrite &operation)
        {
            const RfIniBackend &io = backend.io;
            progress.lastOffset = operation.offset;
            if (!permit(io, progress))
            {
                return false;
            }
            uint32_t previous = 0;
            if (!backend.read32(io.context, operation.offset, &previous))
            {
                progress.result = OfdmTimingResult::ReadFailed;
                return false;
            }
            ++progress.completedReads;
            const uint32_t desired = (previous & ~operation.mask) |
                                     (operation.desiredFields & operation.mask);
            if (!permit(io, progress))
            {
                return false;
            }
            // A callback reporting failure may already have posted to BAR.
            progress.requiresReset = true;
            if (!io.write32(io.context, operation.offset, desired))
            {
                progress.result = OfdmTimingResult::WriteFailed;
                return false;
            }
            ++progress.completedWrites;
            if (!permit(io, progress))
            {
                return false;
            }
            uint32_t observed = 0;
            if (!backend.read32(io.context, operation.offset, &observed))
            {
                progress.result = OfdmTimingResult::ReadFailed;
                return false;
            }
            ++progress.completedReads;
            if ((observed & operation.mask) != (desired & operation.mask))
            {
                progress.result = OfdmTimingResult::ReadbackMismatch;
                return false;
            }
            return permit(io, progress);
        }
    } // namespace

    OfdmTimingProgress
    programAr9565OfdmTiming(const RfChannelRequest &request,
                            const CalibrationAndRegulatory &authorization,
                            const RxAgcBackend &backend)
    {
        OfdmTimingProgress progress {
            OfdmTimingResult::InvalidBackend, 0, 0, 0, 0, 0, 0, 0, 0, false,
        };
        const RxAgcBackend stable = backend;
        const RfIniBackend &io = stable.io;
        if (io.context == nullptr || io.ownerEpoch == 0 ||
            io.permitWrite == nullptr || io.write32 == nullptr ||
            stable.read32 == nullptr)
        {
            return progress;
        }
        progress.result = OfdmTimingResult::InvalidChannel;
        if (!synthesizerCenter(request, progress.synthesizerMhz))
        {
            progress.synthesizerMhz = 0;
            return progress;
        }
        progress.result = OfdmTimingResult::MissingAuthorization;
        if (!radioInitializationAuthorized(authorization) ||
            (request.control.requiresJapanAuthorization &&
             !authorization.localCountryRulesAvailable))
        {
            // Channel 14 is not a global receive-only exception: a trusted
            // local channel policy must exist even when TX stays disabled.
            return progress;
        }
        progress.result = OfdmTimingResult::InvalidBar;
        if (!fitsBar(io.barLengthBytes, kPhyTiming3) ||
            !fitsBar(io.barLengthBytes, kPhySgiDelta))
        {
            return progress;
        }
        const uint32_t scaled = kHardwareClockScaled / progress.synthesizerMhz;
        Slope normal {};
        Slope shortInterval {};
        progress.result = OfdmTimingResult::InvalidChannel;
        if (!calculateSlope(scaled, normal) ||
            !calculateSlope((kSgiRatioNumerator * scaled) /
                                kSgiRatioDenominator,
                            shortInterval))
        {
            return progress;
        }
        progress.normalMantissa = normal.mantissa;
        progress.normalExponent = normal.exponent;
        progress.shortMantissa = shortInterval.mantissa;
        progress.shortExponent = shortInterval.exponent;
        const uint32_t normalFields =
            (static_cast<uint32_t>(normal.mantissa) << kTiming3MantissaShift) |
            (static_cast<uint32_t>(normal.exponent) << kTiming3ExponentShift);
        const uint32_t shortFields =
            (static_cast<uint32_t>(shortInterval.mantissa)
             << kSgiMantissaShift) |
            static_cast<uint32_t>(shortInterval.exponent);
        if (!writeSlope(stable, progress,
                        {
                            kPhyTiming3,
                            kTiming3Mantissa | kTiming3Exponent,
                            normalFields,
                        }) ||
            !writeSlope(stable, progress,
                        {
                            kPhySgiDelta,
                            kSgiMantissa | kSgiExponent,
                            shortFields,
                        }))
        {
            return progress;
        }
        progress.result = OfdmTimingResult::Ok;
        progress.requiresReset = false;
        return progress;
    }
} // namespace simpleath
