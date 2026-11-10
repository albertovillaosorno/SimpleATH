// ath9k-derived target interpolation and 2 GHz CTL edge interpretation.
/*
 * Copyright (c) 2008-2011 Atheros Communications Inc.
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
// Local Linux ath9k reference SHA-256:
// ar9003_eeprom.c:
// 9af461f68c73fdbe553619534f0474dca637a7c5191729251fa479af2ad75dc6
// ar9003_eeprom.h:
// 4de071df42f0d91df022c91779f9bb7d0aac57fa7803f240530b4f0acd457bbd
//
// eeprom.h:
// b6bc5f1bffd56f5b8828d14635eac4846487ff6f2ef06344d474ac4c1c11b7b0
// common-init.c:
// c6f047abac0931612ed3e392d2fc5c4839d46a6fbf5175d54ad2c3c3ffc0ed80
#include "Ar9565Power.hpp"
#include "Ar9565Core.hpp"
#include "Ar9565Eeprom.hpp"
#include "Ar9565InitCatalog.hpp"
#include <cstddef>
#include <cstdint>

namespace simpleath
{
    namespace
    {
        constexpr uint16_t kFrequencyBinBase = 2300U;
        constexpr uint8_t kFirst2GhzBin = 112U;
        constexpr uint8_t kLast2GhzBin = 184U;
        constexpr uint8_t kMissingFrequencyBin = 0xffU;
        constexpr uint8_t kMaximumHalfDbm = 63U;
        constexpr uint8_t kCckOnlyChannel = 14U;
        constexpr uint8_t kHt20Disabled = 0x20U;
        constexpr uint8_t kHt40Disabled = 0x08U;
        constexpr int32_t kHt40OffsetMhz = 20;
        constexpr uint16_t kFirstChannelMhz = 2412U;
        constexpr uint16_t kLastRegularChannelMhz = 2472U;
        constexpr uint16_t kChannelRasterOffsetMhz = 2407U;
        constexpr uint16_t kChannelRasterSpacingMhz = 5U;
        constexpr uint16_t kCckOnlyChannelMhz = 2484U;
        constexpr uint8_t kMcsFirstCode = 0x80U;
        constexpr uint8_t kMcsLastCode = 0x87U;
        constexpr size_t kCtlIndexOffset = 310U;
        constexpr size_t kCtlBinOffset = 322U;
        constexpr size_t kCtlPowerOffset = 370U;
        constexpr size_t kCtlEntries = 12U;
        constexpr size_t kCtlEdgesPerEntry = 4U;
        constexpr uint8_t kCtlModeMask = 0x0fU;
        constexpr uint8_t kCtlGroupMask = 0xf0U;
        constexpr uint8_t kCtlAllGroups = 0xe0U;
        constexpr uint8_t kCtlInvalidGroup = 0xf0U;
        constexpr uint8_t kCtlPowerMask = 0x3fU;
        constexpr uint32_t kCtlInbandShift = 6U;
        constexpr uint8_t kCckMode = 1U;
        constexpr uint8_t kOfdmMode = 2U;
        constexpr uint8_t kHt20Mode = 5U;
        constexpr uint8_t kHt40Mode = 7U;

        struct TargetLayout
        {
                size_t binsOffset;
                size_t powerOffset;
                size_t maximumPiers;
                size_t rates;
        };

        constexpr TargetLayout kCckTargets {
            195U,
            206U,
            2U,
            4U,
        };
        constexpr TargetLayout kOfdmTargets {
            197U,
            214U,
            3U,
            4U,
        };
        constexpr TargetLayout kHt20Targets {
            200U,
            226U,
            3U,
            kHtTargetPowerGroups,
        };
        constexpr TargetLayout kHt40Targets {
            203U,
            268U,
            3U,
            kHtTargetPowerGroups,
        };

        struct CtlQuery
        {
                uint8_t group;
                uint8_t mode;
                uint16_t mhz;
        };

        struct CtlEdgeQuery
        {
                size_t row;
                uint16_t mhz;
        };

        // AR9565 transmit rate codes, as specified by ath9k MAC metadata.
        constexpr uint8_t kRateCckOne = 0x1bU;
        constexpr uint8_t kRateCckTwoLong = 0x1aU;
        constexpr uint8_t kRateCckTwoShort = 0x1eU;
        constexpr uint8_t kRateCckFiveLong = 0x19U;
        constexpr uint8_t kRateCckFiveShort = 0x1dU;
        constexpr uint8_t kRateCckElevenLong = 0x18U;
        constexpr uint8_t kRateCckElevenShort = 0x1cU;
        constexpr uint8_t kRateOfdmSix = 0x0bU;
        constexpr uint8_t kRateOfdmNine = 0x0fU;
        constexpr uint8_t kRateOfdmTwelve = 0x0aU;
        constexpr uint8_t kRateOfdmEighteen = 0x0eU;
        constexpr uint8_t kRateOfdmTwentyFour = 0x09U;
        constexpr uint8_t kRateOfdmThirtySix = 0x0dU;
        constexpr uint8_t kRateOfdmFortyEight = 0x08U;
        constexpr uint8_t kRateOfdmFiftyFour = 0x0cU;

        template <typename T, size_t N>
        const T &at(const T (&items)[N], size_t index)
        {
            for (const T &item : items)
            {
                if (index == 0U)
                {
                    return item;
                }
                --index;
            }
            __builtin_trap(); // All indexes originate in fixed NVM layouts.
        }

        template <typename T, size_t N> T &at(T (&items)[N], size_t index)
        {
            for (T &item : items)
            {
                if (index == 0U)
                {
                    return item;
                }
                --index;
            }
            __builtin_trap();
        }

        uint8_t imageByte(const EepromImage &image, size_t index)
        {
            return at(image.bytes, index);
        }

        uintptr_t pointerValue(const void *pointer)
        {
            uintptr_t value = 0;
            static_assert(sizeof(value) == sizeof(pointer),
                          "native pointers must fit uintptr_t");
            __builtin_memcpy(static_cast<void *>(&value),
                             static_cast<const void *>(&pointer),
                             sizeof(pointer));
            return value;
        }

        // Difference-based overlap checks avoid pointer-end overflow.
        bool overlaps(const void *a, size_t aBytes, const void *b,
                      size_t bBytes)
        {
            const auto first = pointerValue(a);
            const auto second = pointerValue(b);
            return first <= second ? second - first < aBytes
                                   : first - second < bBytes;
        }

        uint8_t minimum(uint8_t a, uint8_t b)
        {
            return a < b ? a : b;
        }

        uint16_t frequency(uint8_t bin)
        {
            return static_cast<uint16_t>(kFrequencyBinBase + bin);
        }

        PowerResult countTargetPiers(const EepromImage &image,
                                     const TargetLayout &layout, size_t &count)
        {
            count = 0;
            bool ended = false;
            for (size_t pier = 0; pier < layout.maximumPiers; ++pier)
            {
                const uint8_t bin = imageByte(image, layout.binsOffset + pier);
                if (bin == kMissingFrequencyBin)
                {
                    ended = true;
                    continue;
                }
                // Target piers must be actual 2.4 GHz frequencies. A
                // malformed 5 GHz or zero bin must not become an implicit
                // extrapolation endpoint for a 2.4 GHz power budget.
                if (ended || bin < kFirst2GhzBin || bin > kLast2GhzBin ||
                    ((pier != 0U) &&
                     bin <= imageByte(image, layout.binsOffset + pier - 1)))
                {
                    return PowerResult::InvalidCurve;
                }
                for (size_t rate = 0; rate < layout.rates; ++rate)
                {
                    if (imageByte(image, layout.powerOffset +
                                             (pier * layout.rates) + rate) >
                        kMaximumHalfDbm)
                    {
                        return PowerResult::InvalidCurve;
                    }
                }
                ++count;
            }
            return count != 0 ? PowerResult::Ok : PowerResult::InvalidCurve;
        }

        // Layout offsets come from packed ar9300_eeprom, not a native structure
        // cast.
        template <size_t N>
        PowerResult targets(const EepromImage &image,
                            const TargetLayout &layout, uint16_t mhz,
                            uint8_t (&out)[N])
        {
            size_t count = 0;
            const PowerResult valid = countTargetPiers(image, layout, count);
            if (valid != PowerResult::Ok)
            {
                return valid;
            }
            size_t low = 0;
            size_t high = 0;
            if (mhz >=
                frequency(imageByte(image, layout.binsOffset + count - 1)))
            {
                low = high = count - 1;
            }
            else if (mhz > frequency(imageByte(image, layout.binsOffset)))
            {
                for (high = 1; high < count; ++high)
                {
                    if (mhz <=
                        frequency(imageByte(image, layout.binsOffset + high)))
                    {
                        break;
                    }
                }
                low = high - 1;
            }
            for (size_t rate = 0; rate < layout.rates; ++rate)
            {
                const int32_t y0 = imageByte(
                    image, layout.powerOffset + (low * layout.rates) + rate);
                int32_t value = y0;
                if (high != low)
                {
                    const int32_t x0 =
                        frequency(imageByte(image, layout.binsOffset + low));
                    const int32_t x1 =
                        frequency(imageByte(image, layout.binsOffset + high));
                    const int32_t y1 =
                        imageByte(image, layout.powerOffset +
                                             (high * layout.rates) + rate);
                    // Preserve ath9k interpolate(): signed division truncates
                    // toward zero; factor/2 + factor%2 handles positive and
                    // negative slopes.
                    const int32_t factor = 2 * (y1 - y0) *
                                           (static_cast<int32_t>(mhz) - x0) /
                                           (x1 - x0);
                    value += (factor / 2) + (factor % 2);
                }
                if (value < 0 || value > kMaximumHalfDbm)
                {
                    return PowerResult::InvalidCurve;
                }
                at(out, rate) = static_cast<uint8_t>(value);
            }
            return PowerResult::Ok;
        }

        PowerResult edgeLimit(const EepromImage &image,
                              const CtlEdgeQuery &query, uint8_t &out)
        {
            uint8_t bins[kCtlEdgesPerEntry] {};
            uint8_t edges[kCtlEdgesPerEntry] {};
            for (size_t index = 0; index < kCtlEdgesPerEntry; ++index)
            {
                at(bins, index) = imageByte(
                    image,
                    kCtlBinOffset + (query.row * kCtlEdgesPerEntry) + index);
                at(edges, index) = imageByte(
                    image,
                    kCtlPowerOffset + (query.row * kCtlEdgesPerEntry) + index);
            }
            size_t count = 0;
            bool ended = false;
            for (size_t i = 0; i < kCtlEdgesPerEntry; ++i)
            {
                // Pinned ath9k AR9300 dictionaries contain both 0x00 and
                // 0xff trailing 2G CTL padding. Zero maps to 2300 MHz, not
                // a usable 2.4 GHz edge: treat it as a terminator only and
                // never allow a later nonempty edge to resume coverage.
                if (at(bins, i) == 0 || at(bins, i) == kMissingFrequencyBin)
                {
                    ended = true;
                    continue;
                }
                // Zero/0xff padding is handled above. All live CTL edges
                // must be in the 2.4 GHz bin range, not a different band.
                if (ended || at(bins, i) < kFirst2GhzBin ||
                    at(bins, i) > kLast2GhzBin ||
                    ((i != 0U) && at(bins, i) <= at(bins, i - 1)))
                {
                    return PowerResult::InvalidCtlEdges;
                }
                ++count;
            }
            if (count == 0U)
            {
                return PowerResult::MissingCtlCoverage;
            }
            for (size_t i = 0; i < count; ++i)
            {
                if (query.mhz == frequency(at(bins, i)))
                {
                    out = at(edges, i) & kCtlPowerMask;
                    return PowerResult::Ok;
                }
                if ((i != 0U) && query.mhz < frequency(at(bins, i)))
                {
                    if (query.mhz > frequency(at(bins, i - 1)) &&
                        (at(edges, i - 1) >> kCtlInbandShift) != 0)
                    {
                        out = at(edges, i - 1) & kCtlPowerMask;
                        return PowerResult::Ok;
                    }
                    break;
                }
            }
            // Upstream can return MAX_RATE_POWER when there is no covered edge
            // and upgrades a 0 edge result to 60 on 2 GHz. Neither is
            // permission here. Require actual coverage and preserve an explicit
            // zero cap as zero.
            return PowerResult::MissingCtlCoverage;
        }

        PowerResult ctlLimit(const EepromImage &image, const CtlQuery &query,
                             uint8_t &out)
        {
            // Validate the entire fixed-size index table even if an early
            // matching row would be sufficient. A nonzero row after the first
            // zero sentinel indicates malformed NVM, not ignorable padding.
            bool terminated = false;
            for (size_t row = 0; row < kCtlEntries; ++row)
            {
                if (imageByte(image, kCtlIndexOffset + row) == 0)
                {
                    terminated = true;
                }
                else if (terminated)
                {
                    return PowerResult::InvalidCtlIndexes;
                }
            }
            bool found = false;
            uint8_t selected = kMaximumHalfDbm;
            for (size_t row = 0;
                 row < kCtlEntries &&
                 (imageByte(image, kCtlIndexOffset + row) != 0U);
                 ++row)
            {
                const uint8_t index = imageByte(image, kCtlIndexOffset + row);
                if ((index & kCtlModeMask) != query.mode ||
                    (query.group != kCtlAllGroups &&
                     (index & kCtlGroupMask) != query.group))
                {
                    continue;
                }
                uint8_t limit = 0;
                const PowerResult result =
                    edgeLimit(image, {row, query.mhz}, limit);
                if (result != PowerResult::Ok)
                {
                    return result;
                }
                found = true;
                selected = minimum(selected, limit);
                if (query.group != kCtlAllGroups)
                {
                    break; // Same first-specific-entry order as ath9k.
                }
            }
            if (!found)
            {
                return PowerResult::MissingCtl;
            }
            out = selected;
            return PowerResult::Ok;
        }

        template <size_t N>
        PowerResult clamp(const EepromImage &image, const CtlQuery &query,
                          uint8_t ceiling, uint8_t (&powers)[N])
        {
            uint8_t edge = 0;
            const PowerResult result = ctlLimit(image, query, edge);
            if (result != PowerResult::Ok)
            {
                return result;
            }
            const uint8_t cap = minimum(edge, ceiling);
            for (size_t rate = 0; rate < N; ++rate)
            {
                at(powers, rate) = minimum(at(powers, rate), cap);
            }
            return PowerResult::Ok;
        }

        PowerResult limitCandidateTables(const EepromImage &image,
                                         const PowerCeilings &ceilings,
                                         PowerCandidates &candidate,
                                         uint8_t cap)
        {
            PowerResult result = targets(image, kCckTargets,
                                         candidate.controlMhz, candidate.cck);
            if (result == PowerResult::Ok)
            {
                result = clamp(
                    image, {ceilings.ctlGroup, kCckMode, candidate.controlMhz},
                    cap, candidate.cck);
            }
            if (result != PowerResult::Ok)
            {
                return result;
            }
            if (!candidate.legacyOnlyChannel14)
            {
                result = targets(image, kOfdmTargets, candidate.controlMhz,
                                 candidate.ofdm);
                if (result == PowerResult::Ok)
                {
                    result = clamp(
                        image,
                        {ceilings.ctlGroup, kOfdmMode, candidate.controlMhz},
                        cap, candidate.ofdm);
                }
                if (result != PowerResult::Ok)
                {
                    return result;
                }
            }
            if (candidate.ht20Present)
            {
                result = targets(image, kHt20Targets, candidate.controlMhz,
                                 candidate.ht20);
                if (result == PowerResult::Ok)
                {
                    result = clamp(
                        image,
                        {ceilings.ctlGroup, kHt20Mode, candidate.controlMhz},
                        cap, candidate.ht20);
                }
                if (result != PowerResult::Ok)
                {
                    return result;
                }
            }
            if (candidate.ht40Present)
            {
                // ath9k interpolates HT40 targets at control frequency, but
                // looks up its CTL at synth center. Do not collapse these into
                // one frequency.
                result = targets(image, kHt40Targets, candidate.controlMhz,
                                 candidate.ht40);
                if (result == PowerResult::Ok)
                {
                    result = clamp(
                        image,
                        {ceilings.ctlGroup, kHt40Mode, candidate.synthMhz}, cap,
                        candidate.ht40);
                }
                if (result != PowerResult::Ok)
                {
                    return result;
                }
            }
            return PowerResult::Ok;
        }

        PowerResult validateCandidateGeometry(const PowerCandidates &candidate,
                                              bool ht40)
        {
            // Require a populated, geometrically valid candidate, not a default
            // object.
            const bool channel14 = candidate.controlMhz == kCckOnlyChannelMhz;
            if ((!channel14 &&
                 (candidate.controlMhz < kFirstChannelMhz ||
                  candidate.controlMhz > kLastRegularChannelMhz ||
                  (candidate.controlMhz - kChannelRasterOffsetMhz) %
                          kChannelRasterSpacingMhz !=
                      0)) ||
                candidate.legacyOnlyChannel14 != channel14)
            {
                return PowerResult::InvalidChannel;
            }
            // This selector is public: callers can supply arbitrary candidate
            // structs. A set HT40 flag is not proof of a valid extension
            // channel. Check the geometry that calculatePowerCandidates would
            // produce.
            if (candidate.conductedCeilingHalfDbm > kMaximumHalfDbm ||
                (channel14 && candidate.ht20Present))
            {
                return PowerResult::InvalidCurve;
            }
            if (candidate.ht40Present)
            {
                const int32_t delta =
                    static_cast<int32_t>(candidate.extensionMhz) -
                    static_cast<int32_t>(candidate.controlMhz);
                if (!candidate.ht20Present || channel14 ||
                    candidate.extensionMhz < kFirstChannelMhz ||
                    candidate.extensionMhz > kLastRegularChannelMhz ||
                    (candidate.extensionMhz - kChannelRasterOffsetMhz) %
                            kChannelRasterSpacingMhz !=
                        0 ||
                    (delta != kHt40OffsetMhz && delta != -kHt40OffsetMhz) ||
                    candidate.synthMhz !=
                        (candidate.controlMhz + candidate.extensionMhz) / 2U)
                {
                    return PowerResult::InvalidChannel;
                }
            }
            else if (candidate.extensionMhz != 0 ||
                     candidate.synthMhz != candidate.controlMhz)
            {
                return PowerResult::InvalidChannel;
            }
            if (ht40 && !candidate.ht40Present)
            {
                return PowerResult::InvalidChannel;
            }
            return PowerResult::Ok;
        }

        PowerResult selectLegacyRatePower(const PowerCandidates &candidate,
                                          uint8_t rateCode, uint8_t &selected)
        {
            switch (rateCode)
            {
                case kRateCckOne:      // 1 Mbps, long preamble.
                case kRateCckTwoLong:  // 2 Mbps, long preamble.
                case kRateCckTwoShort: // 2 Mbps, short preamble.
                    selected = candidate.cck[0];
                    break;
                case kRateCckFiveLong:  // 5.5 Mbps, long preamble.
                case kRateCckFiveShort: // 5.5 Mbps, short preamble.
                    // ath9k ar9003_hw_init_txpower_cck applies the lower
                    // 1L_5L/5S target to both 5.5-Mbps preambles.
                    selected = minimum(candidate.cck[0], candidate.cck[1]);
                    break;
                case kRateCckElevenLong:  // 11 Mbps, long preamble.
                case kRateCckElevenShort: // 11 Mbps, short preamble.
                    // The PHY also uses the lower 11L/11S target for both.
                    selected = minimum(candidate.cck[2], candidate.cck[3]);
                    break;
                default:
                    if (candidate.legacyOnlyChannel14)
                    {
                        return PowerResult::UnsupportedRate;
                    }
                    switch (rateCode)
                    {
                        case kRateOfdmSix:
                        case kRateOfdmNine:
                        case kRateOfdmTwelve:
                        case kRateOfdmEighteen:
                        case kRateOfdmTwentyFour:
                            selected = candidate.ofdm[0];
                            break;
                        case kRateOfdmThirtySix:
                            selected = candidate.ofdm[1];
                            break;
                        case kRateOfdmFortyEight:
                            selected = candidate.ofdm[2];
                            break;
                        case kRateOfdmFiftyFour:
                            selected = candidate.ofdm[3];
                            break;
                        default:
                            return PowerResult::UnsupportedRate;
                    }
            }
            return PowerResult::Ok;
        }

    } // namespace

    PowerResult calculatePowerCandidates(const EepromImage &image,
                                         const PowerChannel &channel,
                                         const PowerCeilings &ceilings,
                                         PowerCandidates &out)
    {
        // Do not overwrite a source image, channel or ceiling through a
        // malformed caller-owned output alias before validating the inputs.
        if (overlaps(&out, sizeof(out), &image, sizeof(image)) ||
            overlaps(&out, sizeof(out), &channel, sizeof(channel)) ||
            overlaps(&out, sizeof(out), &ceilings, sizeof(ceilings)))
        {
            return PowerResult::InvalidArgument;
        }
        out = {};
        BoardDataSummary board {};
        if (summarizeBoardData(image, board) != EepromResult::Ok)
        {
            return PowerResult::InvalidBoard;
        }
        // Use the same structural identity, calibration-pier and supported
        // gain-index gate as discovery's gain selection. Otherwise a caller
        // can compute plausible power limits from the pinned generic template
        // MAC (or another board discovery would have rejected). This does not
        // establish a real board, calibration, regulatory or TX authority.
        TxGainProfile txGain = TxGainProfile::Unknown;
        RxGainProfile rxGain = RxGainProfile::Unknown;
        if (selectBoardGainProfiles(board, txGain, rxGain) != EepromResult::Ok)
        {
            return PowerResult::InvalidBoard;
        }
        if (((ceilings.ctlGroup & kCtlModeMask) != 0U) ||
            ceilings.ctlGroup == kCtlInvalidGroup)
        {
            return PowerResult::InvalidCtlGroup;
        }
        Channel primary {};
        Channel secondary {};
        if (mapChannel(channel.primary, primary) != Result::Ok)
        {
            return PowerResult::InvalidChannel;
        }
        PowerCandidates candidate {};
        candidate.controlMhz = primary.centerMhz;
        candidate.synthMhz = primary.centerMhz;
        candidate.legacyOnlyChannel14 = channel.primary == kCckOnlyChannel;
        if (calculateBoardCalibration2G(board, candidate.controlMhz,
                                        candidate.channelCalibration) !=
            EepromResult::Ok)
        {
            return PowerResult::InvalidBoard;
        }
        candidate.ht20Present = !candidate.legacyOnlyChannel14 &&
                                ((board.operationFlags & kHt20Disabled) == 0U);
        if (channel.secondary != 0U)
        {
            if (channel.primary == kCckOnlyChannel ||
                channel.secondary == kCckOnlyChannel ||
                !candidate.ht20Present ||
                ((board.operationFlags & kHt40Disabled) != 0U) ||
                mapChannel(channel.secondary, secondary) != Result::Ok)
            {
                return PowerResult::InvalidChannel;
            }
            const int32_t difference =
                static_cast<int32_t>(secondary.centerMhz) - primary.centerMhz;
            if (difference != kHt40OffsetMhz && difference != -kHt40OffsetMhz)
            {
                return PowerResult::InvalidChannel;
            }
            candidate.extensionMhz = secondary.centerMhz;
            candidate.synthMhz = static_cast<uint16_t>(
                (primary.centerMhz + secondary.centerMhz) / 2);
            candidate.ht40Present = true;
        }
        // Never increase conducted power because a raw EEPROM gain is negative.
        // Zero half-dBm is NOT an RF mute; a negative cap has no
        // representation.
        const int32_t gainHalfDbi =
            board.antennaGainDb > 0 ? 2 * board.antennaGainDb : 0;
        const int32_t eirpConducted =
            static_cast<int32_t>(ceilings.eirpHalfDbm) - gainHalfDbi;
        int32_t cap = ceilings.conductedHalfDbm < eirpConducted
                          ? ceilings.conductedHalfDbm
                          : eirpConducted;
        if (cap < 0)
        {
            return PowerResult::UnsupportedPowerLimit;
        }
        cap = cap < kMaximumHalfDbm ? cap : kMaximumHalfDbm;
        candidate.conductedCeilingHalfDbm = static_cast<uint8_t>(cap);
        const PowerResult result = limitCandidateTables(
            image, ceilings, candidate, static_cast<uint8_t>(cap));
        if (result != PowerResult::Ok)
        {
            return result;
        }
        out = candidate;
        return PowerResult::Ok;
    }

    PowerResult candidatePowerForRate(const PowerCandidates &candidate,
                                      uint8_t rateCode, bool ht40,
                                      uint8_t &halfDbm)
    {
        if (overlaps(&halfDbm, sizeof(halfDbm), &candidate, sizeof(candidate)))
        {
            return PowerResult::InvalidArgument;
        }
        halfDbm = 0;
        const PowerResult geometry = validateCandidateGeometry(candidate, ht40);
        if (geometry != PowerResult::Ok)
        {
            return geometry;
        }
        uint8_t selected = 0;
        if (rateCode >= kMcsFirstCode && rateCode <= kMcsLastCode &&
            !candidate.legacyOnlyChannel14)
        {
            if (!ht40 && !candidate.ht20Present)
            {
                return PowerResult::UnsupportedRate;
            }
            const uint8_t mcs = rateCode & 7U;
            size_t index = 0;
            if (mcs <= 3U)
            {
                index = (mcs != 0U) ? 1U : 0U;
            }
            else
            {
                index = static_cast<size_t>(mcs - 2U);
            }
            selected =
                ht40 ? at(candidate.ht40, index) : at(candidate.ht20, index);
            if (selected > kMaximumHalfDbm ||
                selected > candidate.conductedCeilingHalfDbm)
            {
                return PowerResult::InvalidCurve;
            }
            halfDbm = selected;
            return PowerResult::Ok;
        }
        if (ht40)
        {
            return PowerResult::UnsupportedRate;
        }
        const PowerResult legacy =
            selectLegacyRatePower(candidate, rateCode, selected);
        if (legacy != PowerResult::Ok)
        {
            return legacy;
        }
        if (selected > kMaximumHalfDbm ||
            selected > candidate.conductedCeilingHalfDbm)
        {
            return PowerResult::InvalidCurve;
        }
        halfDbm = selected;
        return PowerResult::Ok;
    }

} // namespace simpleath
