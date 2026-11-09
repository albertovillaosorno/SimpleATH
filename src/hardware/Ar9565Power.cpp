// SPDX-License-Identifier: AGPL-3.0-only
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

namespace simpleath
{
    namespace
    {
        // Difference-based overlap checks avoid pointer-end overflow.
        bool overlaps(const void *a, size_t aBytes, const void *b,
                      size_t bBytes)
        {
            const auto first = reinterpret_cast<uintptr_t>(a);
            const auto second = reinterpret_cast<uintptr_t>(b);
            return first <= second ? second - first < aBytes
                                   : first - second < bBytes;
        }

        uint8_t minimum(uint8_t a, uint8_t b)
        {
            return a < b ? a : b;
        }

        uint16_t frequency(uint8_t bin)
        {
            return static_cast<uint16_t>(2300u + bin);
        }

        // Layout offsets come from packed ar9300_eeprom, not a native structure
        // cast.
        PowerResult targets(const uint8_t *bytes, size_t binsOffset,
                            size_t powerOffset, size_t maximumPiers,
                            size_t rates, uint16_t mhz, uint8_t *out)
        {
            size_t count = 0;
            bool ended = false;
            for (size_t pier = 0; pier < maximumPiers; ++pier)
            {
                const uint8_t bin = bytes[binsOffset + pier];
                if (bin == 0xff)
                {
                    ended = true;
                    continue;
                }
                // Target piers must be actual 2.4 GHz frequencies. A
                // malformed 5 GHz or zero bin must not become an implicit
                // extrapolation endpoint for a 2.4 GHz power budget.
                if (ended || bin < 112 || bin > 184 ||
                    (pier && bin <= bytes[binsOffset + pier - 1]))
                    return PowerResult::InvalidCurve;
                for (size_t rate = 0; rate < rates; ++rate)
                    if (bytes[powerOffset + pier * rates + rate] > 63)
                        return PowerResult::InvalidCurve;
                ++count;
            }
            if (!count)
                return PowerResult::InvalidCurve;
            size_t low = 0, high = 0;
            if (mhz >= frequency(bytes[binsOffset + count - 1]))
            {
                low = high = count - 1;
            }
            else if (mhz > frequency(bytes[binsOffset]))
            {
                for (high = 1; high < count; ++high)
                    if (mhz <= frequency(bytes[binsOffset + high]))
                        break;
                low = high - 1;
            }
            for (size_t rate = 0; rate < rates; ++rate)
            {
                const int32_t y0 = bytes[powerOffset + low * rates + rate];
                int32_t value = y0;
                if (high != low)
                {
                    const int32_t x0 = frequency(bytes[binsOffset + low]);
                    const int32_t x1 = frequency(bytes[binsOffset + high]);
                    const int32_t y1 = bytes[powerOffset + high * rates + rate];
                    // Preserve ath9k interpolate(): signed division truncates
                    // toward zero; factor/2 + factor%2 handles positive and
                    // negative slopes.
                    const int32_t factor = 2 * (y1 - y0) *
                                           (static_cast<int32_t>(mhz) - x0) /
                                           (x1 - x0);
                    value += factor / 2 + factor % 2;
                }
                if (value < 0 || value > 63)
                    return PowerResult::InvalidCurve;
                out[rate] = static_cast<uint8_t>(value);
            }
            return PowerResult::Ok;
        }

        PowerResult edgeLimit(const uint8_t *bytes, size_t row, uint16_t mhz,
                              uint8_t &out)
        {
            const uint8_t *bins = bytes + 322 + row * 4;
            const uint8_t *edges = bytes + 370 + row * 4;
            size_t count = 0;
            bool ended = false;
            for (size_t i = 0; i < 4; ++i)
            {
                // Pinned ath9k AR9300 dictionaries contain both 0x00 and
                // 0xff trailing 2G CTL padding. Zero maps to 2300 MHz, not
                // a usable 2.4 GHz edge: treat it as a terminator only and
                // never allow a later nonempty edge to resume coverage.
                if (bins[i] == 0 || bins[i] == 0xff)
                {
                    ended = true;
                    continue;
                }
                // Zero/0xff padding is handled above. All live CTL edges
                // must be in the 2.4 GHz bin range, not a different band.
                if (ended || bins[i] < 112 || bins[i] > 184 ||
                    (i && bins[i] <= bins[i - 1]))
                    return PowerResult::InvalidCtlEdges;
                ++count;
            }
            if (!count)
                return PowerResult::MissingCtlCoverage;
            for (size_t i = 0; i < count; ++i)
            {
                if (mhz == frequency(bins[i]))
                {
                    out = edges[i] & 0x3fu;
                    return PowerResult::Ok;
                }
                if (i && mhz < frequency(bins[i]))
                {
                    if (mhz > frequency(bins[i - 1]) &&
                        (edges[i - 1] >> 6) != 0)
                    {
                        out = edges[i - 1] & 0x3fu;
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

        PowerResult ctlLimit(const uint8_t *bytes, uint8_t group, uint8_t mode,
                             uint16_t mhz, uint8_t &out)
        {
            // Validate the entire fixed-size index table even if an early
            // matching row would be sufficient. A nonzero row after the first
            // zero sentinel indicates malformed NVM, not ignorable padding.
            bool terminated = false;
            for (size_t row = 0; row < 12; ++row)
            {
                if (bytes[310 + row] == 0)
                    terminated = true;
                else if (terminated)
                    return PowerResult::InvalidCtlIndexes;
            }
            bool found = false;
            uint8_t selected = 63;
            for (size_t row = 0; row < 12 && bytes[310 + row]; ++row)
            {
                const uint8_t index = bytes[310 + row];
                if ((index & 0x0fu) != mode ||
                    (group != 0xe0 && (index & 0xf0u) != group))
                    continue;
                uint8_t limit = 0;
                const PowerResult result = edgeLimit(bytes, row, mhz, limit);
                if (result != PowerResult::Ok)
                    return result;
                found = true;
                selected = minimum(selected, limit);
                if (group != 0xe0)
                    break; // Same first-specific-entry order as ath9k.
            }
            if (!found)
                return PowerResult::MissingCtl;
            out = selected;
            return PowerResult::Ok;
        }

        PowerResult clamp(const uint8_t *bytes, uint8_t group, uint8_t mode,
                          uint16_t mhz, uint8_t ceiling, uint8_t *powers,
                          size_t count)
        {
            uint8_t edge = 0;
            const PowerResult result = ctlLimit(bytes, group, mode, mhz, edge);
            if (result != PowerResult::Ok)
                return result;
            const uint8_t cap = minimum(edge, ceiling);
            for (size_t rate = 0; rate < count; ++rate)
                powers[rate] = minimum(powers[rate], cap);
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
            return PowerResult::InvalidArgument;
        out = {};
        BoardDataSummary board {};
        if (summarizeBoardData(image, board) != EepromResult::Ok ||
            !board.calibrationPierBinsPlausible)
            // Discovery and direct gain selection reject malformed 2G
            // calibration-pier geometry. A direct power calculation must not
            // bypass that structural board check and publish usable-looking
            // per-rate limits from a board discovery would have discarded.
            return PowerResult::InvalidBoard;
        if ((ceilings.ctlGroup & 0x0fu) || ceilings.ctlGroup == 0xf0)
            return PowerResult::InvalidCtlGroup;
        Channel primary {}, secondary {};
        if (mapChannel(channel.primary, primary) != Result::Ok)
            return PowerResult::InvalidChannel;
        PowerCandidates candidate {};
        candidate.controlMhz = primary.centerMhz;
        candidate.synthMhz = primary.centerMhz;
        candidate.legacyOnlyChannel14 = channel.primary == 14;
        candidate.ht20Present =
            !candidate.legacyOnlyChannel14 && !(board.operationFlags & 0x20u);
        if (channel.secondary)
        {
            if (channel.primary == 14 || channel.secondary == 14 ||
                !candidate.ht20Present || (board.operationFlags & 0x08u) ||
                mapChannel(channel.secondary, secondary) != Result::Ok)
                return PowerResult::InvalidChannel;
            const int32_t difference =
                static_cast<int32_t>(secondary.centerMhz) - primary.centerMhz;
            if (difference != 20 && difference != -20)
                return PowerResult::InvalidChannel;
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
            return PowerResult::UnsupportedPowerLimit;
        if (cap > 63)
            cap = 63;
        candidate.conductedCeilingHalfDbm = static_cast<uint8_t>(cap);
        const uint8_t *bytes = image.bytes;
        PowerResult result =
            targets(bytes, 195, 206, 2, 4, candidate.controlMhz, candidate.cck);
        if (result == PowerResult::Ok)
            result = clamp(bytes, ceilings.ctlGroup, 1, candidate.controlMhz,
                           static_cast<uint8_t>(cap), candidate.cck, 4);
        if (result != PowerResult::Ok)
            return result;
        if (!candidate.legacyOnlyChannel14)
        {
            result = targets(bytes, 197, 214, 3, 4, candidate.controlMhz,
                             candidate.ofdm);
            if (result == PowerResult::Ok)
                result =
                    clamp(bytes, ceilings.ctlGroup, 2, candidate.controlMhz,
                          static_cast<uint8_t>(cap), candidate.ofdm, 4);
            if (result != PowerResult::Ok)
                return result;
        }
        if (candidate.ht20Present)
        {
            result = targets(bytes, 200, 226, 3, 14, candidate.controlMhz,
                             candidate.ht20);
            if (result == PowerResult::Ok)
                result =
                    clamp(bytes, ceilings.ctlGroup, 5, candidate.controlMhz,
                          static_cast<uint8_t>(cap), candidate.ht20, 14);
            if (result != PowerResult::Ok)
                return result;
        }
        if (candidate.ht40Present)
        {
            // ath9k interpolates HT40 targets at control frequency, but looks
            // up its CTL at synth center. Do not collapse these into one
            // frequency.
            result = targets(bytes, 203, 268, 3, 14, candidate.controlMhz,
                             candidate.ht40);
            if (result == PowerResult::Ok)
                result = clamp(bytes, ceilings.ctlGroup, 7, candidate.synthMhz,
                               static_cast<uint8_t>(cap), candidate.ht40, 14);
            if (result != PowerResult::Ok)
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
            return PowerResult::InvalidArgument;
        halfDbm = 0;
        // Require a populated, geometrically valid candidate, not a default
        // object.
        const bool channel14 = candidate.controlMhz == 2484;
        if ((!channel14 &&
             (candidate.controlMhz < 2412 || candidate.controlMhz > 2472 ||
              (candidate.controlMhz - 2407) % 5 != 0)) ||
            candidate.legacyOnlyChannel14 != channel14)
            return PowerResult::InvalidChannel;
        // This selector is public: callers can supply arbitrary candidate
        // structs. A set HT40 flag is not proof of a valid extension channel.
        // Check the geometry that calculatePowerCandidates would produce.
        if (candidate.conductedCeilingHalfDbm > 63 ||
            (channel14 && candidate.ht20Present))
            return PowerResult::InvalidCurve;
        if (candidate.ht40Present)
        {
            const int32_t delta = static_cast<int32_t>(candidate.extensionMhz) -
                                  static_cast<int32_t>(candidate.controlMhz);
            if (!candidate.ht20Present || channel14 ||
                candidate.extensionMhz < 2412 ||
                candidate.extensionMhz > 2472 ||
                (candidate.extensionMhz - 2407u) % 5u != 0 ||
                (delta != 20 && delta != -20) ||
                candidate.synthMhz !=
                    (candidate.controlMhz + candidate.extensionMhz) / 2u)
                return PowerResult::InvalidChannel;
        }
        else if (candidate.extensionMhz != 0 ||
                 candidate.synthMhz != candidate.controlMhz)
        {
            return PowerResult::InvalidChannel;
        }
        if (ht40 && !candidate.ht40Present)
            return PowerResult::InvalidChannel;
        uint8_t selected = 0;
        if (rateCode >= 0x80 && rateCode <= 0x87 &&
            !candidate.legacyOnlyChannel14)
        {
            if (!ht40 && !candidate.ht20Present)
                return PowerResult::UnsupportedRate;
            const uint8_t mcs = rateCode & 7u;
            const size_t index = mcs <= 3 ? (mcs ? 1 : 0) : mcs - 2;
            selected = (ht40 ? candidate.ht40 : candidate.ht20)[index];
            if (selected > 63 || selected > candidate.conductedCeilingHalfDbm)
                return PowerResult::InvalidCurve;
            halfDbm = selected;
            return PowerResult::Ok;
        }
        if (ht40)
            return PowerResult::UnsupportedRate;
        switch (rateCode)
        {
            case 0x1b:
            case 0x1a:
            case 0x19:
            case 0x1e:
                selected = candidate.cck[0];
                break;
            case 0x1d:
                selected = candidate.cck[1];
                break;
            case 0x18:
                selected = candidate.cck[2];
                break;
            case 0x1c:
                selected = candidate.cck[3];
                break;
            default:
                if (candidate.legacyOnlyChannel14)
                    return PowerResult::UnsupportedRate;
                switch (rateCode)
                {
                    case 0x0b:
                    case 0x0f:
                    case 0x0a:
                    case 0x0e:
                    case 0x09:
                        selected = candidate.ofdm[0];
                        break;
                    case 0x0d:
                        selected = candidate.ofdm[1];
                        break;
                    case 0x08:
                        selected = candidate.ofdm[2];
                        break;
                    case 0x0c:
                        selected = candidate.ofdm[3];
                        break;
                    default:
                        return PowerResult::UnsupportedRate;
                }
        }
        if (selected > 63 || selected > candidate.conductedCeilingHalfDbm)
            return PowerResult::InvalidCurve;
        halfDbm = selected;
        return PowerResult::Ok;
    }

} // namespace simpleath
