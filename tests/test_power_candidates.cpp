// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Alberto Villa Osorno.
// Synthetic half-dBm EEPROM target selection, NOT a hardware TX power index.
#include "hardware/Ar9565Eeprom.hpp"
#include "hardware/Ar9565Power.hpp"
#include <cstddef>
#include <cstdint>

using namespace simpleath;

int main()
{
    PowerCandidates candidate {};
    candidate.controlMhz = 2412;
    candidate.synthMhz = 2412;
    candidate.conductedCeilingHalfDbm = 30;
    candidate.ht20Present = true;
    candidate.cck[0] = 25;
    candidate.ofdm[0] = 18;
    candidate.ht20[0] = 15;
    uint8_t halfDbm = 0xff;
    if (candidatePowerForRate(candidate, 0x1b, false, halfDbm) !=
            PowerResult::Ok ||
        halfDbm != 25 ||
        candidatePowerForRate(candidate, 0x0b, false, halfDbm) !=
            PowerResult::Ok ||
        halfDbm != 18 ||
        candidatePowerForRate(candidate, 0x80, false, halfDbm) !=
            PowerResult::Ok ||
        halfDbm != 15)
    {
        return 1;
    }

    halfDbm = 0xff;
    if (candidatePowerForRate(candidate, 0x88, false, halfDbm) !=
            PowerResult::UnsupportedRate ||
        halfDbm != 0 ||
        candidatePowerForRate(candidate, 0x80, true, halfDbm) !=
            PowerResult::InvalidChannel ||
        halfDbm != 0)
    {
        return 2;
    }
    // ath9k uses the lower of 1L_5L / 5S for *both* 5.5-Mbps
    // preambles, and the lower of 11L / 11S for *both* 11-Mbps
    // preambles. A public rate selector must not return a higher raw
    // per-preamble EEPROM target than the PHY actually permits.
    candidate.cck[1] = 17;
    candidate.cck[2] = 19;
    candidate.cck[3] = 27;
    const uint8_t cck55Rates[] {0x19, 0x1d};
    const uint8_t cck11Rates[] {0x18, 0x1c};
    for (uint8_t rate : cck55Rates)
    {
        if (candidatePowerForRate(candidate, rate, false, halfDbm) !=
                PowerResult::Ok ||
            halfDbm != 17)
        {
            return 24;
        }
    }
    for (uint8_t rate : cck11Rates)
    {
        if (candidatePowerForRate(candidate, rate, false, halfDbm) !=
                PowerResult::Ok ||
            halfDbm != 19)
        {
            return 25;
        }
    }
    // Reverse the asymmetric target pairs to test the other minimum
    // direction, while 1/2-Mbps rates still use the original group.
    candidate.cck[0] = 15;
    candidate.cck[1] = 29;
    candidate.cck[2] = 26;
    candidate.cck[3] = 12;
    for (uint8_t rate : cck55Rates)
    {
        if (candidatePowerForRate(candidate, rate, false, halfDbm) !=
                PowerResult::Ok ||
            halfDbm != 15)
        {
            return 26;
        }
    }
    for (uint8_t rate : cck11Rates)
    {
        if (candidatePowerForRate(candidate, rate, false, halfDbm) !=
                PowerResult::Ok ||
            halfDbm != 12)
        {
            return 27;
        }
    }
    const uint8_t cck12Rates[] {0x1b, 0x1a, 0x1e};
    for (uint8_t rate : cck12Rates)
    {
        if (candidatePowerForRate(candidate, rate, false, halfDbm) !=
                PowerResult::Ok ||
            halfDbm != 15)
        {
            return 28;
        }
    }
    candidate.cck[0] = 25;

    candidate.ht20[0] = 31;
    halfDbm = 0xff;
    if (candidatePowerForRate(candidate, 0x80, false, halfDbm) !=
            PowerResult::InvalidCurve ||
        halfDbm != 0)
    {
        return 3;
    }
    candidate.ht20[0] = 15;
    candidate.controlMhz = 2413; // Invalid 2.4 GHz raster.
    if (candidatePowerForRate(candidate, 0x0b, false, halfDbm) !=
            PowerResult::InvalidChannel ||
        halfDbm != 0)
    {
        return 4;
    }

    candidate.controlMhz = 2484;
    candidate.synthMhz = 2484;
    candidate.legacyOnlyChannel14 = true;
    candidate.ht20Present = false;
    if (candidatePowerForRate(candidate, 0x1b, false, halfDbm) !=
            PowerResult::Ok ||
        halfDbm != 25 ||
        candidatePowerForRate(candidate, 0x0b, false, halfDbm) !=
            PowerResult::UnsupportedRate ||
        halfDbm != 0 ||
        candidatePowerForRate(candidate, 0x80, false, halfDbm) !=
            PowerResult::UnsupportedRate ||
        halfDbm != 0)
    {
        return 5;
    }
    candidate.ht20Present = true; // HT on channel 14 is contradictory.
    if (candidatePowerForRate(candidate, 0x1b, false, halfDbm) !=
            PowerResult::InvalidCurve ||
        halfDbm != 0)
    {
        return 6;
    }

    candidate.legacyOnlyChannel14 = false;
    candidate.controlMhz = 2412;
    candidate.extensionMhz = 2432;
    candidate.synthMhz = 2422;
    candidate.ht20Present = true;
    candidate.ht40Present = true;
    candidate.ht40[0] = 19;
    if (candidatePowerForRate(candidate, 0x80, true, halfDbm) !=
            PowerResult::Ok ||
        halfDbm != 19 ||
        candidatePowerForRate(candidate, 0x80, false, halfDbm) !=
            PowerResult::Ok ||
        halfDbm != 15)
    {
        return 7;
    }
    candidate.extensionMhz = 2442; // Wrong 30 MHz channel displacement.
    if (candidatePowerForRate(candidate, 0x80, true, halfDbm) !=
            PowerResult::InvalidChannel ||
        halfDbm != 0)
    {
        return 8;
    }
    candidate.extensionMhz = 2432;
    candidate.synthMhz = 2427; // Contradictory synth center.
    if (candidatePowerForRate(candidate, 0x80, true, halfDbm) !=
            PowerResult::InvalidChannel ||
        halfDbm != 0)
    {
        return 9;
    }
    candidate.synthMhz = 2422;
    candidate.ht40[0] = 31; // Above candidate conducted budget.
    if (candidatePowerForRate(candidate, 0x80, true, halfDbm) !=
            PowerResult::InvalidCurve ||
        halfDbm != 0)
    {
        return 10;
    }

    // An unknown EEPROM image must not leave a stale usable power candidate.
    EepromImage image {};
    PowerCandidates output {};
    output.controlMhz = 2412;
    output.cck[0] = 30;
    PowerChannel channel {1, 0};
    PowerCeilings ceiling {0xe0, 30, 30};
    if (calculatePowerCandidates(image, channel, ceiling, output) !=
            PowerResult::InvalidBoard ||
        (output.controlMhz != 0U) || (output.cck[0] != 0U) ||
        output.ht20Present || (output.conductedCeilingHalfDbm != 0U))
    {
        return 11;
    }

    // Pinned ath9k AR9300 dictionaries carry trailing zero in some 2 GHz
    // CTL edge rows (and 0xff in others). Both are *padding*, not new
    // coverage; construct a synthetic board with explicit, in-range edges.
    image.restored = true;
    image.appliedBlocks = 1;
    image.bytes[0] = 2;
    image.bytes[2] = 0x02;
    image.bytes[3] = 0x11;
    image.bytes[4] = 0x22;
    image.bytes[5] = 0x33;
    image.bytes[6] = 0x44;
    image.bytes[7] = 0x55;
    image.bytes[32] = 0x11;
    image.bytes[33] = 0x22; // 2 GHz, with HT target lookup disabled.
    // A reconstructed AR9565 board has three structurally ordered 2G
    // calibration piers even when this test only evaluates target limits.
    image.bytes[138] = 112;
    image.bytes[139] = 137;
    image.bytes[140] = 162;
    // Synthetic open-loop chain0 measurements; not actual device calibration.
    image.bytes[141] = 0xf8; // -8 correction.
    image.bytes[142] = 100;
    image.bytes[143] = 40;
    image.bytes[147] = 16;
    image.bytes[148] = 120;
    image.bytes[149] = 50;
    image.bytes[153] = 24;
    image.bytes[154] = 140;
    image.bytes[155] = 60;
    image.bytes[195] = image.bytes[197] = 112;
    image.bytes[196] = image.bytes[198] = 137;
    image.bytes[199] = 162;
    for (size_t i = 206; i < 226; ++i)
    {
        image.bytes[i] = 24;
    }
    image.bytes[310] = 0xe1; // CCK CTL.
    image.bytes[311] = 0xe2; // OFDM CTL.
    for (size_t row = 0; row < 2; ++row)
    {
        image.bytes[322 + (row * 4)] = 112;
        image.bytes[323 + (row * 4)] = 137;
        image.bytes[324 + (row * 4)] = 162;
        image.bytes[325 + (row * 4)] = (row != 0U) ? 0xff : 0;
        for (size_t edge = 0; edge < 4; ++edge)
        {
            image.bytes[370 + (row * 4) + edge] = 26;
        }
    }
    if (calculatePowerCandidates(image, channel, ceiling, output) !=
            PowerResult::Ok ||
        output.controlMhz != 2412 || output.cck[0] != 24 ||
        output.ofdm[0] != 24 || output.ht20Present || output.ht40Present ||
        output.conductedCeilingHalfDbm != 30 ||
        output.channelCalibration.channelMhz != 2412 ||
        output.channelCalibration.referenceCorrection != -8 ||
        output.channelCalibration.voltageMeasurement != 100 ||
        output.channelCalibration.temperatureMeasurement != 40 ||
        output.channelCalibration.interpolated)
    {
        return 12;
    }

    // Zero cannot be an interior bin followed by later live edges; a row
    // with only padding cannot grant CTL coverage at any frequency.
    image.bytes[323] = 0;
    output.cck[0] = 31;
    if (calculatePowerCandidates(image, channel, ceiling, output) !=
            PowerResult::InvalidCtlEdges ||
        (output.controlMhz != 0U) || (output.cck[0] != 0U))
    {
        return 13;
    }
    image.bytes[322] = 0;
    image.bytes[324] = 0;
    if (calculatePowerCandidates(image, channel, ceiling, output) !=
            PowerResult::MissingCtlCoverage ||
        (output.controlMhz != 0U) || (output.cck[0] != 0U))
    {
        return 14;
    }

    // An out-of-band target bin is not a usable 2.4 GHz interpolation pier.
    // Restore valid CTL rows so the failure is specifically the target curve.
    image.bytes[322] = 112;
    image.bytes[323] = 137;
    image.bytes[324] = 162;
    image.bytes[195] = 100; // 2400 MHz, not a 2.4 GHz channel center.
    output.cck[0] = 31;
    if (calculatePowerCandidates(image, channel, ceiling, output) !=
            PowerResult::InvalidCurve ||
        (output.controlMhz != 0U) || (output.cck[0] != 0U))
    {
        return 15;
    }
    image.bytes[195] = 112;

    // Out-of-band live CTL bins cannot silently authorize a 2.4 GHz channel.
    image.bytes[322] = 185;
    output.cck[0] = 31;
    if (calculatePowerCandidates(image, channel, ceiling, output) !=
            PowerResult::InvalidCtlEdges ||
        (output.controlMhz != 0U) || (output.cck[0] != 0U))
    {
        return 16;
    }
    image.bytes[322] = 112;
    image.bytes[323] = 100;
    output.cck[0] = 31;
    if (calculatePowerCandidates(image, channel, ceiling, output) !=
            PowerResult::InvalidCtlEdges ||
        (output.controlMhz != 0U) || (output.cck[0] != 0U))
    {
        return 17;
    }

    // A later live CTL index after a zero sentinel must fail even when the
    // first two rows cover this request; the rest cannot be ignored.
    image.bytes[323] = 137;
    image.bytes[313] = 0xe1; // Index 312 remains zero (table terminator).
    output.cck[0] = 31;
    if (calculatePowerCandidates(image, channel, ceiling, output) !=
            PowerResult::InvalidCtlIndexes ||
        (output.controlMhz != 0U) || (output.cck[0] != 0U))
    {
        return 18;
    }
    image.bytes[313] = 0; // Legitimate trailing zero padding again.
    if (calculatePowerCandidates(image, channel, ceiling, output) !=
            PowerResult::Ok ||
        output.cck[0] != 24 || output.ofdm[0] != 24)
    {
        return 19;
    }

    // The board summary can be decoded with corrupted calibration-pier bins,
    // but discovery would refuse to publish it as a selected board. The
    // direct power candidate API must also reject that inconsistent geometry
    // rather than return seemingly usable half-dBm limits.
    image.bytes[140] = 137; // Duplicate of the second calibration pier.
    output.cck[0] = 31;
    if (calculatePowerCandidates(image, channel, ceiling, output) !=
            PowerResult::InvalidBoard ||
        (output.controlMhz != 0U) || (output.cck[0] != 0U) ||
        (output.ofdm[0] != 0U) || (output.conductedCeilingHalfDbm != 0U))
    {
        return 20;
    }
    image.bytes[140] = 162;
    if (calculatePowerCandidates(image, channel, ceiling, output) !=
            PowerResult::Ok ||
        output.cck[0] != 24 || output.ofdm[0] != 24)
    {
        return 21;
    }

    // A reconstruction dictionary's built-in placeholder MAC passes the
    // elementary unicast check, but is not a physical board's identity.
    // The direct numerical planner cannot bypass the gain selector's
    // pinned-template exclusion even when targets/CTL/piers look plausible.
    const uint8_t originalMac[6] {
        image.bytes[2], image.bytes[3], image.bytes[4],
        image.bytes[5], image.bytes[6], image.bytes[7],
    };
    const uint8_t referenceMac[6] {0x00, 0x02, 0x03, 0x04, 0x05, 0x06};
    for (size_t i = 0; i < 6; ++i)
    {
        image.bytes[i + 2] = referenceMac[i];
    }
    output.cck[0] = 31;
    if (calculatePowerCandidates(image, channel, ceiling, output) !=
            PowerResult::InvalidBoard ||
        (output.controlMhz != 0U) || (output.cck[0] != 0U) ||
        (output.ofdm[0] != 0U) || (output.conductedCeilingHalfDbm != 0U))
    {
        return 22;
    }
    for (size_t i = 0; i < 6; ++i)
    {
        image.bytes[i + 2] = originalMac[i];
    }
    if (calculatePowerCandidates(image, channel, ceiling, output) !=
            PowerResult::Ok ||
        output.cck[0] != 24 || output.ofdm[0] != 24)
    {
        return 23;
    }
    // The same plan carries the calibration piers selected for the actual
    // control channel, not an arbitrary stale source or HT40 synth center.
    channel.primary = 6;
    if (calculatePowerCandidates(image, channel, ceiling, output) !=
            PowerResult::Ok ||
        output.controlMhz != 2437 ||
        output.channelCalibration.channelMhz != 2437 ||
        output.channelCalibration.lowerPierMhz != 2437 ||
        output.channelCalibration.upperPierMhz != 2437 ||
        output.channelCalibration.referenceCorrection != 16 ||
        output.channelCalibration.voltageMeasurement != 120 ||
        output.channelCalibration.temperatureMeasurement != 50 ||
        output.channelCalibration.interpolated)
    {
        return 30;
    }
    return 0;
}
