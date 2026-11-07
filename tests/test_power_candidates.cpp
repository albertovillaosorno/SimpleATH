// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Alberto Villa Osorno.
// Synthetic half-dBm EEPROM target selection, NOT a hardware TX power index.
#include "hardware/Ar9565Power.hpp"

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
        return 1;

    halfDbm = 0xff;
    if (candidatePowerForRate(candidate, 0x88, false, halfDbm) !=
            PowerResult::UnsupportedRate ||
        halfDbm != 0 ||
        candidatePowerForRate(candidate, 0x80, true, halfDbm) !=
            PowerResult::InvalidChannel ||
        halfDbm != 0)
        return 2;
    candidate.ht20[0] = 31;
    halfDbm = 0xff;
    if (candidatePowerForRate(candidate, 0x80, false, halfDbm) !=
            PowerResult::InvalidCurve ||
        halfDbm != 0)
        return 3;
    candidate.ht20[0] = 15;
    candidate.controlMhz = 2413; // Invalid 2.4 GHz raster.
    if (candidatePowerForRate(candidate, 0x0b, false, halfDbm) !=
            PowerResult::InvalidChannel ||
        halfDbm != 0)
        return 4;

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
        return 5;
    candidate.ht20Present = true; // HT on channel 14 is contradictory.
    if (candidatePowerForRate(candidate, 0x1b, false, halfDbm) !=
            PowerResult::InvalidCurve ||
        halfDbm != 0)
        return 6;

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
        return 7;
    candidate.extensionMhz = 2442; // Wrong 30 MHz channel displacement.
    if (candidatePowerForRate(candidate, 0x80, true, halfDbm) !=
            PowerResult::InvalidChannel ||
        halfDbm != 0)
        return 8;
    candidate.extensionMhz = 2432;
    candidate.synthMhz = 2427; // Contradictory synth center.
    if (candidatePowerForRate(candidate, 0x80, true, halfDbm) !=
            PowerResult::InvalidChannel ||
        halfDbm != 0)
        return 9;
    candidate.synthMhz = 2422;
    candidate.ht40[0] = 31; // Above candidate conducted budget.
    if (candidatePowerForRate(candidate, 0x80, true, halfDbm) !=
            PowerResult::InvalidCurve ||
        halfDbm != 0)
        return 10;

    // An unknown EEPROM image must not leave a stale usable power candidate.
    EepromImage image {};
    PowerCandidates output {};
    output.controlMhz = 2412;
    output.cck[0] = 30;
    PowerChannel channel {1, 0};
    PowerCeilings ceiling {0xe0, 30, 30};
    if (calculatePowerCandidates(image, channel, ceiling, output) !=
            PowerResult::InvalidBoard ||
        output.controlMhz || output.cck[0] || output.ht20Present ||
        output.conductedCeilingHalfDbm)
        return 11;
    return 0;
}
