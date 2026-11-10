#ifndef SIMPLEATH_AR9565_POWER_HPP
#define SIMPLEATH_AR9565_POWER_HPP

#include "Ar9565Eeprom.hpp"

namespace simpleath
{

    enum class PowerResult : uint8_t
    {
        Ok,
        InvalidBoard,
        InvalidChannel,
        InvalidCurve,
        InvalidCtlGroup,
        InvalidCtlEdges,
        MissingCtl,
        MissingCtlCoverage,
        UnsupportedPowerLimit,
        UnsupportedRate,
        InvalidArgument,
        InvalidCtlIndexes,
    };

    struct PowerChannel
    {
            uint8_t primary;
            // 0 for 20 MHz; HT40 requires a valid secondary exactly 20 MHz
            // away.
            uint8_t secondary;
    };

    // These values must eventually come from a verified board/country/OS
    // policy, covering BOTH subchannels and the occupied bandwidth. This
    // calculation does not establish that authority or infer it from a
    // locale/country string.
    struct PowerCeilings
    {
            uint8_t ctlGroup; // High nibble only. 0xe0 aggregates matching CTL
                              // modes.
            int16_t conductedHalfDbm;
            int16_t eirpHalfDbm;
    };

    // The ath9k 2-GHz MCS table has fourteen rate-power groups per width.
    constexpr size_t kHtTargetPowerGroups = 14;

    // Half-dBm EEPROM target values, not hardware descriptor power indexes.
    // No calibration, radio programming, MCI/PAPRD correction or TX permission
    // is established by this result. All final hardware conversion remains
    // gated.
    struct PowerCandidates
    {
            uint16_t controlMhz {};
            uint16_t extensionMhz {};
            uint16_t synthMhz {};
            uint8_t conductedCeilingHalfDbm {};
            // Source-side EEPROM measurements for this control channel. The
            // future TPC writer still must validate live board provenance,
            // correct temperature/voltage compensation and RF permissions.
            BoardChannelCalibration2G channelCalibration {};
            // Raw signed modal inputs; no TPC programming or TX authority.
            BoardTxModal2G txModal {};
            uint8_t cck[4] {};
            uint8_t ofdm[4] {};
            uint8_t ht20[kHtTargetPowerGroups] {};
            uint8_t ht40[kHtTargetPowerGroups] {};
            bool legacyOnlyChannel14 {};
            bool ht20Present {};
            bool ht40Present {};
    };

    // Interpolates EEPROM targets with ath9k's signed integer rounding, applies
    // explicit CTL edge coverage, and intersects caller ceilings and antenna
    // gain. Missing coverage is an error, never an implicit unrestricted power
    // budget. Output is zeroed on ordinary failure; an output overlapping an
    // input is rejected untouched with InvalidArgument. An Ok result is
    // arithmetic success only.
    PowerResult calculatePowerCandidates(const EepromImage &image,
                                         const PowerChannel &channel,
                                         const PowerCeilings &ceilings,
                                         PowerCandidates &out);

    // Select an AR9565 single-stream rate's candidate limit. Rejects unknown,
    // multi-stream or channel-14 non-CCK rates. Also rejects contradictory
    // HT40 center/extension geometry and power outside 0..63/its ceiling.
    // An output aliasing the candidate is rejected untouched. This is NOT an
    // index conversion for TxRate::powerIndex and does not populate
    // TxSafetyPolicy readiness flags.
    PowerResult candidatePowerForRate(const PowerCandidates &candidates,
                                      uint8_t rateCode, bool ht40,
                                      uint8_t &halfDbm);

} // namespace simpleath
#endif
