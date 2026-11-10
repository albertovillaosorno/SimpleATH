#ifndef SIMPLEATH_AR9565_OFDM_TIMING_HPP
#define SIMPLEATH_AR9565_OFDM_TIMING_HPP

#include "Ar9565Calibration.hpp"
#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    enum class OfdmTimingResult : uint8_t
    {
        Ok,
        InvalidBackend,
        InvalidChannel,
        MissingAuthorization,
        InvalidBar,
        OwnershipLost,
        ReadFailed,
        WriteFailed,
        ReadbackMismatch,
    };

    struct OfdmTimingProgress
    {
            OfdmTimingResult result;
            uint16_t synthesizerMhz;
            uint16_t normalMantissa;
            uint8_t normalExponent;
            uint16_t shortMantissa;
            uint8_t shortExponent;
            size_t completedReads;
            size_t completedWrites;
            uint32_t lastOffset;
            bool requiresReset;
    };

    // Programs the real AR9003 OFDM delta-slope and short guard-interval
    // coefficients (AR_PHY_TIMING3 and AR_PHY_SGI_DELTA) for an AR9565
    // full-rate 2.4-GHz HT20/HT40 channel. Based on Linux ath9k v6.12
    // ar9003_hw_set_delta_slope / ath9k_hw_get_delta_slope_vals. Channel
    // center is calculated from the 20-MHz pair, never from untrusted HT40
    // input. Does not authorize TX, RX, automatic responses or rates.
    //
    // Call after channel synthesizer setup with the RF bus released and
    // before enabling the PHY. The native owner must establish a live D0,
    // same-epoch BAR, quiesced MAC, permitted country/channel, RF-kill and
    // coexistence state for EVERY MMIO through permitWrite. Every posted
    // write ambiguity, owner loss or mismatched readback requires full reset.
    OfdmTimingProgress
    programAr9565OfdmTiming(const RfChannelRequest &request,
                            const CalibrationAndRegulatory &authorization,
                            const RxAgcBackend &backend);
} // namespace simpleath

#endif
