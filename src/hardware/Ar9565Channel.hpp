#ifndef SIMPLEATH_AR9565_CHANNEL_HPP
#define SIMPLEATH_AR9565_CHANNEL_HPP

#include "Ar9565Core.hpp"
#include "Ar9565InitCatalog.hpp"
#include "Ar9565RfIni.hpp"
#include <cstddef>
#include <cstdint>

namespace simpleath
{
    enum class RfReferenceClock : uint8_t
    {
        Crystal25Mhz,
        Crystal40Mhz,
    };

    struct RfChannelRequest
    {
            Revision silicon;
            Channel control;
            ChannelWidth width;
            // Zero for HT20; the actual secondary 20 MHz channel for HT40.
            uint8_t secondary;
            // The owner must determine this from validated physical board
            // evidence. Never infer a crystal from the PCI device ID.
            RfReferenceClock referenceClock;
    };

    enum class RfChannelResult : uint8_t
    {
        Ok,
        InvalidBackend,
        InvalidChannel,
        InvalidBar,
        MissingAuthorization,
        OwnershipLost,
        ReadFailed,
        WriteFailed,
    };

    struct RfChannelBackend
    {
            // Shares the INI writer's live owner-epoch, serialized gate and
            // write contract. permitWrite must ALSO verify that analog RF bus
            // access is granted, TX/RX are quiesced and the clock is trusted.
            RfIniBackend io;
            bool (*read32)(void *context, uint32_t offset, uint32_t *value);
    };

    struct RfChannelProgress
    {
            RfChannelResult result;
            uint16_t synthesizerMhz;
            size_t completedWrites;
            uint32_t lastOffset;
            // Any failed/ambiguous write or mid-sequence owner loss requires
            // reset, even if the callback reported no completed write.
            bool requiresReset;
    };

    // Programs the AR9565 2.4 GHz channel synthesizer exactly as ath9k
    // ar9003_hw_set_channel does for AR_SREV_9565. This only tunes the
    // synthesizer: PLL, spur mitigation, noise/ANI calibration and calibrated
    // TX power remain separate mandatory steps. Must run after the PHY INI
    // phase, inside the native owner's serialized gate with a live RF grant.
    // No caller can infer safe TX permission from an Ok result.
    RfChannelProgress
    tuneAr9565Channel(const RfChannelRequest &request,
                      const CalibrationAndRegulatory &authorization,
                      const RfChannelBackend &backend);
} // namespace simpleath

#endif
