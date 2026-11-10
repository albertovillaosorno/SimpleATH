#ifndef SIMPLEATH_AR9565_PLL_HPP
#define SIMPLEATH_AR9565_PLL_HPP

#include "Ar9565Channel.hpp"
#include "Ar9565InitCatalog.hpp"
#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    enum class RfPllResult : uint8_t
    {
        Ok,
        InvalidBackend,
        InvalidChannel,
        MissingAuthorization,
        InvalidBar,
        OwnershipLost,
        ReadFailed,
        WriteFailed,
    };

    struct RfPllProgress
    {
            RfPllResult result;
            size_t completedWrites;
            size_t completedReads;
            uint32_t lastOffset;
            bool requiresReset;
    };

    // The AR9565-only BB+RTC PLL stage from ath9k_hw_init_pll in hw.c,
    // including the 9565-specific RTC bit, 1-ms BB lock interval and
    // 100-us RTC settle. It is intended after RTC reset and before channel
    // synthesizer programming. The owner must provide an already-awake RTC,
    // ordered/drained MMIO, real crystal provenance, live D0, exclusive MAC
    // quiescence, analog RF bus grant, epoch and board/country/RF-kill gates.
    // This is not a PLL lock measurement, calibration or TX permission.
    // Any partial write or loss of owner authority requires a full reset.
    RfPllProgress
    initializeAr9565Pll(const RfChannelRequest &request,
                        const CalibrationAndRegulatory &authorization,
                        const RfChannelBackend &backend);
} // namespace simpleath
#endif
