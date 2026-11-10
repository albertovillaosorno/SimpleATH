#ifndef SIMPLEATH_AR9565_ANI_HPP
#define SIMPLEATH_AR9565_ANI_HPP

#include "Ar9565Calibration.hpp"
#include "Ar9565Channel.hpp"
#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    enum class AniResult : uint8_t
    {
        Ok,
        InvalidBackend,
        InvalidChannel,
        MissingAuthorization,
        InvalidBar,
        NotInitialized,
        InvalidLevel,
        OwnershipLost,
        ReadFailed,
        WriteFailed,
        ReadbackMismatch,
    };

    // ath9k AR9003 ANI first-step and spur-immunity defaults are read from
    // the *applied* channel INI registers, never a generic gain template.
    // This state is bound to a physical owner epoch and complete channel
    // geometry (primary, HT width, secondary, silicon and reference crystal).
    struct Ar9565AniState
    {
            uint64_t ownerEpoch {};
            Revision silicon {Revision::Unknown};
            uint8_t channel {};
            ChannelWidth width {ChannelWidth::Ht20};
            uint8_t secondary {};
            RfReferenceClock referenceClock {RfReferenceClock::Crystal25Mhz};
            uint8_t firstStepLevel {2U};
            uint8_t spurLevel {3U};
            uint8_t firstStepDefault {};
            uint8_t firstStepLowDefault {};
            uint8_t spurDefault {};
            uint8_t spurExtDefault {};
            bool initialized {};
    };

    struct AniProgress
    {
            AniResult result {AniResult::InvalidBackend};
            size_t completedReads {};
            size_t completedWrites {};
            uint32_t lastOffset {};
            bool requiresReset {};
    };

    // After physical channel INI/PLL and receiver calibration, capture the
    // four register defaults on the live, quiesced and authorized PHY epoch.
    // No write, ANI readiness, channel permission or RX/TX activation occurs.
    // On failure the previous channel baseline is invalidated.
    AniProgress
    cacheAr9565AniIniDefaults(const RfChannelRequest &request,
                              const CalibrationAndRegulatory &authorization,
                              const RxAgcBackend &backend,
                              Ar9565AniState &state);

    // Apply AR9003 first-step/spur levels 0..8 and 0..7 relative to the
    // captured physical INI defaults, clamped to ath9k's field limits.
    // The native owner serializes this with channel/reset/ANI counters and
    // rechecks the actual D0/epoch/quiesced RF gate before EVERY register
    // access. On an ambiguous write/readback or lost epoch, reset the PHY:
    // no partially updated software levels may escape as valid.
    AniProgress
    programAr9565AniLevels(const RfChannelRequest &request,
                           const CalibrationAndRegulatory &authorization,
                           const RxAgcBackend &backend, Ar9565AniState &state,
                           uint8_t firstStepLevel, uint8_t spurLevel);
} // namespace simpleath

#endif // SIMPLEATH_AR9565_ANI_HPP
