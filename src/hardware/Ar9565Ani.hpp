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
        InvalidErrorWindow,
        StaleErrorWindow,
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
            // Linux ath9k ANI monitor starts at OFDM=3, CCK=2. These are
            // independent PHY-error policies; first-step is their maximum.
            // AR9565 single-chain CCK is conservatively capped at level 6
            // until a trustworthy per-BSSID RSSI lease is available.
            uint8_t ofdmImmunityLevel {3U};
            uint8_t cckImmunityLevel {2U};
            bool ofdmTurn {true};
            uint64_t lastCounterSequence {};
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

    // A FINISHED PHY-error observation from one real hardware counter epoch.
    // The native owner must derive listenedMilliseconds from awake/receive
    // cycle counters, NOT wall clock, and obtain the OFDM/CCK timing error
    // counts from AR_PHY_ERR_1/2 after enabling their masks. Counter wrap,
    // a reset/re-tune, or uncertain sleep/RF-kill ownership invalidates the
    // whole window; never infer it from EDMA packet errors or passive scans.
    struct AniErrorWindow
    {
            // Must be a new, complete window from the current PHY epoch.
            uint64_t ownerEpoch {};
            uint64_t counterSequence {};
            uint32_t listenedMilliseconds {};
            uint32_t ofdmTimingErrors {};
            uint32_t cckTimingErrors {};
            bool hardwareCountersVerified {};
            bool scanning {};
    };

    struct AniMonitorProgress
    {
            AniResult result {AniResult::NotInitialized};
            AniProgress programming {};
            uint8_t ofdmImmunityLevel {};
            uint8_t cckImmunityLevel {};
            bool adjusted {};
            bool registerProgrammed {};
    };

    // Adapt the AR9003 first-step and spur registers from ath9k's OFDM/CCK
    // timing-error trigger logic, bound to the already-cached PHY baseline.
    // Only complete >300-ms *listen-time* windows with separately verified
    // physical counter provenance are considered; scanning is read-only.
    // Counter sequence is monotonic and never recycled within an owner epoch;
    // a consumed observation cannot tune ANI twice, even if the old counter
    // bytes are supplied again. This gate does not itself prove physical
    // counter provenance: the native owner must still collect and validate it.
    // This conservative single-chain subset does not alter OFDM weak-signal
    // detection or CCK MRC (unsupported on AR9565) and caps CCK immunity at 6
    // without trusted BSSID RSSI. Its success is NOT a receiver-ready lease.
    // The caller must serialize this with reset, channel changes and radio
    // power, and must not run it during an RF/PHY calibration transaction.
    AniMonitorProgress
    adaptAr9565AniToPhyErrors(const RfChannelRequest &request,
                              const CalibrationAndRegulatory &authorization,
                              const RxAgcBackend &backend,
                              const AniErrorWindow &window,
                              Ar9565AniState &state);
} // namespace simpleath

#endif // SIMPLEATH_AR9565_ANI_HPP
