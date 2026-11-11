#ifndef SIMPLEATH_AR9565_RADIO_SEQUENCE_HPP
#define SIMPLEATH_AR9565_RADIO_SEQUENCE_HPP

#include "Ar9565Ani.hpp"
#include "Ar9565AniMib.hpp"
#include "Ar9565BoardModal.hpp"
#include "Ar9565Calibration.hpp"
#include "Ar9565OfdmTiming.hpp"
#include "Ar9565PhyMode.hpp"
#include "Ar9565Pll.hpp"
#include "Ar9565RfBus.hpp"
#include "Ar9565RfIni.hpp"

namespace simpleath
{
    enum class RadioSequenceStage : uint8_t
    {
        Preflight,
        IniTables,
        PhyMode,
        BoardModal,
        RfBusRequest,
        Pll,
        Synthesizer,
        RfBusRelease,
        OfdmTiming,
        ReceiverCalibration,
        AniBaseline,
        AniMibCounters,
        Completed,
    };

    enum class RadioSequenceResult : uint8_t
    {
        Ok,
        InvalidBackend,
        InvalidBoard,
        InvalidChannel,
        MissingAuthorization,
        StageFailed,
        OwnershipLost,
        InvalidCaptureTime,
    };

    struct RadioSequenceBackends
    {
            // Bus acquisition/release gate: live D0/epoch and MAC quiescence.
            RfChannelBackend rfBus {};
            // PLL/synth gate: additionally checks the *live* RF bus grant.
            RfChannelBackend tuning {};
            // INI/board/OFDM/calibration gate: requires quiescent live PHY,
            // and is valid after RF bus release (never requires its grant).
            RxAgcBackend baseband {};
            // Exact same BAR/epoch transport. The MIB permit additionally
            // attests exclusive ownership of MIB counters across all users.
            AniMibBackend mib {};
    };

    struct RadioSequenceProgress
    {
            RadioSequenceStage stage {RadioSequenceStage::Preflight};
            RadioSequenceResult result {RadioSequenceResult::InvalidBackend};
            RfIniProgress ini {};
            PhyModeProgress phyMode {};
            BoardModalProgress board {};
            RfBusProgress bus {};
            RfPllProgress pll {};
            RfChannelProgress synthesizer {};
            OfdmTimingProgress ofdm {};
            RxCalibrationWorkflowProgress calibration {};
            Ar9565AniState aniState {};
            AniProgress ani {};
            AniMibProgress mib {};
            AniMibState mibState {};
            bool requiresReset {};
    };

    // Execute the complete existing RX-only RF table/channel/calibration
    // sequence, including HT20/40 PHY/MAC mode, RF bus and ANI defaults. The
    // native owner must already have performed reset/RTC, NVM provenance,
    // PMU/XTAL, RF-kill and coexistence setup and must maintain all proofs
    // throughout this serialized epoch. This function never enables RX, TX,
    // automatic MAC responses, or claims dynamic ANI/board/radio readiness.
    //
    // All four backends MUST refer to the same physical BAR and epoch;
    // distinct permitWrite callbacks implement the lease-specific gates.
    // The real owner supplies a nonzero monotonic millisecond timestamp and
    // exclusive MIB-counter lease, for an initialized PHY counter baseline.
    // It must retain the counter epoch for periodic physical observations.
    // A failure after ANY successful physical write requires a hardware
    // reset; in particular, never retry/release an ambiguous RF bus lease.
    RadioSequenceProgress runAr9565ReceiveOnlyRadioSequence(
        const EepromImage &physicalBoard, const RfChannelRequest &request,
        TxGainProfile txGain, RxGainProfile rxGain,
        BoardModalDiversity diversity,
        const CalibrationAndRegulatory &authorization,
        const RadioSequenceBackends &backends, uint64_t monotonicMilliseconds);

    enum class RadioAniPollResult : uint8_t
    {
        Primed,
        Adapted,
        InvalidBackend,
        NotInitialized,
        CounterFailed,
        InvalidWindow,
        AdaptationFailed,
        OwnershipLost,
    };

    struct RadioAniPollState
    {
            AniHardwareSample previous {};
            uint64_t previousCapturedMs {};
            bool primed {};
    };

    struct RadioAniPollProgress
    {
            RadioAniPollResult result {RadioAniPollResult::InvalidBackend};
            AniMibProgress mib {};
            AniResult windowResult {AniResult::NotInitialized};
            AniErrorWindow window {};
            AniMonitorProgress adaptation {};
            bool requiresReset {};
    };

    // Compose two physically frozen MIB samples into one bounded ANI policy
    // window and an optional hardware sensitivity update. The native owner
    // supplies a real periodic scheduler, live physical authorization, and a
    // serialized same-epoch exclusive MIB lease; this routine does not turn
    // on RX/TX or claim RF readiness. Any ambiguity revokes both ANI states
    // and requires a physical reset before trying this epoch again.
    RadioAniPollProgress pollAr9565ReceiveOnlyAni(
        const RfChannelRequest &request,
        const CalibrationAndRegulatory &authorization,
        const RxAgcBackend &baseband, const AniMibBackend &mibBackend,
        uint64_t monotonicMilliseconds, bool scanning, Ar9565AniState &aniState,
        AniMibState &mibState, RadioAniPollState &pollState);
} // namespace simpleath
#endif
