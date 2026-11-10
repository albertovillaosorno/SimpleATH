// SPDX-License-Identifier: AGPL-3.0-only
#ifndef SIMPLEATH_AR9565_RADIO_SEQUENCE_HPP
#define SIMPLEATH_AR9565_RADIO_SEQUENCE_HPP

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
    };

    struct RadioSequenceBackends
    {
            // Bus acquisition/release gate: live D0/epoch and MAC quiescence.
            RfChannelBackend rfBus;
            // PLL/synth gate: additionally checks the *live* RF bus grant.
            RfChannelBackend tuning;
            // INI/board/OFDM/calibration gate: requires quiescent live PHY,
            // and is valid after RF bus release (never requires its grant).
            RxAgcBackend baseband;
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
            bool requiresReset {};
    };

    // Execute the complete existing RX-only RF table/channel/calibration
    // sequence, including HT20/40 PHY/MAC mode and RF bus request/release. The
    // native owner must already have performed reset/RTC, NVM provenance,
    // PMU/XTAL, RF-kill and coexistence setup and must maintain all proofs
    // throughout this serialized epoch. This function never enables RX, TX,
    // automatic MAC responses, or claims complete ANI/board/radio readiness.
    //
    // The three backends MUST refer to the same physical BAR and epoch;
    // distinct permitWrite callbacks implement the lease-specific gates.
    // A failure after ANY successful physical write requires a hardware
    // reset; in particular, never retry/release an ambiguous RF bus lease.
    RadioSequenceProgress runAr9565ReceiveOnlyRadioSequence(
        const EepromImage &physicalBoard, const RfChannelRequest &request,
        TxGainProfile txGain, RxGainProfile rxGain,
        BoardModalDiversity diversity,
        const CalibrationAndRegulatory &authorization,
        const RadioSequenceBackends &backends);
} // namespace simpleath
#endif
