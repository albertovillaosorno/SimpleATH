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

    // AR9003 per-rate TPC bank (AR_PHY_POWER_TX_RATE 0..11), FCS-independent.
    // Packed half-dBm targets remain arithmetic candidates, not complete
    // temperature/PAPRD/antenna-calibrated hardware TX power indexes.
    constexpr size_t kAr9565RatePowerRegisters = 12U;

    struct TxPowerRegisterImage
    {
            uint32_t words[kAr9565RatePowerRegisters] {};
            uint8_t ackCtsHalfDbm {};
    };

    enum class TxPowerProgramResult : uint8_t
    {
        Ok,
        InvalidCandidate,
        InvalidBackend,
        MissingAuthorization,
        InvalidBar,
        OwnershipLost,
        ReadFailed,
        WriteFailed,
        ReadbackMismatch,
        InvalidArgument,
    };

    // Pure packing of the ath9k hardware rate-word order. No device access.
    // Inactive rates get numeric zero (0 dBm, NOT RF mute); the native owner
    // MUST gate every packet and all automatic MAC responses independently.
    // Invalid input wipes output; output/candidate alias returns untouched.
    TxPowerProgramResult
    makeAr9565TxRateRegisters(const PowerCandidates &candidate,
                              TxPowerRegisterImage &out);

    // Requires the real native PCI owner's serialized D0/epoch gate. Every
    // callback is synchronous and non-reentrant; permit must recheck an
    // independently sourced physical board, actually applied temperature/
    // voltage/TPC calibration, legal runtime country/channel/antenna limits,
    // RF-kill, BT coexistence and FULL MAC/EDMA/automatic-TX quiescence.
    // This routine never enables automatic ACK/CTS, TX queues, or PHY TX; the
    // AR_TPC power fields alone are not an authorization to transmit.
    struct TxPowerBackend
    {
            void *context {};
            uint64_t ownerEpoch {};
            uint32_t barLengthBytes {};
            bool (*permitWrite)(void *context, uint64_t epoch) {};
            bool (*write32)(void *context, uint32_t offset, uint32_t value) {};
            bool (*read32)(void *context, uint32_t offset, uint32_t *value) {};
    };

    struct TxPowerProgramProgress
    {
            TxPowerProgramResult result {TxPowerProgramResult::InvalidBackend};
            size_t completedWrites {};
            size_t completedReads {};
            uint32_t lastOffset {};
            bool requiresReset {};
    };

    // Programs and reads back forced-gain OFF, all 12 rate words, then AR_TPC
    // ACK/CTS power fields, preserving unrelated AR_TPC fields. Any ambiguous
    // write/readback or epoch loss after writes requires a native PHY reset
    // before retry. A source-only Ok is not calibrated RF or TX readiness.
    TxPowerProgramProgress
    programAr9565TxRateRegisters(const PowerCandidates &candidate,
                                 const CalibrationAndRegulatory &authorization,
                                 const TxPowerBackend &backend);

    // AR9565 chain-zero open-loop TPC correction from ath9k
    // ar9003_hw_power_control_override(): 8-bit signed gain delta,
    // error-estimator mode, signed thermal slope and factory temperature
    // reference. The channel calibration and modal slope are derived from
    // the physically restored EEPROM by calculatePowerCandidates, but are
    // NOT a substitute for live temperature/voltage compensation, PAPRD,
    // calibrated descriptor power indices or regulatory permission.
    //
    // Requires a stable, serialized D0 PCI owner with MAC/EDMA and automatic
    // responses fully quiesced. permitWrite rechecks the real board, current
    // channel, country, RF-kill, BT coexistence, owner epoch and TX policy
    // on every MMIO access. No transmitter is enabled here. Once a write is
    // attempted, any failure requires a radio reset before retry.
    TxPowerProgramProgress programAr9565TxOpenLoopCalibration(
        const PowerCandidates &candidate,
        const CalibrationAndRegulatory &authorization,
        const TxPowerBackend &backend);

    enum class TxPowerWorkflowPhase : uint8_t
    {
        OpenLoop,
        RateBank,
        Completed,
    };

    struct TxPowerWorkflowProgress
    {
            TxPowerWorkflowPhase phase {TxPowerWorkflowPhase::OpenLoop};
            TxPowerProgramProgress openLoop {};
            TxPowerProgramProgress rateBank {};
            bool requiresReset {};
    };

    // The source-side TX-power transaction: write chain-zero OLPC references
    // before the actual per-rate power bank and AR_TPC automatic-response
    // limits, under one stable candidate/policy/backend snapshot. Both stages
    // recheck the live epoch/owner before every MMIO access. Even if the bank
    // rejects a later write, previously committed OLPC writes require reset.
    // Do not equate Completed with calibrated descriptor power, live thermal/
    // voltage compensation, country approval or a native TX-ready signal.
    // The PCI owner must provide independently verified policy and retain
    // quiescent MAC/EDMA/automatic responses throughout this call.
    TxPowerWorkflowProgress
    programAr9565TransmitPower(const PowerCandidates &candidate,
                               const CalibrationAndRegulatory &authorization,
                               const TxPowerBackend &backend);

} // namespace simpleath
#endif
