// SPDX-License-Identifier: AGPL-3.0-only
#ifndef SIMPLEATH_AR9565_CALIBRATION_HPP
#define SIMPLEATH_AR9565_CALIBRATION_HPP

#include "Ar9565Channel.hpp"
#include "Ar9565InitCatalog.hpp"
#include <cstddef>
#include <cstdint>

namespace simpleath
{
    enum class RxAgcResult : uint8_t
    {
        Ok,
        InvalidBackend,
        InvalidChannel,
        MissingAuthorization,
        InvalidBar,
        AlreadyBusy,
        OwnershipLost,
        ReadFailed,
        WriteFailed,
        Timeout,
    };

    // AGC runs AFTER analog RF-bus ownership is released and settled.
    // Unlike the synthesizer's RfChannelBackend, the native owner must
    // assert an ordinary powered/serialized/quiesced PHY gate and must NOT
    // require the RF bus grant to remain held during calibration.
    struct RxAgcBackend
    {
            RfIniBackend io;
            bool (*read32)(void *context, uint32_t offset, uint32_t *value);
    };

    struct RxAgcProgress
    {
            RxAgcResult result;
            size_t completedWrites;
            size_t completedReads;
            size_t polls;
            uint32_t lastOffset;
            bool requiresReset;
    };

    // AR9003 PCIe AGC offset-calibration phase for an RX-only owner. Clears
    // TX-IQ, carrier-leak and TX filter/peak detector calibration enables
    // before setting AGC.CAL, then waits for hardware to clear it. No TX,
    // MAC auto-response or RF permission is granted by completion.
    //
    // The native serialized owner MUST already have a real mapped D0 BAR,
    // quiesced TX/RX/automatic responses, a verified channel/board/coex
    // policy, released RF-bus lease, and a stable owner epoch. permitWrite
    // must recheck all of those
    // before every MMIO access, including reads and each poll. The callback
    // must drain posted writes. Any ambiguous write or timeout requires a
    // native radio reset before retry. This is NOT the complete AR9565
    // calibration pipeline: chain-mask, noise floor, RX IQ and board-specific
    // calibrations must still run before receiver readiness is asserted.
    RxAgcProgress
    runAr9565RxAgcCalibration(const RfChannelRequest &request,
                              const CalibrationAndRegulatory &authorization,
                              const RxAgcBackend &backend);
    enum class RxIqResult : uint8_t
    {
        Ok,
        InvalidBackend,
        InvalidChannel,
        MissingAuthorization,
        InvalidBar,
        AlreadyBusy,
        OwnershipLost,
        ReadFailed,
        WriteFailed,
        Timeout,
        InvalidMeasurement,
    };

    struct RxIqProgress
    {
            RxIqResult result;
            size_t completedWrites;
            size_t completedReads;
            size_t polls;
            int16_t iCorrection;
            int16_t qCorrection;
            bool requiresReset;
    };

    // Chain-0 RX IQ mismatch: perform the one-sample AR9003 TIMING4 IQ
    // calibration, wait for hardware completion, read actual I/Q/correlation
    // measurements and apply bounded AR9565-specific IQ correction bits.
    // The native owner MUST verify one physical RX chain, an active channel,
    // completed AGC and stable RF/PHY ownership through permitWrite; do not
    // call this routine with untrusted board chain masks, or enable RX on
    // the strength of its result alone. TX and automatic responses stay off.
    RxIqProgress
    runAr9565RxIqCalibration(const RfChannelRequest &request,
                             const CalibrationAndRegulatory &authorization,
                             const RxAgcBackend &backend);

    enum class RxNoiseResult : uint8_t
    {
        Ok,
        InvalidBackend,
        InvalidChannel,
        MissingAuthorization,
        InvalidBar,
        AlreadyBusy,
        OwnershipLost,
        ReadFailed,
        WriteFailed,
        Timeout,
        InvalidMeasurement,
    };

    struct RxNoiseProgress
    {
            RxNoiseResult result;
            size_t completedReads;
            size_t completedWrites;
            size_t polls;
            int16_t controlDbm;
            int16_t extensionDbm;
            bool hasExtension;
            bool requiresReset;
    };

    // Capture chain-zero primary (and HT40 extension) noise floor from
    // AR9003 CCA registers. Start a one-shot NF measurement with the
    // NO_UPDATE_NF bit: this collects a sample without changing the radio's
    // live CCA threshold or creating an unvalidated NF history. The native
    // owner must supply a verified one-chain board mask, current channel,
    // finished AGC/IQ calibration and the same live D0/epoch/PHY gate as
    // RxIqCalibration. Any uncertain MMIO write or missing result requires
    // resetting the PHY; the caller must validate board-specific NF/ANI
    // policy before using the result to activate reception.
    RxNoiseProgress runAr9565RxNoiseFloorCalibration(
        const RfChannelRequest &request,
        const CalibrationAndRegulatory &authorization,
        const RxAgcBackend &backend);

    struct Ar9565BoardChainMasks
    {
            uint8_t rx;
            uint8_t tx;
    };

    enum class RxChainsResult : uint8_t
    {
        Ok,
        InvalidBackend,
        InvalidBoard,
        MissingAuthorization,
        InvalidBar,
        OwnershipLost,
        WriteFailed,
        ReadFailed,
        ReadbackMismatch,
    };

    struct RxChainsProgress
    {
            RxChainsResult result;
            size_t completedWrites;
            size_t completedReads;
            uint32_t lastOffset;
            bool requiresReset;
    };

    // Programs AR_PHY_RX_CHAINMASK / CAL_CHAINMASK for AR9565 chain zero,
    // and writes AR_SELFGEN_MASK=0 FIRST so no automatic ACK/CTS may transmit
    // during receive-only initialization. The board mask MUST come from a
    // verified EEPROM summary (1 RX and 1 TX); an unknown/multichain board
    // is not silently downgraded. INI and quiescence precede this stage.
    // This DOES NOT install a TX mask: TX/self-generated frame permission is
    // a separate operation requiring calibrated TX power and local rules.
    RxChainsProgress configureAr9565ReceiveOnlyChains(
        const Ar9565BoardChainMasks &board,
        const CalibrationAndRegulatory &authorization,
        const RxAgcBackend &backend);

    enum class RxCalibrationPhase : uint8_t
    {
        ChainMasks,
        AgcOffset,
        IqCorrection,
        NoiseFloor,
        Completed,
    };

    struct RxCalibrationWorkflowProgress
    {
            // Phase is the stage that failed, or Completed for success.
            // Only attempted per-stage results are meaningful. A failed
            // stage cannot be retried without reset if prior writes occurred.
            RxCalibrationPhase phase;
            RxChainsProgress chains;
            RxAgcProgress agc;
            RxIqProgress iq;
            RxNoiseProgress noise;
            bool requiresReset;
    };

    // Complete AR9565 chain-zero, RX-only calibration source workflow:
    // SELFGEN off + RX/CAL masks, AGC offset, RX IQ mismatch, NF sampling.
    // The native caller must have completed verified INI/PLL/tuning, released
    // RF-bus lease and quiesced the MAC, and MUST use one live serial owner
    // epoch across all stages. NO TX, automatic responses, PHY readiness,
    // ANI policy or native receiver activation is implied by completion.
    RxCalibrationWorkflowProgress runAr9565ReceiveOnlyCalibration(
        const RfChannelRequest &request, const Ar9565BoardChainMasks &board,
        const CalibrationAndRegulatory &authorization,
        const RxAgcBackend &backend);

    struct RfKillBoardConfiguration
    {
            bool configured;
            uint8_t gpio;
            bool activeHigh;
    };

    struct RfKillBackend
    {
            void *context;
            uint64_t ownerEpoch;
            uint32_t barLengthBytes;
            // RF-kill sampling must be possible before radio authorization.
            // Permit only a live D0 owner, serialized MAC gate, valid board
            // epoch and quiesced engines; do not require RF-kill unblocked.
            bool (*permitMmio)(void *context, uint64_t epoch);
            bool (*read32)(void *context, uint32_t offset, uint32_t *value);
            bool (*write32)(void *context, uint32_t offset, uint32_t value);
            void (*delayMicros)(void *context, uint32_t micros);
    };

    enum class RfKillResult : uint8_t
    {
        Unblocked,
        Blocked,
        InvalidBackend,
        NotConfigured,
        InvalidGpio,
        InvalidBar,
        OwnershipLost,
        ReadFailed,
        WriteFailed,
        ReadbackMismatch,
        Unstable,
    };

    struct RfKillProgress
    {
            RfKillResult result;
            bool hardwareBlocked;
            uint8_t gpio;
            size_t completedReads;
            size_t completedWrites;
            bool requiresReset;
    };

    struct RfKillReadBackend
    {
            void *context;
            uint64_t ownerEpoch;
            uint32_t barLengthBytes;
            // Read-only runtime checks may run with MAC/EDMA active, but
            // still require the same live D0, board lease and owner epoch.
            bool (*permitRead)(void *context, uint64_t epoch);
            bool (*read32)(void *context, uint32_t offset, uint32_t *value);
            void (*delayMicros)(void *context, uint32_t micros);
    };

    // Recheck the already configured GPIO without changing its direction.
    // Require input direction before AND after physical level sampling;
    // unexpected pin mux/direction drift is unsafe and requires reset.
    // Two matching physical samples and a final owner lease check are needed
    // for an Unblocked result. Every failure, unknown board GPIO or switched
    // level denies runtime TX/RX; no write/reset or RF permission is implied.
    // The native owner must have configured this input via sampleAr9565RfKill
    // earlier in the SAME epoch, and must not trust only that old sample.
    RfKillProgress observeAr9565RfKill(const RfKillBoardConfiguration &board,
                                       const RfKillReadBackend &backend);

    // AR9565 PCIe GPIO RF-kill: EEPROM rfSilent GPIO/polarity, AR9300 input
    // and GPIO OE settings. Configure the specified pin to high-impedance
    // input, verify the write, then sample twice across a short delay. Linux
    // ath9k treats a GPIO value equal to EEPROM polarity as BLOCKED. If the
    // EEPROM does not advertise an RF-kill pin, NotConfigured is returned:
    // neither the switch nor an ACPI/platform alternative is assumed safe.
    // This is a sampled state, not a standing authorization; recheck on
    // channel changes and before radio TX/RX. MAC response gates stay shut.
    RfKillProgress sampleAr9565RfKill(const RfKillBoardConfiguration &board,
                                      const RfKillBackend &backend);

} // namespace simpleath

#endif
