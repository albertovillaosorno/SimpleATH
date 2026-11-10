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

} // namespace simpleath

#endif
