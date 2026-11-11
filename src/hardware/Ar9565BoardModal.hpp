// Copyright:
//   - Copyright © 2026 Alberto Villa Osorno
// SPDX-License-Identifier:
//   - MIT
// Confidential:
//   - false
// License-File:
//   - LICENSE-MIT
// Provenance:
//   - SimpleATH original; independently developed or locally authored
//
// Boundary-Contract:
// - Owns:
//   - Native driver contracts and implementation for ar9565 board modal.
// - Must-Not:
//   - Invent hardware readiness, weaken buffer bounds, or assume ABI
//     compatibility.
// - Allows:
//   - Inputs: validated register, protocol, platform, or device state from
//     callers.
//   - Outputs: bounded native transitions, messages, or explicit errors.
//   - Side effects: only the device and kernel operations owned by this module.
// - Split-When:
//   - A separate protocol stage needs independent validation and ownership.
// - Merge-When:
//   - The caller directly owns this narrow contract without reuse.
// - Summary:
//   - Native driver contracts and implementation for ar9565 board modal.
// - Description:
//   - Implements or verifies the Ar9565BoardModal source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for ar9565 board modal.

#ifndef SIMPLEATH_AR9565_BOARD_MODAL_HPP
#define SIMPLEATH_AR9565_BOARD_MODAL_HPP

#include "Ar9565Calibration.hpp"
#include "Ar9565Eeprom.hpp"
#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    enum class BoardModalDiversity : uint8_t
    {
        WlanOnly,
        SharedWithBluetooth,
    };

    enum class BoardModalResult : uint8_t
    {
        Ok,
        InvalidBackend,
        InvalidBoard,
        MissingAuthorization,
        InvalidBar,
        OwnershipLost,
        ReadFailed,
        WriteFailed,
        ReadbackMismatch,
    };

    struct BoardModalProgress
    {
            BoardModalResult result;
            size_t completedWrites;
            size_t completedReads;
            uint32_t lastOffset;
            bool requiresReset;
    };

    // Apply genuine AR9565 AR9003 modal 2-GHz antenna routing and chain-zero
    // attenuation through the live native MMIO owner. The EEPROM image must
    // be a restored, independently verified physical board image, NOT merely
    // a structurally valid pinned reconstruction template. The backend's
    // permitWrite must check D0, owner epoch, board provenance, RF-kill,
    // coexistence agreement, PCI gate and fully quiesced MAC/automatic TX.
    //
    // SharedWithBluetooth requires the native Bluetooth owner to have
    // established antenna/coexistence routing BEFORE this call. The caller
    // must not assert readiness (RX, TX, BLE or AWDL) from a successful stage:
    // PLL/channel, receiver calibration and country/TPC remain independent.
    // No TX/automatic response bit is enabled here. Every ambiguous MMIO
    // write/readback requires hardware reset; do not blindly retry.
    BoardModalProgress programAr9565BoardModal2G(
        const EepromImage &image, const CalibrationAndRegulatory &authorization,
        BoardModalDiversity diversity, const RxAgcBackend &backend);
} // namespace simpleath
#endif
