#ifndef SIMPLEATH_AR9565_BOARD_MODAL_HPP
#define SIMPLEATH_AR9565_BOARD_MODAL_HPP

#include "Ar9565Calibration.hpp"
#include "Ar9565Eeprom.hpp"
#include <cstddef>
#include <cstdint>

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
