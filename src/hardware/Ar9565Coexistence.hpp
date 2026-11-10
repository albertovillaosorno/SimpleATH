#ifndef SIMPLEATH_AR9565_COEXISTENCE_HPP
#define SIMPLEATH_AR9565_COEXISTENCE_HPP

#include "Ar9565Calibration.hpp"
#include "Ar9565Eeprom.hpp"
#include <cstddef>
#include <cstdint>

namespace simpleath
{
    struct WlanOnlyCoexistenceEvidence
    {
            // ALL assertions must come from independently established native
            // device ownership, not an EEPROM template or its raw BT options.
            bool physicallyVerifiedBoard;
            bool bluetoothAbsentOrQuiesced;
            bool exclusiveWlanAntennaLease;
            bool macAndAutoResponsesQuiesced;
    };

    enum class CoexistenceResult : uint8_t
    {
        Ok,
        InvalidBackend,
        InvalidBoard,
        MissingIsolation,
        InvalidBar,
        OwnershipLost,
        ReadFailed,
        WriteFailed,
        ReadbackMismatch,
    };

    struct CoexistenceProgress
    {
            CoexistenceResult result;
            size_t completedWrites;
            size_t completedReads;
            uint32_t lastOffset;
            bool requiresReset;
    };

    // Park the AR9565 MCI/BT coexistence controller for an independently
    // verified WLAN-only board/epoch, following ath9k reg_mci.h register
    // definitions. This is NOT a Bluetooth controller and cannot establish
    // absence of USB Bluetooth, isolation, antenna provenance or RF readiness.
    // The caller MUST prove BT is absent OR hold a live BT quiescence lease
    // and exclusive antenna ownership. permitWrite must revalidate all of
    // this under live PCI D0 + serial work-loop epoch on EVERY MMIO action.
    // First disables AR_SELFGEN_MASK, masks MCI interrupts, disables MCI mode,
    // forbids BT LNA/SPDT updates and automatic TX-chain selection. Every
    // posted write must be drained by the callback, then read back. A write
    // failure or ownership revocation requires an explicit hardware reset.
    // The caller may set coexistenceConfigurationVerified for this specific
    // WLAN-only epoch only if result == Ok and the external BT lease remains.
    CoexistenceProgress
    parkAr9565WlanOnlyCoexistence(const BoardDataSummary &board,
                                  const WlanOnlyCoexistenceEvidence &evidence,
                                  const RxAgcBackend &backend);
} // namespace simpleath
#endif
