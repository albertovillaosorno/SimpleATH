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

    // ath9k mci.h: one 16-entry, 16-byte scheduler table immediately
    // followed by one 16-entry, 16-byte GPM ring in coherent device memory.
    constexpr uint32_t kAr9565MciScheduleBytes = 256U;
    constexpr uint32_t kAr9565MciGpmBytes = 256U;
    constexpr uint16_t kAr9565MciGpmEntries = 16U;

    struct SharedMciDmaBuffers
    {
            uint32_t scheduleBusAddress {};
            uint32_t gpmBusAddress {};
            uint32_t scheduleBytes {};
            uint32_t gpmBytes {};
            uint16_t gpmEntries {};
    };

    struct SharedMciEvidence
    {
            // These are independently established native physical leases.
            // No EEPROM Bluetooth field or USB VID/PID proves any of them.
            bool physicallyVerifiedBoard {};
            bool bluetoothHostOwned {};
            bool coexistenceAndAntennaLease {};
            bool macAndAutoResponsesQuiesced {};
            bool mciEngineQuiesced {};
            // Both coherent, contiguous rings must have been filled with
            // 0xfe BEFORE DMA publication (ath9k MCI_GPM_RSVD_PATTERN).
            bool initializedCoherentDma {};
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
        InvalidDma,
    };

    struct CoexistenceProgress
    {
            CoexistenceResult result;
            size_t completedWrites;
            size_t completedReads;
            uint32_t lastOffset;
            bool requiresReset;
    };

    // Physically stage the shared-Bluetooth MCI scheduler/GPM DMA addresses
    // while the MAC and MCI are quiesced and all MCI interrupts are masked.
    // Every register is read back and every access rechecks the live owner.
    // This deliberately DOES NOT enable MCI, configure antenna arbitration,
    // reset MCI RX/TX, exchange GPM messages, or authorize RF/BT traffic.
    // The native PCI owner must complete those operations in the same lease
    // before claiming shared coexistence readiness. All buffer addresses are
    // the controller-visible coherent 32-bit bus addresses, not host pointers.
    CoexistenceProgress stageAr9565SharedMciDma(
        const BoardDataSummary &board, const SharedMciEvidence &evidence,
        const SharedMciDmaBuffers &buffers, const RxAgcBackend &backend);

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
