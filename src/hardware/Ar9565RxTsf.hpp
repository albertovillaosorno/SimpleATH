// Source-only AR9565 receive timestamp bridge. No RF or AWDL permission.
#ifndef SIMPLEATH_AR9565_RX_TSF_HPP
#define SIMPLEATH_AR9565_RX_TSF_HPP

#include <stdint.h>

namespace simpleath
{
    enum class RxTsfResult : uint8_t
    {
        Ok,
        InvalidBackend,
        InvalidBar,
        OwnershipLost,
        ReadFailed,
        InvalidClock,
        UnstableClock,
        StaleFrame,
    };

    struct RxTsfBackend
    {
            void *context {};
            uint64_t ownerEpoch {};
            uint32_t barLengthBytes {};
            // Revalidate D0, owner epoch, channel-6 RX, RF-kill and the live
            // PCI/EDMA lease BEFORE each register access. Never write TSF.
            bool (*permitRead)(void *, uint64_t) {};
            bool (*read32)(void *, uint32_t, uint32_t *) {};
            // Uptime in microseconds; same monotonic domain used for AWDL
            // peer expiry. Called both before and after the TSF register read.
            uint64_t (*monotonicMicros)(void *) {};
    };

    struct RxTsfSample
    {
            uint64_t ownerEpoch {};
            uint64_t hardwareRxTsfUsec {};
            uint64_t hardwareCaptureTsfUsec {};
            uint64_t captureMonotonicUsec {};
            uint64_t frameMonotonicUsec {};
            uint32_t ageUsec {};
    };

    // Extend the EDMA status3 low 32-bit RX timestamp using a coherent,
    // same-epoch TSF upper/lower/upper snapshot (ath9k_hw_gettsf64). Reject
    // a future/stale timestamp or uncertain host-clock correlation. No MIF,
    // AWDL election, RF transmit or macOS peer permission is established.
    // Ordinary failure clears out; caller must keep output independent of
    // backend/context storage.
    RxTsfResult captureAr9565RxTsf(const RxTsfBackend &backend,
                                   uint32_t descriptorTsfLow, RxTsfSample &out);
} // namespace simpleath

#endif
