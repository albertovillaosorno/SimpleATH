#ifndef SIMPLEATH_AR9565_RFBUS_HPP
#define SIMPLEATH_AR9565_RFBUS_HPP

#include "Ar9565Channel.hpp"
#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    enum class RfBusResult : uint8_t
    {
        Ok,
        InvalidBackend,
        InvalidBar,
        AlreadyRequested,
        LeaseMismatch,
        OwnershipLost,
        ReadFailed,
        WriteFailed,
        GrantTimeout,
    };

    // One native-owner-only lease at a time. A failed or timed-out request
    // remains latched for hardware reset rather than silently pretending a
    // lease was released. Never treat this mutable state as RF/TX authority:
    // the native backend must recheck actual grant and hardware quiescence.
    struct RfBusLease
    {
            void *ownerContext = nullptr;
            uint64_t ownerEpoch = 0;
            bool requestPosted = false;
            bool granted = false;
            bool requiresReset = false;
    };

    struct RfBusProgress
    {
            RfBusResult result;
            size_t polls;
            uint32_t lastGrant;
            bool requiresReset;
    };

    // Serial native MAC gate only. Backend permitWrite must ensure same real
    // provider, D0, quiesced DMA/TX/RX/automatic MAC responses and current
    // owner epoch on EVERY call. MMIO write32 must drain its PCI posted write.
    // Request follows ath9k ar9003_hw_rfbus_req, 10-us polls up to 100-ms
    // budget. Timeout/error after request requires a reset, not guessed unlock.
    RfBusProgress requestAr9565RfBus(const RfChannelBackend &backend,
                                     RfBusLease &lease);

    // Follows ar9003_hw_rfbus_done: read AR_PHY_RX_DELAY (100ns units),
    // delay floor(delay/10)+100us, then clear RF bus request. A lost epoch or
    // unknown read/write leaves lease unsafe and requires reset; it may not be
    // passed to another owner as a valid grant.
    RfBusProgress releaseAr9565RfBus(const RfChannelBackend &backend,
                                     RfBusLease &lease);
} // namespace simpleath
#endif
