#ifndef SIMPLEATH_AR9565_MAC_CONTROL_HPP
#define SIMPLEATH_AR9565_MAC_CONTROL_HPP
#include "Ar9565Core.hpp"

namespace simpleath
{
    enum class MacStopResult : uint8_t
    {
        Ok,
        InvalidBackend,
        ReadFailed,
        WriteFailed,
        UnknownRtcState,
        Timeout,
    };

    enum class MacIdentityResult : uint8_t
    {
        Ok,
        InvalidBackend,
        InvalidMac,
        OwnershipLost,
        ReadFailed,
        WriteFailed,
        ReadbackMismatch,
    };

    struct MacIdentityProgress
    {
            MacIdentityResult result {MacIdentityResult::InvalidBackend};
            uint8_t completedWrites {0};
            // An ambiguous hardware write requires reset, never retry in the
            // same live epoch or assume the old station address survived.
            bool requiresReset {false};
    };

    // Program actual EEPROM-acquired station identity into AR_STA_ID0/1
    // and install the exact-match BSSID mask (AR_BSSMSKL/U) before enabling
    // RX, DMA or automatic acknowledgements. Preserve all mode/control bits
    // in STA_ID1's upper half. The native PCI owner must
    // prove D0, same epoch, quiesced MAC and live NVM board lease on EACH
    // MMIO operation; this helper cannot authorize RF or TX.
    MacIdentityProgress
    programAr9565StationMac(const RegisterBus &supplied,
                            const uint8_t mac[kPermanentMacBytes],
                            uint64_t epoch, bool (*permit)(void *, uint64_t));

    // The exclusive PCI owner serializes this with power and reset. The bus
    // revalidates D0/ownership on every access, drains posted writes, and must
    // refuse access after revocation. PCI bus mastering must already be off.
    // delayMicros runs on the same retained, sleepable operation context.
    // Success only quiesces MAC engines; it grants no RF/TX permission.
    MacStopResult quiesceAr9565Mac(const RegisterBus &supplied,
                                   void (*delayMicros)(void *context,
                                                       uint32_t microseconds));
} // namespace simpleath
#endif
