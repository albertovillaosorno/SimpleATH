// SPDX-License-Identifier: GPL-2.0-only
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
