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
//   - Native driver contracts and implementation for ar9565 mac control.
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
//   - Native driver contracts and implementation for ar9565 mac control.
// - Description:
//   - Implements or verifies the Ar9565MacControl source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for ar9565 mac control.

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

    enum class MacReceiveOnlyResult : uint8_t
    {
        Ok,
        InvalidBackend,
        InvalidBar,
        OwnershipLost,
        ReadFailed,
        AutoResponsesEnabled,
    };

    // Receive-only EDMA may unmask the RX MAC only after a live PCI read
    // proves AR_SELFGEN_MASK is exactly zero. Otherwise the device could
    // autonomously ACK/CTS even if no software TX descriptor is submitted.
    // The owner must hold a serialized D0/epoch/radio lease before and after
    // this read. This check is not country/TPC authorization, and a future
    // TX-capable startup requires a separately verified automatic-TX policy.
    MacReceiveOnlyResult verifyAr9565ReceiveOnlyAutoResponsesDisabled(
        const RegisterBus &supplied, uint64_t epoch,
        bool (*permit)(void *, uint64_t));

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
