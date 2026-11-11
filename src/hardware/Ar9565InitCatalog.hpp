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
//   - Native driver contracts and implementation for ar9565 init catalog.
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
//   - Native driver contracts and implementation for ar9565 init catalog.
// - Description:
//   - Implements or verifies the Ar9565InitCatalog source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for ar9565 init catalog.

#ifndef SIMPLEATH_AR9565_INIT_CATALOG_HPP
#define SIMPLEATH_AR9565_INIT_CATALOG_HPP

#include "Ar9565Core.hpp"
#include <stddef.h>
#include <stdint.h>

namespace simpleath
{

    enum class ChannelWidth : uint8_t
    {
        Ht20,
        Ht40,
    };
    enum class TxGainProfile : uint8_t
    {
        LowOb = 0,
        HighOb = 1,
        HighPower = 2,
        Unknown = 0xff,
    };
    enum class RxGainProfile : uint8_t
    {
        Standard = 0,
        WithoutExternalLna = 1,
        Unknown = 0xff,
    };

    enum class RegisterPhase : uint8_t
    {
        SocPreamble,
        MacCore,
        BasebandCore,
        RadioCore,
        RxGain,
        TxGain,
        SocPostamble,
        MacPostamble,
        BasebandPostamble,
        RadioPostamble,
        Japan2484Txfir,
    };

    // Each recipe contains the ordinary ten tables plus a channel-14 slot.
    constexpr size_t kRegisterPhaseCapacity = 11;

    // Forward-declared generated type; avoids undefined strict-aliasing casts.
    namespace ini
    {
        struct RegisterValue;
    }

    struct RegisterTable
    {
            RegisterPhase phase;
            const ini::RegisterValue *data;
            size_t count;
    };

    // Source code and generated tables deliberately have identical two-field
    // layouts, but this is an independent public type for the hardware backend.
    struct RegisterRecipe
    {
            Revision silicon;
            ChannelWidth width;
            TxGainProfile txGain;
            RxGainProfile rxGain;
            Channel channel;
            RegisterTable phases[kRegisterPhaseCapacity];
            size_t count;
            size_t registerWrites;
            bool regulatoryAuthorized;
            // The selected INI recipe can be executed by Ar9565RfIni. This
            // describes the table stage, never whole-radio or TX readiness.
            bool tablesComplete;
    };

    enum class RadioInitialization : uint8_t
    {
        TransmitReceive,
        ReceiveOnly,
    };

    struct CalibrationAndRegulatory
    {
            bool eepromContentsVerified {};
            bool boardAntennaConfigurationVerified {};
            bool localCountryRulesAvailable {};
            bool channelPermitted {};
            bool txPowerLimitsVerified {};
            bool radioKillUnblocked {};
            bool coexistenceConfigurationVerified {};
            RadioInitialization use {RadioInitialization::TransmitReceive};
    };

    // This code describes supported Linux ath9k revision-specific table
    // layouts. It never touches live PCI or MMIO, and does not claim to
    // implement Linux's calibration / board data / coexistence / 802.11 MAC
    // service layers. On failure, out is zeroed (no stale table pointers).
    Result createInitRecipe(Revision revision, const Channel &channel,
                            ChannelWidth width, TxGainProfile tx,
                            RxGainProfile rx,
                            const CalibrationAndRegulatory &requirements,
                            RegisterRecipe &out);

    // Receive-only initialization never authorizes TX, automatic ACK/CTS or
    // probe requests. The owner must keep those paths blocked independently.
    bool
    radioInitializationAuthorized(const CalibrationAndRegulatory &requirements);

    // Verifies prerequisites and the exact canonical phase list before the
    // MMIO executor starts. INI completion alone is not radio readiness.
    bool canBeginHardwareInitialization(
        const RegisterRecipe &recipe,
        const CalibrationAndRegulatory &requirements);

} // namespace simpleath
#endif
