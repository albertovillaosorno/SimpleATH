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
//   - Native driver contracts and implementation for ar9565 radio sequence.
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
//   - Native driver contracts and implementation for ar9565 radio sequence.
// - Description:
//   - Implements or verifies the Ar9565RadioSequence source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for ar9565 radio sequence.

#include "Ar9565RadioSequence.hpp"
#include "Ar9565Ani.hpp"
#include "Ar9565AniMib.hpp"
#include "Ar9565BoardModal.hpp"
#include "Ar9565Calibration.hpp"
#include "Ar9565Channel.hpp"
#include "Ar9565Core.hpp"
#include "Ar9565Eeprom.hpp"
#include "Ar9565InitCatalog.hpp"
#include "Ar9565OfdmTiming.hpp"
#include "Ar9565PhyMode.hpp"
#include "Ar9565Pll.hpp"
#include "Ar9565RfBus.hpp"
#include "Ar9565RfIni.hpp"
#include <stdint.h>

namespace simpleath
{
    namespace
    {
        constexpr uint8_t kJapanChannel = 14;

        bool validBackend(const RfChannelBackend &backend)
        {
            const auto &io = backend.io;
            return io.context != nullptr && io.ownerEpoch != 0 &&
                   io.barLengthBytes != 0 && io.permitWrite != nullptr &&
                   io.write32 != nullptr && io.delayMicros != nullptr &&
                   backend.read32 != nullptr;
        }

        bool sameOwner(const RfIniBackend &left, const RfIniBackend &right)
        {
            // Only permitWrite may vary between RF-bus, tuning and PHY
            // stages. Reads, writes and delays MUST use one physical BAR
            // transport: sharing an epoch token alone does not establish
            // register-owner identity.
            return left.context == right.context &&
                   left.ownerEpoch == right.ownerEpoch &&
                   left.barLengthBytes == right.barLengthBytes &&
                   left.write32 == right.write32 &&
                   left.delayMicros == right.delayMicros;
        }

        bool validChannel(const RfChannelRequest &request)
        {
            if (request.referenceClock != RfReferenceClock::Crystal25Mhz &&
                request.referenceClock != RfReferenceClock::Crystal40Mhz)
            {
                return false;
            }
            Channel canonical {};
            if (mapChannel(request.control.number, canonical) != Result::Ok ||
                canonical.centerMhz != request.control.centerMhz ||
                canonical.requiresJapanAuthorization !=
                    request.control.requiresJapanAuthorization)
            {
                return false;
            }
            if (request.width == ChannelWidth::Ht20)
            {
                return request.secondary == 0;
            }
            if (request.width != ChannelWidth::Ht40 ||
                request.control.number == kJapanChannel ||
                request.secondary == kJapanChannel)
            {
                return false;
            }
            Channel secondary {};
            if (mapChannel(request.secondary, secondary) != Result::Ok)
            {
                return false;
            }
            const int difference = static_cast<int>(request.secondary) -
                                   static_cast<int>(request.control.number);
            return difference == 4 || difference == -4;
        }
    } // namespace

    RadioSequenceProgress runAr9565ReceiveOnlyRadioSequence(
        const EepromImage &physicalBoard, const RfChannelRequest &request,
        TxGainProfile txGain, RxGainProfile rxGain,
        BoardModalDiversity diversity,
        const CalibrationAndRegulatory &authorization,
        const RadioSequenceBackends &backends, uint64_t monotonicMilliseconds)
    {
        RadioSequenceProgress progress {};
        // Snapshot every descriptor before calling untrusted owner callbacks.
        const RadioSequenceBackends stable = backends;
        const RfChannelRequest channel = request;
        const EepromImage verifiedBoard = physicalBoard;
        const CalibrationAndRegulatory allowed = authorization;
        const RfIniBackend &io = stable.baseband.io;
        const AniMibBackend &mib = stable.mib;
        if (!validBackend(stable.rfBus) || !validBackend(stable.tuning) ||
            io.context == nullptr || io.ownerEpoch == 0 ||
            io.barLengthBytes == 0 || io.permitWrite == nullptr ||
            io.write32 == nullptr || io.delayMicros == nullptr ||
            stable.baseband.read32 == nullptr ||
            stable.rfBus.read32 != stable.baseband.read32 ||
            stable.tuning.read32 != stable.baseband.read32 ||
            !sameOwner(stable.rfBus.io, io) ||
            !sameOwner(stable.tuning.io, io) || mib.context != io.context ||
            mib.ownerEpoch != io.ownerEpoch ||
            mib.barLengthBytes != io.barLengthBytes || mib.permit == nullptr ||
            mib.read32 != stable.baseband.read32 || mib.write32 != io.write32)
        {
            return progress;
        }

        progress.result = RadioSequenceResult::InvalidCaptureTime;
        if (monotonicMilliseconds == 0U)
        {
            return progress;
        }
        progress.result = RadioSequenceResult::InvalidChannel;
        if (!validChannel(channel) ||
            (channel.control.number == kJapanChannel &&
             !allowed.localCountryRulesAvailable))
        {
            return progress;
        }
        progress.result = RadioSequenceResult::MissingAuthorization;
        if (allowed.use != RadioInitialization::ReceiveOnly ||
            !radioInitializationAuthorized(allowed))
        {
            return progress;
        }

        progress.result = RadioSequenceResult::InvalidBoard;
        BoardDataSummary summary {};
        if (!verifiedBoard.restored || verifiedBoard.appliedBlocks == 0 ||
            summarizeBoardData(verifiedBoard, summary) != EepromResult::Ok ||
            summary.rxChainMask != 1 || summary.txChainMask != 1 ||
            !summary.calibrationPierBinsPlausible)
        {
            return progress;
        }
        RegisterRecipe recipe {};
        if (createInitRecipe(channel.silicon, channel.control, channel.width,
                             txGain, rxGain, allowed, recipe) != Result::Ok ||
            !canBeginHardwareInitialization(recipe, allowed))
        {
            progress.result = RadioSequenceResult::InvalidChannel;
            return progress;
        }
        progress.result = RadioSequenceResult::OwnershipLost;
        if (!io.permitWrite(io.context, io.ownerEpoch))
        {
            return progress;
        }

        progress.stage = RadioSequenceStage::IniTables;
        progress.result = RadioSequenceResult::StageFailed;
        progress.ini = applyAr9565RfIni(recipe, allowed, io);
        progress.requiresReset = progress.ini.requiresReset;
        if (progress.ini.result != RfIniResult::Ok)
        {
            return progress;
        }
        // The first successful INI write makes every later failure a reset
        // obligation, even when the failing stage itself wrote nothing.
        progress.requiresReset = true;
        progress.stage = RadioSequenceStage::PhyMode;
        progress.phyMode =
            programAr9565ReceiveOnlyPhyMode(channel, allowed, stable.baseband);
        if (progress.phyMode.result != PhyModeResult::Ok)
        {
            return progress;
        }
        progress.stage = RadioSequenceStage::BoardModal;
        // Later callbacks must consume the same immutable board that
        // passed preflight; MMIO callbacks may change caller-owned storage.
        progress.board = programAr9565BoardModal2G(verifiedBoard, allowed,
                                                   diversity, stable.baseband);
        if (progress.board.result != BoardModalResult::Ok)
        {
            return progress;
        }

        RfBusLease lease {};
        progress.stage = RadioSequenceStage::RfBusRequest;
        progress.bus = requestAr9565RfBus(stable.rfBus, lease);
        if (progress.bus.result != RfBusResult::Ok)
        {
            return progress;
        }
        progress.stage = RadioSequenceStage::Pll;
        progress.pll = initializeAr9565Pll(channel, allowed, stable.tuning);
        if (progress.pll.result != RfPllResult::Ok)
        {
            // A failed PLL must not attempt to release the possibly stale
            // RF lease; owner reset is required for the whole analog epoch.
            return progress;
        }
        progress.stage = RadioSequenceStage::Synthesizer;
        progress.synthesizer =
            tuneAr9565Channel(channel, allowed, stable.tuning);
        if (progress.synthesizer.result != RfChannelResult::Ok)
        {
            return progress;
        }
        progress.stage = RadioSequenceStage::RfBusRelease;
        progress.bus = releaseAr9565RfBus(stable.rfBus, lease);
        if (progress.bus.result != RfBusResult::Ok)
        {
            return progress;
        }

        progress.stage = RadioSequenceStage::OfdmTiming;
        progress.ofdm =
            programAr9565OfdmTiming(channel, allowed, stable.baseband);
        if (progress.ofdm.result != OfdmTimingResult::Ok)
        {
            return progress;
        }
        progress.stage = RadioSequenceStage::ReceiverCalibration;
        progress.calibration = runAr9565ReceiveOnlyCalibration(
            channel, {summary.rxChainMask, summary.txChainMask}, allowed,
            stable.baseband);
        if (progress.calibration.phase != RxCalibrationPhase::Completed)
        {
            return progress;
        }
        // Snapshot actual PHY INI first-step/spur registers, so subsequent
        // channel-specific ANI adjustments cannot assume template defaults.
        // This does not start the receiver or authorize runtime ANI updates.
        progress.stage = RadioSequenceStage::AniBaseline;
        progress.ani = cacheAr9565AniIniDefaults(
            channel, allowed, stable.baseband, progress.aniState);
        if (progress.ani.result != AniResult::Ok)
        {
            return progress;
        }
        // Initialize real PHY/MIB error counters only after the exact physical
        // ANI INI defaults were read back. Do not fabricate a counter window
        // from elapsed time or promote a PHY without counter ownership.
        progress.stage = RadioSequenceStage::AniMibCounters;
        progress.mib =
            initializeAr9565AniMib(progress.aniState, allowed, mib,
                                   monotonicMilliseconds, progress.mibState);
        if (progress.mib.result != AniMibResult::Ok)
        {
            return progress;
        }
        // A lost owner immediately after the last calibration poll is NOT a
        // completed sequence; no readiness may escape from a stale epoch.
        if (!io.permitWrite(io.context, io.ownerEpoch))
        {
            // Counter initialization may have succeeded before the final
            // owner revocation. Its state must not escape as a reusable live
            // hardware counter session in a failed RF sequence.
            progress.aniState.initialized = false;
            progress.mibState.initialized = false;
            progress.mibState.requiresReset = true;
            progress.requiresReset = true;
            progress.result = RadioSequenceResult::OwnershipLost;
            return progress;
        }
        progress.result = RadioSequenceResult::Ok;
        progress.stage = RadioSequenceStage::Completed;
        progress.requiresReset = false;
        return progress;
    }

    RadioAniPollProgress pollAr9565ReceiveOnlyAni(
        const RfChannelRequest &request,
        const CalibrationAndRegulatory &authorization,
        const RxAgcBackend &baseband, const AniMibBackend &mibBackend,
        uint64_t monotonicMilliseconds, bool scanning, Ar9565AniState &aniState,
        AniMibState &mibState, RadioAniPollState &pollState)
    {
        RadioAniPollProgress progress {};
        const RfChannelRequest channel = request;
        const CalibrationAndRegulatory allowed = authorization;
        const RxAgcBackend phy = baseband;
        const AniMibBackend mib = mibBackend;
        const RfIniBackend &io = phy.io;
        // Never combine a real MIB epoch with an unrelated register bus.
        if (io.context == nullptr || io.ownerEpoch == 0U ||
            io.permitWrite == nullptr || io.write32 == nullptr ||
            phy.read32 == nullptr || mib.permit == nullptr ||
            mib.context != io.context || mib.ownerEpoch != io.ownerEpoch ||
            mib.barLengthBytes != io.barLengthBytes ||
            mib.read32 != phy.read32 || mib.write32 != io.write32)
        {
            return progress;
        }
        progress.result = RadioAniPollResult::NotInitialized;
        if (!aniState.initialized || !mibState.initialized ||
            mibState.requiresReset || aniState.ownerEpoch != io.ownerEpoch ||
            mibState.ownerEpoch != io.ownerEpoch)
        {
            return progress;
        }
        const auto revoke = [&]
        {
            pollState = {};
            aniState.initialized = false;
            mibState.initialized = false;
            mibState.requiresReset = true;
            progress.requiresReset = true;
        };
        if (pollState.primed &&
            (pollState.previous.ownerEpoch != io.ownerEpoch ||
             pollState.previousCapturedMs == 0U ||
             !pollState.previous.mmioAndMasksVerified))
        {
            progress.result = RadioAniPollResult::OwnershipLost;
            revoke();
            return progress;
        }
        AniHardwareSample captured {};
        progress.mib = captureAr9565AniMib(
            aniState, allowed, mib, monotonicMilliseconds, mibState, captured);
        if (progress.mib.result != AniMibResult::Ok)
        {
            progress.result = RadioAniPollResult::CounterFailed;
            revoke();
            return progress;
        }
        if (!io.permitWrite(io.context, io.ownerEpoch) ||
            !mib.permit(mib.context, mib.ownerEpoch))
        {
            progress.result = RadioAniPollResult::OwnershipLost;
            revoke();
            return progress;
        }
        if (!pollState.primed)
        {
            pollState.previous = captured;
            pollState.previousCapturedMs = monotonicMilliseconds;
            pollState.primed = true;
            progress.result = RadioAniPollResult::Primed;
            return progress;
        }
        if (monotonicMilliseconds <= pollState.previousCapturedMs ||
            monotonicMilliseconds - pollState.previousCapturedMs > UINT32_MAX)
        {
            progress.result = RadioAniPollResult::InvalidWindow;
            revoke();
            return progress;
        }
        progress.windowResult = deriveAr9565AniErrorWindow(
            channel, pollState.previous, captured,
            static_cast<uint32_t>(monotonicMilliseconds -
                                  pollState.previousCapturedMs),
            scanning, progress.window);
        if (progress.windowResult != AniResult::Ok)
        {
            progress.result = RadioAniPollResult::InvalidWindow;
            revoke();
            return progress;
        }
        progress.adaptation = adaptAr9565AniToPhyErrors(
            channel, allowed, phy, progress.window, aniState);
        if (progress.adaptation.result != AniResult::Ok)
        {
            progress.result = RadioAniPollResult::AdaptationFailed;
            revoke();
            return progress;
        }
        if (!io.permitWrite(io.context, io.ownerEpoch) ||
            !mib.permit(mib.context, mib.ownerEpoch))
        {
            progress.result = RadioAniPollResult::OwnershipLost;
            revoke();
            return progress;
        }
        pollState.previous = captured;
        pollState.previousCapturedMs = monotonicMilliseconds;
        progress.result = RadioAniPollResult::Adapted;
        return progress;
    }
} // namespace simpleath
