#include "Ar9565RadioSequence.hpp"
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
            return left.context == right.context &&
                   left.ownerEpoch == right.ownerEpoch &&
                   left.barLengthBytes == right.barLengthBytes;
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
        const RadioSequenceBackends &backends)
    {
        RadioSequenceProgress progress {};
        // Snapshot every descriptor before calling untrusted owner callbacks.
        const RadioSequenceBackends stable = backends;
        const RfChannelRequest channel = request;
        const EepromImage verifiedBoard = physicalBoard;
        const CalibrationAndRegulatory allowed = authorization;
        const RfIniBackend &io = stable.baseband.io;
        if (!validBackend(stable.rfBus) || !validBackend(stable.tuning) ||
            io.context == nullptr || io.ownerEpoch == 0 ||
            io.barLengthBytes == 0 || io.permitWrite == nullptr ||
            io.write32 == nullptr || io.delayMicros == nullptr ||
            stable.baseband.read32 == nullptr ||
            !sameOwner(stable.rfBus.io, io) || !sameOwner(stable.tuning.io, io))
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
        // A lost owner immediately after the last calibration poll is NOT a
        // completed sequence; no readiness may escape from a stale epoch.
        if (!io.permitWrite(io.context, io.ownerEpoch))
        {
            progress.result = RadioSequenceResult::OwnershipLost;
            return progress;
        }
        progress.result = RadioSequenceResult::Ok;
        progress.stage = RadioSequenceStage::Completed;
        progress.requiresReset = false;
        return progress;
    }
} // namespace simpleath
