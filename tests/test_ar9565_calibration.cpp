// SPDX-License-Identifier: AGPL-3.0-only
// Offline AR9565 RX AGC calibration, never a real hardware operation.
#include "hardware/Ar9565Calibration.hpp"
#include "hardware/Ar9565Channel.hpp"
#include "hardware/Ar9565Core.hpp"
#include "hardware/Ar9565InitCatalog.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>

using namespace simpleath;

namespace
{
    constexpr uint64_t kEpoch = 51;
    constexpr uint32_t kBar = 0x20000;
    constexpr uint32_t kAgc = 0xa2c4;
    constexpr uint32_t kCarrier = 0xa2d8;
    constexpr uint32_t kTxIq = 0xa5c4;
    constexpr uint32_t kRfKillGpioDirection = 0x4050;
    constexpr uint32_t kRfKillGpioInput = 0x404c;
    constexpr uint32_t kRfKillDirectionInitial = 0xff;
    constexpr uint8_t kRfKillTestPin = 2;
    constexpr uint8_t kRfKillInvalidPin = 14;
    constexpr uint32_t kRfKillInputHigh = 1U << kRfKillTestPin;
    constexpr uint32_t kRfKillInputPinShift = kRfKillTestPin * 2U;
    constexpr uint32_t kRfKillInputDirection =
        kRfKillDirectionInitial & ~(3U << kRfKillInputPinShift);
    constexpr uint32_t kRfKillSamplingDelay = 100;
    constexpr size_t kRfKillReads = 4;
    constexpr int kFailedRfKillSuccessExit = 15;
    constexpr int kFailedRfKillAdmissionExit = 16;
    constexpr int kFailedRfKillFailuresExit = 17;
    constexpr int kFailedRfKillRuntimeExit = 18;
    constexpr uint32_t kSelfgenMask = 0x832c;
    constexpr uint32_t kReceiveMask = 0xa2a0;
    constexpr uint32_t kCalMask = 0xa2c0;
    constexpr uint32_t kSingleChain = 1;
    constexpr size_t kChainCount = 3;
    constexpr size_t kRevokeBeforeThirdChainWrite = 5;
    constexpr int kFailedChainsSuccessExit = 10;
    constexpr int kFailedChainsAdmissionExit = 11;
    constexpr int kFailedChainsFailuresExit = 12;
    constexpr size_t kWorkflowWrites = 11;
    constexpr size_t kWorkflowReads = 20;
    constexpr size_t kWorkflowBeforeIqWriteCount = 6;
    constexpr size_t kWorkflowBeforeIqCorrectionWriteCount = 9;
    constexpr size_t kWorkflowRevokeAfterMasks = 8;
    constexpr int kFailedWorkflowSuccessExit = 13;
    constexpr int kFailedWorkflowFailuresExit = 14;
    constexpr uint32_t kNoisePrimary = 0x9e1c;
    constexpr uint32_t kNoiseExtension = 0x9830;
    constexpr uint32_t kNoiseCal = 0x2;
    constexpr uint32_t kNoiseEnable = 0x8000;
    constexpr uint32_t kNoiseNoUpdate = 0x20000;
    constexpr uint32_t kNoiseControlSample = 0x19c00000;     // -100 dBm
    constexpr uint32_t kNoiseExtSample = 0x19a0000;          // -102 dBm
    constexpr uint32_t kNoiseControlAboveLimit = 0x1e200000; // -30 dBm
    constexpr uint32_t kNoiseSampleZero = 0;
    constexpr int16_t kNoiseExpectedControlDbm = -100;
    constexpr int16_t kNoiseExpectedExtensionDbm = -102;
    constexpr size_t kNoiseWideReads = 5;
    constexpr uint8_t kHt40Secondary = 10;
    constexpr int kFailedNoiseSuccessExit = 7;
    constexpr int kFailedNoiseAdmissionExit = 8;
    constexpr int kFailedNoiseFailureExit = 9;
    constexpr uint32_t kIqTiming = 0x980c;
    constexpr uint32_t kIqCalMode = 0xa2c8;
    constexpr uint32_t kIqMeasI = 0x98c0;
    constexpr uint32_t kIqMeasQ = 0x98c4;
    constexpr uint32_t kIqMeasCorr = 0x98c8;
    constexpr uint32_t kIqCorr = 0x98dc;
    constexpr uint32_t kIqDoCal = 0x10000;
    constexpr uint32_t kIqLogCount = 0xa000;
    constexpr uint32_t kIqSampleI = 98304;
    constexpr uint32_t kIqSampleQ = 65536;
    constexpr uint32_t kIqSampleCorrelation = 640;
    constexpr uint32_t kIqUnrelated = 0x80000000;
    constexpr uint32_t kIqExpectedCorrected = 0x7f20;
    constexpr int16_t kIqExpectedQ = 32;
    constexpr uint32_t kIqNegativeCorrelation = 0xfffffd80U;
    constexpr uint32_t kIqSaturatedCorrelation = 0x7fffffffU;
    constexpr size_t kIqRevokeAt = 5;
    constexpr int kFailedIqPreflightExit = 5;
    constexpr int kFailedIqFailuresExit = 6;

    constexpr size_t kIqExpectedReads = 7;
    constexpr size_t kIqExpectedWrites = 4;
    constexpr size_t kIqExpectedPolls = 2;
    constexpr size_t kIqExpectedDelays = 1;

    constexpr uint32_t kCal = 0x1;
    constexpr uint32_t kOffset = 0x800;
    constexpr uint32_t kFilter = 0x10000;
    constexpr uint32_t kPeak = 0x100000;
    constexpr uint32_t kCarrierEnable = 0x2;
    constexpr uint32_t kTxIqEnable = 0x80000000;
    constexpr uint32_t kTxIqUnrelated = 0x20U;
    constexpr uint32_t kCarrierUnrelated = 0x40U;
    constexpr uint32_t kAgcUnrelated = 0x100U;
    constexpr size_t kInitialReads = 3;
    constexpr size_t kSuccessReads = 6;
    constexpr size_t kExpectedWrites = 3;
    constexpr size_t kExpectedPolls = 3;
    constexpr size_t kExpectedDelays = 2;
    constexpr size_t kRevokeBeforeThirdWrite = 6;
    constexpr size_t kFailOnSecondPoll = 5;
    constexpr uint32_t kDelay = 10;
    constexpr size_t kPollLimit = 10000;
    constexpr uint8_t kChannel = 6;
    constexpr uint8_t kJapan = 14;
    constexpr uint8_t kBadSecondary = 9;

    struct Write
    {
            uint32_t address;
            uint32_t value;
    };

    struct Mock
    {
            uint32_t txIq = kTxIqEnable | kTxIqUnrelated;
            uint32_t carrier = kCarrierEnable | kCarrierUnrelated;
            uint32_t agc = kFilter | kPeak | kAgcUnrelated;
            uint32_t gpioDirection = kRfKillDirectionInitial;
            uint32_t gpioInput = 0;
            size_t gpioInputReads = 0;
            size_t rfkillDelays = 0;
            bool changeGpioOnSecondSample = false;
            uint32_t selfgen = kSingleChain;
            uint32_t receiveMask = 0;
            uint32_t calibrationMask = 0;
            uint32_t noiseControl = kNoiseControlSample;
            uint32_t noiseExtension = kNoiseExtSample;
            uint32_t iqTiming = 0;
            uint32_t iqMode = kIqUnrelated;
            uint32_t iqPowerI = kIqSampleI;
            uint32_t iqPowerQ = kIqSampleQ;
            uint32_t iqCorrelation = kIqSampleCorrelation;
            uint32_t iqCorrection = kIqUnrelated;
            std::array<Write, kWorkflowWrites> writes {};
            size_t writeCount = 0;
            size_t readCount = 0;
            size_t permitCount = 0;
            size_t pollReads = 0;
            size_t delayCount = 0;
            size_t completeAfter = 3;
            size_t noisePollReads = 0;
            size_t noiseCompleteAfter = 2;
            size_t iqPollReads = 0;
            size_t iqCompleteAfter = kIqExpectedPolls;

            size_t failReadAt = 0;
            size_t failWriteAt = 0;
            uint32_t ignoreWriteTo = 0;
            size_t revokeAt = 0;
            bool triggered = false;
            bool noiseTriggered = false;
            bool iqTriggered = false;
            bool denied = false;
            bool wrongEpoch = false;
            bool badDelay = false;
    };

    uint32_t *reg(Mock &mock, uint32_t address)
    {
        switch (address)
        {
            case kAgc:
                return &mock.agc;
            case kCarrier:
                return &mock.carrier;
            case kTxIq:
                return &mock.txIq;
            case kRfKillGpioDirection:
                return &mock.gpioDirection;
            case kRfKillGpioInput:
                return &mock.gpioInput;
            case kSelfgenMask:
                return &mock.selfgen;
            case kReceiveMask:
                return &mock.receiveMask;
            case kCalMask:
                return &mock.calibrationMask;
            case kNoisePrimary:
                return &mock.noiseControl;
            case kNoiseExtension:
                return &mock.noiseExtension;
            case kIqTiming:
                return &mock.iqTiming;
            case kIqCalMode:
                return &mock.iqMode;
            case kIqMeasI:
                return &mock.iqPowerI;
            case kIqMeasQ:
                return &mock.iqPowerQ;
            case kIqMeasCorr:
                return &mock.iqCorrelation;
            case kIqCorr:
                return &mock.iqCorrection;
            default:
                return nullptr;
        }
    }

    bool permit(void *context, uint64_t epoch)
    {
        auto &mock = *static_cast<Mock *>(context);
        ++mock.permitCount;
        return epoch == kEpoch && !mock.denied && !mock.wrongEpoch &&
               (mock.revokeAt == 0 || mock.permitCount < mock.revokeAt);
    }

    bool read(void *context, uint32_t address, uint32_t *out)
    {
        auto &mock = *static_cast<Mock *>(context);
        ++mock.readCount;
        if ((mock.failReadAt != 0 && mock.readCount == mock.failReadAt) ||
            reg(mock, address) == nullptr)
        {
            return false;
        }
        if (address == kRfKillGpioInput)
        {
            ++mock.gpioInputReads;
            if (mock.changeGpioOnSecondSample && mock.gpioInputReads == 2)
            {
                mock.gpioInput ^= kRfKillInputHigh;
            }
        }
        if (address == kAgc && mock.triggered)
        {
            ++mock.pollReads;
            if (mock.pollReads >= mock.completeAfter)
            {
                mock.agc &= ~kCal;
            }
        }
        if (address == kAgc && mock.noiseTriggered)
        {
            ++mock.noisePollReads;
            if (mock.noisePollReads >= mock.noiseCompleteAfter)
            {
                mock.agc &= ~kNoiseCal;
            }
        }
        if (address == kIqTiming && mock.iqTriggered)
        {
            ++mock.iqPollReads;
            if (mock.iqPollReads >= mock.iqCompleteAfter)
            {
                mock.iqTiming &= ~kIqDoCal;
            }
        }
        *out = *reg(mock, address);
        return true;
    }

    bool write(void *context, uint32_t address, uint32_t value)
    {
        auto &mock = *static_cast<Mock *>(context);
        if ((mock.failWriteAt != 0 &&
             mock.writeCount + 1 == mock.failWriteAt) ||
            mock.writeCount >= mock.writes.size() ||
            reg(mock, address) == nullptr)
        {
            return false;
        }
        mock.writes.at(mock.writeCount) = {address, value};
        ++mock.writeCount;
        if (mock.ignoreWriteTo != address)
        {
            *reg(mock, address) = value;
        }
        if (address == kAgc)
        {
            mock.triggered = true;
        }
        if (address == kAgc && (value & kNoiseCal) != 0)
        {
            mock.noiseTriggered = true;
        }
        if (address == kIqTiming && (value & kIqDoCal) != 0)
        {
            mock.iqTriggered = true;
        }
        return true;
    }

    void delay(void *context, uint32_t micros)
    {
        auto &mock = *static_cast<Mock *>(context);
        if (micros == kRfKillSamplingDelay)
        {
            ++mock.rfkillDelays;
        }
        if (micros != kDelay && micros != kRfKillSamplingDelay)
        {
            mock.badDelay = true;
        }
        ++mock.delayCount;
    }

    RfKillBackend rfkillBackend(Mock &mock, uint32_t bar = kBar)
    {
        return {&mock, kEpoch, bar, permit, read, write, delay};
    }

    RfKillReadBackend rfkillReadBackend(Mock &mock, uint32_t bar = kBar)
    {
        return {&mock, kEpoch, bar, permit, read, delay};
    }

    RxAgcBackend backend(Mock &mock, uint32_t bar = kBar)
    {
        return {{&mock, kEpoch, bar, permit, write, delay}, read};
    }

    RfChannelRequest request()
    {
        Channel channel {};
        (void)mapChannel(kChannel, channel);
        return {
            Revision::V1_1,
            channel,
            ChannelWidth::Ht20,
            0,
            RfReferenceClock::Crystal40Mhz,
        };
    }

    CalibrationAndRegulatory authorization()
    {
        return {
            true,  true, false, true,
            false, true, true,  RadioInitialization::ReceiveOnly,
        };
    }

    bool testsSuccess()
    {
        Mock mock {};
        const auto result = runAr9565RxAgcCalibration(
            request(), authorization(), backend(mock));
        if (result.result != RxAgcResult::Ok || result.requiresReset ||
            result.completedReads != kSuccessReads ||
            result.completedWrites != kExpectedWrites ||
            result.polls != kExpectedPolls || result.lastOffset != kAgc ||
            mock.writeCount != kExpectedWrites ||
            mock.pollReads != kExpectedPolls ||
            mock.delayCount != kExpectedDelays || mock.badDelay ||
            mock.writes.at(0).address != kTxIq ||
            mock.writes.at(0).value != kTxIqUnrelated ||
            mock.writes.at(1).address != kCarrier ||
            mock.writes.at(1).value != kCarrierUnrelated ||
            mock.writes.at(2).address != kAgc ||
            mock.writes.at(2).value != (kAgcUnrelated | kOffset | kCal) ||
            mock.txIq != kTxIqUnrelated || mock.carrier != kCarrierUnrelated ||
            mock.agc != (kAgcUnrelated | kOffset))
        {
            return false;
        }
        // An authentic progress return is local to the owner epoch.
        // This synthetic result does not establish native PHY readiness.
        return !mock.badDelay;
    }

    bool testsAdmission()
    {
        Mock mock {};
        auto auth = authorization();
        auto req = request();
        auto io = backend(mock);
        io.read32 = nullptr;
        if (runAr9565RxAgcCalibration(req, auth, io).result !=
            RxAgcResult::InvalidBackend)
        {
            return false;
        }
        io = backend(mock, kTxIq + 3);
        if (runAr9565RxAgcCalibration(req, auth, io).result !=
            RxAgcResult::InvalidBar)
        {
            return false;
        }
        auth.use = RadioInitialization::TransmitReceive;
        if (runAr9565RxAgcCalibration(req, auth, backend(mock)).result !=
            RxAgcResult::MissingAuthorization)
        {
            return false;
        }
        auth = authorization();
        auth.radioKillUnblocked = false;
        if (runAr9565RxAgcCalibration(req, auth, backend(mock)).result !=
            RxAgcResult::MissingAuthorization)
        {
            return false;
        }
        auth = authorization();
        req.control.centerMhz = 0;
        if (runAr9565RxAgcCalibration(req, auth, backend(mock)).result !=
            RxAgcResult::InvalidChannel)
        {
            return false;
        }
        req = request();
        req.control.number = kJapan;
        req.width = ChannelWidth::Ht40;
        req.secondary = kBadSecondary;
        if (runAr9565RxAgcCalibration(req, auth, backend(mock)).result !=
            RxAgcResult::InvalidChannel)
        {
            return false;
        }
        if (mock.writeCount != 0)
        {
            return false;
        }
        Mock busy {};
        busy.agc |= kCal;
        const auto current = runAr9565RxAgcCalibration(
            request(), authorization(), backend(busy));
        return current.result == RxAgcResult::AlreadyBusy &&
               !current.requiresReset && busy.writeCount == 0 &&
               current.completedReads == kInitialReads;
    }

    bool testsFailures()
    {
        Mock denied {};
        denied.denied = true;
        const auto unavailable = runAr9565RxAgcCalibration(
            request(), authorization(), backend(denied));
        if (unavailable.result != RxAgcResult::OwnershipLost ||
            unavailable.requiresReset || denied.writeCount != 0)
        {
            return false;
        }
        Mock readFail {};
        readFail.failReadAt = 2;
        const auto failedRead = runAr9565RxAgcCalibration(
            request(), authorization(), backend(readFail));
        if (failedRead.result != RxAgcResult::ReadFailed ||
            failedRead.requiresReset || failedRead.completedWrites != 0 ||
            readFail.writeCount != 0)
        {
            return false;
        }
        Mock writeFail {};
        writeFail.failWriteAt = 1;
        const auto failedWrite = runAr9565RxAgcCalibration(
            request(), authorization(), backend(writeFail));
        if (failedWrite.result != RxAgcResult::WriteFailed ||
            !failedWrite.requiresReset || writeFail.writeCount != 0)
        {
            return false;
        }
        Mock lostEpoch {};
        lostEpoch.revokeAt = kRevokeBeforeThirdWrite;
        const auto revoked = runAr9565RxAgcCalibration(
            request(), authorization(), backend(lostEpoch));
        if (revoked.result != RxAgcResult::OwnershipLost ||
            !revoked.requiresReset || lostEpoch.writeCount != 2)
        {
            return false;
        }
        Mock pollReadFail {};
        pollReadFail.failReadAt = kFailOnSecondPoll;
        const auto brokenPoll = runAr9565RxAgcCalibration(
            request(), authorization(), backend(pollReadFail));
        if (brokenPoll.result != RxAgcResult::ReadFailed ||
            !brokenPoll.requiresReset || brokenPoll.polls != 1)
        {
            return false;
        }
        Mock neverCompletes {};
        neverCompletes.completeAfter = std::numeric_limits<size_t>::max();
        const auto timeout = runAr9565RxAgcCalibration(
            request(), authorization(), backend(neverCompletes));
        return timeout.result == RxAgcResult::Timeout &&
               timeout.requiresReset && timeout.polls == kPollLimit &&
               neverCompletes.delayCount == kPollLimit - 1 &&
               neverCompletes.writeCount == 3 && !neverCompletes.badDelay;
    }

    bool testsIqSuccess()
    {
        Mock mock {};
        const auto result =
            runAr9565RxIqCalibration(request(), authorization(), backend(mock));
        if (result.result != RxIqResult::Ok || result.requiresReset ||
            result.completedWrites != kIqExpectedWrites ||
            result.completedReads != kIqExpectedReads ||
            result.polls != kIqExpectedPolls || result.iCorrection != -2 ||
            result.qCorrection != kIqExpectedQ ||
            mock.iqCorrection != (kIqUnrelated | kIqExpectedCorrected) ||
            mock.iqTiming != kIqLogCount || mock.iqMode != 0 ||
            mock.writeCount != kIqExpectedWrites ||
            mock.delayCount != kIqExpectedDelays || mock.badDelay ||
            mock.writes.at(0).address != kIqTiming ||
            mock.writes.at(0).value != kIqLogCount ||
            mock.writes.at(1).address != kIqCalMode ||
            mock.writes.at(1).value != 0 ||
            mock.writes.at(2).address != kIqTiming ||
            mock.writes.at(2).value != (kIqLogCount | kIqDoCal) ||
            mock.writes.at(3).address != kIqCorr ||
            mock.writes.at(3).value != (kIqUnrelated | kIqExpectedCorrected))
        {
            return false;
        }
        Mock negative {};
        negative.iqCorrelation = kIqNegativeCorrelation;
        const auto reverse = runAr9565RxIqCalibration(
            request(), authorization(), backend(negative));
        return reverse.result == RxIqResult::Ok && reverse.iCorrection == 2 &&
               reverse.qCorrection == kIqExpectedQ;
    }

    bool testsIqPreflight()
    {
        Mock mock {};
        auto auth = authorization();
        auto req = request();
        if (runAr9565RxIqCalibration(req, auth, backend(mock, kIqCalMode))
                .result != RxIqResult::InvalidBar)
        {
            return false;
        }
        mock.iqTiming = kIqDoCal;
        const auto busy = runAr9565RxIqCalibration(req, auth, backend(mock));
        if (busy.result != RxIqResult::AlreadyBusy || busy.requiresReset ||
            mock.writeCount != 0)
        {
            return false;
        }
        req.silicon = Revision::Unknown;
        if (runAr9565RxIqCalibration(req, auth, backend(mock)).result !=
            RxIqResult::InvalidChannel)
        {
            return false;
        }
        req = request();
        auth.radioKillUnblocked = false;
        return runAr9565RxIqCalibration(req, auth, backend(mock)).result ==
                   RxIqResult::MissingAuthorization &&
               mock.writeCount == 0;
    }

    bool testsIqFailures()
    {
        Mock invalid {};
        invalid.iqPowerQ = 0;
        const auto unavailable = runAr9565RxIqCalibration(
            request(), authorization(), backend(invalid));
        if (unavailable.result != RxIqResult::InvalidMeasurement ||
            !unavailable.requiresReset ||
            invalid.writeCount != (kIqExpectedWrites - 1) ||
            invalid.iqCorrection != kIqUnrelated)
        {
            return false;
        }
        Mock saturated {};
        saturated.iqCorrelation = kIqSaturatedCorrelation;
        const auto unsafe = runAr9565RxIqCalibration(request(), authorization(),
                                                     backend(saturated));
        if (unsafe.result != RxIqResult::InvalidMeasurement ||
            !unsafe.requiresReset || saturated.iqCorrection != kIqUnrelated)
        {
            return false;
        }
        Mock stalled {};
        stalled.iqCompleteAfter = std::numeric_limits<size_t>::max();
        const auto timeout = runAr9565RxIqCalibration(
            request(), authorization(), backend(stalled));
        if (timeout.result != RxIqResult::Timeout || !timeout.requiresReset ||
            timeout.polls != kPollLimit ||
            stalled.delayCount != kPollLimit - 1 ||
            stalled.writeCount != kIqExpectedWrites - 1)
        {
            return false;
        }
        Mock writeFail {};
        writeFail.failWriteAt = kIqExpectedWrites;
        const auto failed = runAr9565RxIqCalibration(request(), authorization(),
                                                     backend(writeFail));
        if (failed.result != RxIqResult::WriteFailed || !failed.requiresReset ||
            failed.completedWrites != kIqExpectedWrites - 1)
        {
            return false;
        }
        Mock readFail {};
        readFail.failReadAt = kIqExpectedReads - 1;
        const auto broken = runAr9565RxIqCalibration(request(), authorization(),
                                                     backend(readFail));
        if (broken.result != RxIqResult::ReadFailed || !broken.requiresReset ||
            broken.completedWrites != kIqExpectedWrites - 1)
        {
            return false;
        }
        Mock epochLost {};
        epochLost.revokeAt = kIqRevokeAt;
        const auto revoked = runAr9565RxIqCalibration(
            request(), authorization(), backend(epochLost));
        return revoked.result == RxIqResult::OwnershipLost &&
               revoked.requiresReset && revoked.completedWrites == 2 &&
               epochLost.writeCount == 2;
    }

    bool testsNoiseSuccess()
    {
        Mock primary {};
        const auto sample = runAr9565RxNoiseFloorCalibration(
            request(), authorization(), backend(primary));
        if (sample.result != RxNoiseResult::Ok || sample.requiresReset ||
            sample.controlDbm != kNoiseExpectedControlDbm ||
            sample.extensionDbm != 0 || sample.hasExtension ||
            sample.completedWrites != 1 || sample.completedReads != 4 ||
            sample.polls != 2 || primary.noisePollReads != 2 ||
            primary.delayCount != 1 || primary.writeCount != 1 ||
            primary.badDelay || primary.writes.at(0).address != kAgc ||
            primary.writes.at(0).value !=
                (kFilter | kPeak | kAgcUnrelated | kNoiseCal | kNoiseEnable |
                 kNoiseNoUpdate))
        {
            return false;
        }
        Mock ht40 {};
        auto req = request();
        req.width = ChannelWidth::Ht40;
        req.secondary = kHt40Secondary;
        const auto wide = runAr9565RxNoiseFloorCalibration(req, authorization(),
                                                           backend(ht40));
        return wide.result == RxNoiseResult::Ok && !wide.requiresReset &&
               wide.controlDbm == kNoiseExpectedControlDbm &&
               wide.extensionDbm == kNoiseExpectedExtensionDbm &&
               wide.hasExtension && wide.completedReads == kNoiseWideReads &&
               ht40.writeCount == 1;
    }

    bool testsNoiseAdmission()
    {
        Mock mock {};
        auto req = request();
        auto auth = authorization();
        auto invalidBackend = backend(mock);
        invalidBackend.io.permitWrite = nullptr;
        if (runAr9565RxNoiseFloorCalibration(req, auth, invalidBackend)
                .result != RxNoiseResult::InvalidBackend)
        {
            return false;
        }
        if (runAr9565RxNoiseFloorCalibration(req, auth, backend(mock, kAgc))
                .result != RxNoiseResult::InvalidBar)
        {
            return false;
        }
        req.control.centerMhz = 0;
        if (runAr9565RxNoiseFloorCalibration(req, auth, backend(mock)).result !=
            RxNoiseResult::InvalidChannel)
        {
            return false;
        }
        req = request();
        auth.radioKillUnblocked = false;
        if (runAr9565RxNoiseFloorCalibration(req, auth, backend(mock)).result !=
            RxNoiseResult::MissingAuthorization)
        {
            return false;
        }
        auth = authorization();
        mock.agc |= kCal;
        const auto busy =
            runAr9565RxNoiseFloorCalibration(req, auth, backend(mock));
        if (busy.result != RxNoiseResult::AlreadyBusy || busy.requiresReset ||
            mock.writeCount != 0)
        {
            return false;
        }
        mock.agc &= ~kCal;
        mock.agc |= kNoiseCal;
        const auto noiseBusy =
            runAr9565RxNoiseFloorCalibration(req, auth, backend(mock));
        return noiseBusy.result == RxNoiseResult::AlreadyBusy &&
               !noiseBusy.requiresReset && mock.writeCount == 0;
    }

    bool testsNoiseFailures()
    {
        Mock denied {};
        denied.denied = true;
        const auto unavailable = runAr9565RxNoiseFloorCalibration(
            request(), authorization(), backend(denied));
        if (unavailable.result != RxNoiseResult::OwnershipLost ||
            unavailable.requiresReset || denied.writeCount != 0)
        {
            return false;
        }
        Mock badWrite {};
        badWrite.failWriteAt = 1;
        const auto rejected = runAr9565RxNoiseFloorCalibration(
            request(), authorization(), backend(badWrite));
        if (rejected.result != RxNoiseResult::WriteFailed ||
            !rejected.requiresReset || badWrite.writeCount != 0)
        {
            return false;
        }
        Mock readAfterStart {};
        readAfterStart.failReadAt = 4;
        const auto unreadable = runAr9565RxNoiseFloorCalibration(
            request(), authorization(), backend(readAfterStart));
        if (unreadable.result != RxNoiseResult::ReadFailed ||
            !unreadable.requiresReset || readAfterStart.writeCount != 1)
        {
            return false;
        }
        Mock strong {};
        strong.noiseControl = kNoiseControlAboveLimit;
        const auto invalid = runAr9565RxNoiseFloorCalibration(
            request(), authorization(), backend(strong));
        if (invalid.result != RxNoiseResult::InvalidMeasurement ||
            !invalid.requiresReset || strong.writeCount != 1)
        {
            return false;
        }
        Mock empty {};
        empty.noiseControl = kNoiseSampleZero;
        const auto zero = runAr9565RxNoiseFloorCalibration(
            request(), authorization(), backend(empty));
        if (zero.result != RxNoiseResult::InvalidMeasurement ||
            !zero.requiresReset)
        {
            return false;
        }
        Mock ext {};
        ext.noiseExtension = kNoiseSampleZero;
        auto wide = request();
        wide.width = ChannelWidth::Ht40;
        wide.secondary = kHt40Secondary;
        const auto badExtension = runAr9565RxNoiseFloorCalibration(
            wide, authorization(), backend(ext));
        if (badExtension.result != RxNoiseResult::InvalidMeasurement ||
            !badExtension.requiresReset || badExtension.hasExtension)
        {
            return false;
        }
        Mock staleEpoch {};
        staleEpoch.revokeAt = 4;
        const auto lost = runAr9565RxNoiseFloorCalibration(
            request(), authorization(), backend(staleEpoch));
        if (lost.result != RxNoiseResult::OwnershipLost ||
            !lost.requiresReset || staleEpoch.writeCount != 1)
        {
            return false;
        }
        Mock neverCompletes {};
        neverCompletes.noiseCompleteAfter = std::numeric_limits<size_t>::max();
        const auto timeout = runAr9565RxNoiseFloorCalibration(
            request(), authorization(), backend(neverCompletes));
        return timeout.result == RxNoiseResult::Timeout &&
               timeout.requiresReset && timeout.polls == kPollLimit &&
               neverCompletes.delayCount == kPollLimit - 1 &&
               neverCompletes.writeCount == 1 && !neverCompletes.badDelay;
    }

    bool testsChainsSuccess()
    {
        Mock mock {};
        const auto result = configureAr9565ReceiveOnlyChains(
            {kSingleChain, kSingleChain}, authorization(), backend(mock));
        return result.result == RxChainsResult::Ok && !result.requiresReset &&
               result.completedWrites == kChainCount &&
               result.completedReads == kChainCount &&
               result.lastOffset == kCalMask &&
               mock.writeCount == kChainCount &&
               mock.readCount == kChainCount && mock.selfgen == 0 &&
               mock.receiveMask == kSingleChain &&
               mock.calibrationMask == kSingleChain &&
               mock.writes.at(0).address == kSelfgenMask &&
               mock.writes.at(0).value == 0 &&
               mock.writes.at(1).address == kReceiveMask &&
               mock.writes.at(1).value == kSingleChain &&
               mock.writes.at(2).address == kCalMask &&
               mock.writes.at(2).value == kSingleChain;
    }

    bool testsChainsAdmission()
    {
        Mock mock {};
        const Ar9565BoardChainMasks good {kSingleChain, kSingleChain};
        auto io = backend(mock);
        io.io.write32 = nullptr;
        if (configureAr9565ReceiveOnlyChains(good, authorization(), io)
                .result != RxChainsResult::InvalidBackend)
        {
            return false;
        }
        if (configureAr9565ReceiveOnlyChains({0, kSingleChain}, authorization(),
                                             backend(mock))
                    .result != RxChainsResult::InvalidBoard ||
            configureAr9565ReceiveOnlyChains({kSingleChain, 0}, authorization(),
                                             backend(mock))
                    .result != RxChainsResult::InvalidBoard)
        {
            return false;
        }
        auto auth = authorization();
        auth.radioKillUnblocked = false;
        if (configureAr9565ReceiveOnlyChains(good, auth, backend(mock))
                .result != RxChainsResult::MissingAuthorization)
        {
            return false;
        }
        auth = authorization();
        auth.use = RadioInitialization::TransmitReceive;
        if (configureAr9565ReceiveOnlyChains(good, auth, backend(mock))
                .result != RxChainsResult::MissingAuthorization)
        {
            return false;
        }
        if (configureAr9565ReceiveOnlyChains(good, authorization(),
                                             backend(mock, kCalMask))
                .result != RxChainsResult::InvalidBar)
        {
            return false;
        }
        return mock.writeCount == 0 && mock.readCount == 0;
    }

    bool testsChainsFailures()
    {
        const Ar9565BoardChainMasks board {kSingleChain, kSingleChain};
        Mock denied {};
        denied.denied = true;
        const auto unavailable = configureAr9565ReceiveOnlyChains(
            board, authorization(), backend(denied));
        if (unavailable.result != RxChainsResult::OwnershipLost ||
            unavailable.requiresReset || denied.writeCount != 0)
        {
            return false;
        }
        Mock writeError {};
        writeError.failWriteAt = 2;
        const auto rejected = configureAr9565ReceiveOnlyChains(
            board, authorization(), backend(writeError));
        if (rejected.result != RxChainsResult::WriteFailed ||
            !rejected.requiresReset || rejected.completedWrites != 1 ||
            writeError.selfgen != 0)
        {
            return false;
        }
        Mock readError {};
        readError.failReadAt = 2;
        const auto unreadable = configureAr9565ReceiveOnlyChains(
            board, authorization(), backend(readError));
        if (unreadable.result != RxChainsResult::ReadFailed ||
            !unreadable.requiresReset || unreadable.completedWrites != 2 ||
            readError.selfgen != 0)
        {
            return false;
        }
        Mock ignoredWrite {};
        ignoredWrite.ignoreWriteTo = kReceiveMask;
        const auto mismatch = configureAr9565ReceiveOnlyChains(
            board, authorization(), backend(ignoredWrite));
        if (mismatch.result != RxChainsResult::ReadbackMismatch ||
            !mismatch.requiresReset || mismatch.completedWrites != 2 ||
            ignoredWrite.selfgen != 0 || ignoredWrite.calibrationMask != 0)
        {
            return false;
        }
        Mock revoked {};
        revoked.revokeAt = kRevokeBeforeThirdChainWrite;
        const auto lost = configureAr9565ReceiveOnlyChains(
            board, authorization(), backend(revoked));
        return lost.result == RxChainsResult::OwnershipLost &&
               lost.requiresReset && lost.completedWrites == 2 &&
               revoked.selfgen == 0 && revoked.calibrationMask == 0;
    }

    bool testsWorkflowSuccess()
    {
        Mock mock {};
        const Ar9565BoardChainMasks board {kSingleChain, kSingleChain};
        const auto progress = runAr9565ReceiveOnlyCalibration(
            request(), board, authorization(), backend(mock));
        if (progress.phase != RxCalibrationPhase::Completed ||
            progress.requiresReset ||
            progress.chains.result != RxChainsResult::Ok ||
            progress.agc.result != RxAgcResult::Ok ||
            progress.iq.result != RxIqResult::Ok ||
            progress.noise.result != RxNoiseResult::Ok ||
            progress.noise.controlDbm != kNoiseExpectedControlDbm ||
            progress.noise.hasExtension || mock.writeCount != kWorkflowWrites ||
            mock.readCount != kWorkflowReads || mock.selfgen != 0 ||
            mock.receiveMask != kSingleChain ||
            mock.calibrationMask != kSingleChain || mock.badDelay ||
            mock.writes.at(0).address != kSelfgenMask ||
            mock.writes.at(kWorkflowWrites - 1).address != kAgc)
        {
            return false;
        }
        Mock ht40 {};
        auto wide = request();
        wide.width = ChannelWidth::Ht40;
        wide.secondary = kHt40Secondary;
        const auto band = runAr9565ReceiveOnlyCalibration(
            wide, board, authorization(), backend(ht40));
        return band.phase == RxCalibrationPhase::Completed &&
               !band.requiresReset && band.noise.hasExtension &&
               band.noise.extensionDbm == kNoiseExpectedExtensionDbm &&
               ht40.writeCount == kWorkflowWrites;
    }

    bool testsWorkflowFailures()
    {
        const Ar9565BoardChainMasks board {kSingleChain, kSingleChain};
        Mock invalid {};
        const auto noBoard = runAr9565ReceiveOnlyCalibration(
            request(), {0, kSingleChain}, authorization(), backend(invalid));
        if (noBoard.phase != RxCalibrationPhase::ChainMasks ||
            noBoard.chains.result != RxChainsResult::InvalidBoard ||
            noBoard.requiresReset || invalid.writeCount != 0)
        {
            return false;
        }
        Mock badChannel {};
        auto req = request();
        req.control.centerMhz = 0;
        const auto tuning = runAr9565ReceiveOnlyCalibration(
            req, board, authorization(), backend(badChannel));
        if (tuning.phase != RxCalibrationPhase::AgcOffset ||
            tuning.agc.result != RxAgcResult::InvalidChannel ||
            !tuning.requiresReset || badChannel.writeCount != kChainCount)
        {
            return false;
        }
        Mock revoke {};
        revoke.revokeAt = kWorkflowRevokeAfterMasks;
        const auto lost = runAr9565ReceiveOnlyCalibration(
            request(), board, authorization(), backend(revoke));
        if (lost.phase != RxCalibrationPhase::AgcOffset ||
            lost.agc.result != RxAgcResult::OwnershipLost ||
            !lost.requiresReset || revoke.writeCount != kChainCount)
        {
            return false;
        }
        Mock invalidIq {};
        invalidIq.iqPowerQ = 0;
        const auto iq = runAr9565ReceiveOnlyCalibration(
            request(), board, authorization(), backend(invalidIq));
        if (iq.phase != RxCalibrationPhase::IqCorrection ||
            iq.iq.result != RxIqResult::InvalidMeasurement ||
            !iq.requiresReset ||
            invalidIq.writeCount != kWorkflowBeforeIqCorrectionWriteCount)
        {
            return false;
        }
        Mock invalidNoise {};
        invalidNoise.noiseControl = kNoiseSampleZero;
        const auto noise = runAr9565ReceiveOnlyCalibration(
            request(), board, authorization(), backend(invalidNoise));
        if (noise.phase != RxCalibrationPhase::NoiseFloor ||
            noise.noise.result != RxNoiseResult::InvalidMeasurement ||
            !noise.requiresReset || invalidNoise.writeCount != kWorkflowWrites)
        {
            return false;
        }
        Mock failedAgcWrite {};
        failedAgcWrite.failWriteAt = kWorkflowBeforeIqWriteCount;
        const auto stalled = runAr9565ReceiveOnlyCalibration(
            request(), board, authorization(), backend(failedAgcWrite));
        return stalled.phase == RxCalibrationPhase::AgcOffset &&
               stalled.agc.result == RxAgcResult::WriteFailed &&
               stalled.requiresReset &&
               failedAgcWrite.writeCount == kWorkflowBeforeIqWriteCount - 1;
    }

    bool testsRfKillSuccess()
    {
        const RfKillBoardConfiguration board {true, kRfKillTestPin, true};
        Mock unblocked {};
        const auto clear = sampleAr9565RfKill(board, rfkillBackend(unblocked));
        if (clear.result != RfKillResult::Unblocked || clear.hardwareBlocked ||
            clear.requiresReset || clear.completedWrites != 1 ||
            clear.completedReads != kRfKillReads ||
            clear.gpio != kRfKillTestPin ||
            unblocked.gpioDirection != kRfKillInputDirection ||
            unblocked.writes.at(0).address != kRfKillGpioDirection ||
            unblocked.writes.at(0).value != kRfKillInputDirection ||
            unblocked.rfkillDelays != 1 || unblocked.badDelay)
        {
            return false;
        }
        Mock blocked {};
        blocked.gpioInput = kRfKillInputHigh;
        const auto denied = sampleAr9565RfKill(board, rfkillBackend(blocked));
        if (denied.result != RfKillResult::Blocked || !denied.hardwareBlocked ||
            denied.requiresReset || blocked.rfkillDelays != 1)
        {
            return false;
        }
        Mock inverse {};
        inverse.gpioInput = kRfKillInputHigh;
        inverse.gpioDirection = kRfKillInputDirection;
        const auto activeLow = sampleAr9565RfKill({true, kRfKillTestPin, false},
                                                  rfkillBackend(inverse));
        return activeLow.result == RfKillResult::Unblocked &&
               !activeLow.hardwareBlocked && activeLow.completedWrites == 0 &&
               activeLow.completedReads == kRfKillReads &&
               inverse.rfkillDelays == 1;
    }

    bool testsRfKillAdmission()
    {
        Mock mock {};
        const RfKillBoardConfiguration board {true, kRfKillTestPin, true};
        auto io = rfkillBackend(mock);
        io.permitMmio = nullptr;
        if (sampleAr9565RfKill(board, io).result !=
            RfKillResult::InvalidBackend)
        {
            return false;
        }
        if (sampleAr9565RfKill({false, kRfKillTestPin, true},
                               rfkillBackend(mock))
                    .result != RfKillResult::NotConfigured ||
            sampleAr9565RfKill({true, kRfKillInvalidPin, true},
                               rfkillBackend(mock))
                    .result != RfKillResult::InvalidGpio ||
            sampleAr9565RfKill(board, rfkillBackend(mock, kRfKillGpioDirection))
                    .result != RfKillResult::InvalidBar)
        {
            return false;
        }
        return mock.writeCount == 0 && mock.readCount == 0;
    }

    bool testsRfKillFailures()
    {
        const RfKillBoardConfiguration board {true, kRfKillTestPin, true};
        Mock denied {};
        denied.denied = true;
        const auto unavailable =
            sampleAr9565RfKill(board, rfkillBackend(denied));
        if (unavailable.result != RfKillResult::OwnershipLost ||
            !unavailable.hardwareBlocked || unavailable.requiresReset ||
            denied.writeCount != 0)
        {
            return false;
        }
        Mock failedWrite {};
        failedWrite.failWriteAt = 1;
        const auto failed =
            sampleAr9565RfKill(board, rfkillBackend(failedWrite));
        if (failed.result != RfKillResult::WriteFailed ||
            !failed.requiresReset || !failed.hardwareBlocked ||
            failedWrite.writeCount != 0)
        {
            return false;
        }
        Mock lostEpoch {};
        lostEpoch.revokeAt = 3;
        const auto lost = sampleAr9565RfKill(board, rfkillBackend(lostEpoch));
        if (lost.result != RfKillResult::OwnershipLost || !lost.requiresReset ||
            lostEpoch.writeCount != 1)
        {
            return false;
        }
        Mock ignored {};
        ignored.ignoreWriteTo = kRfKillGpioDirection;
        const auto mismatch = sampleAr9565RfKill(board, rfkillBackend(ignored));
        if (mismatch.result != RfKillResult::ReadbackMismatch ||
            !mismatch.requiresReset ||
            ignored.gpioDirection != kRfKillDirectionInitial)
        {
            return false;
        }
        Mock failingRead {};
        failingRead.failReadAt = 3;
        const auto unreadable =
            sampleAr9565RfKill(board, rfkillBackend(failingRead));
        if (unreadable.result != RfKillResult::ReadFailed ||
            !unreadable.requiresReset || !unreadable.hardwareBlocked ||
            failingRead.writeCount != 1)
        {
            return false;
        }
        Mock unstable {};
        unstable.changeGpioOnSecondSample = true;
        const auto fluctuating =
            sampleAr9565RfKill(board, rfkillBackend(unstable));
        return fluctuating.result == RfKillResult::Unstable &&
               fluctuating.requiresReset && fluctuating.hardwareBlocked &&
               unstable.rfkillDelays == 1 && unstable.gpioInputReads == 2;
    }

    bool testsRfKillRuntime()
    {
        const RfKillBoardConfiguration board {true, kRfKillTestPin, true};
        Mock clear {};
        const auto allowed =
            observeAr9565RfKill(board, rfkillReadBackend(clear));
        if (allowed.result != RfKillResult::Unblocked ||
            allowed.hardwareBlocked || allowed.completedReads != 2 ||
            allowed.completedWrites != 0 || allowed.requiresReset ||
            clear.writeCount != 0 || clear.rfkillDelays != 1 ||
            clear.gpioDirection != kRfKillDirectionInitial)
        {
            return false;
        }
        Mock blocked {};
        blocked.gpioInput = kRfKillInputHigh;
        if (observeAr9565RfKill(board, rfkillReadBackend(blocked)).result !=
                RfKillResult::Blocked ||
            observeAr9565RfKill({false, kRfKillTestPin, true},
                                rfkillReadBackend(blocked))
                    .result != RfKillResult::NotConfigured)
        {
            return false;
        }
        Mock changing {};
        changing.changeGpioOnSecondSample = true;
        if (observeAr9565RfKill(board, rfkillReadBackend(changing)).result !=
                RfKillResult::Unstable ||
            changing.writeCount != 0)
        {
            return false;
        }
        Mock reversed {};
        reversed.gpioInput = kRfKillInputHigh;
        if (observeAr9565RfKill({true, kRfKillTestPin, false},
                                rfkillReadBackend(reversed))
                .result != RfKillResult::Unblocked)
        {
            return false;
        }
        Mock denied {};
        denied.revokeAt = 3;
        if (observeAr9565RfKill(board, rfkillReadBackend(denied)).result !=
                RfKillResult::OwnershipLost ||
            denied.readCount != 1 || denied.writeCount != 0)
        {
            return false;
        }
        Mock badRead {};
        badRead.failReadAt = 2;
        if (observeAr9565RfKill(board, rfkillReadBackend(badRead)).result !=
                RfKillResult::ReadFailed ||
            observeAr9565RfKill({true, kRfKillInvalidPin, true},
                                rfkillReadBackend(badRead))
                    .result != RfKillResult::InvalidGpio ||
            observeAr9565RfKill(board,
                                rfkillReadBackend(badRead, kRfKillGpioInput))
                    .result != RfKillResult::InvalidBar ||
            badRead.writeCount != 0)
        {
            return false;
        }
        auto invalid = rfkillReadBackend(badRead);
        invalid.permitRead = nullptr;
        return observeAr9565RfKill(board, invalid).result ==
               RfKillResult::InvalidBackend;
    }

} // namespace

int main()
{
    if (!testsSuccess())
    {
        return 1;
    }
    if (!testsAdmission())
    {
        return 2;
    }
    if (!testsFailures())
    {
        return 3;
    }
    if (!testsIqSuccess())
    {
        return 4;
    }
    if (!testsIqPreflight())
    {
        return kFailedIqPreflightExit;
    }
    if (!testsIqFailures())
    {
        return kFailedIqFailuresExit;
    }
    if (!testsNoiseSuccess())
    {
        return kFailedNoiseSuccessExit;
    }
    if (!testsNoiseAdmission())
    {
        return kFailedNoiseAdmissionExit;
    }
    if (!testsNoiseFailures())
    {
        return kFailedNoiseFailureExit;
    }
    if (!testsChainsSuccess())
    {
        return kFailedChainsSuccessExit;
    }
    if (!testsChainsAdmission())
    {
        return kFailedChainsAdmissionExit;
    }
    if (!testsChainsFailures())
    {
        return kFailedChainsFailuresExit;
    }
    if (!testsWorkflowSuccess())
    {
        return kFailedWorkflowSuccessExit;
    }
    if (!testsWorkflowFailures())
    {
        return kFailedWorkflowFailuresExit;
    }
    if (!testsRfKillSuccess())
    {
        return kFailedRfKillSuccessExit;
    }
    if (!testsRfKillAdmission())
    {
        return kFailedRfKillAdmissionExit;
    }
    if (!testsRfKillFailures())
    {
        return kFailedRfKillFailuresExit;
    }
    if (!testsRfKillRuntime())
    {
        return kFailedRfKillRuntimeExit;
    }
    return 0;
}
