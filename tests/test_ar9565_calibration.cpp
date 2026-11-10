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
            uint32_t iqTiming = 0;
            uint32_t iqMode = kIqUnrelated;
            uint32_t iqPowerI = kIqSampleI;
            uint32_t iqPowerQ = kIqSampleQ;
            uint32_t iqCorrelation = kIqSampleCorrelation;
            uint32_t iqCorrection = kIqUnrelated;
            std::array<Write, kIqExpectedWrites> writes {};
            size_t writeCount = 0;
            size_t readCount = 0;
            size_t permitCount = 0;
            size_t pollReads = 0;
            size_t delayCount = 0;
            size_t completeAfter = 3;
            size_t iqPollReads = 0;
            size_t iqCompleteAfter = kIqExpectedPolls;

            size_t failReadAt = 0;
            size_t failWriteAt = 0;
            size_t revokeAt = 0;
            bool triggered = false;
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
        if (address == kAgc && mock.triggered)
        {
            ++mock.pollReads;
            if (mock.pollReads >= mock.completeAfter)
            {
                mock.agc &= ~kCal;
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
        *reg(mock, address) = value;
        if (address == kAgc)
        {
            mock.triggered = true;
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
        if (micros != kDelay)
        {
            mock.badDelay = true;
        }
        ++mock.delayCount;
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
    return 0;
}
