// Factory signatures and option byte offsets independently checked against
// Intel 25G332 corecapture + IO80211Family symbols and option consumers.
#include "TahoeCapture.hpp"
#include "TahoeControllerABI.hpp"
#include <IOKit/IOService.h>
#include <IOKit/IOWorkLoop.h>
#include <libkern/c++/OSObject.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace
{
    // The native methods are called directly with their exact x86_64 member
    // ABI (explicit first this argument), without synthesizing CC* vtables or
    // allocating objects of incomplete/legacy SDK class sizes.
    extern "C" OSObject *captureCreatePipe(
        IOService *, const char *, const char *,
        const void
            *) __asm__("__ZN6CCPipe21withOwnerNameCapacityEP9IOServicePKcS3_"
                       "PK13CCPipeOptions");
    extern "C" bool
    captureStartPipe(OSObject *) __asm__("__ZN6CCPipe9startPipeEv");
    extern "C" void
    captureStopPipe(OSObject *) __asm__("__ZN6CCPipe8stopPipeEv");
    extern "C" OSObject *
    captureCreateStream(OSObject *, const char *, const void *) __asm__(
        "__ZN8CCStream15withPipeAndNameEP6CCPipePKcPK15CCStreamOptions");
    extern "C" OSObject *
    captureCreateFaultReporter(OSObject *, IOWorkLoop *) __asm__(
        "__"
        "ZN15CCFaultReporter18withStreamWorkloopEP12CCDataStreamP10IOWorkLoop");
    extern "C" OSObject *wirelessCreateFaultReporter(OSObject *) __asm__(
        "__ZN20IO80211FaultReporter15allocWithParamsEP15CCFaultReporter");

    constexpr size_t kPipeOptionsBytes = 0x350;
    constexpr size_t kStreamOptionsBytes = 0x358;
    constexpr size_t kPipeKindOffset = 0;
    constexpr size_t kPipeDataKindOffset = 8;
    constexpr size_t kPipeSizeOffset = 0x10;
    constexpr size_t kPipeNotifySizeOffset = 0x18;
    constexpr size_t kPipeNotifyTimeOffset = 0x20;
    constexpr size_t kPipeFilenameOffset = 0x24;
    constexpr size_t kPipeNameOffset = 0x124;
    constexpr size_t kPipeDirectoryOffset = 0x244;
    constexpr size_t kStreamKindOffset = 0;
    constexpr uint64_t kLogPipe = 0;
    constexpr uint64_t kSnapshotPipe = 0x200000001ULL;
    constexpr uint64_t kDriverLogData = 1;
    constexpr uint64_t kPacketLogData = 0;
    constexpr uint64_t kSnapshotData = 2;
    constexpr uint64_t kLogCapacity = 1024ULL * 1024ULL;
    constexpr uint64_t kSnapshotCapacity = 128;
    constexpr uint64_t kNotificationBytes = kLogCapacity / 2;
    constexpr uint32_t kNotificationMilliseconds = 1000;
    constexpr char kBundleId[] = "dev.alberto.SimpleATH";

    template <size_t N, typename Value>
    void store(uint8_t (&buffer)[N], size_t offset, Value value)
    {
        if (offset <= N && sizeof(value) <= N - offset)
        {
            memcpy(&buffer[offset], &value, sizeof(value));
        }
    }

    template <size_t N, size_t M>
    void storeText(uint8_t (&buffer)[N], size_t offset, const char (&text)[M])
    {
        if (offset <= N && M <= N - offset)
        {
            memcpy(&buffer[offset], &text[0], M);
        }
    }

    template <typename Native> Native *borrow(OSObject *object)
    {
        // All imported native classes have the same single-inheritance
        // OSObject prefix and pointer representation on the target x86_64 ABI.
        Native *out = nullptr;
        using NativePointer = Native *;
        using ObjectPointer = OSObject *;
        static_assert(sizeof(NativePointer) == sizeof(ObjectPointer),
                      "native pointer width");
        memcpy(static_cast<void *>(&out), static_cast<const void *>(&object),
               sizeof(NativePointer));
        return out;
    }

    void release(OSObject *&object)
    {
        if (object != nullptr)
        {
            const OSObject *retired = object;
            object = nullptr;
            retired->release();
        }
    }

    OSObject *makePipe(IOService *owner, const char *name, uint64_t kind,
                       uint64_t dataKind, uint64_t capacity)
    {
        alignas(uint64_t) uint8_t options[kPipeOptionsBytes] {};
        store(options, kPipeKindOffset, kind);
        store(options, kPipeDataKindOffset, dataKind);
        store(options, kPipeSizeOffset, capacity);
        if (kind == kLogPipe)
        {
            store(options, kPipeNotifySizeOffset, kNotificationBytes);
            store(options, kPipeNotifyTimeOffset, kNotificationMilliseconds);
        }
        storeText(options, kPipeFilenameOffset, "SimpleATH");
        storeText(options, kPipeNameOffset, "wlan");
        storeText(options, kPipeDirectoryOffset, "WiFi");
        OSObject *pipe =
            captureCreatePipe(owner, &kBundleId[0], name, &options[0]);
        if (pipe != nullptr && pipe->metaCast("CCPipe") == nullptr)
        {
            release(pipe);
        }
        return pipe;
    }

    OSObject *makeStream(OSObject *pipe, const char *name, uint64_t kind,
                         const char *requiredClass)
    {
        alignas(uint64_t) uint8_t options[kStreamOptionsBytes] {};
        store(options, kStreamKindOffset, kind);
        OSObject *stream = captureCreateStream(pipe, name, &options[0]);
        if (stream != nullptr && stream->metaCast(requiredClass) == nullptr)
        {
            release(stream);
        }
        return stream;
    }

    void retirePipe(OSObject *&pipe, bool &started)
    {
        if (started)
        {
            started = false;
            captureStopPipe(pipe);
        }
        release(pipe);
    }
} // namespace

namespace simpleath
{
    namespace tahoe
    {
        bool TahoeCapture::start(IOService *owner, IOWorkLoop *loop)
        {
            // A second start cannot replace resources borrowed by IO80211.
            if (owner == nullptr || loop == nullptr || driverPipe_ != nullptr)
            {
                return false;
            }
            owner->setProperty("SimpleATHCaptureStage", "DriverPipe");
            driverPipe_ = makePipe(owner, "DriverLogs", kLogPipe,
                                   kDriverLogData, kLogCapacity);
            if (driverPipe_ != nullptr)
            {
                driverStarted_ = captureStartPipe(driverPipe_);
            }
            if (!driverStarted_)
            {
                stop();
                return false;
            }
            owner->setProperty("SimpleATHCaptureStage", "Logger");
            logger_ = makeStream(driverPipe_, "SimpleATH", 0, "CCLogStream");
            owner->setProperty("SimpleATHCaptureStage", "DataPipe");
            dataPipe_ = makePipe(owner, "DatapathEvents", kLogPipe,
                                 kPacketLogData, kLogCapacity);
            if (dataPipe_ != nullptr)
            {
                dataStarted_ = captureStartPipe(dataPipe_);
            }
            if (logger_ == nullptr || !dataStarted_)
            {
                stop();
                return false;
            }
            owner->setProperty("SimpleATHCaptureStage", "SnapshotsPipe");
            snapshotsPipe_ = makePipe(owner, "StateSnapshots", kSnapshotPipe,
                                      kSnapshotData, kSnapshotCapacity);
            if (snapshotsPipe_ != nullptr)
            {
                snapshotsStarted_ = captureStartPipe(snapshotsPipe_);
            }
            if (!snapshotsStarted_)
            {
                stop();
                return false;
            }
            owner->setProperty("SimpleATHCaptureStage", "FaultStream");
            faultStream_ =
                makeStream(snapshotsPipe_, "FaultReporter", 1, "CCDataStream");
            if (faultStream_ != nullptr)
            {
                owner->setProperty("SimpleATHCaptureStage",
                                   "CoreFaultReporter");
                coreFaultReporter_ =
                    captureCreateFaultReporter(faultStream_, loop);
            }
            if (coreFaultReporter_ != nullptr &&
                coreFaultReporter_->metaCast("CCFaultReporter") != nullptr)
            {
                owner->setProperty("SimpleATHCaptureStage",
                                   "WirelessFaultReporter");
                faultReporter_ =
                    wirelessCreateFaultReporter(coreFaultReporter_);
            }
            if (faultReporter_ == nullptr ||
                faultReporter_->metaCast("CommonFaultReporter") == nullptr)
            {
                stop();
                return false;
            }
            owner->setProperty("SimpleATHCaptureStage", "Ready");
            return true;
        }

        void TahoeCapture::stop()
        {
            // Consumers release before their streams, streams before pipes,
            // and pipes before the controller releases its native work queue.
            release(faultReporter_);
            release(coreFaultReporter_);
            release(faultStream_);
            release(logger_);
            retirePipe(snapshotsPipe_, snapshotsStarted_);
            retirePipe(dataPipe_, dataStarted_);
            retirePipe(driverPipe_, driverStarted_);
        }

        CCLogStream *TahoeCapture::logger() const
        {
            return borrow<CCLogStream>(logger_);
        }

        CommonFaultReporter *TahoeCapture::faultReporter() const
        {
            return borrow<CommonFaultReporter>(faultReporter_);
        }

        bool TahoeCapture::pipes(CCPipe **logs, CCPipe **data,
                                 CCPipe **snapshots) const
        {
            // Native getDriverTextLog requests only logs; other native
            // consumers request only a snapshot or event pipe. Null outputs
            // are optional, never a reason to withhold a requested pipe.
            if ((logs == nullptr && data == nullptr && snapshots == nullptr) ||
                (logs != nullptr && (logs == data || logs == snapshots)) ||
                (data != nullptr && data == snapshots))
            {
                return false;
            }
            if (logs != nullptr)
            {
                *logs = borrow<CCPipe>(driverPipe_);
            }
            if (data != nullptr)
            {
                *data = borrow<CCPipe>(dataPipe_);
            }
            if (snapshots != nullptr)
            {
                *snapshots = borrow<CCPipe>(snapshotsPipe_);
            }
            return logger_ != nullptr && faultReporter_ != nullptr;
        }
    } // namespace tahoe
} // namespace simpleath
