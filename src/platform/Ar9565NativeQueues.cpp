// Linux-derived descriptor format/constants retain their upstream notice.
/*
 * Copyright (c) 2008-2011 Atheros Communications Inc.
 * Copyright (c) 2010-2011 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
// Reference SHA-256:
// ar9003_mac.c:
// a99f8fb18052510161232331e5fc98757619713e6f2ad69d1897f77597c0188b
// ar9003_mac.h:
// 47ada2b3a635aaf3cadb7b9f93bbff676da27bdc566e4a332124f21bbf0c7461
// mac.c: 58267e6ca24c00e4fe0b15bdbbbe9b708c0a8e5dc9a1865f3e94a64225df3b9f
// reg.h: 629a6df177d63b2a99202ab97a3641c488b5f1ac738f6f15612c7b4ebacebade
// hw.c: 8d06b4a22733dedd2d2a46247128f254b9345efae659de14189a8c2c0fd4731f
// mac.h:
// 10025cb48d6443f8c21a841326742562b6394a6df820c1499a5370f059ed9cd9
#include "Ar9565NativeQueues.hpp"
#include "../hardware/Ar9003Descriptors.hpp"
#include "../hardware/Ar9003TxControl.hpp"
#include "../hardware/Ar9565Core.hpp"
#include "../hardware/Ar9565MacControl.hpp"
#include "KernelPlacementNew.hpp"
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IODMACommand.h>
#include <IOKit/IOInterruptEventSource.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOMapper.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOReturn.h>
#include <IOKit/IOService.h>
#include <IOKit/IOTypes.h>
#include <IOKit/IOWorkLoop.h>
#include <kern/task.h>
#include <libkern/OSTypes.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifndef __x86_64__
#error Native coherent AR9565 queues require the Intel DMA coherency contract
#endif

namespace simpleath
{
    namespace
    {
        constexpr uint32_t kTxSlots = 32;
        constexpr uint32_t kRxSlots = 16;
        constexpr uint32_t kBufferStride = 4096;
        constexpr uint32_t kReceiveBytes = 3072;
        constexpr uint32_t kIer = 0x0024, kIsr = 0x0080, kImr = 0x00a0;
        constexpr uint32_t kIsrS0 = 0x0084, kIsrS1 = 0x0088;
        constexpr uint32_t kImrS0 = 0x00a4, kImrS1 = 0x00a8, kImrS2 = 0x00ac;
        constexpr uint32_t kRxBackpressure = 0x0018, kRxFifo = 0x8114;
        constexpr uint32_t kQcuCbr = 0x08c0, kQcuReady = 0x0900;
        constexpr uint32_t kQcuMisc = 0x09c0, kDcuMask = 0x1000;
        constexpr uint32_t kDcuIfs = 0x1040, kDcuRetry = 0x1080;
        constexpr uint32_t kDcuChannelTime = 0x10c0, kDcuMisc = 0x1100;
        constexpr uint32_t kReceiveControl = 0x0008;
        constexpr uint32_t kTxConfiguration = 0x0030, kRxConfiguration = 0x0034;
        constexpr uint32_t kReceiveSize = 0x0060;
        constexpr uint32_t kHighReceivePointer = 0x0074,
                           kLowReceivePointer = 0x0078;
        constexpr uint32_t kStatusStart = 0x0830, kStatusEnd = 0x0834;
        constexpr uint32_t kTxPointer = 0x0800, kTxEnable = 0x0840,
                           kTxDisable = 0x0880;
        constexpr uint32_t kAsyncMask = 0x4030, kAsyncCause = 0x4038,
                           kAsyncEnable = 0x403c;
        constexpr uint32_t kSyncCause = 0x4028, kSyncMask = 0x4034,
                           kSyncEnable = 0x402c;
        constexpr uint32_t kMacInterrupt = 2;
        constexpr uint32_t kInterruptMask =
            0x00000d77; // RX HP/LP/errors/EOL/overrun + TX
                        // OK/error/EOL/underrun.
        constexpr uint32_t kFatalSync = 0x00003060;
        constexpr uint32_t kDiagnostic = 0x8048;
        constexpr uint32_t kReceiveBlock = 0x02000020;
        constexpr uint32_t kDone = 1;
        constexpr uint32_t kRxMore = 0x1000;
        constexpr uint64_t kPhysical32BitBufferMask = 0x00000000fffff000ULL;
        constexpr uint64_t kAbove32BitBusAddress =
            static_cast<uint64_t>(UINT32_MAX) + 1U;
        constexpr uint32_t kHostBusAddressWidth = 32U;
        constexpr uint32_t kIovaSegmentProbeCount = 2U;
        constexpr uint32_t kMinimumQueueBar = 0x9000U;
        constexpr int kMaximumInterruptCandidates = 32;
        constexpr uint32_t kAtherosQcuCount = 10U;
        constexpr uint32_t kFrameReceiveConfigurationMask = 7U;
        constexpr uint32_t kFrameReceiveConfiguration = 5U;
        constexpr uint32_t kReceiveBackpressureMask = 0x3f0fU;
        constexpr uint32_t kReceiveBackpressureValue = 0x101U;
        constexpr uint32_t kReceiveFifoValue = 0x200U;
        constexpr uint32_t kDefaultDcuIfs = 15U | (1023U << 10U) | (2U << 20U);
        constexpr uint32_t kDefaultDcuRetry = 10U | (32U << 8U) | (32U << 14U);
        constexpr uint32_t kDefaultDcuMisc = 0x1102U;
        constexpr uint32_t kDefaultQcuMisc = 0x800U;
        constexpr uint32_t kDefaultImrS1 = 0x00010001U;
        constexpr size_t kMinimumMpduBytes = 10U;
        constexpr size_t kMaximumMpduBytes = 2342U;
        constexpr size_t kTxDescriptorControlWord = 10U;
        constexpr uint32_t kTxDescriptorIdShift = 16U;
        constexpr uint32_t kRxStatusDoneWord = 11U;
        constexpr uint32_t kTxStatusDoneWord = 8U;
        constexpr uint32_t kTxStatusIdentifierWord = 1U;

        // Coherent buffer zeroing must precede DMA publication or release.
        void clearPublishedBytes(void *memory, size_t size)
        {
            __builtin_memset(memory, 0, size);
            __sync_synchronize();
        }

        // Persistent coherent storage for descriptors/status and packet slots.
        // Reject DMA bounce storage: hardware and CPU must see the same bytes
        // while the ring is live. IODMACommand still supplies the device IOVA.
        struct CoherentRegion
        {
                IOBufferMemoryDescriptor *buffer {nullptr};
                IODMACommand *command {nullptr};
                IOMapper *mapper {nullptr};
                uint8_t *cpu {nullptr};
                uint32_t bus {0};
                uint32_t length {0};
                bool bufferPrepared {false};
                bool commandPrepared {false};
        };

        IOReturn prepareCoherentRegion(CoherentRegion &region, IOService *pci,
                                       uint32_t bytes)
        {
            region.mapper = IOMapper::copyMapperForDevice(pci);
            if (region.mapper == nullptr)
            {
                // XNU permits region.command-generated 32-bit DMA addresses
                // without an IOMMU. Do not substitute the global region.mapper
                // when a device mapping is missing on an IOMMU system.
                IOMapper::checkForSystemMapper();
                if ((IOMapper::gSystem != nullptr) ||
                    (pci->getProperty("iommu-parent") != nullptr))
                {
                    return kIOReturnNotReady;
                }
            }
            region.length = bytes;
            region.buffer = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(
                kernel_task,
                static_cast<IOOptionBits>(kIODirectionInOut) |
                    static_cast<IOOptionBits>(kIOMemoryPhysicallyContiguous),
                bytes, kPhysical32BitBufferMask);
            if ((region.buffer == nullptr) ||
                (region.buffer->getBytesNoCopy() == nullptr))
            {
                return kIOReturnNoMemory;
            }
            region.cpu =
                static_cast<uint8_t *>(region.buffer->getBytesNoCopy());
            clearPublishedBytes(region.cpu, bytes);
            IOReturn result = region.buffer->prepare(kIODirectionInOut);
            if (result != kIOReturnSuccess)
            {
                return result;
            }
            region.bufferPrepared = true;
            region.command = IODMACommand::withSpecification(
                IODMACommand::OutputHost32, kHostBusAddressWidth, bytes,
                IODMACommand::kMapped, bytes, kBufferStride, region.mapper);
            if (region.command == nullptr)
            {
                return kIOReturnNoMemory;
            }
            result = region.command->setMemoryDescriptor(region.buffer, false);
            if (result != kIOReturnSuccess)
            {
                return result;
            }
            result = region.command->prepare(0, bytes, true, false);
            if (result != kIOReturnSuccess)
            {
                return result;
            }
            region.commandPrepared = true;
            if (region.command->getIOMemoryDescriptor() != region.buffer)
            {
                return kIOReturnUnsupported;
            }
            UInt64 offset = 0;
            UInt32 count = kIovaSegmentProbeCount;
            IODMACommand::Segment32 segments[kIovaSegmentProbeCount] {};
            result = region.command->gen32IOVMSegments(&offset, &segments[0],
                                                       &count);
            if (result != kIOReturnSuccess)
            {
                return result;
            }
            if (count != 1 || offset != bytes || segments[0].fLength != bytes ||
                (segments[0].fIOVMAddr == 0U) ||
                ((segments[0].fIOVMAddr & (kBufferStride - 1)) != 0U) ||
                static_cast<uint64_t>(segments[0].fIOVMAddr) + bytes >
                    kAbove32BitBusAddress)
            {
                return kIOReturnNoResources;
            }
            region.bus = segments[0].fIOVMAddr;
            return kIOReturnSuccess;
        }

        IOReturn releaseCoherentRegion(CoherentRegion &region)
        {
            if (region.commandPrepared)
            {
                const IOReturn result = region.command->complete(true, false);
                if (result != kIOReturnSuccess)
                {
                    return result;
                }
                region.commandPrepared = false;
            }
            if (region.command != nullptr)
            {
                const IOReturn result =
                    region.command->clearMemoryDescriptor(false);
                if (result != kIOReturnSuccess)
                {
                    return result;
                }
                region.command->release();
                region.command = nullptr;
            }
            if (region.bufferPrepared)
            {
                const IOReturn result =
                    region.buffer->complete(kIODirectionInOut);
                if (result != kIOReturnSuccess)
                {
                    return result;
                }
                region.bufferPrepared = false;
            }
            if (region.buffer != nullptr)
            {
                region.buffer->release();
                region.buffer = nullptr;
            }
            if (region.mapper != nullptr)
            {
                region.mapper->release();
                region.mapper = nullptr;
            }
            region.cpu = nullptr;
            region.bus = region.length = 0;
            return kIOReturnSuccess;
        }

    } // namespace

    namespace
    {
        template <typename Pointer> uintptr_t pointerBits(Pointer pointer)
        {
            static_assert(sizeof(Pointer) == sizeof(uintptr_t),
                          "native DMA pointers must fit address-sized storage");
            uintptr_t result = 0;
            __builtin_memcpy(&result, static_cast<const void *>(&pointer),
                             sizeof(result));
            return result;
        }

        template <typename Pointer> Pointer pointerFromBits(uintptr_t address)
        {
            static_assert(sizeof(Pointer) == sizeof(uintptr_t),
                          "native DMA pointers must fit address-sized storage");
            Pointer result = nullptr;
            __builtin_memcpy(static_cast<void *>(&result), &address,
                             sizeof(result));
            return result;
        }

        uint8_t *regionBytesAt(const CoherentRegion &region, size_t offset,
                               size_t bytes)
        {
            if (region.cpu == nullptr || offset > region.length ||
                bytes > region.length - offset)
            {
                return nullptr;
            }
            const uintptr_t base = pointerBits(region.cpu);
            if (offset > UINTPTR_MAX - base)
            {
                return nullptr;
            }
            return pointerFromBits<uint8_t *>(base + offset);
        }

        volatile uint32_t *regionWordAt(const CoherentRegion &region,
                                        size_t recordOffset, size_t index)
        {
            if (index > SIZE_MAX / sizeof(uint32_t) ||
                recordOffset > region.length)
            {
                return nullptr;
            }
            const size_t byteOffset = index * sizeof(uint32_t);
            if (byteOffset > region.length - recordOffset)
            {
                return nullptr;
            }
            uint8_t *const bytes = regionBytesAt(
                region, recordOffset + byteOffset, sizeof(uint32_t));
            return bytes == nullptr ? nullptr
                                    : pointerFromBits<volatile uint32_t *>(
                                          pointerBits(bytes));
        }

        template <typename T, size_t N>
        T &boundedElement(T (&values)[N], size_t index)
        {
            for (T &element : values)
            {
                if (index == 0U)
                {
                    return element;
                }
                --index;
            }
            __builtin_trap();
        }

        template <typename Words>
        bool snapshotStatusWords(const CoherentRegion &region,
                                 size_t recordOffset, Words &snapshot)
        {
            size_t index = 0;
            for (auto &wordValue : snapshot.word)
            {
                const volatile uint32_t *const word =
                    regionWordAt(region, recordOffset, index++);
                if (word == nullptr)
                {
                    return false;
                }
                wordValue = *word;
            }
            return true;
        }

        template <typename Words>
        bool clearStatusWords(const CoherentRegion &region, size_t recordOffset,
                              const Words &snapshot)
        {
            size_t index = 0;
            for (const auto &unused : snapshot.word)
            {
                static_cast<void>(unused);
                volatile uint32_t *const word =
                    regionWordAt(region, recordOffset, index++);
                if (word == nullptr)
                {
                    return false;
                }
                *word = 0U;
            }
            return true;
        }
    } // namespace

    struct NativeQueueMemory
    {
            CoherentRegion descriptors;
            CoherentRegion transmit;
            CoherentRegion receive;
            CoherentRegion completions;
    };

    // The storage comes from IOMalloc; placement-new must never trigger a
    // second allocation or throw while constructing DMA lifetime records.
    static_assert(noexcept(::operator new(sizeof(NativeQueueMemory),
                                          static_cast<void *>(nullptr))),
                  "native DMA placement construction must be noexcept");
    static_assert(noexcept(NativeQueueMemory {}),
                  "native DMA state initialization must be noexcept");

    NativeQueues::~NativeQueues()
    {
        // Do not free hardware-owned queue storage here. Keep incomplete
        // teardown visible on the retained registry owner.
        if (((memory_ != nullptr) || (owner_ != nullptr) ||
             (interrupt_ != nullptr)) &&
            owner_ != nullptr && !owner_->isInactive())
        {
            owner_->setProperty("SimpleATHNativeQueuesTeardownIncomplete",
                                true);
        }
    }

    IOReturn
    NativeQueues::prepareClient(IOService *owner, IOService *pci,
                                IOWorkLoop *loop, uint64_t epoch,
                                const NativeQueueOwner &callbacks,
                                IOInterruptEventSource::Action interruptAction)
    {
        if (phase_ != NativeQueuePhase::Empty || (memory_ != nullptr) ||
            (owner_ != nullptr))
        {
            return kIOReturnBusy;
        }
        if ((owner == nullptr) || (pci == nullptr) || (loop == nullptr) ||
            (epoch == 0U) || (callbacks.context == nullptr) ||
            (callbacks.current == nullptr) ||
            (callbacks.radioReady == nullptr) ||
            (callbacks.setBusMaster == nullptr) ||
            (callbacks.read32 == nullptr) || (callbacks.write32 == nullptr) ||
            (callbacks.delayMicros == nullptr) ||
            (callbacks.receive == nullptr) ||
            (callbacks.transmitted == nullptr) ||
            (callbacks.fault == nullptr) || (interruptAction == nullptr) ||
            callbacks.barLengthBytes < kMinimumQueueBar)
        {
            return kIOReturnBadArgument;
        }
        if (loop->inGate() || loop->onThread())
        {
            return kIOReturnNotPermitted;
        }
        owner_ = owner;
        owner_->retain();
        pci_ = pci;
        pci_->retain();
        loop_ = loop;
        loop_->retain();
        callbacks_ = callbacks;
        epoch_ = epoch;
        auto *storage = IOMalloc(sizeof(NativeQueueMemory));
        if (storage == nullptr)
        {
            releaseClient();
            return kIOReturnNoMemory;
        }
        // The IOKit allocation owns the memory; placement-new only starts
        // the embedded region objects' lifetimes in that owned storage.
        memory_ = static_cast<NativeQueueMemory *>(storage);
        (void)new(storage) NativeQueueMemory {};
        IOReturn result = prepareCoherentRegion(
            memory_->descriptors, pci, kTxSlots * edma::kTxDescriptorBytes);
        if (result == kIOReturnSuccess)
        {
            result = prepareCoherentRegion(memory_->transmit, pci,
                                           kTxSlots * kBufferStride);
        }
        if (result == kIOReturnSuccess)
        {
            result = prepareCoherentRegion(memory_->receive, pci,
                                           kRxSlots * kBufferStride);
        }
        if (result == kIOReturnSuccess)
        {
            result =
                prepareCoherentRegion(memory_->completions, pci, kBufferStride);
        }
        int index = -1;
        for (int candidate = 0; result == kIOReturnSuccess &&
                                candidate < kMaximumInterruptCandidates;
             ++candidate)
        {
            int type = 0;
            if (pci->getInterruptType(candidate, &type) == kIOReturnSuccess)
            {
                index = candidate;
                break;
            }
        }
        if (result == kIOReturnSuccess && index < 0)
        {
            result = kIOReturnNoInterrupt;
        }
        if (result == kIOReturnSuccess)
        {
            interrupt_ = IOInterruptEventSource::interruptEventSource(
                owner, interruptAction, pci, index);
            if (interrupt_ == nullptr)
            {
                result = kIOReturnNoResources;
            }
        }
        if (result != kIOReturnSuccess)
        {
            releaseClient();
            return result;
        }
        phase_ = NativeQueuePhase::Prepared;
        return kIOReturnSuccess;
    }

    bool NativeQueues::gated() const
    {
        return (loop_ != nullptr) && loop_->inGate() &&
               (callbacks_.current != nullptr) &&
               callbacks_.current(callbacks_.context, epoch_);
    }

    bool NativeQueues::read(uint32_t offset, uint32_t &value) const
    {
        return gated() &&
               callbacks_.read32(callbacks_.context, offset, &value) &&
               value != UINT32_MAX;
    }

    bool NativeQueues::write(uint32_t offset, uint32_t value) const
    {
        return gated() && callbacks_.write32(callbacks_.context, offset, value);
    }

    IOReturn NativeQueues::adoptGated(uint64_t currentEpoch)
    {
        if (!gated() || currentEpoch != epoch_ ||
            phase_ != NativeQueuePhase::Prepared || (interrupt_ == nullptr))
        {
            return kIOReturnNotReady;
        }
        if (attached_)
        {
            return kIOReturnSuccess;
        }
        const IOReturn result = loop_->addEventSource(interrupt_);
        if (result == kIOReturnSuccess)
        {
            attached_ = true;
            interrupt_->disable();
        }
        return result;
    }

    bool NativeQueues::initialStartEligibleGated() const
    {
        return gated() && attached_ && phase_ == NativeQueuePhase::Prepared &&
               !keyUpdateIsolated_ && !keyUpdateRestartPending_ &&
               !inReceiveCallback_ && !inInterruptService_;
    }

    IOReturn NativeQueues::startGated()
    {
        if (!gated() || !attached_ || phase_ != NativeQueuePhase::Prepared ||
            !callbacks_.radioReady(callbacks_.context, epoch_))
        {
            return kIOReturnNotReady;
        }
        keyUpdateIsolated_ = false;
        keyUpdateRestartPending_ = false;
        phase_ = NativeQueuePhase::Running; // Hardware may observe a partial
                                            // publication.
        uint32_t txConfiguration = 0;
        uint32_t rxConfiguration = 0;
        uint32_t backpressure = 0;
        if (!write(kIer, 0) || !read(kTxConfiguration, txConfiguration) ||
            !read(kRxConfiguration, rxConfiguration) ||
            !write(kTxConfiguration,
                   (txConfiguration & ~kFrameReceiveConfigurationMask) |
                       kFrameReceiveConfiguration) ||
            !write(kRxConfiguration,
                   (rxConfiguration & ~kFrameReceiveConfigurationMask) |
                       kFrameReceiveConfiguration) ||
            !read(kRxBackpressure, backpressure) ||
            !write(kRxBackpressure, (backpressure & ~kReceiveBackpressureMask) |
                                        kReceiveBackpressureValue) ||
            !write(kRxFifo, kReceiveFifoValue) ||
            !write(kReceiveSize, kReceiveBytes) ||
            !write(kStatusStart, memory_->completions.bus) ||
            !write(kStatusEnd, memory_->completions.bus +
                                   (kTxSlots * edma::kTxCompletionBytes)) ||
            !write(kTxDisable, 0))
        {
            fault(kIOReturnIOError);
            return kIOReturnIOError;
        }
        // One non-aggregating best-effort QCU/DCU. Other queues cannot
        // acquire our descriptor. Values follow ath9k resettxqueue defaults:
        // CWmin=15, CWmax=1023, AIFS=2, station retries=32, frame retries=10.
        for (uint32_t queue = 0; queue < kAtherosQcuCount; ++queue)
        {
            if (!write(kDcuMask + (queue * 4), queue == 0 ? 1 : 0))
            {
                fault(kIOReturnIOError);
                return kIOReturnIOError;
            }
        }
        if (!write(kDcuIfs, kDefaultDcuIfs) ||
            !write(kDcuRetry, kDefaultDcuRetry) ||
            !write(kDcuMisc, kDefaultDcuMisc) || !write(kDcuChannelTime, 0) ||
            !write(kQcuMisc, kDefaultQcuMisc) || !write(kQcuCbr, 0) ||
            !write(kQcuReady, 0) || !write(kImrS0, 1) ||
            !write(kImrS1, kDefaultImrS1) || !write(kImrS2, 1))
        {
            fault(kIOReturnIOError);
            return kIOReturnIOError;
        }
        for (uint32_t slot = 0; slot < kRxSlots; ++slot)
        {
            if (!write(slot < kRxSlots / 2 ? kHighReceivePointer
                                           : kLowReceivePointer,
                       memory_->receive.bus + (slot * kBufferStride)))
            {
                fault(kIOReturnIOError);
                return kIOReturnIOError;
            }
        }
        __sync_synchronize();
        // Register staging is not permission to hand hardware DMA access.
        // RF-kill or the radio epoch can change while a ring is prepared.
        if (!callbacks_.radioReady(callbacks_.context, epoch_))
        {
            fault(kIOReturnNotReady);
            return kIOReturnNotReady;
        }
        if (!callbacks_.setBusMaster(callbacks_.context, true))
        {
            fault(kIOReturnIOError);
            return kIOReturnIOError;
        }
        uint32_t diagnostic = 0;
        // ACK/CTS remain blocked for passive receive until the radio owner
        // explicitly authorizes the associated channel and automatic replies.
        if (!read(kDiagnostic, diagnostic) ||
            !write(kDiagnostic, diagnostic & ~kReceiveBlock) ||
            !write(kReceiveControl, 0) || !write(kImr, kInterruptMask) ||
            !write(kAsyncEnable, kMacInterrupt) ||
            !write(kAsyncMask, kMacInterrupt) ||
            !write(kSyncEnable, kFatalSync) || !write(kSyncMask, kFatalSync))
        {
            fault(kIOReturnIOError);
            return kIOReturnIOError;
        }
        // Revalidate physical receiver permission after bus mastering and
        // before unmasking the device interrupt source. Any observed loss
        // makes the partially started epoch a recovery obligation.
        if (!callbacks_.radioReady(callbacks_.context, epoch_))
        {
            fault(kIOReturnNotReady);
            return kIOReturnNotReady;
        }
        interrupt_->enable();
        if (!write(kIer, 1))
        {
            fault(kIOReturnIOError);
            return kIOReturnIOError;
        }
        return kIOReturnSuccess;
    }

    bool NativeQueues::isolateHardwareGated()
    {
        if (!gated())
        {
            return false;
        }
        // Disabling the interrupt source does not prove DMA isolation.
        // Attempt every hardware mask even after an earlier failure.
        bool masked = write(kIer, 0);
        masked = write(kAsyncMask, 0) && masked;
        masked = write(kAsyncEnable, 0) && masked;
        masked = write(kSyncMask, 0) && masked;
        masked = write(kSyncEnable, 0) && masked;
        const bool masterOff =
            callbacks_.setBusMaster(callbacks_.context, false);
        const RegisterBus bus {
            callbacks_.context,
            callbacks_.read32,
            callbacks_.write32,
            callbacks_.barLengthBytes,
        };
        const bool stopped =
            quiesceAr9565Mac(bus, callbacks_.delayMicros) == MacStopResult::Ok;
        return masked && masterOff && stopped;
    }

    void NativeQueues::clearQuiescedBuffers()
    {
        // Only after verified DMA/MAC isolation and all RX borrowers exit.
        // Never reset a live descriptor or reuse a completed frame.
        clearPublishedBytes(memory_->descriptors.cpu,
                            memory_->descriptors.length);
        clearPublishedBytes(memory_->transmit.cpu, memory_->transmit.length);
        clearPublishedBytes(memory_->receive.cpu, memory_->receive.length);
        clearPublishedBytes(memory_->completions.cpu,
                            memory_->completions.length);
        rxHead_[0] = rxHead_[1] = 0;
        droppedChain_[0] = droppedChain_[1] = false;
        txSlot_ = completionHead_ = pendingDescriptorId_ = 0;
        txToken_ = 0;
        txPending_ = false;
        // nextDescriptorId_ never resets within an owner epoch.
    }

    IOReturn NativeQueues::beginKeyUpdateGated()
    {
        if (!gated() || !attached_ || phase_ != NativeQueuePhase::Running ||
            !callbacks_.radioReady(callbacks_.context, epoch_) ||
            keyUpdateIsolated_ || keyUpdateRestartPending_)
        {
            return kIOReturnNotReady;
        }
        // Do not discard a device-owned EAPOL/management TX descriptor.
        if (txPending_)
        {
            return kIOReturnBusy;
        }
        interrupt_->disable();
        if (!isolateHardwareGated())
        {
            phase_ = NativeQueuePhase::Quarantined;
            // A synchronous RX borrower must unwind before the owner can
            // tear down queues or revoke the station in its fault callback.
            if (inInterruptService_)
            {
                keyUpdateFaultPending_ = true;
            }
            else
            {
                callbacks_.fault(callbacks_.context, kIOReturnIOError);
            }
            return kIOReturnIOError;
        }
        phase_ = NativeQueuePhase::Prepared;
        keyUpdateIsolated_ = true;
        // Current RX callback may still borrow its completed DMA frame.
        return kIOReturnSuccess;
    }

    bool NativeQueues::keyUpdateIsolatedGated() const
    {
        return gated() && attached_ && keyUpdateIsolated_ &&
               phase_ == NativeQueuePhase::Prepared &&
               !keyUpdateRestartPending_;
    }

    IOReturn NativeQueues::restartAfterKeyUpdateGated()
    {
        if (!gated() || !keyUpdateIsolated_ || !keyUpdateRestartPending_ ||
            inReceiveCallback_ || inInterruptService_ ||
            phase_ != NativeQueuePhase::Prepared)
        {
            return kIOReturnNotReady;
        }
        // The lease has ended, DMA was stopped and no RX borrower remains.
        // A failed readiness preflight must quarantine this key generation;
        // startGated itself notifies the owner on partial hardware failure.
        if (!callbacks_.radioReady(callbacks_.context, epoch_))
        {
            keyUpdateIsolated_ = false;
            keyUpdateRestartPending_ = false;
            phase_ = NativeQueuePhase::Quarantined;
            callbacks_.fault(callbacks_.context, kIOReturnNotReady);
            return kIOReturnNotReady;
        }
        clearQuiescedBuffers();
        const IOReturn result = startGated();
        if (result != kIOReturnSuccess)
        {
            return result;
        }
        if (callbacks_.keyUpdateResumed != nullptr)
        {
            callbacks_.keyUpdateResumed(callbacks_.context, epoch_);
        }
        return kIOReturnSuccess;
    }

    IOReturn NativeQueues::endKeyUpdateGated()
    {
        if (!keyUpdateIsolatedGated())
        {
            return kIOReturnNotReady;
        }
        keyUpdateRestartPending_ = true;
        // A synchronous WPA2 M3 callback still borrows the RX slot.
        if (inReceiveCallback_ || inInterruptService_)
        {
            return kIOReturnSuccess;
        }
        return restartAfterKeyUpdateGated();
    }

    IOReturn NativeQueues::transmitGated(const uint8_t *frame, size_t bytes,
                                         uint64_t token,
                                         const edma::TxControlRequest &control,
                                         const edma::TxSafetyPolicy &policy)
    {
        if (!gated() || phase_ != NativeQueuePhase::Running ||
            !callbacks_.radioReady(callbacks_.context, epoch_))
        {
            return kIOReturnNotReady;
        }
        if (txPending_ || nextDescriptorId_ == 0)
        {
            return kIOReturnNoResources;
        }
        if ((frame == nullptr) || bytes < kMinimumMpduBytes ||
            bytes > kMaximumMpduBytes || (token == 0U))
        {
            return kIOReturnBadArgument;
        }
        edma::TxDescriptor descriptor {};
        edma::TxPointerBlock pointers {};
        pointers.segmentCount = 1;
        pointers.queue = 0;
        pointers.segment[0] = {
            memory_->transmit.bus + (txSlot_ * kBufferStride),
            static_cast<uint16_t>(bytes),
        };
        if (edma::encodeTxPointers(pointers, descriptor) !=
                edma::DescriptorError::Ok ||
            edma::encodeTxControls(control, policy, descriptor) !=
                edma::TxControlError::Ok)
        {
            return kIOReturnBadArgument;
        }
        const uint16_t id = nextDescriptorId_;
        descriptor.word[kTxDescriptorControlWord] |= static_cast<uint32_t>(id)
                                                     << kTxDescriptorIdShift;
        uint8_t *const transmit =
            regionBytesAt(memory_->transmit,
                          static_cast<size_t>(txSlot_) * kBufferStride, bytes);
        uint8_t *const descriptorBytes = regionBytesAt(
            memory_->descriptors,
            static_cast<size_t>(txSlot_) * edma::kTxDescriptorBytes,
            sizeof(descriptor));
        if (transmit == nullptr || descriptorBytes == nullptr)
        {
            fault(kIOReturnIOError);
            return kIOReturnIOError;
        }
        memcpy(transmit, frame, bytes);
        memcpy(descriptorBytes, &descriptor, sizeof(descriptor));
        __sync_synchronize();
        txPending_ = true;
        pendingDescriptorId_ = id;
        txToken_ = token;
        nextDescriptorId_ = static_cast<uint16_t>(nextDescriptorId_ + 1U);
        if (!write(kTxPointer, memory_->descriptors.bus +
                                   (txSlot_ * edma::kTxDescriptorBytes)) ||
            !write(kTxEnable, 1))
        {
            fault(kIOReturnIOError);
            return kIOReturnIOError;
        }
        return kIOReturnSuccess;
    }

    NativeQueues::ReceiveStep NativeQueues::processRxSlot(uint32_t queue)
    {
        const uint32_t slot =
            (queue * (kRxSlots / 2U)) + boundedElement(rxHead_, queue);
        const size_t recordOffset = static_cast<size_t>(slot) * kBufferStride;
        const uint8_t *const buffer =
            regionBytesAt(memory_->receive, recordOffset, kBufferStride);
        const volatile uint32_t *const done =
            regionWordAt(memory_->receive, recordOffset, kRxStatusDoneWord);
        if (buffer == nullptr || done == nullptr)
        {
            fault(kIOReturnIOError);
            return ReceiveStep::Stopped;
        }
        if ((*done & kDone) == 0U)
        {
            return ReceiveStep::QueueEmpty;
        }
        __sync_synchronize();
        edma::RxStatusWords raw {};
        if (!snapshotStatusWords(memory_->receive, recordOffset, raw))
        {
            fault(kIOReturnIOError);
            return ReceiveStep::Stopped;
        }
        const bool more = (raw.word[2] & kRxMore) != 0;
        const bool drop = boundedElement(droppedChain_, queue) || more;
        boundedElement(droppedChain_, queue) = more;
        edma::RxStatus status {};
        if (!drop &&
            edma::decodeRxStatus(raw, status) == edma::DescriptorError::Ok &&
            status.frameValid && status.frameLength <= kReceiveBytes)
        {
            const uint8_t *const frame = regionBytesAt(
                memory_->receive, recordOffset + edma::kRxStatusBytes,
                status.frameLength);
            if (frame == nullptr)
            {
                fault(kIOReturnIOError);
                return ReceiveStep::Stopped;
            }
            inReceiveCallback_ = true;
            callbacks_.receive(callbacks_.context, frame, status.frameLength,
                               status);
            inReceiveCallback_ = false;
        }
        if (!gated() || phase_ != NativeQueuePhase::Running)
        {
            return ReceiveStep::Stopped;
        }
        if (!clearStatusWords(memory_->receive, recordOffset, raw))
        {
            fault(kIOReturnIOError);
            return ReceiveStep::Stopped;
        }
        __sync_synchronize();
        if (!write(queue == 0 ? kHighReceivePointer : kLowReceivePointer,
                   memory_->receive.bus + (slot * kBufferStride)))
        {
            fault(kIOReturnIOError);
            return ReceiveStep::Stopped;
        }
        uint8_t &head = boundedElement(rxHead_, queue);
        head = static_cast<uint8_t>((head + 1U) % (kRxSlots / 2U));
        return ReceiveStep::Processed;
    }

    void NativeQueues::receiveCompleted()
    {
        // Preserve each hardware FIFO's completion order; never scan RX
        // buffers by their addresses or treat a split-frame tail as an MPDU.
        for (uint32_t queue = 0; queue < 2U; ++queue)
        {
            for (uint32_t budget = 0U;
                 budget < kRxSlots / 2U && phase_ == NativeQueuePhase::Running;
                 ++budget)
            {
                const ReceiveStep step = processRxSlot(queue);
                if (step == ReceiveStep::QueueEmpty)
                {
                    break;
                }
                if (step == ReceiveStep::Stopped)
                {
                    return;
                }
            }
        }
    }

    void NativeQueues::transmitCompleted()
    {
        for (uint32_t budget = 0; budget < kTxSlots; ++budget)
        {
            const size_t recordOffset =
                static_cast<size_t>(completionHead_) * edma::kTxCompletionBytes;
            const volatile uint32_t *const done = regionWordAt(
                memory_->completions, recordOffset, kTxStatusDoneWord);
            if (done == nullptr)
            {
                fault(kIOReturnIOError);
                return;
            }
            if ((*done & kDone) == 0U)
            {
                return;
            }
            __sync_synchronize();
            edma::TxCompletionWords raw {};
            if (!snapshotStatusWords(memory_->completions, recordOffset, raw))
            {
                fault(kIOReturnIOError);
                return;
            }
            edma::TxCompletion status {};
            if (!txPending_ ||
                static_cast<uint16_t>(raw.word[kTxStatusIdentifierWord] >>
                                      kTxDescriptorIdShift) !=
                    pendingDescriptorId_ ||
                edma::decodeTxCompletion(raw, status) !=
                    edma::DescriptorError::Ok ||
                status.queue != 0)
            {
                fault(kIOReturnIOError);
                return;
            }
            if (!clearStatusWords(memory_->completions, recordOffset, raw))
            {
                fault(kIOReturnIOError);
                return;
            }
            __sync_synchronize();
            completionHead_ =
                static_cast<uint16_t>((completionHead_ + 1U) % kTxSlots);
            const uint64_t token = txToken_;
            txToken_ = 0;
            txPending_ = false;
            pendingDescriptorId_ = 0;
            txSlot_ = static_cast<uint16_t>((txSlot_ + 1U) % kTxSlots);
            callbacks_.transmitted(callbacks_.context, token, status);
            if (!gated() || phase_ != NativeQueuePhase::Running)
            {
                return;
            }
        }
    }

    void NativeQueues::serviceInterruptGated()
    {
        if (!gated() || phase_ != NativeQueuePhase::Running ||
            inInterruptService_)
        {
            return;
        }
        // A physical RF-kill transition can occur after EDMA was started.
        // Merely discarding a received frame is insufficient: the MAC,
        // automatic responses and bus mastering would otherwise continue.
        // Quarantine the queue on the first delivered interrupt and let the
        // native fault path isolate hardware before revoking RF permission.
        if (!callbacks_.radioReady(callbacks_.context, epoch_))
        {
            fault(kIOReturnNotReady);
            return;
        }
        inInterruptService_ = true;
        serviceInterruptBodyGated();
        inInterruptService_ = false;
        if (keyUpdateFaultPending_)
        {
            keyUpdateFaultPending_ = false;
            callbacks_.fault(callbacks_.context, kIOReturnIOError);
            return;
        }
        if (keyUpdateRestartPending_ && keyUpdateIsolated_)
        {
            // The borrowed RX callback has returned; restart is now safe.
            restartAfterKeyUpdateGated();
        }
    }

    void NativeQueues::serviceInterruptBodyGated()
    {
        uint32_t async = 0;
        uint32_t sync = 0;
        uint32_t isr = 0;
        if (!read(kAsyncCause, async) || !read(kSyncCause, sync))
        {
            fault(kIOReturnIOError);
            return;
        }
        if (!write(kIer, 0))
        {
            fault(kIOReturnIOError);
            return;
        }
        if ((sync & kFatalSync) != 0U)
        {
            write(kSyncCause, sync & kFatalSync);
            fault(kIOReturnIOError);
            return;
        }
        if ((async & kMacInterrupt) != 0U)
        {
            if (!read(kIsr, isr))
            {
                fault(kIOReturnIOError);
                return;
            }
            uint32_t s0 = 0;
            uint32_t s1 = 0;
            if (!read(kIsrS0, s0) || !read(kIsrS1, s1) || !write(kIsrS0, s0) ||
                !write(kIsrS1, s1) || !write(kIsr, isr))
            {
                fault(kIOReturnIOError);
                return;
            }
            transmitCompleted();
            if (phase_ == NativeQueuePhase::Running)
            {
                receiveCompleted();
            }
        }
        if (gated() && phase_ == NativeQueuePhase::Running)
        {
            // The station or RF-kill lease may have changed inside an RX
            // completion callback. Never rearm the device on that old lease.
            if (!callbacks_.radioReady(callbacks_.context, epoch_))
            {
                fault(kIOReturnNotReady);
                return;
            }
            if (!write(kIer, 1))
            {
                fault(kIOReturnIOError);
            }
        }
    }

    void NativeQueues::fault(IOReturn result)
    {
        if (interrupt_ != nullptr)
        {
            interrupt_->disable();
        }
        keyUpdateIsolated_ = false;
        keyUpdateRestartPending_ = false;
        keyUpdateFaultPending_ = false;
        phase_ = NativeQueuePhase::Quarantined;
        callbacks_.fault(callbacks_.context, result);
    }

    bool NativeQueues::stopGated(bool available)
    {
        if ((loop_ == nullptr) || !loop_->inGate())
        {
            return false;
        }
        keyUpdateIsolated_ = false;
        keyUpdateRestartPending_ = false;
        keyUpdateFaultPending_ = false;
        if (interrupt_ != nullptr)
        {
            interrupt_->disable();
        }
        if (attached_)
        {
            loop_->removeEventSource(interrupt_);
            attached_ = false;
        }
        if (phase_ == NativeQueuePhase::Empty ||
            phase_ == NativeQueuePhase::Prepared)
        {
            return true;
        }
        const bool isolated = available && isolateHardwareGated();
        phase_ = isolated ? NativeQueuePhase::Prepared
                          : NativeQueuePhase::Quarantined;
        txPending_ = false;
        return isolated;
    }

    IOReturn NativeQueues::releaseClient()
    {
        if ((loop_ != nullptr) && (loop_->inGate() || loop_->onThread()))
        {
            return kIOReturnNotPermitted;
        }
        if (attached_ || phase_ == NativeQueuePhase::Running ||
            phase_ == NativeQueuePhase::Quarantined)
        {
            return kIOReturnBusy;
        }
        if (interrupt_ != nullptr)
        {
            interrupt_->release();
            interrupt_ = nullptr;
        }
        if (memory_ != nullptr)
        {
            IOReturn result = releaseCoherentRegion(memory_->completions);
            if (result == kIOReturnSuccess)
            {
                result = releaseCoherentRegion(memory_->receive);
            }
            if (result == kIOReturnSuccess)
            {
                result = releaseCoherentRegion(memory_->transmit);
            }
            if (result == kIOReturnSuccess)
            {
                result = releaseCoherentRegion(memory_->descriptors);
            }
            if (result != kIOReturnSuccess)
            {
                phase_ = NativeQueuePhase::Quarantined;
                return result;
            }
            memory_->~NativeQueueMemory();
            IOFree(memory_, sizeof(NativeQueueMemory));
            memory_ = nullptr;
        }
        callbacks_ = {};
        inReceiveCallback_ = inInterruptService_ = false;
        keyUpdateIsolated_ = keyUpdateRestartPending_ = false;
        keyUpdateFaultPending_ = false;
        epoch_ = txToken_ = 0;
        nextDescriptorId_ = 1;
        pendingDescriptorId_ = txSlot_ = completionHead_ = 0;
        droppedChain_[0] = droppedChain_[1] = false;
        phase_ = NativeQueuePhase::Empty;
        if (pci_ != nullptr)
        {
            pci_->release();
            pci_ = nullptr;
        }
        if (loop_ != nullptr)
        {
            loop_->release();
            loop_ = nullptr;
        }
        if (owner_ != nullptr)
        {
            const auto *owner = owner_;
            owner_ = nullptr;
            owner->release();
        }
        return kIOReturnSuccess;
    }
} // namespace simpleath
