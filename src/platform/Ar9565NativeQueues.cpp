// SPDX-License-Identifier: AGPL-3.0-only
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
#include "../hardware/Ar9565MacControl.hpp"
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IODMACommand.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOMapper.h>
#include <libkern/libkern.h>
#include <new>

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

                IOReturn prepare(IOService *pci, uint32_t bytes)
                {
                    mapper = IOMapper::copyMapperForDevice(pci);
                    if (!mapper)
                    {
                        // XNU permits command-generated 32-bit DMA addresses
                        // without an IOMMU. Do not substitute the global mapper
                        // when a device mapping is missing on an IOMMU system.
                        IOMapper::checkForSystemMapper();
                        if (IOMapper::gSystem ||
                            pci->getProperty("iommu-parent"))
                            return kIOReturnNotReady;
                    }
                    length = bytes;
                    buffer = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(
                        kernel_task,
                        kIODirectionInOut | kIOMemoryPhysicallyContiguous,
                        bytes, 0x00000000fffff000ULL);
                    if (!buffer || !buffer->getBytesNoCopy())
                        return kIOReturnNoMemory;
                    cpu = static_cast<uint8_t *>(buffer->getBytesNoCopy());
                    bzero(cpu, bytes);
                    IOReturn result = buffer->prepare(kIODirectionInOut);
                    if (result != kIOReturnSuccess)
                        return result;
                    bufferPrepared = true;
                    command = IODMACommand::withSpecification(
                        IODMACommand::OutputHost32, 32, bytes,
                        IODMACommand::kMapped, bytes, kBufferStride, mapper);
                    if (!command)
                        return kIOReturnNoMemory;
                    result = command->setMemoryDescriptor(buffer, false);
                    if (result != kIOReturnSuccess)
                        return result;
                    result = command->prepare(0, bytes, true, false);
                    if (result != kIOReturnSuccess)
                        return result;
                    commandPrepared = true;
                    if (command->getIOMemoryDescriptor() != buffer)
                        return kIOReturnUnsupported;
                    UInt64 offset = 0;
                    UInt32 count = 2;
                    IODMACommand::Segment32 segments[2] {};
                    result =
                        command->gen32IOVMSegments(&offset, segments, &count);
                    if (result != kIOReturnSuccess)
                        return result;
                    if (count != 1 || offset != bytes ||
                        segments[0].fLength != bytes ||
                        !segments[0].fIOVMAddr ||
                        (segments[0].fIOVMAddr & (kBufferStride - 1)) ||
                        static_cast<uint64_t>(segments[0].fIOVMAddr) + bytes >
                            0x100000000ULL)
                        return kIOReturnNoResources;
                    bus = segments[0].fIOVMAddr;
                    return kIOReturnSuccess;
                }

                IOReturn release()
                {
                    if (commandPrepared)
                    {
                        const IOReturn result = command->complete(true, false);
                        if (result != kIOReturnSuccess)
                            return result;
                        commandPrepared = false;
                    }
                    if (command)
                    {
                        const IOReturn result =
                            command->clearMemoryDescriptor(false);
                        if (result != kIOReturnSuccess)
                            return result;
                        command->release();
                        command = nullptr;
                    }
                    if (bufferPrepared)
                    {
                        const IOReturn result =
                            buffer->complete(kIODirectionInOut);
                        if (result != kIOReturnSuccess)
                            return result;
                        bufferPrepared = false;
                    }
                    if (buffer)
                    {
                        buffer->release();
                        buffer = nullptr;
                    }
                    if (mapper)
                    {
                        mapper->release();
                        mapper = nullptr;
                    }
                    cpu = nullptr;
                    bus = length = 0;
                    return kIOReturnSuccess;
                }
        };
    } // namespace

    struct NativeQueueMemory
    {
            CoherentRegion descriptors;
            CoherentRegion transmit;
            CoherentRegion receive;
            CoherentRegion completions;
    };

    NativeQueues::~NativeQueues()
    {
        if (memory_ || owner_ || interrupt_)
            IOLog("SimpleATH: DMA resources retained after incomplete queue "
                  "teardown\n");
    }

    IOReturn
    NativeQueues::prepareClient(IOService *owner, IOService *pci,
                                IOWorkLoop *loop, uint64_t epoch,
                                const NativeQueueOwner &callbacks,
                                IOInterruptEventSource::Action interruptAction)
    {
        if (phase_ != NativeQueuePhase::Empty || memory_ || owner_)
            return kIOReturnBusy;
        if (!owner || !pci || !loop || !epoch || !callbacks.context ||
            !callbacks.current || !callbacks.radioReady ||
            !callbacks.setBusMaster || !callbacks.read32 ||
            !callbacks.write32 || !callbacks.delayMicros ||
            !callbacks.receive || !callbacks.transmitted || !callbacks.fault ||
            !interruptAction || callbacks.barLengthBytes < 0x9000)
            return kIOReturnBadArgument;
        if (loop->inGate() || loop->onThread())
            return kIOReturnNotPermitted;
        owner_ = owner;
        owner_->retain();
        pci_ = pci;
        pci_->retain();
        loop_ = loop;
        loop_->retain();
        callbacks_ = callbacks;
        epoch_ = epoch;
        auto *storage = IOMalloc(sizeof(NativeQueueMemory));
        if (!storage)
        {
            releaseClient();
            return kIOReturnNoMemory;
        }
        memory_ = new(storage) NativeQueueMemory {};
        IOReturn result = memory_->descriptors.prepare(
            pci, kTxSlots * edma::kTxDescriptorBytes);
        if (result == kIOReturnSuccess)
            result = memory_->transmit.prepare(pci, kTxSlots * kBufferStride);
        if (result == kIOReturnSuccess)
            result = memory_->receive.prepare(pci, kRxSlots * kBufferStride);
        if (result == kIOReturnSuccess)
            result = memory_->completions.prepare(pci, kBufferStride);
        int index = -1;
        for (int candidate = 0; result == kIOReturnSuccess && candidate < 32;
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
            result = kIOReturnNoInterrupt;
        if (result == kIOReturnSuccess)
        {
            interrupt_ = IOInterruptEventSource::interruptEventSource(
                owner, interruptAction, pci, index);
            if (!interrupt_)
                result = kIOReturnNoResources;
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
        return loop_ && loop_->inGate() && callbacks_.current &&
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
            phase_ != NativeQueuePhase::Prepared || !interrupt_)
            return kIOReturnNotReady;
        if (attached_)
            return kIOReturnSuccess;
        const IOReturn result = loop_->addEventSource(interrupt_);
        if (result == kIOReturnSuccess)
        {
            attached_ = true;
            interrupt_->disable();
        }
        return result;
    }

    IOReturn NativeQueues::startGated()
    {
        if (!gated() || !attached_ || phase_ != NativeQueuePhase::Prepared ||
            !callbacks_.radioReady(callbacks_.context, epoch_))
            return kIOReturnNotReady;
        phase_ = NativeQueuePhase::Running; // Hardware may observe a partial
                                            // publication.
        uint32_t txConfiguration = 0, rxConfiguration = 0, backpressure = 0;
        if (!write(kIer, 0) || !read(kTxConfiguration, txConfiguration) ||
            !read(kRxConfiguration, rxConfiguration) ||
            !write(kTxConfiguration, (txConfiguration & ~7U) | 5U) ||
            !write(kRxConfiguration, (rxConfiguration & ~7U) | 5U) ||
            !read(kRxBackpressure, backpressure) ||
            !write(kRxBackpressure, (backpressure & ~0x3f0fU) | 0x101U) ||
            !write(kRxFifo, 0x200) || !write(kReceiveSize, kReceiveBytes) ||
            !write(kStatusStart, memory_->completions.bus) ||
            !write(kStatusEnd, memory_->completions.bus +
                                   kTxSlots * edma::kTxCompletionBytes) ||
            !write(kTxDisable, 0))
        {
            fault(kIOReturnIOError);
            return kIOReturnIOError;
        }
        // One non-aggregating best-effort QCU/DCU. Other queues cannot
        // acquire our descriptor. Values follow ath9k resettxqueue defaults:
        // CWmin=15, CWmax=1023, AIFS=2, station retries=32, frame retries=10.
        for (uint32_t queue = 0; queue < 10; ++queue)
        {
            if (!write(kDcuMask + queue * 4, queue == 0 ? 1 : 0))
            {
                fault(kIOReturnIOError);
                return kIOReturnIOError;
            }
        }
        if (!write(kDcuIfs, 15U | (1023U << 10) | (2U << 20)) ||
            !write(kDcuRetry, 10U | (32U << 8) | (32U << 14)) ||
            !write(kDcuMisc, 0x1102) || !write(kDcuChannelTime, 0) ||
            !write(kQcuMisc, 0x800) || !write(kQcuCbr, 0) ||
            !write(kQcuReady, 0) || !write(kImrS0, 1) ||
            !write(kImrS1, 0x00010001) || !write(kImrS2, 1))
        {
            fault(kIOReturnIOError);
            return kIOReturnIOError;
        }
        for (uint32_t slot = 0; slot < kRxSlots; ++slot)
        {
            if (!write(slot < kRxSlots / 2 ? kHighReceivePointer
                                           : kLowReceivePointer,
                       memory_->receive.bus + slot * kBufferStride))
            {
                fault(kIOReturnIOError);
                return kIOReturnIOError;
            }
        }
        __sync_synchronize();
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
        interrupt_->enable();
        if (!write(kIer, 1))
        {
            fault(kIOReturnIOError);
            return kIOReturnIOError;
        }
        return kIOReturnSuccess;
    }

    IOReturn NativeQueues::transmitGated(const uint8_t *frame, size_t bytes,
                                         uint64_t token,
                                         const edma::TxControlRequest &control,
                                         const edma::TxSafetyPolicy &policy)
    {
        if (!gated() || phase_ != NativeQueuePhase::Running ||
            !callbacks_.radioReady(callbacks_.context, epoch_))
            return kIOReturnNotReady;
        if (txPending_ || nextDescriptorId_ == 0)
            return kIOReturnNoResources;
        if (!frame || bytes < 10 || bytes > 2342 || !token)
            return kIOReturnBadArgument;
        edma::TxDescriptor descriptor {};
        edma::TxPointerBlock pointers {};
        pointers.segmentCount = 1;
        pointers.queue = 0;
        pointers.segment[0] = {memory_->transmit.bus + txSlot_ * kBufferStride,
                               static_cast<uint16_t>(bytes)};
        if (edma::encodeTxPointers(pointers, descriptor) !=
                edma::DescriptorError::Ok ||
            edma::encodeTxControls(control, policy, descriptor) !=
                edma::TxControlError::Ok)
            return kIOReturnBadArgument;
        const uint16_t id = nextDescriptorId_;
        descriptor.word[10] |= static_cast<uint32_t>(id) << 16;
        memcpy(memory_->transmit.cpu + txSlot_ * kBufferStride, frame, bytes);
        memcpy(memory_->descriptors.cpu + txSlot_ * edma::kTxDescriptorBytes,
               &descriptor, sizeof(descriptor));
        __sync_synchronize();
        txPending_ = true;
        pendingDescriptorId_ = id;
        txToken_ = token;
        nextDescriptorId_ = static_cast<uint16_t>(nextDescriptorId_ + 1U);
        if (!write(kTxPointer, memory_->descriptors.bus +
                                   txSlot_ * edma::kTxDescriptorBytes) ||
            !write(kTxEnable, 1))
        {
            fault(kIOReturnIOError);
            return kIOReturnIOError;
        }
        return kIOReturnSuccess;
    }

    void NativeQueues::receiveCompleted()
    {
        // Process each hardware FIFO in publication order. Scanning buffers
        // by address can reorder wrapped completions and misidentify a split
        // frame's tail as an independent MPDU.
        for (uint32_t queue = 0; queue < 2; ++queue)
        {
            for (uint32_t budget = 0;
                 budget < kRxSlots / 2 && phase_ == NativeQueuePhase::Running;
                 ++budget)
            {
                const uint32_t slot = queue * (kRxSlots / 2) + rxHead_[queue];
                auto *buffer = memory_->receive.cpu + slot * kBufferStride;
                auto *words = reinterpret_cast<volatile uint32_t *>(buffer);
                if (!(words[11] & kDone))
                    break;
                __sync_synchronize();
                edma::RxStatusWords raw {};
                for (size_t i = 0; i < edma::kRxStatusWordCount; ++i)
                    raw.word[i] = words[i];
                const bool more = (raw.word[2] & kRxMore) != 0;
                const bool drop = droppedChain_[queue] || more;
                droppedChain_[queue] = more;
                edma::RxStatus status {};
                if (!drop &&
                    edma::decodeRxStatus(raw, status) ==
                        edma::DescriptorError::Ok &&
                    status.frameValid && status.frameLength <= kReceiveBytes)
                {
                    callbacks_.receive(callbacks_.context,
                                       buffer + edma::kRxStatusBytes,
                                       status.frameLength, status);
                }
                if (!gated() || phase_ != NativeQueuePhase::Running)
                    return;
                for (size_t i = 0; i < edma::kRxStatusWordCount; ++i)
                    words[i] = 0;
                __sync_synchronize();
                if (!write(queue == 0 ? kHighReceivePointer
                                      : kLowReceivePointer,
                           memory_->receive.bus + slot * kBufferStride))
                {
                    fault(kIOReturnIOError);
                    return;
                }
                rxHead_[queue] = static_cast<uint8_t>((rxHead_[queue] + 1U) %
                                                      (kRxSlots / 2));
            }
        }
    }

    void NativeQueues::transmitCompleted()
    {
        for (uint32_t budget = 0; budget < kTxSlots; ++budget)
        {
            auto *words = reinterpret_cast<volatile uint32_t *>(
                memory_->completions.cpu +
                completionHead_ * edma::kTxCompletionBytes);
            if (!(words[8] & kDone))
                return;
            __sync_synchronize();
            edma::TxCompletionWords raw {};
            for (size_t i = 0; i < edma::kTxCompletionWordCount; ++i)
                raw.word[i] = words[i];
            edma::TxCompletion status {};
            if (!txPending_ ||
                static_cast<uint16_t>(raw.word[1] >> 16) !=
                    pendingDescriptorId_ ||
                edma::decodeTxCompletion(raw, status) !=
                    edma::DescriptorError::Ok ||
                status.queue != 0)
            {
                fault(kIOReturnIOError);
                return;
            }
            for (size_t i = 0; i < edma::kTxCompletionWordCount; ++i)
                words[i] = 0;
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
                return;
        }
    }

    void NativeQueues::serviceInterruptGated()
    {
        if (!gated() || phase_ != NativeQueuePhase::Running)
            return;
        uint32_t async = 0, sync = 0, isr = 0;
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
        if (sync & kFatalSync)
        {
            write(kSyncCause, sync & kFatalSync);
            fault(kIOReturnIOError);
            return;
        }
        if (async & kMacInterrupt)
        {
            if (!read(kIsr, isr))
            {
                fault(kIOReturnIOError);
                return;
            }
            uint32_t s0 = 0, s1 = 0;
            if (!read(kIsrS0, s0) || !read(kIsrS1, s1) || !write(kIsrS0, s0) ||
                !write(kIsrS1, s1) || !write(kIsr, isr))
            {
                fault(kIOReturnIOError);
                return;
            }
            transmitCompleted();
            if (phase_ == NativeQueuePhase::Running)
                receiveCompleted();
        }
        if (gated() && phase_ == NativeQueuePhase::Running && !write(kIer, 1))
            fault(kIOReturnIOError);
    }

    void NativeQueues::fault(IOReturn result)
    {
        if (interrupt_)
            interrupt_->disable();
        phase_ = NativeQueuePhase::Quarantined;
        callbacks_.fault(callbacks_.context, result);
    }

    bool NativeQueues::stopGated(bool available)
    {
        if (!loop_ || !loop_->inGate())
            return false;
        if (interrupt_)
            interrupt_->disable();
        if (attached_)
        {
            loop_->removeEventSource(interrupt_);
            attached_ = false;
        }
        if (phase_ == NativeQueuePhase::Empty ||
            phase_ == NativeQueuePhase::Prepared)
            return true;
        bool isolated = false;
        if (available && gated())
        {
            // Attempt every isolation operation even after an earlier write
            // fails. One failed register must not leave another IRQ enabled.
            bool masked = write(kIer, 0);
            masked = write(kAsyncMask, 0) && masked;
            masked = write(kAsyncEnable, 0) && masked;
            masked = write(kSyncMask, 0) && masked;
            masked = write(kSyncEnable, 0) && masked;
            const bool masterOff =
                callbacks_.setBusMaster(callbacks_.context, false);
            const RegisterBus bus {callbacks_.context, callbacks_.read32,
                                   callbacks_.write32,
                                   callbacks_.barLengthBytes};
            const bool stopped =
                quiesceAr9565Mac(bus, callbacks_.delayMicros) ==
                MacStopResult::Ok;
            isolated = masked && masterOff && stopped;
        }
        phase_ = isolated ? NativeQueuePhase::Prepared
                          : NativeQueuePhase::Quarantined;
        txPending_ = false;
        return isolated;
    }

    IOReturn NativeQueues::releaseClient()
    {
        if (loop_ && (loop_->inGate() || loop_->onThread()))
            return kIOReturnNotPermitted;
        if (attached_ || phase_ == NativeQueuePhase::Running ||
            phase_ == NativeQueuePhase::Quarantined)
            return kIOReturnBusy;
        if (interrupt_)
        {
            interrupt_->release();
            interrupt_ = nullptr;
        }
        if (memory_)
        {
            IOReturn result = memory_->completions.release();
            if (result == kIOReturnSuccess)
                result = memory_->receive.release();
            if (result == kIOReturnSuccess)
                result = memory_->transmit.release();
            if (result == kIOReturnSuccess)
                result = memory_->descriptors.release();
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
        epoch_ = txToken_ = 0;
        nextDescriptorId_ = 1;
        pendingDescriptorId_ = txSlot_ = completionHead_ = 0;
        droppedChain_[0] = droppedChain_[1] = false;
        phase_ = NativeQueuePhase::Empty;
        if (pci_)
        {
            pci_->release();
            pci_ = nullptr;
        }
        if (loop_)
        {
            loop_->release();
            loop_ = nullptr;
        }
        if (owner_)
        {
            auto *owner = owner_;
            owner_ = nullptr;
            owner->release();
        }
        return kIOReturnSuccess;
    }
} // namespace simpleath
