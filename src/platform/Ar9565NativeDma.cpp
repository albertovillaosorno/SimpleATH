// SPDX-License-Identifier: AGPL-3.0-only
#include "Ar9565NativeDma.hpp"
#if SIMPLEATH_ENABLE_EXPERIMENTAL_DMA_BACKEND
#include <IOKit/IOLib.h>
#include <libkern/libkern.h>

namespace simpleath
{

    NativeDmaBuffer::NativeDmaBuffer()
        : provider_(nullptr), loop_(nullptr), mapper_(nullptr),
          buffer_(nullptr), command_(nullptr), request_ {}, layout_ {},
          phase_(NativeDmaPhase::Empty), lastKernelError_(kIOReturnSuccess),
          nextSubmission_(0), bufferPrepared_(false), commandAttached_(false),
          commandPrepared_(false), readyForDevice_(false),
          completedTransfer_(false), cpuSynchronized_(false)
    {
    }

    NativeDmaBuffer::~NativeDmaBuffer()
    {
        // Cleanup must be explicit on a client thread before owner destruction.
        // Even an unpublished prepared command may block in complete(). In an
        // invalid teardown deliberately retain every resource rather than free
        // a possible DMA target or invoke blocking VM operations under the
        // gate.
        if (provider_ || loop_ || mapper_ || buffer_ || command_)
            IOLog("SimpleATH: unreleased DMA buffer retained; teardown "
                  "incomplete\n");
    }

    bool NativeDmaBuffer::inClientContext() const
    {
        return loop_ && !loop_->inGate() && !loop_->onThread();
    }

    bool NativeDmaBuffer::validRange(uint32_t offset, uint32_t length) const
    {
        return length && offset <= request_.length &&
               length <= request_.length - offset;
    }

    NativeDmaResult
    NativeDmaBuffer::prepareClient(IOService *provider, IOWorkLoop *loop,
                                   uint64_t epoch, uint64_t allocationId,
                                   const NativeDmaRequest &request)
    {
        if (phase_ != NativeDmaPhase::Empty || provider_ || loop_)
            return NativeDmaResult::WrongState;
        if (!provider || !loop || !epoch || !allocationId || !request.length ||
            request.length > 65536 || request.alignment < 4 ||
            request.alignment > 4096 ||
            (request.alignment & (request.alignment - 1)) ||
            !request.maximumSegmentBytes ||
            request.maximumSegmentBytes > request.length ||
            !request.maximumSegments || request.maximumSegments > 4 ||
            (request.direction != kIODirectionOut &&
             request.direction != kIODirectionIn))
            return NativeDmaResult::InvalidArgument;
        if (loop->inGate() || loop->onThread())
            return NativeDmaResult::WrongContext;
        provider_ = provider;
        loop_ = loop;
        provider_->retain();
        loop_->retain();
        request_ = request;
        layout_ = {};
        layout_.token.ownerEpoch = epoch;
        layout_.token.allocation = allocationId;
        phase_ = NativeDmaPhase::CpuOwned;
        lastKernelError_ = kIOReturnSuccess;

        // A device-specific mapper is mandatory. Never substitute a raw
        // physical address, system-global mapper or bypassed/unmapped command
        // on failure.
        mapper_ = IOMapper::copyMapperForDevice(provider_);
        if (!mapper_)
            return cleanupUnpublishedClient(NativeDmaResult::MapperUnavailable);
        buffer_ = IOBufferMemoryDescriptor::inTaskWithOptions(
            kernel_task, request_.direction, request_.length,
            request_.alignment);
        if (!buffer_ || !buffer_->getBytesNoCopy())
            return cleanupUnpublishedClient(NativeDmaResult::AllocationFailed);
        bzero(buffer_->getBytesNoCopy(), request_.length);
        lastKernelError_ = buffer_->prepare(request_.direction);
        if (lastKernelError_ != kIOReturnSuccess)
            return cleanupUnpublishedClient(NativeDmaResult::PreparationFailed);
        bufferPrepared_ = true;
        command_ = IODMACommand::withSpecification(
            IODMACommand::OutputHost32, 32, request_.maximumSegmentBytes,
            IODMACommand::kMapped, request_.length, request_.alignment, mapper_,
            nullptr);
        if (!command_)
            return cleanupUnpublishedClient(NativeDmaResult::AllocationFailed);
        lastKernelError_ = command_->setMemoryDescriptor(buffer_, false);
        if (lastKernelError_ != kIOReturnSuccess)
            return cleanupUnpublishedClient(NativeDmaResult::PreparationFailed);
        commandAttached_ = true;
        lastKernelError_ = command_->prepare(0, request_.length, true, true);
        if (lastKernelError_ != kIOReturnSuccess)
            return cleanupUnpublishedClient(NativeDmaResult::PreparationFailed);
        commandPrepared_ = true;

        UInt64 offset = 0;
        UInt32 count = 5; // One extra slot detects an overlong scatter list.
        IODMACommand::Segment32 segments[5] {};
        lastKernelError_ =
            command_->gen32IOVMSegments(&offset, segments, &count);
        if (lastKernelError_ != kIOReturnSuccess || count == 0 ||
            count > request_.maximumSegments || offset != request_.length)
            return cleanupUnpublishedClient(NativeDmaResult::SegmentRejected);
        uint64_t total = 0;
        for (UInt32 index = 0; index < count; ++index)
        {
            const auto &segment = segments[index];
            if (!segment.fIOVMAddr || !segment.fLength ||
                segment.fLength > request_.maximumSegmentBytes ||
                (segment.fIOVMAddr & (request_.alignment - 1)) ||
                static_cast<uint64_t>(segment.fIOVMAddr) + segment.fLength >
                    0x100000000ULL)
                return cleanupUnpublishedClient(
                    NativeDmaResult::SegmentRejected);
            total += segment.fLength;
            layout_.segments[index] = segment;
        }
        if (total != request_.length)
            return cleanupUnpublishedClient(NativeDmaResult::SegmentRejected);
        layout_.segmentCount = count;
        layout_.length = request_.length;
        // prepare() synchronizes the initially zeroed descriptor according to
        // direction.
        readyForDevice_ = true;
        return NativeDmaResult::Ok;
    }

    NativeDmaResult NativeDmaBuffer::writeClient(uint32_t offset,
                                                 const void *bytes,
                                                 uint32_t length)
    {
        if (!inClientContext())
            return NativeDmaResult::WrongContext;
        if (phase_ != NativeDmaPhase::CpuOwned ||
            request_.direction != kIODirectionOut)
            return NativeDmaResult::WrongState;
        if (!bytes || !validRange(offset, length))
            return NativeDmaResult::InvalidArgument;
        readyForDevice_ = false;
        // Write the ORIGINAL descriptor, then synchronize OUT. Writing a
        // command's bounce buffer followed by synchronize(OUT) could overwrite
        // the new bytes.
        return buffer_->writeBytes(offset, bytes, length) == length
                   ? NativeDmaResult::Ok
                   : NativeDmaResult::CopyFailed;
    }

    NativeDmaResult NativeDmaBuffer::synchronizeForDeviceClient()
    {
        if (!inClientContext())
            return NativeDmaResult::WrongContext;
        if (phase_ != NativeDmaPhase::CpuOwned)
            return NativeDmaResult::WrongState;
        readyForDevice_ = false;
        lastKernelError_ = command_->synchronize(request_.direction);
        if (lastKernelError_ != kIOReturnSuccess)
            return NativeDmaResult::SynchronizationFailed;
        readyForDevice_ = true;
        return NativeDmaResult::Ok;
    }

    NativeDmaResult NativeDmaBuffer::publishGated(uint64_t epoch,
                                                  NativeDmaLayout &out)
    {
        out = {};
        if (!loop_ || !loop_->inGate())
            return NativeDmaResult::WrongContext;
        if (phase_ != NativeDmaPhase::CpuOwned || !readyForDevice_)
            return NativeDmaResult::WrongState;
        if (!epoch || epoch != layout_.token.ownerEpoch)
            return NativeDmaResult::StaleEpoch;
        if (nextSubmission_ == UINT64_MAX)
            return NativeDmaResult::GenerationExhausted;
        layout_.token.submission = ++nextSubmission_;
        completedTransfer_ = false;
        cpuSynchronized_ = false;
        readyForDevice_ = false;
        phase_ = NativeDmaPhase::DeviceOwned;
        out = layout_;
        // Queue programming, descriptor ownership barriers and legal-TX checks
        // belong to the controller. No hardware operation occurs here.
        return NativeDmaResult::Ok;
    }

    NativeDmaResult NativeDmaBuffer::retireGated(const NativeDmaToken &token,
                                                 NativeDmaRetirement reason)
    {
        if (!loop_ || !loop_->inGate())
            return NativeDmaResult::WrongContext;
        if (phase_ != NativeDmaPhase::DeviceOwned)
            return NativeDmaResult::WrongState;
        if (!token.submission || token.ownerEpoch != layout_.token.ownerEpoch ||
            token.allocation != layout_.token.allocation ||
            token.submission != layout_.token.submission)
            return NativeDmaResult::StaleCompletion;
        if (reason != NativeDmaRetirement::TransferCompleted &&
            reason != NativeDmaRetirement::HardwareQuiesced)
            return NativeDmaResult::InvalidArgument;
        phase_ = NativeDmaPhase::CpuOwned;
        completedTransfer_ = reason == NativeDmaRetirement::TransferCompleted;
        return NativeDmaResult::Ok;
    }

    NativeDmaResult NativeDmaBuffer::readClient(uint32_t offset, void *bytes,
                                                uint32_t length)
    {
        if (!inClientContext())
            return NativeDmaResult::WrongContext;
        if (phase_ != NativeDmaPhase::CpuOwned || !completedTransfer_ ||
            request_.direction != kIODirectionIn)
            return NativeDmaResult::WrongState;
        if (!bytes || !validRange(offset, length))
            return NativeDmaResult::InvalidArgument;
        // A failed synchronize or short read must never leave an earlier RX
        // packet (or a partial new packet) in the caller's output buffer.
        bzero(bytes, length);
        if (!cpuSynchronized_)
        {
            lastKernelError_ = command_->synchronize(kIODirectionIn);
            if (lastKernelError_ != kIOReturnSuccess)
                return NativeDmaResult::SynchronizationFailed;
            cpuSynchronized_ = true;
        }
        if (buffer_->readBytes(offset, bytes, length) != length)
        {
            bzero(bytes, length);
            return NativeDmaResult::CopyFailed;
        }
        return NativeDmaResult::Ok;
    }

    NativeDmaResult
    NativeDmaBuffer::cleanupUnpublishedClient(NativeDmaResult original)
    {
        const IOReturn cause = lastKernelError_;
        const auto result = releaseClient();
        if (result != NativeDmaResult::Ok)
            return result;
        lastKernelError_ = cause;
        return original;
    }

    NativeDmaResult NativeDmaBuffer::releaseClient()
    {
        if (phase_ == NativeDmaPhase::Empty)
            return NativeDmaResult::Ok;
        if (!inClientContext())
            return NativeDmaResult::WrongContext;
        if (phase_ == NativeDmaPhase::DeviceOwned)
            return NativeDmaResult::DeviceStillOwnsBuffer;
        if (phase_ == NativeDmaPhase::CleanupFailed)
            return NativeDmaResult::CleanupFailed;
        if (commandPrepared_)
        {
            lastKernelError_ = command_->complete(true, true);
            if (lastKernelError_ != kIOReturnSuccess)
            {
                phase_ = NativeDmaPhase::CleanupFailed;
                return NativeDmaResult::CleanupFailed;
            }
            commandPrepared_ = false;
        }
        if (commandAttached_)
        {
            lastKernelError_ = command_->clearMemoryDescriptor(false);
            if (lastKernelError_ != kIOReturnSuccess)
            {
                phase_ = NativeDmaPhase::CleanupFailed;
                return NativeDmaResult::CleanupFailed;
            }
            commandAttached_ = false;
        }
        if (bufferPrepared_)
        {
            lastKernelError_ = buffer_->complete(request_.direction);
            if (lastKernelError_ != kIOReturnSuccess)
            {
                phase_ = NativeDmaPhase::CleanupFailed;
                return NativeDmaResult::CleanupFailed;
            }
            bufferPrepared_ = false;
        }
        if (command_)
        {
            command_->release();
            command_ = nullptr;
        }
        if (buffer_)
        {
            if (buffer_->getBytesNoCopy())
                bzero(buffer_->getBytesNoCopy(), request_.length);
            buffer_->release();
            buffer_ = nullptr;
        }
        if (mapper_)
        {
            mapper_->release();
            mapper_ = nullptr;
        }
        provider_->release();
        provider_ = nullptr;
        loop_->release();
        loop_ = nullptr;
        request_ = {};
        layout_ = {};
        readyForDevice_ = completedTransfer_ = cpuSynchronized_ = false;
        phase_ = NativeDmaPhase::Empty;
        return NativeDmaResult::Ok;
    }

} // namespace simpleath
#endif
