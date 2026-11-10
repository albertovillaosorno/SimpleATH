#include "Ar9565NativeDma.hpp"
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IODMACommand.h>
#include <IOKit/IOMapper.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOReturn.h>
#include <IOKit/IOService.h>
#include <IOKit/IOWorkLoop.h>
#include <cstddef>
#include <cstdint>
#include <kern/task.h>
#include <libkern/OSTypes.h>

namespace simpleath
{
    namespace
    {
        constexpr uint32_t kMaxPacketDmaBytes = 65536U;
        constexpr uint32_t kMaxPacketAlignment = 4096U;
        constexpr uint32_t kMaxPacketSegments = 4U;
        constexpr uint32_t kSegmentProbeCount = kMaxPacketSegments + 1U;
        constexpr uint32_t kHostBusAddressWidth = 32U;
        constexpr uint64_t kAbove32BitBusAddress =
            static_cast<uint64_t>(UINT32_MAX) + 1U;

        uintptr_t pointerAddress(const void *pointer)
        {
            static_assert(sizeof(uintptr_t) == sizeof(pointer),
                          "native DMA address and pointer widths must match");
            uintptr_t result = 0;
            __builtin_memcpy(&result, static_cast<const void *>(&pointer),
                             sizeof(pointer));
            return result;
        }

        template <typename T, size_t N>
        T &boundedElement(T (&items)[N], size_t index)
        {
            for (T &item : items)
            {
                if (index == 0U)
                {
                    return item;
                }
                --index;
            }
            __builtin_trap(); // Caller checked segment count <= four.
        }

        void clearOwnedBytes(void *bytes, size_t length)
        {
            // The barrier ensures that the zeroing remains ordered before
            // the descriptor is re-used or released to the kernel allocator.
            __builtin_memset(bytes, 0, length);
            __sync_synchronize();
        }

        bool disjointMemory(const void *first, size_t firstLength,
                            const void *second, size_t secondLength)
        {
            const uintptr_t a = pointerAddress(first);
            const uintptr_t b = pointerAddress(second);
            // Subtract first so even a forged near-UINTPTR_MAX span cannot
            // cause wraparound in pointer-plus-length arithmetic.
            return a <= b ? b - a >= firstLength : a - b >= secondLength;
        }
    } // namespace

    NativeDmaBuffer::NativeDmaBuffer() = default;

    NativeDmaBuffer::~NativeDmaBuffer()
    {
        // Cleanup must be explicit on a client thread before owner destruction.
        // Even an unpublished prepared command may block in complete(). In an
        // invalid teardown deliberately retain every resource rather than free
        // a possible DMA target or invoke blocking VM operations under the
        // gate.
        // Retain unsafe DMA resources rather than release live targets;
        // expose incomplete teardown on the still-live registry provider.
        if (((provider_ != nullptr) || (loop_ != nullptr) ||
             (mapper_ != nullptr) || (buffer_ != nullptr) ||
             (command_ != nullptr)) &&
            provider_ != nullptr && !provider_->isInactive())
        {
            provider_->setProperty("SimpleATHNativeDmaTeardownIncomplete",
                                   true);
        }
    }

    bool NativeDmaBuffer::inClientContext() const
    {
        return (loop_ != nullptr) && !loop_->inGate() && !loop_->onThread();
    }

    bool NativeDmaBuffer::validRange(uint32_t offset, uint32_t length) const
    {
        return (length != 0U) && offset <= request_.length &&
               length <= request_.length - offset;
    }

    NativeDmaResult
    NativeDmaBuffer::prepareClient(IOService *provider, IOWorkLoop *loop,
                                   uint64_t epoch, uint64_t allocationId,
                                   const NativeDmaRequest &request)
    {
        if (phase_ != NativeDmaPhase::Empty || (provider_ != nullptr) ||
            (loop_ != nullptr))
        {
            return NativeDmaResult::WrongState;
        }
        if ((provider == nullptr) || (loop == nullptr) || (epoch == 0U) ||
            (allocationId == 0U) || (request.length == 0U) ||
            request.length > kMaxPacketDmaBytes || request.alignment < 4 ||
            request.alignment > kMaxPacketAlignment ||
            ((request.alignment & (request.alignment - 1)) != 0U) ||
            (request.maximumSegmentBytes == 0U) ||
            request.maximumSegmentBytes > request.length ||
            (request.maximumSegments == 0U) ||
            request.maximumSegments > kMaxPacketSegments ||
            (request.direction != kIODirectionOut &&
             request.direction != kIODirectionIn))
        {
            return NativeDmaResult::InvalidArgument;
        }
        if (loop->inGate() || loop->onThread())
        {
            return NativeDmaResult::WrongContext;
        }
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

        // Use the device's IOMMU domain when present. A machine without any
        // mapper still uses IODMACommand for address-width/segment validation.
        // Never substitute another IOMMU domain or manufacture bus addresses.
        mapper_ = IOMapper::copyMapperForDevice(provider_);
        if (mapper_ == nullptr)
        {
            IOMapper::checkForSystemMapper();
            if ((IOMapper::gSystem != nullptr) ||
                (provider_->getProperty("iommu-parent") != nullptr))
            {
                return cleanupUnpublishedClient(
                    NativeDmaResult::MapperUnavailable);
            }
        }
        buffer_ = IOBufferMemoryDescriptor::inTaskWithOptions(
            kernel_task, request_.direction, request_.length,
            request_.alignment);
        if ((buffer_ == nullptr) || (buffer_->getBytesNoCopy() == nullptr))
        {
            return cleanupUnpublishedClient(NativeDmaResult::AllocationFailed);
        }
        clearOwnedBytes(buffer_->getBytesNoCopy(), request_.length);
        lastKernelError_ = buffer_->prepare(request_.direction);
        if (lastKernelError_ != kIOReturnSuccess)
        {
            return cleanupUnpublishedClient(NativeDmaResult::PreparationFailed);
        }
        bufferPrepared_ = true;
        command_ = IODMACommand::withSpecification(
            IODMACommand::OutputHost32, kHostBusAddressWidth,
            request_.maximumSegmentBytes, IODMACommand::kMapped,
            request_.length, request_.alignment, mapper_, nullptr);
        if (command_ == nullptr)
        {
            return cleanupUnpublishedClient(NativeDmaResult::AllocationFailed);
        }
        lastKernelError_ = command_->setMemoryDescriptor(buffer_, false);
        if (lastKernelError_ != kIOReturnSuccess)
        {
            return cleanupUnpublishedClient(NativeDmaResult::PreparationFailed);
        }
        commandAttached_ = true;
        lastKernelError_ = command_->prepare(0, request_.length, true, true);
        if (lastKernelError_ != kIOReturnSuccess)
        {
            return cleanupUnpublishedClient(NativeDmaResult::PreparationFailed);
        }
        commandPrepared_ = true;

        UInt64 offset = 0;
        UInt32 count = kSegmentProbeCount; // One extra slot detects an overlong
                                           // scatter list.
        IODMACommand::Segment32 segments[kSegmentProbeCount] {};
        lastKernelError_ =
            command_->gen32IOVMSegments(&offset, &segments[0], &count);
        if (lastKernelError_ != kIOReturnSuccess || count == 0 ||
            count > request_.maximumSegments || offset != request_.length)
        {
            return cleanupUnpublishedClient(NativeDmaResult::SegmentRejected);
        }
        uint64_t total = 0;
        for (UInt32 index = 0; index < count; ++index)
        {
            const auto &segment = boundedElement(segments, index);
            if ((segment.fIOVMAddr == 0U) || (segment.fLength == 0U) ||
                segment.fLength > request_.maximumSegmentBytes ||
                ((segment.fIOVMAddr & (request_.alignment - 1)) != 0U) ||
                static_cast<uint64_t>(segment.fIOVMAddr) + segment.fLength >
                    kAbove32BitBusAddress)
            {
                return cleanupUnpublishedClient(
                    NativeDmaResult::SegmentRejected);
            }
            total += segment.fLength;
            boundedElement(layout_.segments, index) = segment;
        }
        if (total != request_.length)
        {
            return cleanupUnpublishedClient(NativeDmaResult::SegmentRejected);
        }
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
        {
            return NativeDmaResult::WrongContext;
        }
        if (phase_ != NativeDmaPhase::CpuOwned ||
            request_.direction != kIODirectionOut)
        {
            return NativeDmaResult::WrongState;
        }
        if ((bytes == nullptr) || !validRange(offset, length) ||
            !disjointMemory(bytes, length, this, sizeof(*this)) ||
            !disjointMemory(bytes, length, buffer_->getBytesNoCopy(),
                            request_.length))
        {
            return NativeDmaResult::InvalidArgument;
        }
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
        {
            return NativeDmaResult::WrongContext;
        }
        if (phase_ != NativeDmaPhase::CpuOwned)
        {
            return NativeDmaResult::WrongState;
        }
        readyForDevice_ = false;
        lastKernelError_ = command_->synchronize(request_.direction);
        if (lastKernelError_ != kIOReturnSuccess)
        {
            return NativeDmaResult::SynchronizationFailed;
        }
        readyForDevice_ = true;
        return NativeDmaResult::Ok;
    }

    NativeDmaResult NativeDmaBuffer::publishGated(uint64_t epoch,
                                                  NativeDmaLayout &out)
    {
        // A forged layout reference into the owner or live DMA storage
        // would erase internal state or packet bytes before epoch checks.
        // Reject prior to any output write, even if the caller is not gated.
        if (!disjointMemory(&out, sizeof(out), this, sizeof(*this)) ||
            ((buffer_ != nullptr) && (buffer_->getBytesNoCopy() != nullptr) &&
             !disjointMemory(&out, sizeof(out), buffer_->getBytesNoCopy(),
                             request_.length)))
        {
            return NativeDmaResult::InvalidArgument;
        }
        out = {};
        if ((loop_ == nullptr) || !loop_->inGate())
        {
            return NativeDmaResult::WrongContext;
        }
        if (phase_ != NativeDmaPhase::CpuOwned || !readyForDevice_)
        {
            return NativeDmaResult::WrongState;
        }
        if ((epoch == 0U) || epoch != layout_.token.ownerEpoch)
        {
            return NativeDmaResult::StaleEpoch;
        }
        if (nextSubmission_ == UINT64_MAX)
        {
            return NativeDmaResult::GenerationExhausted;
        }
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
        if ((loop_ == nullptr) || !loop_->inGate())
        {
            return NativeDmaResult::WrongContext;
        }
        if (phase_ != NativeDmaPhase::DeviceOwned)
        {
            return NativeDmaResult::WrongState;
        }
        if ((token.submission == 0U) ||
            token.ownerEpoch != layout_.token.ownerEpoch ||
            token.allocation != layout_.token.allocation ||
            token.submission != layout_.token.submission)
        {
            return NativeDmaResult::StaleCompletion;
        }
        if (reason != NativeDmaRetirement::TransferCompleted &&
            reason != NativeDmaRetirement::HardwareQuiesced)
        {
            return NativeDmaResult::InvalidArgument;
        }
        phase_ = NativeDmaPhase::CpuOwned;
        completedTransfer_ = reason == NativeDmaRetirement::TransferCompleted;
        return NativeDmaResult::Ok;
    }

    NativeDmaResult NativeDmaBuffer::readClient(uint32_t offset, void *bytes,
                                                uint32_t length)
    {
        if (!inClientContext())
        {
            return NativeDmaResult::WrongContext;
        }
        if (phase_ != NativeDmaPhase::CpuOwned || !completedTransfer_ ||
            request_.direction != kIODirectionIn)
        {
            return NativeDmaResult::WrongState;
        }
        if ((bytes == nullptr) || !validRange(offset, length) ||
            !disjointMemory(bytes, length, this, sizeof(*this)) ||
            !disjointMemory(bytes, length, buffer_->getBytesNoCopy(),
                            request_.length))
        {
            return NativeDmaResult::InvalidArgument;
        }
        // A failed synchronize or short read must never leave an earlier RX
        // packet (or a partial new packet) in the caller's output buffer.
        clearOwnedBytes(bytes, length);
        if (!cpuSynchronized_)
        {
            lastKernelError_ = command_->synchronize(kIODirectionIn);
            if (lastKernelError_ != kIOReturnSuccess)
            {
                return NativeDmaResult::SynchronizationFailed;
            }
            cpuSynchronized_ = true;
        }
        if (buffer_->readBytes(offset, bytes, length) != length)
        {
            clearOwnedBytes(bytes, length);
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
        {
            return result;
        }
        lastKernelError_ = cause;
        return original;
    }

    NativeDmaResult NativeDmaBuffer::releaseClient()
    {
        if (phase_ == NativeDmaPhase::Empty)
        {
            return NativeDmaResult::Ok;
        }
        if (!inClientContext())
        {
            return NativeDmaResult::WrongContext;
        }
        if (phase_ == NativeDmaPhase::DeviceOwned)
        {
            return NativeDmaResult::DeviceStillOwnsBuffer;
        }
        if (phase_ == NativeDmaPhase::CleanupFailed)
        {
            return NativeDmaResult::CleanupFailed;
        }
        if (commandPrepared_)
        {
            if (command_ == nullptr)
            {
                phase_ = NativeDmaPhase::CleanupFailed;
                return NativeDmaResult::CleanupFailed;
            }
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
            if (command_ == nullptr)
            {
                phase_ = NativeDmaPhase::CleanupFailed;
                return NativeDmaResult::CleanupFailed;
            }
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
            if (buffer_ == nullptr)
            {
                phase_ = NativeDmaPhase::CleanupFailed;
                return NativeDmaResult::CleanupFailed;
            }
            lastKernelError_ = buffer_->complete(request_.direction);
            if (lastKernelError_ != kIOReturnSuccess)
            {
                phase_ = NativeDmaPhase::CleanupFailed;
                return NativeDmaResult::CleanupFailed;
            }
            bufferPrepared_ = false;
        }
        if (command_ != nullptr)
        {
            command_->release();
            command_ = nullptr;
        }
        if (buffer_ != nullptr)
        {
            if (buffer_->getBytesNoCopy() != nullptr)
            {
                clearOwnedBytes(buffer_->getBytesNoCopy(), request_.length);
            }
            buffer_->release();
            buffer_ = nullptr;
        }
        if (mapper_ != nullptr)
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
