// SPDX-License-Identifier: AGPL-3.0-only
#ifndef SIMPLEATH_SRC_PLATFORM_AR9565NATIVEDMA_HPP
#define SIMPLEATH_SRC_PLATFORM_AR9565NATIVEDMA_HPP

#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IODMACommand.h>
#include <IOKit/IOMapper.h>
#include <IOKit/IOWorkLoop.h>
#include <stdint.h>

namespace simpleath
{

    enum class NativeDmaResult : uint8_t
    {
        Ok,
        InvalidArgument,
        WrongContext,
        WrongState,
        AllocationFailed,
        MapperUnavailable,
        PreparationFailed,
        SegmentRejected,
        CopyFailed,
        SynchronizationFailed,
        StaleEpoch,
        StaleCompletion,
        GenerationExhausted,
        DeviceStillOwnsBuffer,
        CleanupFailed
    };

    struct NativeDmaToken
    {
            uint64_t ownerEpoch;
            uint64_t allocation; // Unique owner-issued reservation within that
                                 // epoch, across ALL buffers.
            uint64_t submission;
    };

    struct NativeDmaLayout
    {
            IODMACommand::Segment32 segments[4];
            uint32_t segmentCount;
            uint32_t length;
            NativeDmaToken token;
    };

    struct NativeDmaRequest
    {
            uint32_t length; // 1..65536; this is not an AR9565 queue limit.
            uint32_t
                alignment; // Power of two, 4..4096; applied to bus addresses.
            uint32_t maximumSegmentBytes; // TX callers must additionally honor
                                          // the 12-bit length.
            uint32_t maximumSegments; // 1..4; RX queues ordinarily require one.
            IODirection
                direction; // kIODirectionOut (TX) or kIODirectionIn (RX).
    };

    enum class NativeDmaPhase : uint8_t
    {
        Empty,
        CpuOwned,
        DeviceOwned,
        CleanupFailed
    };
    enum class NativeDmaRetirement : uint8_t
    {
        TransferCompleted,
        HardwareQuiesced
    };

    // Packet-buffer mapping, not a perpetually active descriptor/status ring.
    // All blocking *Client methods MUST run on a separate sleepable client
    // thread, outside the owner's work loop and command gate. One caller owns
    // this object at a time; allocation must finish before the gate can adopt
    // the object. The controller retains an outstanding-operation reference
    // while allocating. After retirement the gate can hand CPU ownership back
    // to the client thread. No client operation may race with a gated method or
    // another client operation.
    //
    // The controller supplies a retained, exclusively owned physical PCI
    // provider and a monotonic, nonzero epoch for each powered session. It also
    // reserves a unique nonzero allocation ID under its gate before starting
    // each allocation. Neither ID may wrap/reuse within a controller lifetime.
    // It invalidates the epoch under the gate BEFORE sleep, stop or
    // termination. Reenter the gate with the CURRENT epoch after allocation; no
    // DMA address escapes on an epoch mismatch. This object never opens PCI,
    // enables bus mastering or starts a queue/transfer.
    class NativeDmaBuffer final
    {
        public:
            NativeDmaBuffer();
            ~NativeDmaBuffer();
            NativeDmaBuffer(const NativeDmaBuffer &) = delete;
            NativeDmaBuffer &operator=(const NativeDmaBuffer &) = delete;

            NativeDmaResult prepareClient(IOService *pciProvider,
                                          IOWorkLoop *ownerLoop,
                                          uint64_t ownerEpoch,
                                          uint64_t allocationId,
                                          const NativeDmaRequest &request);
            // Source may not overlap this object or the DMA descriptor's
            // live CPU memory; use a separately owned staging buffer.
            NativeDmaResult writeClient(uint32_t offset, const void *bytes,
                                        uint32_t length);
            NativeDmaResult synchronizeForDeviceClient();
            // Valid only after a real completed RX transfer has been retired
            // under the gate. Caller bounds length to the actual verified RX
            // status, not capacity. Output must be disjoint from this object
            // and its mapped CPU buffer BEFORE any zeroing. After validated
            // arguments, errors zero output so partial frames cannot escape.
            NativeDmaResult readClient(uint32_t offset, void *bytes,
                                       uint32_t length);
            // Mark ownership BEFORE programming a queue. Failure/uncertain
            // programming leaves DeviceOwned until the owner proves completion
            // or hardware isolation.
            // Reject a layout overlapping owner state or mapped DMA storage
            // before zeroing output or assigning a device-owned token.
            NativeDmaResult publishGated(uint64_t currentOwnerEpoch,
                                         NativeDmaLayout &layout);
            // Caller must prove no further DMA to THIS packet: real transfer
            // completion, or verified engine quiescence/reset/isolation. An IRQ
            // mask or elapsed timeout is insufficient. A stale token never
            // retires another transfer.
            NativeDmaResult retireGated(const NativeDmaToken &token,
                                        NativeDmaRetirement reason);
            // May block. Rejects DeviceOwned; never frees memory just because
            // of a timeout.
            NativeDmaResult releaseClient();

            NativeDmaPhase phase() const
            {
                return phase_;
            }

            IOReturn lastKernelError() const
            {
                return lastKernelError_;
            }

        private:
            bool inClientContext() const;
            bool validRange(uint32_t offset, uint32_t length) const;
            NativeDmaResult cleanupUnpublishedClient(NativeDmaResult original);
            IOService *provider_;
            IOWorkLoop *loop_;
            IOMapper *mapper_;
            IOBufferMemoryDescriptor *buffer_;
            IODMACommand *command_;
            NativeDmaRequest request_;
            NativeDmaLayout layout_;
            NativeDmaPhase phase_;
            IOReturn lastKernelError_;
            uint64_t nextSubmission_; // Never reset across clear/reprepare; no
                                      // wrap reuse.
            bool bufferPrepared_;
            bool commandAttached_;
            bool commandPrepared_;
            bool readyForDevice_;
            bool completedTransfer_;
            bool cpuSynchronized_;
    };

} // namespace simpleath
#endif
